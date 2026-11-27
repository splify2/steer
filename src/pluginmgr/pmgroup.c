/* До решения оба поколения существуют на том же FS. Каждый rename переносит
 * каталог целиком, включая локальные файлы. Не восстанавливаем из архива.
 * G1 active -> G1 finished — единственная граница, после неё только GC. */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/stat.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "pmgroup.h"
#include "ctlcall.h"
#include "ctlcall_io.h"
#include "scrypto.h"

int pm_group_reader(int writer) {
    int fd = open(pm_root(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? -2 : -1;
    if (flock(fd, (writer ? LOCK_EX : LOCK_SH) | LOCK_NB) == 0) return fd;
    close(fd);
    return -1;
}

/* Прочие read-only команды не должны начать replay одиночной установки. */
int pm_group_pending(void) {
    if (pm_managed()) return 0;
    char *work = pm_path(pm_root(),PM_GROUP_DIR);
    struct stat st;
    int pending = !lstat(work,&st) || errno != ENOENT;
    free(work);
    if (pending) return 1;
    /* Окно между окончанием GC и снятием последнего маркера. */
    char *path = pm_path(pm_root(),".install-in-progress");
    int fd = open(path,O_RDONLY|O_NONBLOCK|O_NOFOLLOW|O_CLOEXEC);
    free(path);
    if (fd < 0) return 0;
    char tag[3];
    pending = read(fd,tag,3) == 3 && !memcmp(tag,"G1 ",3);
    close(fd);
    return pending;
}

static void hex(const unsigned char b[32], char s[65]) {
    for (int i = 0; i < 32; i++) sprintf(s+i*2, "%02x", b[i]);
}

static int sha256(const void *buf, size_t n, unsigned char out[32]) {
    struct sc_hash_ctx h;
    if (sc_hash_init(&h, SC_SHA256)) return -1;
    int rc = sc_hash_update(&h, buf, n);
    if (!rc) rc = sc_hash_final(&h, out);
    sc_hash_free(&h);
    return rc;
}

/* ynode проверяет вложенность, UTF-8 и повторы ключей, но допускает YAML.
 * Для квитанции v1 сверяем также лексемы JSON, включая тип скаляра. В этом
 * конверте код целый, внутри status встречаются также дробные измерения. */
static const char *ws(const char *s) { return s + strspn(s," \r\n\t"); }
static const char *wire_value(const char *s, const struct ynode *v) {
    s = ws(s);
    if (v->kind == YN_SCALAR) {
        if (*s == '"' && v->style == YS_DOUBLE) {
            if (strlen(v->str) != v->len) return NULL;
            for (s++; *s && *s != '"'; s++) {
                if ((unsigned char)*s < 32) return NULL;
                if (*s != '\\') continue;
                if (!*++s) return NULL;
                if (*s == 'u') {
                    if (strspn(s+1,"0123456789abcdefABCDEF") < 4) return NULL;
                    s += 4;
                } else if (!strchr("\"\\/bfnrt",*s)) return NULL;
            }
            return *s ? s+1 : NULL;
        }
        if (v->style != YS_PLAIN) return NULL;
        if (!strncmp(s,"true",4) || !strncmp(s,"null",4)) return s+4;
        if (!strncmp(s,"false",5)) return s+5;
        if (*s == '-') s++;
        size_t n = strspn(s,"0123456789");
        if (!n || (n > 1 && *s == '0')) return NULL;
        s += n;
        if (*s == '.') {
            n = strspn(++s,"0123456789");
            if (!n) return NULL;
            s += n;
        }
        if (*s == 'e' || *s == 'E') {
            s++; if (*s == '-' || *s == '+') s++;
            n = strspn(s,"0123456789");
            if (!n) return NULL;
            s += n;
        }
        return s;
    }
    int map = v->kind == YN_MAP;
    if (*s++ != (map ? '{' : '[')) return NULL;
    for (size_t i = 0; i < v->len; i++) {
        if (i && *ws(s) != ',') return NULL;
        if (i) s = ws(s)+1;
        if (map) {
            if (ynode_key_at(v,i)->style != YS_DOUBLE) return NULL;
            s = wire_value(s,ynode_key_at(v,i));
            if (!s || *ws(s) != ':') return NULL;
            s = ws(s)+1;
        }
        s = wire_value(s,map ? ynode_val_at(v,i) : ynode_at(v,i));
        if (!s) return NULL;
    }
    s = ws(s);
    return *s == (map ? '}' : ']') ? s+1 : NULL;
}

enum reload_result { UNCERTAIN = -1, CONFIRMED, CONFIG_ERROR };

static char *ctl_path(void) {
    const char *path = ctlcall_socket(NULL);
    if (*path == '/') return pm_strdup(path);
    char *cwd = getcwd(NULL,0), *p = cwd ? pm_path(cwd,path) : NULL;
    free(cwd);
    return p;
}

static int reply_string(const struct ynode *map, const char *k) {
    const struct ynode *n = ynode_get(map,k);
    return n && n->kind == YN_SCALAR && n->style == YS_DOUBLE && n->len;
}

static int string_list(const struct ynode *map, const char *k) {
    const struct ynode *a = ynode_get(map,k);
    if (!a || a->kind != YN_SEQ) return 0;
    for (size_t i = 0; i < a->len; i++)
        if (ynode_at(a,i)->style != YS_DOUBLE) return 0;
    return 1;
}

/* Вызывать только на fd того владельца, которого проверили. При replay не
 * посылать даже первый байт другому слушателю. */
static int group_request(const char *owner, char found[128], const char *request, char **reply) {
    const char *path = ctlcall_socket(NULL);
    struct stat a, b;
    int fd = -1;
    if (strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) goto uncertain;
    if (lstat(path,&a)) {
        if (errno != ENOENT || (owner && strcmp(owner,"offline"))) goto uncertain;
        strcpy(found,"offline");
        return CONFIRMED;
    }
    if (!S_ISSOCK(a.st_mode) || (owner && !strcmp(owner,"offline"))) goto uncertain;
    fd = ctlcall_open(300);
    struct ucred peer;
    socklen_t len = sizeof(peer);
    if (fd < 0 || getsockopt(fd,SOL_SOCKET,SO_PEERCRED,&peer,&len) || len != sizeof(peer) ||
        peer.pid <= 0 || lstat(path,&b) || a.st_dev != b.st_dev || a.st_ino != b.st_ino) goto uncertain;
    snprintf(found,128,"%ju:%ju:%jd:%ju",(uintmax_t)b.st_dev,(uintmax_t)b.st_ino,
             (intmax_t)peer.pid,(uintmax_t)peer.uid);
    if (owner && strcmp(owner,found)) goto uncertain;
    if (ctl_write_all(fd,request,strlen(request),NULL)) goto uncertain;
    *reply = ctl_read_reply(fd);
    close(fd);
    return *reply ? CONFIRMED : UNCERTAIN;
uncertain:
    if (fd >= 0) close(fd);
    return UNCERTAIN;
}

struct ydoc *pm_group_status(const struct pm_group *g) {
    char found[128], *reply = NULL;
    if (group_request(g->owner,found,"status\n",&reply) != CONFIRMED || !reply) return NULL;
    struct ydoc *d = pm_json_parse(reply,strlen(reply),"status",NULL), *out = NULL;
    const struct ynode *r = d ? ydoc_root(d) : NULL;
    const char *end = r ? wire_value(reply,r) : NULL;
    const char *cmd = yn_str(r,"cmd"), *body = yn_str(r,"stdout");
    int trunc;
    if (end && !*ws(end) && yn_long(r,"v",-1) == 1 && cmd && !strcmp(cmd,"status") &&
        !ynode_get(r,"error") && !ynode_get(r,"ok") && yn_long(r,"code",-1) == 0 &&
        (!ynode_get(r,"truncated") || (!ynode_bool(ynode_get(r,"truncated"),&trunc) && !trunc)) &&
        body && reply_string(r,"stdout")) {
        out = pm_json_parse(body,strlen(body),"status.stdout",NULL);
        const struct ynode *s = out ? ydoc_root(out) : NULL, *outputs = ynode_get(s,"outputs");
        const char *tail = s ? wire_value(body,s) : NULL;
        if (out && (!tail || *ws(tail) || yn_long(s,"schema",-1) != 1 ||
                    ynode_get(s,"cached") || !outputs || outputs->kind != YN_MAP)) {
            ydoc_free(out); out = NULL;
        }
    }
    if (d) ydoc_free(d);
    free(reply);
    return out;
}

static int group_reload(const char *owner, char found[128], char failure[65], struct pm_err *e) {
    char *reply = NULL;
    if (group_request(owner,found,"plugin-reload\n",&reply) == UNCERTAIN) goto uncertain;
    if (!reply) return CONFIRMED; /* offline */
    struct ydoc *d = pm_json_parse(reply,strlen(reply),"plugin-reload",NULL);
    const struct ynode *r = d ? ydoc_root(d) : NULL, *reload = ynode_get(r,"reload"), *changed = ynode_get(r,"changed");
    const char *end = r ? wire_value(reply,r) : NULL, *cmd = yn_str(r,"cmd");
    long code = yn_long(r,"code",-1);
    int flag, trunc, rc = UNCERTAIN;
    if (end && !*ws(end) && yn_long(r,"v",-1) == 1 && cmd && !strcmp(cmd,"plugin-reload") &&
        !ynode_get(r,"error") && !ynode_get(r,"ok") && !ynode_bool(ynode_get(r,"enabled"),&flag) &&
        (!ynode_get(r,"truncated") || (!ynode_bool(ynode_get(r,"truncated"),&trunc) && !trunc)) &&
        reply_string(reload,"dnsd") && reply_string(reload,"outputs") &&
        !ynode_bool(ynode_get(changed,"ruleset"),&flag) && !ynode_bool(ynode_get(changed,"dnsd"),&flag) &&
        string_list(changed,"routing") && string_list(changed,"helpers")) {
        if (!code) rc = CONFIRMED;
        const struct ynode *err = ynode_get(r,"stderr");
        if (code > 0 && code <= 255 && err && err->style == YS_DOUBLE && err->len && strlen(err->str) == err->len) {
            unsigned char sum[32];
            char *key = pm_fmt("%ld:%s",code,err->str);
            if (!sha256(key,strlen(key),sum)) {
                hex(sum,failure);
                pm_errc(e,"plugin.reload_failed",PMA("why",err->str),"ядро не перечитало плагины: %s",err->str);
                rc = CONFIG_ERROR;
            }
            free(key);
        }
    }
    if (d) ydoc_free(d);
    free(reply);
    if (rc != UNCERTAIN) return rc;
uncertain:
    return pm_errc(e,"plugin.group_reload_unconfirmed",NULL,"нет подтверждённого ответа владельца ctl на plugin-reload");
}

int pm_group_output_up(const struct ynode *v) {
    const char *kind = yn_str(v,"kind");
    int up;
    return kind && (!strcmp(kind,"vless") || !strcmp(kind,"tunnel:vless")) &&
        !ynode_bool(ynode_get(v,"up"),&up) && up;
}

/* Штатная повторная подготовка спеки — только после полученного отказа,
 * повтор на том же владельце. Обрыв транспорта не является config-error. */
static int reload_checked(const char *owner, char found[128], char failure[65], struct pm_err *e) {
    int rc = group_reload(owner,found,failure,e);
    if (rc != CONFIG_ERROR || !strstr(e->msg,"нужен reload")) return rc;
    char retry[128];
    return group_reload(found,retry,failure,e);
}

int pm_group_baseline(struct pm_group *g, struct pm_err *e) {
    char failure[65];
    int rc = reload_checked(NULL,g->owner,failure,e);
    if (rc == CONFIG_ERROR) strcpy(g->config_err,failure);
    return rc == UNCERTAIN ? -1 : 0;
}

int pm_group_health(const struct pm_group *g, struct pm_err *e) {
    char found[128], failure[65];
    int rc = reload_checked(g->owner,found,failure,e);
    if (rc == CONFIG_ERROR && !strcmp(g->config_err,failure)) return 0;
    return rc == CONFIRMED ? 0 : -1;
}

static int by_name(const struct dirent **a, const struct dirent **b) {
    return strcmp((*a)->d_name, (*b)->d_name);
}

/* st_dev недостаточно для bind на том же разделе. На старых ядрах — только
 * fdinfo нашего открытого fd, а не обход процессов/таблиц монтирования. */
static uint64_t mount_of(const char *p) {
#if defined(SYS_statx) && defined(STATX_MNT_ID)
    struct statx sx;
    if (!syscall(SYS_statx, AT_FDCWD, p, AT_SYMLINK_NOFOLLOW, STATX_MNT_ID, &sx) &&
        (sx.stx_mask & STATX_MNT_ID)) return sx.stx_mnt_id;
#endif
    int fd = open(p,O_PATH|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return 0;
    char name[64], line[160];
    snprintf(name,sizeof(name),"/proc/self/fdinfo/%d",fd);
    FILE *f = fopen(name,"r");
    uint64_t id = 0;
    if (f) {
        while (fgets(line,sizeof(line),f) && sscanf(line,"mnt_id: %" SCNu64,&id) != 1) {}
        fclose(f);
    }
    close(fd);
    return id;
}

/* Полная идентичность старого/нового дерева, а не доверие к версии в plugin.json.
 * Имена отделены NUL, каталог заканчивается пустым именем. Не следуем ссылкам. */
static int fingerprint(struct sc_hash_ctx *h, const char *p, int depth, uint64_t mount) {
    struct stat st;
    if (depth > 64 || lstat(p, &st) || !mount || mount_of(p) != mount) return -1;
    char meta[128];
    int m = snprintf(meta, sizeof(meta), "%ju:%ju:%o:", (uintmax_t)st.st_dev,
                     (uintmax_t)st.st_ino, (unsigned)st.st_mode);
    if (sc_hash_update(h, meta, m+1)) return -1;
    if (S_ISREG(st.st_mode)) {
        unsigned char b[32]; unsigned long long n;
        return pm_file_sha256(p, b, &n) || sc_hash_update(h, b, sizeof(b)) ? -1 : 0;
    }
    if (!S_ISDIR(st.st_mode)) return -1;
    struct dirent **v = NULL;
    /* Сравнение по байтам, не strcoll/локали последующего процесса. */
    int n = scandir(p, &v, NULL, by_name);
    if (n < 0) return -1;
    int rc = 0;
    for (int i = 0; i < n; i++) {
        const char *name = v[i]->d_name;
        if (!rc && strcmp(name, ".") && strcmp(name, "..")) {
            char *child = pm_path(p, name);
            if (sc_hash_update(h, name, strlen(name)+1) || fingerprint(h, child, depth+1,mount)) rc = -1;
            free(child);
        }
        free(v[i]);
    }
    free(v);
    return rc || sc_hash_update(h, "", 1) ? -1 : 0;
}

static int identity(const char *p, char out[65]) {
    struct stat st;
    if (lstat(p, &st)) {
        if (errno != ENOENT) return -1;
        strcpy(out, "-"); return 0;
    }
    struct sc_hash_ctx h;
    unsigned char b[32];
    if (!S_ISDIR(st.st_mode) || sc_hash_init(&h, SC_SHA256)) return -1;
    int rc = fingerprint(&h, p, 0,mount_of(pm_root())) || sc_hash_final(&h, b);
    sc_hash_free(&h);
    if (rc) return -1;
    hex(b, out); return 0;
}

static int digest(const char *p, char out[65]) {
    struct stat st;
    unsigned char b[32]; unsigned long long size;
    if (lstat(p, &st) || !S_ISREG(st.st_mode) || pm_file_sha256(p, b, &size)) return -1;
    hex(b, out); return 0;
}

/* До записи рабочего файла отмечаем SHA его допустимого промежуточного
 * содержимого. Replay не затирает постороннюю редакцию реестра/keep.d. */
int pm_group_write(const struct pm_group *g, const char *name, const char *path,
                   const char *buf, size_t n) {
    unsigned char b[32]; char sum[65];
    if (sha256(buf,n,b)) return -1;
    struct stat st;
    unsigned mode = 0644;
    if (!lstat(path,&st)) {
        if (!S_ISREG(st.st_mode)) return -1;
        mode = st.st_mode & 0777;
    } else if (errno != ENOENT) return -1;
    hex(b,sum);
    char *receipt = pm_fmt("%s/wrote-%s-%s",g->dir,name,sum);
    char *last = pm_fmt("%s/last-%s",g->dir,name);
    int bad = pm_write_atomic(receipt,sum,64,0600) || pm_write_atomic(last,sum,64,0600) ||
              pm_write_atomic(path,buf,n,mode);
    free(receipt); free(last); return bad ? -1 : 0;
}

/* Метаданные могут лежать на другом разделе. В журнал идут байты, режим,
 * признак отсутствия и путь (другой STEER_PLUGIN_ETC/KEEPD не владелец). */
static int save_file(struct jw *w, const char *dir, const char *name, const char *path) {
    struct stat st;
    char sum[65] = "-";
    if (lstat(path, &st) == 0) {
        size_t n;
        if (!S_ISREG(st.st_mode) || (st.st_mode & 07000)) return -1;
        char *b = pm_read(path, &n), *dst = pm_path(dir, name);
        int bad = !b || pm_write_atomic(dst, b, n, 0600) || digest(dst, sum);
        free(dst); free(b);
        if (bad) return -1;
    } else if (errno != ENOENT) return -1;
    jw_key(w, name); jw_obj(w);
    jw_kstr(w, "path", path); jw_kstr(w, "sha", sum);
    jw_kint(w, "mode", strcmp(sum, "-") ? st.st_mode & 0777 : 0);
    jw_end(w); return 0;
}

static int metadata(const struct ynode *root, const char *dir, const char *name,
                    const char *path, int restore, int accept) {
    const struct ynode *row = ynode_get(root, name);
    const char *bound = yn_str(row, "path"), *sum = yn_str(row, "sha");
    long mode = yn_long(row, "mode", -1);
    if (!bound || strcmp(bound, path) || !sum || mode < 0 || mode > 0777) return -1;
    struct stat st;
    int live = lstat(path, &st) == 0;
    if (live ? !S_ISREG(st.st_mode) : errno != ENOENT) return -1;
    char current[65] = "-";
    if (live && digest(path,current)) return -1;
    if (accept) {
        char *last = pm_fmt("%s/last-%s",dir,name);
        size_t n; char *s = pm_read(last,&n);
        int match = live && s && n == 64 && !memcmp(s,current,64);
        free(s); free(last);
        if (!match) return -1;
    }
    if (strcmp(current,sum)) {
        char *receipt = pm_fmt("%s/wrote-%s-%s",dir,name,current);
        size_t n; char *s = pm_read(receipt,&n);
        int ours = s && n == 64 && !memcmp(s,current,64);
        free(s); free(receipt);
        if (!ours) return -1;
    }
    if (!strcmp(sum, "-")) return restore && live ? unlink(path) : 0;
    char *saved = pm_path(dir, name), hash[65];
    int bad = digest(saved, hash) || strcmp(hash, sum);
    if (!bad && restore && (strcmp(current,sum) || (st.st_mode & 0777) != mode)) {
        size_t n; char *bytes = pm_read(saved, &n);
        /* Независимо от umask восстановления. */
        bad = !bytes || pm_write_atomic(path, bytes, n, (unsigned)mode) || chmod(path, (mode_t)mode);
        free(bytes);
    }
    free(saved);
    return bad ? -1 : 0;
}

static int mark(const char *path, const char *phase, const char *dir, const char *sum,
                uintmax_t dev, uintmax_t ino) {
    char *s = pm_fmt("G1 %s %s %ju %ju %s", phase, strrchr(dir, '/')+1, dev, ino, sum);
    unsigned char b[32]; char check[65]; int rc = -1;
    if (!sha256(s,strlen(s),b)) {
        hex(b,check);
        char *record = pm_fmt("%s %s\n",s,check);
        rc = pm_write_atomic(path,record,strlen(record),0600);
        free(record);
    }
    free(s);
    return rc;
}

int pm_group_preparing(const struct pm_group *g) {
    struct stat st;
    char *marker = pm_path(pm_root(),".install-in-progress");
    int bad = lstat(g->dir,&st) || mark(marker,"preparing",g->dir,"-",st.st_dev,st.st_ino);
    free(marker);
    return bad ? -1 : 0;
}

int pm_group_publish(const struct pm_group *g) {
    char *buf = NULL; size_t n = 0;
    FILE *f = open_memstream(&buf, &n);
    if (!f) return -1;
    struct jw w; jw_init(&w, f); jw_obj(&w);
    char *ctl = ctl_path();
    jw_kstr(&w,"ctl_path",ctl);
    jw_kstr(&w,"ctl_owner",g->owner);
    if (g->before.n) {
        jw_key(&w,"vless_up"); jw_arr(&w);
        for (size_t i = 0; i < g->before.n; i++) jw_str(&w,g->before.v[i]);
        jw_aend(&w);
    }
    char *sp = pm_state_path();
    int bad = !ctl || save_file(&w, g->dir, "registry", sp) || save_file(&w, g->dir, "keep", pm_keepd());
    free(ctl); free(sp);
    jw_key(&w, "members"); jw_obj(&w);
    for (size_t i = 0; !bad && i < g->n; i++) {
        const char *id = g->v[i].id;
        char *live = pm_path(pm_root(), id), *next = pm_fmt("%s/new-%s", g->dir, id);
        char a[65], b[65];
        bad = identity(live, a) || identity(next, b) || !strcmp(b, "-");
        if (!bad) {
            jw_key(&w, id); jw_obj(&w);
            jw_kstr(&w, "old", a); jw_kstr(&w, "new", b); jw_end(&w);
        }
        free(live); free(next);
    }
    jw_end(&w); jw_end(&w);
    if (ferror(f)) bad = 1;
    if (fclose(f)) bad = 1;
    char *plan = pm_path(g->dir, "plan"), *marker = pm_path(pm_root(), ".install-in-progress");
    char sum[65]; struct stat st;
    struct pm_err err = {0};
    struct ydoc *check = bad ? NULL : pm_json_parse(buf, n, plan, &err);
    if (!check || pm_write_atomic(plan, buf, n, 0600) || digest(plan, sum) || lstat(g->dir, &st) ||
        mark(marker, "active", g->dir, sum, st.st_dev, st.st_ino)) bad = 1;
    if (check) ydoc_free(check);
    free(plan); free(marker); free(buf);
    return bad ? -1 : 0;
}

/* Допустимы только три позиции до решения: untouched, old отложен,
 * new на месте. Обратные rename проходят те же позиции в обратном порядке. */
static int member(const char *dir, const char *id, const struct ynode *row, int restore, int accept) {
    const char *a = yn_str(row, "old"), *b = yn_str(row, "new");
    if (!pm_id_ok(id) || !a || !b || strlen(b) != 64) return -1;
    char *live = pm_path(pm_root(), id), *old = pm_fmt("%s/old-%s", dir, id),
         *next = pm_fmt("%s/new-%s", dir, id);
    char l[65], o[65], n[65];
    int rc = -1;
    if (identity(live,l) || identity(old,o) || identity(next,n)) goto out;
    int placed = !strcmp(l,b) && !strcmp(o,a) && !strcmp(n,"-");
    int moved = !strcmp(l,"-") && !strcmp(o,a) && !strcmp(n,b);
    int initial = !strcmp(l,a) && !strcmp(o,"-") && !strcmp(n,b);
    if (accept ? !placed : !(placed || moved || initial)) goto out;
    if (restore && ((placed && rename(live,next)) ||
                    (!initial && strcmp(a,"-") && rename(old,live)))) goto out;
    rc = 0;
out:
    free(live); free(old); free(next); return rc;
}

int pm_group_finish(const char *marker, int accept) {
    size_t n; char *record = pm_read(marker, &n);
    char phase[12], sum[65], hash[65]; int end = -1, rc = -1;
    uintmax_t dev, ino;
    unsigned char b[32];
    if (!record || sscanf(record,"G1 %11s " PM_GROUP_DIR " %ju %ju %64[-0-9a-f]%n",
                          phase, &dev, &ino, sum, &end) != 4 || end < 0 || (size_t)end+66 != n ||
        record[end] != ' ' || record[n-1] != '\n' || sha256(record,end,b) ||
        (!strcmp(phase,"preparing") ? strcmp(sum,"-") :
        (strlen(sum) != 64 || (strcmp(phase,"active") && strcmp(phase,"finished"))))) {
        free(record); return -1;
    }
    hex(b,hash);
    if (memcmp(hash,record+end+1,64)) { free(record); return -1; }
    free(record);
    char *dir = pm_path(pm_root(),PM_GROUP_DIR), *plan = pm_path(dir,"plan"), *sp = pm_state_path();
    struct ydoc *d = NULL;
    struct stat st;
    int exists = !lstat(dir,&st);
    if (exists ? (!S_ISDIR(st.st_mode) || st.st_dev != dev || st.st_ino != ino) : errno != ENOENT) goto out;
    if (!strcmp(phase,"active")) {
        struct pm_err why = {0};
        if (digest(plan,hash) || strcmp(hash,sum) || !(d = pm_json_load(plan,&why))) goto out;
        const struct ynode *root = ydoc_root(d), *rows = ynode_get(root,"members");
        const char *owner = yn_str(root,"ctl_owner"), *path = yn_str(root,"ctl_path");
        if (!owner || !*owner || !path || !rows || rows->kind != YN_MAP || rows->len < 2 ||
            metadata(root,dir,"registry",sp,0,accept) || metadata(root,dir,"keep",pm_keepd(),0,accept)) goto out;
        /* Проверить ВСЮ группу до первого обратного rename. */
        for (int pass = 0; pass < (accept ? 1 : 2); pass++)
            for (size_t i = rows->len; i-- > 0;)
                if (member(dir,ynode_key_at(rows,i)->str,ynode_val_at(rows,i),pass,accept)) goto out;
        if (!accept) {
            char found[128], failure[65];
            char *ctl = ctl_path();
            int same = ctl && !strcmp(path,ctl);
            free(ctl);
            if (metadata(root,dir,"registry",sp,1,0) || metadata(root,dir,"keep",pm_keepd(),1,0) ||
                !same || reload_checked(owner,found,failure,&why) != CONFIRMED) goto out;
            const struct ynode *up = ynode_get(root,"vless_up");
            if (up) {
                struct pm_group g = {0};
                if (!string_list(root,"vless_up") || strlen(owner) >= sizeof(g.owner)) goto out;
                strcpy(g.owner,owner);
                struct ydoc *status = pm_group_status(&g);
                if (!status) goto out;
                const struct ynode *outputs = ynode_get(ydoc_root(status),"outputs");
                int ok = 1;
                for (size_t i = 0; i < up->len; i++)
                    if (!pm_group_output_up(ynode_get(outputs,ynode_at(up,i)->str))) ok = 0;
                ydoc_free(status);
                if (!ok) goto out;
            }
        }
        if (mark(marker,"finished",dir,sum,dev,ino)) goto out;
    }
    /* После решения даже частично удалённый каталог журнала — только мусор. */
    if ((!exists || !pm_rmrf(dir)) && !unlink(marker)) rc = 0;
out:
    if (d) ydoc_free(d);
    free(dir); free(plan); free(sp); return rc;
}

/* Обычный отказ живого manager исторически оставляет bad_versions. Не
 * пересобирать для этого весь старый реестр из lossy модели pm_state. */
static void fields_except(struct jw *w, const struct ynode *map, const char *except) {
    for (size_t i = 0; i < ynode_len(map); i++) {
        const char *key = ynode_key_at(map,i)->str;
        if (strcmp(key,except)) jw_knode(w,key,ynode_val_at(map,i));
    }
}

int pm_group_bad_versions(const struct pm_result *res, const char *why) {
    char *path = pm_state_path(), *buf = NULL;
    size_t n = 0;
    struct stat st;
    int rc = -1;
    struct ydoc *d = NULL;
    if (lstat(path,&st)) { rc = errno == ENOENT ? 0 : -1; goto out; }
    d = pm_json_load(path,NULL);
    if (!d) goto out;
    const struct ynode *root = ydoc_root(d), *plugins = ynode_get(root,"plugins");
    if (!plugins || plugins->kind != YN_MAP) goto out;
    FILE *f = open_memstream(&buf,&n);
    if (!f) goto out;
    struct jw w; jw_init(&w,f); jw_obj(&w); fields_except(&w,root,"plugins");
    jw_key(&w,"plugins"); jw_obj(&w);
    int changed = 0, invalid = 0;
    for (size_t i = 0; i < plugins->len; i++) {
        const char *id = ynode_key_at(plugins,i)->str, *ver = NULL;
        for (size_t j = 0; j < res->n; j++)
            if (!strcmp(id,res->v[j].id)) ver = res->v[j].version;
        const struct ynode *entry = ynode_val_at(plugins,i);
        if (!ver) { jw_knode(&w,id,entry); continue; }
        const struct ynode *bad = ynode_get(entry,"bad_versions");
        if (entry->kind != YN_MAP || (bad && bad->kind != YN_MAP)) { invalid = 1; break; }
        jw_key(&w,id); jw_obj(&w); fields_except(&w,entry,"bad_versions");
        jw_key(&w,"bad_versions"); jw_obj(&w); fields_except(&w,bad,ver);
        jw_kstr(&w,ver,why); jw_end(&w); jw_end(&w); changed = 1;
    }
    jw_end(&w); jw_end(&w); fputc('\n',f);
    if (ferror(f)) invalid = 1;
    if (!fclose(f) && !invalid) rc = changed ? pm_write_atomic(path,buf,n,st.st_mode & 0777) : 0;
out:
    if (d) ydoc_free(d);
    free(path); free(buf); return rc;
}
