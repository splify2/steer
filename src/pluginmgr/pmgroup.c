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
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "pmgroup.h"
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
    if (sc_hash(SC_SHA256,buf,n,b)) return -1;
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
    if (!sc_hash(SC_SHA256,s,strlen(s),b)) {
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
    char *sp = pm_state_path();
    int bad = save_file(&w, g->dir, "registry", sp) || save_file(&w, g->dir, "keep", pm_keepd());
    free(sp);
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

int pm_group_finish(const char *marker, int accept, struct pm_ctx *x) {
    size_t n; char *record = pm_read(marker, &n);
    char phase[12], sum[65], hash[65]; int end = -1, rc = -1;
    uintmax_t dev, ino;
    unsigned char b[32];
    if (!record || sscanf(record,"G1 %11s " PM_GROUP_DIR " %ju %ju %64[-0-9a-f]%n",
                          phase, &dev, &ino, sum, &end) != 4 || end < 0 || (size_t)end+66 != n ||
        record[end] != ' ' || record[n-1] != '\n' || sc_hash(SC_SHA256,record,end,b) ||
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
        if (!rows || rows->kind != YN_MAP || rows->len < 2 ||
            metadata(root,dir,"registry",sp,0,accept) || metadata(root,dir,"keep",pm_keepd(),0,accept)) goto out;
        /* Проверить ВСЮ группу до первого обратного rename. */
        for (int pass = 0; pass < (accept ? 1 : 2); pass++)
            for (size_t i = rows->len; i-- > 0;)
                if (member(dir,ynode_key_at(rows,i)->str,ynode_val_at(rows,i),pass,accept)) goto out;
        if (!accept && (metadata(root,dir,"registry",sp,1,0) || metadata(root,dir,"keep",pm_keepd(),1,0) ||
                        pm_daemon_reload(x,&why))) goto out;
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
