/* Распаковка ustar+gzip (untar.h). Устройство и доводы:
 *
 * ЗАПИСЬ — ЧЕРЕЗ ДЕСКРИПТОРЫ КАТАЛОГОВ, а не через строки путей. Проверить путь на «..» мало: архив
 * может положить символьную ссылку `a -> /etc`, а следующей записью файл `a/passwd`, и проверенный
 * по буквам путь окажется записью в чужой каталог. Поэтому каждая компонента пути открывается
 * openat(O_DIRECTORY|O_NOFOLLOW) от дескриптора предыдущей, а сам файл — O_CREAT|O_EXCL|O_NOFOLLOW:
 * ядро отказывает на любой ссылке в пути (ELOOP), и это не зависит от того, что мы о путях подумали.
 * Тем не менее путь нормализуется и проверяется до открытия (UNTAR_EPATH): ясный отказ лучше ELOOP.
 *
 * СИМВОЛЬНЫЕ ССЫЛКИ в архиве допустимы, но только вниз: цель относительная, без «..» и без
 * абсолютного начала. Ссылка, которой нельзя выйти из каталога ни при каком раскладе каталогов
 * под ней, не требует разбора «куда она на самом деле ведёт»; ссылки вверх («../lib») в пакетах
 * плагинов не нужны, а доказывать безопасность цепочек ссылок дороже, чем без них обойтись.
 *
 * ПОТОК. Вход читается кусками (gz_read или память), файл пишется по мере чтения — в памяти только
 * 64 КиБ буфера и окно DEFLATE, поэтому размер файла и архива не ограничен. Заголовки pax и GNU
 * длинные имена копятся в памяти ровно по объявленному размеру, растя по мере чтения: враньё в
 * размере кончится концом входа, а не огромным malloc. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "untar.h"
#include "gz.h"
#include "scrypto.h"

#define WHY(...) do { if (why && wn) snprintf(why, wn, __VA_ARGS__); } while (0)

/* ---- вход: gzip или память ------------------------------------------------------------------- */

struct rd {
    struct gz *g;
    const unsigned char *mem;
    size_t memn, pos;
};

/* Прочитать ровно n байт. Возвращает сколько прочиталось (меньше n — конец входа) или -1 (gzip испорчен). */
static long rd_exact(struct rd *r, unsigned char *dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        long k;
        if (r->g) {
            k = gz_read(r->g, dst + got, n - got);
            if (k < 0) return -1;
        } else {
            size_t left = r->memn - r->pos;
            k = (long)(left < n - got ? left : n - got);
            memcpy(dst + got, r->mem + r->pos, (size_t)k);
            r->pos += (size_t)k;
        }
        if (k == 0) break;
        got += (size_t)k;
    }
    return (long)got;
}

/* Пропустить n байт входа; 0 — пропущено, 1 — вход кончился раньше, -1 — gzip испорчен. */
static int rd_skip(struct rd *r, unsigned long long n) {
    unsigned char buf[4096];
    while (n) {
        size_t want = n < sizeof buf ? (size_t)n : sizeof buf;
        long k = rd_exact(r, buf, want);
        if (k < 0) return -1;
        if ((size_t)k < want) return 1;
        n -= want;
    }
    return 0;
}

/* ---- разбор заголовка ------------------------------------------------------------------------ */

static int all_zero(const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) if (p[i]) return 0;
    return 1;
}

/* Число из поля: восьмеричное (пробелы и нули по краям) или base-256 (старший бит первого байта).
 * -1 — не число или не влезло в 63 бита. */
static long long field_num(const unsigned char *f, size_t n) {
    if (f[0] & 0x80) {
        unsigned long long v = f[0] & 0x7f;
        for (size_t i = 1; i < n; i++) {
            if (v >> 55) return -1;
            v = v << 8 | f[i];
        }
        return (long long)v;
    }
    unsigned long long v = 0;
    size_t i = 0;
    while (i < n && f[i] == ' ') i++;
    int digits = 0;
    for (; i < n && f[i] >= '0' && f[i] <= '7'; i++) {
        if (v >> 60) return -1;
        v = v << 3 | (unsigned)(f[i] - '0');
        digits++;
    }
    for (; i < n; i++) if (f[i] != ' ' && f[i] != 0) return -1;
    return digits ? (long long)v : -1;
}

static int checksum_ok(const unsigned char *h) {
    long long want = field_num(h + 148, 8);
    if (want < 0) return 0;
    unsigned long sum = 0;
    for (int i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? ' ' : h[i];
    return sum == (unsigned long)want;
}

/* Растущий буфер для длинных имён и pax. */
struct buf {
    char *p;
    size_t n;
};

/* Прочитать size байт данных записи в b (с нулём в конце) и пропустить добивку до 512. */
static int read_blob(struct rd *r, unsigned long long size, struct buf *b) {
    free(b->p);
    b->p = NULL;
    b->n = 0;
    size_t cap = 0;
    unsigned long long left = size;
    while (left) {
        size_t want = left < 65536 ? (size_t)left : 65536;
        if (b->n + want + 1 > cap) {
            size_t nc = (b->n + want + 1) * 2;
            char *np = realloc(b->p, nc);
            if (!np) return UNTAR_ENOMEM;
            b->p = np;
            cap = nc;
        }
        long k = rd_exact(r, (unsigned char *)b->p + b->n, want);
        if (k < 0) return UNTAR_EGZ;
        if ((size_t)k < want) return UNTAR_EFORMAT;
        b->n += want;
        left -= want;
    }
    if (!b->p) {
        b->p = calloc(1, 1);
        if (!b->p) return UNTAR_ENOMEM;
    }
    b->p[b->n] = 0;
    int sk = rd_skip(r, (512 - size % 512) % 512);
    return sk < 0 ? UNTAR_EGZ : sk ? UNTAR_EFORMAT : 0;
}

/* pax: «<длина> <ключ>=<значение>\n» подряд. Достаём path, linkpath, size; остальное не нужно. */
static int pax_parse(const struct buf *b, char **path, char **link, long long *size) {
    size_t off = 0;
    while (off < b->n) {
        size_t len = 0, i = off;
        while (i < b->n && b->p[i] >= '0' && b->p[i] <= '9') {
            len = len * 10 + (size_t)(b->p[i] - '0');
            if (len > b->n) return UNTAR_EFORMAT;
            i++;
        }
        if (i == off || i >= b->n || b->p[i] != ' ' || len > b->n - off || len < (i - off) + 3) return UNTAR_EFORMAT;
        char *rec = b->p + i + 1;
        size_t rl = len - (i - off) - 1;                   /* ключ=значение\n */
        if (rec[rl - 1] != '\n') return UNTAR_EFORMAT;
        rec[rl - 1] = 0;
        char *eq = strchr(rec, '=');
        if (eq) {
            *eq = 0;
            const char *v = eq + 1;
            if (!strcmp(rec, "path")) { free(*path); *path = strdup(v); if (!*path) return UNTAR_ENOMEM; }
            else if (!strcmp(rec, "linkpath")) { free(*link); *link = strdup(v); if (!*link) return UNTAR_ENOMEM; }
            else if (!strcmp(rec, "size")) {
                char *e;
                errno = 0;
                long long s = strtoll(v, &e, 10);
                if (errno || *e || s < 0) return UNTAR_EFORMAT;
                *size = s;
            }
        }
        off += len;
    }
    return 0;
}

/* ---- пути ------------------------------------------------------------------------------------- */

/* Нормализовать путь записи: без пустых компонент и «.», «..» и начальный «/» — отказ. Результат —
 * malloc. Пустой результат (сам корень: «./», «.») отдаётся как "" — каталог корня не трогаем. */
static int norm_path(const char *in, char **out) {
    if (in[0] == '/') return UNTAR_EPATH;
    size_t l = strlen(in);
    char *o = malloc(l + 1);
    if (!o) return UNTAR_ENOMEM;
    size_t w = 0;
    const char *p = in;
    while (*p) {
        const char *e = strchr(p, '/');
        size_t cl = e ? (size_t)(e - p) : strlen(p);
        if (cl == 2 && p[0] == '.' && p[1] == '.') { free(o); return UNTAR_EPATH; }
        if (cl && !(cl == 1 && p[0] == '.')) {
            if (w) o[w++] = '/';
            memcpy(o + w, p, cl);
            w += cl;
        }
        p = e ? e + 1 : p + cl;
    }
    o[w] = 0;
    *out = o;
    return 0;
}

/* Цель символьной ссылки: относительная, непустая, без «..». */
static int link_ok(const char *t) {
    if (!*t || t[0] == '/') return 0;
    const char *p = t;
    while (*p) {
        const char *e = strchr(p, '/');
        size_t cl = e ? (size_t)(e - p) : strlen(p);
        if (cl == 2 && p[0] == '.' && p[1] == '.') return 0;
        p = e ? e + 1 : p + cl;
    }
    return 1;
}

/* Дойти до каталога, где лежит последняя компонента rel, создавая недостающие (0755) и не следуя за
 * ссылками. Возвращает дескриптор каталога (>= 0) и в *leaf — последнюю компоненту (внутри rel,
 * который портится: '/' заменяются нулями). Отрицательное — код untar. */
static int walk_parent(int root, char *rel, const char **leaf) {
    int cur = dup(root);
    if (cur < 0) return UNTAR_EIO;
    char *p = rel;
    for (;;) {
        char *e = strchr(p, '/');
        if (!e) { *leaf = p; return cur; }
        *e = 0;
        int nx = openat(cur, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (nx < 0 && errno == ENOENT) {
            if (mkdirat(cur, p, 0755) != 0 && errno != EEXIST) { close(cur); return UNTAR_EIO; }
            nx = openat(cur, p, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }
        close(cur);
        if (nx < 0) return (errno == ELOOP || errno == ENOTDIR) ? UNTAR_EPATH : UNTAR_EIO;
        cur = nx;
        p = e + 1;
    }
}

/* ---- распаковка ------------------------------------------------------------------------------- */

struct dirmode {
    char *path;
    unsigned mode;
};

struct ctx {
    struct rd *r;
    int root;
    const struct untar_opts *o;
    char *why;
    size_t wn;
    unsigned long long total;
    struct dirmode *dirs;
    size_t ndirs, capdirs;
};

static int note_dir(struct ctx *c, const char *rel, unsigned mode) {
    if (c->ndirs == c->capdirs) {
        size_t nc = c->capdirs ? c->capdirs * 2 : 16;
        struct dirmode *nd = realloc(c->dirs, nc * sizeof *nd);
        if (!nd) return UNTAR_ENOMEM;
        c->dirs = nd;
        c->capdirs = nc;
    }
    char *d = strdup(rel);
    if (!d) return UNTAR_ENOMEM;
    c->dirs[c->ndirs].path = d;
    c->dirs[c->ndirs].mode = mode;
    c->ndirs++;
    return 0;
}

static int emit(struct ctx *c, const struct untar_entry *e) {
    if (c->o && c->o->cb && c->o->cb(c->o->arg, e) != 0) {
        if (c->why && c->wn) snprintf(c->why, c->wn, "распаковку прервал вызывающий на «%s»", e->path);
        return UNTAR_ECB;
    }
    return 0;
}

/* Одна запись. hdr — заголовок; path/link — уже с учётом длинных имён и pax; size — с учётом pax. */
static int extract(struct ctx *c, int type, const char *rawpath, const char *rawlink, unsigned mode,
                   unsigned long long size) {
    char *rel = NULL;
    int rc = norm_path(rawpath, &rel);
    if (rc == UNTAR_EPATH) {
        if (c->why && c->wn) snprintf(c->why, c->wn, "путь «%.200s» выходит за каталог распаковки", rawpath);
        return rc;
    }
    if (rc) return rc;
    if (!*rel) {
        /* Корень («./»): не запись. Допустим только каталогом. */
        free(rel);
        if (type != UNTAR_DIR) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "запись без имени файла");
            return UNTAR_EPATH;
        }
        int sk = rd_skip(c->r, (size + 511) / 512 * 512);
        return sk < 0 ? UNTAR_EGZ : sk ? UNTAR_EFORMAT : 0;
    }
    struct untar_entry e = { .path = rel, .type = type, .mode = mode & 0777, .rawmode = mode & 07777 };
    char *work = strdup(rel);
    if (!work) { free(rel); return UNTAR_ENOMEM; }
    const char *leaf = NULL;
    int dfd = walk_parent(c->root, work, &leaf);
    if (dfd < 0) {
        if (dfd == UNTAR_EPATH && c->why && c->wn)
            snprintf(c->why, c->wn, "путь «%.200s» идёт сквозь символьную ссылку или файл", rel);
        else if (c->why && c->wn) snprintf(c->why, c->wn, "каталог для «%.200s»: %s", rel, strerror(errno));
        rc = dfd;
        goto out;
    }
    if (type == UNTAR_DIR) {
        if (mkdirat(dfd, leaf, 0755) != 0) {
            struct stat st;
            if (errno != EEXIST || fstatat(dfd, leaf, &st, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISDIR(st.st_mode)) {
                if (c->why && c->wn) snprintf(c->why, c->wn, "каталог «%.200s»: %s", rel, strerror(errno));
                rc = UNTAR_EIO;
                goto out_fd;
            }
        }
        rc = note_dir(c, rel, e.mode);
        if (!rc) {
            int sk = rd_skip(c->r, (size + 511) / 512 * 512);
            rc = sk < 0 ? UNTAR_EGZ : sk ? UNTAR_EFORMAT : 0;
        }
        if (!rc) rc = emit(c, &e);
    } else if (type == UNTAR_SYMLINK) {
        if (!rawlink || !link_ok(rawlink)) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "ссылка «%.200s» ведёт наружу или вверх: «%.200s»", rel, rawlink ? rawlink : "");
            rc = UNTAR_EPATH;
            goto out_fd;
        }
        if (symlinkat(rawlink, dfd, leaf) != 0) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "ссылка «%.200s»: %s", rel, strerror(errno));
            rc = UNTAR_EIO;
            goto out_fd;
        }
        e.link = rawlink;
        int sk = rd_skip(c->r, (size + 511) / 512 * 512);
        rc = sk < 0 ? UNTAR_EGZ : sk ? UNTAR_EFORMAT : 0;
        if (!rc) rc = emit(c, &e);
    } else {
        e.size = size;
        c->total += size;
        if (c->o && c->o->max_bytes && (c->total < size || c->total > c->o->max_bytes)) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "архив больше допустимого (%llu байт)", c->o->max_bytes);
            rc = UNTAR_EBIG;
            goto out_fd;
        }
        int fd = openat(dfd, leaf, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "файл «%.200s»: %s", rel, strerror(errno));
            rc = (errno == ELOOP) ? UNTAR_EPATH : UNTAR_EIO;
            goto out_fd;
        }
        struct sc_hash_ctx h;
        if (sc_hash_init(&h, SC_SHA256) != 0) { close(fd); rc = UNTAR_ENOMEM; goto out_fd; }
        unsigned char *buf = malloc(65536);
        if (!buf) { sc_hash_free(&h); close(fd); rc = UNTAR_ENOMEM; goto out_fd; }
        unsigned long long left = size;
        while (left && !rc) {
            size_t want = left < 65536 ? (size_t)left : 65536;
            long k = rd_exact(c->r, buf, want);
            if (k < 0) { rc = UNTAR_EGZ; break; }
            if ((size_t)k < want) { rc = UNTAR_EFORMAT; break; }
            sc_hash_update(&h, buf, want);
            for (size_t w = 0; w < want;) {
                ssize_t wr = write(fd, buf + w, want - w);
                if (wr < 0 && errno == EINTR) continue;
                if (wr <= 0) {
                    if (c->why && c->wn) snprintf(c->why, c->wn, "запись «%.200s»: %s", rel, strerror(errno));
                    rc = UNTAR_EIO;
                    break;
                }
                w += (size_t)wr;
            }
            left -= want;
        }
        free(buf);
        sc_hash_final(&h, e.sha256);
        sc_hash_free(&h);
        if (!rc && fchmod(fd, e.mode) != 0) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "права «%.200s»: %s", rel, strerror(errno));
            rc = UNTAR_EIO;
        }
        if (close(fd) != 0 && !rc) {
            if (c->why && c->wn) snprintf(c->why, c->wn, "закрытие «%.200s»: %s", rel, strerror(errno));
            rc = UNTAR_EIO;
        }
        if (!rc) {
            int sk = rd_skip(c->r, (512 - size % 512) % 512);
            rc = sk < 0 ? UNTAR_EGZ : sk ? UNTAR_EFORMAT : 0;
        }
        if (!rc) rc = emit(c, &e);
    }
out_fd:
    close(dfd);
out:
    free(work);
    free(rel);
    return rc;
}

static int run(struct rd *r, const char *dest, const struct untar_opts *o, char *why, size_t wn) {
    if (why && wn) why[0] = 0;
    if (mkdir(dest, 0755) != 0 && errno != EEXIST) { WHY("каталог %s: %s", dest, strerror(errno)); return UNTAR_EIO; }
    int root = open(dest, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) { WHY("каталог %s: %s", dest, strerror(errno)); return UNTAR_EIO; }
    struct ctx c = { .r = r, .root = root, .o = o, .why = why, .wn = wn };
    struct buf lname = {0}, llink = {0}, pax = {0};
    char *ppath = NULL, *plink = NULL;
    long long psize = -1;
    int rc = 0, ended = 0;

    for (;;) {
        unsigned char h[512];
        long k = rd_exact(r, h, sizeof h);
        if (k < 0) { rc = UNTAR_EGZ; break; }
        if (k == 0) { ended = 1; break; }                        /* конец входа на границе блока без нулевых блоков */
        if (k < 512) { WHY("tar оборван в заголовке"); rc = UNTAR_EFORMAT; break; }
        if (all_zero(h, 512)) { ended = 1; break; }
        if (!checksum_ok(h)) { WHY("заголовок tar с неверной контрольной суммой"); rc = UNTAR_EFORMAT; break; }
        long long sz = field_num(h + 124, 12);
        long long mode = field_num(h + 100, 8);
        if (sz < 0 || mode < 0) { WHY("заголовок tar: размер или права не разобрались"); rc = UNTAR_EFORMAT; break; }
        int tf = h[156] ? h[156] : '0';

        if (tf == 'L' || tf == 'K' || tf == 'x' || tf == 'g') {
            struct buf *dst = tf == 'L' ? &lname : tf == 'K' ? &llink : &pax;
            rc = read_blob(r, (unsigned long long)sz, dst);
            if (rc) { if (rc == UNTAR_EFORMAT) WHY("tar оборван в служебной записи"); break; }
            if (tf == 'x') {
                rc = pax_parse(&pax, &ppath, &plink, &psize);
                if (rc) { if (rc == UNTAR_EFORMAT) WHY("заголовок pax не разобрался"); break; }
            } else if (tf == 'g') {
                free(pax.p); pax.p = NULL; pax.n = 0;            /* глобальные значения не используются */
            }
            continue;
        }

        /* Имя: GNU-длинное, pax или ustar (префикс + имя). */
        char namebuf[100 + 1 + 155 + 1];
        const char *name = namebuf;
        if (ppath) name = ppath;
        else if (lname.p) name = lname.p;
        else {
            size_t nl = strnlen((char *)h, 100), pl = 0;
            if (!memcmp(h + 257, "ustar", 5)) pl = strnlen((char *)h + 345, 155);
            size_t w = 0;
            if (pl) { memcpy(namebuf, h + 345, pl); w = pl; namebuf[w++] = '/'; }
            memcpy(namebuf + w, h, nl);
            namebuf[w + nl] = 0;
        }
        char linkbuf[101];
        const char *link = linkbuf;
        if (plink) link = plink;
        else if (llink.p) link = llink.p;
        else { size_t ll = strnlen((char *)h + 157, 100); memcpy(linkbuf, h + 157, ll); linkbuf[ll] = 0; }
        unsigned long long size = psize >= 0 ? (unsigned long long)psize : (unsigned long long)sz;

        int type;
        size_t nlen = strlen(name);
        switch (tf) {
        case '0': case '7':
            type = (nlen && name[nlen - 1] == '/' && size == 0) ? UNTAR_DIR : UNTAR_FILE;   /* старые tar: каталог без типа 5 */
            break;
        case '5': type = UNTAR_DIR; break;
        case '2':
            if (o && (o->flags & UNTAR_NO_LINKS)) {
                WHY("запись «%.100s»: символьные ссылки в пакете недопустимы", name);
                rc = UNTAR_ETYPE;
                goto done;
            }
            type = UNTAR_SYMLINK;
            break;
        default:
            WHY("запись «%.100s»: тип %c не поддержан (жёсткие ссылки и устройства в пакете недопустимы)", name, (tf >= 32 && tf < 127) ? tf : '?');
            rc = UNTAR_ETYPE;
            goto done;
        }
        if (type == UNTAR_FILE && nlen && name[nlen - 1] == '/') {
            WHY("запись «%.100s»: файл с именем каталога", name);
            rc = UNTAR_EFORMAT;
            break;
        }
        rc = extract(&c, type, name, link, (unsigned)mode, size);
        free(lname.p); lname.p = NULL; lname.n = 0;
        free(llink.p); llink.p = NULL; llink.n = 0;
        free(ppath); ppath = NULL;
        free(plink); plink = NULL;
        psize = -1;
        if (rc) break;
    }
done:
    /* Конец архива: для gzip дочитываем до хвоста — CRC-32 сверяется только там, и «тар кончился»
     * без «gzip сошёлся» не успех. */
    if (!rc && ended && r->g) {
        unsigned char sink[4096];
        long k;
        int strict = o && (o->flags & UNTAR_STRICT_END);
        while ((k = gz_read(r->g, sink, sizeof sink)) > 0)
            if (strict && !all_zero(sink, (size_t)k)) { WHY("после конца tar лежат данные"); rc = UNTAR_EFORMAT; break; }
        if (k < 0) rc = UNTAR_EGZ;
        else if (!rc && strict && gz_trailing(r->g)) { WHY("после gzip лежат лишние байты"); rc = UNTAR_EGZ; }
    } else if (!rc && ended && !r->g && o && (o->flags & UNTAR_STRICT_END) && !all_zero(r->mem + r->pos, r->memn - r->pos)) {
        WHY("после конца tar лежат данные");
        rc = UNTAR_EFORMAT;
    }
    /* Права каталогов — от глубоких к мелким, после того как всё лежит на месте. */
    if (!rc)
        for (size_t i = c.ndirs; i-- > 0;)
            if (fchmodat(root, c.dirs[i].path, c.dirs[i].mode, 0) != 0) {
                WHY("права каталога «%.200s»: %s", c.dirs[i].path, strerror(errno));
                rc = UNTAR_EIO;
                break;
            }
    if (why && wn && !why[0]) {
        if (rc == UNTAR_EGZ) WHY("gzip испорчен или оборван");
        else if (rc == UNTAR_EFORMAT) WHY("tar оборван посреди записи");
        else if (rc == UNTAR_ENOMEM) WHY("не хватило памяти");
    }
    for (size_t i = 0; i < c.ndirs; i++) free(c.dirs[i].path);
    free(c.dirs);
    free(lname.p); free(llink.p); free(pax.p); free(ppath); free(plink);
    close(root);
    return rc;
}

int untar_gz(const void *gzdata, size_t n, const char *dest, const struct untar_opts *o, char *why, size_t wn) {
    struct gz *g = gz_open(gzdata, n);
    if (!g) { WHY("это не gzip"); return UNTAR_EGZ; }
    struct rd r = { .g = g };
    int rc = run(&r, dest, o, why, wn);
    gz_close(g);
    return rc;
}

int untar_gz_file(const char *path, const char *dest, const struct untar_opts *o, char *why, size_t wn) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) { WHY("%s: %s", path, strerror(errno)); if (fd >= 0) close(fd); return UNTAR_EIO; }
    if (st.st_size <= 0) { close(fd); WHY("%s: пустой файл", path); return UNTAR_EGZ; }
    void *m = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (m == MAP_FAILED) { WHY("%s: %s", path, strerror(errno)); return UNTAR_EIO; }
    int rc = untar_gz(m, (size_t)st.st_size, dest, o, why, wn);
    munmap(m, (size_t)st.st_size);
    return rc;
}

int untar_mem(const void *tar, size_t n, const char *dest, const struct untar_opts *o, char *why, size_t wn) {
    struct rd r = { .mem = tar, .memn = n };
    return run(&r, dest, o, why, wn);
}
