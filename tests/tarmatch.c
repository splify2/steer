/* Распаковка ustar+gzip (src/lib/untar.c, gz.c): стенд против настоящих архивов.
 *
 * Векторы — tests/tarvec: хорошие архивы собраны модулем tarfile трёх форматов (ustar с префиксом,
 * GNU с длинными именами, pax), плохие — те же средства с именами «../», «/abs», ссылками наружу,
 * записью сквозь ссылку, жёсткой ссылкой, устройством; порченые — сумма заголовка, обрыв, CRC и
 * длина gzip (tests/tarvec/gen.py). Содержимое big.bin считается здесь той же формулой, что и в
 * gen.py, а ожидаемый SHA-256 — независимой реализацией (steer_sha256 из src/tools/hwid.c), не
 * той, что внутри распаковщика.
 *
 * Хеш файлов внутри распаковщика — sc_hash_* слоя scrypto. В make test криптобиблиотеки нет, поэтому
 * стенд подставляет свои sc_hash_* (копят вход и считают тем же steer_sha256); в make ext-test стенд
 * собирается с настоящим слоем (без TAR_STUB_HASH), и тогда проверяется ещё и он. Рабочий каталог —
 * корень дерева. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <ftw.h>
#include <sys/stat.h>
#include "unit.h"
#include "untar.h"
#include "gz.h"
#include "hwid.h"

#ifdef TAR_STUB_HASH
#include "scrypto.h"
struct stubh { unsigned char *b; size_t n, cap; };
int sc_hash_init(struct sc_hash_ctx *c, enum sc_hash h) {
    (void)h;
    struct stubh *s = (struct stubh *)c->st;
    memset(s, 0, sizeof *s);
    c->alg = SC_SHA256;
    return 0;
}
int sc_hash_update(struct sc_hash_ctx *c, const void *d, size_t n) {
    struct stubh *s = (struct stubh *)c->st;
    if (s->n + n > s->cap) { s->cap = (s->n + n) * 2; s->b = realloc(s->b, s->cap); }
    memcpy(s->b + s->n, d, n);
    s->n += n;
    return 0;
}
int sc_hash_final(struct sc_hash_ctx *c, unsigned char *out) {
    struct stubh *s = (struct stubh *)c->st;
    steer_sha256(s->b ? s->b : (const unsigned char *)"", s->n, out);
    return 0;
}
void sc_hash_free(struct sc_hash_ctx *c) {
    struct stubh *s = (struct stubh *)c->st;
    free(s->b);
    memset(s, 0, sizeof *s);
}
#endif

static unsigned char *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { *n = (size_t)-1; return NULL; }
    size_t cap = 4096, len = 0, got;
    unsigned char *b = malloc(cap);
    while ((got = fread(b + len, 1, cap - len, f)) > 0) {
        len += got;
        if (len == cap) b = realloc(b, cap *= 2);
    }
    fclose(f);
    *n = len;
    return b;
}

static int rmone(const char *p, const struct stat *st, int fl, struct FTW *w) {
    (void)st; (void)fl; (void)w;
    if (fl == FTW_D || fl == FTW_DP) chmod(p, 0755);
    return remove(p);
}
static void rmtree(const char *p) { nftw(p, rmone, 16, FTW_DEPTH | FTW_PHYS); }

static char base[128];
static char dst[256];

/* Свежий dest внутри base, имя — по счётчику. dst — каталог распаковки. */
static const char *fresh(void) {
    static int n;
    snprintf(dst, sizeof dst, "%s/d%d", base, ++n);
    return dst;
}

static int exists(const char *rel) {
    char p[512];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", dst, rel);
    return lstat(p, &st) == 0;
}

static int mode_of(const char *rel) {
    char p[512];
    struct stat st;
    snprintf(p, sizeof p, "%s/%s", dst, rel);
    return lstat(p, &st) == 0 ? (int)(st.st_mode & 07777) : -1;
}

static int content_is(const char *rel, const void *want, size_t wn) {
    char p[512];
    snprintf(p, sizeof p, "%s/%s", dst, rel);
    size_t n;
    unsigned char *b = slurp(p, &n);
    int ok = b && n == wn && !memcmp(b, want, wn);
    free(b);
    return ok;
}


#define MAXE 64
static struct { char path[300]; int type; unsigned mode; unsigned long long size; unsigned char sha[32]; char link[300]; } g_e[MAXE];
static int g_n, g_abort_at = -1;

static int cb(void *arg, const struct untar_entry *e) {
    (void)arg;
    if (g_n < MAXE) {
        snprintf(g_e[g_n].path, sizeof g_e[g_n].path, "%s", e->path);
        g_e[g_n].type = e->type;
        g_e[g_n].mode = e->mode;
        g_e[g_n].size = e->size;
        memcpy(g_e[g_n].sha, e->sha256, 32);
        snprintf(g_e[g_n].link, sizeof g_e[g_n].link, "%s", e->link ? e->link : "");
    }
    g_n++;
    return g_abort_at >= 0 && g_n - 1 == g_abort_at;
}

static int find(const char *path) {
    for (int i = 0; i < g_n && i < MAXE; i++) if (!strcmp(g_e[i].path, path)) return i;
    return -1;
}

static int run_file(const char *vec, const struct untar_opts *o, char *why, size_t wn) {
    char p[256];
    snprintf(p, sizeof p, "tests/tarvec/%s", vec);
    g_n = 0;
    return untar_gz_file(p, fresh(), o, why, wn);
}

static void pattern(unsigned char *b, size_t n) {
    for (size_t i = 0; i < n; i++) b[i] = (unsigned char)((i * 31 + 7) & 0xff);
}

/* Хороший архив: что разложилось и что увидел обратный вызов. */
static void check_good(const char *label) {
    char what[160];
    #define C(txt, w, g) do { snprintf(what, sizeof what, "%s: %s", label, txt); check(what, w, g); } while (0)
    C("plugin.json", 1, content_is("plugin.json", "{\"name\":\"demo\"}\n", 16));
    C("bin/run.sh содержимое", 1, content_is("bin/run.sh", "#!/bin/sh\necho hi\n", 18));
    C("bin/run.sh режим 0755", 0755, mode_of("bin/run.sh"));
    C("plugin.json режим 0644", 0644, mode_of("plugin.json"));
    C("empty режим 0600", 0600, mode_of("empty"));
    C("sub/deep/er/file.txt (родители созданы)", 1, content_is("sub/deep/er/file.txt", "deep\n", 5));
    C("setuid-бит не перенесён (0755)", 0755, mode_of("setuid.sh"));
    C("locked/inside.txt лёг в каталог 0500", 1, content_is("locked/inside.txt", "in a read-only dir\n", 19));
    C("locked режим выставлен в конце (0500)", 0500, mode_of("locked"));
    C("locked/inside.txt режим 0444", 0444, mode_of("locked/inside.txt"));
    char t[300];
    ssize_t k = readlink((snprintf(t, sizeof t, "%s/link-to-file", dst), t), t, sizeof t - 1);
    if (k >= 0) t[k] = 0; else t[0] = 0;
    C("ссылка link-to-file -> plugin.json", 0, strcmp(t, "plugin.json"));
    snprintf(t, sizeof t, "%s/link-to-dir/er/file.txt", dst);
    size_t n;
    unsigned char *b = slurp(t, &n);
    C("файл виден через ссылку на каталог", 1, b && n == 5);
    free(b);

    unsigned char *big = malloc(1500000), want[32];
    pattern(big, 1500000);
    steer_sha256(big, 1500000, want);
    C("big.bin содержимое (1,5 МБ через окно DEFLATE)", 1, content_is("big.bin", big, 1500000));
    free(big);
    int i = find("big.bin");
    C("обратный вызов: big.bin есть", 1, i >= 0);
    if (i >= 0) {
        C("big.bin: размер", 1500000, (long)g_e[i].size);
        C("big.bin: SHA-256 независимой реализацией", 0, memcmp(g_e[i].sha, want, 32));
        C("big.bin: тип файл", UNTAR_FILE, g_e[i].type);
    }
    unsigned char e0[32];
    steer_sha256((const unsigned char *)"", 0, e0);
    i = find("empty");
    C("empty: SHA-256 пустого", 1, i >= 0 && !memcmp(g_e[i].sha, e0, 32));
    i = find("link-to-file");
    C("обратный вызов: ссылка с целью", 1, i >= 0 && g_e[i].type == UNTAR_SYMLINK && !strcmp(g_e[i].link, "plugin.json"));
    i = find("bin");
    C("обратный вызов: каталог bin", 1, i >= 0 && g_e[i].type == UNTAR_DIR && g_e[i].mode == 0755);
    C("корень «./» не запись", -1, find(""));
    C("нет путей с «./»", -1, find("./plugin.json"));
    C("setuid.sh: режим в вызове без бита", 0755, (int)g_e[find("setuid.sh")].mode);
    C("всего записей (родители файлов — не записи)", 11, g_n);
    #undef C
}

int main(void) {
    snprintf(base, sizeof base, "/tmp/tarmatch.XXXXXX");
    if (!mkdtemp(base)) { perror("mkdtemp"); return 2; }
    char why[300];
    struct untar_opts o = { .cb = cb };

    /* ---- хороший архив: файлом (mmap), памятью gzip, памятью tar ------------------------------------ */
    check("good.tar.gz файлом", 0, run_file("good.tar.gz", &o, why, sizeof why));
    check_good("файл");

    {
        size_t n;
        unsigned char *z = slurp("tests/tarvec/good.tar.gz", &n);
        g_n = 0;
        check("good.tar.gz из памяти", 0, untar_gz(z, n, fresh(), &o, why, sizeof why));
        check_good("память gz");

        /* Тот же tar без gzip: распаковать gzip тем же gz_* и скормить untar_mem. */
        struct gz *g = gz_open(z, n);
        size_t cap = 1 << 20, tn = 0;
        unsigned char *tar = malloc(cap);
        long k;
        while ((k = gz_read(g, tar + tn, cap - tn)) > 0) {
            tn += (size_t)k;
            if (tn == cap) tar = realloc(tar, cap *= 2);
        }
        check("gz_read: поток кончился и хвост сошёлся", 0, k);
        gz_close(g);
        g_n = 0;
        check("несжатый tar из памяти", 0, untar_mem(tar, tn, fresh(), &o, why, sizeof why));
        check_good("память tar");
        /* Без обратного вызова. */
        check("без обратного вызова", 0, untar_mem(tar, tn, fresh(), NULL, why, sizeof why));
        free(tar);
        free(z);
    }

    /* ---- длинные имена ---------------------------------------------------------------------- */
    {
        char l100[200], l300[600];
        snprintf(l100, sizeof l100, "%s/%s/file-with-a-long-name.txt",
                 "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
                 "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");
        l300[0] = 0;
        for (int i = 0; i < 30; i++) { char s[32]; snprintf(s, sizeof s, "segment%03d/", i); strcat(l300, s); }
        strcat(l300, "leaf.txt");
        check("ustar с префиксом (путь > 100 знаков)", 0, run_file("long-ustar.tar.gz", &o, why, sizeof why));
        check("  файл на месте", 1, content_is(l100, "prefix\n", 7));
        check("GNU длинные имена (L, K)", 0, run_file("long-gnu.tar.gz", &o, why, sizeof why));
        check("  файл на месте (путь > 300)", 1, content_is(l300, "gnu\n", 4));
        char t[400];
        snprintf(t, sizeof t, "%s/s", dst);
        char lt[400];
        ssize_t k = readlink(t, lt, sizeof lt - 1);
        check("  ссылка с целью 150 знаков (K)", 150, k);
        check("pax (path)", 0, run_file("long-pax.tar.gz", &o, why, sizeof why));
        check("  файл на месте (путь > 300)", 1, content_is(l300, "pax\n", 4));
    }

    /* ---- защита пути и ссылок ------------------------------------------------------------------ */
    struct { const char *vec; int rc; const char *note; } bad[] = {
        { "dotdot.tar.gz",        UNTAR_EPATH, "«../evil.txt»" },
        { "dotdot-mid.tar.gz",    UNTAR_EPATH, "«a/../../evil.txt»" },
        { "dotdot-dir.tar.gz",    UNTAR_EPATH, "каталог «../evildir»" },
        { "abs.tar.gz",           UNTAR_EPATH, "абсолютный путь" },
        { "link-abs.tar.gz",      UNTAR_EPATH, "ссылка на /etc" },
        { "link-up.tar.gz",       UNTAR_EPATH, "ссылка «../outside»" },
        { "link-up-mid.tar.gz",   UNTAR_EPATH, "ссылка «a/../../outside»" },
        { "link-then-file.tar.gz",UNTAR_EPATH, "файл сквозь ссылку на каталог" },
        { "link-then-dir.tar.gz", UNTAR_EPATH, "каталог сквозь ссылку" },
        { "hardlink.tar.gz",      UNTAR_ETYPE, "жёсткая ссылка" },
        { "chardev.tar.gz",       UNTAR_ETYPE, "устройство" },
        { "fifo.tar.gz",          UNTAR_ETYPE, "очередь" },
        { "dup.tar.gz",           UNTAR_EIO,   "тот же файл дважды (O_EXCL)" },
        { "badsum.tar.gz",        UNTAR_EFORMAT, "контрольная сумма заголовка" },
        { "cut.tar.gz",           UNTAR_EFORMAT, "обрыв внутри данных файла" },
        { "cut-hdr.tar.gz",       UNTAR_EFORMAT, "обрыв внутри заголовка" },
        { "badcrc.tar.gz",        UNTAR_EGZ,   "CRC-32 gzip" },
        { "badlen.tar.gz",        UNTAR_EGZ,   "длина в хвосте gzip" },
        { "cut-gz.tar.gz",        UNTAR_EGZ,   "обрыв gzip" },
        { "notgz.tar.gz",         UNTAR_EGZ,   "не gzip" },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char what[160];
        snprintf(what, sizeof what, "отказ: %s", bad[i].note);
        check(what, bad[i].rc, run_file(bad[i].vec, &o, why, sizeof why));
        if (bad[i].rc != UNTAR_EGZ || strcmp(bad[i].vec, "notgz.tar.gz"))
            { char w[200]; snprintf(w, sizeof w, "  причина названа словами (%s)", bad[i].vec); check(w, 1, why[0] != 0); }
    }
    {
        char p[300];
        snprintf(p, sizeof p, "%s/evil.txt", base);
        check("  base/evil.txt нет", -1, access(p, F_OK));
        snprintf(p, sizeof p, "%s/evildir", base);
        check("  base/evildir нет", -1, access(p, F_OK));
        check("  /tmp/steer-untar-evil.txt нет", -1, access("/tmp/steer-untar-evil.txt", F_OK));
        snprintf(p, sizeof p, "%s/outside", base);
        check("  base/outside нет", -1, access(p, F_OK));
    }
    /* Ссылка внутри архива не помогла писать сквозь неё: real/ пуст. */
    {
        run_file("link-then-file.tar.gz", &o, why, sizeof why);
        check("link-then-file: real/f.txt не создан", 0, exists("real/f.txt"));
    }

    /* ---- прерывание вызывающим, предел, существующий файл ---------------------------------------- */
    g_abort_at = 1;
    check("обратный вызов прерывает на второй записи", UNTAR_ECB, run_file("two.tar.gz", &o, why, sizeof why));
    g_abort_at = -1;
    check("  первый файл уже на диске", 1, exists("a.txt"));
    check("  причина называет запись", 1, strstr(why, "b.txt") != NULL);
    {
        struct untar_opts lim = { .cb = cb, .max_bytes = 1000 };
        check("max_bytes меньше суммы — отказ", UNTAR_EBIG, run_file("good.tar.gz", &lim, why, sizeof why));
        lim.max_bytes = 2000000;
        check("max_bytes больше суммы — распаковано", 0, run_file("good.tar.gz", &lim, why, sizeof why));
        lim.max_bytes = 12;
        check("max_bytes = 12 при 13 байтах в two — отказ", UNTAR_EBIG, run_file("two.tar.gz", &lim, why, sizeof why));
        lim.max_bytes = 13;
        check("max_bytes = 13 при 13 байтах в two — можно", 0, run_file("two.tar.gz", &lim, why, sizeof why));
    }
    {
        /* Распаковка в каталог, где файл уже есть. */
        const char *d = fresh();
        mkdir(d, 0755);
        char p[300];
        snprintf(p, sizeof p, "%s/a.txt", d);
        FILE *f = fopen(p, "w");
        fputs("old", f);
        fclose(f);
        check("существующий файл не перезаписывается", UNTAR_EIO,
              untar_gz_file("tests/tarvec/two.tar.gz", d, NULL, why, sizeof why));
        size_t n;
        unsigned char *b = slurp(p, &n);
        check("  старое содержимое цело", 1, b && n == 3 && !memcmp(b, "old", 3));
        free(b);
        /* Существующий каталог в пути — можно. */
        check("распаковка в уже существующий каталог (пустой)", 0,
              untar_gz_file("tests/tarvec/long-pax.tar.gz", (mkdir((snprintf(p, sizeof p, "%s/pre", base), p), 0755), p), NULL, why, sizeof why));
    }
    check("несуществующий файл архива", UNTAR_EIO, untar_gz_file("tests/tarvec/нет", fresh(), NULL, why, sizeof why));

    rmtree(base);
    return unit_done("tarmatch");
}
