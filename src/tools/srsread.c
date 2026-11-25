/* `steer srs-read` — набор правил sing-box нашим синтаксисом списка, через тот же читатель,
 * которым набор читают компилятор и резолвер (src/model/srs.c, там же — формат и соответствие
 * видов элементов нашему синтаксису).
 *
 * Вывод прежний до байта (стенд tests/srsmatch.sh): домены и подсети — в порядке файла, по
 * строке на элемент; сужение — третьим потоком, ОДНО на весь набор (протоколы и порты всех
 * правил вместе), в виде `proto=` и `ports=`, готовом к переносу в канал.
 *
 * ПОЧЕМУ СУЖЕНИЕ ОТДЕЛЬНЫМ ПОТОКОМ, а не строкой в списке. Список читают dnsd и компилятор
 * набора правил, и обоим `proto=udp` — мусор: первый сочтёт это доменным правилом, второй
 * пропустит как не-адрес. Сужение принадлежит каналу, а не списку.
 *
 * ЧЕГО ТРИ ФАЙЛА НЕ ВЫРАЖАЮТ (и отвергается кодом 2): исключения («x.com, но не y.x.com»),
 * ограничение по клиенту (source_ip_cidr) и по приложению (package_name). Канал с `srs_files`
 * выражает и это — поэтому, а не ради команды, набор теперь подключается к каналу сам. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#include "srs.h"
#include "srsread.h"

#define META_PORT_LEN  16

struct out {
    FILE *dom, *pfx;
    int saw_v6;
};

static int print_elem(void *ctx, const struct srs_elem *el) {
    struct out *o = ctx;
    if (el->kind == SRS_EL_DOMAIN) {
        switch (el->dom) {
        case SRS_DOM_SUFFIX:   fprintf(o->dom, "%s\n", el->str); break;   /* имя и поддомены */
        case SRS_DOM_WILDCARD: fprintf(o->dom, "*%s\n", el->str); break;  /* буквальный суффикс */
        case SRS_DOM_EXACT:    fprintf(o->dom, "=%s\n", el->str); break;  /* только само имя */
        case SRS_DOM_KEYWORD:  fprintf(o->dom, "*%s*\n", el->str); break;
        case SRS_DOM_REGEX:    fprintf(o->dom, "re:%s\n", el->str); break;
        case SRS_DOM_GLOB:     fprintf(o->dom, "%s\n", el->str); break;      /* шаблон AdGuard */
        }
        return 0;
    }
    if (el->family == 6) {
        /* IPv6 в наших наборах правил пока не участвует, а молча выбросить его нельзя —
         * иначе список выглядел бы прочитанным целиком. */
        o->saw_v6 = 1;
        return 0;
    }
    fprintf(o->pfx, "%u.%u.%u.%u/%d\n", el->addr[0], el->addr[1], el->addr[2], el->addr[3],
            el->plen);
    return 0;
}

static int srs_dump_set(const struct srs_set *s, const char *path, FILE *dom, FILE *pfx,
                        FILE *meta) {
    struct err e = {0};
    /* Что тремя файлами не выражается — решается до печати: половина набора — не набор. */
    const char *why = NULL;
    int tcp = 0, udp = 0;
    char (*ports)[META_PORT_LEN] = NULL;      /* различные порты набора: растёт по числу */
    size_t ports_n = 0, ports_cap = 0;
    int ports_over = 0;                       /* нет памяти */
    for (size_t i = 0; i < srs_clause_n(s) && !why; i++) {
        const struct srs_clause *c = srs_clause(s, i);
        if (c->flags & (SRS_F_XDOM | SRS_F_XCIDR))
            why = "правило-исключение: списком исключения не выражаются (подключите набор к "
                  "каналу ключом srs_files)";
        else if (c->src_n)
            why = "source_ip_cidr: набор описывает клиентов, а не назначение (подключите набор "
                  "к каналу ключом srs_files)";
        else if (c->pkg_n)
            why = "package_name: набор описывает приложения (подключите набор к каналу ключом "
                  "srs_files)";
        tcp |= c->net_tcp;
        udp |= c->net_udp;
        /* Повторы отбрасываются: у sing-box один и тот же диапазон встречается в двух
         * элементах, а nft на дубле в множестве отвергает весь набор правил. */
        for (size_t k = 0; k < c->raw_n && !ports_over; k++) {
            char b[META_PORT_LEN];
            if (c->raw_range[k] || c->raw[k].lo != c->raw[k].hi)
                snprintf(b, sizeof(b), "%u-%u", c->raw[k].lo, c->raw[k].hi);
            else
                snprintf(b, sizeof(b), "%u", c->raw[k].lo);
            size_t j = 0;
            while (j < ports_n && strcmp(ports[j], b) != 0) j++;
            if (j < ports_n) continue;
            if (ports_n == ports_cap) {
                size_t cap = ports_cap ? ports_cap * 2 : 32;
                char (*v)[META_PORT_LEN] = realloc(ports, cap * sizeof(*v));
                if (!v) { ports_over = 1; break; }
                ports = v;
                ports_cap = cap;
            }
            snprintf(ports[ports_n++], META_PORT_LEN, "%s", b);
        }
    }
    if (!why && ports_over) why = "нет памяти на список портов";
    if (why) {
        fprintf(stderr, "steer: srs: набор понят, но не выразим списком — %s\n", why);
        free(ports);
        return 2;
    }
    /* Сужение есть, а печатать его некуда — это ОТКАЗ, а не мелочь. Отдать подсети Cloudflare
     * без «только udp 50000-65535» значит увести в туннель весь TCP к 104.16.0.0/12, и
     * вызывающий об этом даже не узнает. */
    if (!meta && (tcp || udp || ports_n)) {
        fprintf(stderr, "steer: srs: набор сужен по протоколу или портам — нужен --meta-out, "
                        "иначе сужение потеряется, а подсети уедут в туннель целиком\n");
        free(ports);
        return 2;
    }
    struct out o = { dom, pfx, 0 };
    int rc = srs_walk(s, SRS_EL_DOMAIN | SRS_EL_CIDR, NULL, print_elem, &o, &e);
    if (rc != 0) {
        fprintf(stderr, "steer: %s\n", e.msg);
        free(ports);
        return 1;
    }
    /* Уровень обязателен: разбор УДАЛСЯ, значит это строка журнала во время работы, а не
     * отказ вызывающему (контракт docs/contract-v1.md §5). */
    if (srs_skipped(s))
        fprintf(stderr, "steer[warn] srs: %s: %s\n", path, srs_skipped(s));
    if (o.saw_v6)
        fprintf(stderr, "steer[warn] srs: в наборе есть подсети IPv6 — они пропущены, "
                        "правила работают по IPv4\n");
    if (meta) {
        if (tcp && udp) fprintf(meta, "proto=both\n");
        else if (tcp)   fprintf(meta, "proto=tcp\n");
        else if (udp)   fprintf(meta, "proto=udp\n");
        if (ports_n) {
            fprintf(meta, "ports=");
            for (size_t i = 0; i < ports_n; i++) fprintf(meta, "%s%s", i ? "," : "", ports[i]);
            fprintf(meta, "\n");
        }
    }
    free(ports);
    return 0;
}

struct output_file {
    const char *name;       /* как указано пользователем */
    char *resolved;         /* цель существующей символической ссылки */
    const char *target;
    char *temp;             /* только для обычного файла, рядом с target */
    FILE *file;
    mode_t mode;
    struct stat previous;
    int existed;
};

static int open_output(struct output_file *out, mode_t create_mode) {
    char *temp = NULL;
    struct stat st;
    const char *target = out->name;
    int fd = -1;
    if (lstat(target, &st) == 0 && S_ISLNK(st.st_mode)) {
        out->resolved = realpath(target, NULL);
        if (!out->resolved) goto fail;
        target = out->resolved;
    }
    out->target = target;
    if (lstat(target, &st) == 0) {
        if (!S_ISREG(st.st_mode) && !S_ISCHR(st.st_mode) && !S_ISFIFO(st.st_mode)) {
            errno = EINVAL;
            goto fail;
        }
        /* Не подменяем возможность писать в существующий файл правами на каталог. */
        fd = open(target, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0 || fstat(fd, &out->previous) != 0) goto fail;
        if ((st.st_mode & S_IFMT) != (out->previous.st_mode & S_IFMT)) {
            errno = EINVAL;
            goto fail;
        }
        if (!S_ISREG(st.st_mode)) goto stream;
        out->existed = 1;
        out->mode = out->previous.st_mode & 0777;
        int rc = close(fd);
        fd = -1;
        if (rc != 0) goto fail;
    } else {
        if (errno != ENOENT || out->resolved) goto fail;
        out->mode = create_mode;
    }
    const char *slash = strrchr(target, '/');
    int dir_len = slash ? (int)(slash + 1 - target) : 0;
    if (asprintf(&temp, "%.*s.steer-srs.XXXXXX", dir_len, target) < 0) {
        temp = NULL;
        goto fail;
    }
    fd = mkstemp(temp);
    if (fd < 0) goto fail;
    out->temp = temp;
    temp = NULL;
stream:
    out->file = fdopen(fd, "w");
    if (out->file) return 0;
fail:
    fprintf(stderr, "steer: srs: не открыть %s: %s\n", out->name, strerror(errno));
    if (fd >= 0) close(fd);
    free(temp);
    return -1;
}

/* Сброс/закрытие не скрывают отложенный отказ записи (например, ENOSPC). */
static int finish_output(struct output_file *out, int check) {
    FILE *file = out->file;
    if (!file) return 0;
    int error = 0;
    if (check) {
        if (fflush(file) != 0) error = errno;
        if (!error && ferror(file)) error = EIO;
        if (!error && out->temp) {
            int fd = fileno(file);
            if (out->existed) {
                struct stat st;
                if (fstat(fd, &st) != 0 ||
                    ((st.st_uid != out->previous.st_uid || st.st_gid != out->previous.st_gid) &&
                     fchown(fd, out->previous.st_uid, out->previous.st_gid) != 0))
                    error = errno;
            }
            if (!error && (fchmod(fd, out->mode) != 0 || fsync(fd) != 0)) error = errno;
        }
    }
    if (file != stdout && fclose(file) != 0 && !error) error = errno;
    if (!check || !error) return 0;
    fprintf(stderr, "steer: srs: %s не записался до конца: %s\n",
            out->name ? out->name : "stdout", strerror(error));
    return -1;
}

int srs_dump(const char *path, const char *dom_path, const char *pfx_path,
             const char *meta_path) {
    const struct srs_set *s;
    struct err e = {0};
    if (srs_open(path, &s, &e) != 0) {
        fprintf(stderr, "steer: %s\n", e.msg);
        return 1;
    }
    /* EPIPE тоже должен пройти через обычную очистку временных файлов. */
    struct sigaction ignore = { .sa_handler = SIG_IGN }, previous;
    sigemptyset(&ignore.sa_mask);
    if (sigaction(SIGPIPE, &ignore, &previous) != 0) {
        fprintf(stderr, "steer: srs: не обработать SIGPIPE: %s\n", strerror(errno));
        srs_release(s);
        return 1;
    }
    struct output_file out[] = {
        { .name = dom_path }, { .name = pfx_path }, { .name = meta_path },
        { .file = dom_path && pfx_path ? NULL : stdout },
    };
    const size_t count = sizeof(out) / sizeof(*out);
    mode_t mask = umask(0);
    umask(mask);
    int rc = 1;
    for (size_t i = 0; i < count; i++)
        if (out[i].name && open_output(&out[i], 0666 & ~mask) != 0) goto done;
    rc = srs_dump_set(s, path, dom_path ? out[0].file : stdout,
                      pfx_path ? out[1].file : stdout, out[2].file);
done:
    srs_release(s);
    for (size_t i = 0; i < count; i++)
        if (finish_output(&out[i], rc == 0) != 0) rc = 1;

    /* Ничего не заменяем до конца чтения и записи всех потоков. Каждое имя
     * заменяется одним rename, но это не общая транзакция нескольких имён. */
    for (size_t i = 0; !rc && i < count; i++) {
        if (!out[i].temp) continue;
        if (rename(out[i].temp, out[i].target) != 0) {
            fprintf(stderr, "steer: srs: не заменить %s: %s\n", out[i].name, strerror(errno));
            rc = 1;
        } else {
            free(out[i].temp);
            out[i].temp = NULL;
        }
    }
    for (size_t i = 0; i < count; i++) {
        if (out[i].temp) {
            unlink(out[i].temp);
            free(out[i].temp);
        }
        free(out[i].resolved);
    }
    (void)sigaction(SIGPIPE, &previous, NULL);
    return rc;
}
