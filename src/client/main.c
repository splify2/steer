/* steer — клиент демона движка (docs/architecture.md, раздел 4а, «Бинарники»; протокол —
 * docs/ctl.md).
 *
 * ЗАЧЕМ ОТДЕЛЬНАЯ ПРОГРАММА. Движок — это steerd: демон, компилятор, apply, помощники и
 * инструменты одним файлом. Но зовут его под именем `steer` все, кто был до демона: rpcd и
 * скрипты splify2, init-скрипт, стенды, человек в shell. Команды, на которые теперь отвечает
 * демон из своей памяти (status, diag, explain, conns, dns-log) или которые он исполняет сам
 * (apply — сверка с применённым, reload, subscribe), должны идти к нему: иначе status мимо демона
 * не видит хода перебора узлов, а apply мимо демона не знает, что помощников и резолвер держит
 * он. Всё остальное — и любая команда, когда демона нет, — работа самого движка, и её клиент
 * отдаёт steerd, заменяя себя им (execv с теми же аргументами). Так вызов `steer <команда>`
 * остаётся тем же для каждого, кто его делал, а клиент весит десятки килобайт: в нём нет ни
 * разбора спеки, ни компилятора — только разбор команды, протокол v1 и exec.
 *
 * ВЫВОД ТОТ ЖЕ. Ответ демона несёт код возврата, stdout и stderr одноимённой подкоманды — их
 * клиент и печатает, байт в байт, и выходит тем же кодом. Отказ самого сервера без кода
 * (denied, internal, bad-request…) — не ответ на вопрос, и клиент тогда тоже отдаёт команду
 * движку: прежнее поведение лучше отказа, который раньше не случался.
 *
 * К ТОМУ ЛИ ДЕМОНУ. Сокет — STEER_SOCKET или путь платформы. Демон на нём может обслуживать
 * другую спеку или другой каталог состояния (стенд, ручной запуск с --spec), и тогда ответ на
 * `steer status --spec X` был бы ответом про чужую спеку. Поэтому перед командой клиент
 * спрашивает `version`: демон называет свою спеку и каталог состояния, и команда идёт к нему,
 * только если они те же, что у вызова (пути сверяются после realpath). Иначе — движку.
 *
 * ГДЕ ДВИЖОК. STEER_ENGINE, иначе steerd в том же каталоге, что сам клиент (/proc/self/exe):
 * в пакете оба в /usr/sbin, на телефоне — в /system_ext/bin/der, у стендов — в build/. */
#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>

#include "platform.h"
#include "ctlcall.h"

/* Пределы протокола v1 и разговор с сокетом — общие со steerd (src/lib/ctlcall.h). */
#define LINE_MAX_V1 CTLCALL_LINE_MAX
#define BODY_MAX_V1 CTLCALL_BODY_MAX

/* Код выхода «демона нет» у команд, которые исполняет только он (reload, subscribe): отличим от
 * кодов подкоманд (0, 1 — поломка, 2 — отказ разбора), чтобы init.d мог сказать «демон не
 * запущен» отдельно от «reload не прошёл». */
#define EXIT_NODAEMON 3

static char **g_argv;
static char g_engine[PATH_MAX + 16];

static void engine_path(void) {
    const char *e = getenv("STEER_ENGINE");
    if (e && *e) {
        snprintf(g_engine, sizeof(g_engine), "%s", e);
        return;
    }
    char self[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (n > 0) {
        self[n] = '\0';
        char *sl = strrchr(self, '/');
        if (sl) {
            *sl = '\0';
            snprintf(g_engine, sizeof(g_engine), "%s/steerd", self);
            return;
        }
    }
    snprintf(g_engine, sizeof(g_engine), "steerd");
}

/* Отдать команду движку: тот же argv, включая argv[0] — в списке процессов вызов выглядит так
 * же, как выглядел, а роль steerd по argv[0] выбирается только для steer-tools. */
static void run_engine(void) {
    if (strchr(g_engine, '/')) execv(g_engine, g_argv);
    else execvp(g_engine, g_argv);
    fprintf(stderr, "steer: не запустить ядро %s: %s\n", g_engine, strerror(errno));
    exit(127);
}

/* ---- вызов ------------------------------------------------------------------------------ */

enum { K_LOCAL, K_ROUTE, K_DAEMON };   /* движку; демону, если он есть; только демону */

struct call {
    const char *cmd;
    int kind;
    const char *spec, *state_dir;
    const char *pos;          /* explain; select — группа */
    const char *pos2;         /* select — член */
    int fast, dry_run;
};

/* Разобрать вызов так же строго, как движок, но только ради одного решения — к демону или нет.
 * Всё, что не укладывается в форму команды демона (другой флаг, справка, лишнее слово), идёт
 * движку: он и откажет своими словами, и справку напечатает свою. */
static int parse_call(int argc, char **argv, struct call *c) {
    memset(c, 0, sizeof(*c));
    int i = 1;
    /* --platform понимает любая команда в любом месте строки (src/daemon/main.c). */
    for (int k = 1; k < argc; k++) {
        if (strcmp(argv[k], "--platform") != 0) continue;
        if (k + 1 >= argc || plat_select(argv[k + 1]) != 0) return K_LOCAL;
        k++;
    }
    while (i < argc && !strcmp(argv[i], "--platform")) i += 2;
    if (i >= argc) return K_LOCAL;
    c->cmd = argv[i];
    int st = 0, sd = 0, fa = 0, dr = 0, pos = 0, npos = 0;
    if (!strcmp(c->cmd, "status")) { st = sd = fa = 1; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "diag") || !strcmp(c->cmd, "conns") || !strcmp(c->cmd, "dns-log")) {
        st = sd = 1;
        c->kind = K_ROUTE;
    } else if (!strcmp(c->cmd, "explain")) { st = sd = 1; pos = 1; c->kind = K_ROUTE; }
    /* select — к демону, если он есть (он держит память сторожа и шлёт события); без демона тот
     * же выбор делает движок сам (src/daemon/fogroup.c, cmd_select). */
    else if (!strcmp(c->cmd, "select")) { st = sd = 1; pos = 2; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "apply")) { st = sd = dr = 1; c->kind = K_ROUTE; }
    else if (!strcmp(c->cmd, "reload") || !strcmp(c->cmd, "subscribe")) {
        st = sd = 1;
        c->kind = K_DAEMON;
    } else return K_LOCAL;

    for (int k = i + 1; k < argc; k++) {
        const char *a = argv[k];
        if (!strcmp(a, "--platform")) { k++; continue; }
        if (st && !strcmp(a, "--spec") && k + 1 < argc && argv[k + 1][0] != '-') {
            c->spec = argv[++k];
            continue;
        }
        if (sd && !strcmp(a, "--state-dir") && k + 1 < argc && argv[k + 1][0] != '-') {
            c->state_dir = argv[++k];
            continue;
        }
        if (fa && !strcmp(a, "--fast")) { c->fast = 1; continue; }
        if (dr && !strcmp(a, "--dry-run")) { c->dry_run = 1; continue; }
        if (pos && a[0] != '-' && a[0] && npos < pos) {
            if (npos++ == 0) c->pos = a;
            else c->pos2 = a;
            continue;
        }
        return K_LOCAL;
    }
    if (pos && npos < pos) return K_LOCAL;
    /* Проверка без применения — работа компилятора, демону в ней делать нечего. */
    if (c->dry_run) return K_LOCAL;
    /* Слово идёт в строку запроса, где разделитель — пробел, а конец — перевод строки. Слово с
     * ними исказило бы запрос, а не просто получило бы отказ; такое — движку (он и откажет). */
    if (c->pos && strpbrk(c->pos, " \t\r\n")) return K_LOCAL;
    if (c->pos2 && strpbrk(c->pos2, " \t\r\n")) return K_LOCAL;
    return c->kind;
}

/* ---- сокет и ответ — src/lib/ctlcall.c ------------------------------------------------------ */

static int write_all(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

/* Демон на сокете обслуживает эти же спеку и каталог состояния? */
static int same_daemon(const struct call *c) {
    return ctlcall_same_daemon(c->spec, c->state_dir, 10);
}

static char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    size_t cap = 65536, got = 0;
    char *b = malloc(cap);
    while (b) {
        size_t m = fread(b + got, 1, cap - got, f);
        got += m;
        if (got > (size_t)BODY_MAX_V1) break;
        if (m == 0) break;
        if (got == cap) {
            char *q = realloc(b, cap * 2);
            if (!q) { free(b); b = NULL; break; }
            b = q;
            cap *= 2;
        }
    }
    int bad = ferror(f);
    fclose(f);
    if (!b || bad || got > (size_t)BODY_MAX_V1) { free(b); return NULL; }
    *n = got;
    return b;
}

static void nap_ms(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

/* ---- subscribe: поток событий --------------------------------------------------------------- */

static int do_subscribe(void) {
    int s = ctlcall_open(0);
    if (s < 0) return -1;
    if (write_all(s, "subscribe\n", 10) != 0) { close(s); return -1; }
    char buf[16384];
    ssize_t m;
    int first = 1, ok = 0;
    while ((m = read(s, buf, sizeof(buf))) > 0 || (m < 0 && errno == EINTR)) {
        if (m <= 0) continue;
        if (first) {
            /* Код выхода — по первой строке, ответу на сам subscribe. */
            ok = memmem(buf, (size_t)m, "\"code\":0", 8) != NULL &&
                 memmem(buf, (size_t)m, "\"error\":", 8) == NULL;
            first = 0;
        }
        fwrite(buf, 1, (size_t)m, stdout);
        fflush(stdout);
    }
    close(s);
    return first ? 2 : ok ? 0 : 1;
}

int main(int argc, char **argv) {
    g_argv = argv;
    engine_path();
    struct call c;
    int kind = parse_call(argc, argv, &c);
    if (kind == K_LOCAL) run_engine();
    /* Отсюда движок получает команду, только если демон не ответил или чужой: сам спрашивать
     * его ещё раз ему незачем (src/daemon/main.c, ask_daemon). */
    setenv("STEER_DAEMON_ASKED", "1", 1);

    const char *g_sock = ctlcall_socket(NULL);
    if (!same_daemon(&c)) {
        if (kind == K_ROUTE) run_engine();
        fprintf(stderr, "steer: %s: демон ядра не отвечает на %s (или обслуживает другую "
                        "спеку) — %s исполняет только он\n", c.cmd, g_sock, c.cmd);
        return EXIT_NODAEMON;
    }
    if (!strcmp(c.cmd, "subscribe")) {
        int rc = do_subscribe();
        if (rc < 0) {
            fprintf(stderr, "steer: subscribe: нет соединения с %s\n", g_sock);
            return EXIT_NODAEMON;
        }
        return rc;
    }

    char line[LINE_MAX_V1 + 32];
    char *body = NULL;
    size_t body_n = 0;
    int readonly = 1;
    if (!strcmp(c.cmd, "status")) snprintf(line, sizeof(line), "status%s\n", c.fast ? " fast" : "");
    else if (!strcmp(c.cmd, "explain")) {
        if (strlen(c.pos) > LINE_MAX_V1 - 16) run_engine();
        snprintf(line, sizeof(line), "explain %s\n", c.pos);
    } else if (!strcmp(c.cmd, "select")) {
        /* Имена выходов — до 31 байта; длиннее — не наши, движок откажет своими словами. */
        if (strlen(c.pos) > 64 || strlen(c.pos2) > 64) run_engine();
        snprintf(line, sizeof(line), "select %.64s %.64s\n", c.pos, c.pos2);
        readonly = 0;
    } else if (!strcmp(c.cmd, "apply")) {
        /* Спеку демону — телом, как её присылает приложение: он проверит её, положит на место
         * (это тот же файл — сверено выше) и применит только изменившееся. */
        body = read_file(plat_spec_resolve(c.spec), &body_n);
        if (!body) run_engine();
        snprintf(line, sizeof(line), "apply %zu\n", body_n);
        readonly = 0;
    } else {
        snprintf(line, sizeof(line), "%s\n", c.cmd);
        if (!strcmp(c.cmd, "reload")) readonly = 0;
    }

    /* busy — четыре запроса уже идут: подождать, а не отдавать команду движку в обход демона
     * (apply рядом с идущим apply демона спорил бы с ним за одни таблицы). */
    struct ctlcall_resp r;
    char *raw = NULL;
    for (int tries = 0;; tries++) {
        /* Срок ответа: apply у демона идёт до 420 с (план и применение), сверх того — зависание. */
        raw = ctlcall_roundtrip(line, body, body_n, 600);
        if (!raw || ctlcall_parse(raw, &r) != 0) {
            free(raw);
            if (readonly || kind == K_ROUTE) {
                if (!readonly) fprintf(stderr, "steer[warn] демон не ответил на %s — "
                                               "исполняю ядром\n", c.cmd);
                free(body);
                run_engine();
            }
            fprintf(stderr, "steer: %s: демон не ответил\n", c.cmd);
            return EXIT_NODAEMON;
        }
        if (r.error.p && !strcmp(r.error.p, "busy") && tries < 100) {
            free(raw);
            ctlcall_resp_free(&r);
            nap_ms(100);
            continue;
        }
        break;
    }
    free(raw);
    free(body);

    if (!r.has_code) {
        /* Отказ сервера без исполнения: прежний путь — движок — лучше отказа, которого раньше не
         * было. Только демону принадлежащие команды отказом и отвечают. */
        if (kind == K_ROUTE) run_engine();
        fprintf(stderr, "steer: %s: %s\n", c.cmd, r.message.p ? r.message.p :
                r.error.p ? r.error.p : "демон отказал");
        return 1;
    }
    /* Обрезанный вывод читающей команды — повторить движком целиком, а не отдать обрубок. */
    if (r.truncated && readonly) run_engine();
    if (r.err.n) fwrite(r.err.p, 1, r.err.n, stderr);
    /* Слово отказа подкоманды: демон вынул строку JSON из stderr в ecode и args — при STEER_ERR_JSON=1 вернуть её, как
     * печатает подкоманда в командной строке (docs/errors.md). error — первая строка stderr без «steer: ». */
    if (r.ecode.p && r.args.p && getenv("STEER_ERR_JSON")) {
        const char *t = r.err.p ? r.err.p : "";
        if (!strncmp(t, "steer: ", 7)) t += 7;
        fputs("{\"ok\":false,\"error\":\"", stderr);
        for (; *t && *t != '\n'; t++) {
            unsigned char ch = (unsigned char)*t;
            if (ch == '"' || ch == '\\') fprintf(stderr, "\\%c", ch);
            else if (ch < 0x20) fprintf(stderr, "\\u%04x", ch);
            else fputc(ch, stderr);
        }
        fprintf(stderr, "\",\"code\":\"%s\",\"args\":%s}\n", r.ecode.p, r.args.p);
    }
    if (r.out.n) fwrite(r.out.p, 1, r.out.n, stdout);
    if (r.error.p)
        fprintf(stderr, "steer: %s: %s\n", c.cmd, r.message.p ? r.message.p : r.error.p);
    if (!strcmp(c.cmd, "apply") && r.applied == 0 && r.enabled == 0)
        fputs("steer: ядро выключено — спека сохранена, в ядро Linux не применялась\n", stderr);
    fflush(stdout);
    return r.error.p && r.code == 0 ? 1 : r.code;
}
