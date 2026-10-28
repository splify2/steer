/* Программа плагина tgws (plugins/tgws/plugin.json): мост Telegram — помощник выхода `kind: tgws`, хук
 * check его вида и подкоманда `steer tgws-probe`.
 *
 * С ядром программа говорит только через API (plugin-sdk/docs/steer-api.md, src/plugkit): ядро запускает
 * её по манифесту, о выходе она знает из {conf} (ключ domain, порт моста — ресурс выхода), правила
 * перехвата ставит ядро по шаблону nft плагина (plugins/tgws/nft/tgws.nft). Настройки плагина — пул
 * доменов, пути ДЦ, адреса ДЦ, туннели WARP — лежат в своём каталоге настроек ({conf}: paths.conf,
 * у подкоманды — STEER_PLUGIN_CONF), файл settings.json по схеме plugins/tgws/settings.schema.json;
 * пишет его панель (splify2-api, plugin_settings_set). Мост читает его один раз при старте: файл входит в подпись
 * перезапуска помощника (манифест: steer.settings = "restart", steer-api 1.4), и хост, записав его, зовёт
 * reload — ядро поднимает мост заново сразу, без паузы перезапуска. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "plugkit.h"
#include "tghook.h"
#include "tgws.h"
#include "thrstack.h"

extern char **environ;

/* Настройки плагина: документ живёт, пока жив процесс, списки — указатели на его строки. */
struct tg_settings {
    struct pkj *doc;
    const char **alt, **route, **dc, **warp;
    size_t alt_n, route_n, dc_n, warp_n;
    int verbose;
    int pick;               /* pick: подбирать пути ДЦ замером (умолчание схемы — да) */
};

/* Список строк ключа key; не список строк — отказ с именем ключа (схему проверяет панель, но файл
 * мог написать и человек). */
static int strs(const struct pkj *doc, const char *key, const char ***out, size_t *n, const char *path) {
    const struct pkj *j = pkj_get(doc, key);
    *out = NULL;
    *n = 0;
    if (!j) return 0;
    if (j->t != PKJ_ARR) {
        fprintf(stderr, "steer[warn] tgws: %s: %s — не список, пропущен\n", path, key);
        return -1;
    }
    const char **a = calloc(j->n ? j->n : 1, sizeof(*a));
    if (!a) return -1;
    size_t k = 0;
    for (size_t i = 0; i < j->n; i++) {
        const char *s = pkj_str(j->v[i]);
        if (s) a[k++] = s;
        else fprintf(stderr, "steer[warn] tgws: %s: %s[%zu] — не строка, пропущено\n", path, key, i);
    }
    *out = a;
    *n = k;
    return 0;
}

/* Прочитать settings.json каталога настроек dir. Файла нет — умолчания схемы (пусто). Негодный файл
 * не роняет мост: Telegram без пула лучше, чем без моста, — причина уходит в журнал. */
static void settings_load(const char *dir, struct tg_settings *s, char *path, size_t pn) {
    memset(s, 0, sizeof(*s));
    s->pick = 1;
    path[0] = '\0';
    if (!dir || !*dir) return;
    snprintf(path, pn, "%s/settings.json", dir);
    if (access(path, F_OK) != 0) return;
    char err[300];
    s->doc = pkj_load(path, err, sizeof err);
    if (!s->doc || s->doc->t != PKJ_OBJ) {
        fprintf(stderr, "steer[warn] tgws: настройки %s не читаются (%s) — без них\n", path, s->doc ? "не объект" : err);
        pkj_free(s->doc);
        s->doc = NULL;
        return;
    }
    strs(s->doc, "domains", &s->alt, &s->alt_n, path);
    strs(s->doc, "routes", &s->route, &s->route_n, path);
    strs(s->doc, "dc_addresses", &s->dc, &s->dc_n, path);
    strs(s->doc, "warp", &s->warp, &s->warp_n, path);
    int b;
    if (pkj_bool(pkj_get(s->doc, "verbose"), &b) == 0) s->verbose = b;
    if (pkj_bool(pkj_get(s->doc, "pick"), &b) == 0) s->pick = b;
}

static void settings_opts(const struct tg_settings *s, struct tgws_opts *o) {
    o->alt = s->alt;     o->alt_n = s->alt_n;
    o->route = s->route; o->route_n = s->route_n;
    o->dc = s->dc;       o->dc_n = s->dc_n;
    o->warp = s->warp;   o->warp_n = s->warp_n;
    o->verbose = s->verbose;
}

/* ---- подбор путей ДЦ (настройка pick) -----------------------------------------------------------
 *
 * Прежде это был `tgws pick` — скрипт микропакета stgws (описание — tech/04-stgws.md, 4.11): по установке
 * пакета он мерил пробами, какие ДЦ открыты напрямую и какой домен пула лучше для каждого ДЦ, писал карту
 * route.conf и перезапускал службу. Здесь то же делает сам мост, в фоне, без перезапуска:
 *
 *   ФАЗА 0 — какие ДЦ 1..5 отвечают напрямую (tgws-probe --direct);
 *   ФАЗА 1 — каждый домен (домен выхода и пул) у ДЦ 1..5 и медийного ДЦ2 (tgws-probe --domain);
 *   ИТОГ   — ДЦ, ответивший напрямую, — «N direct» и «Nm direct»; иначе самый быстрый ответивший домен
 *            для N (и для Nm, если мерили). Ни одного ответа — карта не меняется.
 *
 * Пробы — эта же программа подкомандой tgws-probe (posix_spawn /proc/self/exe): у пробы свои глобальные
 * домен и таблица ДЦ, и в процессе моста она их перетёрла бы. Разом — не больше PICK_PAR проб. Итог
 * действует там, где настройки (`routes`) о ДЦ молчат (tgws_route_pick), и обновляется раз в PICK_EVERY_S:
 * карта — замер, а замер стареет. web.telegram.org и туннели WARP подбор не меряет: их мост пробует сам
 * на каждом соединении (4.11). */
#define PICK_PAR 6
#define PICK_TIMEOUT "6"
#define PICK_EVERY_S (6 * 3600)
#define PICK_FIRST_S 5

struct pick_job { int dc, media, direct; const char *dom; pid_t pid; long t0, ms; int ok; };

struct pick_ctx {
    const char *conf;               /* каталог настроек: пробе — STEER_PLUGIN_CONF (адреса ДЦ) */
    const char **dom;  size_t dom_n;
};

static long mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Окружение пробы: своё, без STEER_EVENT_FD (иначе проба сказала бы ядру hello от имени моста) и с
 * каталогом настроек. */
static char **pick_env(const char *conf) {
    size_t n = 0;
    while (environ[n]) n++;
    char **e = calloc(n + 2, sizeof(*e));
    if (!e) return NULL;
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (strncmp(environ[i], "STEER_EVENT_FD=", 15) && strncmp(environ[i], "STEER_PLUGIN_CONF=", 18))
            e[k++] = environ[i];
    if (conf && *conf && asprintf(&e[k], "STEER_PLUGIN_CONF=%s", conf) > 0) k++;
    e[k] = NULL;
    return e;
}

static int pick_spawn(struct pick_job *j, char **envp, posix_spawn_file_actions_t *fa) {
    char nb[8];
    snprintf(nb, sizeof nb, "%d", j->dc);
    const char *argv[12];
    int a = 0;
    argv[a++] = "tgws";
    argv[a++] = "tgws-probe";
    argv[a++] = "--node";
    argv[a++] = nb;
    if (j->media) argv[a++] = "media";
    if (j->direct) argv[a++] = "--direct";
    else { argv[a++] = "--domain"; argv[a++] = j->dom; }
    argv[a++] = "--timeout";
    argv[a++] = PICK_TIMEOUT;
    argv[a] = NULL;
    j->t0 = mono_ms();
    int rc = posix_spawn(&j->pid, "/proc/self/exe", fa, NULL, (char *const *)argv, envp);
    if (rc != 0) { j->pid = 0; errno = rc; return -1; }
    return 0;
}

/* Прогнать задания разом по PICK_PAR. 0 — все прошли (каждое — со своим ok), -1 — пробы не запускаются. */
static int pick_run(struct pick_job *jobs, size_t n, const char *conf) {
    char **envp = pick_env(conf);
    if (!envp) return -1;
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    for (int fd = 0; fd <= 2; fd++)
        posix_spawn_file_actions_addopen(&fa, fd, "/dev/null", fd ? O_WRONLY : O_RDONLY, 0);
    size_t next = 0, live = 0, done = 0;
    int bad = 0;
    while (done < n) {
        while (live < PICK_PAR && next < n) {
            if (pick_spawn(&jobs[next], envp, &fa) != 0) {
                fprintf(stderr, "steer[warn] tgws: подбор: проба не запускается (%s)\n", strerror(errno));
                bad = 1;
                jobs[next].ok = 0;
                done++;
            } else live++;
            next++;
        }
        if (bad) break;
        int st;
        pid_t p = waitpid(-1, &st, 0);
        if (p < 0) { if (errno == EINTR) continue; break; }
        for (size_t i = 0; i < next; i++)
            if (jobs[i].pid == p) {
                jobs[i].ms = mono_ms() - jobs[i].t0;
                jobs[i].ok = WIFEXITED(st) && WEXITSTATUS(st) == 0;
                jobs[i].pid = 0;
                live--;
                done++;
                break;
            }
    }
    while (live) {          /* отказ запуска посреди круга: дождаться начатых */
        int st;
        if (waitpid(-1, &st, 0) < 0 && errno != EINTR) break;
        live--;
    }
    posix_spawn_file_actions_destroy(&fa);
    for (size_t i = 0; envp[i]; i++)
        if (!strncmp(envp[i], "STEER_PLUGIN_CONF=", 18)) free(envp[i]);
    free(envp);
    return bad ? -1 : 0;
}

/* Один круг подбора: замер и, если ответил хоть кто-то, новая карта моста. */
static void pick_once(const struct pick_ctx *c) {
    static const int DC[] = { 1, 2, 3, 4, 5 };
    size_t n = 5 + c->dom_n * 6;
    struct pick_job *j = calloc(n, sizeof(*j));
    if (!j) return;
    size_t k = 0;
    for (int i = 0; i < 5; i++) j[k++] = (struct pick_job){ .dc = DC[i], .direct = 1 };
    for (size_t d = 0; d < c->dom_n; d++) {
        for (int i = 0; i < 5; i++) j[k++] = (struct pick_job){ .dc = DC[i], .dom = c->dom[d] };
        j[k++] = (struct pick_job){ .dc = 2, .media = 1, .dom = c->dom[d] };
    }
    if (pick_run(j, n, c->conf) != 0) { free(j); return; }
    /* Строки карты: по ДЦ 1..5 обычный и медийный (медийный мерили только у ДЦ2 — как прежний подбор). */
    char lines[10][160];
    const char *lv[10];
    size_t ln = 0, direct_n = 0, answered = 0;
    char said[600] = "";
    size_t sl = 0;
    for (int i = 0; i < 5; i++) {
        int dc = DC[i];
        if (j[i].ok) {
            direct_n++;
            snprintf(lines[ln], sizeof lines[0], "%d direct", dc); lv[ln] = lines[ln]; ln++;
            snprintf(lines[ln], sizeof lines[0], "%dm direct", dc); lv[ln] = lines[ln]; ln++;
            sl += (size_t)snprintf(said + sl, sl < sizeof said ? sizeof said - sl : 0, "%sДЦ%d напрямую", sl ? ", " : "", dc);
            continue;
        }
        for (int media = 0; media <= (dc == 2); media++) {
            const struct pick_job *best = NULL;
            for (size_t q = 5; q < n; q++)
                if (j[q].ok && j[q].dc == dc && j[q].media == media && (!best || j[q].ms < best->ms)) best = &j[q];
            if (!best) continue;
            answered++;
            snprintf(lines[ln], sizeof lines[0], "%d%s ws %s", dc, media ? "m" : "", best->dom);
            lv[ln] = lines[ln];
            ln++;
            if (sl < sizeof said)
                sl += (size_t)snprintf(said + sl, sizeof said - sl, "%sДЦ%d%s %s (%ld мс)", sl ? ", " : "", dc,
                                       media ? "m" : "", best->dom, best->ms);
        }
    }
    free(j);
    if (!direct_n && !answered) {
        fprintf(stderr, "steer[info] tgws: подбор: ни один ДЦ не ответил ни напрямую, ни через домены — карта прежняя\n");
        return;
    }
    int r = tgws_route_pick(lv, ln);
    fprintf(stderr, "steer[info] tgws: подбор: %s%s\n", said, r == 1 ? " — карта обновлена" : r == 0 ? " — карта та же" : " — нет памяти, карта прежняя");
}

static void *pick_thread(void *arg) {
    const struct pick_ctx *c = arg;
    sleep(PICK_FIRST_S);
    for (;;) {
        pick_once(c);
        sleep(PICK_EVERY_S);
    }
    return NULL;
}

/* Домены подбора: домен выхода и пул, без повторов и без web.telegram.org (его мост пробует сам). */
static void pick_start(const struct tgws_opts *o, const char *conf) {
    static struct pick_ctx c;
    c.conf = conf;
    c.dom = calloc(o->alt_n + 1, sizeof(*c.dom));
    if (!c.dom) return;
    const char *all[1] = { o->domain };
    for (size_t i = 0; i < o->alt_n + 1; i++) {
        const char *d = i ? o->alt[i - 1] : all[0];
        if (!d || !*d || !strcmp(d, "web.telegram.org")) continue;
        int dup = 0;
        for (size_t k = 0; k < c.dom_n; k++) dup |= !strcmp(c.dom[k], d);
        if (!dup) c.dom[c.dom_n++] = d;
    }
    pthread_t t;
    pthread_attr_t at;
    pthread_attr_init(&at);
    pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_attr_setstacksize(&at, thread_stack(128 * 1024));
    if (pthread_create(&t, &at, pick_thread, &c) != 0)
        fprintf(stderr, "steer[warn] tgws: подбор путей не завёлся (%s) — пути из настроек\n", strerror(errno));
    else
        fprintf(stderr, "steer[info] tgws: подбор путей включён: доменов %zu, круг раз в %d ч\n", c.dom_n, PICK_EVERY_S / 3600);
    pthread_attr_destroy(&at);
}

/* ---- подкоманды -------------------------------------------------------------------------------- */

static int r_tgws(const struct pk_args *a) {
    const struct pk_out *o = a->out;
    struct tgws_opts opt;
    memset(&opt, 0, sizeof opt);
    opt.name = o->tun.name;
    opt.domain = pk_key_str(o, "domain");
    long port = 0;
    pkj_long(pkj_at(pkj_get(o->output, "ports"), 0), &port);
    opt.port = (int)port;
    static struct tg_settings s;
    char path[4200];
    settings_load(o->plugin_conf, &s, path, sizeof path);
    settings_opts(&s, &opt);
    if (s.pick) pick_start(&opt, o->plugin_conf);
    return tgws_serve(&opt);
}

static int r_probe(const struct pk_args *a) {
    if (a->npos && strcmp(a->pos[0], "media") != 0)
        pk_fail("команда tgws-probe понимает аргументом только «media», а получила «%s»", a->pos[0]);
    struct tgws_opts opt;
    memset(&opt, 0, sizeof opt);
    opt.domain = pk_opt(a, "domain");
    static struct tg_settings s;
    char path[4200];
    settings_load(getenv("STEER_PLUGIN_CONF"), &s, path, sizeof path);
    settings_opts(&s, &opt);
    long dc = pk_opt_long(a, "node", 2, 1, 203);
    return tgws_probe(&opt, (int)dc, a->npos == 1, pk_has(a, "direct"), (int)pk_opt_long(a, "timeout", 5, 1, 3600));
}

static int r_check(const struct pk_args *a) { (void)a; return tg_check_hook(); }

static const struct pk_cmd CMDS[] = {
    { "tgws", "<выход>", 0, 1, "", "поднять мост Telegram выхода kind: tgws по его {conf}", 1, r_tgws },
    { "tgws-probe", "[media]", 0, 1, "node: direct timeout: domain:",
      "проверить путь до дата-центра Telegram (--node 1..5 или 203, по умолчанию 2) через домен --domain "
      "или напрямую (--direct); срок --timeout, по умолчанию 5 секунд", 0, r_probe },
    { "check", "", 0, 0, "", "хук check вида tgws: вход — JSON выхода в stdin", 0, r_check },
};

PK_PROGRAM("tgws", CMDS);
