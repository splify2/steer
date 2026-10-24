/* Модуль hysteria2: подкоманды `steer hysteria2`, `hysteria2-nodes`, `hysteria2-probe`, слежка за
 * узлом и файл состояния для status/diag.
 *
 * ПОВТОРЯЕТ УСТРОЙСТВО vless (src/proto/vless/vlmain.c; слежка vless теперь — пул узлов src/tunnel/pool.c) и нарочно не выносит общего:
 * общее — «прочитать спеку, выбрать узел, поднять стек, следить», а различается всё внутри — что
 * такое узел, чем он проверяется, что значит «поднят». Вынос заставил бы протоколы знать друг
 * друга; пока их два, копия в сотню строк дешевле. Разница по существу одна: соединение с узлом у
 * hysteria2 постоянное (hy2conn.c), поэтому слежка меряет узел тем же, чем он выбирается, —
 * рукопожатием QUIC и авторизацией, — но НЕ мешает живому соединению: проба идёт своим сокетом, а
 * решение «узел потерян» принимает только после двух неудач подряд.
 *
 * Под демоном (evline_enabled) клиент говорит `up` с dev при появлении устройства, `down` с
 * причиной, когда узел перестал отвечать, и снова `up`, когда ответил; демон привязывает маршрут
 * по dev и принимает слово клиента о здоровье узла (docs/ctl.md). Смена узла на ходу невозможна —
 * соединение одно и несёт параметры одного узла, — поэтому, когда свой узел молчит, а другой
 * кандидат отвечает, процесс выходит, и супервизор поднимает его заново с тем же перебором. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "hy2.h"
#include "hy2conn.h"
#include "hy2dial.h"
#include "spec.h"
#include "evline.h"
#include "jsonw.h"
#include "pool.h"
#include "probe.h"
#include "thrstack.h"

#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

/* Узлы подписки — в куче по числу узлов в файле (hy2_load_sub), а не массив на заданное число. */
static struct hy2_node *g_nodes;

/* Номера узлов для перебора: не больше, чем пригодных узлов и записей выбора nodes. */
static int *sel_alloc(const struct output *o, size_t cnt, size_t *cap) {
    size_t c = cnt;
    if (o && o->hy2.nodes_n > c) c = o->hy2.nodes_n;
    *cap = c;
    int *s = calloc(c + 1, sizeof(*s));
    if (!s) die("нет памяти под список узлов", NULL);
    return s;
}

static struct spec *spec_new(void) {
    struct spec *sp = calloc(1, sizeof(*sp));
    if (!sp) die("нет памяти под спеку", NULL);
    return sp;
}

/* ---- подписка --------------------------------------------------------------------------------- */

static int load_nodes_file(const char *path, size_t *cnt, struct hy2_sub_stats *st) {
    g_nodes = hy2_load_sub(path, cnt, st);
    if (!g_nodes) { fprintf(stderr, LOG_W2 "%s не читается (или больше 64 МиБ)\n", path); return 2; }
    return 0;
}

static int load_nodes(struct spec *sp, const char *spec_path, const char *out_name,
                      struct output **out, size_t *cnt, struct hy2_sub_stats *st) {
    struct err e = {0};
    if (load_spec(spec_path, sp, &e) < 0) err_die(&e);
    struct output *o = out_by_name(sp, out_name);
    if (!o) { fprintf(stderr, LOG_W2 "выхода %s нет в спеке\n", out_name); return 2; }
    const struct hy2_cfg *hc = out_hysteria2(o);
    if (!hc) {
        fprintf(stderr, LOG_W2 "выход %s не hysteria2 (kind другой)\n", out_name);
        return 2;
    }
    *out = o;
    return load_nodes_file(hc->sub_file, cnt, st);
}

/* Метка сокета к узлу — до первого соединения: проба при подъёме и `hysteria2-probe` идут тем же
 * путём, что и сам туннель (иначе при `via` проба стучалась бы напрямую). Смысл метки — «вложенные
 * выходы» в spec.h; сокет QUIC метит обёртка (qc_cfg.sock_mark). */
static void underlay_setup(struct spec *sp, const struct output *o) {
    static const struct output none;
    if (o && o->over[0]) {
        struct err e = {0};
        if (registry_assign(sp, &e) < 0) err_die(&e);
    }
    hy2c_set_mark(out_underlay_mark(sp, o ? o : &none), o && o->over[0]);
}

/* x — исключение выхода; NULL — перечень по файлу. cc и excluded — как у vless (vlmain.c). */
static void node_json(const struct hy2_node *n, int index, const struct node_exclude *x) {
    printf("{\"index\":%d,\"name\":", index);
    jsonw_str(stdout, n->name);
    printf(",\"host\":");
    jsonw_str(stdout, n->host);
    printf(",\"port\":%u,\"type\":\"hysteria2\",\"security\":\"tls\",\"vision\":false", n->port);
    printf(",\"obfs\":%s,\"pinned\":%s,\"insecure\":%s,\"hop\":%s,\"up_bps\":%llu,\"down_bps\":%llu",
           n->obfs == 2 ? "\"gecko\"" : n->obfs ? "\"salamander\"" : "\"\"", n->has_pin ? "true" : "false",
           n->insecure ? "true" : "false", n->hop_n ? "true" : "false",
           (unsigned long long)n->up_bps, (unsigned long long)n->down_bps);
    char cc[3];
    if (node_cc(n->name, cc)) { printf(",\"cc\":"); jsonw_str(stdout, cc); }
    if (node_excluded(x, n->name)) printf(",\"excluded\":true");
    printf("}");
}

/* exclude, exclude_name (hy2_cfg.excl): исключённые уходят из кандидатов, номера не сдвигаются. Одна
 * функция на подъём и на `hysteria2-probe`. */
static size_t exclude_filter(const struct output *o, const struct hy2_node *nodes, int *sel, size_t n) {
    if (!o) return n;
    size_t k = 0;
    for (size_t i = 0; i < n; i++)
        if (!node_excluded(&o->hy2.excl, nodes[sel[i]].name)) sel[k++] = sel[i];
    return k;
}

static void skipped_json(const struct hy2_sub_stats *st) {
    printf(",\"skipped_reasons\":[");
    for (size_t i = 0; i < st->reasons_n; i++) {
        if (i) putchar(',');
        printf("{\"reason\":");
        jsonw_str(stdout, st->reasons[i].reason);
        printf(",\"count\":%zu,\"example\":", st->reasons[i].count);
        jsonw_str(stdout, st->reasons[i].example);
        printf("}");
    }
    printf("]");
    if (st->reasons_dropped) printf(",\"skipped_other\":%zu", st->reasons_dropped);
}

/* insecure — `--insecure` по файлу. У hysteria2 он ничего не меняет и принимается ради единого вызова
 * у всех протоколов: `insecure=1` здесь параметр ссылки узла, а не ключ выхода (kinds/hysteria2.c),
 * поэтому такие узлы пригодны всегда и номера по файлу с флагом и без него те же, что у выхода. */
int cmd_hysteria2_nodes(const char *spec_path, const char *out_name, int insecure) {
    (void)insecure;
    struct output *o = NULL;
    size_t cnt = 0;
    struct hy2_sub_stats st;
    int by_file = out_name && out_name[0] == '/';
    int rc = by_file ? load_nodes_file(out_name, &cnt, &st)
                     : load_nodes(spec_new(), spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->hy2.sub_file);
    size_t chosen_n = o ? o->hy2.nodes_n : 0;
    printf(",\"node\":%d,\"chosen\":[", chosen_n == 1 ? o->hy2.nodes[0] : -1);
    for (size_t i = 0; i < chosen_n; i++) printf("%s%d", i ? "," : "", o->hy2.nodes[i]);
    printf("],\"usable\":%zu,\"skipped\":%zu,\"foreign\":%zu,\"nodes\":[", cnt, st.skipped, st.foreign);
    for (size_t i = 0; i < cnt; i++) {
        if (i) putchar(',');
        node_json(&g_nodes[i], (int)i, o ? &o->hy2.excl : NULL);
    }
    printf("]");
    skipped_json(&st);
    printf("}\n");
    return 0;
}

int cmd_hysteria2_probe(const char *spec_path, const char *out_name, int node, int timeout_s,
                        int insecure) {
    (void)insecure;                                    /* см. cmd_hysteria2_nodes */
    struct output *o = NULL;
    size_t cnt = 0;
    struct hy2_sub_stats st;
    int by_file = out_name && out_name[0] == '/';
    struct spec *sp = spec_new();
    int rc = by_file ? load_nodes_file(out_name, &cnt, &st)
                     : load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    if (!cnt) {
        printf("{\"ok\":false,\"error\":\"в подписке нет пригодных узлов hysteria2\",\"skipped\":%zu,"
               "\"foreign\":%zu", st.skipped, st.foreign);
        skipped_json(&st);
        printf("}\n");
        return 1;
    }
    if (node >= (int)cnt) {
        printf("{\"ok\":false,\"error\":\"узла %d нет, всего %zu\"}\n", node, cnt);
        return 1;
    }
    size_t sel_cap;
    int *sel = sel_alloc(o, cnt, &sel_cap);
    size_t sel_n = 0;
    if (node >= 0) { sel[0] = node; sel_n = 1; }
    else if (by_file) {
        for (size_t i = 0; i < cnt; i++) sel[sel_n++] = (int)i;
    } else {
        sel_n = out_hy2_node_list(o, cnt, sel, sel_cap);
        if (!sel_n) {
            printf("{\"ok\":false,\"error\":\"выбранных узлов нет в подписке, пригодных всего %zu\"}\n", cnt);
            return 1;
        }
        sel_n = exclude_filter(o, g_nodes, sel, sel_n);
        if (!sel_n) {
            printf("{\"ok\":false,\"error\":\"все выбранные узлы исключены exclude, exclude_name или only\"}\n");
            return 1;
        }
    }
    int found = -1;
    printf("{\"output\":");
    jsonw_str(stdout, by_file ? "" : out_name);
    printf(",\"sub_file\":");
    jsonw_str(stdout, by_file ? out_name : o->hy2.sub_file);
    printf(",\"results\":[");
    for (size_t k = 0; k < sel_n; k++) {
        size_t i = (size_t)sel[k];
        char why[256] = "";
        int hs = -1;
        int pr = hy2_probe(&g_nodes[i], timeout_s > 0 ? timeout_s : 8, why, sizeof(why), &hs);
        if (k) putchar(',');
        printf("{\"index\":%zu,\"name\":", i);
        jsonw_str(stdout, g_nodes[i].name);
        printf(",\"type\":\"hysteria2\",\"ok\":%s,\"handshake_ms\":%d,\"ttfb_ms\":-1,\"why\":",
               pr == 0 ? "true" : "false", hs);
        jsonw_str(stdout, why);
        printf("}");
        if (pr == 0) { found = (int)i; if (node < 0) break; }
    }
    printf("],\"working\":%d}\n", found);
    return found >= 0 ? 0 : 1;
}

/* ---- файл состояния для status и diag --------------------------------------------------------- */

static char g_state_out[64];
static const struct hy2_node *g_cur;

/* СТРАНА ВЫХОДА. node_cc — по флагу в имени узла, geo_cc — какую видят сайты через выход (одна проверка
 * geo.c после подъёма: узел у hysteria2 на ходу не меняется — клиент перезапускается). Поля состояния
 * читает сторож групп (only и exclude группы, daemon/fogroup.c) и status. geo.c — только в libsteer
 * (слабая ссылка): без него проверки нет. */
int geo_trace(const char *dev, char cc[3], char *why, size_t wn) __attribute__((weak));
static int g_geo_state;             /* 0 — нет, 1 — страна получена, 2 — не вышло (атомарно) */
static char g_geo_cc[3];

static void *geo_thread(void *arg) {
    char dev[16], why[200];
    snprintf(dev, sizeof(dev), "%s", (const char *)arg);
    for (int tries = 0; tries < 2; tries++) {
        char cc[3];
        if (geo_trace(dev, cc, why, sizeof(why)) == 0) {
            memcpy(g_geo_cc, cc, 3);
            __atomic_store_n(&g_geo_state, 1, __ATOMIC_RELEASE);
            if (node_cc(g_cur->name, cc) && strcmp(cc, g_geo_cc) != 0)
                fprintf(stderr, LOG_W2 "узел %s назван страной %s, а выход виден из %s\n", g_cur->name, cc,
                        g_geo_cc);
            return NULL;
        }
        if (tries == 0) sleep(20);
    }
    fprintf(stderr, LOG_I2 "страна выхода не определилась: %s\n", why);
    __atomic_store_n(&g_geo_state, 2, __ATOMIC_RELEASE);
    return NULL;
}

static void state_write(void) {
    char path[300], tmp[320];
    snprintf(path, sizeof(path), "%s/hy2-%.32s", steer_state_dir(), g_state_out);
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    struct hy2c_status s;
    hy2c_status(&s);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"pid\":%ld,\"node\":", (long)getpid());
    jsonw_str(f, g_cur->name);
    char ncc[3];
    int has = node_cc(g_cur->name, ncc);
    if (has) fprintf(f, ",\"node_cc\":\"%s\"", ncc);
    int gs = __atomic_load_n(&g_geo_state, __ATOMIC_ACQUIRE);
    if (gs == 1) {
        fprintf(f, ",\"geo_cc\":\"%s\"", g_geo_cc);
        if (has && strcmp(ncc, g_geo_cc) != 0) fputs(",\"geo_mismatch\":true", f);
    } else if (gs == 2) fputs(",\"geo_failed\":true", f);
    fprintf(f, ",\"up\":%s,\"hs_ms\":%u,\"cc\":\"%s\",\"brutal_bps\":%llu,\"udp\":%s,\"obfs\":\"%s\","
               "\"hop\":%s,\"rtt_ms\":%llu,\"flows\":%u,\"error\":",
            s.up ? "true" : "false", s.hs_ms, s.brutal ? "brutal" : "bbr",
            (unsigned long long)s.brutal_bps, s.udp_ok ? "true" : "false",
            g_cur->obfs == 2 ? "gecko" : g_cur->obfs ? "salamander" : "", g_cur->hop_n ? "true" : "false",
            (unsigned long long)(s.rtt_us / 1000), s.flows);
    jsonw_str(f, s.up ? "" : s.err);
    fprintf(f, "}\n");
    fclose(f);
    if (rename(tmp, path) != 0) unlink(tmp);
}

static void *state_thread(void *arg) {
    (void)arg;
    for (;;) {
        /* Имя узла разрешается тут, а не в цикле рабочего: getaddrinfo блокирует (hy2conn.c). */
        hy2c_refresh_addr();
        state_write();
        struct timespec ts = { 3, 0 };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ---- слежка за узлом -------------------------------------------------------------------------- */

#define NW_PERIOD_S    60
/* Период проверки — ключ `interval` выхода (умолчание NW_PERIOD_S). */
static int g_nw_period_s = NW_PERIOD_S;
#define NW_CONFIRM_S   3
#define NW_RETRY_S     15
#define NW_RETRY_MAX_S 300
#define NW_STREAK      3
#define NW_TIMEOUT_S   8

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    int on, streak, kick;
    const struct hy2_node *nodes;
    const int *sel;
    size_t sel_n;
    int cur, checked;
    char dev[16];
} g_nw = { .mu = PTHREAD_MUTEX_INITIALIZER };

static void nw_up(int watch) {
    if (g_nw.dev[0] && watch)
        evline_emit("up", "watch", EVLINE_INT, 1L, "dev", EVLINE_STR, g_nw.dev, (const char *)NULL);
    else if (g_nw.dev[0])
        evline_emit("up", "dev", EVLINE_STR, g_nw.dev, (const char *)NULL);
    else if (watch)
        evline_emit("up", "watch", EVLINE_INT, 1L, (const char *)NULL);
    else
        evline_emit("up", (const char *)NULL);
}

/* Исход открытия потока (от дайлера): серия отказов зовёт проверку раньше срока. */
void hy2_watch_seen(int rc) {
    if (!__atomic_load_n(&g_nw.on, __ATOMIC_ACQUIRE)) return;
    pthread_mutex_lock(&g_nw.mu);
    if (rc == 0) g_nw.streak = 0;
    else if (++g_nw.streak >= NW_STREAK) {
        g_nw.kick = 1;
        pthread_cond_signal(&g_nw.cv);
    }
    pthread_mutex_unlock(&g_nw.mu);
}

static uint64_t nw_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static void nw_wait(uint64_t due, int up) {
    struct timespec ts = { .tv_sec = (time_t)(due / 1000), .tv_nsec = (long)(due % 1000) * 1000000L };
    while (!(up && g_nw.kick) && nw_now_ms() < due)
        pthread_cond_timedwait(&g_nw.cv, &g_nw.mu, &ts);
    g_nw.kick = 0;
}

/* Причина в событии down — не длиннее записи линии событий (EVLINE_WRITE_MAX 480 байт, кириллица в
 * ней по шесть знаков на байт), обрезка по границе знака UTF-8. Довод — pl_down_event в src/tunnel/pool.c. */
#define NW_WHY_ESC 440
static void nw_down(const char *why) {
    char w[160];
    size_t n = 0, esc = 0;
    for (const unsigned char *s = (const unsigned char *)why; *s && n + 1 < sizeof(w); ) {
        size_t len = *s >= 0xF0 ? 4 : *s >= 0xE0 ? 3 : *s >= 0xC0 ? 2 : 1;
        size_t cost = 0, k;
        for (k = 0; k < len && s[k]; k++)
            cost += s[k] >= 0x80 || s[k] < 0x20 ? 6 : (s[k] == '"' || s[k] == '\\') ? 2 : 1;
        if (k < len || n + len + 1 > sizeof(w) || esc + cost > NW_WHY_ESC) break;
        memcpy(w + n, s, len);
        n += len;
        esc += cost;
        s += len;
    }
    w[n] = '\0';
    evline_emit("down", "why", EVLINE_STR, w[0] ? w : "узел не отвечает", (const char *)NULL);
}

/* Проверка узла наперегонки (pool_race_first, I-535). Рукопожатие и авторизацию в мс несёт строка why. */
static int hy_race_probe(void *arg, int id, char *why, size_t n) {
    int hs = 0;
    int rc = hy2_probe(&((const struct hy2_node *)arg)[id], 8, why, n, &hs);
    if (rc == 0) snprintf(why, n, "рукопожатие и авторизация %d мс", hs);
    return rc;
}
static void *nw_thread(void *arg) {
    (void)arg;
    const struct hy2_node *cur = &g_nw.nodes[g_nw.cur];
    int up = 1, fails = 0;
    uint64_t retry = NW_RETRY_S;
    uint64_t due = nw_now_ms() + (g_nw.checked ? (uint64_t)g_nw_period_s * 1000ull : 0);
    char why[256];
    int hs;
    for (;;) {
        pthread_mutex_lock(&g_nw.mu);
        nw_wait(due, up);
        pthread_mutex_unlock(&g_nw.mu);
        if (up) {
            /* Соединение туннеля с узлом живо (поднято, и узел отвечает на PING) — это и есть
             * ответ проверки: отдельное рукопожатие и авторизация раз в interval ничего к нему не
             * прибавили бы, а узлу — лишнее соединение каждую минуту. Проба — когда соединения
             * нет или узел замолчал. */
            if (hy2c_alive() || hy2_probe(cur, NW_TIMEOUT_S, why, sizeof(why), &hs) == 0) {
                fails = 0;
                pthread_mutex_lock(&g_nw.mu);
                g_nw.streak = 0;
                pthread_mutex_unlock(&g_nw.mu);
                due = nw_now_ms() + (uint64_t)g_nw_period_s * 1000ull;
                continue;
            }
            if (++fails < 2) { due = nw_now_ms() + NW_CONFIRM_S * 1000ull; continue; }
            up = 0;
            fails = 0;
            retry = NW_RETRY_S;
            nw_down(why);
            fprintf(stderr, LOG_W2 "узел %s не отвечает: %s — проверяю узлы\n", cur->name, why);
            due = nw_now_ms() + retry * 1000ull;
            continue;
        }
        if (hy2_probe(cur, NW_TIMEOUT_S, why, sizeof(why), &hs) == 0) {
            up = 1;
            pthread_mutex_lock(&g_nw.mu);
            g_nw.streak = 0;
            g_nw.kick = 0;
            pthread_mutex_unlock(&g_nw.mu);
            nw_up(1);
            fprintf(stderr, LOG_I2 "узел %s снова отвечает\n", cur->name);
            due = nw_now_ms() + (uint64_t)g_nw_period_s * 1000ull;
            continue;
        }
        {
            /* Остальные кандидаты — наперегонки: ответил хоть один — выходим, чтобы выбрать узел заново. */
            int *others = malloc((g_nw.sel_n ? g_nw.sel_n : 1) * sizeof(*others));
            size_t on = 0;
            for (size_t k = 0; others && k < g_nw.sel_n; k++)
                if (g_nw.sel[k] != g_nw.cur) others[on++] = g_nw.sel[k];
            struct pool_race pr = { .n = on, .ids = others, .probe = hy_race_probe, .arg = (void *)g_nw.nodes };
            int w = on ? pool_race_first(&pr, why, sizeof(why)) : -1;
            free(others);
            if (w >= 0) {
                fprintf(stderr, LOG_W2 "узел %s не отвечает, а %s отвечает — выхожу, чтобы выбрать "
                                "узел заново\n", cur->name, g_nw.nodes[w].name);
                exit(0);
            }
        }
        retry = retry * 2 > NW_RETRY_MAX_S ? NW_RETRY_MAX_S : retry * 2;
        due = nw_now_ms() + retry * 1000ull;
    }
    return NULL;
}

static void watch_start(const struct hy2_node *nodes, const int *sel, size_t sel_n, int cur,
                        int checked, const char *dev) {
    snprintf(g_nw.dev, sizeof(g_nw.dev), "%s", dev ? dev : "");
    if (!evline_enabled()) { nw_up(0); return; }
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_nw.cv, &ca);
    pthread_condattr_destroy(&ca);
    g_nw.nodes = nodes;
    g_nw.sel = sel;
    g_nw.sel_n = sel_n;
    g_nw.cur = cur;
    g_nw.checked = checked;
    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstacksize(&a, thread_stack(512 * 1024));
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    pthread_mutex_lock(&g_nw.mu);
    int err = pthread_create(&t, &a, nw_thread, NULL);
    pthread_attr_destroy(&a);
    if (err) {
        pthread_mutex_unlock(&g_nw.mu);
        fprintf(stderr, LOG_W2 "поток слежки за узлом не создался (%s) — потерю узла клиент "
                        "не заметит\n", strerror(err));
        nw_up(0);
        return;
    }
    __atomic_store_n(&g_nw.on, 1, __ATOMIC_RELEASE);
    nw_up(1);
    pthread_mutex_unlock(&g_nw.mu);
}

/* ---- подъём выхода ---------------------------------------------------------------------------- */

static void h2_probe_report(const char *out_name, enum probe_state st, int node, int total) {
    if (!evline_enabled()) probe_report(out_name, st, node, total);
}

struct ready_arg {
    const struct hy2_node *nodes;
    const int *sel;
    size_t sel_n;
    int cur, checked;
};

/* Устройство поднято: сказать демону up и завести слежку. Маршрут выхода ставит демон по dev
 * (docs/ctl.md); без демона его не ставит никто — об этом одна строка в журнал. */
static void h2_ready(void *arg, const char *dev) {
    const struct ready_arg *ra = arg;
    static pthread_t st;
    pthread_create(&st, NULL, state_thread, NULL);
    pthread_detach(st);
    watch_start(ra->nodes, ra->sel, ra->sel_n, ra->cur, ra->checked, dev);
    if (geo_trace && dev && dev[0]) {
        static char gdev[16];
        static pthread_t gt;
        snprintf(gdev, sizeof(gdev), "%s", dev);
        if (pthread_create(&gt, NULL, geo_thread, gdev) == 0) pthread_detach(gt);
    }
    if (!evline_enabled())
        fprintf(stderr, LOG_I2 "%s поднят; маршрут выхода к нему ставит демон — без демона "
                        "таблица выхода не тронута\n", dev);
}

static const char *g_race_out;
static void hy_race_start(void *arg, int id, size_t k, size_t n) {
    (void)arg; (void)id;
    h2_probe_report(g_race_out, PROBE_RUNNING, (int)k, (int)n);
    evline_emit("node", "n", EVLINE_INT, (long)k, "total", EVLINE_INT, (long)n, (const char *)NULL);
}
static void hy_race_fail(void *arg, int id, const char *why) {
    fprintf(stderr, LOG_I2 "%s — %s\n", ((const struct hy2_node *)arg)[id].name, why);
}

int cmd_hysteria2(const char *spec_path, const char *out_name) {
    evline_open();
    struct output *o = NULL;
    size_t cnt = 0;
    struct hy2_sub_stats st;
    struct spec *sp = spec_new();
    int rc = load_nodes(sp, spec_path, out_name, &o, &cnt, &st);
    if (rc) return rc;
    underlay_setup(sp, o);
    struct hy2_node *nodes = g_nodes;
    if (!cnt) {
        h2_probe_report(out_name, PROBE_FAILED, 0, 0);
        evline_emit("down", "why", EVLINE_STR, "в подписке нет пригодных узлов hysteria2",
                    (const char *)NULL);
        fprintf(stderr, LOG_W2 "в подписке нет пригодных узлов hysteria2 (пропущено %zu, чужих %zu)\n",
                st.skipped, st.foreign);
        for (size_t i = 0; i < st.reasons_n; i++)
            fprintf(stderr, LOG_W2 "  %s — узлов %zu%s%s\n", st.reasons[i].reason, st.reasons[i].count,
                    st.reasons[i].example[0] ? ", например " : "", st.reasons[i].example);
        return 1;
    }
    fprintf(stderr, LOG_I2 "узлов %zu (пропущено %zu, чужих %zu)\n", cnt, st.skipped, st.foreign);

    size_t sel_cap;
    int *sel = sel_alloc(o, cnt, &sel_cap);          /* живёт до конца процесса: его читает сторож */
    size_t sel_n = out_hy2_node_list(o, cnt, sel, sel_cap);
    if (!sel_n) {
        h2_probe_report(out_name, PROBE_NO_SUCH_NODE, o->hy2.nodes_n ? o->hy2.nodes[0] : -1, (int)cnt);
        evline_emit("nonode", "node", EVLINE_INT, (long)(o->hy2.nodes_n ? o->hy2.nodes[0] : -1),
                    "total", EVLINE_INT, (long)cnt, (const char *)NULL);
        fprintf(stderr, LOG_W2 "выбранных узлов нет в подписке (пригодных всего %zu) — проверьте nodes\n", cnt);
        return 1;
    }
    size_t before = sel_n;
    sel_n = exclude_filter(o, g_nodes, sel, sel_n);
    if (!sel_n) {
        h2_probe_report(out_name, PROBE_ALL_EXCLUDED, 0, (int)before);
        evline_emit("excluded", "total", EVLINE_INT, (long)before, (const char *)NULL);
        evline_emit("down", "why", EVLINE_STR, "все узлы-кандидаты исключены exclude", (const char *)NULL);
        fprintf(stderr, LOG_W2 "все %zu узлов-кандидатов исключены exclude, exclude_name или only — проверьте "
                        "исключение и подписку\n", before);
        return 1;
    }
    int chosen = -1;
    if (out_hy2_node_named(o)) {
        chosen = sel[0];
        probe_clear(out_name);
    } else {
        /* Кандидаты — наперегонки (pool_race_first, I-535), как у VLESS. */
        char why[256];
        g_race_out = out_name;
        struct pool_race pr = { .n = sel_n, .ids = sel, .probe = hy_race_probe, .arg = nodes,
                                .on_start = hy_race_start, .on_fail = hy_race_fail };
        chosen = pool_race_first(&pr, why, sizeof why);
        if (chosen >= 0) fprintf(stderr, LOG_I2 "выбран %s (%s)\n", nodes[chosen].name, why);
    }
    if (chosen < 0) {
        h2_probe_report(out_name, PROBE_FAILED, 0, (int)sel_n);
        evline_emit("down", "why", EVLINE_STR, "ни один узел подписки не отвечает", (const char *)NULL);
        fprintf(stderr, LOG_W2 "ни один узел подписки не отвечает\n");
        return 1;
    }
    probe_clear(out_name);
    static struct ready_arg ra;
    ra.nodes = nodes;
    ra.sel = sel;
    ra.sel_n = sel_n;
    ra.cur = chosen;
    ra.checked = !out_hy2_node_named(o);
    g_cur = &nodes[chosen];
    snprintf(g_state_out, sizeof(g_state_out), "%s", out_name);

    struct err e = {0};
    if (registry_assign(sp, &e) < 0) err_die(&e);
    /* Ключи пула, которые у hysteria2 есть: период проверки узла и срок простоя QUIC. */
    if (o->hy2.pool.interval_s) g_nw_period_s = o->hy2.pool.interval_s;
    hy2c_set_idle(o->hy2.pool.silence_s);
    return hy2_tunnel_run(o, &nodes[chosen], h2_ready, &ra);
}
