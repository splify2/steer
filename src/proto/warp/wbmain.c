/* Команды модуля steer-warpbox: помощник группы `kind: warp` и служебные warp-reg, warp-scan.
 *
 * ПОМОЩНИК (cmd_warp). Демон поднимает его для группы `kind: warp` (kinds/group.c, helper). Члены
 * группы — обычные выходы awg «<группа>.<n>», заведённые разбором (model/v2.c, p_warp): устройство,
 * метку, таблицу, здоровье и подхват ведёт ядро steer, как у любого awg. Модуль делает то, чего
 * ядро не знает:
 *   1. регистрация WARP на каждого члена (wbreg.c), кэш — {etc}/warp/<группа>-<n>.reg;
 *   2. подбор точек входа (wbscan.c) — разными колониями, если их хватает;
 *   3. файл члена {etc}/warp/<группа>-<n>.conf и событие `awg` демону: «перенастрой член» —
 *      демон перечитывает файл тем же awg_revive, что и сторож (daemon/supd.c);
 *   4. сторож: член без рукопожатия и без HTTPS через себя дважды подряд — замена точки; третья
 *      замена подряд — новые ключи (у апстрима ZM так лечится ключ, который Cloudflare перестал
 *      принимать); все точки рвёт DPI — следующая маска I1 для всей группы.
 * Интерфейсов (netifd) и правил фаервола модуль не заводит: устройства членов — выходы ядра, а
 * подбор идёт в своём пространстве сети (wbns.c).
 *
 * Состояние для человека — события up/down с причиной (status показывает их у группы) и журнал. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include "err.h"
#include "evline.h"
#include "jsonw.h"
#include "kind.h"
#include "platform.h"
#include "registry.h"
#include "spec.h"
#include "spec.h"
#include "awg.h"
#include "wbconf.h"
#include "wbns.h"
#include "wbreg.h"
#include "wbscan.h"

#define LOG(...) fprintf(stderr, "steer-warpbox: " __VA_ARGS__)

#define WB_CHECK_S 60           /* проход сторожа */
#define WB_HS_FRESH 180         /* рукопожатие моложе — туннель жив (как у awg_healthy) */
#define WB_FAILS 2              /* столько проходов подряд без признаков жизни — замена */
#define WB_REKEY_AT 3           /* на какой замене подряд — новые ключи */
#define WB_REKEY_MIN_S 86400    /* новые ключи не чаще раза в сутки на член */
#define WB_REG_RETRY_S 120

static volatile sig_atomic_t g_stop;
static void on_term(int sig) { (void)sig; g_stop = 1; }

static void nap(int s) {
    for (int i = 0; i < s * 4 && !g_stop; i++) {
        struct timespec t = { 0, 250000000L };
        nanosleep(&t, NULL);
    }
}

static int mkdir_p(const char *d, mode_t m) {
    char b[512];
    snprintf(b, sizeof(b), "%s", d);
    for (char *p = b + 1; *p; p++)
        if (*p == '/') { *p = '\0'; mkdir(b, 0755); *p = '/'; }
    return mkdir(b, m) == 0 || errno == EEXIST ? 0 : -1;
}

struct member {
    const struct output *o;
    char reg_path[512], conf_path[512];
    struct wb_reg reg;
    int have_reg;
    char ip[16];
    unsigned port;
    char colo[4], seen[3];
    int ok;                     /* последний проход: жив */
    int fails;                  /* проходов подряд без жизни */
    int replaced;               /* замен подряд без успеха */
    time_t rekey_at;
    time_t reg_retry;
};

struct wb {
    struct spec *sp;
    const struct output *g;
    struct member *m;
    size_t n;
    int ns;
    int obfs;
    int mask;
    char i1[8192];
    char etc[512], st[512];
    char (*xcc_def)[3];
};

static void mask_load(struct wb *w) {
    char p[600];
    snprintf(p, sizeof(p), "%s/mask", w->st);
    FILE *f = fopen(p, "r");
    w->mask = 0;
    if (f) { if (fscanf(f, "%d", &w->mask) != 1 || w->mask < 0 || w->mask >= WB_MASKS) w->mask = 0; fclose(f); }
    const char *name;
    if (!wb_mask(w->mask, w->i1, sizeof(w->i1), &name)) w->i1[0] = '\0';
}

static void mask_next(struct wb *w) {
    w->mask = (w->mask + 1) % WB_MASKS;
    const char *name;
    if (!wb_mask(w->mask, w->i1, sizeof(w->i1), &name)) w->i1[0] = '\0';
    LOG("маска первого пакета: %s\n", name);
    char p[600];
    snprintf(p, sizeof(p), "%s/mask", w->st);
    FILE *f = fopen(p, "w");
    if (f) { fprintf(f, "%d\n", w->mask); fclose(f); }
}

static int member_reg(struct member *m, int fresh) {
    char why[256] = "";
    if (!fresh && wb_reg_load(m->reg_path, &m->reg) == 0) { m->have_reg = 1; return 0; }
    if (time(NULL) < m->reg_retry) return -1;
    LOG("%s: регистрация устройства WARP\n", m->o->name);
    struct wb_reg r;
    if (wb_register(&r, why, sizeof(why)) != 0) {
        LOG("%s: регистрация не удалась — %s; повтор через %d с\n", m->o->name, why, WB_REG_RETRY_S);
        m->reg_retry = time(NULL) + WB_REG_RETRY_S;
        return -1;
    }
    if (wb_reg_save(m->reg_path, &r) != 0)
        LOG("%s: регистрацию не сохранить в %s: %s — после перезапуска будет новая\n", m->o->name, m->reg_path, strerror(errno));
    wb_reg_wipe(&m->reg);
    m->reg = r;
    wb_reg_wipe(&r);
    m->have_reg = 1;
    LOG("%s: зарегистрировано (%s)\n", m->o->name, m->reg.api);
    return 0;
}

/* Поставить точку члену: файл и событие демону. */
static int member_set(struct wb *w, struct member *m, const struct wb_pt *p) {
    char ep[40];
    snprintf(ep, sizeof(ep), "%s:%u", p->ip, p->port);
    struct wb_conf c = { .reg = &m->reg, .endpoint = ep, .i1 = w->i1, .obfs = w->obfs, .addr = 1, .keepalive = 25 };
    if (wb_conf_write(m->conf_path, &c) != 0) {
        LOG("%s: файл %s не записан: %s\n", m->o->name, m->conf_path, strerror(errno));
        return -1;
    }
    snprintf(m->ip, sizeof(m->ip), "%s", p->ip);
    m->port = p->port;
    snprintf(m->colo, sizeof(m->colo), "%s", p->colo);
    snprintf(m->seen, sizeof(m->seen), "%s", p->seen);
    LOG("%s: точка %s (колония %s%s%s)\n", m->o->name, ep, p->colo, p->seen[0] ? ", сайты видят " : "", p->seen);
    evline_emit("awg", "out", EVLINE_STR, m->o->name, (const char *)NULL);
    return 0;
}

static void scan_setup(struct wb *w, struct wb_scan *s, const struct wb_reg *reg) {
    const struct group_cfg *gc = &w->g->grp;
    memset(s, 0, sizeof(*s));
    s->sp = w->sp;
    s->ns = w->ns;
    s->over = w->m[0].o->over[0] ? w->m[0].o->over : NULL;
    s->reg = reg;
    s->i1 = w->i1[0] ? w->i1 : NULL;
    s->obfs = w->obfs;
    s->dir = w->st;
    s->cc = (const char (*)[3])gc->warp.cc;
    s->cc_n = gc->warp.cc_n;
    if (gc->warp.xcc_set || gc->warp.cc_n) {
        s->xcc = (const char (*)[3])gc->warp.xcc;
        s->xcc_n = gc->warp.xcc_n;
    } else {
        static const char RU[1][3] = { "RU" };
        s->xcc = RU;
        s->xcc_n = 1;
    }
}

/* Подобрать точки членам с нужда[i]. Остальные — занятые колонии и адреса. */
static int assign(struct wb *w, const int *need) {
    size_t nn = 0;
    const struct wb_reg *key = NULL;
    for (size_t i = 0; i < w->n; i++) if (need[i]) { nn++; if (!key && w->m[i].have_reg) key = &w->m[i].reg; }
    if (!nn) return 0;
    if (!key) return -1;
    char (*bc)[4] = calloc(w->n, sizeof(*bc));
    char (*bi)[16] = calloc(w->n, sizeof(*bi));
    if (!bc || !bi) { free(bc); free(bi); return -1; }
    size_t bcn = 0, bin = 0;
    for (size_t i = 0; i < w->n; i++) {
        if (need[i] || !w->m[i].ip[0]) continue;
        if (w->m[i].colo[0]) snprintf(bc[bcn++], 4, "%s", w->m[i].colo);
        snprintf(bi[bin++], 16, "%s", w->m[i].ip);
    }
    int rc = -1;
    for (int attempt = 0; attempt < WB_MASKS && !g_stop; attempt++) {
        struct wb_scan s;
        scan_setup(w, &s, key);
        s.busy_colo = (const char (*)[4])bc;
        s.busy_colo_n = bcn;
        s.busy_ip = (const char (*)[16])bi;
        s.busy_ip_n = bin;
        s.want = nn + 1;
        s.quick = attempt > 0;
        for (size_t i = 0; i < w->n; i++) if (need[i]) { s.rot = (unsigned)i; break; }
        if (wb_scan_run(&s) != 0) {
            LOG("подбор: %s\n", s.why);
            int torn = s.torn > 0;
            wb_scan_free(&s);
            if (torn && w->obfs) { mask_next(w); continue; }
            evline_emit("down", "why", EVLINE_STR, s.why, (const char *)NULL);
            break;
        }
        /* Разными колониями, пока их хватает; затем — разными адресами. */
        int *used = calloc(s.out_n, sizeof(*used));
        if (!used) { wb_scan_free(&s); break; }
        for (int pass = 0; pass < 2; pass++)
            for (size_t i = 0; i < w->n; i++) {
                if (!need[i] || w->m[i].ip[0]) continue;
                for (size_t k = 0; k < s.out_n; k++) {
                    if (used[k]) continue;
                    int clash = 0;
                    for (size_t j = 0; j < w->n && !pass; j++)
                        if (j != i && w->m[j].ip[0] && !strcmp(w->m[j].colo, s.out[k].colo)) clash = 1;
                    if (clash) continue;
                    used[k] = 1;
                    member_set(w, &w->m[i], &s.out[k]);
                    break;
                }
            }
        free(used);
        wb_scan_free(&s);
        rc = 0;
        break;
    }
    free(bc);
    free(bi);
    return rc;
}

/* Жив ли член: рукопожатие свежее, а если нет — HTTPS через его устройство. */
static int member_alive(struct member *m) {
    int64_t hs;
    uint64_t rx, tx;
    if (awg_scan_stat(m->o->device, -1, &hs, &rx, &tx) != 0) return 0;
    struct wb_pt p;
    memset(&p, 0, sizeof(p));
    if (hs > 0 && time(NULL) - hs <= WB_HS_FRESH) return 1;
    if (wb_trace_dev(m->o->device, &p) == 0) {
        if (p.colo[0]) snprintf(m->colo, sizeof(m->colo), "%s", p.colo);
        return 1;
    }
    return 0;
}

static int load(struct wb *w, const char *spec_path, const char *group) {
    struct err e = { 0 };
    w->sp = calloc(1, sizeof(*w->sp));
    if (!w->sp) return 2;
    if (load_spec(spec_path, w->sp, &e) < 0) err_die(&e);
    if (registry_assign(w->sp, &e) < 0) err_die(&e);
    w->g = out_by_name(w->sp, group);
    if (!w->g || !out_group(w->g) || !w->g->grp.warp.on) {
        LOG("группы kind: warp с именем %s нет в спеке\n", group);
        return 2;
    }
    w->m = calloc(w->g->grp.members_n ? w->g->grp.members_n : 1, sizeof(*w->m));
    if (!w->m) return 2;
    snprintf(w->etc, sizeof(w->etc), "%s/warp", plat()->etc_dir);
    snprintf(w->st, sizeof(w->st), "%s/warp-%s", steer_state_dir(), group);
    if (mkdir_p(w->etc, 0700) || mkdir_p(w->st, 0700)) {
        LOG("каталоги %s и %s не создать: %s\n", w->etc, w->st, strerror(errno));
        return 2;
    }
    for (size_t k = 0; k < w->g->grp.members_n; k++) {
        const struct output *o = spec_out(w->sp, w->g->grp.members[k]);
        if (!o || strcmp(o->warp_of, group) != 0) continue;
        struct member *m = &w->m[w->n++];
        m->o = o;
        snprintf(m->conf_path, sizeof(m->conf_path), "%s", o->awg.conf);
        snprintf(m->reg_path, sizeof(m->reg_path), "%.*s.reg", (int)(strlen(o->awg.conf) - 5), o->awg.conf);
    }
    return w->n ? 0 : 2;
}

int cmd_warp(const char *spec_path, const char *group) {
    evline_open();
    signal(SIGTERM, on_term);
    signal(SIGINT, on_term);
    struct wb w;
    memset(&w, 0, sizeof(w));
    int rc = load(&w, spec_path, group);
    if (rc) return rc;
    if (w.g->grp.warp.transport != WARP_AWG) {
        evline_emit("down", "why", EVLINE_STR, "MASQUE — следующий этап", (const char *)NULL);
        return 2;
    }
    w.ns = wb_ns_new();
    if (w.ns < 0) {
        char why[160];
        snprintf(why, sizeof(why), "своё пространство сети для подбора не создать: %s", strerror(errno));
        LOG("%s\n", why);
        evline_emit("down", "why", EVLINE_STR, why, (const char *)NULL);
        return 1;
    }
    w.obfs = awg_kernel_has_awg();
    if (!w.obfs) LOG("в ядре нет AmneziaWG — туннели WARP без обфускации (обычный WireGuard)\n");
    mask_load(&w);
    int *need = calloc(w.n, sizeof(*need));
    if (!need) return 1;
    int said_up = -1;
    while (!g_stop) {
        /* Регистрации. */
        for (size_t i = 0; i < w.n && !g_stop; i++)
            if (!w.m[i].have_reg) member_reg(&w.m[i], 0);
        /* Кто жив, кому нужна точка. */
        size_t alive = 0;
        for (size_t i = 0; i < w.n; i++) {
            struct member *m = &w.m[i];
            need[i] = 0;
            if (!m->have_reg) continue;
            if (!m->ip[0]) {
                char ep[64];
                /* Файл уже есть (прошлый запуск) — сначала проверить его, а не подбирать заново. */
                if (wb_conf_endpoint(m->conf_path, ep, sizeof(ep)) == 0 && strchr(ep, ':')) {
                    *strrchr(ep, ':') = '\0';
                    snprintf(m->ip, sizeof(m->ip), "%.15s", ep);
                    m->fails = WB_FAILS - 1;            /* одна неудача — и замена */
                } else { need[i] = 1; continue; }
            }
            if (member_alive(m)) {
                if (!m->ok) LOG("%s: работает (%s%s%s)\n", m->o->name, m->ip, m->colo[0] ? ", колония " : "", m->colo);
                m->ok = 1;
                m->fails = 0;
                m->replaced = 0;
                alive++;
                continue;
            }
            m->ok = 0;
            if (++m->fails < WB_FAILS) continue;
            m->fails = 0;
            if (++m->replaced >= WB_REKEY_AT && time(NULL) >= m->rekey_at) {
                LOG("%s: %d замены подряд не помогли — новые ключи\n", m->o->name, m->replaced - 1);
                m->rekey_at = time(NULL) + WB_REKEY_MIN_S;
                m->replaced = 0;
                if (member_reg(m, 1) != 0) continue;
            } else
                LOG("%s: точка %s не отвечает — подбираю другую\n", m->o->name, m->ip);
            m->ip[0] = m->colo[0] = '\0';
            need[i] = 1;
        }
        if (assign(&w, need) == 0)
            for (size_t i = 0; i < w.n; i++) if (need[i] && w.m[i].ip[0]) alive++;
        int up = alive > 0;
        if (up != said_up) {
            if (up) evline_emit("up", (const char *)NULL);
            else evline_emit("down", "why", EVLINE_STR, "ни один туннель WARP не работает", (const char *)NULL);
            said_up = up;
        }
        nap(WB_CHECK_S);
    }
    free(need);
    for (size_t i = 0; i < w.n; i++) wb_reg_wipe(&w.m[i].reg);
    return 0;
}

/* ---- служебные ------------------------------------------------------------------------------ */

int cmd_warp_reg(const char *path) {
    struct wb_reg r;
    char why[256] = "";
    if (wb_reg_load(path, &r) == 0) {
        printf("{\"ok\":true,\"cached\":true,\"api\":\"%s\",\"v4\":\"%s\"}\n", r.api, r.v4);
        wb_reg_wipe(&r);
        return 0;
    }
    if (wb_register(&r, why, sizeof(why)) != 0) {
        printf("{\"ok\":false,\"error\":");
        jsonw_str(stdout, why);
        printf("}\n");
        return 1;
    }
    int sv = wb_reg_save(path, &r);
    printf("{\"ok\":true,\"cached\":false,\"api\":\"%s\",\"v4\":\"%s\",\"saved\":%s}\n", r.api, r.v4, sv ? "false" : "true");
    wb_reg_wipe(&r);
    return sv ? 1 : 0;
}

int cmd_warp_scan(const char *spec_path, const char *group) {
    struct wb w;
    memset(&w, 0, sizeof(w));
    int rc = load(&w, spec_path, group);
    if (rc) return rc;
    w.ns = wb_ns_new();
    if (w.ns < 0) {
        printf("{\"ok\":false,\"error\":");
        jsonw_str(stdout, strerror(errno));
        printf("}\n");
        return 1;
    }
    w.obfs = awg_kernel_has_awg();
    mask_load(&w);
    if (member_reg(&w.m[0], 0) != 0) { printf("{\"ok\":false,\"error\":\"регистрации нет\"}\n"); return 1; }
    struct wb_scan s;
    scan_setup(&w, &s, &w.m[0].reg);
    s.want = w.n + 2;
    rc = wb_scan_run(&s);
    printf("{\"ok\":%s,\"points\":[", rc ? "false" : "true");
    for (size_t i = 0; i < s.out_n; i++) {
        const struct wb_pt *p = &s.out[i];
        printf("%s{\"ip\":\"%s\",\"port\":%u,\"class\":%d,\"loss\":%d,\"rtt\":%d,\"colo\":\"%s\",\"cc\":\"%s\","
               "\"seen\":\"%s\",\"warp\":%s}", i ? "," : "", p->ip, p->port, p->cls, p->loss, p->rtt, p->colo, p->cc,
               p->seen, p->warp ? "true" : "false");
    }
    printf("],\"torn\":%d,\"filtered\":%d", s.torn, s.rufilt);
    if (rc) { printf(",\"error\":"); jsonw_str(stdout, s.why); }
    printf("}\n");
    wb_scan_free(&s);
    wb_reg_wipe(&w.m[0].reg);
    return rc ? 1 : 0;
}
