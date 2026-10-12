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
#include "awg.h"
#include "wbconf.h"
#include "wbns.h"
#include "wbmq.h"
#include "marks.h"
#include <pthread.h>
#include "wbping.h"
#include "wbreg.h"
#include "wbscan.h"

#define LOG(...) fprintf(stderr, "steer-warpbox: " __VA_ARGS__)

#define WB_CHECK_S 30           /* проход сторожа: отказ туннеля ядро узнаёт отсюда (событие member) */
#define WB_FAILS 2              /* столько проходов подряд без признаков жизни — замена */
#define WB_REKEY_AT 3           /* на какой замене подряд — новые ключи */
#define WB_REKEY_MIN_S 86400    /* новые ключи не чаще раза в сутки на член */
#define WB_REG_RETRY_S 120
#define WB_MQ_GRACE_S 15        /* туннелю MASQUE после новой точки — на рукопожатие и CONNECT */
#define WB_BAD_S 1800           /* снятая точка не возвращается полчаса: молчит она чаще всего не случайно */
#define WB_OPT_S 600            /* замер точек для смены на ходу, когда interval не задан (как у группы, v2.c) */

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
    char ip[48];
    unsigned port;
    char colo[4], seen[3];
    int ok;                     /* последний проход: жив */
    int fails;                  /* проходов подряд без жизни */
    int replaced;               /* замен подряд без успеха */
    int pt_saved;               /* колония и страна точки записаны в .pt */
    int awg;                    /* член awg (transport: awg); иначе MASQUE */
    int said;                   /* последний приговор демону (member): 1, 0, -1; 2 — ещё не говорили */
    char bad_ip[48];            /* точка, которую только что сняли: в подбор не берётся WB_BAD_S */
    unsigned bad_port;          /* у MASQUE снимается пара адрес:порт */
    struct wb_mq *mq;           /* туннель MASQUE (transport: masque) */
    long mq_set_ms;             /* когда туннелю дана точка: до WB_MQ_GRACE_S он «ещё поднимается» */
    time_t bad_until;
    time_t rekey_at;
    time_t reg_retry;
};

struct wb {
    struct spec *sp;
    const struct output *g;
    struct member *m;
    size_t n;
    struct member scan;         /* своя регистрация замера awg: точки мерятся не ключом живого туннеля */
    time_t opt_at;              /* следующий замер «самой быстрой точки» */
    int ns;
    int obfs;
    int mq;                     /* transport: masque */
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

/* Приговор члену — демону (событие member, daemon/supd.c): 0 — мёртв, ядро уводит группу с него в
 * этом же проходе сторожа, не дожидаясь, пока рукопожатие устареет (у awg это до трёх минут); 1 —
 * жив; -1 — не знаю (новая точка ещё не проверена): решает ядро по рукопожатию. Только при смене. */
static void member_say(struct member *m, int v) {
    if (m->said == v) return;
    m->said = v;
    evline_emit("member", "out", EVLINE_STR, m->o->name, "ok", EVLINE_INT, (long)v, (const char *)NULL);
}

/* Колония и страна точки члена — в каталоге состояния: после перезапуска модуля точка берётся из
 * файла туннеля, а колонию из него не узнать, и разнесение туннелей по колониям потеряло бы её. */
static void pt_path(const struct wb *w, const struct member *m, char *p, size_t n) {
    snprintf(p, n, "%s/%s.pt", w->st, m->o->name);
}

static void pt_save(const struct wb *w, const struct member *m) {
    char p[600];
    pt_path(w, m, p, sizeof(p));
    FILE *f = fopen(p, "w");
    if (!f) return;
    fprintf(f, "%s %s %s\n", m->ip, m->colo[0] ? m->colo : "-", m->seen[0] ? m->seen : "-");
    fclose(f);
}

static void pt_load(const struct wb *w, struct member *m) {
    char p[600], ip[48], colo[8], seen[8];
    pt_path(w, m, p, sizeof(p));
    FILE *f = fopen(p, "r");
    if (!f) return;
    if (fscanf(f, "%47s %7s %7s", ip, colo, seen) == 3 && !strcmp(ip, m->ip)) {
        if (strcmp(colo, "-")) snprintf(m->colo, sizeof(m->colo), "%.3s", colo);
        if (strcmp(seen, "-")) snprintf(m->seen, sizeof(m->seen), "%.2s", seen);
    }
    fclose(f);
}

/* Поставить точку члену: файл и событие демону. */
static int member_set(struct wb *w, struct member *m, const struct wb_pt *p, int fresh) {
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
    pt_save(w, m);
    m->pt_saved = 1;
    member_say(m, -1);
    evline_emit("awg", "out", EVLINE_STR, m->o->name, "fresh", EVLINE_INT, (long)(fresh != 0), (const char *)NULL);
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
    /* Без countries и exclude_countries — любые страны (решение владельца 2026-10-13: «сами
     * разберутся»); прежде здесь молча исключалась Россия. */
    s->xcc = (const char (*)[3])gc->warp.xcc;
    s->xcc_n = gc->warp.xcc_n;
}

/* Подобрать точки членам с нужда[i]. Остальные — занятые колонии и адреса. */
static int assign(struct wb *w, const int *need) {
    size_t nn = 0;
    const struct wb_reg *key = NULL;
    for (size_t i = 0; i < w->n; i++) if (need[i]) { nn++; if (!key && w->m[i].have_reg) key = &w->m[i].reg; }
    if (!nn) return 0;
    if (!key) return -1;
    char (*bc)[4] = calloc(w->n, sizeof(*bc));
    char (*bi)[16] = calloc(2 * w->n, sizeof(*bi));
    if (!bc || !bi) { free(bc); free(bi); return -1; }
    size_t bcn = 0, bin = 0;
    for (size_t i = 0; i < w->n; i++) {
        if (need[i] && w->m[i].bad_ip[0] && time(NULL) < w->m[i].bad_until)
            snprintf(bi[bin++], 16, "%.15s", w->m[i].bad_ip);
        if (need[i] || !w->m[i].ip[0]) continue;
        if (w->m[i].colo[0]) snprintf(bc[bcn++], 4, "%s", w->m[i].colo);
        snprintf(bi[bin++], 16, "%.15s", w->m[i].ip);
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
                    member_set(w, &w->m[i], &s.out[k], 0);
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

/* Жив ли член: 1 — эхо-запросы через его устройство возвращаются (или, если ICMP молчит, идёт HTTPS);
 * 0 — нет; -1 — устройства нет: демон его ещё не поднял (модуль стартует вместе с демоном, раньше
 * применения спеки) — это не приговор точке, а повод попросить демон поднять член ещё раз.
 *
 * Проверка ДЕЛОМ на каждом проходе, а не по свежести рукопожатия: рукопожатие считается свежим ещё
 * три минуты после обрыва (WireGuard обновляет ключи раз в две), и по нему отказ замечался через
 * 118 с после того, как точку перерезали (стенд QEMU 2026-10-12). Три эхо-запроса — три пакета в
 * 30 с; trace — только когда эхо молчит (ICMP бывает закрыт) или когда колония и страна неизвестны. */
static int member_alive(struct member *m) {
    int64_t hs;
    uint64_t rx, tx;
    /* Устройство есть? У awg — спросом WireGuard (оно же «наше по виду»), у MASQUE — TUN модуля,
     * который держит сам поток туннеля (mq_alive зовёт сюда, только когда туннель поднят). */
    if (m->awg && awg_scan_stat(m->o->device, -1, &hs, &rx, &tx) != 0) return -1;
    struct wb_ping pg;
    int echo = wb_ping_dev(m->o->device, "1.1.1.1", 3, 200, 1500, &pg) == 0 && pg.got > 0;
    if (echo && m->colo[0] && m->seen[0]) return 1;
    struct wb_pt p;
    memset(&p, 0, sizeof(p));
    if (wb_trace_dev(m->o->device, &p) == 0) {
        if (p.colo[0]) snprintf(m->colo, sizeof(m->colo), "%s", p.colo);
        if (p.seen[0]) snprintf(m->seen, sizeof(m->seen), "%s", p.seen);
        return 1;
    }
    return echo;
}

/* ---- MASQUE (transport: masque, этап 2; WARPBOX.md в хабе, «Протокол») -------------------------
 *
 * Точка входа MASQUE — эникаст Cloudflare: адрес даёт API при включении (обычно 162.159.198.x и
 * 2606:4700:103::x), колонию выбирает сеть, а не адрес, поэтому подбор здесь — не перебор пулов, как
 * у awg, а выбор открытого порта: API называет 443, 500, 1701, 4500, 4443, 8443, 8095 (все отвечают —
 * проверено 2026-10-12), и у провайдера, режущего одни, работают другие. Каждая пара адрес:порт
 * пробуется разом своим соединением (wb_mq_probe: рукопожатие, CONNECT и эхо-запрос в датаграмме),
 * члены получают разные пары, пока их хватает. */
static const unsigned MQ_PORTS[] = { 443, 500, 1701, 4500, 4443, 8443, 8095 };

/* Включить MASQUE у регистрации члена (новая регистрация, если у прежней нет id и token). */
static int member_masque(struct member *m) {
    if (wb_reg_has_masque(&m->reg)) return 0;
    char why[256] = "";
    if ((!m->reg.id[0] || !m->reg.token[0]) && member_reg(m, 1) != 0) return -1;
    if (wb_enroll_masque(&m->reg, why, sizeof(why)) != 0) {
        LOG("%s: MASQUE не включился — %s\n", m->o->name, why);
        m->reg_retry = time(NULL) + WB_REG_RETRY_S;
        return -1;
    }
    if (wb_reg_save(m->reg_path, &m->reg) != 0)
        LOG("%s: регистрацию не сохранить в %s: %s\n", m->o->name, m->reg_path, strerror(errno));
    LOG("%s: MASQUE включён (точка %s%s%s)\n", m->o->name, m->reg.mq_ep4, m->reg.mq_ep6[0] ? ", " : "", m->reg.mq_ep6);
    return 0;
}

/* Регистрация была включена в MASQUE (transport сменили на awg) — вернуть ключ WireGuard. Файл
 * туннеля пишется заново при следующем подборе: точка прежняя не годится уже потому, что туннель с
 * этим ключом у Cloudflare только что снова заведён. */
static int member_wireguard(struct member *m) {
    char why[256] = "";
    if (wb_enroll_wireguard(&m->reg, why, sizeof(why)) != 0) {
        LOG("%s: ключ WireGuard не вернулся — %s\n", m->o->name, why);
        return -1;
    }
    if (wb_reg_save(m->reg_path, &m->reg) != 0)
        LOG("%s: регистрацию не сохранить в %s: %s\n", m->o->name, m->reg_path, strerror(errno));
    LOG("%s: устройству WARP возвращён ключ WireGuard\n", m->o->name);
    return 0;
}

static int mq_cfg(const struct wb *w, const struct member *m, struct wb_mq_cfg *c) {
    memset(c, 0, sizeof(*c));
    snprintf(c->dev, sizeof(c->dev), "%s", m->o->device);
    unsigned char b[128];
    if (wb_b64_decode(m->reg.mq_priv, b, sizeof(b)) != 32) return -1;
    memcpy(c->priv, b, 32);
    if (wb_b64_decode(m->reg.mq_peer, b, sizeof(b)) != WB_SPKI_P256) return -1;
    memcpy(c->spki, b, WB_SPKI_P256);
    memset(b, 0, sizeof(b));
    snprintf(c->v4, sizeof(c->v4), "%s", m->reg.v4);
    snprintf(c->v6, sizeof(c->v6), "%s", m->reg.v6);
    c->mark = out_underlay_mark(w->sp, m->o);
    return 0;
}

struct mq_try {
    struct wb_mq_cfg c;
    int rc, rtt, used;
    char why[160];
    pthread_t th;
};

static void *mq_try_run(void *a) {
    struct mq_try *t = a;
    t->rc = wb_mq_probe(&t->c, 6000, &t->rtt, t->why, sizeof(t->why));
    return NULL;
}

static int mq_point_busy(const struct wb *w, const struct member *self, const char *ep, unsigned port) {
    for (size_t i = 0; i < w->n; i++) {
        const struct member *m = &w->m[i];
        if (m == self) {
            if (m->bad_ip[0] && time(NULL) < m->bad_until && !strcmp(m->bad_ip, ep) && m->bad_port == port) return 1;
            continue;
        }
        if (m->ip[0] && !strcmp(m->ip, ep) && m->port == port) return 1;
    }
    return 0;
}

/* Пробы всех пар адрес:порт MASQUE разом, ключом члена key. Массив — в куче (free и затирание ключа —
 * mq_tries_free); NULL — нет памяти. */
#define MQ_TRIES (sizeof(MQ_PORTS) / sizeof(MQ_PORTS[0]) + 1)
static struct mq_try *mq_probe_all(const struct wb *w, const struct member *key, size_t *tn_out) {
    size_t pn = sizeof(MQ_PORTS) / sizeof(MQ_PORTS[0]), tn = 0;
    struct mq_try *t = calloc(MQ_TRIES, sizeof(*t));
    if (!t) return NULL;
    for (size_t k = 0; k < pn + 1; k++) {
        const char *ep = k < pn ? key->reg.mq_ep4 : key->reg.mq_ep6;
        if (!ep[0] || mq_cfg(w, key, &t[tn].c) != 0) continue;
        t[tn].c.dev[0] = '\0';
        snprintf(t[tn].c.ep, sizeof(t[tn].c.ep), "%s", ep);
        t[tn].c.port = k < pn ? MQ_PORTS[k] : 443;
        t[tn].rc = -1;
        if (pthread_create(&t[tn].th, NULL, mq_try_run, &t[tn]) == 0) tn++;
    }
    for (size_t k = 0; k < tn; k++) pthread_join(t[k].th, NULL);
    *tn_out = tn;
    return t;
}

static void mq_tries_free(struct mq_try *t) {
    if (!t) return;
    for (size_t k = 0; k < MQ_TRIES; k++) memset(t[k].c.priv, 0, sizeof(t[k].c.priv));
    free(t);
}

/* Точки членам с need[i]: разом все пары адрес:порт, лучшие по задержке — разным членам. */
static int mq_assign(struct wb *w, const int *need) {
    struct member *key = NULL;
    size_t nn = 0;
    for (size_t i = 0; i < w->n; i++)
        if (need[i]) { nn++; if (!key && wb_reg_has_masque(&w->m[i].reg)) key = &w->m[i]; }
    if (!nn || !key) return nn ? -1 : 0;
    size_t tn = 0;
    struct mq_try *t = mq_probe_all(w, key, &tn);
    if (!t) return -1;
    size_t okn = 0;
    for (size_t k = 0; k < tn; k++) {
        if (t[k].rc == 0) {
            okn++;
            LOG("%s:%u — MASQUE отвечает, %d мс\n", t[k].c.ep, t[k].c.port, t[k].rtt);
        } else
            LOG("%s:%u — %s\n", t[k].c.ep, t[k].c.port, t[k].why[0] ? t[k].why : "не отвечает");
    }
    int rc = 0;
    if (!okn) {
        char why[256];
        snprintf(why, sizeof(why), "MASQUE не отвечает ни на одном порту (%.160s)", tn ? t[0].why : "нет точки");
        LOG("подбор: %s\n", why);
        evline_emit("down", "why", EVLINE_STR, why, (const char *)NULL);
        rc = -1;
    }
    for (size_t i = 0; okn && i < w->n; i++) {
        struct member *m = &w->m[i];
        if (!need[i] || !wb_reg_has_masque(&m->reg)) continue;
        int best = -1;
        for (int pass = 0; pass < 2 && best < 0; pass++)
            for (size_t k = 0; k < tn; k++) {
                if (t[k].rc != 0 || (!pass && (t[k].used || mq_point_busy(w, m, t[k].c.ep, t[k].c.port)))) continue;
                if (best < 0 || t[k].rtt < t[best].rtt) best = (int)k;
            }
        if (best < 0) continue;
        t[best].used = 1;
        struct wb_mq_cfg c;
        if (mq_cfg(w, m, &c) != 0) { LOG("%s: ключи MASQUE не разобраны\n", m->o->name); continue; }
        snprintf(c.ep, sizeof(c.ep), "%s", t[best].c.ep);
        c.port = t[best].c.port;
        char why[200] = "";
        if (!m->mq) {
            if (wb_mq_start(&c, &m->mq, why, sizeof(why)) != 0) { LOG("%s: туннель не поднят — %s\n", m->o->name, why); continue; }
        } else
            wb_mq_retarget(m->mq, c.ep, c.port);
        memset(c.priv, 0, sizeof(c.priv));
        snprintf(m->ip, sizeof(m->ip), "%.47s", t[best].c.ep);
        m->port = t[best].c.port;
        m->colo[0] = m->seen[0] = '\0';
        m->pt_saved = 0;
        m->mq_set_ms = (long)time(NULL);
        member_say(m, -1);
        LOG("%s: точка MASQUE %s:%u\n", m->o->name, m->ip, m->port);
    }
    mq_tries_free(t);
    return rc;
}

/* Жив ли член MASQUE: туннель поднят (CONNECT принят) и эхо через его устройство возвращается. -1 —
 * туннель ещё поднимается после новой точки (WB_MQ_GRACE_S). */
static int mq_alive(struct member *m) {
    if (!m->mq) return 0;
    char why[160] = "";
    if (!wb_mq_up(m->mq, why, sizeof(why))) {
        if ((long)time(NULL) - m->mq_set_ms < WB_MQ_GRACE_S) return -1;
        if (why[0] && m->ok) LOG("%s: туннель MASQUE не работает — %s\n", m->o->name, why);
        return 0;
    }
    return member_alive(m) == 1;
}

/* ---- самая быстрая точка (решение владельца 2026-10-12: «самый быстрый, не держа кучу интерфейсов») --
 *
 * Туннель у члена один, а точек входа у Cloudflare много. Раз в interval группы (без него — WB_OPT_S)
 * модуль меряет кандидатов и, найдя точку быстрее текущей больше чем на tolerance (без неё — 50 мс),
 * переставляет точку у того же устройства — без нового интерфейса и без перезапуска:
 *   awg — кандидаты и текущая точка меряются одинаково (wbscan.c, also) на устройствах подбора в своём
 *     пространстве сети и СВОЕЙ регистрацией замера ({etc}/warp/<группа>-scan.reg): ключ живого
 *     туннеля на втором устройстве увёл бы его сессию у Cloudflare; смена — файл члена и событие awg
 *     с fresh: демон ставит пира заново (awg_refresh), и рукопожатие с новой точкой идёт сразу;
 *   masque — пробы всех пар адрес:порт разом (как при подборе), смена — wb_mq_retarget: TUN тот же,
 *     переподключается только соединение QUIC под ним.
 * Смена колонии меняет адрес выхода в интернет: долгие соединения через туннель при ней рвутся
 * (новые идут уже через быструю точку). Поэтому меняется только заметно лучшая точка — не хуже по
 * потерям и быстрее больше чем на tolerance. Член, который сейчас не работает, сюда не попадает: его
 * точку меняет сторож. */

static int opt_tol(const struct wb *w) {
    return w->g->grp.lat_tolerance_ms >= 0 ? w->g->grp.lat_tolerance_ms : GROUP_TOL_DEFAULT_MS;
}

static int opt_interval(const struct wb *w) {
    return w->g->grp.lat_interval_s > 0 ? w->g->grp.lat_interval_s : WB_OPT_S;
}

/* Лучше ли точка b текущей a (потери в процентах, задержка в мс) с допуском tol. */
static int opt_better(int a_loss, int a_rtt, int b_loss, int b_rtt, int tol) {
    if (b_loss > a_loss) return 0;
    return b_rtt + tol < a_rtt || (a_loss >= 30 && b_loss + 20 <= a_loss);
}

static void opt_awg(struct wb *w, size_t i) {
    struct member *m = &w->m[i];
    if (!w->scan.have_reg && member_reg(&w->scan, 0) != 0) return;
    char (*bc)[4] = calloc(w->n + 1, sizeof(*bc));
    char (*bi)[16] = calloc(w->n + 1, sizeof(*bi));
    if (!bc || !bi) { free(bc); free(bi); return; }
    size_t bcn = 0, bin = 0;
    for (size_t j = 0; j < w->n; j++) {
        if (j == i || !w->m[j].ip[0]) continue;
        if (w->m[j].colo[0]) snprintf(bc[bcn++], 4, "%s", w->m[j].colo);
        snprintf(bi[bin++], 16, "%.15s", w->m[j].ip);
    }
    struct wb_scan sc;
    scan_setup(w, &sc, &w->scan.reg);
    sc.busy_colo = (const char (*)[4])bc;
    sc.busy_colo_n = bcn;
    sc.busy_ip = (const char (*)[16])bi;
    sc.busy_ip_n = bin;
    sc.want = 2;
    sc.quick = 1;
    sc.rot = (unsigned)i;
    sc.also_ip = m->ip;
    sc.also_port = m->port;
    LOG("%s: замер точек — есть ли быстрее %s:%u\n", m->o->name, m->ip, m->port);
    int rc = wb_scan_run(&sc);
    const struct wb_pt *b = NULL;
    for (size_t k = 0; rc == 0 && k < sc.out_n && !b; k++)
        if (sc.out[k].cls == WB_GOOD) b = &sc.out[k];
    int tol = opt_tol(w);
    if (b && sc.also_ok && opt_better(sc.also.loss, sc.also.rtt, b->loss, b->rtt, tol)) {
        LOG("%s: точка быстрее — %s:%u (%d мс, потери %d%%, колония %s) вместо %s:%u (%d мс, потери %d%%)\n",
            m->o->name, b->ip, b->port, b->rtt, b->loss, b->colo, m->ip, m->port, sc.also.rtt, sc.also.loss);
        member_set(w, m, b, 1);
    } else if (sc.also_ok)
        LOG("%s: текущая точка не хуже найденных (%d мс, допуск %d мс)\n", m->o->name, sc.also.rtt, tol);
    wb_scan_free(&sc);
    free(bc);
    free(bi);
}

static void opt_masque(struct wb *w, size_t i) {
    struct member *m = &w->m[i];
    if (!m->mq || !wb_reg_has_masque(&m->reg)) return;
    size_t tn = 0;
    struct mq_try *t = mq_probe_all(w, m, &tn);
    if (!t) return;
    int cur = -1, best = -1;
    for (size_t k = 0; k < tn; k++) {
        if (t[k].rc != 0) continue;
        if (!strcmp(t[k].c.ep, m->ip) && t[k].c.port == m->port) { cur = (int)k; continue; }
        if (mq_point_busy(w, m, t[k].c.ep, t[k].c.port)) continue;
        if (best < 0 || t[k].rtt < t[best].rtt) best = (int)k;
    }
    int tol = opt_tol(w);
    if (cur >= 0 && best >= 0 && opt_better(0, t[cur].rtt, 0, t[best].rtt, tol)) {
        LOG("%s: точка MASQUE быстрее — %s:%u (%d мс) вместо %s:%u (%d мс)\n", m->o->name, t[best].c.ep,
            t[best].c.port, t[best].rtt, m->ip, m->port, t[cur].rtt);
        wb_mq_retarget(m->mq, t[best].c.ep, t[best].c.port);
        snprintf(m->ip, sizeof(m->ip), "%.47s", t[best].c.ep);
        m->port = t[best].c.port;
        m->colo[0] = m->seen[0] = '\0';
        m->pt_saved = 0;
        m->mq_set_ms = (long)time(NULL);
        member_say(m, -1);
    } else if (cur >= 0)
        LOG("%s: текущая точка MASQUE не хуже других (%d мс, допуск %d мс)\n", m->o->name, t[cur].rtt, tol);
    mq_tries_free(t);
}

/* Замер «самой быстрой точки» — работающим членам, по сроку. */
static void opt_pass(struct wb *w) {
    if (time(NULL) < w->opt_at) return;
    w->opt_at = time(NULL) + opt_interval(w);
    for (size_t i = 0; i < w->n && !g_stop; i++) {
        struct member *m = &w->m[i];
        if (!m->ok || !m->ip[0]) continue;
        if (w->mq) opt_masque(w, i);
        else opt_awg(w, i);
    }
}

/* Состояние группы для `steer status` (поле warp у группы, daemon/status.c): строками в каталоге
 * состояния, запись заменой. Ядро читает его как данные — разбирает по полям и печатает своим JSON,
 * сырого текста модуля в ответ не вставляет.
 *     mask <имя>          маска I1 (или «-» без AmneziaWG)
 *     why <текст>         почему группа сейчас не работает (или «-»)
 *     member <выход> <адрес> <порт> <колония> <страна сайтов> <жив 0|1>   «-» — неизвестно */
static void state_write(const struct wb *w, const char *why) {
    char p[600], t[620];
    snprintf(p, sizeof(p), "%s/state", w->st);
    snprintf(t, sizeof(t), "%s.tmp", p);
    FILE *f = fopen(t, "w");
    if (!f) return;
    fprintf(f, "mask %s\nwhy %s\n", w->obfs ? wb_mask_name(w->mask) : "-", why && why[0] ? why : "-");
    for (size_t i = 0; i < w->n; i++) {
        const struct member *m = &w->m[i];
        fprintf(f, "member %s %s %u %s %s %d\n", m->o->name, m->ip[0] ? m->ip : "-", m->ip[0] ? m->port : 0,
                m->colo[0] ? m->colo : "-", m->seen[0] ? m->seen : "-", m->ok);
    }
    if (fclose(f) == 0) rename(t, p);
    else unlink(t);
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
        m->said = 2;
        /* Файл регистрации — по имени группы и номеру члена, как файл туннеля awg ({etc}/warp/<группа>-<n>):
         * у члена MASQUE файла туннеля нет, и выводить путь из него нельзя. */
        m->awg = w->g->grp.warp.transport == WARP_AWG;
        if (m->awg) snprintf(m->conf_path, sizeof(m->conf_path), "%s", o->awg.conf);
        snprintf(m->reg_path, sizeof(m->reg_path), "%s/%s-%zu.reg", w->etc, group, w->n);
    }
    w->scan.o = w->g;
    w->scan.said = 2;
    snprintf(w->scan.reg_path, sizeof(w->scan.reg_path), "%s/%s-scan.reg", w->etc, group);
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
    w.mq = w.g->grp.warp.transport == WARP_MASQUE;
    w.ns = w.mq ? -1 : wb_ns_new();
    if (!w.mq && w.ns < 0) {
        char why[160];
        snprintf(why, sizeof(why), "своё пространство сети для подбора не создать: %s", strerror(errno));
        LOG("%s\n", why);
        evline_emit("down", "why", EVLINE_STR, why, (const char *)NULL);
        return 1;
    }
    w.obfs = !w.mq && awg_kernel_has_awg();
    if (!w.mq && !w.obfs) LOG("в ядре нет AmneziaWG — туннели WARP без обфускации (обычный WireGuard)\n");
    if (!w.mq) mask_load(&w);
    int *need = calloc(w.n, sizeof(*need));
    if (!need) return 1;
    int said_up = -1;
    w.opt_at = time(NULL) + opt_interval(&w);      /* подъём уже выбрал лучшую: первый замер — через срок */
    while (!g_stop) {
        /* Регистрации. */
        for (size_t i = 0; i < w.n && !g_stop; i++) {
            if (!w.m[i].have_reg) member_reg(&w.m[i], 0);
            if (w.mq && w.m[i].have_reg) member_masque(&w.m[i]);
            if (!w.mq && w.m[i].have_reg && w.m[i].reg.mq_priv[0]) member_wireguard(&w.m[i]);
        }
        /* Кто жив, кому нужна точка. */
        size_t alive = 0;
        for (size_t i = 0; i < w.n; i++) {
            struct member *m = &w.m[i];
            need[i] = 0;
            if (!m->have_reg) continue;
            if (w.mq && (!wb_reg_has_masque(&m->reg) || !m->mq || !m->ip[0])) {
                need[i] = wb_reg_has_masque(&m->reg);
                continue;
            }
            if (!w.mq && !m->ip[0]) {
                char ep[64];
                /* Файл уже есть (прошлый запуск) — сначала проверить его, а не подбирать заново. */
                if (wb_conf_endpoint(m->conf_path, ep, sizeof(ep)) == 0 && strchr(ep, ':')) {
                    char *c = strrchr(ep, ':');
                    m->port = (unsigned)atoi(c + 1);
                    *c = '\0';
                    snprintf(m->ip, sizeof(m->ip), "%.47s", ep);
                    pt_load(&w, m);
                } else { need[i] = 1; continue; }
            }
            int al = w.mq ? mq_alive(m) : member_alive(m);
            if (al < 0) {
                if (!w.mq) evline_emit("awg", "out", EVLINE_STR, m->o->name, (const char *)NULL);
                continue;
            }
            if (al) {
                member_say(m, 1);
                if (m->colo[0] && m->seen[0] && !m->pt_saved) { pt_save(&w, m); m->pt_saved = 1; }
                if (!m->ok) LOG("%s: работает (%s%s%s)\n", m->o->name, m->ip, m->colo[0] ? ", колония " : "", m->colo);
                m->ok = 1;
                m->fails = 0;
                m->replaced = 0;
                alive++;
                continue;
            }
            m->ok = 0;
            member_say(m, 0);           /* трафик — с него сразу; точку меняем после WB_FAILS проверок */
            if (++m->fails < WB_FAILS) continue;
            m->fails = 0;
            if (++m->replaced >= WB_REKEY_AT && time(NULL) >= m->rekey_at) {
                LOG("%s: %d замены подряд не помогли — новые ключи\n", m->o->name, m->replaced - 1);
                m->rekey_at = time(NULL) + WB_REKEY_MIN_S;
                m->replaced = 0;
                if (member_reg(m, 1) != 0) continue;
                if (w.mq) {
                    /* Новые ключи — новый туннель: у прежнего потока старый ключ клиента. */
                    wb_mq_stop(m->mq);
                    m->mq = NULL;
                    if (member_masque(m) != 0) continue;
                }
            } else
                LOG("%s: точка %s не отвечает — подбираю другую\n", m->o->name, m->ip);
            snprintf(m->bad_ip, sizeof(m->bad_ip), "%s", m->ip);
            m->bad_port = m->port;
            m->bad_until = time(NULL) + WB_BAD_S;
            m->ip[0] = m->colo[0] = '\0';
            need[i] = 1;
        }
        if ((w.mq ? mq_assign(&w, need) : assign(&w, need)) == 0)
            for (size_t i = 0; i < w.n; i++) if (need[i] && w.m[i].ip[0]) alive++;
        int up = alive > 0;
        const char *why = up ? NULL : "ни один туннель WARP не работает";
        if (up != said_up) {
            if (up) evline_emit("up", (const char *)NULL);
            else evline_emit("down", "why", EVLINE_STR, why, (const char *)NULL);
            said_up = up;
        }
        state_write(&w, why);
        if (up) opt_pass(&w);
        nap(WB_CHECK_S);
    }
    free(need);
    for (size_t i = 0; i < w.n; i++) {
        wb_mq_stop(w.m[i].mq);
        wb_reg_wipe(&w.m[i].reg);
    }
    wb_reg_wipe(&w.scan.reg);
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
    if (w.g->grp.warp.transport == WARP_MASQUE) {
        /* MASQUE: пробы всех пар адрес:порт, без туннелей. */
        if (member_reg(&w.m[0], 0) != 0 || member_masque(&w.m[0]) != 0) {
            printf("{\"ok\":false,\"error\":\"регистрации MASQUE нет\"}\n");
            return 1;
        }
        size_t pn = sizeof(MQ_PORTS) / sizeof(MQ_PORTS[0]), tn = 0;
        struct mq_try t[sizeof(MQ_PORTS) / sizeof(MQ_PORTS[0]) + 1];
        memset(t, 0, sizeof(t));
        for (size_t k = 0; k < pn + 1; k++) {
            const char *ep = k < pn ? w.m[0].reg.mq_ep4 : w.m[0].reg.mq_ep6;
            if (!ep[0] || mq_cfg(&w, &w.m[0], &t[tn].c) != 0) continue;
            t[tn].c.dev[0] = '\0';
            snprintf(t[tn].c.ep, sizeof(t[tn].c.ep), "%s", ep);
            t[tn].c.port = k < pn ? MQ_PORTS[k] : 443;
            if (pthread_create(&t[tn].th, NULL, mq_try_run, &t[tn]) == 0) tn++;
        }
        int any = 0;
        for (size_t k = 0; k < tn; k++) { pthread_join(t[k].th, NULL); if (t[k].rc == 0) any = 1; }
        printf("{\"ok\":%s,\"transport\":\"masque\",\"points\":[", any ? "true" : "false");
        for (size_t k = 0; k < tn; k++) {
            printf("%s{\"ip\":\"%s\",\"port\":%u,\"ok\":%s", k ? "," : "", t[k].c.ep, t[k].c.port,
                   t[k].rc == 0 ? "true" : "false");
            if (t[k].rc == 0) printf(",\"rtt\":%d", t[k].rtt);
            else { printf(",\"error\":"); jsonw_str(stdout, t[k].why); }
            printf("}");
            memset(t[k].c.priv, 0, sizeof(t[k].c.priv));
        }
        printf("]}\n");
        wb_reg_wipe(&w.m[0].reg);
        return any ? 0 : 1;
    }
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
