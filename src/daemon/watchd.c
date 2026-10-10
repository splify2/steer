/* Сторож выходов в демоне: `steer daemon --watch` вместо `steer failover --loop`.
 *
 * Шаг 3 устройства 1.8 (docs/architecture.md, «4а»): таймер и события netlink в цикле демона,
 * память выходов — в памяти демона. Проход тот же, что у `steer failover`, — автомат прохода
 * failover.c (fo_pass_start), а не его копия; отличается только то, где лежит память между
 * проходами (fostate.h), кто зовёт проход и куда уходят его новости.
 *
 * ВКЛЮЧАЕТСЯ ФЛАГОМ. До шага 6 procd и init по-прежнему держат `steer failover --loop`, а демон
 * на телефоне поднят всегда. Два сторожа сразу дрались бы за одни и те же таблицы выходов и
 * оживляли бы одни и те же устройства дважды, поэтому демон сторожит только с `--watch`, а
 * сервис, который его так запускает, обязан снять старый круг.
 *
 * ПРОХОД — В ЦИКЛЕ ДЕМОНА, БЕЗ FORK. Решение владельца: без процесса на проход. Проход —
 * конечный автомат на цикле демона: пробы (TCP connect, эхо ICMP из сырого или ping-сокета),
 * ожидание подъёма устройства (таймер шага и события netlink), внешние команды оживления
 * (ifdown/ifup, ubus — ребёнок на ДЕЙСТВИЕ, выход через loop_child), разрешение имени Endpoint
 * у awg (рабочий поток) — всё это ждётся шагами автомата, а не синхронно. Цикл демона во время
 * прохода свободен: status, subscribe, apply отвечают, пока проба ждёт ответа (стенд ctlmatch
 * меряет это пробой, которая ждёт три секунды), и проход по исправной спеке не запускает ни
 * одного процесса (тот же стенд считает процессы в своём пространстве PID). Устройство
 * автомата и что в нём по-прежнему синхронно — в failover.c, «ПРОХОД — КОНЕЧНЫЙ АВТОМАТ».
 *
 * Раньше (6c0cecf) проход шёл в ребёнке — копии демона без exec, с ответом по трубе: пробы и
 * оживление ждали синхронно, а неблокирующий проход был бы второй логикой рядом с
 * `steer failover`. Теперь автомат у них общий — `steer failover` крутит его на своём цикле до
 * конца прохода, — и копия с трубой ушли.
 *
 * Спека прохода — своя копия спеки демона (проход пишет в неё выбранные устройства, а apply
 * посреди прохода может заменить спеку демона); память — прямо память демона: проход кладёт
 * `active` в конце, и status посреди прохода видит прежний выбор целиком, а не половину.
 * Предел прохода остаётся (WATCHD_PASS_MAX_S): каждое ожидание автомата имеет свой срок, но
 * проход, который его всё же превысит, прерывается — с уборкой правила пробы и команды.
 *
 * РАСПИСАНИЕ — как у `failover --loop` (watch.c): первый проход при старте, следующий — через
 * период после конца предыдущего; событие сети (RTMGRP_LINK, адреса IPv4/IPv6) — внеочередной
 * проход через WATCH_SETTLE_S секунд после первого события пачки. На роутере (plat()->netifd)
 * события, пришедшие за время прохода, — следы его же ifdown/ifup, и они выбрасываются; на
 * телефоне сторож интерфейсы не трогает, и событие за время прохода настоящее — после прохода
 * ещё один через WATCH_SETTLE_S. Смена спеки в памяти демона (apply, reload, SIGHUP) — тоже
 * внеочередной проход: `failover --loop` перечитывал спеку на каждом проходе, демон — при смене.
 * В тишине демон просыпается только таймером периода (timerfd на CLOCK_MONOTONIC: во сне
 * устройства он стоит и не будит его) — не чаще, чем `--loop`.
 *
 * ВЫКЛЮЧЕННЫЙ ДВИЖОК — НОЛЬ ПРОБУЖДЕНИЙ (требование батареи телефона). Демон работает и при
 * выключенном движке — он же управляющий сокет, — но сторожить тогда нечего: правила снял init, а
 * трогать маршрутизацию нельзя. Раньше таймер периода тикал и так — просыпался, видел «выключен»
 * и заводился снова: раз в минуту ради ответа «нет». Теперь выключенный сторож не держит ни
 * таймера, ни сокета событий сети (событие сети будило бы его ради того же «нет»), и демон спит
 * в epoll_wait без срока до запроса по сокету. Положение выключателя сторожу говорит сервер
 * сокета (watchd_enable) — после apply, reload и SIGHUP, то есть тогда, когда init включает или
 * выключает движок; выключатель, сменившийся без reload, сторож замечает на ближайшем своём
 * таймере и засыпает сам. Без спеки — то же: проходить нечем, и первый проход зовёт прочитанная
 * спека.
 *
 * ПЕРВЫЙ ПРОХОД — ПОСЛЕ СТАРТОВОГО APPLY. С --apply демон при старте ставит спеку в ядро сам, и
 * проход раньше этого видел бы ядро без правил (их снял `steerd down` при остановке сервиса):
 * «маршрутизация разъехалась (правила fwmark нет)» у каждого выхода, выбор которого остался в
 * `active`, и «туннель молчит» у тех, чьи помощники ещё не подняты. Поэтому сторож заводится
 * придержанным (hold) и первый проход делает watchd_release — по концу стартового apply,
 * удачного или нет. Раньше тот же порядок держала только проверка «идёт изменяющая команда» в
 * таймере — случайно, а не по устройству.
 *
 * ПАМЯТЬ ВЫХОДОВ — в демоне: `active`, `latency`, `restart-*` (fostate.h) и замеры awg
 * (awg_hs_memory, как у `--loop`). status демона берёт выбор устройств отсюда. `active` при
 * этом ещё и отражается в файл — только при изменении, как и раньше: до шага 6 status, diag и
 * apply подкомандой (rpcd на роутере, дети демона) читают выбор сторожа из файла, и без него
 * apply привязал бы таблицу пула к первому кандидату в обход выбора сторожа. `latency` и
 * `restart-*` на диск больше не пишутся вовсе. При старте демон берёт `active` из файла — ровно
 * то, что увидел бы очередной `steer failover`, — и не перепривязывает выходы на пустом месте
 * (перепривязка снимает соединения выхода).
 *
 * Запись `select` (выбор человека у pick: manual) отражается тем же путём, но лежит рядом со
 * спекой, а не в каталоге состояния (files_put в failover.c): она обязана пережить перезагрузку.
 *
 * ЗАМЕРЫ ГРУПП latency — своими таймерами (folat.c), а не в проходе: у каждой группы таймер на её
 * interval, и замер, меняющий выбор, зовёт внеочередной проход сразу (watchd_lat_kick). Проход
 * меряет сам, только если у живого члена замера нет вовсе (fo_pass_lat_extern). Таймеры сверяются
 * со спекой после каждого прохода и снимаются вместе со сторожем, когда движок выключают.
 *
 * ЗДОРОВЬЕ ПОМОЩНИКОВ (демон ещё и с --supervise). Помощники — дети демона, и их состояние он
 * знает по событиям из трубы (helpers.h, helper_state_of). Проход берёт его отсюда — источник
 * здоровья помощника в памяти (fostate.h), — а не из файлов probe-* и xsteer-*.json, которые
 * помощники с трубой событий и не пишут; обфускатор выхода interface оживляется перезапуском в
 * супервизоре демона (supd_restart), а не сигналом экземпляру procd через ubus. Смена состояния
 * помощника vless или xsteer (up, down, процесс вышел после up) — внеочередной проход через
 * WATCH_SETTLE_S, как событие сети: упавший туннель не ждёт периода. Клиент vless, следящий за
 * узлом сам (up с watch), говорит down и о потерянном узле — и выход уходит в отказ или группа на
 * другого члена тем же проходом, без пробы TCP (fostate.h). Без --supervise источник — прежние
 * файлы.
 *
 * СОБЫТИЯ подписчикам (docs/ctl.md): switched, failed, revived — копятся за проход и уходят
 * после его конца, когда память выходов уже новая (подписчик, спросивший status по событию,
 * видит уже новое).
 *
 * MASQUERADE НА ТЕЛЕФОНЕ (plat()->iptables_masq): netd при перезапуске перестраивает iptables, и
 * правило masquerade пропадает — сторож его возвращает (iptables_masq_ensure в apply.c). Это
 * `iptables -C` на устройство, то есть процессы, и потому не на каждом проходе: после прохода
 * по событию сети или смене спеки и не реже раза в WATCH_MASQ_S (watch_masq_due в watch.c).
 *
 * СВЕРКА НАБОРА ПРАВИЛ (решение владельца 2026-09-28). Перед каждым проходом сторож зовёт
 * watchd_conf.kcheck — сервер сокета сверяет номер и отпечаток наших таблиц nftables с тем, что
 * стояло сразу после последнего нашего nft -f (recon_kernel_drift: четыре обмена netlink, без
 * элементов наборов и без процессов). Снятое снаружи правило канала раньше жило до ближайшего
 * `steer apply` человека; теперь — до ближайшего прохода. Сам сторож набор правил не ставит:
 * расхождение сервер ставит починкой в очередь изменяющих команд (reload без соединения, тот
 * же путь, что apply той же спеки), и проход тогда откладывается, как при любой изменяющей
 * команде, — до её конца и успокоения. Устройство и доводы — в шапке recon.c, «СВЕРКА НА ПРОХОДЕ
 * СТОРОЖА». У `steer failover` (без демона) сверки нет: применённое помнит только демон.
 *
 * УСТРОЙСТВА РАЗДАЧИ (проверка на QEMU 04664a5). После
 * `/etc/init.d/network restart` br-lan пересоздан, и цепочку ingress_mark (compile/generate.c,
 * «разметка на ingress») ядро сняло вместе со старым устройством: на новое она сама не вешается.
 * Трафик от этого не ломается — запасные правила prerouting_mark метят его сами, — но выигрыш
 * ingress пропадает, а вернуть цепочку может только замена набора правил. Прежде её делала сверка
 * на проходе сторожа, а проход после события сети идёт через WATCH_SETTLE_S: цепочка возвращалась
 * через 3,6-8,6 с. Теперь тот же сокет событий сети читается с разбором: RTM_NEWLINK устройства
 * из lan_devices спеки с новым номером (устройство пересоздано или создано впервые после apply) и
 * RTM_DELLINK такого устройства сразу уходят серверу сокета (watchd_conf.lan), а тот ставит
 * сверку набора правил в очередь без ожидания прохода (ctl.c, srv_lan). Номер, а не само
 * событие: RTM_NEWLINK приходит и на каждую смену состояния (порт моста, carrier, up), и сверка
 * на каждое такое была бы компиляцией на пустом месте; новый номер бывает только у нового
 * устройства. Только там, где устройства раздачи постоянны (plat()->lan_devs_persist — роутер):
 * на телефоне ingress не ставится вовсе. События за время прохода и перед ним по-прежнему
 * выбрасываются для прохода (следы его же ifdown/ifup), но устройства раздачи из них разбираются
 * всегда — выброшенное пересоздание моста оставило бы цепочку снятой до следующего прохода. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "platform.h"
#include "spec.h"
#include "awg.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "fostate.h"
#include "helpers.h"
#include "nftdump.h"
#include "folat.h"
#include "watchd.h"

#define LOG_WW "steer[warn] watch: "

/* Проход дольше этого — зависание: каждое ожидание автомата имеет свой срок (пробы — секунды,
 * команда оживления — минута), так что сюда проход может прийти только очень длинным списком
 * мёртвых устройств. Прерывается с уборкой (fo_pass_abort). С запасом: восемь выходов по восемь
 * мёртвых устройств с оживлением и замером — это минуты, а не десять. */
#define WATCHD_PASS_MAX_S 600
/* События прохода копятся в растущем массиве (watchd_ev): их столько, сколько решений у выходов
 * за проход, а выходов не 16 (раньше — 64 записи, и события сверх них молча пропадали). */

/* ---- память выходов ------------------------------------------------------------------ */

struct fo_blob {
    char name[48];
    char *p;
    size_t n;
};

struct fo_mem {
    struct fo_store base;
    struct fo_blob *b;
    size_t n, cap;
    int mirror;          /* active — ещё и в файл (см. шапку) */
};

static struct fo_blob *mem_find(struct fo_mem *m, const char *name) {
    for (size_t i = 0; i < m->n; i++)
        if (!strcmp(m->b[i].name, name)) return &m->b[i];
    return NULL;
}

static FILE *mem_open_r(struct fo_store *st, const char *name) {
    struct fo_blob *b = mem_find((struct fo_mem *)st, name);
    /* Пустая запись — как пустой файл: читать нечего. fmemopen нулевой длины musl отвергает. */
    if (!b || !b->n) return NULL;
    return fmemopen(b->p, b->n, "r");
}

/* Положить запись; та же — ничего не делать (и в файл не писать). 0 — положено. */
static int mem_set(struct fo_mem *m, const char *name, const char *data, size_t n) {
    struct fo_blob *b = mem_find(m, name);
    if (b && b->n == n && (!n || !memcmp(b->p, data, n))) return 1;
    if (strlen(name) >= sizeof(b->name)) return -1;
    char *p = malloc(n ? n : 1);
    if (!p) return -1;
    if (n) memcpy(p, data, n);
    if (!b) {
        if (m->n == m->cap) {
            size_t nc = m->cap ? m->cap * 2 : 16;
            struct fo_blob *nb = realloc(m->b, nc * sizeof(*nb));
            if (!nb) { free(p); return -1; }
            m->b = nb;
            m->cap = nc;
        }
        b = &m->b[m->n++];
        snprintf(b->name, sizeof(b->name), "%s", name);
        b->p = NULL;
    }
    free(b->p);
    b->p = p;
    b->n = n;
    return 0;
}

/* Записи, которые живут и на диске (только при изменении): active — выбор устройств для apply,
 * status и diag подкомандой; select — выбор человека у pick: manual, он обязан пережить перезапуск
 * демона и перезагрузку; groups — выбранный член и живые члены групп для status подкомандой. */
static int mem_mirrored(const char *name) {
    return !strcmp(name, "active") || !strcmp(name, "select") || !strcmp(name, "groups");
}

static void mem_put(struct fo_store *st, const char *name, const char *data, size_t n) {
    struct fo_mem *m = (struct fo_mem *)st;
    if (mem_set(m, name, data, n) == 0 && m->mirror && mem_mirrored(name))
        fo_store_files.ops->put(&fo_store_files, name, data, n);
}

static const struct fo_store_ops mem_ops = { mem_open_r, mem_put };

/* ---- здоровье помощников из памяти супервизора (fostate.h) ---------------------------------- */

struct fo_hmem {
    struct fo_hsrc base;
    struct steerd *d;
};

/* Помощник, которого демон не держит (вид без команды в этой сборке, движок выключен), —
 * прежним путём, по файлам: пишет их тот, кто его поднял. */
static int hmem_state(struct fo_hsrc *hs, const char *out, struct fo_hstate *h) {
    const struct helper_state *st = helper_state_of(((struct fo_hmem *)hs)->d, out);
    if (!st) return fo_hsrc_files.ops->state(&fo_hsrc_files, out, h);
    h->node = h->total = 0;
    /* Процесс жив и сам следит за узлом (последний его up — с watch, evline.h): UP — приговор без
     * пробы, DOWN — ждать его up (fostate.h). */
    h->watch = st->running && st->watch;
    if (st->nonode) {
        h->st = FO_HS_NONODE;
        h->node = (int)st->nonode;
        h->total = (int)st->total;
    } else if (!st->running) {
        h->st = FO_HS_DOWN;
    } else if (st->up) {
        h->st = FO_HS_UP;
    } else if (st->known) {
        h->st = FO_HS_DOWN;
    } else if (st->node > 0) {
        h->st = FO_HS_PROBING;
        h->node = (int)st->node;
        h->total = (int)st->total;
    } else {
        h->st = FO_HS_STARTING;
    }
    return 0;
}

/* Туннель xsteer, поднятый netifd, — не ребёнок демона: его клиент пишет файл, как и раньше. */
static int hmem_xsdev(struct fo_hsrc *hs, const char *dev, int *up, int *fresh) {
    (void)hs;
    return fo_hsrc_files.ops->xsdev(&fo_hsrc_files, dev, up, fresh);
}

static int hmem_restart(struct fo_hsrc *hs, const char *out, const char *cmd) {
    return supd_restart(((struct fo_hmem *)hs)->d->sup, out, cmd);
}

static const struct fo_hsrc_ops hmem_ops = {
    hmem_state, hmem_xsdev, hmem_restart, "процесс туннеля поднимет заново демон",
};


/* ---- сторож ---------------------------------------------------------------------------- */

/* Событие прохода, отложенное до его конца (см. шапку). */
struct wev {
    enum fo_ev_kind kind;
    char out[48], from[48], to[48], why[24], of[16], member[48];
    char *alive;                  /* имена живых членов через запятую — в куче, любой длины */
};

struct watchd {
    struct steerd *d;
    struct loop *l;
    struct watchd_conf cf;
    int nl;                       /* netlink; -1 — живём одним периодом */
    struct loop_timer *tm;        /* следующий проход: период или успокоение после события */
    struct loop_timer *kill_tm;   /* срок идущего прохода */
    int settling;                 /* tm стоит на успокоении, а не на периоде */
    int pending;                  /* после идущего прохода нужен ещё один */
    int revive_next;              /* ...и в нём члены групп оживляются (FO_PASS_REVIVE) */
    int eventful;                 /* проход идёт по событию сети или смене спеки */
    int on;                       /* движок включён: без этого ни таймера, ни сокета событий */
    int hold;                     /* первый проход ждёт конца стартового apply (watchd_release) */
    unsigned long passes;         /* проходов с начала — первый отмечается в журнале */
    struct fo_run *run;           /* идущий проход; NULL — нет */
    struct spec *sp;              /* копия спеки для прохода */
    struct wev *ev;
    int ev_n, ev_cap;
    long masq_at;                 /* когда последний раз возвращали masquerade (телефон) */
    struct fo_mem mem;
    struct fo_hmem hmem;          /* здоровье помощников — у супервизора демона (--supervise) */
    struct folat *lat;            /* замеры групп latency своими таймерами (folat.c) */
    /* Устройства раздачи и их номера, какими их видел сторож (шапка, «УСТРОЙСТВА РАЗДАЧИ»);
     * 0 — устройства нет. */
    struct { char name[IFNAMSIZ]; int idx; } *lan;   /* растёт по числу устройств спеки */
    size_t lan_n, lan_cap;
};

/* Сбросить очередь событий: alive у каждого — своя строка в куче. */
static void wev_clear(struct watchd *w) {
    for (int i = 0; i < w->ev_n; i++) { free(w->ev[i].alive); w->ev[i].alive = NULL; }
    w->ev_n = 0;
}

static void watchd_pass_start(struct watchd *w);

/* ---- устройства раздачи (шапка, «УСТРОЙСТВА РАЗДАЧИ») -------------------------------------- */

static int watchd_lan_on(const struct watchd *w) {
    return w->cf.lan && plat()->lan_devs_persist;
}

static int lan_in_spec(const struct watchd *w, const char *name) {
    const struct spec *sp = w->d->have ? w->d->sp : NULL;
    for (size_t i = 0; sp && i < sp->lan_dev_n; i++)
        if (!strcmp(sp->lan_dev[i], name)) return 1;
    return 0;
}

/* Место устройства name; нет — завести (create) с номером idx. NULL — не нашлось и не завелось. */
static int *lan_slot(struct watchd *w, const char *name, int create, int idx, int *fresh) {
    *fresh = 0;
    for (size_t i = 0; i < w->lan_n; i++)
        if (!strcmp(w->lan[i].name, name)) return &w->lan[i].idx;
    if (!create || strlen(name) >= IFNAMSIZ) return NULL;
    if (w->lan_n == w->lan_cap) {
        size_t nc = w->lan_cap ? w->lan_cap * 2 : 8;
        void *nl = realloc(w->lan, nc * sizeof(*w->lan));
        if (!nl) return NULL;
        w->lan = nl;
        w->lan_cap = nc;
    }
    snprintf(w->lan[w->lan_n].name, IFNAMSIZ, "%s", name);
    w->lan[w->lan_n].idx = idx;
    *fresh = 1;
    return &w->lan[w->lan_n++].idx;
}

/* Номера устройств раздачи спеки — как они есть сейчас; уже известные не трогаются (их смену
 * скажет событие). Зовётся при открытии сокета и при смене спеки. */
static void watchd_lan_seed(struct watchd *w) {
    if (!watchd_lan_on(w) || !w->d->have) return;
    const struct spec *sp = w->d->sp;
    for (size_t i = 0; i < sp->lan_dev_n; i++) {
        int fresh;
        lan_slot(w, sp->lan_dev[i], 1, (int)if_nametoindex(sp->lan_dev[i]), &fresh);
    }
}

/* Номер устройства name стал idx (0 — устройства нет): изменился — серверу сокета. */
static void watchd_lan_set(struct watchd *w, const char *name, int idx) {
    if (!lan_in_spec(w, name)) return;
    int fresh;
    int *cur = lan_slot(w, name, 1, idx, &fresh);
    if (!cur || (!fresh && *cur == idx)) return;
    if (fresh && !idx) return;        /* незнакомое и пропавшее — говорить не о чем */
    *cur = idx;
    w->cf.lan(w->cf.busy_arg, name, idx != 0);
}

static void watchd_lan_msg(struct watchd *w, const struct nlmsghdr *h) {
    if (h->nlmsg_type != RTM_NEWLINK && h->nlmsg_type != RTM_DELLINK) return;
    const struct ifinfomsg *ifi = NLMSG_DATA(h);
    size_t hl = NLMSG_ALIGN(sizeof(*ifi));
    if (h->nlmsg_len < NLMSG_HDRLEN + hl) return;
    char name[IFNAMSIZ] = "";
    const struct rtattr *a = (const struct rtattr *)((const char *)ifi + hl);
    int left = (int)(h->nlmsg_len - NLMSG_HDRLEN - hl);
    for (; RTA_OK(a, left); a = RTA_NEXT(a, left))
        if (a->rta_type == IFLA_IFNAME) {
            size_t n = RTA_PAYLOAD(a);
            if (n >= sizeof(name)) n = sizeof(name) - 1;
            memcpy(name, RTA_DATA(a), n);
            name[n] = '\0';
        }
    if (!name[0]) return;
    watchd_lan_set(w, name, h->nlmsg_type == RTM_NEWLINK ? ifi->ifi_index : 0);
}

/* Дочитать сокет событий сети: 1 — было хоть одно событие (как watch_nl_drain). Устройства
 * раздачи разбираются всегда, даже когда событие для прохода выбрасывается. Переполнение
 * (ENOBUFS: события потеряны) — номера устройств раздачи сверяются с ядром заново. */
static int watchd_drain(struct watchd *w) {
    if (w->nl < 0) return 0;
    _Alignas(struct nlmsghdr) char buf[8192];
    int any = 0, lost = 0;
    ssize_t r;
    while ((r = recv(w->nl, buf, sizeof(buf), 0)) > 0 || (r < 0 && errno == ENOBUFS)) {
        any = 1;
        if (r < 0) { lost = 1; continue; }
        if (!watchd_lan_on(w)) continue;
        size_t m = (size_t)r;
        for (struct nlmsghdr *h = (struct nlmsghdr *)buf; NLMSG_OK(h, m); h = NLMSG_NEXT(h, m))
            watchd_lan_msg(w, h);
    }
    if (lost && watchd_lan_on(w) && w->d->have)
        for (size_t i = 0; i < w->d->sp->lan_dev_n; i++)
            watchd_lan_set(w, w->d->sp->lan_dev[i], (int)if_nametoindex(w->d->sp->lan_dev[i]));
    return any;
}

/* Сторож спит: движок выключен или первый проход ждёт стартового apply. Ни один таймер тогда
 * не заводится — ни успокоение, ни период (см. шапку, «ВЫКЛЮЧЕННЫЙ ДВИЖОК»). */
static int watchd_dormant(const struct watchd *w) {
    return !w->on || w->hold;
}

static void watchd_settle(struct watchd *w) {
    w->eventful = 1;
    if (watchd_dormant(w)) return;
    if (w->settling) return;      /* пачка уже ждёт своего прохода — срок не отодвигаем */
    w->settling = 1;
    loop_timer_set(w->tm, WATCH_SETTLE_S * 1000L);
}

static void watchd_period(struct watchd *w) {
    w->settling = 0;
    if (watchd_dormant(w)) { loop_timer_stop(w->tm); return; }
    loop_timer_set(w->tm, w->cf.period_s * 1000L);
}

static void watchd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    w->settling = 0;
    if (w->run) return;           /* не бывает: таймер снят на время прохода */
    /* Спеки нет — проходить нечем, и тикать впустую незачем: прочитанная спека (apply, reload,
     * SIGHUP) сама позовёт проход через watchd_spec_changed. Выключатель сменился без
     * reload — сторож засыпает сам, а не проверяет его раз в период. */
    if (!w->d->have) return;
    if (w->cf.enabled && !w->cf.enabled()) { watchd_enable(w, 0); return; }
    if (w->cf.busy && w->cf.busy(w->cf.busy_arg)) { watchd_settle(w); return; }
    /* Набор правил против ядра — перед каждым проходом (шапка, «СВЕРКА НАБОРА ПРАВИЛ»): сейчас,
     * когда своей изменяющей команды нет. Нашлось расхождение — починка встала в очередь и,
     * скорее всего, уже идёт; проход тогда откладывается, как при любой изменяющей команде:
     * он и она пишут одни и те же таблицы. */
    if (w->cf.kcheck) {
        w->cf.kcheck(w->cf.busy_arg);
        if (w->cf.busy && w->cf.busy(w->cf.busy_arg)) { watchd_settle(w); return; }
    }
    watchd_drain(w);                         /* пачка, ради которой ждали, — в этот проход */
    watchd_pass_start(w);
}

static void watchd_nl(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct watchd *w = arg;
    (void)fd;
    if (!watchd_drain(w)) return;
    if (watchd_dormant(w)) return;
    /* Во время прохода: на роутере — следы его же ifdown/ifup (выбрасываются после прохода),
     * на телефоне — настоящее событие, и после прохода нужен ещё один. */
    if (w->run) {
        if (!plat()->netifd) w->pending = 1;
        return;
    }
    watchd_settle(w);
}

void watchd_spec_changed(struct watchd *w) {
    if (!w) return;
    /* Устройства раздачи новой спеки — с номерами, какие есть сейчас (шапка, «УСТРОЙСТВА
     * РАЗДАЧИ»). Только при открытом сокете: без него событий и не будет. */
    if (w->nl >= 0) watchd_lan_seed(w);
    if (watchd_dormant(w)) return;
    if (w->run) w->pending = 1;
    else watchd_settle(w);
}

void watchd_helper_changed(struct watchd *w) {
    watchd_spec_changed(w);
}

/* ---- проход ------------------------------------------------------------------------------ */

/* Событие прохода — в очередь до конца прохода. */
static void watchd_ev(void *arg, const struct fo_event *e) {
    struct watchd *w = arg;
    if (w->ev_n == w->ev_cap) {
        int nc = w->ev_cap ? w->ev_cap * 2 : 64;
        struct wev *ne = realloc(w->ev, (size_t)nc * sizeof(*ne));
        if (!ne) return;                /* событие теряется только без памяти */
        w->ev = ne;
        w->ev_cap = nc;
    }
    struct wev *q = &w->ev[w->ev_n++];
    q->kind = e->kind;
    snprintf(q->out, sizeof(q->out), "%s", e->out ? e->out : "");
    snprintf(q->from, sizeof(q->from), "%s", e->from ? e->from : "");
    snprintf(q->to, sizeof(q->to), "%s", e->to ? e->to : "");
    snprintf(q->why, sizeof(q->why), "%s", e->why ? e->why : "");
    snprintf(q->of, sizeof(q->of), "%s", e->on_fail ? e->on_fail : "");
    snprintf(q->member, sizeof(q->member), "%s", e->member ? e->member : "");
    q->alive = strdup(e->alive ? e->alive : "");
}

void steerd_fo_emit(struct steerd *d, const struct fo_event *e) {
    char out[112], from[112], to[112], why[64], of[48], mem[112], f[2048];
    steerd_json_str(out, sizeof(out), e->out ? e->out : "");
    if (e->from && e->from[0]) steerd_json_str(from, sizeof(from), e->from); else strcpy(from, "null");
    if (e->to && e->to[0]) steerd_json_str(to, sizeof(to), e->to); else strcpy(to, "null");
    steerd_json_str(why, sizeof(why), e->why ? e->why : "");
    steerd_json_str(of, sizeof(of), e->on_fail ? e->on_fail : "");
    /* Поля групп v2 — только добавлены и только у них: у пула v1 событие прежнее до байта. */
    char extra[256] = "";
    if (e->member && e->member[0]) {
        steerd_json_str(mem, sizeof(mem), e->member);
        snprintf(extra, sizeof(extra), ",\"member\":%s", mem);
    }
    if (e->by && e->by[0]) {
        size_t l = strlen(extra);
        snprintf(extra + l, sizeof(extra) - l, ",\"by\":\"%s\"", e->by);
    }
    switch (e->kind) {
    case FO_EV_SWITCHED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"to\":%s,\"why\":%s%s", out, from, to, why,
                 extra);
        steerd_emit(d, "switched", f);
        break;
    case FO_EV_FAILED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"from\":%s,\"on_fail\":%s,\"why\":%s%s", out, from, of,
                 why, extra);
        steerd_emit(d, "failed", f);
        break;
    case FO_EV_REVIVED:
        snprintf(f, sizeof(f), ",\"out\":%s,\"dev\":%s", out, to);
        steerd_emit(d, "revived", f);
        break;
    case FO_EV_BALANCE: {
        /* alive — массив имён живых членов (в карте раздачи). Буфер — по длине списка: имён в
         * группе не «не больше 16», а сколько написано (имя в JSON — до ~112 байт с кавычками). */
        const char *al = e->alive ? e->alive : "";
        size_t fc = 256 + strlen(al) * 4 + 16;
        char *fb = malloc(fc), *names = strdup(al);
        if (!fb || !names) { free(fb); free(names); break; }
        size_t l = (size_t)snprintf(fb, fc, ",\"out\":%s,\"alive\":[", out);
        int first = 1;
        for (char *tok = strtok(names, ","); tok && l < fc; tok = strtok(NULL, ",")) {
            char js[112];
            steerd_json_str(js, sizeof(js), tok);
            l += (size_t)snprintf(fb + l, fc - l, "%s%s", first ? "" : ",", js);
            first = 0;
        }
        if (l < fc) snprintf(fb + l, fc - l, "]");
        steerd_emit(d, "balance", fb);
        free(fb);
        free(names);
        break;
    }
    }
}

/* Одно событие прохода — подписчикам (поля — docs/ctl.md). */
static void watchd_emit(struct watchd *w, const struct wev *q) {
    struct fo_event e = { .kind = q->kind, .out = q->out, .from = q->from, .to = q->to,
                          .why = q->why, .on_fail = q->of, .member = q->member,
                          .alive = q->alive };
    steerd_fo_emit(w->d, &e);
}

static void watchd_after(struct watchd *w) {
    w->run = NULL;
    loop_timer_stop(w->kill_tm);
    /* Память выходов уже новая — теперь события (см. шапку). */
    int n = w->ev_n;
    w->ev_n = 0;
    for (int i = 0; i < n; i++) {
        watchd_emit(w, &w->ev[i]);
        free(w->ev[i].alive);
        w->ev[i].alive = NULL;
    }
    /* masquerade правилом iptables (телефон) — см. шапку: не на каждом проходе. */
    if (plat()->iptables_masq && w->d->have && watch_masq_due(&w->masq_at, w->eventful))
        iptables_masq_ensure(w->d->sp);
    w->eventful = 0;
    /* Таймеры замеров групп latency — по спеке, которую проход только что прошёл (новая группа
     * получает свой, ушедшая теряет). */
    if (!watchd_dormant(w)) folat_sync(w->lat);
    /* На роутере события за время прохода — следы его же ifdown/ifup (см. шапку). */
    if (plat()->netifd) watchd_drain(w);
    if (w->pending) {
        w->pending = 0;
        watchd_settle(w);
    } else {
        watchd_period(w);
    }
}

/* Итог FO_PASS_REVIVE — член группы v2 молчал, и его оживление отложено (fo_pass_defer_revive):
 * группа в этом проходе уже ушла на живого члена, а оживление — в следующем, через успокоение. */
static void watchd_pass_done(void *arg, int res) {
    struct watchd *w = arg;
    if (res & FO_PASS_REVIVE) {
        w->revive_next = 1;
        w->pending = 1;
    }
    watchd_after(w);
}

static void watchd_kill(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct watchd *w = arg;
    if (!w->run) return;
    fprintf(stderr, LOG_WW "проход идёт дольше %d с — прерываю\n", WATCHD_PASS_MAX_S);
    fo_pass_abort(w->run);
    /* Выбор прерванного прохода не записан (active кладётся в конце) — и его события тоже не
     * уходят: следующий проход решит заново и скажет сам. */
    wev_clear(w);
    watchd_after(w);
}

/* ---- трафик через группу (idle_timeout замера urltest) ---------------------------------- */

/* Выбирает ли группа a (прямо или через вложенные) выход g. */
static int group_reaches(const struct spec *sp, const struct output *a, const struct output *g,
                         int depth) {
    if (a == g) return 1;
    const struct group_cfg *ga = out_group(a);
    for (size_t k = 0; ga && k < ga->members_n && (size_t)depth < sp->out_n; k++)
        if (spec_is_named(ga->members[k]) &&
            group_reaches(sp, &sp->out[ga->members[k]], g, depth + 1))
            return 1;
    return 0;
}

struct wtraffic {
    const struct groups *gr;
    unsigned char *want;              /* по номеру группы каналов: её правила — трафик группы */
    unsigned long long pkts;
};

static void wtraffic_rule(void *arg, const char *comment, int has_counter, uint64_t packets,
                          uint64_t bytes) {
    (void)bytes;
    struct wtraffic *t = arg;
    if (!has_counter || strncmp(comment, "steer:", 6) != 0) return;
    for (size_t i = 0; i < t->gr->n; i++)
        if (t->want[i] && !strcmp(t->gr->g[i].name, comment + 6)) t->pkts += packets;
}

/* Пакеты правил каналов, ведущих в группу g или в группу, которая выбирает g (fostate.h,
 * fo_traffic_fn). Счётчики — у ядра по netlink (nfd_chain_rules), без процессов; группы каналов
 * — демона (в памяти вместе со спекой). Обе цепочки разметки: раздача и сам телефон. */
static int watchd_traffic(void *arg, const struct spec *sp, const struct output *g,
                          unsigned long long *pkts) {
    struct watchd *w = arg;
    if (!w->d->have || !sp) return -1;
    struct wtraffic t;
    memset(&t, 0, sizeof(t));
    t.gr = w->d->gr;
    t.want = calloc(t.gr->n ? t.gr->n : 1, 1);      /* по группе каналов — их не 256 */
    if (!t.want) return -1;
    int any = 0;
    for (size_t i = 0; i < t.gr->n; i++) {
        const struct output *o = NULL;
        for (size_t k = 0; k < sp->out_n; k++)
            if (!strcmp(sp->out[k].name, t.gr->g[i].out)) o = &sp->out[k];
        if (o && group_reaches(sp, o, &sp->out[g - sp->out], 0)) t.want[i] = any = 1;
    }
    if (!any) {
        free(t.want);
        *pkts = 0;
        return 0;
    }
    /* ingress_mark — разметка каналов раздачи на хуке ingress (compile/generate.c, «разметка на
     * ingress»): там растут счётчики каналов раздачи, а запасные правила prerouting_mark их
     * пакеты уже не проходят. Цепочки нет (ingress не ставился) — nfd_chain_rules её просто не
     * находит. Пакет, который разметили оба хука (чужая перезапись метки между ними), здесь
     * засчитывается дважды: вопрос «шёл ли трафик» от этого не меняется. */
    static const char *const chains[] = { "ingress_mark", "prerouting_mark", "output_mark" };
    int rc = nfd_chain_rules(NFD_INET, nft_table(), chains, 3, wtraffic_rule, &t);
    free(t.want);
    if (rc != 0) return -1;
    *pkts = t.pkts;
    return 0;
}

/* ---- замеры групп latency своими таймерами (folat.c) ---------------------------------------- */

static const struct spec *watchd_lat_spec(void *arg) {
    struct watchd *w = arg;
    return w->d->have ? w->d->sp : NULL;
}

static struct fo_hsrc *watchd_lat_hs(void *arg) {
    struct watchd *w = arg;
    return w->d->sup ? &w->hmem.base : &fo_hsrc_files;
}

/* Замер сменил бы выбор группы — внеочередной проход сейчас, без успокоения: ждать нечего, это
 * не пачка событий сети. Идёт проход — ещё один после него. */
static void watchd_lat_kick(void *arg, const char *group) {
    struct watchd *w = arg;
    if (watchd_dormant(w)) return;
    fprintf(stderr, "steer[info] watch: %s: по замеру быстрее другой член — внеочередной проход\n",
            group);
    if (w->run) { w->pending = 1; return; }
    w->settling = 1;
    loop_timer_set(w->tm, 0);
}

static void watchd_pass_start(struct watchd *w) {
    if (!w->sp) w->sp = calloc(1, sizeof(*w->sp));
    /* Проход меняет device у выходов — своя копия, а спека демона остаётся нетронутой для
     * status и masquerade (они смотрят на спеку так, как её прочитал бы свежий процесс).
     * Копируются выходы и состояние групп; правила, списки и клиенты читаются из общей арены
     * по ссылке (spec_clone): раньше здесь был memcpy всей struct spec, под 250 КБ на проход. */
    if (!w->sp || spec_clone(w->sp, w->d->sp) != 0) {
        fprintf(stderr, LOG_WW "нет памяти под проход\n");
        watchd_period(w);
        return;
    }
    wev_clear(w);
    if (!w->passes++) fprintf(stderr, "steer[info] watch: первый проход\n");
    loop_timer_stop(w->tm);
    w->run = fo_pass_start(w->l, w->sp, &w->mem.base, 0, watchd_ev, w, watchd_pass_done, w);
    if (!w->run) {
        fprintf(stderr, LOG_WW "нет памяти под проход\n");
        watchd_period(w);
        return;
    }
    /* Супервизор заводится после сторожа — спрашивается на каждый проход. */
    if (w->d->sup) fo_pass_helpers(w->run, &w->hmem.base);
    fo_pass_traffic(w->run, watchd_traffic, w);
    /* Замеры по сроку — таймерами групп (folat.c), а не проходом. */
    if (w->lat) fo_pass_lat_extern(w->run);
    if (!w->revive_next) fo_pass_defer_revive(w->run);
    w->revive_next = 0;
    loop_timer_set(w->kill_tm, WATCHD_PASS_MAX_S * 1000L);
}

/* ---- заведение и уход ------------------------------------------------------------------ */

/* Сокет событий сети: открыт, только пока движок включён. */
static void watchd_nl_up(struct watchd *w) {
    if (w->nl >= 0) return;
    w->nl = watch_nl_open();
    if (w->nl >= 0 && loop_fd_add(w->l, w->nl, EPOLLIN, watchd_nl, w) != 0) {
        close(w->nl);
        w->nl = -1;
    }
    if (w->nl < 0)
        fprintf(stderr, LOG_WW "события сети недоступны — проход только по периоду\n");
    else
        watchd_lan_seed(w);
}

static void watchd_nl_down(struct watchd *w) {
    if (w->nl < 0) return;
    loop_fd_del(w->l, w->nl);
    close(w->nl);
    w->nl = -1;
    w->lan_n = 0;                 /* без сокета номера устаревают — при включении заново */
}

struct watchd *watchd_start(struct steerd *d, const struct watchd_conf *c, int on, int hold) {
    struct watchd *w = calloc(1, sizeof(*w));
    if (!w) return NULL;
    w->d = d;
    w->l = d->loop;
    w->cf = *c;
    if (w->cf.period_s <= 0) w->cf.period_s = 60;
    w->mem.base.ops = &mem_ops;
    w->hmem.base.ops = &hmem_ops;
    w->hmem.d = d;
    w->tm = loop_timer_new(w->l, watchd_timer, w);
    w->kill_tm = loop_timer_new(w->l, watchd_kill, w);
    struct folat_conf lc = { .l = w->l, .st = &w->mem.base, .spec = watchd_lat_spec,
                             .hs = watchd_lat_hs, .traffic = watchd_traffic,
                             .kick = watchd_lat_kick, .arg = w };
    w->lat = folat_new(&lc);
    if (!w->tm || !w->kill_tm || !w->lat) {
        loop_timer_free(w->tm);
        loop_timer_free(w->kill_tm);
        free(w->lat);
        free(w);
        return NULL;
    }
    /* Выбор устройств, оставленный прежним сторожем (или этим же демоном до перезапуска), —
     * как его увидел бы очередной `steer failover`. */
    static const char *const kept[] = { "active", "select", "groups" };
    for (size_t r = 0; r < sizeof(kept) / sizeof(kept[0]); r++) {
        FILE *f = fo_store_files.ops->open_r(&fo_store_files, kept[r]);
        if (!f) continue;
        /* Файл читается целиком в буфер по его размеру (раньше — 11 КБ на «16 выходов по 700»:
         * длиннее — не подхватывался вовсе, и выбор устройств у большой спеки терялся). */
        size_t cap = 4096, n = 0;
        char *buf = malloc(cap);
        for (;;) {
            if (!buf) break;
            if (n == cap) {
                char *nb = realloc(buf, cap * 2);
                if (!nb) { free(buf); buf = NULL; break; }
                buf = nb;
                cap *= 2;
            }
            size_t got = fread(buf + n, 1, cap - n, f);
            if (!got) break;
            n += got;
        }
        fclose(f);
        if (buf) mem_set(&w->mem, kept[r], buf, n);
        free(buf);
    }
    w->mem.mirror = 1;
    /* Замеры awg — в памяти процесса, как у `failover --loop`. */
    awg_hs_memory(1);
    /* Правило пробы, оставшееся от сторожа, убитого SIGKILL (прежний круг, прежний демон), —
     * один раз при старте: свои правила проход снимает сам (и при отмене). */
    cleanup_probe_rule();
    w->nl = -1;
    d->outs = &w->mem.base;
    d->watch = w;
    w->eventful = 1;              /* первый проход — как по событию: masquerade проверить */
    w->hold = hold;
    if (on) watchd_enable(w, 1);
    return w;
}

void watchd_enable(struct watchd *w, int on) {
    if (!w || w->on == !!on) return;
    w->on = !!on;
    if (on) {
        watchd_nl_up(w);
        w->eventful = 1;
        w->settling = 0;
        if (!w->hold) loop_timer_set(w->tm, 0);
        return;
    }
    /* Выключили: маршрутизацию трогать больше нельзя — идущий проход прерывается с уборкой
     * правила пробы, его события не уходят (решения прерванного прохода не записаны). */
    if (w->run) {
        fo_pass_abort(w->run);
        w->run = NULL;
        wev_clear(w);
    }
    loop_timer_stop(w->kill_tm);
    loop_timer_stop(w->tm);
    w->settling = w->pending = 0;
    watchd_nl_down(w);
    /* И замеры групп: выключенный движок — ни одного пробуждения. */
    folat_stop(w->lat);
}

void watchd_release(struct watchd *w) {
    if (!w || !w->hold) return;
    w->hold = 0;
    if (!w->on || w->run) return;
    w->eventful = 1;
    w->settling = 0;
    loop_timer_set(w->tm, 0);
}

void watchd_preempt(struct watchd *w) {
    if (!w || !w->run) return;
    fo_pass_abort(w->run);
    w->run = NULL;
    wev_clear(w);
    loop_timer_stop(w->kill_tm);
    w->pending = 0;
    /* Следующий проход — после успокоения (он сверит всё заново по ядру и памяти); таймер периода
     * был снят на время прохода. */
    watchd_settle(w);
}

void watchd_stop(struct watchd *w) {
    if (w && w->run) {
        fo_pass_abort(w->run);
        w->run = NULL;
    }
    if (w) folat_stop(w->lat);
}
