/* Супервизор в демоне: `steer daemon --supervise` — помощники выходов и резолвер детьми демона.
 *
 * Шаг 4 устройства 1.8 (docs/architecture.md, «4а», «Дети и здоровье», «dnsd»). Что поднимать,
 * в каком порядке и когда перезапускать — общая с `steer supervise` логика (helpers.c); здесь —
 * то, как это живёт в цикле событий демона, и то, чего у `supervise` нет: трубы событий
 * помощников и резолвер на таблице.
 *
 * ВКЛЮЧАЕТСЯ ФЛАГОМ, как сторож (--watch). До шага 6 на роутере помощников и резолвер держит
 * procd (init.d/steer), на телефоне — сервисы `steer supervise` и dnsd. Два супервизора сразу
 * подняли бы по два экземпляра каждого помощника (второй обфускатор на том же порту, второй
 * резолвер на 5300), поэтому демон супервизор только с --supervise, а сервис, который его так
 * запускает, обязан снять прежние.
 *
 * ДЕТИ — fork+exec без ожиданий в цикле: выход ребёнка приходит через loop_child, срок
 * следующего запуска — одним таймером цикла на ближайший срок (в тишине таймер снят, и демон
 * не просыпается). Запуск помощника — та же командная строка, что у init.d и `supervise`
 * (helper_argv); дочерний процесс не знает, кто его поднял, кроме одной переменной:
 *
 * ТРУБА СОБЫТИЙ. Каждому помощнику — своя труба: конец записи он получает номером в
 * STEER_EVENT_FD (формат строк — src/lib/evline.h), конец чтения — в epoll демона. Пишет
 * помощник только при смене состояния, поэтому в тишине труба молчит. Демон разбирает строки
 * evline_parse и держит по выходу struct helper_state (поднят ли, почему упал, какой узел
 * проверяется, с какого времени), а подписчикам шлёт helper-up, helper-down и node (docs/ctl.md).
 * Процесс, вышедший молча после up, — тоже helper-down: причина — код выхода. Труба своя у
 * каждого запуска: события прежнего экземпляра не спутать с событиями нового.
 *
 * СТОРОЖУ (демон ещё и с --watch) это состояние — источник здоровья выходов vless и xsteer
 * (fostate.h, watchd.c): смена up/down будит его внеочередным проходом (watchd_helper_changed), а
 * обфускатор выхода interface он оживляет не сигналом procd, а просьбой сюда — supd_restart:
 * помощник гасится и поднимается сразу, без паузы падения, с причиной «перезапуск: выход не
 * отвечает» у helper-down. Ход перебора узлов vless отсюда же берут status демона (в процессе,
 * probe_source) и его дети (переменная STEER_PROBE_MEM) — файлов probe-* клиенты с трубой не пишут.
 *
 * РЕЗОЛВЕР НА ТАБЛИЦЕ. `steer dnsd --table-fd N`: спеку он не читает — таблицу доменных каналов
 * (src/dnsd/tabfmt.h) демон пишет ему в трубу при запуске и при каждой смене спеки в памяти
 * (apply, reload, SIGHUP), и резолвер заменяет её без перезапуска (и перечитывает файлы списков
 * — то, что прежде делал SIGHUP). Поэтому ни подпись dnsd.sig, ни выбор «HUP или перезапуск»
 * здесь не нужны. Нужен ли резолвер, решает то же, что у init.d (needs-dnsd, dnsd_wanted).
 *
 * РЕЗОЛВЕР ПЕРЕЖИВАЕТ ДЕМОНА. Закрытая труба (демон убит SIGKILL, упал) для резолвера — «демона
 * нет»: он отвечает по последней таблице и ждёт нового демона (src/dnsd/adopt.c — доводы и
 * протокол). Поэтому, прежде чем запускать резолвер, демон ищет живой — по управляющему сокету в
 * каталоге состояния — и забирает его (adopt_dnsd): отдаёт новую трубу таблицы через SCM_RIGHTS,
 * и дальше всё как с ребёнком, кроме одного: выход не своего ребёнка не приходит через
 * loop_child, и о нём говорит закрытие того же соединения (dn_conn). Резолвер не нужен (спеки нет,
 * движок выключен) — найденный гасится (orphan_stop).
 *
 * ПОМОЩНИКИ ДЕМОНА НЕ ПЕРЕЖИВАЮТ. В отличие от резолвера, пережить демона помощнику незачем и
 * вредно: у резолвера есть что отдать новому демону (последняя таблица, порт 5300 без перерыва
 * DNS), у помощника — нет, зато он держит то, что нужно новому экземпляру: устройство TUN
 * клиента vless или xsteer (новый падает «устройство vr не создалось: Resource busy, отказал
 * TUNSETIFF» с паузой 5→10→…→80 с, и выход лежит, пока сироту не убьют руками — проверка на
 * QEMU 4192267), порт listen обфускатора, очередь NFQUEUE обработчика модуля DPI. Прежде после
 * kill -9 демона такого сироту не гасил никто: новый демон подхватывал только резолвер
 * (adopt_dnsd), а сам помощник смерти родителя не замечал — события он пишет лишь при смене
 * состояния, и закрытая труба в тишине ничем себя не выдаёт. Теперь признаков три, и каждый
 * закрывает окно, которое оставляют другие:
 *
 *   1) PR_SET_PDEATHSIG(SIGTERM) в ребёнке до exec (child_arm) — ядро само шлёт помощнику
 *      SIGTERM, когда умирает поток, сделавший fork. Потоки у демона есть (gaiw.c — getaddrinfo,
 *      urltls.c — проверка urltest), но fork делает только главный: supd_kick зовётся из
 *      обратных вызовов цикла (loop.c однопоточный), а потоки те — рабочие, без fork и exec, и
 *      выходят сами, не забирая с собой детей. Главный же поток кончается только вместе с
 *      процессом. Признак переживает exec (кроме set-uid и файлов с capabilities — таких
 *      помощников нет) и не требует от помощника ничего: так гаснет и steer-nfqws, в код которого
 *      мы не лезем. Окно между fork и prctl (демон умер раньше, чем ребёнок взвёл признак)
 *      закрывает проверка getppid() сразу после prctl — обычная пара.
 *   2) Переменная STEER_SUPD=<pid>:<время старта>:<каталог состояния> — метка «чей я». По ней
 *      evline_open (src/lib/evline.c) в самом помощнике после exec проверяет, жив ли ещё его
 *      демон, и взводит признак заново; по ней же новый демон находит сирот прежнего (ниже).
 *      EPIPE на трубе событий — тоже «демона нет», и evline_emit гасит процесс тем же SIGTERM.
 *      Идёт он именно EPIPE, а не SIGPIPE: у модульных команд SIGPIPE выключен (cli/modcmd.c,
 *      ради сокетов узла), как у моста tgws и резолвера.
 *   3) Новый демон при старте (supd_start) и `steerd down` (supd_orphan_down) гасят помощников,
 *      чей демон мёртв, — orphans_stop: по /proc, процессы с STEER_EVENT_FD и STEER_SUPD этого
 *      каталога состояния, чьего демона с тем pid и тем временем старта больше нет. Нужно это
 *      не на случай, что PDEATHSIG не сработал, а потому что SIGTERM помощник исполняет не
 *      мгновенно: клиент vless закрывает соединения, обфускатор — сокеты, и новый демон,
 *      поднятый procd через секунду, иначе ещё мог бы застать устройство занятым.
 *      Чужих не трогает: без STEER_EVENT_FD или без STEER_SUPD (помощники под procd, `steer supervise`) процесс не
 *      наш, с меткой другого каталога состояния — чужой демон, с меткой живого демона —
 *      помощник живого демона (второй демон на том же каталоге — не наш случай, и гасить у
 *      него помощников этот демон не берётся).
 *
 * Резолвер ни одного из трёх не получает: у него нет STEER_EVENT_FD и STEER_SUPD, и PDEATHSIG
 * ему не ставится — он переживает демона нарочно (выше).
 *
 * ВЫКЛЮЧАТЕЛЬ. Движок выключен (телефон) — состав пустой: ни помощников, ни резолвера, и
 * поднятые гаснут при очередной сверке (apply, reload, SIGHUP — то, после чего демон перечитывает
 * спеку и спрашивает выключатель).
 *
 * ОСТАНОВКА — supd_stop: резолверу SIGTERM (явно: закрытую трубу он пережил бы) и закрыть
 * трубу, помощникам по одному в обратном порядке подъёма SIGTERM и по сроку SIGKILL
 * (helpers_stop). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <poll.h>
#include <dirent.h>

#include "platform.h"
#include "spec.h"
#include "evline.h"
#include "tabfmt.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "watchd.h"
#include "helpers.h"
#include "module.h"
#include "awg.h"

#define LOG_SW "steer[warn] supervise: "
/* Таблицы, не забранные резолвером: резолвер, у которого в очереди лежит больше восьми таблиц
 * сразу (и не меньше мегабайта), трубу не читает вовсе, и она закрывается (он выйдет и
 * поднимется заново). Предел считается в таблицах, а не в байтах: таблица спеки с большими
 * списками бывает и в десятки мегабайт, и жёсткий мегабайт закрывал бы трубу на первой же
 * отдаче. Одна таблица в пустую очередь принимается любой длины. */
#define SUPD_TABQ_MIN (1024 * 1024)
#define SUPD_TABQ_TABS 8

struct supd {
    struct steerd *d;
    struct loop *l;
    int (*enabled)(void);
    const char **dnsd_flags;        /* куча, NULL в конце; число флагов не ограничено */
    size_t dnsd_flag_n;
    struct helper_set set;
    struct helper *fresh;          /* план сверки: по выходу спеки + резолвер (supd_plan) */
    size_t fresh_cap, fresh_n;
    struct loop_timer *tm;
    char exe[PATH_MAX];       /* движок или шов STEER_SUPERVISE_EXE */
    char self[PATH_MAX];      /* настоящий файл движка: резолвер и помощники-программы */
    int seam;
    int stopping;
    /* Отпечаток последней отданной резолверу таблицы (текст и файлы списков); tab_ok=0 — не
     * отдавали. */
    unsigned long long tab_fp;
    int tab_ok;
    /* Резолвер: конец записи трубы таблицы и не отданные ещё байты. */
    int dn_fd;
    int dn_out;               /* ждём EPOLLOUT */
    char *q;
    size_t qn, qoff, qcap;
    /* Резолвер забран у прежнего демона (adopt_dnsd): соединение с его управляющим сокетом —
     * его закрытие и есть выход резолвера; -1 — резолвер свой ребёнок (или его нет). */
    int dn_conn;
    /* Забор резолвера (adopt_dnsd) идёт без ожидания в цикле демона: ad_ph — что ждём (0 — ничего;
     * 1 — ответ «ok» на «adopt»; 2 — выхода резолвера после SIGTERM; 3 — после SIGKILL), ad_ans/ad_an —
     * принятая часть ответа, ad_pid — резолвер, ad_p1 — конец записи новой трубы таблицы (до «ok» — не
     * s->dn_fd), ad_tm — срок ожидания. */
    int ad_ph, ad_p1;
    char ad_ans[16];
    size_t ad_an;
    pid_t ad_pid;
    struct loop_timer *ad_tm;
    /* Метка помощников «чей я» (шапка, «Помощники демона не переживают»): «STEER_SUPD=…» для
     * putenv в ребёнке, и pid демона — для проверки getppid() там же. */
    char tag[PATH_MAX + 64];
    pid_t me;
    /* Приговоры членам групп от их помощника (событие member, модуль steer-warpbox): член мёртв
     * по проверке модуля раньше, чем это увидит сторож по рукопожатию. Держится, пока жив процесс
     * помощника: вышел он — его приговоры снимаются (child_cb), иначе член остался бы «мёртвым»
     * навсегда. */
    struct mverdict { char out[32], grp[32]; signed char v; } *mv;
    size_t mv_n, mv_cap;
};

static void supd_kick(struct supd *s);
static const struct supd *g_probe_sup;
static int probe_mem(const char *out, struct probe_status *ps);
static void status_fields(FILE *out, const char *name);

/* ---- события помощников ------------------------------------------------------------------- */

static struct helper *by_fd(struct supd *s, int fd) {
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].evfd == fd) return &s->set.h[i];
    return NULL;
}

static void emit_state(struct supd *s, const struct helper *h, const char *ev, const char *why) {
    char out[80], w[512], f[700];
    steerd_json_str(out, sizeof(out), h->name);
    if (why) {
        steerd_json_str(w, sizeof(w), why);
        snprintf(f, sizeof(f), ",\"out\":%s,\"helper\":\"%s\",\"why\":%s", out, h->cmd, w);
    } else {
        snprintf(f, sizeof(f), ",\"out\":%s,\"helper\":\"%s\"", out, h->cmd);
    }
    steerd_emit(s->d, ev, f);
}

/* Сторожу (--watch) — внеочередной проход, если от этого помощника зависит здоровье выхода:
 * устройство выхода создаёт наш процесс (vless, xsteer). Обфускатор и мост сторож о здоровье не
 * спрашивает — будить его их событиями незачем. */
static void wake_watch(struct supd *s, const struct helper *h) {
    if (!s->d->watch || !s->d->have) return;
    const struct output *o = out_by_name(s->d->sp, h->name);
    if (o && out_engine_managed(o)) watchd_helper_changed(s->d->watch);
}

/* up с устройством (поле dev, evline.h): помощник выхода поднял TUN — привязать к нему маршрут
 * выхода. Шаг 3 выпуска 1.10 (docs/architecture.md, «4а», «Дети и здоровье»: маршрут выхода к
 * устройству помощника ставит демон по событию up).
 *
 * ЧТО БЫЛО. bind_device звали сами клиенты: VLESS — из стека сразу после подъёма устройства,
 * xsteer — из spoke_run. Это код демона (таблица, ip rule, conntrack, набор failopen — failover.c)
 * в процессе помощника, а с шага 4 помощник — бинарник модуля на libsteer, и маршрутизации с её
 * моделью в нём быть не должно. Момент готовности устройства по-прежнему знает только помощник,
 * поэтому он о нём говорит, а привязывает демон — тем же bind_device, в своём процессе, без
 * ребёнка: bind_device зовёт и проход сторожа на этом же цикле событий.
 *
 * ОДИН РАЗ НА ПРОЦЕСС (st->bound). Помощник пишет dev в каждом up: клиент vless — и после
 * возврата узла, xsteer — на каждом рукопожатии каждого соединения. Привязка же — событие «маршрут
 * меняется» (первое устройство процесса), а не «помощник снова здоров»: bind_device снимает
 * соединения выхода (conntrack_evict), и повтор на каждом рукопожатии рвал бы людям закачки.
 * Прежде клиент тоже привязывал ровно раз — при подъёме устройства. Маршрут после отказа (down →
 * сторож поставил on_fail → снова up) возвращает проход сторожа, которого будит тот же up
 * (wake_watch): решение об отказе и возврате одно, у сторожа, второго пути здесь нет.
 *
 * НЕ ПРИВЯЗЫВАЕТСЯ: выход не наш по виду (устройством владеет не наш процесс — out_engine_managed),
 * без метки или таблицы (реестр не назначен — `ip rule fwmark 0` поймал бы весь трафик), и
 * устройство не то, что у выхода в спеке: помощник поднимает TUN с именем устройства выхода, и
 * другое имя — чужой или устаревший помощник; строка в журнал, и решает сторож.
 *
 * Вызывается ДО helper-up подписчикам и до внеочередного прохода: проход, которого будит этот up,
 * видит уже привязанный маршрут, а подписчик, получивший helper-up, — выход, по которому идёт
 * трафик. */
static void route_up(struct supd *s, struct helper *h, const char *dev) {
    struct helper_state *st = &h->st;
    if (!s->d->have || !dev[0] || !strcmp(st->bound, dev)) return;
    struct output *o = out_by_name(s->d->sp, h->name);
    if (!o || !out_engine_managed(o) || !o->mark || !o->table) return;
    if (strcmp(dev, o->device) != 0) {
        fprintf(stderr, LOG_SW "%s %s сообщил устройство %.15s, а у выхода — %s: маршрут не "
                        "привязан\n", h->cmd, h->name, dev, o->device);
        return;
    }
    bind_device(o, dev);
    snprintf(st->bound, sizeof(st->bound), "%s", dev);
    fprintf(stderr, "steer[info] supervise: %s %s — %s поднят, маршрут выхода привязан "
                    "(таблица %d)\n", h->cmd, h->name, dev, o->table);
}

/* health (мост tgws): путь до ДЦ отставлен — оценка пути, а не помощника целиком, поэтому
 * здоровья выхода она не меняет и сторожа не будит (выход моста сторож не выбирает: устройства у
 * него нет). Демон её помнит — status выхода показывает отставленные пути, пока их срок не
 * вышел (paths_down, status_fields), — и шлёт подписчикам событием health. Тот же путь
 * повторно — запись обновляется на месте; мест нет — вытесняется самая старая. */
static void ev_health(struct supd *s, struct helper *h, const struct evline *e) {
    long dc, media = 0, cool = 0;
    const char *dom = evline_str(e, "domain");
    if (!evline_int(e, "dc", &dc)) return;
    evline_int(e, "media", &media);
    evline_int(e, "cool", &cool);
    if (cool < 0) cool = 0;
    if (!dom) dom = "";
    struct helper_state *st = &h->st;
    struct helper_health *p = NULL;
    for (size_t i = 0; i < st->health_n && !p; i++)
        if (st->health[i].dc == dc && st->health[i].media == !!media &&
            !strcmp(st->health[i].domain, dom))
            p = &st->health[i];
    if (!p && st->health_n < HELPER_HEALTH_MAX) p = &st->health[st->health_n++];
    if (!p) {
        p = &st->health[0];
        for (size_t i = 1; i < st->health_n; i++)
            if (st->health[i].at < p->at) p = &st->health[i];
    }
    long now = (long)time(NULL);
    p->dc = (int)dc;
    p->media = !!media;
    snprintf(p->domain, sizeof(p->domain), "%s", dom);
    p->at = now;
    p->until = now + cool;
    char out[80], dj[160], f[400];
    steerd_json_str(out, sizeof(out), h->name);
    steerd_json_str(dj, sizeof(dj), p->domain);
    snprintf(f, sizeof(f), ",\"out\":%s,\"helper\":\"%s\",\"dc\":%d,\"media\":%s,\"domain\":%s,"
             "\"cool\":%ld", out, h->cmd, p->dc, p->media ? "true" : "false", dj, cool);
    steerd_emit(s->d, "health", f);
}

/* ОТВЕРГНУТЬ МОДУЛЬ (шаг 4 выпуска 1.10, evline.h: hello). Модуль — отдельный бинарник со своим
 * пакетом, и на роутере он легко оказывается другой версии, чем движок: пакеты обновили не
 * все. Формат событий между выпусками не обещан, поэтому чужой версии демон не верит ни в чём —
 * ни в up, ни в устройство, к которому пришлось бы привязывать маршрут. Процесс гасится
 * (SIGTERM), причина остаётся в журнале и в status (last_down, поле rejected) до нового запуска:
 * человек видит не «помощник упал», а «поставьте модуль той же версии». Перезапуск идёт по
 * обычной паузе — обновили пакет, и следующий запуск пройдёт. */
static void mod_reject(struct supd *s, struct helper *h, const char *why) {
    struct helper_state *st = &h->st;
    char reason[200];
    snprintf(reason, sizeof(reason), "модуль %s %s", h->prog, why);
    fprintf(stderr, LOG_SW "%s %s — %s: отвергнут\n", h->cmd, h->name, reason);
    h->rejected = 1;
    st->up = 0;
    st->known = 1;
    st->said_down = 1;
    st->since = (long)time(NULL);
    snprintf(st->why, sizeof(st->why), "%s", reason);
    emit_state(s, h, "helper-down", st->why);
    wake_watch(s, h);
    if (h->pid > 0) kill(h->pid, SIGTERM);
}

/* Первое сообщение модуля обязано быть hello с версией движка. */
static void mod_hello(struct supd *s, struct helper *h, const struct evline *e) {
    const char *ver = evline_str(e, "ver");
    if (!ver) {
        mod_reject(s, h, "прислал hello без версии");
        return;
    }
    /* Версия, которой модуль представился, запоминается и у отвергнутого: по ней человек видит в
     * helper, какой модуль стоит, а не только «отвергнут» (docs/ctl.md, module_ver). */
    snprintf(h->mver, sizeof(h->mver), "%s", ver);
    if (strcmp(ver, steer_engine_version()) != 0) {
        char why[160];
        snprintf(why, sizeof(why), "версии %.16s, а ядро %.16s — обновите пакеты steer вместе",
                 ver, steer_engine_version());
        mod_reject(s, h, why);
        return;
    }
    h->hello = 1;
}

/* awg (модуль steer-warpbox, evline.h): файл члена группы `kind: warp` переписан — перенастроить его
 * устройство сейчас, тем же awg_revive, что зовёт сторож, а не ждать прохода; fresh 1 — живой туннель
 * пересел на более быструю точку, и сессия нужна новая (awg_refresh). Только член группы этого
 * помощника (warp_of): чужим выходом помощник распоряжаться не вправе. */
static void ev_awg(struct supd *s, struct helper *h, const struct evline *e) {
    const char *name = evline_str(e, "out");
    if (!name || !s->d->have) return;
    const struct output *o = out_by_name(s->d->sp, name);
    if (!o || strcmp(o->warp_of, h->name) != 0) {
        fprintf(stderr, LOG_SW "%s %s просит перенастроить %s — это не член его группы\n", h->cmd, h->name, name);
        return;
    }
    long fresh = 0;
    if (evline_int(e, "fresh", &fresh) && fresh == 1) awg_refresh(s->d->sp, o);
    else awg_revive(s->d->sp, o, o->device, NULL, 0);
    if (s->d->watch) watchd_helper_changed(s->d->watch);
}

/* member (модуль steer-warpbox, evline.h): приговор члену его группы — ok 0 (мёртв: трафик группы
 * уходит с него сразу), 1 (жив) или -1 (не знаю: решает сторож по своим признакам). Только член
 * группы этого помощника. Смена приговора будит сторожа: проход уводит группу с мёртвого члена, не
 * дожидаясь, пока рукопожатие устареет (у awg это до трёх минут). */
static void ev_member(struct supd *s, struct helper *h, const struct evline *e) {
    const char *name = evline_str(e, "out");
    long v;
    if (!name || !evline_int(e, "ok", &v) || v < -1 || v > 1 || !s->d->have) return;
    const struct output *o = out_by_name(s->d->sp, name);
    if (!o || strcmp(o->warp_of, h->name) != 0) return;
    struct mverdict *m = NULL;
    for (size_t i = 0; i < s->mv_n; i++)
        if (!strcmp(s->mv[i].out, name)) m = &s->mv[i];
    if (!m) {
        if (v == -1) return;
        if (s->mv_n == s->mv_cap) {
            size_t nc = s->mv_cap ? s->mv_cap * 2 : 8;
            struct mverdict *n = realloc(s->mv, nc * sizeof(*n));
            if (!n) return;
            s->mv = n;
            s->mv_cap = nc;
        }
        m = &s->mv[s->mv_n++];
        snprintf(m->out, sizeof(m->out), "%s", name);
        snprintf(m->grp, sizeof(m->grp), "%s", h->name);
        m->v = -1;
    }
    if (m->v == (signed char)v) return;
    m->v = (signed char)v;
    if (v == 0) fprintf(stderr, "steer[info] supervise: %s %s: член %s не отвечает — увожу группу с него\n",
                        h->cmd, h->name, name);
    if (s->d->watch) watchd_helper_changed(s->d->watch);
}

static void mv_drop_group(struct supd *s, const char *grp) {
    size_t w = 0;
    for (size_t i = 0; i < s->mv_n; i++)
        if (strcmp(s->mv[i].grp, grp) != 0) s->mv[w++] = s->mv[i];
    s->mv_n = w;
}

int supd_member_verdict(const struct steerd *d, const char *out) {
    const struct supd *s = d ? d->sup : NULL;
    for (size_t i = 0; s && out && i < s->mv_n; i++)
        if (!strcmp(s->mv[i].out, out)) return s->mv[i].v;
    return -1;
}

static void ev_dispatch(struct supd *s, struct helper *h, const struct evline *ep) {
    const struct evline e = *ep;
    struct helper_state *st = &h->st;
    long v, t;
    /* Шов стенда (STEER_SUPERVISE_EXE) подменяет модуль заглушкой движка: она про hello не знает. */
    if (h->module && !s->seam) {
        if (h->rejected) return;         /* процесс уже приговорён, его словам не верим */
        if (!h->hello) {
            if (!strcmp(e.ev, "hello")) mod_hello(s, h, &e);
            else mod_reject(s, h, "не назвал версию (первое сообщение — не hello): "
                                  "нужен модуль того же выпуска, что ядро");
            return;
        }
        if (!strcmp(e.ev, "hello")) return;
    }
    if (!strcmp(e.ev, "up")) {
        st->up = 1;
        st->known = 1;
        st->said_down = 0;
        st->watch = evline_int(&e, "watch", &v) && v == 1;
        st->since = (long)time(NULL);
        st->why[0] = '\0';
        const char *dev = evline_str(&e, "dev");
        if (dev) route_up(s, h, dev);
        emit_state(s, h, "helper-up", NULL);
        wake_watch(s, h);
    } else if (!strcmp(e.ev, "down")) {
        const char *why = evline_str(&e, "why");
        st->up = 0;
        st->known = 1;
        st->said_down = 1;
        st->since = (long)time(NULL);
        snprintf(st->why, sizeof(st->why), "%s", why ? why : "");
        emit_state(s, h, "helper-down", st->why);
        wake_watch(s, h);
    } else if (!strcmp(e.ev, "node")) {
        if (!evline_int(&e, "n", &v) || !evline_int(&e, "total", &t)) return;
        st->node = v;
        st->total = t;
        char out[80], f[160];
        steerd_json_str(out, sizeof(out), h->name);
        snprintf(f, sizeof(f), ",\"out\":%s,\"n\":%ld,\"total\":%ld", out, v, t);
        steerd_emit(s->d, "node", f);
    } else if (!strcmp(e.ev, "nonode")) {
        if (evline_int(&e, "node", &v)) st->nonode = v;
        if (evline_int(&e, "total", &t)) st->total = t;
    } else if (!strcmp(e.ev, "excluded")) {
        st->excluded = 1;
        if (evline_int(&e, "total", &t)) st->total = t;
    } else if (!strcmp(e.ev, "health")) {
        ev_health(s, h, &e);
    } else if (!strcmp(e.ev, "awg")) {
        ev_awg(s, h, &e);
    } else if (!strcmp(e.ev, "member")) {
        ev_member(s, h, &e);
    } else if (!strcmp(e.ev, "active")) {
        /* Активные узлы пула: только цифры и запятые — строка ложится в JSON массивом как есть
         * (helper ниже), поэтому чужое в ней отвергается целиком. */
        const char *nodes = evline_str(&e, "nodes");
        if (!nodes || strspn(nodes, "0123456789,") != strlen(nodes) ||
            strlen(nodes) >= sizeof(st->active)) return;
        snprintf(st->active, sizeof(st->active), "%s", nodes);
        st->active_known = 1;
    }
}

static void ev_line(struct supd *s, struct helper *h, const char *line) {
    struct evline e;
    if (evline_parse(line, &e) != 0) return;
    ev_dispatch(s, h, &e);
    evline_free(&e);
}

/* Дочитать трубу помощника. 1 — открыта, 0 — конец (закрыта здесь же). */
static int ev_drain(struct supd *s, struct helper *h) {
    for (;;) {
        size_t room = sizeof(h->evbuf) - 1 - h->evlen;
        ssize_t m = read(h->evfd, h->evbuf + h->evlen, room);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        if (m <= 0) {
            loop_fd_del(s->l, h->evfd);
            close(h->evfd);
            h->evfd = -1;
            h->evlen = 0;
            return 0;
        }
        h->evlen += (size_t)m;
        h->evbuf[h->evlen] = '\0';
        char *p = h->evbuf, *nl;
        while ((nl = memchr(p, '\n', h->evlen - (size_t)(p - h->evbuf)))) {
            *nl = '\0';
            ev_line(s, h, p);
            p = nl + 1;
        }
        size_t rest = h->evlen - (size_t)(p - h->evbuf);
        /* Строка длиннее буфера — не наша (evline пишет короткие): выбросить. */
        if (rest == sizeof(h->evbuf) - 1) rest = 0;
        memmove(h->evbuf, p, rest);
        h->evlen = rest;
    }
}

static void ev_cb(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)events;
    struct supd *s = arg;
    struct helper *h = by_fd(s, fd);
    if (!h) { loop_fd_del(s->l, fd); close(fd); return; }
    ev_drain(s, h);
}

/* ---- резолвер: таблица в трубу ------------------------------------------------------------ */

static void tab_close(struct supd *s) {
    if (s->dn_fd >= 0) {
        if (s->dn_out) loop_fd_del(s->l, s->dn_fd);
        close(s->dn_fd);
    }
    s->dn_fd = -1;
    s->dn_out = 0;
    s->qn = s->qoff = 0;
}

static void tab_out_cb(struct loop *l, int fd, uint32_t events, void *arg);

static void tab_flush(struct supd *s) {
    while (s->qoff < s->qn) {
        ssize_t w = write(s->dn_fd, s->q + s->qoff, s->qn - s->qoff);
        if (w > 0) { s->qoff += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (!s->dn_out && loop_fd_add(s->l, s->dn_fd, EPOLLOUT, tab_out_cb, s) == 0)
                s->dn_out = 1;
            return;
        }
        /* EPIPE — резолвер вышел; его выход придёт через loop_child. */
        tab_close(s);
        return;
    }
    s->qn = s->qoff = 0;
    if (s->dn_out) { loop_fd_del(s->l, s->dn_fd); s->dn_out = 0; }
}

static void tab_out_cb(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)fd; (void)events;
    tab_flush(arg);
}

/* Отпечаток таблицы: сам текст и то, что резолвер прочтёт по путям из неё (устройство, inode,
 * размер и время правки каждого файла списка). Резолвер, получив таблицу, перечитывает списки —
 * поэтому список, обновлённый на месте (put-file кладёт его переименованием: новый inode), тоже
 * повод отдать таблицу, хотя текст её тот же. Поля строки канала — через «|», пути — с шестого
 * (src/dnsd/tabfmt.h). */
static unsigned long long tab_fingerprint(const char *p, size_t n) {
    unsigned long long h = KIND_SIG_INIT;
    kind_sig_mix(&h, p, n);
    const char *end = p + n;
    const char *ln = memchr(p, '\n', n);
    for (ln = ln ? ln + 1 : end; ln < end; ) {
        const char *e = memchr(ln, '\n', (size_t)(end - ln));
        if (!e) e = end;
        int field = 0;
        for (const char *q = ln; q < e; ) {
            const char *bar = memchr(q, '|', (size_t)(e - q));
            const char *fe = bar ? bar : e;
            if (field >= 5 && fe > q) {
                char path[PATH_MAX];
                size_t l = (size_t)(fe - q) < sizeof(path) - 1 ? (size_t)(fe - q) : sizeof(path) - 1;
                memcpy(path, q, l);
                path[l] = '\0';
                struct stat sb;
                long long v[5] = { 0, 0, -1, 0, 0 };
                if (stat(path, &sb) == 0) {
                    v[0] = (long long)sb.st_dev;
                    v[1] = (long long)sb.st_ino;
                    v[2] = (long long)sb.st_size;
                    v[3] = (long long)sb.st_mtim.tv_sec;
                    v[4] = (long long)sb.st_mtim.tv_nsec;
                }
                kind_sig_mix(&h, v, sizeof(v));
            }
            field++;
            q = bar ? bar + 1 : e;
        }
        ln = e + 1;
    }
    return h;
}

/* Собрать таблицу по спеке в памяти и поставить в трубу. force=0 — только если она (или файлы
 * списков) изменилась с прошлой отдачи; 1 — всегда (резолвер только что запущен). 1 — отдана. */
static int tab_send(struct supd *s, int force) {
    if (s->dn_fd < 0 || !s->d->have) return 0;
    char *p = NULL;
    size_t n = 0;
    FILE *f = open_memstream(&p, &n);
    if (!f) return 0;
    tabfmt_build(s->d->sp, f);
    if (fclose(f) != 0 || !p) { free(p); return 0; }
    unsigned long long fp = tab_fingerprint(p, n);
    if (!force && s->tab_ok && fp == s->tab_fp) { free(p); return 0; }
    if (s->qoff) {
        memmove(s->q, s->q + s->qoff, s->qn - s->qoff);
        s->qn -= s->qoff;
        s->qoff = 0;
    }
    size_t qmax = n > SUPD_TABQ_MIN / SUPD_TABQ_TABS ? n * SUPD_TABQ_TABS : SUPD_TABQ_MIN;
    if (s->qn > 0 && s->qn + n > qmax) {
        fprintf(stderr, LOG_SW "резолвер не забирает таблицу: в очереди %zu байт, ещё %zu, предел %zu — "
                "закрываю трубу\n", s->qn, n, qmax);
        free(p);
        tab_close(s);
        return 0;
    }
    if (s->qn + n > s->qcap) {
        size_t c = s->qcap ? s->qcap : 65536;
        while (c < s->qn + n) c *= 2;
        char *q = realloc(s->q, c);
        if (!q) { free(p); return 0; }
        s->q = q;
        s->qcap = c;
    }
    memcpy(s->q + s->qn, p, n);
    s->qn += n;
    free(p);
    s->tab_fp = fp;
    s->tab_ok = 1;
    tab_flush(s);
    return 1;
}

/* ---- запуск ------------------------------------------------------------------------------- */

/* В ребёнке до exec: конец трубы — дескриптором 3, без O_CLOEXEC. Номер один и тот же у каждого
 * запуска, а не случайный номер демона: помощник на shell (стенды, отладка) перенаправляет только
 * однозначные дескрипторы, и «STEER_EVENT_FD=3» в окружении процесса читается глазами. Что было на
 * 3 у демона, помечено O_CLOEXEC (все его дескрипторы) и закрылось бы при exec всё равно. */
static void child_fd3(int fd) {
    if (fd == 3) fcntl(3, F_SETFD, 0);
    else if (dup2(fd, 3) == 3) close(fd);
}

/* В ребёнке-помощнике до exec: признак смерти родителя и метка «чей я» (шапка, «Помощники демона
 * не переживают»). getppid() — сразу ПОСЛЕ prctl: демон, умерший между fork и prctl, сигнала уже
 * не пришлёт, и ребёнок остался бы тем самым сиротой. Выход с кодом 0: пожинать его некому, а
 * запускать помощника без демона — незачем. */
static void child_arm(struct supd *s) {
    prctl(PR_SET_PDEATHSIG, SIGTERM);
    if (getppid() != s->me) _exit(0);
    putenv(s->tag);
}

/* ---- помощники, пережившие прежний демон --------------------------------------------------- */

/* Время старта процесса (поле 22 /proc/<pid>/stat, тики от загрузки). 0 — процесса
 * нет или он зомби: вышел и ждёт только, пока его приберут, — для нас это «вышел». Пара «pid и
 * время старта» и есть имя процесса: pid, занятый заново, даст другое время. */
static unsigned long long proc_start(pid_t pid) {
    char path[64], b[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    ssize_t n = read(fd, b, sizeof(b) - 1);
    close(fd);
    if (n <= 0) return 0;
    b[n] = '\0';
    /* Имя процесса в скобках может содержать и пробелы, и скобки: поля считаются от последней. */
    char *p = strrchr(b, ')');
    if (!p || p[1] != ' ') return 0;
    p += 2;
    char st = 0;
    if (sscanf(p, "%c", &st) != 1 || st == 'Z' || st == 'X') return 0;
    for (int f = 3; f < 22; f++) {
        p = strchr(p, ' ');
        if (!p) return 0;
        p++;
    }
    unsigned long long t = strtoull(p, NULL, 10);
    return t ? t : 1;
}

/* Файл /proc/<pid>/<what> целиком (environ, cmdline — строки через NUL) до n-1 байт; длина. */
static size_t proc_read(pid_t pid, const char *what, char **out) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/%s", (int)pid, what);
    *out = NULL;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;
    /* Окружение с плагинами бывает любым по размеру: читаем, пока не кончится. */
    char *b = NULL;
    size_t got = 0, cap = 0;
    for (;;) {
        if (got + 4097 > cap) {
            size_t nc = cap ? cap * 2 : 8192;
            char *nb = realloc(b, nc);
            if (!nb) { free(b); close(fd); return 0; }
            b = nb;
            cap = nc;
        }
        ssize_t m = read(fd, b + got, cap - 1 - got);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        got += (size_t)m;
    }
    close(fd);
    b[got] = '\0';
    *out = b;
    return got;
}

/* Значение KEY в блоке строк через NUL (environ); NULL — нет. */
static const char *nul_env(const char *b, size_t n, const char *key) {
    size_t kl = strlen(key);
    for (size_t i = 0; i < n;) {
        const char *e = b + i;
        size_t l = strnlen(e, n - i);
        if (l > kl && !memcmp(e, key, kl) && e[kl] == '=') return e + kl + 1;
        i += l + 1;
    }
    return NULL;
}

/* Помощник ли pid демона этого каталога состояния, оставшийся без демона (шапка, признак 3). В
 * what — «команда выход» из командной строки, для журнала. */
static int orphan_check(pid_t pid, char *what, size_t wn, char **envp, char **clp);
static int orphan_of(pid_t pid, char *what, size_t wn) {
    char *env = NULL, *cl = NULL;
    int rc = orphan_check(pid, what, wn, &env, &cl);
    free(env);
    free(cl);
    return rc;
}

static int orphan_check(pid_t pid, char *what, size_t wn, char **envp, char **clp) {
    if (!proc_start(pid)) return 0;
    size_t n = proc_read(pid, "environ", envp);
    char *env = *envp;
    if (!n || !nul_env(env, n, "STEER_EVENT_FD")) return 0;
    size_t cn = proc_read(pid, "cmdline", clp);
    char *cl = *clp ? *clp : (char *)"";
    const char *tag = nul_env(env, n, "STEER_SUPD");
    if (!tag) return 0;
    char *end = NULL;
    long dp = strtol(tag, &end, 10);
    if (end == tag || *end != ':' || dp <= 0) return 0;
    const char *t = end + 1;
    unsigned long long st = strtoull(t, &end, 10);
    if (end == t || *end != ':') return 0;
    if (strcmp(end + 1, steer_state_dir()) != 0) return 0;
    if (proc_start((pid_t)dp) == st) return 0;                   /* его демон жив */
    /* argv[1] и argv[2] — «vless vr», «obfs a»; у помощника-программы — её имя и первый флаг. */
    const char *a1 = cn ? cl + strnlen(cl, cn) + 1 : cl;
    const char *a2 = a1 < cl + cn ? a1 + strlen(a1) + 1 : a1;
    if (a1 >= cl + cn) a1 = "";
    if (a2 >= cl + cn) a2 = "";
    snprintf(what, wn, "%s%s%s", a1, *a2 ? " " : "", a2);
    return 1;
}

/* Сирот прежнего демона — сколько нашлось: массивы pid и времён старта растут (раньше — 32 места,
 * и при большем числе туннелей часть сирот оставалась жить и держала устройства). */

/* Погасить помощников прежнего демона этого каталога состояния (шапка, признак 3): SIGTERM всем
 * сразу, три секунды на выход — столько же, сколько helpers_stop даёт своим, — дальше SIGKILL и
 * секунда. Ждёт выхода: устройство TUN и порт освобождаются с выходом процесса, а запустить
 * своего раньше — значит получить тот самый Resource busy. Не свои дети, поэтому выход узнаётся
 * по /proc (proc_start), а не waitpid, и по той же паре «pid и время старта» SIGKILL не уйдёт
 * процессу, занявшему pid заново. who — начало строки журнала. Возврат — сколько найдено. */
static int orphans_stop(const char *who) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    pid_t *pid = NULL;
    unsigned long long *st = NULL;
    size_t n = 0, cap = 0;
    pid_t me = getpid();
    struct dirent *e;
    while ((e = readdir(d))) {
        char *end = NULL;
        long p = strtol(e->d_name, &end, 10);
        if (!end || *end || p <= 1 || p == me) continue;
        char what[128];
        if (!orphan_of((pid_t)p, what, sizeof(what))) continue;
        unsigned long long started = proc_start((pid_t)p);
        if (!started) continue;
        if (n == cap) {
            size_t nc = cap ? cap * 2 : 16;
            pid_t *np = realloc(pid, nc * sizeof(*np));
            unsigned long long *ns = realloc(st, nc * sizeof(*ns));
            if (np) pid = np;
            if (ns) st = ns;
            if (!np || !ns) break;
            cap = nc;
        }
        st[n] = started;
        pid[n++] = (pid_t)p;
        kill((pid_t)p, SIGTERM);
        fprintf(stderr, "steer[info] %s: помощник прежнего демона (pid %ld, %s) остался без него — "
                        "гашу\n", who, p, what);
    }
    closedir(d);
    long due = helpers_now_ms() + 3000;
    int hard = 0;
    for (;;) {
        size_t left = 0;
        for (size_t i = 0; i < n; i++) {
            if (!pid[i]) continue;
            if (proc_start(pid[i]) != st[i]) pid[i] = 0;
            else left++;
        }
        if (!left) break;
        if (helpers_now_ms() >= due) {
            if (hard) break;
            for (size_t i = 0; i < n; i++)
                if (pid[i]) {
                    kill(pid[i], SIGKILL);
                    fprintf(stderr, "steer[warn] %s: помощник прежнего демона (pid %d) не вышел "
                                    "по SIGTERM за 3 с — SIGKILL\n", who, (int)pid[i]);
                }
            hard = 1;
            due = helpers_now_ms() + 1000;
        }
        struct timespec ts = { 0, 50000000L };
        nanosleep(&ts, NULL);
    }
    free(pid);
    free(st);
    return (int)n;
}

/* ---- резолвер, переживший прежний демон (src/dnsd/adopt.c) --------------------------------- */

static void child_cb(struct loop *l, pid_t pid, int status, void *arg);

/* Подключиться к живому резолверу этого каталога состояния: дескриптор соединения, *pid — его
 * pid (SO_PEERCRED); -1 — живого нет (сокета нет, никто не слушает) или собеседник не root. */
static int dnsd_connect(pid_t *pid) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if ((size_t)snprintf(a.sun_path, sizeof(a.sun_path), "%s/" DNSD_CTL_SOCK, steer_state_dir()) >=
            sizeof(a.sun_path))
        return -1;
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct ucred uc;
    socklen_t l = sizeof(uc);
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) != 0 ||
        getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0 ||
        (uc.uid != 0 && uc.uid != geteuid()) || uc.pid <= 0) {
        close(fd);
        return -1;
    }
    *pid = uc.pid;
    return fd;
}

/* Ждать закрытия соединения резолвером (его выхода) до ms. 1 — закрыл. */
static int dnsd_gone(int fd, long ms) {
    long end = helpers_now_ms() + ms;
    for (;;) {
        long left = end - helpers_now_ms();
        if (left <= 0) return 0;
        struct pollfd p = { fd, POLLIN, 0 };
        int r = poll(&p, 1, (int)left);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) return 0;
        char b[64];
        ssize_t m = recv(fd, b, sizeof(b), MSG_DONTWAIT);
        if (m == 0 || (m < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) return 1;
    }
}

/* Погасить не своего резолвера: SIGTERM, три секунды на выход, дальше SIGKILL. Закрывает fd. */
static void dnsd_kill(int fd, pid_t pid) {
    kill(pid, SIGTERM);
    if (!dnsd_gone(fd, 3000)) {
        kill(pid, SIGKILL);
        dnsd_gone(fd, 1000);
    }
    close(fd);
}

/* Попросить резолвер этого каталога состояния выйти, если хозяина у него нет (просьба «down»,
 * src/dnsd/adopt.c): решает сам резолвер, потому что только он знает, открыта ли его труба
 * таблицы. «ok» — ждать его выхода (закрытие соединения), по сроку SIGKILL; «busy» — хозяин жив,
 * не трогать. Ответа нет — резолвер не отвечает: гасить сигналом. 1 — погашен, pid в *pid; 0 —
 * резолвера нет или у него живой хозяин. */
static int dnsd_down(pid_t *pid) {
    int fd = dnsd_connect(pid);
    if (fd < 0) return 0;
    if (send(fd, "down\n", 5, MSG_NOSIGNAL) != 5) {
        dnsd_kill(fd, *pid);
        return 1;
    }
    char b[16];
    ssize_t m = -1;
    struct pollfd p = { fd, POLLIN, 0 };
    int r;
    while ((r = poll(&p, 1, 2000)) < 0 && errno == EINTR) {}
    if (r > 0) m = recv(fd, b, sizeof(b), MSG_DONTWAIT);
    if (m >= 5 && !memcmp(b, "busy\n", 5)) {
        close(fd);
        return 0;
    }
    if (m >= 3 && !memcmp(b, "ok\n", 3)) {
        if (!dnsd_gone(fd, 3000)) {
            kill(*pid, SIGKILL);
            dnsd_gone(fd, 1000);
        }
        close(fd);
        return 1;
    }
    dnsd_kill(fd, *pid);
    return 1;
}

/* Резолвер не нужен (спеки нет, движок выключен), а прежний демон оставил живой — погасить, а не
 * ждать, пока он выйдет по сроку сам: заворот DNS к нему этот демон уже не сопровождает. */
static void orphan_stop(void) {
    pid_t pid;
    if (!dnsd_down(&pid)) return;
    fprintf(stderr, "steer[info] supervise: резолвер прежнего демона (pid %d) погашен — "
                    "резолвер не нужен\n", (int)pid);
}

int supd_orphan_down(void) {
    /* Помощники упавшего демона — тоже (шапка, признак 3): сами они по PDEATHSIG уже гаснут, а
     * этот проход дожидается их выхода и добивает не вышедших. Помощников живого демона не
     * трогает: их демон с той же меткой жив. */
    orphans_stop("down");
    pid_t pid;
    if (!dnsd_down(&pid)) return 0;
    fprintf(stderr, "steer[info] down: резолвер, оставшийся без демона (pid %d), погашен\n",
            (int)pid);
    return 1;
}

/* Сразу после загрузки набора правил — попросить резолвер вернуть элементы real-ip (просьба
 * «reassert», src/dnsd/adopt.c; зачем — у ruleset_load в apply.c). Зовёт загрузчик — ребёнок
 * демона apply-commit или подкоманда `steer apply`, — а не демон: демон узнаёт о загрузке только
 * по выходу ребёнка, а ребёнок после nft -f ещё ставит метки «пущен напрямую», карту balance и
 * проверки (сотни миллисекунд), и всё это время адреса real-ip шли бы без метки.
 *
 * Ответ ждётся недолго (500 мс): резолвер отвечает из своего цикла, и если он в этот миг
 * перечитывает списки, просьба дождётся очереди и без нас — загрузчику незачем стоять. 1 —
 * резолвер ответил; 0 — резолвера нет (сокета нет: без демона и без пережившего его резолвера)
 * или ответ не пришёл вовремя: тогда элементы вернёт таблица от демона. */
static int dnsd_ask(const char *req, int ms) {
    pid_t pid;
    int fd = dnsd_connect(&pid);
    if (fd < 0) return 0;
    size_t l = strlen(req);
    if (send(fd, req, l, MSG_NOSIGNAL) != (ssize_t)l) {
        close(fd);
        return 0;
    }
    char b[16];
    ssize_t m = -1;
    struct pollfd p = { fd, POLLIN, 0 };
    int r;
    while ((r = poll(&p, 1, ms)) < 0 && errno == EINTR) {}
    if (r > 0) m = recv(fd, b, sizeof(b), MSG_DONTWAIT);
    close(fd);
    return m >= 3 && !memcmp(b, "ok\n", 3);
}

int supd_dnsd_reassert(void) {
    return dnsd_ask("reassert\n", 500);
}

/* Прямо перед засевом карты и наборов fake-IP — попросить резолвер записать файл состояния
 * (просьба «flush», src/dnsd/adopt.c; зачем — у fakeip_state_flush в src/dnsd/fakeip.c). Зовёт
 * тот же загрузчик, что и reassert. Ответ «ok» приходит после записи, и ждётся дольше (1 с):
 * засев из отставшего файла — это новые имена без подмены и прежние адреса в новой таблице, а
 * запись на tmpfs — доли миллисекунды, так что долго ждать приходится, только если резолвер занят
 * (перечитывает списки). Не дождались — засев из того, что лежит: расхождение карты с памятью
 * исправит проход резолвера после таблицы (nft_map_ensure_element), новые имена — он же. Возврат —
 * как у supd_dnsd_reassert. */
int supd_dnsd_flush(void) {
    return dnsd_ask("flush\n", 1000);
}

static void dn_conn_close(struct supd *s) {
    if (s->dn_conn < 0) return;
    loop_fd_del(s->l, s->dn_conn);
    close(s->dn_conn);
    s->dn_conn = -1;
}

static int dnsd_spawn(struct supd *s, struct helper *h);

/* Забор не удался или резолвер погашен: поднять свой ребёнок вместо него. Зовётся из событий цикла,
 * поэтому за start_one докладывает сам — loop_child и повторный подъём по паузе. */
static void ad_spawn_own(struct supd *s) {
    pid_t old = s->ad_pid;
    s->ad_ph = 0;
    loop_timer_stop(s->ad_tm);
    dn_conn_close(s);
    if (s->ad_p1 >= 0) { close(s->ad_p1); s->ad_p1 = -1; }
    if (s->stopping) return;
    for (size_t i = 0; i < s->set.n; i++) {
        struct helper *h = &s->set.h[i];
        if (!h->table || h->pid != old) continue;
        h->pid = 0;
        if (dnsd_spawn(s, h) == 0) loop_child(s->l, h->pid, child_cb, s);
        break;
    }
    supd_kick(s);
}

/* Погасить резолвер, не ответивший на «adopt»: SIGTERM, три секунды на выход, дальше SIGKILL и ещё
 * секунда. Выход — закрытие соединения (ad_conn_cb) или срок (ad_timer). */
static void ad_kill_begin(struct supd *s) {
    fprintf(stderr, LOG_SW "резолвер прежнего демона (pid %d) не отдался — гашу\n", (int)s->ad_pid);
    kill(s->ad_pid, SIGTERM);
    s->ad_ph = 2;
    loop_timer_set(s->ad_tm, 3000);
}

static void ad_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct supd *s = arg;
    if (s->ad_ph == 1) { ad_kill_begin(s); return; }
    if (s->ad_ph == 2) {
        kill(s->ad_pid, SIGKILL);
        s->ad_ph = 3;
        loop_timer_set(s->ad_tm, 1000);
        return;
    }
    if (s->ad_ph == 3) ad_spawn_own(s);
}

/* Соединение с резолвером читаемо в ходе забора: ответ на «adopt» или его закрытие. */
static void ad_conn_cb(struct supd *s) {
    char b[64];
    ssize_t m = recv(s->dn_conn, b, sizeof(b), MSG_DONTWAIT);
    if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    if (m <= 0) {                         /* закрыл: ответа не будет (прежняя версия) или он вышел */
        if (s->ad_ph == 1) kill(s->ad_pid, SIGTERM);
        ad_spawn_own(s);
        return;
    }
    if (s->ad_ph != 1) return;            /* гасим: ждём закрытия, лишнее не нужно */
    size_t take = (size_t)m < sizeof(s->ad_ans) - 1 - s->ad_an ? (size_t)m : sizeof(s->ad_ans) - 1 - s->ad_an;
    memcpy(s->ad_ans + s->ad_an, b, take);
    s->ad_an += take;
    s->ad_ans[s->ad_an] = '\0';
    if (!memchr(s->ad_ans, '\n', s->ad_an) && s->ad_an < sizeof(s->ad_ans) - 1) return;
    if (!strcmp(s->ad_ans, "ok\n")) {
        fcntl(s->ad_p1, F_SETFL, fcntl(s->ad_p1, F_GETFL) | O_NONBLOCK);
        tab_close(s);
        s->dn_fd = s->ad_p1;
        s->ad_p1 = -1;
        s->ad_ph = 0;
        loop_timer_stop(s->ad_tm);
        fprintf(stderr, "steer[info] supervise: dnsd подхвачен (pid %d) — резолвер пережил прежний "
                        "демон\n", (int)s->ad_pid);
        tab_send(s, 1);
        return;
    }
    if (!strcmp(s->ad_ans, "busy\n")) {
        /* Труба у резолвера открыта — у него живой хозяин, второй демон на том же каталоге
         * состояния. Не наш случай, и гасить чужой резолвер этот демон не берётся. */
        fprintf(stderr, LOG_SW "у резолвера (pid %d) живой демон — поднимаю свой\n", (int)s->ad_pid);
        ad_spawn_own(s);
        return;
    }
    ad_kill_begin(s);
}

/* Соединение с резолвером стало читаемым. После забора он ничего не пишет после «ok», так что это
 * его выход — то же, что loop_child у своего ребёнка (код выхода неизвестен: не наш ребёнок). */
static void dn_conn_cb(struct loop *l, int fd, uint32_t events, void *arg) {
    (void)l; (void)events;
    struct supd *s = arg;
    if (s->ad_ph) { ad_conn_cb(s); return; }
    char b[64];
    ssize_t m = recv(fd, b, sizeof(b), MSG_DONTWAIT);
    if (m > 0 || (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR))) return;
    dn_conn_close(s);
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].table && s->set.h[i].pid) {
            child_cb(s->l, s->set.h[i].pid, 0, s);
            break;
        }
}

/* Забрать резолвер, переживший прежний демон: отдать ему новую трубу таблицы (конец чтения) и
 * свой stderr через SCM_RIGHTS. Ответ «ok» ждёт цикл (ad_conn_cb, срок — ad_timer), а не эта
 * функция: резолвер, занятый перечитыванием списков, отвечает не сразу, и демон на это время не
 * замирал бы. 1 — забор начат, резолвер считается принадлежащим помощнику (h->pid), и если не
 * отдастся — цикл сам поднимет свой (ad_spawn_own); 0 — живого нет, запускать надо свой. */
static int adopt_dnsd(struct supd *s, struct helper *h) {
    pid_t pid;
    if (s->ad_ph) return 1;               /* забор уже идёт */
    int c = dnsd_connect(&pid);
    if (c < 0) return 0;
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) { dnsd_kill(c, pid); return 0; }
    int fds[2] = { p[0], 2 };
    size_t nfd = fcntl(2, F_GETFD) >= 0 ? 2 : 1;     /* stderr закрыт — отдать одну трубу */
    union { struct cmsghdr h; char b[CMSG_SPACE(sizeof(fds))]; } cm;
    memset(&cm, 0, sizeof(cm));
    char req[] = "adopt\n";
    struct iovec iov = { req, 6 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cm.b;
    mh.msg_controllen = CMSG_SPACE(nfd * sizeof(int));
    struct cmsghdr *ch = CMSG_FIRSTHDR(&mh);
    ch->cmsg_level = SOL_SOCKET;
    ch->cmsg_type = SCM_RIGHTS;
    ch->cmsg_len = CMSG_LEN(nfd * sizeof(int));
    memcpy(CMSG_DATA(ch), fds, nfd * sizeof(int));
    ssize_t w = sendmsg(c, &mh, MSG_NOSIGNAL);
    close(p[0]);
    if (w != 6 || !s->ad_tm) {
        fprintf(stderr, LOG_SW "резолвер прежнего демона (pid %d) не отдался — гашу\n", (int)pid);
        close(p[1]);
        dnsd_kill(c, pid);
        return 0;
    }
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
    tab_close(s);
    dn_conn_close(s);
    s->dn_conn = c;
    if (loop_fd_add(s->l, c, EPOLLIN, dn_conn_cb, s) != 0) {
        /* Без соединения в цикле ответа не узнать: погасить и поднять свой. */
        s->dn_conn = -1;
        close(p[1]);
        dnsd_kill(c, pid);
        return 0;
    }
    s->ad_ph = 1;
    s->ad_p1 = p[1];
    s->ad_an = 0;
    s->ad_ans[0] = '\0';
    s->ad_pid = pid;
    loop_timer_set(s->ad_tm, 2000);
    h->pid = pid;
    h->started_ms = helpers_now_ms();
    return 1;
}

/* 0 — запущен свой ребёнок, 1 — забран живой (loop_child ему не нужен), -1 — не вышло. */
static int dnsd_spawn(struct supd *s, struct helper *h) {
    int p[2];
    if (pipe2(p, O_CLOEXEC) != 0) return -1;
    const char **av = malloc((8 + s->dnsd_flag_n) * sizeof(*av));
    if (!av) { close(p[0]); close(p[1]); return -1; }
    size_t n = 0;
    av[n++] = s->self;
    av[n++] = "dnsd";
    av[n++] = "--table-fd";
    av[n++] = "3";
    if (strcmp(steer_state_dir(), plat()->state_dir) != 0) {
        av[n++] = "--state-dir";
        av[n++] = steer_state_dir();
    }
    for (size_t i = 0; s->dnsd_flags[i]; i++) av[n++] = s->dnsd_flags[i];
    av[n] = NULL;
    char a0[PATH_MAX + 8];
    av[0] = helper_argv0(s->self, a0, sizeof(a0));
    pid_t pid = fork();
    if (pid < 0) { free(av); close(p[0]); close(p[1]); return -1; }
    if (pid == 0) {
        loop_child_reset();
        child_fd3(p[0]);
        execv(s->self, (char *const *)av);
        _exit(127);
    }
    free(av);
    close(p[0]);
    fcntl(p[1], F_SETFL, fcntl(p[1], F_GETFL) | O_NONBLOCK);
    tab_close(s);
    s->dn_fd = p[1];
    helper_started(h, pid);
    tab_send(s, 1);
    return 0;
}

static int start_dnsd(struct supd *s, struct helper *h) {
    if (adopt_dnsd(s, h)) return 1;
    return dnsd_spawn(s, h);
}

static void child_cb(struct loop *l, pid_t pid, int status, void *arg);

static int start_one(struct helper *h, void *arg) {
    struct supd *s = arg;
    if (s->enabled && !s->enabled()) return -1;
    if (h->table) {
        int rc = start_dnsd(s, h);
        if (rc < 0) return -1;
        if (rc == 1) return 0;          /* забран живой: о его выходе скажет dn_conn */
    } else {
        /* Бинарника модуля нет (пакет не поставлен или удалён): не запускать вслепую, а сказать
         * прямо — один раз в журнал, дальше в status (last_down), — и повторять по обычной паузе:
         * поставят пакет, следующая попытка запустит. */
        if (h->module && !s->seam) {
            char mp[PATH_MAX + 64];
            if (steer_module_path(h->prog, mp, sizeof(mp)) != 0) {
                snprintf(h->st.why, sizeof(h->st.why), "нужен пакет %s", h->prog);
                h->st.known = 1;
                h->st.said_down = 1;
                if (!h->nomod_logged) {
                    /* steer-extended ставит остальные модули, но не hysteria2 и не proxy: у них свои пакеты. */
                    int in_ext = strcmp(h->prog, "steer-hysteria2") != 0 && strcmp(h->prog, "steer-proxy") != 0;
                    fprintf(stderr, LOG_SW "%s %s — модуля нет: нужен пакет %s%s\n", h->cmd, h->name,
                            h->prog, in_ext ? " (входит в steer-extended)" : "");
                    h->nomod_logged = 1;
                }
                return -1;
            }
            h->nomod_logged = 0;
        }
        h->hello = h->rejected = 0;
        h->mver[0] = '\0';
        int p[2];
        if (pipe2(p, O_CLOEXEC) != 0) return -1;
        char prog[PATH_MAX + 32];
        const char **av = helper_argv(h, s->exe, s->self, s->seam, s->d->spec_path, prog, sizeof(prog));
        if (!av) { close(p[0]); close(p[1]); return -1; }
        const char *path = av[0];
        char a0[PATH_MAX + 8];
        av[0] = helper_argv0(path, a0, sizeof(a0));
        pid_t pid = fork();
        if (pid < 0) { free(av); close(p[0]); close(p[1]); return -1; }
        if (pid == 0) {
            loop_child_reset();
            child_arm(s);
            child_fd3(p[1]);
            putenv("STEER_EVENT_FD=3");
            helper_putenv(h);
            execv(path, (char *const *)av);
            _exit(127);
        }
        free(av);
        close(p[1]);
        fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
        h->evfd = p[0];
        h->evlen = 0;
        if (loop_fd_add(s->l, h->evfd, EPOLLIN, ev_cb, s) != 0) { close(h->evfd); h->evfd = -1; }
        if (h->st.started) h->st.restarts++;
        h->st.running = 1;
        h->st.up = h->st.known = h->st.said_down = h->st.watch = 0;
        h->st.bound[0] = '\0';
        h->st.node = h->st.total = h->st.nonode = h->st.excluded = 0;
        h->st.health_n = 0;
        h->st.active[0] = '\0';
        h->st.active_known = 0;
        h->st.started = (long)time(NULL);
        helper_started(h, pid);
    }
    loop_child(s->l, h->pid, child_cb, s);
    return 0;
}

static void supd_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    supd_kick(arg);
}

static void supd_kick(struct supd *s) {
    if (s->stopping) return;
    long wait = helpers_due(&s->set, start_one, s);
    if (wait < 0) loop_timer_stop(s->tm);
    else loop_timer_set(s->tm, wait);
}

static void child_cb(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l;
    struct supd *s = arg;
    if (s->stopping) return;
    for (size_t i = 0; i < s->set.n; i++) {
        struct helper *h = &s->set.h[i];
        if (h->pid != pid) continue;
        if (h->table) { tab_close(s); dn_conn_close(s); break; }
        /* Что помощник успел написать перед выходом, — раньше, чем вывод о его выходе. */
        if (h->evfd >= 0) ev_drain(s, h);
        if (h->evfd >= 0) { loop_fd_del(s->l, h->evfd); close(h->evfd); h->evfd = -1; }
        int was_up = h->st.up;
        /* Приговоры членам от этого процесса больше не правда (ev_member). */
        if (h->name[0]) mv_drop_group(s, h->name);
        /* Слушатель TCP модуля ушёл вместе с процессом (R-152): перенаправление к нему — снять. */
        if (h->st.bound[0]) tcp_redir_dev_gone(h->st.bound);
        h->st.running = 0;
        h->st.up = 0;
        /* down клиента, следившего за узлом, говорил об узлах этого процесса (пул узлов,
         * tunnel/pool.c, «слежка»). Новый процесс выберет узел заново, и
         * «ни один узел не ответил» (probe_of) до его подъёма было бы неправдой. */
        if (h->st.watch) h->st.said_down = 0;
        h->st.watch = 0;
        /* Погашен нами — причина наша, а не код выхода, который это «вышел по SIGTERM». */
        if (h->rejected) {
            /* причина уже записана приговором модулю (mod_reject), а не «убит SIGTERM» */
        } else if (h->gone)
            snprintf(h->st.why, sizeof(h->st.why), "выход убран из спеки");
        else if (h->restart && h->revive)
            snprintf(h->st.why, sizeof(h->st.why), "перезапуск: выход не отвечает");
        else if (h->restart)
            snprintf(h->st.why, sizeof(h->st.why), "перезапуск: параметры выхода изменились");
        else if (WIFEXITED(status))
            snprintf(h->st.why, sizeof(h->st.why), "процесс вышел (код %d)", WEXITSTATUS(status));
        else
            snprintf(h->st.why, sizeof(h->st.why), "процесс убит (сигнал %d)", WTERMSIG(status));
        if (was_up) {
            h->st.since = (long)time(NULL);
            emit_state(s, h, "helper-down", h->st.why);
            wake_watch(s, h);
        }
        break;
    }
    helpers_exited(&s->set, pid, status);
    helpers_compact(&s->set);
    supd_kick(s);
}

/* Поднимать ли резолвер — ответ needs-dnsd (там же доводы, почему «всегда»); по нему же решает
 * супервизор демона. Здесь, а не в main.c: стенды компонуют модули демона без main.c. В
 * мини-сборке — «поднимать нечего», и это тот же ответ, что даёт генератор правил: он там
 * перенаправления DNS не ставит. Два ответа обязаны совпадать, иначе init-скрипт однажды поднимет
 * резолвер без правила или, хуже, правило останется без резолвера. */
int dnsd_wanted(void) {
    return !prof()->no_resolver;
}

/* ---- состав -------------------------------------------------------------------------------- */

static size_t supd_plan(struct supd *s) {
    size_t n = 0;
    /* Прежний план отдан сверке и больше не нужен: его строки — свои у каждой записи. */
    helpers_launch_free(s->fresh, s->fresh_n);
    s->fresh_n = 0;
    if (!s->d->have || (s->enabled && !s->enabled())) return 0;
    /* Помощников не больше выходов спеки + резолвер. */
    size_t need = s->d->sp->out_n + 1;
    if (need > s->fresh_cap) {
        struct helper *nf = realloc(s->fresh, need * sizeof(*nf));
        if (!nf) return 0;
        s->fresh = nf;
        s->fresh_cap = need;
    }
    n = helpers_plan(s->d->sp, s->fresh, s->fresh_cap - 1, NULL);
    if (dnsd_wanted()) {
        struct helper *h = &s->fresh[n++];
        memset(h, 0, sizeof(*h));
        if (helper_set_cmd(h, "dnsd") != 0) { n--; return s->fresh_n = n; }
        h->table = 1;
        h->sig = KIND_SIG_INIT;
        h->delay_ms = HELPERS_DELAY_MS;
        h->evfd = -1;
    }
    return s->fresh_n = n;
}

struct supd *supd_start(struct steerd *d, const struct supd_conf *c) {
    struct supd *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->d = d;
    s->l = d->loop;
    s->enabled = c->enabled;
    s->dn_fd = -1;
    s->dn_conn = -1;
    s->ad_p1 = -1;
    size_t nfl = 0;
    while (c->dnsd_flags && c->dnsd_flags[nfl]) nfl++;
    s->dnsd_flags = calloc(nfl + 1, sizeof(*s->dnsd_flags));
    if (!s->dnsd_flags) { free(s); return NULL; }
    for (size_t i = 0; i < nfl; i++) s->dnsd_flags[i] = c->dnsd_flags[i];
    s->dnsd_flag_n = nfl;
    ssize_t el = readlink("/proc/self/exe", s->self, sizeof(s->self) - 1);
    if (el <= 0) { free(s); return NULL; }
    s->self[el] = '\0';
    /* Шов стенда — тот же, что у `steer supervise`: помощником становится программа стенда. */
    const char *seam = getenv("STEER_SUPERVISE_EXE");
    s->seam = seam && *seam;
    snprintf(s->exe, sizeof(s->exe), "%s", s->seam ? seam : s->self);
    s->tm = loop_timer_new(s->l, supd_timer, s);
    s->ad_tm = loop_timer_new(s->l, ad_timer, s);
    if (!s->tm || !s->ad_tm) { free(s); return NULL; }
    s->me = getpid();
    snprintf(s->tag, sizeof(s->tag), "STEER_SUPD=%d:%llu:%s", (int)s->me,
             proc_start(s->me), steer_state_dir());
    /* Раньше первого запуска своих: сирота прежнего демона держит устройство или порт, и свой
     * помощник на них не встал бы (шапка, «Помощники демона не переживают»). */
    orphans_stop("supervise");
    d->sup = s;
    /* status демона отвечает в процессе — ход перебора узлов берёт отсюда (probe.h). */
    g_probe_sup = s;
    probe_source(probe_mem);
    status_extra_source(status_fields);
    size_t fn = supd_plan(s);
    if (fn && helpers_reserve(&s->set, fn) != 0) { free(s->fresh); free(s); return NULL; }
    for (size_t i = 0; i < fn; i++)
        if (helper_clone(&s->set.h[s->set.n], &s->fresh[i]) == 0) s->set.n++;
    fn = s->set.n;
    if (d->have && fn == (size_t)(dnsd_wanted() && (!s->enabled || s->enabled())))
        fprintf(stderr, "steer[info] supervise: выходов со своим процессом в спеке нет\n");
    int dn = 0;
    for (size_t i = 0; i < fn; i++) dn |= s->set.h[i].table;
    if (!dn) orphan_stop();
    supd_kick(s);
    return s;
}

/* Кого тронет сверка: помощник новый (или возвращён, пока прежний гас), с новой подписью,
 * убранный. Считается ДО helpers_merge по тем же признакам, что у неё (команда и выход, подпись),
 * — сама сверка общая с `steer supervise` и отчёта не ведёт. */
/* Имя тронутого помощника — в список ch (растёт по числу). */
static void changes_add(struct supd_changes *ch, const char *name) {
    if (ch->helpers_n == ch->helpers_cap) {
        size_t nc = ch->helpers_cap ? ch->helpers_cap * 2 : 8;
        char (*np)[32] = realloc(ch->helpers, nc * sizeof(*np));
        if (!np) return;
        ch->helpers = np;
        ch->helpers_cap = nc;
    }
    snprintf(ch->helpers[ch->helpers_n++], sizeof(ch->helpers[0]), "%s", name);
}

void supd_changes_free(struct supd_changes *ch) {
    free(ch->helpers);
    memset(ch, 0, sizeof(*ch));
}

static void changes_of(const struct supd *s, size_t fn, struct supd_changes *ch) {
    const struct helper *h = s->set.h;
    for (size_t k = 0; k < fn; k++) {
        const struct helper *f = &s->fresh[k];
        if (f->table) continue;
        int same = 0;
        for (size_t i = 0; i < s->set.n; i++)
            if (!h[i].gone && !strcmp(h[i].cmd, f->cmd) && !strcmp(h[i].name, f->name) &&
                h[i].sig == f->sig)
                same = 1;
        if (!same) changes_add(ch, f->name);
    }
    for (size_t i = 0; i < s->set.n; i++) {
        if (h[i].table || h[i].gone) continue;
        int keep = 0;
        for (size_t k = 0; k < fn; k++)
            if (!strcmp(h[i].cmd, s->fresh[k].cmd) && !strcmp(h[i].name, s->fresh[k].name))
                keep = 1;
        if (!keep) changes_add(ch, h[i].name);
    }
}

void supd_spec_changed(struct supd *s, struct supd_changes *ch, int replaced) {
    if (ch) memset(ch, 0, sizeof(*ch));
    if (!s || s->stopping) return;
    size_t fn = supd_plan(s);
    if (ch) changes_of(s, fn, ch);
    helpers_merge(&s->set, s->fresh, fn);
    helpers_compact(&s->set);
    int sent = tab_send(s, 0);
    if (!sent && replaced) tab_send(s, 1);
    if (ch) ch->dnsd = sent;
    supd_kick(s);
}

void supd_stop(struct supd *s) {
    if (!s || s->stopping) return;
    s->stopping = 1;
    loop_timer_stop(s->tm);
    loop_timer_stop(s->ad_tm);
    s->ad_ph = 0;
    if (s->ad_p1 >= 0) { close(s->ad_p1); s->ad_p1 = -1; }
    /* Резолвер гасится явно: закрытую трубу он пережил бы — для него это «демон пропал» (adopt.c).
     * Сигнал — раньше, чем конец трубы: тогда EOF он и не примет за пропажу. Свой ребёнок
     * дожидается ниже, в helpers_stop, вместе с помощниками; забранный — здесь, по закрытию его
     * соединения (waitpid не своего ребёнка не ждёт). */
    struct helper *dn = NULL;
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].table && s->set.h[i].pid) dn = &s->set.h[i];
    if (dn) kill(dn->pid, SIGTERM);
    tab_close(s);
    if (s->dn_conn >= 0) {
        loop_fd_del(s->l, s->dn_conn);
        if (dn) {
            dnsd_kill(s->dn_conn, dn->pid);
            dn->pid = 0;
        } else {
            close(s->dn_conn);
        }
        s->dn_conn = -1;
    }
    for (size_t i = 0; i < s->set.n; i++)
        if (s->set.h[i].evfd >= 0) {
            loop_fd_del(s->l, s->set.h[i].evfd);
            close(s->set.h[i].evfd);
            s->set.h[i].evfd = -1;
        }
    helpers_stop(&s->set, 1);
}

const struct helper_state *helper_state_of(const struct steerd *d, const char *out) {
    const struct supd *s = d ? d->sup : NULL;
    if (!s || !out) return NULL;
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (!h->table && !h->gone && !strcmp(h->name, out)) return &h->st;
    }
    return NULL;
}

int supd_restart(struct supd *s, const char *out, const char *cmd) {
    if (!s || s->stopping || !out || !cmd) return -1;
    for (size_t i = 0; i < s->set.n; i++) {
        struct helper *h = &s->set.h[i];
        if (h->table || h->gone || strcmp(h->name, out) || strcmp(h->cmd, cmd)) continue;
        if (h->pid) {
            /* Уже гасится (новые параметры или прошлая просьба) — поднимется сразу и так. */
            if (!h->restart) {
                h->restart = 1;
                h->revive = 1;
                kill(h->pid, SIGTERM);
            }
        } else {
            /* Ждёт паузы после падения — сторожу ждать её незачем: подъём сейчас. */
            h->delay_ms = HELPERS_DELAY_MS;
            h->next_ms = 0;
            supd_kick(s);
        }
        return 0;
    }
    return -1;
}

/* ---- ход перебора узлов vless из памяти (probe.h) ---------------------------------------- */

/* Помощник перебирает узлы подписки и рассказывает о переборе событиями node/nonode/down: vless и
 * hysteria2 говорят одним языком, и память демона отвечает про обоих одинаково. */
static int cmd_picks_nodes(const char *cmd) {
    return !strcmp(cmd, "vless") || !strcmp(cmd, "hysteria2") || !strcmp(cmd, "proxy");
}

/* То же, что записал бы клиент (probe_report в src/proto/vless/vlmain.c), — по его событиям:
 * nonode — номер вне подписки (живёт до следующего запуска, как запись — пока свежа); node без
 * up и down у живого процесса — перебор идёт; down самого клиента — ни один узел не ответил (total
 * — из последнего node, 0 — узлов в подписке не было). Остальное — сказать нечего. */
static enum probe_state probe_of(const struct helper *h, int *node, int *total) {
    const struct helper_state *st = &h->st;
    *node = 0;
    *total = (int)st->total;
    if (st->nonode) { *node = (int)st->nonode; return PROBE_NO_SUCH_NODE; }
    if (st->excluded) return PROBE_ALL_EXCLUDED;
    if (st->running && !st->known && st->node > 0) { *node = (int)st->node; return PROBE_RUNNING; }
    /* down после up с watch — узел потерян живым клиентом, а не подъём кончился ничем: устройство
     * на месте, и «ни один узел не ответил» было бы про подъём, которого не было (probe.h). */
    if (st->running && st->watch && st->said_down) { *total = 0; return PROBE_LOST; }
    if (st->said_down) return PROBE_FAILED;
    *total = 0;
    return PROBE_NONE;
}

static int probe_mem(const char *out, struct probe_status *ps) {
    const struct supd *s = g_probe_sup;
    if (!s || !out) return -1;
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (h->table || h->gone || strcmp(h->name, out) || !cmd_picks_nodes(h->cmd)) continue;
        ps->state = probe_of(h, &ps->node, &ps->total);
        ps->since = 0;
        ps->why[0] = '\0';
        if (ps->state == PROBE_LOST) {
            ps->since = h->st.since;
            snprintf(ps->why, sizeof(ps->why), "%.*s", (int)sizeof(ps->why) - 1, h->st.why);
        }
        return 0;
    }
    return -1;
}

/* ---- состояние помощников наружу: status и команда helper ------------------------------ */

static void health_json(FILE *out, const struct helper_state *st, long now) {
    int n = 0;
    fputs("[", out);
    for (size_t i = 0; i < st->health_n; i++) {
        const struct helper_health *p = &st->health[i];
        if (p->until <= now) continue;
        char dj[160];
        steerd_json_str(dj, sizeof(dj), p->domain);
        fprintf(out, "%s{\"dc\":%d,\"media\":%s,\"domain\":%s,\"at\":%ld,\"until\":%ld}",
                n++ ? "," : "", p->dc, p->media ? "true" : "false", dj, p->at, p->until);
    }
    fputs("]", out);
}

/* Объект выхода моста tgws в status: отставленные им пути, чей срок не вышел (пустой массив —
 * отставленных нет). Только у выхода, чей помощник — ребёнок этого демона: у моста всегда, у
 * другого помощника — если он о путях сообщал (health пишет только мост; так событие видно и
 * стенду, у которого моста в сборке нет). */
static void status_fields(FILE *out, const char *name) {
    const struct supd *s = g_probe_sup;
    if (!s || !name) return;
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (h->table || h->gone || strcmp(h->name, name)) continue;
        if (strcmp(h->cmd, "tgws") && !h->st.health_n) continue;
        fputs(",\"paths_down\":", out);
        health_json(out, &h->st, (long)time(NULL));
        return;
    }
}

int supd_helper_json(const struct supd *s, const char *name, FILE *out) {
    if (!s || !name) return -1;
    int found = 0;
    long now = (long)time(NULL);
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (h->table || h->gone || strcmp(h->name, name)) continue;
        const struct helper_state *st = &h->st;
        char nj[80], wj[512];
        steerd_json_str(nj, sizeof(nj), h->name);
        fprintf(out, "{\"schema\":1,\"out\":%s,\"helper\":\"%s\",\"running\":%s,\"up\":%s",
                nj, h->cmd, st->running ? "true" : "false", st->up ? "true" : "false");
        fprintf(out, ",\"since\":%ld,\"started\":%ld,\"restarts\":%u", st->since, st->started,
                st->restarts);
        if (st->why[0]) {
            steerd_json_str(wj, sizeof(wj), st->why);
            fprintf(out, ",\"last_down\":%s", wj);
        }
        /* Модуль (отдельный бинарник): чей и какой версии, если он представился; отвергнутый за
         * чужую версию помечен — причина в last_down. */
        if (h->module) {
            fprintf(out, ",\"module\":\"%s\"", h->prog);
            if (h->mver[0]) {
                steerd_json_str(wj, sizeof(wj), h->mver);
                fprintf(out, ",\"module_ver\":%s", wj);
            }
            if (h->rejected) fputs(",\"rejected\":true", out);
        }
        if (cmd_picks_nodes(h->cmd) && (st->node || st->nonode))
            fprintf(out, ",\"node\":%ld,\"total\":%ld", st->nonode ? st->nonode : st->node,
                    st->total);
        /* Активные узлы пула (номера среди пригодных, как у vless-nodes) — когда клиент сказал. */
        if (st->active_known) fprintf(out, ",\"active\":[%s]", st->active);
        if (!strcmp(h->cmd, "tgws") || st->health_n) {
            fputs(",\"paths_down\":", out);
            health_json(out, st, now);
        }
        fputs("}\n", out);
        found = 1;
    }
    return found ? 0 : -1;
}

char *supd_probe_env(const struct supd *s) {
    if (!s) return NULL;
    char *buf = NULL;
    size_t bn = 0;
    FILE *f = open_memstream(&buf, &bn);
    if (!f) return NULL;
    fputs("STEER_PROBE_MEM=", f);
    long w0 = ftell(f);
    for (size_t i = 0; i < s->set.n; i++) {
        const struct helper *h = &s->set.h[i];
        if (h->table || h->gone || !cmd_picks_nodes(h->cmd)) continue;
        int node, total;
        enum probe_state ps = probe_of(h, &node, &total);
        const char *word = ps == PROBE_RUNNING ? "probing" : ps == PROBE_FAILED ? "failed"
                         : ps == PROBE_NO_SUCH_NODE ? "nonode" : ps == PROBE_ALL_EXCLUDED ? "excluded"
                         : ps == PROBE_LOST ? "lost"
                         : "none";
        if (ftell(f) > w0) fputc(' ', f);
        fprintf(f, "%s:%s:%d:%d", h->name, word, node, total);
        /* У lost ещё время и причина — diag ребёнком называет её так же, как status демона. */
        if (ps == PROBE_LOST) {
            char ew[520];
            probe_mem_escape(h->st.why, ew, sizeof(ew));
            fprintf(f, ":%ld:%s", h->st.since, ew);
        }
    }
    if (fclose(f) != 0) { free(buf); return NULL; }
    return buf;
}
