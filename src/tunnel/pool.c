/* Пул узлов выхода: N узлов подписки работают сразу, новые соединения делятся между ними, за каждым
 * узлом — своя слежка, и мёртвый заменяется следующим кандидатом без перезапуска процесса.
 *
 * ОТКУДА. Слежка за узлом жила в модуле VLESS (vlwatch.c) и держала ОДИН узел: потерян — проверить
 * остальных кандидатов и, если ответил другой, ВЫЙТИ, чтобы супервизор поднял процесс заново. Довод
 * был «сменить узел на ходу нельзя, каждое соединение несёт параметры своего узла». Довод верен ровно
 * наоборот: раз параметры узла берутся на КАЖДОЙ отправке, узел можно выбирать на каждое НОВОЕ
 * соединение, и соединения разных узлов живут в одном процессе рядом. Выход же стоил дорого: устройство
 * пропадало, соединения приложений оставались висеть до их таймаута (новый процесс их не знает), а
 * маршрут выхода демон привязывал заново.
 *
 * ГДЕ. Пул — обёртка дайлера (dialer.h), а не часть протокола: протоколу (VLESS, прокси) он не
 * меняет ничего — ctx его таблицы по-прежнему узел, только узел теперь свой у каждого соединения и
 * лежит в шапке сессии пула. Стеку пул отвечает на четыре необязательных вопроса таблицы (peer_of,
 * match, stale, lost), и стек про узлы не знает по-прежнему.
 *
 * СЛОТЫ. Активных узлов — `active` (ключ выхода, умолчание 1 — прежнее поведение одного узла).
 * Слот — место активного узла: узел (или пусто), жив ли, поколение. Поколение меняется, когда узел
 * слота признан мёртвым или заменён: соединения прежнего поколения стек сбрасывает (stale, RST
 * клиенту), а соединения живых слотов не трогаются. Кандидат занят, если он узел хоть одного слота —
 * два слота на одном узле не бывают.
 *
 * РАЗДАЧА (`by`, имена — как у `by` группы balance): connection — каждое новое соединение на
 * случайный живой слот; site — слот по хешу адреса назначения («сайт на одном узле»; слот мёртв —
 * следующий живой по кругу, и сайты живых слотов при этом не переезжают); site_client — по хешу пары
 * «клиент, адрес». Соединение остаётся на своём узле до конца. Адрес — тот, что в пакете: после fake-IP
 * это уже настоящий адрес сайта.
 *
 * ЗАПАСНЫЕ СВЯЗИ стека (DC_PRECONNECT) — к своему узлу: запасная наполняется к живым слотам по кругу,
 * а берёт её соединение, которому годится её узел (match): при connection — любое (соединение
 * переезжает на узел запасной, раз выбор был случайным), при site — только того же слота. Связь к узлу,
 * который больше не активен, выбрасывается.
 *
 * СЛЕЖКА — та же мера и тот же ритм, что у прежней слежки vlwatch.c, только на каждый слот. Мера —
 * проверка узла протоколом (у VLESS — vless_probe: соединение, TLS/Reality, запрос через узел и
 * первый байт ответа), та же, по которой узел выбран при подъёме: down и up меряются одной линейкой.
 * Исходы соединений живого трафика приговором НЕ служат, они только зовут проверку раньше срока: пачка
 * SYN при открытии страницы отказывает вся разом на одной потере пакетов, а удачное рукопожатие не
 * говорит, что узел пропускает трафик дальше себя. SYN-ACK клиенту стек отдаёт сам, до рукопожатия с
 * узлом, поэтому проба TCP сторожа через устройство узла не мерит — жив ли узел, знает только клиент:
 *   - живой узел проверяется раз в `interval` (умолчание 60 с); неудача — повтор через 3 с, две
 *     подряд — узел мёртв (после обрыва связи по порогу молчания хватает одной: узел и так молчал
 *     дольше порога);
 *   - раньше срока проверку зовут: три отказа установления связи подряд (как прежде) и ОБРЫВ живого
 *     соединения ядром (lost): порог молчания `silence` (stack.c, node_sock_silence) — отправленное
 *     узлу не подтверждено или узел не ответил на проверку keepalive дольше порога. Это и есть узел,
 *     умерший под длинной закачкой или звонком: новых соединений нет, и прежде его замечала только
 *     плановая проверка — до минуты;
 *   - мёртвый узел: соединения слота — в сброс (поколение), и сразу поиск замены среди свободных
 *     кандидатов по порядку предпочтения. Нашёлся — слот на новом узле. Не нашёлся — круг через 15 с:
 *     сперва свой прежний узел, потом свободные кандидаты, с каждым пустым кругом вдвое дольше, до 5 мин.
 *     Пустой слот (кандидатов при подъёме ответило меньше `active`) ищет узел тем же кругом.
 *
 * ДЕМОНУ — как прежде (evline.h): up с dev и watch, когда устройство поднято; down с причиной, когда
 * живых слотов не осталось (не раньше первой неудачной попытки замены — иначе выход мигал бы на каждой
 * замене, которая удаётся за доли секунды); снова up, когда живой нашёлся. И новое событие `active`
 * — номера активных живых узлов через запятую (поле nodes): демон показывает их в `helper`. Файл
 * состояния <tag>-<выход> (status, diag) — тем же составом, с именами; пишется на перемене, а не по
 * таймеру: флеш телефона.
 *
 * Без демона трубы нет, а слежка всё равно идёт: замена узла и сброс соединений нужны и там.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/random.h>

#include "pool.h"
#include "kind.h"
#include "evline.h"
#include "jsonw.h"
#include "platform.h"
#include "transport.h"

#define PL_LOG_W "steer[warn]: "
#define PL_LOG_I "steer[info]: "

#define PL_CONFIRM_S   3
#define PL_RETRY_S     15
#define PL_RETRY_MAX_S 300
#define PL_STREAK      3
#define PL_TIMEOUT_S   8
/* Обрыв соединения зовёт проверку не чаще, чем раз в столько: обрывы приходят пачкой (все соединения
 * умершего узла рвутся по одному сроку), а проверке хватает одной. */
#define PL_LOST_GAP_MS 5000

/* Шапка сессии пула; за ней, с отступом PL_HDR, — сессия протокола. */
struct pl_sess {
    const void *node;           /* узел соединения; NULL — запасная, ещё ничья */
    unsigned gen;               /* поколение слота на момент выбора */
    int slot;                   /* -1 — нет */
    uint8_t udp, opened;        /* flow_open был, k — его ключ */
    struct flow_key k;
};
#define PL_HDR 64
_Static_assert(sizeof(struct pl_sess) <= PL_HDR, "шапка сессии пула больше отступа");
#define INNER(s) ((void *)((unsigned char *)(s) + PL_HDR))
#define CINNER(s) ((const void *)((const unsigned char *)(s) + PL_HDR))

struct pl_slot {
    int node;                   /* индекс узла; -1 — пусто */
    int up;                     /* жив: новые соединения идут сюда */
    unsigned gen;
    int fails;                  /* неудачных проверок подряд */
    int streak;                 /* отказов установления подряд */
    int kick;                   /* проверить сейчас */
    int lost;                   /* позвал обрыв связи по порогу молчания: одной неудачи хватит */
    uint64_t due;               /* срок следующей проверки, мс CLOCK_MONOTONIC */
    uint64_t retry;             /* пауза круга мёртвого или пустого слота, с */
    uint64_t checked_at;        /* когда проверялся в последний раз */
};

static struct {
    pthread_mutex_t mu;
    pthread_cond_t cv;
    struct pool_cfg cf;
    const struct dialer_ops *in;
    struct pl_slot *slot;
    int *live;                  /* запас pl_pick: индексы живых слотов, по числу слотов; под замком */
    int n;                      /* слотов: active, но не больше кандидатов */
    unsigned rr;                /* круг запасных связей */
    int said_up;                /* демону последним сказано up (а не down) */
    char why[256];              /* причина последней неудачной проверки — для down */
    char dev[16];
    char sig[512];              /* последний опубликованный состав — писать только на перемене */
} g_pl = { .mu = PTHREAD_MUTEX_INITIALIZER };

static const void *pl_node(int i) {
    return (const unsigned char *)g_pl.cf.nodes + (size_t)i * g_pl.cf.stride;
}

static uint64_t pl_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

/* ---- раздача ---------------------------------------------------------------------------------- */

static uint32_t pl_mix(uint32_t h) {
    h ^= h >> 16;
    h *= 0x7feb352du;
    h ^= h >> 15;
    h *= 0x846ca68bu;
    h ^= h >> 16;
    return h;
}

/* Случайное на поток цикла: равномерность «поровну» не требует криптостойкости. */
static unsigned pl_rand(void) {
    static __thread uint32_t x;
    if (!x) {
        if (getrandom(&x, sizeof x, GRND_NONBLOCK) != (ssize_t)sizeof x || !x)
            x = (uint32_t)pl_now_ms() ^ (uint32_t)getpid() ^ 0x9e3779b9u;
        if (!x) x = 1;
    }
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    return x;
}

/* Слот нового соединения по раздаче. Под замком. -1 — ни у одного слота нет узла. Живых нет — мёртвый
 * слот с узлом: соединение откажет быстро (RST), а выход к этому времени уже в отказе у демона. */
static int pl_pick(const struct flow_key *k) {
    int *live = g_pl.live, nl = 0, any = -1;
    for (int i = 0; i < g_pl.n; i++) {
        if (g_pl.slot[i].node < 0) continue;
        if (any < 0) any = i;
        if (g_pl.slot[i].up) live[nl++] = i;
    }
    if (!nl) return any;
    if (g_pl.cf.by == BY_CONNECTION || !k) return live[pl_rand() % (unsigned)nl];
    uint32_t h = g_pl.cf.by == BY_SITE_CLIENT ? pl_mix(k->src * 0x9e3779b1u) ^ k->dst : k->dst;
    int at = (int)(pl_mix(h) % (uint32_t)g_pl.n);
    /* Слот сайта мёртв или пуст — следующий живой по кругу: сайты живых слотов остаются на месте. */
    for (int d = 0; d < g_pl.n; d++) {
        const struct pl_slot *sl = &g_pl.slot[(at + d) % g_pl.n];
        if (sl->node >= 0 && sl->up) return (at + d) % g_pl.n;
    }
    return any;
}

static void pl_bind(struct pl_sess *s, int slot) {
    s->slot = slot;
    s->node = slot >= 0 ? pl_node(g_pl.slot[slot].node) : NULL;
    s->gen = slot >= 0 ? g_pl.slot[slot].gen : 0;
}

/* ---- слежка: события и файл состояния -------------------------------------------------------- */

static void pl_up_event(void) {
    if (g_pl.dev[0])
        evline_emit("up", "watch", EVLINE_INT, 1L, "dev", EVLINE_STR, g_pl.dev, (const char *)NULL);
    else
        evline_emit("up", "watch", EVLINE_INT, 1L, (const char *)NULL);
}

/* down с причиной проверки — обрезанной по границе знака UTF-8 так, чтобы запись влезла в
 * EVLINE_WRITE_MAX (EVLINE_WRITE_MAX — 480 байт, evline.c, и каждый байт вне ASCII идёт в ней шестью знаками \u00XX:
 * кириллицы влезает меньше восьмидесяти байт; длиннее — событие потерялось бы целиком). */
#define PL_WHY_ESC 440
static void pl_down_event(const char *why) {
    char w[160];
    size_t n = 0, esc = 0;
    for (const unsigned char *s = (const unsigned char *)why; *s && n + 1 < sizeof(w); ) {
        size_t len = *s >= 0xF0 ? 4 : *s >= 0xE0 ? 3 : *s >= 0xC0 ? 2 : 1;
        size_t cost = 0, k;
        for (k = 0; k < len && s[k]; k++)
            cost += s[k] >= 0x80 || s[k] < 0x20 ? 6 : (s[k] == '"' || s[k] == '\\') ? 2 : 1;
        if (k < len || n + len + 1 > sizeof(w) || esc + cost > PL_WHY_ESC) break;
        memcpy(w + n, s, len);
        n += len;
        esc += cost;
        s += len;
    }
    w[n] = '\0';
    evline_emit("down", "why", EVLINE_STR, w[0] ? w : "узел не отвечает", (const char *)NULL);
}

/* Состав и здоровье выхода — демону и в файл состояния, только на перемене. Не под замком: читает
 * слоты под ним сам. */
static void pl_publish(void) {
    char nodes[480] = "";
    size_t nn = 0;
    int any = 0;
    pthread_mutex_lock(&g_pl.mu);
    int idx[64], ni = 0;
    for (int i = 0; i < g_pl.n && ni < 64; i++)
        if (g_pl.slot[i].node >= 0 && g_pl.slot[i].up) { idx[ni++] = g_pl.slot[i].node; any = 1; }
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < ni && nn + 12 < sizeof nodes; i++)
        nn += (size_t)snprintf(nodes + nn, sizeof nodes - nn, "%s%d", i ? "," : "", idx[i]);

    if (any && !g_pl.said_up) {
        g_pl.said_up = 1;
        pl_up_event();
    } else if (!any && g_pl.said_up) {
        g_pl.said_up = 0;
        pl_down_event(g_pl.why);
    }
    char sig[512];
    snprintf(sig, sizeof sig, "%d|%s", any, nodes);
    if (!strcmp(sig, g_pl.sig)) return;
    snprintf(g_pl.sig, sizeof g_pl.sig, "%s", sig);
    evline_emit("active", "nodes", EVLINE_STR, nodes, (const char *)NULL);

    /* Файл состояния одной строкой: {"pid","up","node","want","slots","by","active":[{"index","name"}]}
     * и поля протокола (extra). up — есть живой узел; node — имя первого активного (прежнее поле
     * файла proxy-*: один узел); want — сколько просили (active), slots — сколько держим (не больше
     * кандидатов). Верен, пока жив pid (как у hy2-*): kill -9 убрать за собой не даст. */
    if (!g_pl.cf.out || !g_pl.cf.proto->tag) return;
    char path[320], tmp[340];
    snprintf(path, sizeof path, "%s/%s-%.32s", steer_state_dir(), g_pl.cf.proto->tag, g_pl.cf.out);
    snprintf(tmp, sizeof tmp, "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (!f) return;
    fprintf(f, "{\"pid\":%ld,\"up\":%s,\"node\":", (long)getpid(), any ? "true" : "false");
    jsonw_str(f, ni ? g_pl.cf.proto->name(pl_node(idx[0])) : "");
    if (g_pl.cf.proto->extra) fprintf(f, ",%s", g_pl.cf.proto->extra);
    fprintf(f, ",\"want\":%d,\"slots\":%d,\"by\":\"%s\",\"active\":[", g_pl.cf.active, g_pl.n,
            group_by_name(g_pl.cf.by));
    for (int i = 0; i < ni; i++) {
        fprintf(f, "%s{\"index\":%d,\"name\":", i ? "," : "", idx[i]);
        jsonw_str(f, g_pl.cf.proto->name(pl_node(idx[i])));
        fputc('}', f);
    }
    fputs("]}\n", f);
    if (fclose(f) != 0 || rename(tmp, path) != 0) unlink(tmp);
}

/* ---- слежка: проверки ---------------------------------------------------------------------------- */

static int pl_probe(int node, char *why, size_t n) {
    return g_pl.cf.proto->probe(pl_node(node), PL_TIMEOUT_S, why, n);
}

/* Занят ли кандидат c другим слотом (живым или мёртвым, который его ещё ждёт). Под замком. */
static int pl_taken(int c, int except) {
    for (int i = 0; i < g_pl.n; i++)
        if (i != except && g_pl.slot[i].node == c) return 1;
    return 0;
}

/* Слоту i — живой узел: свой прежний (если own), потом свободные кандидаты по порядку. 1 — нашёлся.
 * Проверки — без замка (до восьми секунд каждая); после каждой неудачной — публикация: если живых
 * не осталось, демон узнаёт об этом сразу, а не после всего круга. */
static int pl_refill(int i, int own) {
    char why[256];
    int prev = g_pl.slot[i].node;
    if (own && prev >= 0) {
        if (pl_probe(prev, why, sizeof why) == 0) {
            pthread_mutex_lock(&g_pl.mu);
            struct pl_slot *sl = &g_pl.slot[i];
            sl->up = 1;
            sl->fails = sl->streak = sl->kick = sl->lost = 0;
            sl->retry = PL_RETRY_S;
            sl->checked_at = pl_now_ms();
            sl->due = sl->checked_at + (uint64_t)g_pl.cf.interval_s * 1000ull;
            pthread_mutex_unlock(&g_pl.mu);
            fprintf(stderr, PL_LOG_I "узел %s снова отвечает\n", g_pl.cf.proto->name(pl_node(prev)));
            pl_publish();
            return 1;
        }
        snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
        pl_publish();
    }
    for (size_t k = 0; k < g_pl.cf.sel_n; k++) {
        int c = g_pl.cf.sel[k];
        pthread_mutex_lock(&g_pl.mu);
        int busy = c == prev || pl_taken(c, i);
        pthread_mutex_unlock(&g_pl.mu);
        if (busy) continue;
        if (pl_probe(c, why, sizeof why) != 0) {
            if (!g_pl.why[0]) snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
            pl_publish();
            continue;
        }
        pthread_mutex_lock(&g_pl.mu);
        if (pl_taken(c, i)) { pthread_mutex_unlock(&g_pl.mu); continue; }
        struct pl_slot *sl = &g_pl.slot[i];
        sl->node = c;
        sl->up = 1;
        __atomic_add_fetch(&sl->gen, 1, __ATOMIC_RELEASE);  /* pl_stale читает без замка */
        sl->fails = sl->streak = sl->kick = sl->lost = 0;
        sl->retry = PL_RETRY_S;
        sl->checked_at = pl_now_ms();
        sl->due = sl->checked_at + (uint64_t)g_pl.cf.interval_s * 1000ull;
        pthread_mutex_unlock(&g_pl.mu);
        if (prev >= 0)
            fprintf(stderr, PL_LOG_W "узел %s не отвечает — вместо него %s\n",
                    g_pl.cf.proto->name(pl_node(prev)), g_pl.cf.proto->name(pl_node(c)));
        else
            fprintf(stderr, PL_LOG_I "активный узел %d из %d: %s\n", i + 1, g_pl.n,
                    g_pl.cf.proto->name(pl_node(c)));
        /* Узел слота сменился: соединения прежнего (если они ещё были) — в сброс. */
        stack_nodes_changed();
        pl_publish();
        return 1;
    }
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[i];
    sl->due = pl_now_ms() + sl->retry * 1000ull;
    sl->retry = sl->retry * 2 > PL_RETRY_MAX_S ? PL_RETRY_MAX_S : sl->retry * 2;
    pthread_mutex_unlock(&g_pl.mu);
    pl_publish();
    return 0;
}

/* Одна проверка слота i: живой — обычная проверка, мёртвый или пустой — круг поиска. */
static void pl_check(int i) {
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[i];
    int node = sl->node, up = sl->up, lost = sl->lost;
    sl->kick = sl->lost = 0;
    pthread_mutex_unlock(&g_pl.mu);
    if (node < 0 || !up) { pl_refill(i, 1); return; }

    char why[256];
    int rc = pl_probe(node, why, sizeof why);
    pthread_mutex_lock(&g_pl.mu);
    sl->checked_at = pl_now_ms();
    if (rc == 0) {
        sl->fails = sl->streak = 0;
        sl->due = sl->checked_at + (uint64_t)g_pl.cf.interval_s * 1000ull;
        pthread_mutex_unlock(&g_pl.mu);
        return;
    }
    /* Две неудачи подряд — против одной потери на радиоканале. Проверку, которую позвал обрыв связи
     * ядром, первая неудача уже подтверждает: узел и так молчал дольше порога silence. */
    if (++sl->fails < 2 && !lost) {
        sl->due = sl->checked_at + PL_CONFIRM_S * 1000ull;
        pthread_mutex_unlock(&g_pl.mu);
        return;
    }
    /* Мёртв: соединения этого узла — в сброс сейчас же (поколение), не дожидаясь замены. */
    sl->up = 0;
    sl->fails = 0;
    __atomic_add_fetch(&sl->gen, 1, __ATOMIC_RELEASE);
    sl->retry = PL_RETRY_S;
    pthread_mutex_unlock(&g_pl.mu);
    snprintf(g_pl.why, sizeof g_pl.why, "%s", why);
    fprintf(stderr, PL_LOG_W "узел %s не отвечает: %s — ищу замену\n",
            g_pl.cf.proto->name(pl_node(node)), why);
    stack_nodes_changed();
    /* Сразу — замена среди свободных; свой только что дважды не ответил, его — в следующем круге. */
    pl_refill(i, 0);
}

/* Слот, который пора проверять: с просьбой проверить сейчас — первым, иначе с ближайшим сроком.
 * Под замком; ждёт до срока. */
static int pl_next(void) {
    for (;;) {
        uint64_t now = pl_now_ms(), due = UINT64_MAX;
        int best = -1;
        for (int i = 0; i < g_pl.n; i++) {
            const struct pl_slot *sl = &g_pl.slot[i];
            if (sl->kick && sl->up && sl->node >= 0) return i;
            if (sl->due < due) { due = sl->due; best = i; }
        }
        if (best >= 0 && due <= now) return best;
        struct timespec ts = { .tv_sec = (time_t)(due / 1000), .tv_nsec = (long)(due % 1000) * 1000000L };
        pthread_cond_timedwait(&g_pl.cv, &g_pl.mu, &ts);
    }
}

static void *pl_thread(void *arg) {
    (void)arg;
    for (;;) {
        pthread_mutex_lock(&g_pl.mu);
        int i = pl_next();
        pthread_mutex_unlock(&g_pl.mu);
        pl_check(i);
    }
    return NULL;
}

/* Проверить слот сейчас (исход соединения или обрыв). Под замком. */
static void pl_kick(int i) {
    g_pl.slot[i].kick = 1;
    pthread_cond_signal(&g_pl.cv);
}

/* ---- дайлер пула --------------------------------------------------------------------------------- */

static const char *pl_peer(const void *ctx) {
    (void)ctx;
    for (int i = 0; i < g_pl.n; i++)
        if (g_pl.slot[i].node >= 0) return g_pl.in->peer(pl_node(g_pl.slot[i].node));
    return "?";
}

static const char *pl_peer_of(const void *ctx, const void *sess) {
    const struct pl_sess *s = sess;
    return s->node ? g_pl.in->peer(s->node) : pl_peer(ctx);
}

static void pl_describe(const void *ctx, char *out, size_t n) {
    (void)ctx;
    size_t w = 0;
    out[0] = '\0';
    pthread_mutex_lock(&g_pl.mu);
    for (int i = 0; i < g_pl.n && w + 2 < n; i++) {
        if (g_pl.slot[i].node < 0) continue;
        if (w) w += (size_t)snprintf(out + w, n - w, ", ");
        if (w < n) {
            g_pl.in->describe(pl_node(g_pl.slot[i].node), out + w, n - w);
            w += strlen(out + w);
        }
    }
    pthread_mutex_unlock(&g_pl.mu);
    if (g_pl.cf.active > 1 && w < n)
        snprintf(out + w, n - w, " — активных %d, раздача %s", g_pl.cf.active, group_by_name(g_pl.cf.by));
}

static const char *pl_strerror(int rc) { return g_pl.in->strerror(rc); }

/* Исход установления — слежке слота: серия отказов зовёт его проверку раньше срока. */
static void pl_seen(const struct pl_sess *s, int rc) {
    if (s->slot < 0) return;
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[s->slot];
    if (sl->gen == s->gen) {
        if (rc == 0) sl->streak = 0;
        else if (++sl->streak >= PL_STREAK) pl_kick(s->slot);
    }
    pthread_mutex_unlock(&g_pl.mu);
}

static int pl_connect(const void *ctx, void *sess, int timeout_s) {
    (void)ctx;
    struct pl_sess *s = sess;
    if (!s->node) {
        /* Запасная: к живым слотам по кругу. */
        pthread_mutex_lock(&g_pl.mu);
        int pick = -1;
        for (int d = 0; d < g_pl.n && pick < 0; d++) {
            int i = (int)((g_pl.rr + (unsigned)d) % (unsigned)g_pl.n);
            if (g_pl.slot[i].node >= 0 && g_pl.slot[i].up) pick = i;
        }
        if (pick >= 0) {
            g_pl.rr = (unsigned)pick + 1;
            pl_bind(s, pick);
        }
        pthread_mutex_unlock(&g_pl.mu);
        if (pick < 0) return TR_ECONNECT;
    }
    int rc = g_pl.in->connect(s->node, INNER(s), timeout_s);
    pl_seen(s, rc);
    return rc;
}

/* Запасная связь — соединению. Узел запасной другой (раздача connection) — соединение переезжает на
 * него: состояние потока заводится заново под новый узел (у VLESS — UUID и Vision), потом связь. */
static void pl_take(void *dst, void *src) {
    struct pl_sess *d = dst, *s = src;
    if (d->node != s->node) {
        d->node = s->node;
        d->slot = s->slot;
        d->gen = s->gen;
        if (d->opened) g_pl.in->flow_open(d->node, INNER(d), &d->k, d->udp);
    }
    g_pl.in->take(INNER(d), INNER(s));
    s->node = NULL;
    s->slot = -1;
}

static void pl_close(void *sess) { g_pl.in->close(INNER(sess)); }

static void pl_clear(void *sess) {
    struct pl_sess *s = sess;
    s->node = NULL;
    s->slot = -1;
    s->opened = 0;
    g_pl.in->clear(INNER(s));
}

static int pl_fd(const void *sess) { return g_pl.in->fd(CINNER(sess)); }
static int pl_has_data(const void *sess) { return g_pl.in->has_data(CINNER(sess)); }

static int pl_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx;
    struct pl_sess *s = sess;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, pl_pick(k));
    pthread_mutex_unlock(&g_pl.mu);
    if (!s->node) return -1;
    s->k = *k;
    s->udp = (uint8_t)udp;
    s->opened = 1;
    return g_pl.in->flow_open(s->node, INNER(s), k, udp);
}

static int pl_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx;
    struct pl_sess *s = sess;
    return g_pl.in->send(s->node, INNER(s), k, udp, d, n);
}

static long pl_room(const void *ctx, const void *sess) {
    (void)ctx;
    const struct pl_sess *s = sess;
    if (!g_pl.in->room || !s->node) return -1;
    return g_pl.in->room(s->node, (const char *)sess + PL_HDR);
}

static size_t pl_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    return g_pl.in->dgram_frame(p, n, out, cap);
}

static int pl_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    return g_pl.in->read(INNER(sess), buf, cap, data, got);
}

static int pl_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx;
    struct pl_sess *s = sess;
    return g_pl.in->deliver(s->node, INNER(s), udp, d, n, emit, arg);
}

static int pl_match(const void *ctx, const void *dst, const void *src) {
    (void)ctx;
    const struct pl_sess *d = dst, *s = src;
    if (!s->node || s->slot < 0) return -1;
    pthread_mutex_lock(&g_pl.mu);
    const struct pl_slot *sl = &g_pl.slot[s->slot];
    int live = sl->gen == s->gen && sl->up;
    pthread_mutex_unlock(&g_pl.mu);
    if (!live) return -1;
    if (g_pl.cf.by == BY_CONNECTION) return 1;
    return d->slot == s->slot;
}

static int pl_stale(const void *ctx, const void *sess) {
    (void)ctx;
    const struct pl_sess *s = sess;
    if (s->slot < 0 || !s->node) return 0;
    return __atomic_load_n(&g_pl.slot[s->slot].gen, __ATOMIC_ACQUIRE) != s->gen;
}

static void pl_lost(const void *ctx, const void *sess) {
    (void)ctx;
    const struct pl_sess *s = sess;
    if (s->slot < 0) return;
    pthread_mutex_lock(&g_pl.mu);
    struct pl_slot *sl = &g_pl.slot[s->slot];
    if (sl->gen == s->gen && sl->up && pl_now_ms() - sl->checked_at >= PL_LOST_GAP_MS) {
        sl->lost = 1;
        pl_kick(s->slot);
    }
    pthread_mutex_unlock(&g_pl.mu);
}

static struct dialer_ops g_pl_ops;

/* ---- подъём -------------------------------------------------------------------------------------- */

struct pl_ready { stack_ready_fn ready; void *arg; };

/* Устройство поднято: up демону и слежка. up — до потока слежки: первая проверка узла, названного
 * человеком (его при подъёме не проверяли), идёт сразу, и её down не должен обогнать up в трубе. */
static void pl_ready_cb(void *arg, const char *dev) {
    const struct pl_ready *r = arg;
    snprintf(g_pl.dev, sizeof g_pl.dev, "%s", dev ? dev : "");
    pl_publish();
    pthread_attr_t a;
    pthread_attr_init(&a);
    /* Проверка держит соединение (struct transport, ~40 КБ) на своём стеке. */
    pthread_attr_setstacksize(&a, 512 * 1024);
    pthread_attr_setdetachstate(&a, PTHREAD_CREATE_DETACHED);
    pthread_t t;
    int err = pthread_create(&t, &a, pl_thread, NULL);
    pthread_attr_destroy(&a);
    if (err) {
        /* Без слежки up — прежний, без watch: сторож демона тогда пробует устройство сам. */
        fprintf(stderr, PL_LOG_W "поток слежки за узлами не создался (%s) — потерю узла клиент не "
                        "заметит\n", strerror(err));
        evline_emit("up", "dev", EVLINE_STR, g_pl.dev, (const char *)NULL);
    }
    if (r->ready) r->ready(r->arg, dev);
}

/* Слоты и таблица пула по настройке pc; дайлер для стека или NULL — нет памяти. Отдельно от pool_run
 * ради стенда (tests/poolmatch.c): он заводит пул без устройства. */
static const struct dialer *pool_setup(const struct pool_cfg *pc) {
    /* Сроки слежки — по CLOCK_MONOTONIC: во сне телефона эти часы стоят, и слежка его не будит. */
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&g_pl.cv, &ca);
    pthread_condattr_destroy(&ca);
    g_pl.cf = *pc;
    g_pl.in = pc->proto->ops;
    if (g_pl.cf.interval_s <= 0) g_pl.cf.interval_s = POOL_INTERVAL_S;
    if (g_pl.cf.active < 1) g_pl.cf.active = 1;
    /* Слотов — не больше кандидатов: держать активными больше узлов, чем их есть, нечем. */
    g_pl.n = g_pl.cf.active;
    if ((size_t)g_pl.n > pc->sel_n) {
        fprintf(stderr, PL_LOG_W "активных узлов просили %d, а кандидатов %zu — активны все\n",
                g_pl.cf.active, pc->sel_n);
        g_pl.n = (int)pc->sel_n;
    }
    if (g_pl.n < 1) g_pl.n = 1;
    g_pl.slot = calloc((size_t)g_pl.n, sizeof *g_pl.slot);
    free(g_pl.live);
    g_pl.live = malloc((size_t)g_pl.n * sizeof *g_pl.live);
    if (!g_pl.slot || !g_pl.live) { fprintf(stderr, PL_LOG_W "нет памяти под слоты узлов\n"); return NULL; }
    uint64_t now = pl_now_ms();
    for (int i = 0; i < g_pl.n; i++) {
        g_pl.slot[i].node = -1;
        g_pl.slot[i].retry = PL_RETRY_S;
        g_pl.slot[i].due = now;            /* пустой слот ищет узел сразу */
    }
    /* Первый слот — узел, выбранный при подъёме. Проверен перебором — следующая проверка через
     * период; назван человеком — сразу. */
    g_pl.slot[0].node = pc->first;
    g_pl.slot[0].up = 1;
    g_pl.slot[0].checked_at = now;
    g_pl.slot[0].due = pc->checked ? now + (uint64_t)g_pl.cf.interval_s * 1000ull : now;

    g_pl_ops = *g_pl.in;
    g_pl_ops.sess_size = PL_HDR + g_pl.in->sess_size;
    g_pl_ops.peer = pl_peer;
    g_pl_ops.describe = pl_describe;
    g_pl_ops.strerror = pl_strerror;
    g_pl_ops.connect = pl_connect;
    g_pl_ops.take = pl_take;
    g_pl_ops.close = pl_close;
    g_pl_ops.clear = pl_clear;
    g_pl_ops.fd = pl_fd;
    g_pl_ops.has_data = pl_has_data;
    g_pl_ops.flow_open = pl_flow_open;
    g_pl_ops.send = pl_send;
    g_pl_ops.room = pl_room;
    g_pl_ops.dgram_frame = pl_dgram_frame;
    g_pl_ops.read = pl_read;
    g_pl_ops.deliver = pl_deliver;
    g_pl_ops.peer_of = pl_peer_of;
    g_pl_ops.match = pl_match;
    g_pl_ops.stale = pl_stale;
    g_pl_ops.lost = pl_lost;

    /* Статический: стек держит указатель до конца процесса. */
    static struct dialer d;
    d.ops = &g_pl_ops;
    d.ctx = &g_pl;
    d.silence_s = pc->silence_s;
    return &d;
}

int pool_run(struct output *o, const struct pool_cfg *pc, stack_ready_fn ready, void *arg) {
    const struct dialer *d = pool_setup(pc);
    if (!d) return 1;
    static struct pl_ready r;
    r.ready = ready;
    r.arg = arg;
    return stack_run(o, d, pl_ready_cb, &r);
}
