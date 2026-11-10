/* Соединения апстримов резолвера без сети и без TLS: DoT, DoH по HTTP/1.1 и HTTP/2, TCP.
 *
 * Стенд линкуется с src/dnsd/dup.c (объекты цикла — в dupint.h) и подменяет слой TLS: вместо
 * tls13_read/tls13_write — очередь «записей», которую задаёт проверка, и счётчик отправленного.
 * Соединение собирается прямо в таблице апстрима в состоянии «готово», как его оставил бы поток
 * установки (dial_event_cb), — рукопожатия и сети нет. Проверяется то, что происходит в цикле
 * событий: разбор пришедшего, сроки, перестановка вопросов между соединениями.
 *
 * Обёртка QUIC подменена так же (шов dupq.h): соединение «открывается» сразу, потоки выдаются по
 * номеру, в сеть ничего не уходит. Этого хватает для того, что dup.c решает сам: PING в настройке
 * соединения, сроки молчащего соединения DoQ, срок простоя. Сам PING на проводе — tests/doqup.sh.
 *
 * Кадры и HPACK без соединения — tests/dupmatch.c; настоящие серверы — tests/dnsup.sh,
 * tests/doh2up.sh. */
#define _GNU_SOURCE
#include "dnsd_int.h"
#include "dupint.h"
#include "doh2.h"
#include "dupq.h"
#include "tls13.h"
#include <sys/eventfd.h>
#include "reality.h"
#include "unit.h"

#define CN(up, i) ((up)->c[i])
#define RQ(k) (*req_ref(k))
static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* ---- подмена TLS --------------------------------------------------------------------------- */

struct frec { uint8_t *d; size_t n; };
static struct frec g_rq[1024];
static int g_rh, g_rt;
static size_t g_wrote;

static void rec_push(const uint8_t *d, size_t n) {
    g_rq[g_rt].d = malloc(n);
    memcpy(g_rq[g_rt].d, d, n);
    g_rq[g_rt].n = n;
    g_rt++;
}
static void rec_clear(void) {
    while (g_rh < g_rt) free(g_rq[g_rh++].d);
    g_rh = g_rt = 0;
}

int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) {
    (void)t;
    *got = 0;
    if (g_rh == g_rt) return 0;                   /* записи нет — «пока нечего», как у настоящего */
    struct frec *r = &g_rq[g_rh++];
    if (r->n > cap) return TLS13_ETOOBIG;
    memcpy(out, r->d, r->n);
    *got = r->n;
    free(r->d);
    return 0;
}
int tls13_has_record(const struct tls13 *t) { (void)t; return g_rh != g_rt; }
int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) { (void)t; (void)data; g_wrote += n; return 0; }
void tls13_free(struct tls13 *t) { (void)t; }
/* Нужны только затем, чтобы dup_have_tls() был истинным; установки соединения стенд не ведёт. */
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *client_hello, size_t hello_n,
                         const unsigned char *our_priv, const struct tls13_auth *auth) {
    (void)t; (void)fd; (void)client_hello; (void)hello_n; (void)our_priv; (void)auth;
    return -1;
}
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car, unsigned char *out, size_t out_n,
                              size_t *out_len) {
    (void)cfg; (void)st; (void)car; (void)out; (void)out_n; (void)out_len;
    return -1;
}

/* ---- подмена QUIC -------------------------------------------------------------------------- */

struct dupq { int fd; };
static struct dupq_cfg g_qcfg;                    /* настройка последнего dupq_open */
static int g_qopen, g_qclose, g_qstreams;

int dupq_prepare(const char *roots) { (void)roots; return 1; }
int dupq_ready(void) { return 1; }
int dupq_open(const struct dupq_cfg *cfg, const struct dupq_ops *ops, void *user, struct dupq **out) {
    (void)ops; (void)user;
    g_qcfg = *cfg;
    g_qopen++;
    struct dupq *q = calloc(1, sizeof(*q));
    q->fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    *out = q;
    return 0;
}
void dupq_close(struct dupq *q, uint64_t app_err) { (void)q; (void)app_err; g_qclose++; }
void dupq_free(struct dupq *q) { close(q->fd); free(q); }
int dupq_fd(const struct dupq *q) { return q->fd; }
int dupq_timeout_ms(struct dupq *q) { (void)q; return -1; }
int dupq_on_readable(struct dupq *q) { (void)q; return 0; }
int dupq_on_timer(struct dupq *q) { (void)q; return 0; }
int dupq_early_ready(const struct dupq *q) { (void)q; return 0; }
int dupq_stream_open(struct dupq *q, int64_t *sid) { (void)q; *sid = 4 * g_qstreams++; return 0; }
int dupq_stream_open_uni(struct dupq *q, int64_t *sid) { (void)q; *sid = 2; return 0; }
ssize_t dupq_stream_send(struct dupq *q, int64_t sid, const uint8_t *d, size_t n, int fin) {
    (void)q; (void)sid; (void)d; (void)fin;
    return (ssize_t)n;
}
int dupq_stream_reset(struct dupq *q, int64_t sid, uint64_t app_err) { (void)q; (void)sid; (void)app_err; return 0; }

/* ---- проверки ----------------------------------------------------------------------------- */


static int g_ans, g_fail;
static size_t g_last_n;
static void on_done(void *ctx, const uint8_t *ans, size_t n, const uint8_t *q, size_t qn) {
    (void)ctx; (void)q; (void)qn;
    if (ans) { g_ans++; g_last_n = n; } else g_fail++;
}

static int g_peer[256], g_peer_n;

/* Апстрим по адресу url — единственный в настройке. */
static struct dup *mk_up(const char *url) {
    dup_apply(NULL, 0);
    struct dup_cfg cfg;
    char why[128];
    memset(&cfg, 0, sizeof(cfg));
    if (dnsurl_parse(url, &cfg.u, why, sizeof(why)) != 0) { printf("url %s: %s\n", url, why); exit(2); }
    snprintf(cfg.u.name, sizeof(cfg.u.name), "t");
    snprintf(cfg.u.url, sizeof(cfg.u.url), "%s", url);
    dup_apply(&cfg, 1);
    g_ans = g_fail = 0;
    g_last_n = 0;
    g_wrote = 0;
    rec_clear();
    return g_dups[0];
}

/* Соединение в состоянии, в каком его оставляет dial_event_cb (или tcp_dial при st == CS_TCPCONN). */
static struct dconn *add_conn(struct dup *up, int st, int h2) {
    if (up->c_n == up->c_cap) {
        int nc = up->c_cap ? up->c_cap * 2 : 4;
        up->c = realloc(up->c, (size_t)nc * sizeof(*up->c));
        up->c_cap = nc;
    }
    struct dconn *c = NULL;
    for (int i = 0; i < up->c_n; i++) if (CN(up, i)->st == CS_FREE) { c = CN(up, i); break; }
    if (!c) {
        c = calloc(1, sizeof(*c));
        c->idx = up->c_n;
        up->c[up->c_n++] = c;
    }
    int sv[2];
    socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
    g_peer[g_peer_n++] = sv[1];
    c->up = up;
    c->tag.magic = DTAG_MAGIC; c->tag.kind = DT_CONN; c->tag.obj = c;
    c->fd = sv[0];
    c->qfd = -1;
    c->tls = st == CS_TCPCONN || up->cfg.u.proto == DNSP_TCP ? NULL : calloc(1, sizeof(struct tls13));
    c->st = st;
    c->last_ms = now_ms();
    c->qrx_ms = c->last_ms;
    c->busy = 0;
    c->h2 = h2;
    c->h2_go = 0;
    c->h2_next = 1;
    c->h2_maxs = 100;
    c->h2_win = c->h2_iwin = H2D_WINDOW_DEFAULT;
    if (up->cfg.u.proto == DNSP_DOH) up->hproto = h2 ? 2 : 1;
    struct epoll_event e = { .events = st == CS_TCPCONN ? EPOLLOUT : EPOLLIN, .data.ptr = &c->tag };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, c->fd, &e);
    return c;
}

/* Готовое соединение QUIC — каким его оставляет quic_after по завершении рукопожатия. */
static struct dconn *add_quic(struct dup *up) {
    if (up->c_n == up->c_cap) {
        int nc = up->c_cap ? up->c_cap * 2 : 4;
        up->c = realloc(up->c, (size_t)nc * sizeof(*up->c));
        up->c_cap = nc;
    }
    struct dconn *c = NULL;
    for (int i = 0; i < up->c_n; i++) if (CN(up, i)->st == CS_FREE) { c = CN(up, i); break; }
    if (!c) {
        c = calloc(1, sizeof(*c));
        c->idx = up->c_n;
        up->c[up->c_n++] = c;
    }
    c->up = up;
    c->tag.magic = DTAG_MAGIC; c->tag.kind = DT_CONN; c->tag.obj = c;
    c->fd = -1;
    struct dupq_cfg qc = {0};
    struct dupq_ops ops = {0};
    dupq_open(&qc, &ops, c, &c->qc);
    c->qfd = dupq_fd(c->qc);
    c->qhs = 1;
    c->qclosed = c->qerej = 0;
    c->st = CS_READY;
    c->busy = 0;
    c->last_ms = c->qrx_ms = now_ms();
    struct epoll_event e = { .events = EPOLLIN, .data.ptr = &c->tag };
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, c->qfd, &e);
    return c;
}

/* Группа failover из двух серверов DoT: настройка — серверы a и b, за ними группа g (номер 2). */
static void mk_group(void) {
    dup_apply(NULL, 0);
    struct dup_cfg cfg[3];
    char why[128];
    static unsigned gm[2] = { 0, 1 };
    memset(cfg, 0, sizeof(cfg));
    static const char *const url[2] = { "tls://127.0.0.1", "tls://127.0.0.2" };
    for (int i = 0; i < 2; i++) {
        if (dnsurl_parse(url[i], &cfg[i].u, why, sizeof(why)) != 0) { printf("url %s: %s\n", url[i], why); exit(2); }
        snprintf(cfg[i].u.name, sizeof(cfg[i].u.name), "%c", 'a' + i);
        snprintf(cfg[i].u.url, sizeof(cfg[i].u.url), "%s", url[i]);
    }
    snprintf(cfg[2].u.name, sizeof(cfg[2].u.name), "g");
    cfg[2].grp = DNSG_FAILOVER;
    cfg[2].gm = gm;
    cfg[2].gm_n = 2;
    dup_apply(cfg, 3);
    g_ans = g_fail = 0;
    g_wrote = 0;
    rec_clear();
}

/* Ответ DoT на вопрос r — записью TLS в очередь подмены. */
static void push_dot_answer(const struct dreq *r) {
    uint8_t rec[2 + 64];
    if (!r) return;                               /* вопроса нет — проверка рядом это и покажет */
    rec[0] = 0; rec[1] = (uint8_t)r->qn;
    memcpy(rec + 2, r->q, r->qn);
    rec[4] |= 0x80;
    rec_push(rec, 2u + r->qn);
}

static uint8_t g_qbuf[64];
static size_t mk_query(const char *name) {
    size_t o = 12;
    memset(g_qbuf, 0, 12);
    g_qbuf[2] = 0x01; g_qbuf[5] = 1;
    for (const char *p = name; *p;) {
        const char *d = strchr(p, '.');
        size_t l = d ? (size_t)(d - p) : strlen(p);
        g_qbuf[o++] = (uint8_t)l; memcpy(g_qbuf + o, p, l); o += l;
        p += l + (d ? 1 : 0);
    }
    g_qbuf[o++] = 0; g_qbuf[o++] = 0; g_qbuf[o++] = 1; g_qbuf[o++] = 0; g_qbuf[o++] = 1;
    return o;
}

/* Ответ на вопрос r длиной len (вопрос как есть, дальше — нули: разбору апстрима важен вопрос). */
static uint8_t *mk_answer(const struct dreq *r, size_t len) {
    uint8_t *a = calloc(1, len);
    memcpy(a, r->q, r->qn);
    a[2] |= 0x80;
    return a;
}

/* Вопросы апстрима по порядку мест. */
static struct dreq *nth_req(struct dup *up, int n) {
    for (int k = 0; k < g_req_cap; k++)
        if (RQ(k).used && RQ(k).up == up && n-- == 0) return &RQ(k);
    return NULL;
}

int main(void) {
    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    size_t qn = mk_query("a.test");

    /* 1. Больше 64 записей TLS, уже прочитанных у сокета. Слой TLS читает сокет порциями до 16 КиБ, и
     *    в одну порцию помещается сотня коротких ответов DoT — каждый своей записью. Цикл чтения
     *    соединения останавливался на 64-й и уходил ждать события сокета, а сокет пуст: остальные
     *    ответы лежали в буфере TLS до следующего пакета сервера или до срока вопроса. */
    {
        struct dup *up = mk_up("tls://127.0.0.1");
        struct dconn *c = add_conn(up, CS_READY, 0);
        for (int i = 0; i < 100; i++) dup_ask(0, g_qbuf, qn, on_done, NULL);
        check("DoT: сто вопросов ушли по одному соединению", 100, c->busy);
        for (int i = 0; i < 100; i++) {
            struct dreq *r = nth_req(up, i);
            uint8_t rec[2 + 64];
            rec[0] = 0; rec[1] = (uint8_t)r->qn;
            memcpy(rec + 2, r->q, r->qn);
            rec[4] |= 0x80;
            rec_push(rec, 2u + r->qn);
        }
        dup_event(&c->tag, EPOLLIN);
        check("  сто ответов записями TLS, прочитанными разом: все розданы за одно событие", 100, g_ans);
        check("  в буфере TLS ничего не осталось", 0, g_rt - g_rh);
    }

    /* 2. Ответ DoT почти в 64 КиБ, а за ним в той же записи TLS — начало следующего. Недочитанный хвост
     *    (до 65 537 байт) плюс запись (до 16 КиБ) больше прежнего потолка буфера в 70 КиБ, и исправное
     *    соединение закрывалось «ответ слишком велик». */
    {
        struct dup *up = mk_up("tls://127.0.0.1");
        struct dconn *c = add_conn(up, CS_READY, 0);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        const size_t l1 = 65000, l2 = 11380;
        uint8_t *a1 = mk_answer(nth_req(up, 0), l1), *a2 = mk_answer(nth_req(up, 1), l2);
        size_t sn = 2 + l1 + 2 + l2;
        uint8_t *s = malloc(sn);
        s[0] = (uint8_t)(l1 >> 8); s[1] = (uint8_t)l1; memcpy(s + 2, a1, l1);
        s[2 + l1] = (uint8_t)(l2 >> 8); s[3 + l1] = (uint8_t)l2; memcpy(s + 4 + l1, a2, l2);
        static const size_t cut[] = { 16384, 16384, 16384, 10848, 16384 };
        size_t o = 0;
        for (size_t i = 0; i < 5; i++) { rec_push(s + o, cut[i]); o += cut[i]; }
        check("  (разбивка стенда покрывает оба ответа)", (long)sn, (long)o);
        dup_event(&c->tag, EPOLLIN);
        check("DoT: ответ 65000 байт и следом другой в той же записи — оба доставлены", 2, g_ans);
        check("  соединение живо", CS_READY, c->st);
        free(a1); free(a2); free(s);
    }

    /* 3. DoH по HTTP/1.1, ответ кусками (Transfer-Encoding: chunked) больше 4 КиБ. С длиной
     *    (Content-Length) такой ответ принимался, кусками — отвергался, и соединение рвалось. */
    {
        struct dup *up = mk_up("https://127.0.0.1/dns-query");
        struct dconn *c = add_conn(up, CS_READY, 0);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        check("DoH/1.1: вопрос ушёл", 0, nth_req(up, 0) ? nth_req(up, 0)->ci : -9);
        const size_t al = 5000;
        uint8_t *a = mk_answer(nth_req(up, 0), al);
        a[0] = a[1] = 0;
        char hd[160];
        int hn = snprintf(hd, sizeof(hd), "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n"
                                          "Transfer-Encoding: chunked\r\n\r\n%zx\r\n", al);
        uint8_t *rec = malloc((size_t)hn + al + 16);
        memcpy(rec, hd, (size_t)hn);
        memcpy(rec + hn, a, al);
        memcpy(rec + hn + al, "\r\n0\r\n\r\n", 7);
        rec_push(rec, (size_t)hn + al + 7);
        dup_event(&c->tag, EPOLLIN);
        check("  ответ кусками в 5000 байт доставлен", 1, g_ans);
        check("  длина ответа", (long)al, (long)g_last_n);
        check("  соединение живо", CS_READY, c->st);
        free(a); free(rec);
    }

    /* 4. HTTP/2: номера потоков на соединении кончились. Такое соединение обязано перестать брать
     *    вопросы (как после GOAWAY), иначе диспетчер выбирал его снова и снова и вопросы ждали срока,
     *    хотя рядом есть исправное. */
    {
        struct dup *up = mk_up("https://127.0.0.1/dns-query");
        struct dconn *c0 = add_conn(up, CS_READY, 1);
        struct dconn *c1 = add_conn(up, CS_READY, 1);
        c0->h2_next = 0x7FFFFFF1u;
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        struct dreq *r = nth_req(up, 0);
        check("h2: номера потоков кончились — вопрос ушёл по второму соединению", 1, r ? r->ci : -9);
        check("  первое больше вопросов не берёт", 1, c0->h2_go || c0->st == CS_FREE);
        (void)c1;
    }

    /* 5. HTTP/2: просроченный вопрос на молчащем соединении рвёт его, а остальные вопросы этого
     *    соединения переставляются в ожидание — и должны сразу уйти по другому соединению, а не
     *    ждать до своего срока, пока кто-нибудь не спросит апстрим снова. */
    {
        struct dup *up = mk_up("https://127.0.0.1/dns-query");
        struct dconn *c0 = add_conn(up, CS_READY, 1);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        struct dreq *r1 = nth_req(up, 0), *r2 = nth_req(up, 1);
        check("h2: оба вопроса — потоками одного соединения", 2, c0->busy);
        add_conn(up, CS_READY, 1);
        c0->qrx_ms = now_ms() - 10000;
        r1->deadline = now_ms() - 1;
        req_rekey(r1);
        dup_tick();
        check("  первый вопрос — отказ по сроку", 1, g_fail);
        check("  молчащее соединение закрыто", CS_FREE, c0->st);
        check("  второй вопрос сразу ушёл по второму соединению", 1, r2->used ? r2->ci : -9);
    }

    /* 6. DoT: соединение, по которому с ухода вопроса не пришло ни байта, к сроку вопроса мертво
     *    (путь пропал без RST). Его надо закрыть, как у DoH и DoQ, иначе все вопросы апстрима идут в
     *    него до тех пор, пока ядро не бросит повторы TCP — это десятки минут. Соединение, по
     *    которому ответы идут, при этом не трогается. */
    {
        struct dup *up = mk_up("tls://127.0.0.1");
        struct dconn *c = add_conn(up, CS_READY, 0);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        c->qrx_ms = now_ms() + 1;                 /* после ухода вопросов от сервера что-то пришло */
        nth_req(up, 0)->deadline = now_ms() - 1;
        req_rekey(nth_req(up, 0));
        dup_tick();
        check("DoT: вопрос просрочен, но сервер отвечает — соединение живо", CS_READY, c->st);
        check("  отказ получил только просроченный", 1, g_fail);
        c->qrx_ms = now_ms() - 10000;
        nth_req(up, 0)->deadline = now_ms() - 1;
        req_rekey(nth_req(up, 0));
        dup_tick();
        check("  вопрос просрочен на молчащем соединении — соединение закрыто", CS_FREE, c->st);
    }

    /* 6а. Сроки вопросов — куча (I-536): каскад из тысячи просроченных вопросов снимается одним
     *     тиком, каждый получает отказ ровно один раз; живой вопрос с далёким сроком не тронут, и
     *     сон цикла (dup_wait_ms) считается по его сроку, а не по просроченным. */
    {
        struct dup *up = mk_up("tls://127.0.0.1");
        struct dconn *c = add_conn(up, CS_READY, 0);
        c->qrx_ms = now_ms() + 1;                  /* сервер отвечает: соединение при отказах не рвётся */
        enum { N = 1000 };
        for (int i = 0; i < N + 1; i++) dup_ask(0, g_qbuf, qn, on_done, NULL);
        int ok = 1;
        for (int i = 0; i < N; i++) {
            struct dreq *r = nth_req(up, i);
            if (!r) { ok = 0; break; }
            r->deadline = now_ms() - 1 - (i * 7919) % 500;      /* сроки вперемешку */
            req_rekey(r);
        }
        check("куча: все вопросы поставлены", 1, ok);
        dup_tick();
        check("куча: просроченные получили отказ все и по одному разу", N, g_fail);
        check("куча: живой вопрос остался", 1, dup_busy());
        int w = dup_wait_ms();
        check("куча: сон цикла — по сроку живого вопроса, не ноль", 1, w > 1000);
        dup_tick();
        check("куча: повторный тик ничего не добавил", N, g_fail);
    }

    /* 7. tcp://: соединение, которое не устанавливается (SYN уходит в никуда), держит место
     *    «соединяемся» столько, сколько ядро повторяет SYN (около двух минут), и новое не заводится —
     *    все вопросы апстрима всё это время получают отказ по сроку. Срок установки — как у TLS. */
    {
        struct dup *up = mk_up("tcp://127.0.0.1");
        struct dconn *c = add_conn(up, CS_TCPCONN, 0);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        check("tcp: вопрос ждёт соединения", -1, nth_req(up, 0) ? nth_req(up, 0)->ci : -9);
        c->last_ms = now_ms() - DUP_DIAL_MS - 1;
        dup_tick();
        check("  соединение, не установившееся за срок, закрыто", CS_FREE, c->st);
        check("  ждавший вопрос получил отказ сразу", 1, g_fail);
    }

    /* 8. DoQ: соединение держится с PING. Настройка доходит до обёртки через настоящий путь —
     *    вопрос, поток поиска адреса (адрес записан в url, искать нечего), quic_start. Без PING о
     *    мёртвом пути узнавал первый вопрос после паузы: полторы секунды тишины и рукопожатие. */
    {
        struct dup *up = mk_up("quic://127.0.0.1");
        int was = g_qopen;
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        for (int i = 0; i < 50 && g_qopen == was; i++) {
            struct epoll_event ev;
            if (epoll_wait(g_epfd, &ev, 1, 100) == 1) dup_event(ev.data.ptr, ev.events);
        }
        check("DoQ: соединение открыто через обёртку", was + 1, g_qopen);
        check("  PING при молчании — раз в 15 с", 15000, (long)g_qcfg.keepalive_ms);
        check("  срок простоя QUIC длиннее срока PING", 1, g_qcfg.idle_ms > g_qcfg.keepalive_ms);
        (void)up;
    }

    /* 9. DoQ: срок «сервер молчит». На соединении, где пакеты идут (PING подтверждается), он
     *    прежний — полторы секунды. На соединении, молчавшем дольше PING ещё до вопроса, — 400 мс:
     *    путь, скорее всего, мёртв, и клиенту незачем ждать полторы секунды, чтобы в этом убедиться. */
    {
        struct dup *up = mk_up("quic://127.0.0.1");
        struct dconn *c = add_quic(up);
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        struct dreq *r = nth_req(up, 0);
        check("DoQ: вопрос ушёл потоком готового соединения", 0, r ? r->ci : -9);
        int w = dup_wait_ms();
        check("  соединение не молчало: срок «сервер молчит» — 1,5 с", 1, w > 1300 && w <= 1500);
        dup_tick();
        check("  и до срока соединение живо", CS_READY, c->st);

        up = mk_up("quic://127.0.0.1");
        c = add_quic(up);
        c->qrx_ms = now_ms() - 18000;             /* PING ушёл три секунды назад, ответа нет */
        dup_ask(0, g_qbuf, qn, on_done, NULL);
        r = nth_req(up, 0);
        check("DoQ: вопрос ушёл на молчавшее соединение", 0, r ? r->ci : -9);
        w = dup_wait_ms();
        check("  срок «сервер молчит» — 400 мс", 1, w > 200 && w <= 400);
        r->t0 -= 450;                             /* 450 мс спустя: от сервера по-прежнему ни пакета */
        c->qrx_ms -= 450;
        req_rekey(r);
        dup_tick();
        check("  срок вышел: молчавшее соединение закрыто", 1, c->qc == NULL);
        check("  вопрос не отказан, а ждёт нового соединения (одна попытка)", 1,
              g_fail == 0 && r->used && r->tries == 1);
    }

    /* 10. DoQ без вопросов: PING и его повторы остались без ответа — соединение закрывается сразу, не
     *     дожидаясь вопроса клиента, и цикл просыпается к этому сроку сам. Соединение, по которому
     *     пакеты идут, держится — но не дольше срока простоя: тот считается от последнего вопроса,
     *     и подтверждения PING его не продлевают. */
    {
        struct dup *up = mk_up("quic://127.0.0.1");
        struct dconn *c = add_quic(up);
        c->qrx_ms = now_ms() - 10000;
        int w = dup_wait_ms();
        check("DoQ: цикл проснётся к сроку «PING без ответа» (20 с молчания)", 1, w > 9000 && w <= 10001);
        dup_tick();
        check("  десять секунд тишины — соединение живо", CS_READY, c->st);
        c->qrx_ms = now_ms() - 21000;
        dup_tick();
        check("  PING без ответа: соединение закрыто без вопроса клиента", CS_FREE, c->st);
        check("  готового соединения у сервера нет (группа шагнёт раньше)", 0, dup_warm(up));

        up = mk_up("quic://127.0.0.1");
        c = add_quic(up);
        check("DoQ: готовое соединение, пакеты идут — вопрос уйдёт сразу", 1, dup_warm(up));
        c->last_ms = now_ms() - 300001;           /* последний вопрос — больше пяти минут назад */
        dup_event(&c->tag, EPOLLIN);              /* а пакет от сервера (подтверждение PING) — только что */
        check("  пакет от сервера учтён", 1, now_ms() - c->qrx_ms < 1000);
        dup_tick();
        check("  PING срок простоя не продлевает: соединение закрыто", CS_FREE, c->st);
    }

    /* 11. Группа failover: шаг к следующему серверу. У первого готовое соединение — следующего
     *     спрашивают через полторы секунды молчания; готового нет (идёт рукопожатие) — через 350 мс:
     *     после простоя первая пачка вопросов ждала рукопожатия первого сервера полторы секунды. */
    {
        mk_group();
        struct dconn *a = add_conn(g_dups[0], CS_READY, 0);
        struct dconn *b = add_conn(g_dups[1], CS_READY, 0);
        dup_ask(2, g_qbuf, qn, on_done, NULL);
        check("группа: вопрос ушёл первому серверу", 1, a->busy);
        check("  второму — нет", 0, b->busy);
        long left = grp_deadline() - now_ms();
        check("  шаг к следующему — через 1,5 с", 1, left > 1300 && left <= 1500);

        mk_group();
        a = add_conn(g_dups[0], CS_DIAL, 0);      /* первый сервер ещё соединяется */
        a->tls = NULL;
        b = add_conn(g_dups[1], CS_READY, 0);
        dup_ask(2, g_qbuf, qn, on_done, NULL);
        check("группа: первый сервер без готового соединения — вопрос ждёт его", 0, b->busy);
        left = grp_deadline() - now_ms();
        check("  шаг к следующему — через 350 мс", 1, left > 200 && left <= 350);
        a->st = CS_FREE;                          /* стенд собрал его руками: потока установки нет */
    }

    /* 12. Группа failover: сервер после паузы. Он снова первый и проверяется настоящим вопросом, но
     *     клиент проверку не ждёт: вместе с ним сразу спрошен следующий, и ответ — первого, кто
     *     ответил годно. Годный ответ вернувшегося снимает испытание. */
    {
        mk_group();
        struct dup *g = g_dups[2];
        struct dconn *a = add_conn(g_dups[0], CS_READY, 0);
        struct dconn *b = add_conn(g_dups[1], CS_READY, 0);
        g->gp[0].step_ms = 5000;                  /* отказывал; пауза кончилась секунду назад */
        g->gp[0].fail_ms = now_ms() - 6000;
        g->gp[0].until_ms = now_ms() - 1000;
        dup_ask(2, g_qbuf, qn, on_done, NULL);
        check("группа: сервер после паузы спрошен первым", 1, a->busy);
        check("  и сразу же — следующий", 1, b->busy);
        push_dot_answer(nth_req(g_dups[1], 0));
        dup_event(&b->tag, EPOLLIN);
        check("  клиенту ушёл ответ следующего, не дожидаясь вернувшегося", 1, g_ans);
        check("  вернувшийся ещё на испытании", 5000, g->gp[0].step_ms);
        push_dot_answer(nth_req(g_dups[0], 0));
        dup_event(&a->tag, EPOLLIN);
        check("  ответил годно — испытание снято", 0, g->gp[0].step_ms);
        check("  второго ответа клиент не получил", 1, g_ans);
        dup_ask(2, g_qbuf, qn, on_done, NULL);
        check("  дальше — как обычно: вопрос только первому", 1, a->busy == 1 && b->busy == 0);
    }

    /* 13. Пауза члена группы: пачка вопросов, бывших в пути, когда сервер отказал, — один сбой.
     *     Каждый отказ пачки удваивал паузу, и страница в двадцать вопросов за один миг доводила её
     *     до предела в пять минут. */
    {
        mk_group();
        struct dup *g = g_dups[2];
        struct dconn *a = add_conn(g_dups[0], CS_READY, 0);
        add_conn(g_dups[1], CS_READY, 0);
        for (int i = 0; i < 20; i++) dup_ask(2, g_qbuf, qn, on_done, NULL);
        check("пауза: двадцать вопросов у первого сервера", 20, a->busy);
        a->qrx_ms = now_ms() + 1;                 /* сервер шлёт что-то, но не ответы: соединение живо */
        usleep(2000);                             /* отказ — позже отправки */
        for (int i = 0; i < 20; i++) {
            struct dreq *r = nth_req(g_dups[0], i);
            r->deadline = now_ms() - 1;
            req_rekey(r);
        }
        dup_tick();
        check("  все двадцать отказаны по сроку", 20, (long)g->gp[0].fail);
        check("  пауза — первая (5 с), а не удвоенная двадцать раз", 5000, g->gp[0].step_ms);
    }

    /* 14. Группу убрали (перенастройка), когда её вопрос ждал шага к следующему серверу: первый уже
     *     отказал, следующего спросит ближайший виток. Спрашивать больше некого — вопрос обязан
     *     закончиться отказом на этом витке, а не висеть вечно: вызывающий не получал ответа вовсе, а
     *     цикл считал, что у группы есть работа, и не засыпал. */
    {
        mk_group();
        add_conn(g_dups[0], CS_READY, 0);
        add_conn(g_dups[1], CS_READY, 0);
        dup_ask(2, g_qbuf, qn, on_done, NULL);
        /* Новая настройка без этих серверов и группы: первый сервер уходит раньше группы и отдаёт
         * её вопросу отказ, пока группа ещё жива. */
        struct dup_cfg none;
        memset(&none, 0, sizeof(none));
        snprintf(none.u.name, sizeof(none.u.name), "other");
        dup_apply(&none, 1);
        check("группа убрана посреди обхода: ответа клиент не получил", 0, g_ans);
        dup_tick();
        check("  вопрос группы закончен отказом", 1, g_fail);
        check("  у групп работы не осталось", 0, grp_busy());
    }

    dup_apply(NULL, 0);
    for (int i = 0; i < g_peer_n; i++) close(g_peer[i]);
    return unit_done("dupconnmatch");
}
