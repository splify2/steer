/* Соединения апстримов резолвера без сети и без TLS: DoT, DoH по HTTP/1.1 и HTTP/2, TCP.
 *
 * Стенд линкуется с src/dnsd/dup.c (объекты цикла — в dupint.h) и подменяет слой TLS: вместо
 * tls13_read/tls13_write — очередь «записей», которую задаёт проверка, и счётчик отправленного.
 * Соединение собирается прямо в таблице апстрима в состоянии «готово», как его оставил бы поток
 * установки (dial_event_cb), — рукопожатия и сети нет. Проверяется то, что происходит в цикле
 * событий: разбор пришедшего, сроки, перестановка вопросов между соединениями.
 *
 * Кадры и HPACK без соединения — tests/dupmatch.c; настоящие серверы — tests/dnsup.sh,
 * tests/doh2up.sh. */
#define _GNU_SOURCE
#include "dnsd_int.h"
#include "dupint.h"
#include "doh2.h"
#include "tls13.h"
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

/* ---- проверки ----------------------------------------------------------------------------- */


static int g_ans, g_fail;
static size_t g_last_n;
static void on_done(void *ctx, const uint8_t *ans, size_t n, const uint8_t *q, size_t qn) {
    (void)ctx; (void)q; (void)qn;
    if (ans) { g_ans++; g_last_n = n; } else g_fail++;
}

static int g_peer[64], g_peer_n;

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

    dup_apply(NULL, 0);
    for (int i = 0; i < g_peer_n; i++) close(g_peer[i]);
    return unit_done("dupconnmatch");
}
