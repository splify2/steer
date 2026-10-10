/* Апстримы резолвера: цикл событий, очередь вопросов, транспорты UDP, TCP, DoT, DoH и DoQ.
 * Устройство, доводы и границы — в шапке dup.h; установка соединения TLS — в dupdial.c.
 *
 * КАК УСТРОЕНО. Вопрос (dup_ask) получает запись в таблице запросов и уходит на транспорт
 * апстрима:
 *   - UDP — датаграмма из подключённого сокета апстрима, с одной повторной отправкой через
 *     1,5 с; усечённый ответ (TC) переигрывается по TCP к тому же серверу;
 *   - TCP и DoT — сообщения с длиной в два байта (RFC 1035, RFC 7858) по одному долгоживущему
 *     соединению, вопросы идут по нему вперемешку и сопоставляются с ответами по номеру
 *     транзакции: номер у каждого вопроса свой на апстрим, а не тот, что дал вызывающий (исходный
 *     возвращается в ответе). DoT отличается от TCP только слоем TLS;
 *   - DoH — POST application/dns-message поверх TLS (RFC 8484). В ALPN предлагается «h2,
 *     http/1.1», дальше — по выбору сервера, потому что RFC 8484 требует от сервера поддержки
 *     HTTP/2, а HTTP/1.1 — нет (Quad9 отвечает на него кодом 505).
 *     HTTP/2 (кадры и HPACK — doh2.c): одно соединение на апстрим и по потоку на вопрос, вопросы
 *     идут вперемешку и обгоняют друг друга; число одновременных потоков — то, что сервер объявил
 *     (SETTINGS_MAX_CONCURRENT_STREAMS), сверх этого вопрос ждёт закрытия чужого потока. Свой клиент
 *     h2.c для этого не годится: он ведёт один поток для xsteer и мультиплексировать не умеет.
 *     HTTP/1.1: keep-alive, соединение на каждый ожидающий вопрос (пул растёт по нагрузке до
 *     предела дескрипторов, dup_conn_limit), на каждом один вопрос за раз; следующий ждёт
 *     свободного или нового соединения. Номер в теле — 0 в обоих случаях, как рекомендует RFC 8484
 *     (кэшируемость), а исходный возвращается в ответе.
 *   - DoQ (RFC 9250) — QUIC поверх обёртки src/proto/quic (ngtcp2 на wolfSSL), ALPN `doq`. Одно
 *     долгоживущее соединение на апстрим (пока нужно — одно: потоков QUIC хватает на все вопросы),
 *     и КАЖДЫЙ ВОПРОС — СВОЙ двунаправленный поток: запрос (длина, сообщение с номером 0) и FIN,
 *     ответ (длина, сообщение) на том же потоке. Сопоставление с вопросом — по потоку, а не по
 *     номеру, поэтому вопросы обгоняют друг друга без склейки и потеря одного пакета не задерживает
 *     остальные вопросы (в TCP, а значит в DoT, задержала бы). Кадры и коды — doq.c. Рукопожатие
 *     QUIC не блокирует ничего: qc_open только создаёт сокет и шлёт первый пакет, дальше его ведут
 *     события того же epoll и таймер qc_timeout_ms (dup_wait_ms), а потоку dial остаётся найти
 *     адреса сервера через bootstrap. Сокет соединения метится меткой выхода (sock_mark), как и
 *     остальные. Новое соединение, для сервера которого есть билет прошлой сессии, берёт вопросы
 *     до конца рукопожатия (0-RTT, dupq_early_ready в pick_conn); сервер, отвергший 0-RTT, получает
 *     их заново на том же соединении (on_early_rejected, quic_after). Без билета — полное
 *     рукопожатие, и платить его приходится раз на простой в DUP_IDLE_MS.
 * Соединение TLS создаётся потоком (dial), сокет тогда переходит циклу. Пока соединения нет,
 * вопросы ждут в той же таблице (ci < 0); не установилось — все ожидающие получают отказ сразу,
 * а следующая попытка — через растущую паузу (1, 2, 4 ... 30 с). Обрыв соединения под вопросом —
 * вопрос переставляется в ожидание один раз (сервер закрыл простаивающее соединение как раз
 * тогда, когда мы его выбрали: это обычное дело), второй раз — отказ.
 *
 * СРОКИ. Вопрос живёт не дольше DUP_REQ_MS (4 с, меньше PENDING_TTL_SEC резолвера, чтобы отказ
 * успел дойти до клиента SERVFAIL, а не молчанием). У DoH просроченный вопрос рвёт своё
 * соединение: состояние протокола на нём неизвестно, а запоздавший ответ склеился бы со
 * следующим вопросом. Простаивающее соединение закрывается через DUP_IDLE_MS.
 *
 * ПАМЯТЬ. Объекты апстримов лежат в статическом хранилище и не освобождаются: адреса внутри них
 * (метки epoll) переживают перенастройку, и запоздалое событие закрытого апстрима попадает в
 * живую, пусть и чужую по содержимому, память. Соединение занимает struct tls13 (около 17 КБ) и
 * буфер чтения; их нет, пока соединения нет. */

#define _GNU_SOURCE
#include <stdarg.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include "dnsd_int.h"
#include "dupint.h"
#include "tls13.h"
#include "doq.h"
#include "doh2.h"
#include "dupq.h"

/* Обёртка QUIC — через шов dupq.h, слабыми ссылками, как и TLS ниже: в статической базовой сборке
 * (без src/proto/quic) DoQ-апстрим отвечает причиной в status, а сборка не падает. В разделяемой
 * раскладке роутера символы отдаёт libsteer.so (build/libsteer.map; списки экспорта считают и
 * слабые ссылки — build/libs-exports.sh). */
extern int dupq_prepare(const char *roots) __attribute__((weak));
extern int dupq_ready(void) __attribute__((weak));
extern int dupq_open(const struct dupq_cfg *cfg, const struct dupq_ops *ops, void *user, struct dupq **out) __attribute__((weak));
extern void dupq_close(struct dupq *q, uint64_t app_err) __attribute__((weak));
extern void dupq_free(struct dupq *q) __attribute__((weak));
extern int dupq_fd(const struct dupq *q) __attribute__((weak));
extern int dupq_timeout_ms(struct dupq *q) __attribute__((weak));
extern int dupq_on_readable(struct dupq *q) __attribute__((weak));
extern int dupq_on_timer(struct dupq *q) __attribute__((weak));
extern int dupq_stream_open(struct dupq *q, int64_t *sid) __attribute__((weak));
extern int dupq_early_ready(const struct dupq *q) __attribute__((weak));
extern ssize_t dupq_stream_send(struct dupq *q, int64_t sid, const uint8_t *d, size_t n, int fin) __attribute__((weak));
extern int dupq_stream_reset(struct dupq *q, int64_t sid, uint64_t app_err) __attribute__((weak));

int dup_have_quic(void) {
    return dupq_prepare && dupq_ready && dupq_open && dupq_close && dupq_free && dupq_fd && dupq_timeout_ms &&
           dupq_on_readable && dupq_on_timer && dupq_stream_open && dupq_stream_send && dupq_stream_reset;
}

extern int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) __attribute__((weak));
extern int tls13_has_record(const struct tls13 *t) __attribute__((weak));
extern int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) __attribute__((weak));
extern void tls13_free(struct tls13 *t) __attribute__((weak));

/* СОЕДИНЕНИЙ НА АПСТРИМ НЕ «ТРИ», А СКОЛЬКО НУЖНО. Пул растёт по нагрузке: DoH открывает
 * соединение на каждый ожидающий вопрос (up_want_conns), когда все заняты, а простаивающие
 * закрываются через DUP_IDLE_MS. Пределом служит ресурс — дескрипторы процесса: четверть
 * RLIMIT_NOFILE (остальное нужно клиентам, сокетам апстримов и наборам), не меньше трёх. Упёрся —
 * вопросы ждут свободного соединения, а в состоянии апстрима (status) стоит причина с цифрой.
 * Раньше константа DUP_CONNS = 3 стояла и в размере массива, и в решении, и десять одновременных
 * запросов DoH шли через три соединения. */
#include <sys/resource.h>
static int dup_conn_limit(void) {
    static int lim;
    if (lim) return lim;
    struct rlimit rl;
    long v = 1024;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur != RLIM_INFINITY) v = (long)rl.rlim_cur;
    v /= 4;
    lim = v < 3 ? 3 : v > 65536 ? 65536 : (int)v;
    return lim;
}
/* Вопросов в полёте — тоже растущий пул блоками (req_ref): предел — очередь ожидающих резолвера
 * (MAX_PENDING в dnsd_int.h, защита от шторма запросов), а не размер массива здесь. */
#define DUP_REQ_BLOCK 64
/* DUP_QMAX — в dupint.h. */
#define DUP_REQ_MS 4000
#define DUP_UDP_RETRY_MS 1500
/* DoQ: вопрос без ответа через столько миллисекунд на соединении, которое за это время не подало
 * ни пакета, — знак мёртвого соединения (сервер перезапущен и не знает наших идентификаторов,
 * маршрут пропал): без него QUIC ждал бы своего срока простоя (DUP_IDLE_MS и больше), и DNS сети
 * молчал бы все эти минуты. Срок — тот же, что у повтора по UDP: за него живой сервер успевает
 * подтвердить пакет хотя бы на канале в сотни миллисекунд. Соединение пересоздаётся, вопрос
 * уходит на новом (один раз, как при любом обрыве). */
#define DUP_QUIC_DEAD_MS 1500
/* Срок простоя первого соединения. Пять минут; STEER_DNSD_IDLE_MS (не меньше 200) — только для стендов:
 * 0-RTT виден лишь на соединении, которое закрылось само, и ждать ради этого пять минут в тесте незачем
 * (tests/doqup.sh). */
#define DUP_IDLE_MS_DEFAULT 300000L
static long dup_idle_ms(void) {
    static long v;
    if (!v) {
        const char *e = getenv("STEER_DNSD_IDLE_MS");
        long n = e ? atol(e) : 0;
        v = n >= 200 ? n : DUP_IDLE_MS_DEFAULT;
    }
    return v;
}
#define DUP_IDLE_MS dup_idle_ms()
/* DUP_DIAL_MS — в dupint.h. */
/* Буфер чтения соединения: недочитанное сообщение с длиной (до 2 + 65535 байт, DoT и TCP) плюс одна
 * запись TLS целиком (TLS13_MAX_PLAIN), которая может нести его хвост и начало следующего. Прежние
 * 70 КиБ были меньше этой суммы (81 920), и ответ почти в 64 КиБ закрывал исправное соединение. */
#define DUP_RBUF_MAX (2 + 65535 + TLS13_MAX_PLAIN + 1024)
#define DUP_BACKOFF_MAX 30000

/* Состояния соединения и struct dconn, struct dup, struct dreq — в dupint.h (их смотрит стенд
 * tests/dupconnmatch.c). */

/* Хранилище объектов апстримов и таблица текущих — растут по числу апстримов; объекты (struct dup)
 * лежат каждый в своём блоке и не освобождаются (шапка, «ПАМЯТЬ»): освободившийся (live == 0)
 * берётся снова. */
static struct dup **g_store;
static size_t g_store_n, g_store_cap;
struct dup **g_dups;                /* dupint.h: видны стенду */
size_t g_dups_n;
static size_t g_dups_cap;
/* Вопросы в полёте — блоками по DUP_REQ_BLOCK: адрес вопроса стабилен (его держат вызовы
 * обратной связи), рост — новый блок. */
static struct dreq **g_reqb;
int g_req_cap;                      /* dupint.h */
               /* всего мест: кратно DUP_REQ_BLOCK */
struct dreq *req_ref(int k) { return &g_reqb[k / DUP_REQ_BLOCK][k % DUP_REQ_BLOCK]; }
#define RQ(k) (*req_ref(k))
static int req_grow(void) {
    struct dreq **nb = realloc(g_reqb, (size_t)(g_req_cap / DUP_REQ_BLOCK + 1) * sizeof(*nb));
    if (!nb) return -1;
    g_reqb = nb;
    struct dreq *blk = calloc(DUP_REQ_BLOCK, sizeof(*blk));
    if (!blk) return -1;
    for (int i = 0; i < DUP_REQ_BLOCK; i++) blk[i].slot = g_req_cap + i;
    g_reqb[g_req_cap / DUP_REQ_BLOCK] = blk;
    g_req_cap += DUP_REQ_BLOCK;
    return 0;
}
#define CN(up, i) ((up)->c[i])

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int sa_len(const struct sockaddr_storage *a) {
    return a->ss_family == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
}

/* Транспорты с долгоживущим соединением (состояние ready/connecting/down по соединению, а не по
 * ответам). */
static int stream_proto(const struct dup *up) {
    return up->cfg.u.proto == DNSP_TCP || up->cfg.u.proto == DNSP_DOT || up->cfg.u.proto == DNSP_DOH ||
           up->cfg.u.proto == DNSP_QUIC;
}
static int quic_proto(const struct dup *up) { return up->cfg.u.proto == DNSP_QUIC; }
static int tls_proto(const struct dup *up) {
    return up->cfg.u.proto == DNSP_DOT || up->cfg.u.proto == DNSP_DOH;
}

static void up_err(struct dup *up, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void up_err(struct dup *up, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(up->err, sizeof(up->err), fmt, ap);
    va_end(ap);
    up->err_ms = now_ms();
}

/* Конец секции вопроса пакета (после имени, типа и класса); 0 — не разобралось. */
static size_t qsec_end(const uint8_t *p, size_t n) {
    if (n < 17 || ((p[4] << 8) | p[5]) != 1) return 0;
    size_t off = 12;
    for (;;) {
        if (off >= n) return 0;
        uint8_t l = p[off];
        if (!l) { off++; break; }
        if (l & 0xC0) return 0;
        off += 1u + l;
    }
    return off + 4 <= n ? off + 4 : 0;
}

/* Вопрос ответа совпадает с вопросом запроса (без учёта регистра имени). */
static int same_question(const struct dreq *r, const uint8_t *a, size_t an) {
    size_t qe = qsec_end(r->q, r->qn);
    if (!qe || an < qe) return 0;
    for (size_t i = 12; i < qe; i++) {
        uint8_t x = r->q[i], y = a[i];
        if (x >= 'A' && x <= 'Z') x = (uint8_t)(x + 32);
        if (y >= 'A' && y <= 'Z') y = (uint8_t)(y + 32);
        if (x != y) return 0;
    }
    return 1;
}

/* ---- запросы --------------------------------------------------------------------------------- */

static void h2_rst(struct dconn *c, uint32_t sid, uint32_t code);

static void req_finish(struct dreq *r, uint8_t *ans, size_t n) {
    uint8_t q[DUP_QMAX];
    uint16_t qn = r->qn;
    memcpy(q, r->q, qn);
    dup_done_fn cb = r->cb;
    void *ctx = r->ctx;
    struct dup *up = r->up;
    if (quic_proto(up) && r->ci >= 0 && r->ci < up->c_n) {
        struct dconn *c = CN(up, r->ci);
        /* Брошенный вопрос (таймаут, отказ) — сбросить его поток кодом «запрос отменён» (RFC 9250,
         * 4.3): сервер перестаёт работать над ответом, а поток освобождается под следующий вопрос.
         * Поток, дочитанный до конца или уже закрытый, не трогаем. */
        if (!ans && r->sid >= 0 && c->qc && !c->qclosed && !r->rxfin && dupq_stream_reset)
            dupq_stream_reset(c->qc, r->sid, DOQ_REQUEST_CANCELLED);
        if (r->sid >= 0 && c->busy > 0) c->busy--;
    }
    if (up->cfg.u.proto == DNSP_DOH && r->sid >= 0 && r->ci >= 0 && r->ci < up->c_n) {
        struct dconn *c = CN(up, r->ci);
        /* HTTP/2: брошенный вопрос (таймаут, ошибка сервера в ответе) — сбросить поток кодом CANCEL,
         * чтобы сервер не работал над ответом, а его место в пределе потоков освободилось. Поток,
         * дочитанный до конца, не трогаем. Соединение, уже закрытое (conn_close), не в счёт: у него
         * busy обнулён. */
        if (c->h2 && c->st == CS_READY) {
            if (!ans && !r->rxfin) h2_rst(c, (uint32_t)r->sid, H2D_E_CANCEL);
            if (c->busy > 0) c->busy--;
        }
    }
    uint8_t *rx = r->rx;            /* ans при DoQ и DoH/h2 лежит внутри него: освободить после обратного вызова */
    r->rx = NULL;
    r->used = 0;
    if (ans) {
        ans[0] = (uint8_t)(r->oid >> 8);
        ans[1] = (uint8_t)r->oid;
        up->q_ok++;
        up->ok_ms = now_ms();
    } else {
        up->q_fail++;
    }
    cb(ctx, ans, n, q, qn);
    free(rx);
}

static struct dreq *req_at(int i) { return (i >= 0 && i < g_req_cap && RQ(i).used) ? &RQ(i) : NULL; }

/* ---- соединения ------------------------------------------------------------------------------ */

static void conn_free_bufs(struct dconn *c) {
    free(c->rb); free(c->wb);
    c->rb = c->wb = NULL;
    c->rn = c->rcap = c->wn = c->woff = 0;
}

static int cidx(const struct dconn *c) { return c->idx; }

static void up_kick(struct dup *up);

/* Закрыть соединение: вопросы на нём переставляются в ожидание (один раз) или получают отказ. */
static void conn_close(struct dconn *c, const char *why) {
    struct dup *up = c->up;
    int i = cidx(c);
    if (c->fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
    }
    if (c->tls) {
        if (tls13_free) tls13_free(c->tls);
        free(c->tls);
    }
    if (c->qc) {
        /* Живое соединение QUIC закрываем кодом (по умолчанию DOQ_NO_ERROR: простой, перенастройка);
         * dupq_close шлёт CONNECTION_CLOSE и вызывает on_closed — тот только ставит отметки. Сокет
         * закрывает dupq_free, из epoll он уходит до него. */
        struct dupq *q = c->qc;
        c->qc = NULL;
        if (!c->qclosed && dupq_close) dupq_close(q, c->qerr);
        if (c->qfd >= 0) epoll_ctl(g_epfd, EPOLL_CTL_DEL, c->qfd, NULL);
        if (dupq_free) dupq_free(q);
    }
    c->qfd = -1;
    c->qhs = c->qclosed = 0;
    c->qerr = DOQ_NO_ERROR;
    c->fd = -1;
    c->tls = NULL;
    int was_ready = c->st == CS_READY;
    c->st = CS_FREE;
    c->busy = 0;
    c->close_after = 0;
    c->hdr_done = 0;
    c->h2 = c->h2_go = 0;
    free(c->hb);
    c->hb = NULL;
    c->hbn = 0;
    conn_free_bufs(c);
    int had = 0;
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used || r->up != up || r->ci != i) continue;
        had = 1;
        if (r->tries < 1) {
            r->tries++;
            r->ci = -1;
            r->sid = -1;                                /* DoQ: поток погиб вместе с соединением */
            free(r->rx);
            r->rx = NULL;
            r->rxn = r->rxcap = 0;
            r->rxfin = r->rxbad = 0;
            r->hgot = 0;
        } else {
            req_finish(r, NULL, 0);
        }
    }
    /* Простаивающее соединение сервер закрывает по своему сроку — это не сбой; сбой — обрыв под
     * вопросом. */
    if (why && was_ready && had) up_err(up, "%s", why);
}

static int rb_reserve(struct dconn *c, size_t more) {
    if (c->rn + more > DUP_RBUF_MAX) return -1;
    if (c->rn + more > c->rcap) {
        size_t cap = c->rcap ? c->rcap : 2048;
        while (cap < c->rn + more) cap *= 2;
        uint8_t *nb = realloc(c->rb, cap);
        if (!nb) return -1;
        c->rb = nb;
        c->rcap = cap;
    }
    return 0;
}

static void conn_ev(struct dconn *c, uint32_t ev) {
    struct epoll_event e = {0};
    e.events = ev;
    e.data.ptr = &c->tag;
    epoll_ctl(g_epfd, EPOLL_CTL_MOD, c->fd, &e);
}

static void conn_register(struct dconn *c, uint32_t ev) {
    struct epoll_event e = {0};
    e.events = ev;
    e.data.ptr = &c->tag;
    epoll_ctl(g_epfd, EPOLL_CTL_ADD, c->fd, &e);
}

/* Отправить байты по соединению. 0 — ушло или поставлено в очередь; -1 — соединение сломано. */
static int conn_write(struct dconn *c, const uint8_t *b, size_t n) {
    if (c->tls) {
        if (!tls13_write || tls13_write(c->tls, b, n) != 0) return -1;
        return 0;
    }
    size_t done = 0;
    if (!c->wn) {
        ssize_t w = send(c->fd, b, n, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return -1;
            w = 0;
        }
        done = (size_t)w;
        if (done == n) return 0;
    }
    if (c->wn - c->woff + (n - done) > 256 * 1024) return -1;
    if (c->woff == c->wn) c->wn = c->woff = 0;
    uint8_t *nb = realloc(c->wb, c->wn + (n - done));
    if (!nb) return -1;
    c->wb = nb;
    memcpy(c->wb + c->wn, b + done, n - done);
    c->wn += n - done;
    conn_ev(c, EPOLLIN | EPOLLOUT);
    return 0;
}

/* Поставить вопрос r на готовое соединение c. */
static int conn_send(struct dup *up, struct dconn *c, struct dreq *r) {
    if (quic_proto(up)) {
        /* DoQ: новый двунаправленный поток, в нём один запрос и FIN (RFC 9250, 4.2). Потоков
         * больше нет (сервер разрешил столько-то одновременных) — QC_EAGAIN, вопрос остаётся в
         * очереди и уйдёт, когда закроется чей-то поток (quic_after зовёт up_kick). */
        uint8_t buf[2 + DUP_QMAX];
        size_t fn = doq_frame_query(buf, sizeof(buf), r->q, r->qn);
        int64_t sid = -1;
        if (!fn) return -1;
        int rc = dupq_stream_open(c->qc, &sid);
        if (rc == DUPQ_EAGAIN) return 1;
        if (rc != 0) return -1;
        ssize_t w = dupq_stream_send(c->qc, sid, buf, fn, 1);
        if (w != (ssize_t)fn) {
            /* Кадр в несколько сотен байт буфер отправки (1 МиБ) принимает целиком; иначе
             * соединение неисправно. Поток, открытый впустую, сбрасывается. */
            dupq_stream_reset(c->qc, sid, DOQ_INTERNAL_ERROR);
            return -1;
        }
        r->ci = cidx(c);
        r->sid = sid;
        c->busy++;
        c->last_ms = now_ms();
        up->q_sent++;
        up->q_early += c->st == CS_QHS;        /* до рукопожатия: 0-RTT (pick_conn пускает сюда только с билетом) */
        return 0;
    }
    if (c->h2) {
        /* HTTP/2: вопрос — новый поток, HEADERS и DATA с END_STREAM одной записью. Ждать (1), а не
         * отказывать, приходится при пределе потоков, объявленном сервером, и при исчерпанном окне
         * отправки: то и другое снимается кадром сервера (закрылся чужой поток, WINDOW_UPDATE,
         * SETTINGS), после которого conn_readable зовёт up_kick. */
        if (c->h2_next > 0x7FFFFFF0u) c->h2_go = 1;  /* номера кончились: как после GOAWAY (поле h2_go) */
        if (c->h2_go) return 1;
        if (c->busy >= 0 && (uint32_t)c->busy >= c->h2_maxs) return 1;
        if (c->h2_win < r->qn || c->h2_iwin < r->qn) return 1;
        char auth[160];
        if (up->cfg.u.port != 443) snprintf(auth, sizeof(auth), "%s:%u", up->cfg.u.host, up->cfg.u.port);
        else snprintf(auth, sizeof(auth), "%s", up->cfg.u.host);
        uint8_t buf[1200 + DUP_QMAX];
        size_t bn = h2d_request(buf, sizeof(buf), c->h2_next, auth, up->cfg.u.path, r->q, r->qn);
        if (!bn) return -1;
        if (conn_write(c, buf, bn) != 0) return -1;
        r->ci = cidx(c);
        r->sid = c->h2_next;
        r->hgot = 0;
        c->h2_next += 2;
        c->h2_win -= r->qn;
        c->busy++;
        c->last_ms = now_ms();
        up->q_sent++;
        return 0;
    }
    r->ci = cidx(c);
    if (up->cfg.u.proto == DNSP_DOH) {
        /* Порт в Host — только нестандартный (RFC 9110, 7.2), как у остальных HTTPS движка. */
        char auth[160], hdr[512];
        if (up->cfg.u.port != 443) snprintf(auth, sizeof(auth), "%s:%u", up->cfg.u.host, up->cfg.u.port);
        else snprintf(auth, sizeof(auth), "%s", up->cfg.u.host);
        int hn = snprintf(hdr, sizeof(hdr),
                          "POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/dns-message\r\n"
                          "Accept: application/dns-message\r\nContent-Length: %u\r\n\r\n",
                          up->cfg.u.path, auth, r->qn);
        if (hn <= 0 || (size_t)hn >= sizeof(hdr)) return -1;
        uint8_t buf[sizeof(hdr) + DUP_QMAX];
        memcpy(buf, hdr, (size_t)hn);
        memcpy(buf + hn, r->q, r->qn);
        buf[hn] = 0;                                   /* тело — с номером 0 */
        buf[hn + 1] = 0;
        c->busy = r->slot + 1;
        c->hdr_done = 0;
        c->chunked = 0;
        c->rn = 0;
        c->last_ms = now_ms();
        up->q_sent++;
        if (conn_write(c, buf, (size_t)hn + r->qn) != 0) return -1;
        return 0;
    }
    uint8_t buf[2 + DUP_QMAX];
    buf[0] = (uint8_t)(r->qn >> 8);
    buf[1] = (uint8_t)r->qn;
    memcpy(buf + 2, r->q, r->qn);
    c->busy++;
    c->last_ms = now_ms();
    up->q_sent++;
    return conn_write(c, buf, (size_t)r->qn + 2) == 0 ? 0 : -1;
}

/* ---- установка соединения -------------------------------------------------------------------- */

static void dial_event_cb(struct dial *d);
static void quic_start(struct dup *up, struct dconn *c, const struct sockaddr_storage *ad, int an);

static int up_conns_alive(const struct dup *up) {
    int n = 0;
    for (int i = 0; i < up->c_n; i++) n += CN(up, i)->st != CS_FREE;
    return n;
}

static int up_want_conns(const struct dup *up) {
    if (up->cfg.u.proto != DNSP_DOH) return 1;
    /* h2 (или ещё не знаем, что выберет сервер): одно соединение — вопросы идут потоками по нему.
     * Пока не знаем, не тратим рукопожатия на пачку соединений, из которых окажется нужно одно; если
     * сервер выберет http/1.1, пул вырастет со следующего кадра диспетчера. */
    if (up->hproto != 1) return 1;
    /* DoH по http/1.1: по соединению на ожидающий вопрос, но не больше предела дескрипторов (dup_conn_limit),
     * и уже идущие не считаются. */
    int waiting = 0, lim = dup_conn_limit();
    for (int k = 0; k < g_req_cap; k++)
        if (RQ(k).used && RQ(k).up == up && RQ(k).ci == -1) waiting++;
    return waiting > lim ? lim : (waiting ? waiting : 1);
}

static void fail_waiting(struct dup *up) {
    for (int k = 0; k < g_req_cap; k++)
        if (RQ(k).used && RQ(k).up == up && RQ(k).ci == -1) req_finish(&RQ(k), NULL, 0);
}

static void up_backoff(struct dup *up) {
    up->backoff_ms = up->backoff_ms ? up->backoff_ms * 2 : 1000;
    if (up->backoff_ms > DUP_BACKOFF_MAX) up->backoff_ms = DUP_BACKOFF_MAX;
    up->retry_at_ms = now_ms() + up->backoff_ms;
}

/* Начать соединение по TCP без TLS (tcp://): неблокирующий connect в цикле. */
static int tcp_dial(struct dup *up, struct dconn *c) {
    int fd = socket(up->srv.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (up->cfg.mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &up->cfg.mark, sizeof(up->cfg.mark)) != 0) {
        close(fd);
        return -1;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (const struct sockaddr *)&up->srv, (socklen_t)sa_len(&up->srv)) != 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    c->fd = fd;
    c->st = CS_TCPCONN;
    c->last_ms = now_ms();
    conn_register(c, EPOLLOUT);
    return 0;
}

static void *memdup(const void *p, size_t n) {
    void *q = malloc(n);
    if (q) memcpy(q, p, n);
    return q;
}

static void dial_free(struct dial *d) {
    if (!d) return;
    free(d->ips_own);
    free(d->boot_own);
    free(d);
}

static void up_dial(struct dup *up) {
    struct dconn *c = NULL;
    for (int i = 0; i < up->c_n; i++) if (CN(up, i)->st == CS_FREE) { c = CN(up, i); break; }
    if (!c) {
        /* Свободного нет — завести новое, пока не упёрлись в дескрипторы (dup_conn_limit). */
        if (up->c_n >= dup_conn_limit()) {
            up_err(up, "открытых соединений %d — предел (четверть дескрипторов процесса, RLIMIT_NOFILE)",
                   up->c_n);
            return;
        }
        if (up->c_n == up->c_cap) {
            int nc = up->c_cap ? up->c_cap * 2 : 4;
            struct dconn **np = realloc(up->c, (size_t)nc * sizeof(*np));
            if (!np) return;
            up->c = np;
            up->c_cap = nc;
        }
        c = calloc(1, sizeof(*c));
        if (!c) return;
        c->fd = -1;
        c->idx = up->c_n;
        up->c[up->c_n++] = c;
    }
    c->up = up;
    c->tag.magic = DTAG_MAGIC; c->tag.kind = DT_CONN; c->tag.obj = c;
    if (!tls_proto(up) && !quic_proto(up)) {
        if (tcp_dial(up, c) != 0) {
            up_err(up, "TCP: %s", strerror(errno));
            up_backoff(up);
            fail_waiting(up);
        }
        return;
    }
    struct dial *d = calloc(1, sizeof(*d));
    int sv[2] = { -1, -1 };
    if (!d || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
        dial_free(d);
        up_err(up, "нет ресурсов для соединения");
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    d->fd = -1;
    d->tag.magic = DTAG_MAGIC; d->tag.kind = DT_DIAL; d->tag.obj = d;
    d->rfd = sv[0]; d->wfd = sv[1];
    d->up = up; d->up_gen = up->gen; d->conn = cidx(c);
    d->u = up->cfg.u;
    /* Поток читает адреса сервера и bootstrap после того, как апстрим могли перенастроить, — у
     * него свои копии (освобождает dial_free), а не указатели в память апстрима. */
    if (d->u.ips_n) {
        d->ips_own = memdup(d->u.ips, d->u.ips_n * sizeof(*d->u.ips));
        d->u.ips = d->ips_own;
        if (!d->ips_own) d->u.ips_n = 0;
    }
    if (d->u.boot_n) {
        d->boot_own = memdup(d->u.boot, d->u.boot_n * sizeof(*d->u.boot));
        d->u.boot = d->boot_own;
        if (!d->boot_own) d->u.boot_n = 0;
    }
    d->mark = up->cfg.mark;
    d->doh = up->cfg.u.proto == DNSP_DOH;
    d->quic = quic_proto(up);
    d->timeout_ms = DUP_DIAL_MS;
    if (g_dup_ca_file) snprintf(d->ca, sizeof(d->ca), "%s", g_dup_ca_file);
    long now = now_ms();
    d->cached_n = up->ad_n;
    d->cached_fresh = up->ad_n && now < up->ad_exp_ms;
    for (int i = 0; i < up->ad_n; i++) d->cached[i] = up->ad[i];
    struct epoll_event e = {0};
    e.events = EPOLLIN;
    e.data.ptr = &d->tag;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, sv[0], &e) != 0 || dial_launch(d) != 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, sv[0], NULL);
        close(sv[0]); close(sv[1]);
        up_err(up, "%s", d->err[0] ? d->err : "соединение не начато");
        dial_free(d);
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    c->st = CS_DIAL;
    c->dial = d;
    up->dialing++;
}

static void dial_event_cb(struct dial *d) {
    char b;
    ssize_t k;
    do k = recv(d->rfd, &b, 1, 0); while (k < 0 && errno == EINTR);
    if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, d->rfd, NULL);
    close(d->rfd);
    struct dup *up = d->up;
    int same = up->live && up->gen == d->up_gen && !d->cancel;
    int alive = same && k > 0;
    struct dconn *c = CN(up, d->conn);
    if (same) { c->dial = NULL; up->dialing--; }
    if (!alive || d->rc != 0) {
        if (d->fd >= 0) close(d->fd);
        if (d->tls) { if (tls13_free) tls13_free(d->tls); free(d->tls); }
        if (same) {
            c->st = CS_FREE;
            up_err(up, "%s", d->err[0] ? d->err : "соединение не установилось");
            /* Найденные адреса не подошли — в следующий раз искать заново. */
            if (!d->res_n) up->ad_n = 0;
            up_backoff(up);
            fail_waiting(up);
        }
        dial_free(d);
        return;
    }
    if (d->res_n) {
        for (int i = 0; i < d->res_n; i++) up->ad[i] = d->res[i];
        up->ad_n = d->res_n;
        up->ad_exp_ms = now_ms() + d->res_ttl * 1000L;
    }
    if (d->quic) {
        /* Адреса найдены — дальше соединение QUIC ведёт цикл. Копия списка: dial_free отдаёт d. */
        struct sockaddr_storage ad[DIAL_MAXADDR];
        int an = d->addr_n;
        for (int i = 0; i < an; i++) ad[i] = d->addr[i];
        dial_free(d);
        quic_start(up, c, ad, an);
        return;
    }
    c->fd = d->fd;
    c->tls = d->tls;
    c->st = CS_READY;
    c->last_ms = now_ms();
    c->qrx_ms = c->last_ms;
    c->busy = 0;
    c->h2 = d->h2;
    c->h2_go = 0;
    c->h2_next = 1;
    c->h2_maxs = 100;           /* до SETTINGS сервера — минимум, который RFC 9113 (6.5.2) советует
                                 * поддерживать; настоящее число придёт кадром и заменит это */
    c->h2_win = c->h2_iwin = H2D_WINDOW_DEFAULT;
    if (up->cfg.u.proto == DNSP_DOH) up->hproto = d->h2 ? 2 : 1;
    up->backoff_ms = 0;
    up->retry_at_ms = 0;
    up->err[0] = '\0';
    dial_free(d);
    conn_register(c, EPOLLIN);
    if (c->h2) {
        uint8_t hello[64];
        size_t hn = h2d_hello(hello, sizeof(hello));
        if (!hn || conn_write(c, hello, hn) != 0) {
            conn_close(c, NULL);
            up_err(up, "HTTP/2: преамбула не ушла");
            up_backoff(up);
            fail_waiting(up);
            return;
        }
    }
    up_kick(up);
}

/* ---- DoQ: соединение QUIC и потоки вопросов --------------------------------------------------- */

static void q_on_hs(void *u) { ((struct dconn *)u)->qhs = 1; }
static void q_on_early_rej(void *u) { ((struct dconn *)u)->qerej = 1; }

static void q_on_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct dconn *c = u;
    struct dup *up = c->up;
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used || r->up != up || r->ci != cidx(c) || r->sid != sid) continue;
        /* Потолок буфера ответа — формат: длина сообщения 16 бит, значит кадр не больше 2 + 65535
         * (doq.h). Больше — сервер нарушил формат, и это видно уже здесь, до накопления гигабайтов. */
        if (r->rxn + n > 2u + DOQ_MSG_MAX) {
            r->rxbad = 1;
            r->rxfin = 1;
            c->qerr = DOQ_PROTOCOL_ERROR;
            return;
        }
        if (r->rxn + n > r->rxcap) {
            size_t cap = r->rxcap ? r->rxcap : 512;
            while (cap < r->rxn + n) cap *= 2;
            uint8_t *nb = realloc(r->rx, cap);
            if (!nb) { r->rxbad = 1; r->rxfin = 1; return; }
            r->rx = nb;
            r->rxcap = cap;
        }
        if (n) memcpy(r->rx + r->rxn, d, n);
        r->rxn += n;
        if (fin) r->rxfin = 1;
        return;
    }
}

static void q_on_sclose(void *u, int64_t sid, uint64_t app_err) {
    struct dconn *c = u;
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used || r->up != c->up || r->ci != cidx(c) || r->sid != sid) continue;
        r->rxfin = 1;
        if (app_err) r->rxbad = 1;
        return;
    }
}

static void q_on_closed(void *u, int reason, const char *why) {
    struct dconn *c = u;
    c->qclosed = 1;
    c->qreason = reason;
    snprintf(c->qwhy, sizeof(c->qwhy), "%s", why ? why : "");
}

/* Ответы, дошедшие до конца, — вопросам; остальное — отказы. Зовётся после возврата из qc_*, не из
 * обратных вызовов (см. struct dconn). */
static void quic_reap(struct dconn *c) {
    struct dup *up = c->up;
    for (int k = 0; k < g_req_cap && c->qc; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used || r->up != up || r->ci != cidx(c) || r->sid < 0) continue;
        const uint8_t *m = NULL;
        size_t ml = 0;
        int rc = doq_take_answer(r->rx, r->rxn, &m, &ml);
        if (rc == 1) {
            if (same_question(r, m, ml)) {
                c->last_ms = now_ms();
                req_finish(r, (uint8_t *)m, ml);        /* m — внутри r->rx; req_finish освободит его сам */
            } else {
                up_err(up, "ответ не на наш вопрос");
                req_finish(r, NULL, 0);
            }
        } else if (rc < 0) {
            up_err(up, "DoQ: ответ нарушает формат RFC 9250 (%zu байт на потоке)", r->rxn);
            c->qerr = DOQ_PROTOCOL_ERROR;
            r->rxfin = 1;                               /* поток не сбрасывать: сервер и так наказан */
            req_finish(r, NULL, 0);
        } else if (r->rxfin) {
            up_err(up, r->rxbad ? "DoQ: сервер сбросил поток вопроса" : "DoQ: поток закрыт без ответа");
            req_finish(r, NULL, 0);
        }
    }
}

/* Последствия события соединения: рукопожатие завершено, ответы розданы, соединение закрыто миром
 * или нами (нарушение формата). */
static void quic_after(struct dconn *c) {
    struct dup *up = c->up;
    if (!c->qc) return;
    if (c->st == CS_QHS && c->qhs && !c->qclosed) {
        if (c->qerej) {
            /* Сервер отверг 0-RTT (билет устарел, ключи билетов сменились): ушедшие до рукопожатия
             * вопросы пропали вместе с потоками. Вопрос DNS идемпотентен — они возвращаются в очередь и
             * уходят заново на этом же соединении, ставшем готовым; попытка не тратится, это не сбой
             * вопроса. Ответа на них не будет, поэтому ждать его нельзя. */
            int i = cidx(c);
            for (int k = 0; k < g_req_cap; k++) {
                struct dreq *r = &RQ(k);
                if (!r->used || r->up != up || r->ci != i) continue;
                r->ci = -1;
                r->sid = -1;
                free(r->rx);
                r->rx = NULL;
                r->rxn = r->rxcap = 0;
                r->rxfin = r->rxbad = 0;
            }
            c->busy = 0;
            c->qerej = 0;
            up->q_early_rej++;
        }
        c->st = CS_READY;
        c->last_ms = now_ms();
        up->backoff_ms = 0;
        up->retry_at_ms = 0;
        up->err[0] = '\0';
    }
    quic_reap(c);
    if (!c->qc) return;
    if (c->qclosed) {
        if (c->st == CS_QHS) {
            /* Не дошли до конца рукопожатия: отказ TLS (имя в сертификате, корни, ALPN), порт
             * закрыт, сервер молчит. Следующая попытка — с другого адреса из выдачи и не раньше
             * паузы, вопросы, что ждали, получают SERVFAIL сейчас. */
            up_err(up, "DoQ: рукопожатие с %.60s не удалось (%s)", up->cfg.u.host,
                   c->qwhy[0] ? c->qwhy : "нет ответа");
            up->qpos++;
            conn_close(c, NULL);
            up_backoff(up);
            fail_waiting(up);
        } else {
            /* Простаивающее соединение закрывается сервером или по молчанию (QC_CLOSE_IDLE) — не
             * сбой; сбой — закрытие под вопросами, о нём conn_close напишет в error. */
            char why[128];
            snprintf(why, sizeof(why), "DoQ: соединение закрыто (%s)", c->qwhy);
            conn_close(c, why);
        }
        return;
    }
    if (c->qerr != DOQ_NO_ERROR) conn_close(c, "DoQ: сервер нарушил протокол — соединение закрыто");
}

/* Событие сокета QUIC или таймера. */
static void quic_run(struct dconn *c, int timer) {
    if (!c->qc) return;
    if (timer) {
        dupq_on_timer(c->qc);
    } else {
        c->qrx_ms = now_ms();
        dupq_on_readable(c->qc);
    }
    quic_after(c);
    up_kick(c->up);
}

/* Открыть соединение QUIC по найденным адресам (вызов из dial_event_cb, поток свою часть сделал). */
static void quic_start(struct dup *up, struct dconn *c, const struct sockaddr_storage *ad, int an) {
    const char *err = NULL;
    char ip[64] = "";
    unsigned port = up->cfg.u.port;
    if (!dup_have_quic()) err = "в этой сборке нет QUIC: DoQ недоступен";
    else if (an <= 0) err = "нет адреса сервера";
    else if (!dupq_ready()) err = "нет корней для проверки сертификата DoQ";
    if (!err) {
        const struct sockaddr_storage *a = &ad[up->qpos % (unsigned)an];
        if (a->ss_family == AF_INET6) inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)a)->sin6_addr, ip, sizeof(ip));
        else inet_ntop(AF_INET, &((const struct sockaddr_in *)a)->sin_addr, ip, sizeof(ip));
        struct dupq_cfg cfg;
        memset(&cfg, 0, sizeof(cfg));
        cfg.host = ip;
        cfg.port = (uint16_t)port;
        cfg.sni = up->cfg.u.host;              /* имя апстрима: SNI и проверка сертификата, как у DoT */
        cfg.sock_mark = up->cfg.mark;          /* метка пути выхода на сокете до connect(); без неё
                                                * через выход не уйти — шов не откроет сокет */
        cfg.handshake_ms = DUP_DIAL_MS;
        /* Простой соединения обрываем мы сами (dup_tick, DUP_IDLE_MS) — с CONNECTION_CLOSE и кодом
         * DOQ_NO_ERROR; срок QUIC чуть длиннее, чтобы он не сработал первым молча. Сервер вправе
         * договориться о меньшем: тогда соединение уйдёт раньше и пересоздастся вопросом. */
        cfg.idle_ms = (unsigned)DUP_IDLE_MS + 30000u;
        cfg.early_data = 1;                    /* 0-RTT по билету, если он есть (dupq_early_ready) */
        struct dupq_ops ops = { .on_handshake = q_on_hs, .on_stream_data = q_on_data,
                                .on_stream_close = q_on_sclose, .on_closed = q_on_closed,
                                .on_early_rejected = q_on_early_rej };
        c->qhs = c->qclosed = c->qerej = 0;
        c->qerr = DOQ_NO_ERROR;
        c->qwhy[0] = '\0';
        int rc = dupq_open(&cfg, &ops, c, &c->qc);
        if (rc != 0) {
            c->qc = NULL;
            /* Код обёртки (src/proto/quic/quic.h, QC_E*) называем причиной: «код -3» из журнала ничего
             * не говорил тому, кто его читает. */
            const char *why = rc == -1 ? "неверный адрес или параметр" :
                              rc == -2 ? "не хватило памяти" :
                              rc == -3 ? "сокет UDP не открылся или не связался с адресом сервера" :
                              rc == -4 ? "не создался контекст TLS (корни сертификатов)" :
                              rc == -5 ? "ngtcp2 отказал при создании соединения" : "причина не названа";
            static char buf[256];
            snprintf(buf, sizeof(buf), "соединение QUIC не открылось: %s (код %d)", why, rc);
            err = buf;
        }
    }
    if (err) {
        c->st = CS_FREE;
        up_err(up, "DoQ: %s", err);
        up->qpos++;
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    c->fd = -1;
    c->qfd = dupq_fd(c->qc);
    c->qrx_ms = now_ms();
    c->st = CS_QHS;
    c->busy = 0;
    c->last_ms = now_ms();
    struct epoll_event e = {0};
    e.events = EPOLLIN;
    e.data.ptr = &c->tag;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, c->qfd, &e) != 0) {
        c->qfd = -1;
        conn_close(c, NULL);
        up_err(up, "DoQ: сокет не встал в epoll");
        up_backoff(up);
        fail_waiting(up);
        return;
    }
    /* Ждущие вопросы уходят сразу, если по билету разрешён 0-RTT (pick_conn); без билета соединение
     * ещё не готово, и up_kick ничего не сделает — вопросы уйдут по завершении рукопожатия (quic_after). */
    up_kick(up);
}

/* ---- диспетчер ожидающих --------------------------------------------------------------------- */

static struct dconn *pick_conn(struct dup *up) {
    struct dconn *best = NULL;
    for (int i = 0; i < up->c_n; i++) {
        struct dconn *c = CN(up, i);
        /* DoQ: соединение, у которого рукопожатие ещё идёт, но по билету прошлой сессии разрешён 0-RTT,
         * годится для вопроса уже сейчас — первый вопрос после переподключения не ждёт рукопожатия. */
        int early = c->st == CS_QHS && c->qc && !c->qclosed && dupq_early_ready && dupq_early_ready(c->qc);
        if (c->st != CS_READY && !early) continue;
        if (up->cfg.u.proto == DNSP_DOH && !c->h2) { if (!c->busy) return c; }
        else if (c->h2 && c->h2_go) continue;
        else if (!best || c->busy < best->busy) best = c;
    }
    return best;
}

static void up_kick(struct dup *up) {
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used || r->up != up || r->ci != -1) continue;
        struct dconn *c = pick_conn(up);
        if (!c) break;
        int sr = conn_send(up, c, r);
        if (sr == 1 && c->h2 && c->h2_go) {
            /* HTTP/2: на соединении кончились номера потоков. pick_conn его больше не выберет — вопрос
             * пробует следующее, а пустое закрывается сразу (с вопросами — когда ответит последний). */
            if (!c->busy) conn_close(c, NULL);
            k--;
            continue;
        }
        if (sr == 1) break;             /* DoQ: потоков пока нет — ждать закрытия чужого (quic_after) */
        if (sr != 0) { conn_close(c, "запись в соединение не удалась"); k = -1; }
        else if (c->qc && c->qclosed) { quic_after(c); k = -1; }  /* соединение умерло при отправке */
    }
    int waiting = 0;
    for (int k = 0; k < g_req_cap; k++) if (RQ(k).used && RQ(k).up == up && RQ(k).ci == -1) waiting++;
    if (!waiting) return;
    /* Соединение есть, вопросы ждут потоков, а не второго соединения (DoQ; DoH по h2). */
    if ((quic_proto(up) || (up->cfg.u.proto == DNSP_DOH && up->hproto == 2)) && pick_conn(up)) return;
    if (now_ms() < up->retry_at_ms) { fail_waiting(up); return; }
    int have = 0;
    for (int i = 0; i < up->c_n; i++)
        have += CN(up, i)->st == CS_DIAL || CN(up, i)->st == CS_TCPCONN || CN(up, i)->st == CS_QHS;
    if (have < up_want_conns(up)) {
        if (up_conns_alive(up) < up->c_n || up->c_n < dup_conn_limit()) up_dial(up);
        else up_err(up, "открытых соединений %d — предел (четверть дескрипторов процесса, "
                        "RLIMIT_NOFILE): вопросы ждут свободного", up->c_n);
    }
}

/* ---- чтение ---------------------------------------------------------------------------------- */

static struct dreq *find_by_wid(struct dup *up, int ci, uint16_t wid) {
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (r->used && r->up == up && r->ci == ci && r->wid == wid) return r;
    }
    return NULL;
}

static void stream_frames(struct dconn *c) {
    struct dup *up = c->up;
    size_t off = 0;
    while (c->rn - off >= 2) {
        size_t len = ((size_t)c->rb[off] << 8) | c->rb[off + 1];
        if (c->rn - off < 2 + len) break;
        uint8_t *m = c->rb + off + 2;
        if (len >= 12) {
            struct dreq *r = find_by_wid(up, cidx(c), (uint16_t)((m[0] << 8) | m[1]));
            if (r && same_question(r, m, len)) {
                if (c->busy > 0) c->busy--;
                req_finish(r, m, len);
            }
        }
        off += 2 + len;
    }
    if (off) {
        memmove(c->rb, c->rb + off, c->rn - off);
        c->rn -= off;
    }
}

static int ci_lower(const char *s, const char *word) {
    return strncasecmp(s, word, strlen(word)) == 0;
}

/* Разбор ответа HTTP по накопленным байтам. 1 — ответ целиком доставлен; 0 — ждём; -1 — соединение
 * негодно. */
static int doh_parse(struct dconn *c) {
    struct dup *up = c->up;
    if (!c->hdr_done) {
        uint8_t *e = NULL;
        for (size_t i = 0; i + 3 < c->rn; i++)
            if (!memcmp(c->rb + i, "\r\n\r\n", 4)) { e = c->rb + i; break; }
        if (!e) return c->rn > 16384 ? -1 : 0;
        size_t hl = (size_t)(e - c->rb);
        char *h = malloc(hl + 1);
        if (!h) return -1;
        memcpy(h, c->rb, hl);
        h[hl] = '\0';
        int code = 0;
        if (sscanf(h, "HTTP/1.%*d %d", &code) != 1) { free(h); return -1; }
        c->clen = -1;
        c->chunked = 0;
        c->close_after = 0;
        for (char *ln = strstr(h, "\r\n"); ln; ln = strstr(ln + 2, "\r\n")) {
            char *v = ln + 2;
            if (ci_lower(v, "content-length:")) c->clen = strtol(v + 15, NULL, 10);
            else if (ci_lower(v, "transfer-encoding:")) {
                char *t = v + 18;
                size_t l = strcspn(t, "\r\n");
                for (size_t i = 0; i + 7 <= l; i++) if (strncasecmp(t + i, "chunked", 7) == 0) c->chunked = 1;
            } else if (ci_lower(v, "connection:")) {
                char *t = v + 11;
                size_t l = strcspn(t, "\r\n");
                for (size_t i = 0; i + 5 <= l; i++) if (strncasecmp(t + i, "close", 5) == 0) c->close_after = 1;
            }
        }
        free(h);
        c->hdr_done = 1;
        c->body_off = hl + 4;
        if (code != 200) {
            up_err(up, "HTTP %d от сервера", code);
            return -1;
        }
        if (c->clen < 0 && !c->chunked) { up_err(up, "ответ HTTP без длины"); return -1; }
    }
    const uint8_t *body = c->rb + c->body_off;
    size_t have = c->rn - c->body_off;
    uint8_t *msg = NULL;
    size_t mlen = 0;
    /* Тело кусками собирается сюда. Предел — сообщение DNS (65535), как у тела с Content-Length: прежний
     * буфер в 4 КиБ (DUP_QMAX * 4 — размер ВОПРОСА) отвергал ответ кусками больше 4 КиБ и рвал соединение,
     * хотя тот же ответ с длиной проходил. Статический: цикл резолвера один, поток установки сюда не ходит. */
    static uint8_t dec[DOQ_MSG_MAX];
    if (c->chunked) {
        size_t o = 0, out = 0;
        int done = 0;
        while (o < have) {
            /* Строка размера куска: шестнадцатеричное число, возможно с расширением («;name=value»),
             * до CRLF. Длиннее 64 знаков — не ответ DNS. */
            char sz[65];
            size_t l = 0;
            while (o + l < have && body[o + l] != '\r' && l < sizeof(sz) - 1) { sz[l] = (char)body[o + l]; l++; }
            if (o + l + 2 > have) { if (l == sizeof(sz) - 1) return -1; break; }
            if (body[o + l] != '\r' || body[o + l + 1] != '\n') return -1;
            sz[l] = '\0';
            long cl = strtol(sz, NULL, 16);
            if (cl < 0 || (size_t)cl > sizeof(dec)) return -1;
            o += l + 2;
            if (cl == 0) { done = o + 2 <= have; break; }
            if (o + (size_t)cl + 2 > have) break;
            if (out + (size_t)cl > sizeof(dec)) return -1;
            memcpy(dec + out, body + o, (size_t)cl);
            out += (size_t)cl;
            o += (size_t)cl + 2;
        }
        if (!done) return 0;
        msg = dec;
        mlen = out;
    } else {
        if ((long)have < c->clen) return c->clen > DUP_RBUF_MAX ? -1 : 0;
        msg = c->rb + c->body_off;
        mlen = (size_t)c->clen;
    }
    struct dreq *r = req_at(c->busy - 1);
    c->busy = 0;
    c->hdr_done = 0;
    c->rn = 0;
    if (r && mlen >= 12 && same_question(r, msg, mlen)) {
        c->last_ms = now_ms();
        req_finish(r, msg, mlen);
    } else if (r) {
        up_err(up, "ответ не на наш вопрос");
        req_finish(r, NULL, 0);
    }
    return 1;
}

/* ---- DoH по HTTP/2 --------------------------------------------------------------------------- */

static void h2_rst(struct dconn *c, uint32_t sid, uint32_t code) {
    uint8_t b[16], body[4] = { (uint8_t)(code >> 24), (uint8_t)(code >> 16), (uint8_t)(code >> 8), (uint8_t)code };
    size_t n = h2d_frame_put(b, sizeof(b), H2D_RST_STREAM, 0, sid, body, 4);
    if (n) conn_write(c, b, n);
}

static struct dreq *find_by_sid(struct dup *up, int ci, uint32_t sid) {
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (r->used && r->up == up && r->ci == ci && r->sid == (int64_t)sid) return r;
    }
    return NULL;
}

/* Вопрос вернуть в ожидание: сервер его не обработал (GOAWAY за пределом last_stream_id, REFUSED_STREAM)
 * или соединение уходит. Поток на этом соединении закрыт, место в счётчике освобождается. */
static void h2_requeue(struct dconn *c, struct dreq *r) {
    if (c->busy > 0) c->busy--;
    r->ci = -1;
    r->sid = -1;
    free(r->rx);
    r->rx = NULL;
    r->rxn = r->rxcap = 0;
    r->rxfin = r->rxbad = 0;
    r->hgot = 0;
}

static int rx_append(struct dreq *r, const uint8_t *d, size_t n) {
    if (r->rxn + n > DOQ_MSG_MAX) return -1;            /* больше сообщения DNS не бывает */
    if (r->rxn + n > r->rxcap) {
        size_t cap = r->rxcap ? r->rxcap : 512;
        while (cap < r->rxn + n) cap *= 2;
        uint8_t *nb = realloc(r->rx, cap);
        if (!nb) return -1;
        r->rx = nb;
        r->rxcap = cap;
    }
    if (n) memcpy(r->rx + r->rxn, d, n);
    r->rxn += n;
    return 0;
}

/* Ответ потока получен целиком. */
static void h2_complete(struct dconn *c, struct dreq *r) {
    struct dup *up = c->up;
    r->rxfin = 1;
    if (r->rxn >= 12 && same_question(r, r->rx, r->rxn)) {
        c->last_ms = now_ms();
        req_finish(r, r->rx, r->rxn);
        return;
    }
    up_err(up, r->rxn < 12 ? "HTTP/2: ответ DoH пуст или короче заголовка DNS" : "ответ не на наш вопрос");
    req_finish(r, NULL, 0);
}

/* Блок заголовков ответа (целиком). 0 — принят; -1 — блок негоден (нарушение протокола). */
static int h2_headers(struct dconn *c, uint32_t sid, const uint8_t *blk, size_t n, int fin) {
    struct dup *up = c->up;
    struct dreq *r = find_by_sid(up, cidx(c), sid);
    int st = h2d_status(blk, n);
    if (st < 0) return -1;
    if (!r) return 0;                                   /* поток уже закрыт нашей стороной */
    if (st == 0) {                                      /* трейлеры: тело кончилось, больше ничего */
        if (r->hgot && fin) h2_complete(c, r);
        return 0;
    }
    if (st < 200) return 0;                             /* 1xx: настоящий ответ впереди */
    if (st != 200) {
        /* Причина отказа сервера доходит до dns-log как есть. Раньше она терялась в общем «нет
         * ответа за N мс» (dup_tick перезаписывал error). Quad9 на HTTP/1.1 — 505. */
        up_err(up, "HTTP %d от сервера", st);
        r->rxfin = fin;
        req_finish(r, NULL, 0);
        return 0;
    }
    r->hgot = 1;
    if (fin) h2_complete(c, r);
    return 0;
}

/* Разбор накопленных в c->rb кадров. 0 — разобрано (осталась неполная часть); -1 — соединение закрыто
 * (нарушение протокола или GOAWAY без вопросов), c больше не трогать. */
static int h2_frames(struct dconn *c) {
    struct dup *up = c->up;
    size_t off = 0;
    uint64_t owed = 0;
    const char *bad = NULL;
    char nb[24];
    for (;;) {
        struct h2d_frame f;
        int fr = h2d_next(c->rb + off, c->rn - off, &f);
        if (fr < 0) { bad = "кадр длиннее 16 КиБ"; break; }
        if (!fr) break;
        const uint8_t *b = f.body;
        /* Блок заголовков, начатый HEADERS без END_HEADERS, продолжают только CONTINUATION того же
         * потока (RFC 9113, 6.10). */
        if (c->hb && (f.type != H2D_CONTINUATION || f.sid != c->hb_sid)) { bad = "блок заголовков прерван"; break; }
        switch (f.type) {
        case H2D_SETTINGS: {
            if (f.flags & H2D_F_ACK) break;
            if (f.sid || f.len % 6) { bad = "SETTINGS неверной формы"; break; }
            for (size_t i = 0; i + 6 <= f.len; i += 6) {
                unsigned id = ((unsigned)b[i] << 8) | b[i + 1];
                uint32_t v = ((uint32_t)b[i + 2] << 24) | ((uint32_t)b[i + 3] << 16) | ((uint32_t)b[i + 4] << 8) | b[i + 5];
                if (id == H2D_S_MAX_CONCURRENT_STREAMS) c->h2_maxs = v;
                else if (id == H2D_S_INITIAL_WINDOW_SIZE) {
                    if (v > 0x7FFFFFFFu) { bad = "начальное окно больше 2^31-1"; break; }
                    c->h2_iwin = v;
                }
            }
            if (bad) break;
            uint8_t ack[9];
            size_t an = h2d_frame_put(ack, sizeof(ack), H2D_SETTINGS, H2D_F_ACK, 0, NULL, 0);
            if (an) conn_write(c, ack, an);
            break;
        }
        case H2D_PING:
            if (f.sid || f.len != 8) { bad = "PING неверной формы"; break; }
            if (!(f.flags & H2D_F_ACK)) {
                uint8_t pong[17];
                size_t pn = h2d_frame_put(pong, sizeof(pong), H2D_PING, H2D_F_ACK, 0, b, 8);
                if (pn) conn_write(c, pong, pn);
            }
            break;
        case H2D_GOAWAY: {
            if (f.sid || f.len < 8) { bad = "GOAWAY неверной формы"; break; }
            uint32_t last = (((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]) & 0x7FFFFFFFu;
            uint32_t code = ((uint32_t)b[4] << 24) | ((uint32_t)b[5] << 16) | ((uint32_t)b[6] << 8) | b[7];
            c->h2_go = 1;
            /* Потоки за last_stream_id сервер не обрабатывал: их вопросы уходят на новое соединение,
             * попытка не считается. Остальные дорабатывают на этом. */
            for (int k = 0; k < g_req_cap; k++) {
                struct dreq *r = &RQ(k);
                if (r->used && r->up == up && r->ci == cidx(c) && r->sid > (int64_t)last) h2_requeue(c, r);
            }
            if (code != H2D_E_NO_ERROR)
                up_err(up, "HTTP/2: сервер закрывает соединение (GOAWAY, %s)", h2d_errname(code, nb, sizeof(nb)));
            break;
        }
        case H2D_RST_STREAM: {
            if (!f.sid || f.len != 4) { bad = "RST_STREAM неверной формы"; break; }
            uint32_t code = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
            struct dreq *r = find_by_sid(up, cidx(c), f.sid);
            if (!r) break;
            if (code == H2D_E_REFUSED_STREAM && r->tries < 1) {
                r->tries++;                             /* сервер вопрос не принял: повтор, один раз */
                h2_requeue(c, r);
                break;
            }
            up_err(up, "HTTP/2: сервер сбросил поток (%s)", h2d_errname(code, nb, sizeof(nb)));
            r->rxfin = 1;
            req_finish(r, NULL, 0);
            break;
        }
        case H2D_WINDOW_UPDATE: {
            if (f.len != 4) { bad = "WINDOW_UPDATE неверной формы"; break; }
            uint32_t inc = (((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3]) & 0x7FFFFFFFu;
            if (!f.sid) {
                if (!inc || c->h2_win + inc > 0x7FFFFFFF) { bad = "WINDOW_UPDATE выводит окно за предел"; break; }
                c->h2_win += inc;
            }                                           /* окно потока: тело вопроса всегда меньше начального */
            break;
        }
        case H2D_HEADERS:
        case H2D_CONTINUATION: {
            size_t o = 0, pad = 0;
            if (!f.sid || (f.type == H2D_CONTINUATION && !c->hb)) { bad = "заголовки без потока"; break; }
            if (f.type == H2D_HEADERS) {
                if (f.flags & H2D_F_PADDED) { if (!f.len) { bad = "HEADERS короче набивки"; break; } pad = b[0]; o = 1; }
                if (f.flags & H2D_F_PRIORITY) o += 5;
            }
            if (o + pad > f.len) { bad = "HEADERS короче набивки"; break; }
            const uint8_t *frag = b + o;
            size_t fl = f.len - o - pad;
            int fin = f.type == H2D_HEADERS ? (f.flags & H2D_F_END_STREAM) != 0 : c->hb_fin;
            uint32_t sid = f.sid;
            if (f.flags & H2D_F_END_HEADERS) {
                int rc;
                if (c->hb) {                            /* последний кусок составного блока */
                    uint8_t *nbuf = realloc(c->hb, c->hbn + fl + 1);
                    if (!nbuf) { bad = "нет памяти"; break; }
                    c->hb = nbuf;
                    memcpy(c->hb + c->hbn, frag, fl);
                    c->hbn += fl;
                    rc = h2_headers(c, sid, c->hb, c->hbn, fin);
                    free(c->hb);
                    c->hb = NULL;
                    c->hbn = 0;
                } else {
                    rc = h2_headers(c, sid, frag, fl, fin);
                }
                if (rc < 0) bad = "блок заголовков не разобрался (HPACK)";
            } else {
                if (c->hbn + fl > 65536) { bad = "блок заголовков слишком велик"; break; }
                uint8_t *nbuf = realloc(c->hb, c->hbn + fl + 1);
                if (!nbuf) { bad = "нет памяти"; break; }
                c->hb = nbuf;
                memcpy(c->hb + c->hbn, frag, fl);
                c->hbn += fl;
                c->hb_sid = sid;
                if (f.type == H2D_HEADERS) c->hb_fin = fin;
            }
            break;
        }
        case H2D_DATA: {
            if (!f.sid) { bad = "DATA без потока"; break; }
            size_t o = 0, pad = 0;
            if (f.flags & H2D_F_PADDED) { if (!f.len) { bad = "DATA короче набивки"; break; } pad = b[0]; o = 1; }
            if (o + pad > f.len) { bad = "DATA короче набивки"; break; }
            owed += f.len;                              /* окно соединения возвращается за весь кадр */
            struct dreq *r = find_by_sid(up, cidx(c), f.sid);
            if (!r) break;
            if (!r->hgot) { bad = "DATA раньше заголовков"; break; }
            if (rx_append(r, b + o, f.len - o - pad) != 0) {
                up_err(up, "HTTP/2: ответ DoH длиннее сообщения DNS");
                req_finish(r, NULL, 0);                 /* rxfin не выставлен: поток будет сброшен */
                break;
            }
            if (f.flags & H2D_F_END_STREAM) h2_complete(c, r);
            break;
        }
        case H2D_PUSH_PROMISE:
            bad = "PUSH_PROMISE при выключенном push";
            break;
        default:
            break;                                      /* PRIORITY и неизвестные типы — мимо (RFC 9113, 4.1) */
        }
        if (bad) break;
        if (c->st != CS_READY || !c->rb) return -1;     /* обратный вызов закрыл соединение */
        off += f.total;
    }
    if (bad) {
        up_err(up, "HTTP/2: %s", bad);
        conn_close(c, NULL);
        return -1;
    }
    if (off) {
        memmove(c->rb, c->rb + off, c->rn - off);
        c->rn -= off;
    }
    /* Окно приёма соединения — 65535, и без возврата оно кончилось бы через сотню ответов. Возвращаем
     * сразу всё принятое: буфера под данные мы не держим (тело потока копится в вопросе). */
    while (owed) {
        uint32_t inc = owed > 0x7FFFFFFFu ? 0x7FFFFFFFu : (uint32_t)owed;
        uint8_t wu[13], body[4] = { (uint8_t)(inc >> 24), (uint8_t)(inc >> 16), (uint8_t)(inc >> 8), (uint8_t)inc };
        size_t wn = h2d_frame_put(wu, sizeof(wu), H2D_WINDOW_UPDATE, 0, 0, body, 4);
        if (wn) conn_write(c, wu, wn);
        owed -= inc;
    }
    if (c->h2_go && !c->busy) { conn_close(c, NULL); return -1; }
    return 0;
}

static void conn_readable(struct dconn *c) {
    struct dup *up = c->up;
    if (c->st == CS_TCPCONN) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            up_err(up, "TCP: %s", strerror(err ? err : errno));
            conn_close(c, NULL);
            up_backoff(up);
            fail_waiting(up);
            return;
        }
        c->st = CS_READY;
        c->busy = 0;
        up->backoff_ms = 0;
        up->retry_at_ms = 0;
        up->err[0] = '\0';
        conn_ev(c, EPOLLIN);
        up_kick(up);
        return;
    }
    /* Предел в 64 витка — против того, чтобы один сокет держал цикл, пока сервер шлёт без остановки;
     * он считает чтения сокета, а не записи TLS, уже лежащие в буфере соединения. Те прочитаны у
     * ядра, и событие epoll о них не придёт: в одну порцию слоя TLS (до 16 КиБ) помещается сотня
     * коротких ответов DoT, каждый своей записью, и уйти после 64-й значило оставить остальные
     * лежать до следующего пакета сервера или до срока вопроса. Буфер конечен, так что дочитать его
     * до конца — ограниченная работа. */
    for (int guard = 0; guard < 64 || (c->tls && tls13_has_record && tls13_has_record(c->tls)); guard++) {
        if (c->tls) {
            static unsigned char pl[TLS13_MAX_PLAIN + 16];
            size_t got = 0;
            int rc = tls13_read ? tls13_read(c->tls, pl, sizeof(pl), &got) : -1;
            if (rc != 0) { conn_close(c, rc == TLS13_ECLOSED ? "сервер закрыл соединение" : "ошибка TLS"); return; }
            if (got) {
                if (rb_reserve(c, got) != 0) { conn_close(c, "ответ слишком велик"); return; }
                memcpy(c->rb + c->rn, pl, got);
                c->rn += got;
            }
            if (got) c->qrx_ms = now_ms();
            if (c->h2) {
                if (c->rn && h2_frames(c) != 0) { up_kick(up); return; }
            } else if (up->cfg.u.proto == DNSP_DOH) {
                if (c->rn) {
                    int pr = doh_parse(c);
                    if (pr < 0) { conn_close(c, NULL); return; }
                    if (pr == 1 && c->close_after) { conn_close(c, NULL); up_kick(up); return; }
                }
            } else if (got) {
                stream_frames(c);
            }
            if (!got && !(tls13_has_record && tls13_has_record(c->tls))) break;
        } else {
            if (rb_reserve(c, 4096) != 0) { conn_close(c, "ответ слишком велик"); return; }
            ssize_t r = recv(c->fd, c->rb + c->rn, c->rcap - c->rn, MSG_DONTWAIT);
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
            if (r <= 0) { conn_close(c, "сервер закрыл соединение"); return; }
            c->qrx_ms = now_ms();                   /* от сервера пришло: не молчащее (dup_tick) */
            c->rn += (size_t)r;
            stream_frames(c);
        }
    }
    up_kick(up);
}

static void conn_writable(struct dconn *c) {
    if (c->st == CS_TCPCONN) { conn_readable(c); return; }
    while (c->woff < c->wn) {
        ssize_t w = send(c->fd, c->wb + c->woff, c->wn - c->woff, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
            conn_close(c, "запись в соединение не удалась");
            return;
        }
        c->woff += (size_t)w;
    }
    c->wn = c->woff = 0;
    conn_ev(c, EPOLLIN);
}

/* ---- UDP ------------------------------------------------------------------------------------- */

static int udp_open(struct dup *up) {
    if (up->ufd >= 0) return 0;
    if (!up->srv_ok) return -1;
    int fd = socket(up->srv.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (up->cfg.mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &up->cfg.mark, sizeof(up->cfg.mark)) != 0) {
        close(fd);
        return -1;
    }
    if (connect(fd, (const struct sockaddr *)&up->srv, (socklen_t)sa_len(&up->srv)) != 0) {
        close(fd);
        return -1;
    }
    struct epoll_event e = {0};
    e.events = EPOLLIN;
    e.data.ptr = &up->utag;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &e) != 0) { close(fd); return -1; }
    up->ufd = fd;
    return 0;
}

static int udp_send(struct dup *up, struct dreq *r) {
    if (udp_open(up) != 0) return -1;
    if (send(up->ufd, r->q, r->qn, MSG_NOSIGNAL | MSG_DONTWAIT) < 0) return -1;
    up->q_sent += r->tries == 0;
    return 0;
}

static void udp_readable(struct dup *up) {
    for (int guard = 0; guard < 64; guard++) {
        uint8_t buf[4096];
        ssize_t n = recv(up->ufd, buf, sizeof(buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            /* Отложенная ошибка сокета (ICMP unreachable): следующее чтение — дальше. */
            up_err(up, "UDP: %s", strerror(errno));
            continue;
        }
        if (n < 12) continue;
        struct dreq *r = find_by_wid(up, -1, (uint16_t)((buf[0] << 8) | buf[1]));
        /* UDP-вопросы живут с ci == -2: не «ждёт соединения» (-1), а «в полёте по UDP». */
        if (!r) r = find_by_wid(up, -2, (uint16_t)((buf[0] << 8) | buf[1]));
        if (!r || r->tcp || !same_question(r, buf, (size_t)n)) continue;
        if (buf[2] & 0x02) {                                      /* TC: то же самое по TCP */
            r->tcp = 1;
            r->ci = -1;
            up_kick(up);
            continue;
        }
        req_finish(r, buf, (size_t)n);
    }
}

/* ---- публичное ------------------------------------------------------------------------------- */

static void up_reset_state(struct dup *up) {
    up->ad_n = 0;
    up->backoff_ms = 0;
    up->retry_at_ms = 0;
    up->err[0] = '\0';
    up->dialing = 0;
    up->q_sent = up->q_ok = up->q_fail = 0;
    up->q_early = up->q_early_rej = 0;
}

static void up_retire(struct dup *up) {
    if (!up->live) return;
    for (int i = 0; i < up->c_n; i++) {
        struct dconn *c = CN(up, i);
        if (c->dial) { c->dial->cancel = 1; c->dial = NULL; }
        if (c->st != CS_FREE && c->st != CS_DIAL) {
            /* Вопросы без повтора: апстрима больше нет. */
            for (int k = 0; k < g_req_cap; k++)
                if (RQ(k).used && RQ(k).up == up && RQ(k).ci == i) RQ(k).tries = 2;
            conn_close(c, NULL);
        }
        c->st = CS_FREE;
    }
    for (int k = 0; k < g_req_cap; k++)
        if (RQ(k).used && RQ(k).up == up) req_finish(&RQ(k), NULL, 0);
    if (up->ufd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, up->ufd, NULL);
        close(up->ufd);
        up->ufd = -1;
    }
    up->live = 0;
    up->gen++;
}

static int cfg_same(const struct dup_cfg *a, const struct dup_cfg *b) {
    if (strcmp(a->u.name, b->u.name) || strcmp(a->u.url, b->u.url) || strcmp(a->via, b->via) ||
        a->mark != b->mark || a->need_mark != b->need_mark || a->u.ips_n != b->u.ips_n ||
        a->u.boot_n != b->u.boot_n || a->grp != b->grp || a->gm_n != b->gm_n || a->u.frag != b->u.frag)
        return 0;
    /* Группа — те же члены на тех же местах настройки: паузы членов переживают перенастройку. */
    for (size_t i = 0; i < a->gm_n; i++) if (a->gm[i] != b->gm[i]) return 0;
    for (size_t i = 0; i < a->u.ips_n; i++) if (strcmp(a->u.ips[i], b->u.ips[i])) return 0;
    for (size_t i = 0; i < a->u.boot_n; i++) if (strcmp(a->u.boot[i], b->u.boot[i])) return 0;
    return 1;
}

void dup_apply(const struct dup_cfg *c, size_t n) {
    /* Число апстримов не ограничено: таблицы прежних и новых — по n. */
    size_t oldn = g_dups_n;
    struct dup **old = oldn ? malloc(oldn * sizeof(*old)) : NULL;
    struct dup **nw = n ? calloc(n, sizeof(*nw)) : NULL;
    int *taken = oldn ? calloc(oldn, sizeof(int)) : NULL;
    if ((oldn && (!old || !taken)) || (n && !nw)) { free(old); free(nw); free(taken); return; }
    if (oldn) memcpy(old, g_dups, oldn * sizeof(*old));
    for (size_t i = 0; i < n; i++) {
        for (size_t j = 0; j < oldn; j++)
            if (!taken[j] && cfg_same(&old[j]->cfg, &c[i])) { taken[j] = 1; nw[i] = old[j]; break; }
    }
    for (size_t j = 0; j < oldn; j++) if (!taken[j]) up_retire(old[j]);
    for (size_t i = 0; i < n; i++) {
        if (nw[i]) continue;
        struct dup *up = NULL;
        for (size_t k = 0; k < g_store_n; k++)
            if (!g_store[k]->live) { up = g_store[k]; break; }
        if (!up) {
            if (g_store_n == g_store_cap) {
                size_t nc = g_store_cap ? g_store_cap * 2 : 8;
                struct dup **ns = realloc(g_store, nc * sizeof(*ns));
                if (!ns) continue;
                g_store = ns;
                g_store_cap = nc;
            }
            up = calloc(1, sizeof(*up));
            if (!up) continue;
            g_store[g_store_n++] = up;
        }
        unsigned gen = up->gen;
        struct dconn **keepc = up->c;           /* соединения (их блоки) переживают переназначение */
        int keep_n = up->c_n, keep_cap = up->c_cap;
        free(up->ips_own);                      /* личные копии адресов прежней настройки */
        free(up->boot_own);
        free(up->gm_own);                       /* и номеров членов группы, их паузы */
        free(up->gp);
        memset(up, 0, sizeof(*up));
        up->c = keepc;
        up->c_n = keep_n;
        up->c_cap = keep_cap;
        up->gen = gen + 1;
        up->live = 1;
        up->ufd = -1;
        up->cfg = c[i];
        /* Адреса в настройке — указатели в таблицу резолвера, которую перечитают; апстриму нужны
         * свои копии (dial берёт их дальше, у него — ещё свои). */
        if (up->cfg.u.ips_n) {
            up->ips_own = memdup(up->cfg.u.ips, up->cfg.u.ips_n * sizeof(*up->cfg.u.ips));
            up->cfg.u.ips = up->ips_own;
            if (!up->ips_own) up->cfg.u.ips_n = 0;
        }
        if (up->cfg.u.boot_n) {
            up->boot_own = memdup(up->cfg.u.boot, up->cfg.u.boot_n * sizeof(*up->cfg.u.boot));
            up->cfg.u.boot = up->boot_own;
            if (!up->boot_own) up->cfg.u.boot_n = 0;
        }
        up->cfg.gm = NULL;
        if (up->cfg.grp && c[i].gm_n) {
            /* Группа: свои копии номеров членов и место паузы на каждого (dupgrp.c). */
            up->gm_own = memdup(c[i].gm, c[i].gm_n * sizeof(*c[i].gm));
            up->gp = calloc(c[i].gm_n, sizeof(*up->gp));
            if (!up->gm_own || !up->gp) {
                free(up->gm_own); free(up->gp);
                up->gm_own = NULL; up->gp = NULL;
                up->cfg.gm_n = 0;
            }
            up->cfg.gm = up->gm_own;
        } else {
            up->cfg.gm_n = 0;
        }
        up->cfg.own = 0;
        up->utag.magic = DTAG_MAGIC; up->utag.kind = DT_UDP; up->utag.obj = up;
        for (int k = 0; k < up->c_n; k++) {
            struct dconn *cc = CN(up, k);
            cc->up = up; cc->fd = -1; cc->st = CS_FREE;
            cc->tag.magic = DTAG_MAGIC; cc->tag.kind = DT_CONN; cc->tag.obj = cc;
        }
        up_reset_state(up);
        uint16_t seed = 0;
        if (getrandom(&seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) seed = (uint16_t)time(NULL);
        up->next_id = seed;
        /* Адрес сервера обычного DNS и DoT/DoH-по-адресу известен сразу. */
        struct sockaddr_in *v4 = (struct sockaddr_in *)&up->srv;
        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&up->srv;
        if (inet_pton(AF_INET, up->cfg.u.host, &v4->sin_addr) == 1) {
            v4->sin_family = AF_INET;
            v4->sin_port = htons(up->cfg.u.port);
            up->srv_ok = 1;
        } else if (inet_pton(AF_INET6, up->cfg.u.host, &v6->sin6_addr) == 1) {
            v6->sin6_family = AF_INET6;
            v6->sin6_port = htons(up->cfg.u.port);
            up->srv_ok = 1;
        }
        nw[i] = up;
    }
    if (n > g_dups_cap) {
        struct dup **nd = realloc(g_dups, n * sizeof(*nd));
        if (nd) { g_dups = nd; g_dups_cap = n; }
    }
    g_dups_n = 0;
    if (n <= g_dups_cap)
        for (size_t i = 0; i < n; i++) g_dups[g_dups_n++] = nw[i];
    free(old);
    free(nw);
    free(taken);
}

int dup_ask(size_t idx, const uint8_t *q, size_t n, dup_done_fn cb, void *ctx) {
    if (idx >= g_dups_n || !g_dups[idx] || n < 12 || n > DUP_QMAX) return -1;
    struct dup *up = g_dups[idx];
    if (up->cfg.grp) return grp_ask(up, q, n, cb, ctx);
    if (up->cfg.u.proto == DNSP_NONE) return -1;
    if (up->cfg.need_mark && !up->cfg.mark) {
        up_err(up, "выход «%s» не размечен: запрос через него не отправить", up->cfg.via);
        return -1;
    }
    if (tls_proto(up) && !dup_have_tls()) {
        up_err(up, "в этой сборке нет TLS: DoT и DoH недоступны");
        return -1;
    }
    if (quic_proto(up) && !dup_have_quic()) {
        up_err(up, "в этой сборке нет QUIC: DoQ недоступен");
        return -1;
    }
    struct dreq *r = NULL;
    for (int k = 0; k < g_req_cap; k++) if (!RQ(k).used) { r = &RQ(k); break; }
    if (!r) {
        /* Мест нет — новый блок; растёт до нехватки памяти, а число вопросов в полёте держит
         * очередь ожидающих резолвера (MAX_PENDING). */
        int first = g_req_cap;
        if (req_grow() != 0) return -1;
        r = &RQ(first);
    }
    int slot = r->slot;
    memset(r, 0, offsetof(struct dreq, q));
    r->slot = slot;
    r->sid = -1;                                        /* DoQ: поток ещё не открыт */
    memcpy(r->q, q, n);
    r->qn = (uint16_t)n;
    r->used = 1;
    r->up = up;
    r->up_gen = up->gen;
    r->oid = (uint16_t)((q[0] << 8) | q[1]);
    for (;;) {                                          /* номер, не занятый другим вопросом апстрима */
        r->wid = up->next_id++;
        int taken = 0;
        for (int k = 0; k < g_req_cap; k++)
            if (&RQ(k) != r && RQ(k).used && RQ(k).up == up && RQ(k).wid == r->wid) taken = 1;
        if (!taken) break;
    }
    r->q[0] = (uint8_t)(r->wid >> 8);
    r->q[1] = (uint8_t)r->wid;
    r->cb = cb;
    r->ctx = ctx;
    r->t0 = now_ms();
    r->deadline = r->t0 + DUP_REQ_MS;
    r->ci = -1;
    if (up->cfg.u.proto == DNSP_UDP) {
        r->ci = -2;
        if (udp_send(up, r) != 0) {
            up_err(up, "UDP: %s", strerror(errno));
            r->used = 0;
            return -1;
        }
        return 0;
    }
    if (now_ms() < up->retry_at_ms && !pick_conn(up)) {
        r->used = 0;
        return -1;                                     /* пауза после неудачи: отказ сразу */
    }
    up_kick(up);
    if (!r->used) return 0;                             /* отказ уже отдан обратным вызовом */
    return 0;
}

int dup_event(void *ptr, uint32_t evs) {
    struct dtag *t = ptr;
    if (!t || t->magic != DTAG_MAGIC) return 0;
    switch (t->kind) {
    case DT_UDP: {
        struct dup *up = t->obj;
        if (up->live && up->ufd >= 0) udp_readable(up);
        break;
    }
    case DT_CONN: {
        struct dconn *c = t->obj;
        if (c->qc) {                                    /* DoQ: сокет и таймер ведёт обёртка */
            if (c->st == CS_READY || c->st == CS_QHS) quic_run(c, 0);
            break;
        }
        if (c->st != CS_READY && c->st != CS_TCPCONN) break;
        if (evs & (EPOLLERR | EPOLLHUP) && c->st == CS_TCPCONN) { conn_readable(c); break; }
        if (evs & EPOLLOUT) conn_writable(c);
        if (c->fd >= 0 && (evs & (EPOLLIN | EPOLLERR | EPOLLHUP))) conn_readable(c);
        break;
    }
    case DT_DIAL:
        dial_event_cb(t->obj);
        break;
    }
    return 1;
}

void dup_tick(void) {
    long now = now_ms();
    for (int k = 0; k < g_req_cap; k++) {
        struct dreq *r = &RQ(k);
        if (!r->used) continue;
        struct dup *up = r->up;
        if (up->cfg.u.proto == DNSP_UDP && r->ci == -2 && r->tries == 0 && now - r->t0 >= DUP_UDP_RETRY_MS &&
            now < r->deadline) {
            r->tries = 1;
            udp_send(up, r);
            continue;
        }
        if (quic_proto(up) && r->sid >= 0 && r->tries == 0 && r->ci >= 0 && now - r->t0 >= DUP_QUIC_DEAD_MS &&
            now < r->deadline && CN(up, r->ci)->st == CS_READY && CN(up, r->ci)->qrx_ms <= r->t0) {
            /* Ни пакета от сервера с тех пор, как ушёл вопрос: соединение мертво (DUP_QUIC_DEAD_MS).
             * conn_close переставит этот вопрос и остальные в ожидание, up_kick заведёт соединение. */
            struct dconn *dc = CN(up, r->ci);
            up_err(up, "DoQ: сервер молчит %d мс — соединение пересоздаётся", DUP_QUIC_DEAD_MS);
            conn_close(dc, NULL);
            up_kick(up);
            k = -1;                                     /* таблицу вопросов сдвинули: с начала */
            continue;
        }
        if (now < r->deadline) continue;
        int ci = r->ci;
        /* Причина, названная сервером или соединением после ухода вопроса (HTTP 505, сброс потока,
         * отказ TLS), полезнее общего «нет ответа»: её и оставляем в last_error. */
        if (!(up->err[0] && up->err_ms >= r->t0)) up_err(up, "нет ответа за %d мс", DUP_REQ_MS);
        int silent = ci >= 0 && ci < up->c_n && CN(up, ci)->qrx_ms <= r->t0;
        req_finish(r, NULL, 0);
        if (ci >= 0 && CN(up, ci)->st == CS_READY) {
            /* HTTP/2, DoT и TCP: остальные вопросы соединения живы (поток брошенного вопроса h2
             * req_finish сбросил); соединение рвём, только если с ухода вопроса от сервера не пришло
             * ни байта (мёртвый путь). Иначе мёртвое DoT-соединение принимало бы все вопросы апстрима,
             * пока ядро не бросит повторы TCP (tcp_retries2 — десятки минут). */
            int closed = 1;
            if (up->cfg.u.proto == DNSP_DOH && CN(up, ci)->h2) { if (silent) conn_close(CN(up, ci), NULL); else closed = 0; }
            else if (up->cfg.u.proto == DNSP_DOH) conn_close(CN(up, ci), NULL);
            else if (!quic_proto(up)) {                                            /* у DoQ — req_finish */
                if (CN(up, ci)->busy > 0) CN(up, ci)->busy--;
                if (silent) conn_close(CN(up, ci), NULL); else closed = 0;
            } else closed = 0;
            /* Вопросы закрытого соединения conn_close переставил в ожидание — отправить их сейчас (по
             * другому соединению или новому), а не в следующий раз, когда кто-нибудь спросит апстрим. */
            if (closed) { up_kick(up); k = -1; }
        }
    }
    for (size_t i = 0; i < g_dups_n; i++) {
        struct dup *up = g_dups[i];
        for (int k = 0; k < up->c_n; k++) {
            struct dconn *c = CN(up, k);
            /* Таймеры QUIC (потери, PING, рукопожатие, простой) обслуживает обёртка по нашему зову. */
            if (c->qc && (c->st == CS_READY || c->st == CS_QHS) && dupq_timeout_ms && dupq_timeout_ms(c->qc) == 0)
                quic_run(c, 1);
            /* Первое соединение держится DUP_IDLE_MS (пять минут), лишние, выросшие под всплеск
             * нагрузки, — тридцать секунд: пул растёт по нагрузке и так же сжимается, не держа
             * дескрипторы впрок. */
            long idle = k == 0 ? DUP_IDLE_MS : 30000L;
            if (c->st == CS_READY && !c->busy && now - c->last_ms > idle) conn_close(c, NULL);
            /* tcp:// (и TCP после усечённого UDP): connect идёт в цикле, и без своего срока SYN в никуда
             * держал бы место «соединяемся» столько, сколько ядро его повторяет (около двух минут), —
             * новое соединение всё это время не заводится. Срок — как у установки TLS в потоке. */
            if (c->st == CS_TCPCONN && now - c->last_ms > DUP_DIAL_MS) {
                up_err(up, "TCP: соединение не установилось за %d мс", DUP_DIAL_MS);
                conn_close(c, NULL);
                up_backoff(up);
                fail_waiting(up);
            }
        }
    }
    grp_tick(now_ms());
}

int dup_wait_ms(void) {
    long now = now_ms(), best = grp_deadline();
    for (int k = 0; k < g_req_cap; k++) {
        if (!RQ(k).used) continue;
        long t = RQ(k).deadline;
        if (RQ(k).ci == -2 && RQ(k).tries == 0 && RQ(k).t0 + DUP_UDP_RETRY_MS < t)
            t = RQ(k).t0 + DUP_UDP_RETRY_MS;
        if (RQ(k).sid >= 0 && RQ(k).tries == 0 && RQ(k).ci >= 0 && quic_proto(RQ(k).up) &&
            CN(RQ(k).up, RQ(k).ci)->qrx_ms <= RQ(k).t0 && RQ(k).t0 + DUP_QUIC_DEAD_MS < t)
            t = RQ(k).t0 + DUP_QUIC_DEAD_MS;
        if (best < 0 || t < best) best = t;
    }
    /* Соединения DoQ живут и без вопросов: проснуться к таймеру QUIC (потерянный пакет, конец
     * рукопожатия, простой) и к сроку нашего закрытия простаивающего соединения. */
    for (size_t i = 0; i < g_dups_n; i++) {
        const struct dup *up = g_dups[i];
        for (int k = 0; k < up->c_n; k++) {
            struct dconn *c = CN(up, k);
            if (c->st == CS_TCPCONN) {
                long t = c->last_ms + DUP_DIAL_MS + 1;
                if (best < 0 || t < best) best = t;
                continue;
            }
            if (!c->qc || (c->st != CS_READY && c->st != CS_QHS)) continue;
            int qt = dupq_timeout_ms ? dupq_timeout_ms(c->qc) : -1;
            if (qt >= 0 && (best < 0 || now + qt < best)) best = now + qt;
            if (c->st == CS_READY && !c->busy) {
                long t = c->last_ms + (k == 0 ? DUP_IDLE_MS : 30000L);
                if (best < 0 || t < best) best = t;
            }
        }
    }
    if (best < 0) return -1;
    return best - now > 0 ? (int)(best - now) : 0;
}

int dup_busy(void) {
    for (int k = 0; k < g_req_cap; k++) if (RQ(k).used) return 1;
    return grp_busy();
}

void dup_close_all(void) {
    dup_apply(NULL, 0);
}

const char *dup_state(const struct dup *up) {
    if (up->cfg.need_mark && !up->cfg.mark) return "unmarked";
    if (tls_proto(up) && !dup_have_tls()) return "no-tls";
    if (quic_proto(up) && !dup_have_quic()) return "no-tls";      /* нет библиотеки: как у DoT/DoH */
    if (stream_proto(up)) {
        for (int i = 0; i < up->c_n; i++) if (CN(up, i)->st == CS_READY) return "ready";
        if (up->dialing) return "connecting";
        for (int i = 0; i < up->c_n; i++) if (CN(up, i)->st == CS_QHS) return "connecting";
        if (now_ms() < up->retry_at_ms) return "down";
        return "idle";
    }
    if (up->q_ok) return up->q_fail > up->q_ok ? "down" : "ready";
    return up->q_fail ? "down" : "idle";
}

static const char *proto_name(int p) {
    switch (p) {
    case DNSP_UDP: return "udp";
    case DNSP_TCP: return "tcp";
    case DNSP_DOT: return "dot";
    case DNSP_DOH: return "doh";
    case DNSP_QUIC: return "doq";
    default: return "?";
    }
}

void dup_render(FILE *f) {
    long now = now_ms();
    for (size_t i = 0; i < g_dups_n; i++) {
        const struct dup *up = g_dups[i];
        int conns = 0, queued = 0;
        for (int k = 0; k < up->c_n; k++) conns += CN(up, k)->st == CS_READY;
        for (int k = 0; k < g_req_cap; k++) queued += RQ(k).used && RQ(k).up == up;
        if (up->cfg.grp) {
            /* Группа серверов: свои поля (dupgrp.c), имя и пустой url — как у сервера. */
            fprintf(f, "%s{\"name\":\"%s\",\"url\":\"\",", i ? "," : "", up->cfg.u.name);
            grp_render(f, up);
            fputs(",\"error\":null,\"error_ago\":null}", f);
            continue;
        }
        fprintf(f, "%s{\"name\":\"%s\",\"url\":\"%s\",\"proto\":\"%s\",\"via\":", i ? "," : "",
                up->cfg.u.name, up->cfg.u.url, proto_name(up->cfg.u.proto));
        if (up->cfg.via[0]) fprintf(f, "\"%s\"", up->cfg.via); else fputs("null", f);
        fprintf(f, ",\"state\":\"%s\",\"conns\":%d,\"inflight\":%d,\"sent\":%lu,\"ok\":%lu,\"failed\":%lu,"
                   "\"last_ok_ago\":", dup_state(up), conns, queued, up->q_sent, up->q_ok, up->q_fail);
        if (up->ok_ms) fprintf(f, "%ld", (now - up->ok_ms) / 1000); else fputs("null", f);
        /* DoQ: сколько вопросов ушло в 0-RTT и сколько раз сервер его отверг. Только когда 0-RTT был. */
        if (up->q_early || up->q_early_rej)
            fprintf(f, ",\"early\":%lu,\"early_rejected\":%lu", up->q_early, up->q_early_rej);
        fputs(",\"error\":", f);
        if (up->err[0]) {
            fputc('"', f);
            for (const char *p = up->err; *p; p++) {
                if (*p == '"' || *p == '\\') fputc('\\', f);
                if ((unsigned char)*p >= 0x20) fputc(*p, f);
            }
            fprintf(f, "\",\"error_ago\":%ld", (now - up->err_ms) / 1000);
        } else {
            fputs("null,\"error_ago\":null", f);
        }
        /* DoH: по какому HTTP говорит сервер (выбор ALPN при последнем соединении). */
        if (up->cfg.u.proto == DNSP_DOH && up->hproto)
            fprintf(f, ",\"http\":\"%s\"", up->hproto == 2 ? "h2" : "http/1.1");
        fputc('}', f);
    }
}
