/* QUIC-соединение движка поверх ngtcp2 — устройство и границы описаны в quic.h.
 *
 * ЧТО ЗДЕСЬ ЖИВЁТ: сокет и адреса, колбэки ngtcp2, очередь отправки потоков и датаграмм, таймер.
 * Чего нет: TLS (qcssl.c, единственное место с типами wolfSSL) и любого протокола поверх QUIC.
 *
 * ОТПРАВКА. ngtcp2 не хранит данные потока: он берёт указатель и длину, пишет пакет и просит
 * держать байты, пока их не подтвердят (acked_stream_data_offset). Поэтому у потока свой буфер
 * (struct qc_stream): [base, base+len) — то, что ещё не подтверждено; sent — сколько из этого уже
 * ушло в пакеты. Подтверждённый префикс срезается лениво, чтобы каждый ACK не двигал память.
 *
 * ПАЧКИ. Пакеты пишет ngtcp2_conn_write_aggregate_pkt: она сама складывает их в буфер подряд (до
 * send_quantum — а это то, что решил алгоритм перегрузки: у Brutal миллисекунда на выбранной
 * скорости), сама вызывает ngtcp2_conn_update_pkt_tx_time. Буфер нарезаем по gso_size на датаграммы
 * UDP и отдаём ядру пачкой (send_batch): равные по размеру — одним sendmsg с UDP_SEGMENT, остальные —
 * sendmmsg; ядро без GSO или устройство без контрольной суммы (EIO, EINVAL) выключают GSO для сокета.
 * ПРИЁМ — recvmmsg, с UDP_GRO ядро склеивает подряд пришедшие датаграммы, и qc_on_readable режет их
 * обратно по размеру сегмента. Приём одной датаграммой за вызов (по умолчанию при отказе UDP_GRO)
 * стоил на роутере больше, чем шифр: 1 Гбит/с — около 100 тысяч вызовов в секунду.
 *
 * ТАЙМЕР. Срок — ngtcp2_conn_get_expiry: потеря, PTO, idle, пейсинг. Линия событий потребителя
 * держит его в миллисекундах (qc_timeout_ms округляет вверх); опоздание на миллисекунду пейсинг
 * ngtcp2 возмещает сам (compensation), а у Brutal пачка и есть миллисекунда данных. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "quic.h"
#include "qcssl.h"

#define QC_TXBUF        (64 * 1024)     /* пачка — до send_quantum, а он не больше 64 КиБ */
/* Очередь исходящих датаграмм — 64: это защита от накопления, а не размер нагрузки. Датаграммы
 * ненадёжны по природе, и при полной очереди qc_datagram_send отвечает QC_EAGAIN (вызывающий
 * отбрасывает пакет, как сеть при перегрузке); растущая очередь только добавила бы задержку. */
#define QC_DG_QUEUE     64
#define QC_RXBUF        65536
/* Результат фильтра отправки для целой пачки: сама пачка (до QC_TXBUF) и запас фильтра (n + 64) на
 * каждую из QC_GSO_SEGS датаграмм. */
#define QC_OBUF         (QC_TXBUF + 64 * 64)
/* Пакетный ввод-вывод UDP (quic.h, «ПАКЕТНЫЙ ВВОД-ВЫВОД»). Пределы — ядра Linux: UDP_SEGMENT нарезает
 * не больше 64 сегментов и не больше 65507 байт (65535 минус заголовки IPv4 и UDP) за один вызов. */
#define QC_GSO_SEGS     64
#define QC_GSO_BYTES    65507
#define QC_RX_BATCH     32              /* сообщений за один recvmmsg без UDP_GRO: слоты по 2 КиБ */
#define QC_RX_SLOT      (QC_RXBUF / QC_RX_BATCH)
/* С UDP_GRO сообщение — до 64 КиБ склеенных датаграмм, и слот нужен на целых 64 КиБ. Слотов 16: если
 * ядро ничего не склеило (loopback, veth, сетевая карта без GRO), recvmmsg всё равно берёт по 16
 * датаграмм за вызов, а если склеило — до 16 склеек. Буфер приёма — 1 МиБ виртуальной памяти: ядро
 * пишет ровно столько, сколько пришло, остальное страниц не занимает (RSS не растёт). */
#define QC_RX_GRO_BATCH 16
#define QC_RXBUF_GRO    (QC_RX_GRO_BATCH * 65536)
#ifndef SOL_UDP
#define SOL_UDP         17
#endif
#ifndef UDP_SEGMENT
#define UDP_SEGMENT     103
#endif
#ifndef UDP_GRO
#define UDP_GRO         104
#endif
/* Длина нашего идентификатора соединения. Была 17; против сервера эталона (quic-go) это стоило
 * потери датаграмм: он режет фрагменты UDP по предельному размеру датаграммы, посчитанному
 * без учёта длинного CID адресата, и первый (самый большой) фрагмент не влезал в пакет и молча
 * пропадал — UDP крупнее одного фрагмента не работал вовсе. Четыре байта — как у самого quic-go. */
#define QC_CID_LEN      4

/* Буфер отправки потока — цепочка блоков ФИКСИРОВАННОГО размера, и это не вкус. ngtcp2 не копирует
 * данные потока: указатель, отданный в ngtcp2_conn_writev_stream, она хранит для повторной отправки
 * потерянного, пока не сообщит о подтверждении (acked_stream_data_offset). Единый буфер с realloc
 * или memmove при подтверждении двигал бы данные из-под этих указателей — чтение освобождённой
 * памяти при первой же потере (так и было найдено: AddressSanitizer на канале с 5% потерь). Блок,
 * однажды выделенный, не двигается до освобождения, а освобождается, когда подтверждён целиком. */
#define QC_CHUNK 32768
struct qc_chunk {
    struct qc_chunk *next;
    uint64_t  off;          /* смещение в потоке первого байта */
    size_t    len;
    uint8_t   data[QC_CHUNK];
};

struct qc_stream {
    struct qc_stream *next;
    int64_t   id;
    struct qc_chunk *head, *tail;
    struct qc_chunk *cur;   /* блок, в котором лежит смещение sent (или следующий за ним) */
    uint64_t  total;        /* принято в буфер всего (смещение конца данных) */
    uint64_t  sent;         /* смещение, до которого данные переданы ngtcp2 */
    uint64_t  acked;
    int       fin_req;      /* потребитель закрыл передачу */
    int       fin_sent;
    int       blocked;      /* ngtcp2 отказала по окну потока: ждём extend_max_stream_data */
};

struct qc_dg {
    uint8_t  *d;
    size_t    n;
};

/* Рабочие массивы приёма: recvmmsg берёт до QC_RX_BATCH датаграмм, у каждой свой адрес отправителя.
 * Живут в куче, а не на стеке потока потребителя (около восьми килобайт). */
struct qc_rx {
    struct mmsghdr mm[QC_RX_BATCH];
    struct iovec iov[QC_RX_BATCH];
    struct sockaddr_storage from[QC_RX_BATCH];
    union { char b[CMSG_SPACE(sizeof(int))]; struct cmsghdr a; } ctl[QC_RX_BATCH];    /* UDP_GRO: размер сегмента */
};

struct qc {
    struct qc_ops ops;
    void     *user;
    int       fd;
    int       epfd;
    int       server;
    int       connected;        /* сокет connect()-нут (клиент) */
    struct sockaddr_storage local, remote;
    socklen_t local_len, remote_len;

    ngtcp2_conn *conn;
    ngtcp2_crypto_conn_ref ref;
    void     *ssl;
    void     *ctx;              /* свой контекст TLS, если не общий */
    int       own_ctx;
    struct qc_tls *shared;
    uint8_t   secret[32];       /* для токенов сброса без состояния */
    size_t    datagram_max;
    size_t    send_buf;
    /* Настройки будущего соединения сервера стенда (QC_WITH_SERVER): создаётся по первому пакету. */
    char      alpn[32];
    uint64_t  brutal_bps, max_data, max_stream_data, max_streams;
    unsigned  idle_ms;
    unsigned  keepalive_ms;     /* PING при молчании (cfg.keepalive_ms); 0 — не слать */
    unsigned  idle_local_ms;    /* свой max_idle_timeout: с ним сверяется срок сервера (keepalive_tune) */

    struct qc_stream *streams;
    struct qc_stream *rr;       /* с кого продолжать обход потоков */
    struct qc_dg dgq[QC_DG_QUEUE];
    unsigned  dg_head, dg_n;
    uint64_t  dg_dropped;       /* датаграммы, выброшенные из очереди, не дойдя до пакета */

    int       hs_done;
    int       closed;           /* on_closed уже вызвано */
    int       in_cb;            /* внутри колбэка потребителя: qc_free запрещён */
    int       brutal;
    int       flow_manual;      /* окна приёма продлевает потребитель (qc_stream_consumed) */
    int       credit_dirty;     /* окна продлены, а пакет с их обновлением ещё не уходил (qc_flush_credit) */
    uint8_t  *txbuf;
    uint8_t  *rxbuf;
    struct qc_rx *rx;
    /* Шов «фильтр датаграмм» (quic.h, struct qc_filter): обфускация всего, что идёт по сокету.
     * obuf — куда фильтр отправки складывает результат (пачка ngtcp2 нарезана на кусочки размером
     * с датаграмму, поэтому достаточно одной датаграммы с запасом). */
    struct qc_filter filter;
    uint8_t  *obuf;
    uint64_t  tx_calls, rx_calls;
    int       gso_ok;           /* отправка пачкой через UDP_SEGMENT ещё не отказывала */
    int       gro_on;           /* приём склеенных датаграмм (UDP_GRO) включён на сокете */
    /* Прыжки по портам сервера (quic.h): диапазоны, интервал, текущий порт и момент последней
     * смены. Сокет тогда не connect()-нут: адрес назначения выбирает каждая отправка. */
    uint16_t  hop[QC_HOP_RANGES * 2];
    unsigned  hop_n, hop_ms;
    uint16_t  hop_port;
    uint64_t  hop_at_ns;
    /* pinSHA256 (quic.h): сверка листового сертификата вместо цепочки. why — причина закрытия,
     * которую колбэк ngtcp2 не может вернуть иначе, чем кодом. */
    int       pin_on;
    uint8_t   pin[32];
    const char *why;
    /* 0-RTT (quic.h, cfg.early_data). skey — ключ записи в кэше билетов общего контекста (sni:порт);
     * early_tried — билет с разрешением early data поставлен и параметры транспорта прошлой сессии
     * применены, то есть слать можно до рукопожатия; early_ok — это ещё действует (сбрасывается, когда
     * рукопожатие завершилось: дальше потоки открываются как обычно, либо отказ сервера). */
    char      skey[160];
    int       want_sess;        /* билеты этого соединения запоминаются */
    int       early_tried, early_ok;
};

/* Кэш билетов сессий для 0-RTT: одна запись на сервер. der — сессия wolfSSL (i2d), tp — параметры
 * транспорта сервера, которые ngtcp2 нужны, чтобы открывать потоки до рукопожатия (ngtcp2 без них не
 * знает лимитов). Без билета, разрешающего early data, запись бесполезна и не хранится. Под замком:
 * DoQ-соединения одного процесса открываются из потока резолвера, но контекст общий по определению. */
struct qc_sess {
    char     key[160];
    uint8_t *der, *tp;
    size_t   der_n, tp_n;
};

struct qc_tls {
    void *ctx;
    int early;
    pthread_mutex_t mu;
    struct qc_sess sess[QC_SESS_MAX];
    unsigned next;              /* кого вытеснять, когда серверов больше QC_SESS_MAX */
};

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * NGTCP2_SECONDS + (uint64_t)ts.tv_nsec;
}

static void fill_random(uint8_t *p, size_t n) {
    while (n > 0) {
        ssize_t r = getrandom(p, n, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            /* getrandom не бывает недоступным на ядрах, где живёт движок (3.17+); но молча
             * отдать нули значило бы выдать предсказуемые идентификаторы соединения. */
            abort();
        }
        p += r;
        n -= (size_t)r;
    }
}

/* ---- кэш билетов 0-RTT ----------------------------------------------------------------------- */

static void sess_clear(struct qc_sess *e) {
    free(e->der);
    free(e->tp);
    memset(e, 0, sizeof *e);
}

/* Положить (заменить) запись сервера key. Копии принадлежат кэшу. */
static void sess_put(struct qc_tls *t, const char *key, const uint8_t *der, size_t der_n,
                     const uint8_t *tp, size_t tp_n) {
    uint8_t *d = malloc(der_n), *p = malloc(tp_n);
    if (!d || !p) { free(d); free(p); return; }
    memcpy(d, der, der_n);
    memcpy(p, tp, tp_n);
    pthread_mutex_lock(&t->mu);
    struct qc_sess *e = NULL;
    for (unsigned i = 0; i < QC_SESS_MAX; i++)
        if (t->sess[i].der && !strcmp(t->sess[i].key, key)) { e = &t->sess[i]; break; }
    if (!e)
        for (unsigned i = 0; i < QC_SESS_MAX; i++)
            if (!t->sess[i].der) { e = &t->sess[i]; break; }
    if (!e) { e = &t->sess[t->next++ % QC_SESS_MAX]; }
    sess_clear(e);
    snprintf(e->key, sizeof e->key, "%s", key);
    e->der = d; e->der_n = der_n;
    e->tp = p; e->tp_n = tp_n;
    pthread_mutex_unlock(&t->mu);
}

/* Копия записи сервера key (кучные буферы вызывающему) или 0. */
static int sess_get(struct qc_tls *t, const char *key, uint8_t **der, size_t *der_n, uint8_t **tp, size_t *tp_n) {
    int ok = 0;
    pthread_mutex_lock(&t->mu);
    for (unsigned i = 0; i < QC_SESS_MAX; i++) {
        struct qc_sess *e = &t->sess[i];
        if (!e->der || strcmp(e->key, key)) continue;
        *der = malloc(e->der_n);
        *tp = malloc(e->tp_n);
        if (*der && *tp) {
            memcpy(*der, e->der, e->der_n);
            memcpy(*tp, e->tp, e->tp_n);
            *der_n = e->der_n;
            *tp_n = e->tp_n;
            ok = 1;
        } else { free(*der); free(*tp); }
        break;
    }
    pthread_mutex_unlock(&t->mu);
    return ok;
}

/* Забыть запись сервера key: билет, который сервер не принял (или принял без 0-RTT), повторно не
 * предлагается — иначе каждое соединение начиналось бы с отказа. */
static void sess_drop(struct qc_tls *t, const char *key) {
    pthread_mutex_lock(&t->mu);
    for (unsigned i = 0; i < QC_SESS_MAX; i++)
        if (t->sess[i].der && !strcmp(t->sess[i].key, key)) sess_clear(&t->sess[i]);
    pthread_mutex_unlock(&t->mu);
}

/* Пришёл новый билет соединения (колбэк wolfSSL, qcssl.c). Хранится вместе с параметрами транспорта,
 * которые ngtcp2 нужны для 0-RTT: снять их можно только с живого соединения, а билет приходит уже
 * после рукопожатия — то есть в этот самый момент. */
void qc_session_new(void *user, const uint8_t *der, size_t n) {
    struct qc *q = user;
    if (!q->want_sess || !q->shared || !q->conn) return;
    uint8_t tp[512];
    ngtcp2_ssize tn = ngtcp2_conn_encode_0rtt_transport_params2(q->conn, tp, sizeof tp);
    if (tn <= 0) return;
    sess_put(q->shared, q->skey, der, n, tp, (size_t)tn);
}

/* ---- потоки ---------------------------------------------------------------------------------- */

static struct qc_stream *stream_find(struct qc *q, int64_t id) {
    for (struct qc_stream *s = q->streams; s; s = s->next)
        if (s->id == id) return s;
    return NULL;
}

static struct qc_stream *stream_get(struct qc *q, int64_t id) {
    struct qc_stream *s = stream_find(q, id);
    if (s) return s;
    s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->id = id;
    s->next = q->streams;
    q->streams = s;
    return s;
}

static void stream_drop(struct qc *q, struct qc_stream *s) {
    for (struct qc_stream **pp = &q->streams; *pp; pp = &(*pp)->next)
        if (*pp == s) { *pp = s->next; break; }
    if (q->rr == s) q->rr = NULL;
    while (s->head) {
        struct qc_chunk *c = s->head;
        s->head = c->next;
        free(c);
    }
    free(s);
}

/* Освободить блоки, подтверждённые целиком. */
static void stream_trim(struct qc_stream *s) {
    while (s->head && s->head->off + s->head->len <= s->acked && s->head->len == QC_CHUNK) {
        struct qc_chunk *c = s->head;
        s->head = c->next;
        if (s->cur == c) s->cur = c->next;
        if (s->tail == c) s->tail = NULL;
        free(c);
    }
}

/* Дописать в буфер потока (место проверил вызывающий). Блоки не двигаются: см. QC_CHUNK. */
static int stream_append(struct qc_stream *s, const uint8_t *d, size_t n) {
    while (n > 0) {
        struct qc_chunk *c = s->tail;
        if (!c || c->len == QC_CHUNK) {
            c = malloc(sizeof *c);
            if (!c) return -1;
            c->next = NULL;
            c->off = s->total;
            c->len = 0;
            if (s->tail) s->tail->next = c; else s->head = c;
            s->tail = c;
            if (!s->cur) s->cur = c;
        }
        size_t k = QC_CHUNK - c->len < n ? QC_CHUNK - c->len : n;
        memcpy(c->data + c->len, d, k);
        c->len += k;
        s->total += k;
        d += k;
        n -= k;
    }
    return 0;
}

/* ---- колбэки ngtcp2 -------------------------------------------------------------------------- */

static ngtcp2_conn *get_conn_cb(ngtcp2_crypto_conn_ref *ref) {
    return ((struct qc *)ref->user_data)->conn;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *ctx) {
    (void)ctx;
    fill_random(dest, destlen);
}

static int new_cid_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, ngtcp2_stateless_reset_token *token,
                      size_t cidlen, void *ud) {
    struct qc *q = ud;
    (void)conn;
    fill_random(cid->data, cidlen);
    cid->datalen = cidlen;
    if (ngtcp2_crypto_generate_stateless_reset_token(token->data, q->secret, sizeof q->secret, cid) != 0)
        return NGTCP2_ERR_CALLBACK_FAILURE;
    return 0;
}

/* Срок PING — по сроку простоя, о котором договорились, а не только по своему. Действует меньший
 * из двух max_idle_timeout (RFC 9000, 10.1), а сервер вправе объявить свой короче нашего (у apernet
 * quic.maxIdleTimeout от 4 с): PING раз в 10 с при сроке сервера 5 с — соединение, которое молча
 * умирает на каждой паузе, хотя узел жив. Поэтому после рукопожатия, когда срок сервера известен,
 * PING идёт не реже трети меньшего срока (и не реже заданного keepalive_ms). Три PING на срок —
 * запас на потерю двух подряд. */
static void keepalive_tune(struct qc *q) {
    if (!q->keepalive_ms || !q->conn) return;
    const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params2(q->conn);
    uint64_t idle = (uint64_t)q->idle_local_ms * NGTCP2_MILLISECONDS;
    if (rp && rp->max_idle_timeout && (!idle || rp->max_idle_timeout < idle)) idle = rp->max_idle_timeout;
    uint64_t ka = (uint64_t)q->keepalive_ms * NGTCP2_MILLISECONDS;
    if (idle && idle / 3 < ka) ka = idle / 3;
    if (ka < 500 * NGTCP2_MILLISECONDS) ka = 500 * NGTCP2_MILLISECONDS;
    ngtcp2_conn_set_keep_alive_timeout(q->conn, ka);
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *ud) {
    struct qc *q = ud;
    if (q->early_tried) {
        /* 0-RTT был предложен: принят или нет, известно только теперь. Принят — потоки, открытые до
         * рукопожатия, продолжаются как есть. Отвергнут — ngtcp2 выбрасывает пакеты 0-RTT и все
         * исходящие потоки (номера начнутся с нуля), а наш буфер потоков (qc_stream) хранит уже
         * несуществующие: его очищаем, билет забываем (сервер его не принял — предлагать снова
         * значило бы получать отказ на каждом соединении), потребителю сообщаем — он повторит запросы. */
        q->early_ok = 0;
        if (!qcssl_early_accepted(q->ssl)) {
            while (q->streams) stream_drop(q, q->streams);
            ngtcp2_conn_tls_early_data_rejected(conn);
            if (q->shared) sess_drop(q->shared, q->skey);
            if (q->ops.on_early_rejected) {
                q->in_cb++;
                q->ops.on_early_rejected(q->user);
                q->in_cb--;
            }
        }
    }
    if (q->pin_on) {
        /* Отпечаток листа — вместо цепочки (так у эталона: pinSHA256 заменяет проверку, а не
         * дополняет её). Сравнение не за постоянное время: отпечаток не секрет. */
        uint8_t h[32];
        if (qcssl_peer_sha256(q->ssl, h) != 0 || memcmp(h, q->pin, 32) != 0) {
            q->why = "сертификат сервера не совпал с pinSHA256";
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }
    q->hs_done = 1;
    keepalive_tune(q);
    if (q->ops.on_handshake) {
        q->in_cb++;
        q->ops.on_handshake(q->user);
        q->in_cb--;
    }
    return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t sid, uint64_t offset,
                               const uint8_t *data, size_t datalen, void *ud, void *sud) {
    struct qc *q = ud;
    (void)offset; (void)sud;
    if (q->ops.on_stream_data) {
        q->in_cb++;
        q->ops.on_stream_data(q->user, sid, data, datalen, (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
        q->in_cb--;
    }
    /* Окно приёма продлеваем сразу: обратного давления нет (quic.h). С flow_manual окно
     * продлевает потребитель (qc_stream_consumed), когда отдал байты дальше: так медленный
     * получатель тормозит отправителя, а не копит очередь в памяти роутера. */
    if (!q->flow_manual) {
        ngtcp2_conn_extend_max_stream_offset(conn, sid, datalen);
        ngtcp2_conn_extend_max_offset(conn, datalen);
    }
    return 0;
}

void qc_stream_consumed(struct qc *q, int64_t sid, size_t n) {
    if (!q || !q->conn || !n) return;
    /* Поток мог закрыться раньше: его окно продлевать нечем и незачем, а окно соединения
     * возвращается всё равно — иначе закрытые потоки съели бы его насовсем. */
    (void)ngtcp2_conn_extend_max_stream_offset(q->conn, sid, n);
    ngtcp2_conn_extend_max_offset(q->conn, n);
    /* ngtcp2 только ставит MAX_STREAM_DATA и MAX_DATA в очередь, а пакет с ними пишется при
     * следующей отправке. Из колбэка отправлять нельзя (мы внутри разбора пакета), и там об
     * этом позаботится конец qc_on_readable; снаружи — сам потребитель зовёт qc_flush_credit. */
    q->credit_dirty = 1;
}

int qc_set_cc(struct qc *q, uint64_t brutal_bps) {
    if (!q || !q->conn || q->closed) return QC_EINVAL;
    /* Тот же потолок, что при открытии (settings_fill): bps * RTT не должно переполнять 64 бита. */
    if (brutal_bps > 0x7fffffffULL) brutal_bps = 0x7fffffffULL;
    ngtcp2_conn_set_cc_brutal(q->conn, brutal_bps, now_ns());     /* наш патч 0002 */
    q->brutal = brutal_bps != 0;
    return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t sid, uint64_t offset,
                                       uint64_t datalen, void *ud, void *sud) {
    struct qc *q = ud;
    (void)conn; (void)sud;
    struct qc_stream *s = stream_find(q, sid);
    if (s && offset + datalen > s->acked) {
        s->acked = offset + datalen;
        stream_trim(s);
    }
    return 0;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags, int64_t sid, uint64_t rx_err,
                           uint64_t tx_err, void *ud, void *sud) {
    struct qc *q = ud;
    (void)conn; (void)sud; (void)tx_err;
    uint64_t err = (flags & NGTCP2_STREAM_CLOSE_FLAG_APP_ERROR_CODE_SET) ? rx_err : 0;
    struct qc_stream *s = stream_find(q, sid);
    if (s) stream_drop(q, s);
    if (q->ops.on_stream_close) {
        q->in_cb++;
        q->ops.on_stream_close(q->user, sid, err);
        q->in_cb--;
    }
    return 0;
}

static int extend_max_stream_data_cb(ngtcp2_conn *conn, int64_t sid, uint64_t max, void *ud, void *sud) {
    struct qc *q = ud;
    (void)conn; (void)max; (void)sud;
    struct qc_stream *s = stream_find(q, sid);
    if (s) s->blocked = 0;
    return 0;
}

static int recv_datagram_cb(ngtcp2_conn *conn, uint32_t flags, const uint8_t *data, size_t datalen, void *ud) {
    struct qc *q = ud;
    (void)conn; (void)flags;
    if (q->ops.on_datagram) {
        q->in_cb++;
        q->ops.on_datagram(q->user, data, datalen);
        q->in_cb--;
    }
    return 0;
}

static const ngtcp2_callbacks g_client_cbs = {
    .client_initial = ngtcp2_crypto_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = recv_stream_data_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .recv_retry = ngtcp2_crypto_recv_retry_cb,
    .rand = rand_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = recv_datagram_cb,
    .version_negotiation = ngtcp2_crypto_version_negotiation_cb,
    .get_new_connection_id2 = new_cid_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
    .stream_close2 = stream_close_cb,
};

/* ---- отправка -------------------------------------------------------------------------------- */

static uint16_t *sa_port(struct sockaddr_storage *ss) {
    return ss->ss_family == AF_INET6 ? &((struct sockaddr_in6 *)ss)->sin6_port
                                     : &((struct sockaddr_in *)ss)->sin_port;
}

/* Выбрать порт назначения из диапазонов прыжков: равновероятно по ПОРТАМ, а не по диапазонам
 * (иначе порт из узкого диапазона выпадал бы чаще), как у эталона (udphop: rand.Intn на весь
 * диапазон). Порт — в порядке хоста. */
static uint16_t hop_pick(const struct qc *q) {
    uint32_t total = 0;
    for (unsigned i = 0; i < q->hop_n; i++) total += (uint32_t)q->hop[2 * i + 1] - q->hop[2 * i] + 1;
    if (!total) return 0;
    uint32_t r;
    fill_random((uint8_t *)&r, sizeof r);
    r %= total;
    for (unsigned i = 0; i < q->hop_n; i++) {
        uint32_t w = (uint32_t)q->hop[2 * i + 1] - q->hop[2 * i] + 1;
        if (r < w) return (uint16_t)(q->hop[2 * i] + r);
        r -= w;
    }
    return q->hop[0];
}

static void raw_send(struct qc *q, const uint8_t *p, size_t n);

/* Выход фильтра из нескольких датаграмм (tx_multi): каждая уходит в сокет как есть. */
static void multi_out(void *ctx, const uint8_t *d, size_t n) {
    raw_send(ctx, d, n);
}

static void send_udp(struct qc *q, const uint8_t *p, size_t n) {
    if (q->filter.tx_multi) {
        (void)q->filter.tx_multi(q->filter.user, p, n, multi_out, q);
        return;
    }
    if (q->filter.tx) {
        /* Фильтр вправе отказать (0): пакет пропадает, как в сети, и ngtcp2 его пересдаст. */
        n = q->filter.tx(q->filter.user, q->obuf, p, n);
        if (!n) return;
        p = q->obuf;
    }
    raw_send(q, p, n);
}

/* Куда слать. 0 — сокет connect()-нут, адрес не нужен; иначе длина адреса, сам адрес — в *to. */
static socklen_t tx_dest(struct qc *q, struct sockaddr_storage *to) {
    if (q->hop_n) {
        /* Смена порта — при отправке, а не по своему таймеру: молчащее соединение шлёт
         * keepalive, и следующий пакет уйдёт уже на новый порт; отдельный таймер ради этого
         * стоил бы ещё одного срока в qc_timeout_ms. Пачка уходит на один порт целиком. */
        uint64_t now = now_ns();
        if (!q->hop_port || (q->hop_ms && now - q->hop_at_ns >= (uint64_t)q->hop_ms * 1000000ull)) {
            q->hop_port = hop_pick(q);
            q->hop_at_ns = now;
        }
        *to = q->remote;
        *sa_port(to) = htons(q->hop_port);
        return q->remote_len;
    }
    if (q->connected) return 0;
    *to = q->remote;
    return q->remote_len;
}

static void raw_send(struct qc *q, const uint8_t *p, size_t n) {
    /* EAGAIN — буфер сокета полон: пакет пропадает, как в сети, и ngtcp2 его пересдаст. Ждать
     * POLLOUT ради этого не стоит — линия событий потребителя не должна знать о записи. */
    struct sockaddr_storage to;
    socklen_t tl = tx_dest(q, &to);
    q->tx_calls++;
    if (tl) (void)sendto(q->fd, p, n, MSG_DONTWAIT, (struct sockaddr *)&to, tl);
    else (void)send(q->fd, p, n, MSG_DONTWAIT);
}

/* ---- пакетный ввод-вывод: чистые части (проверяются tests/qcbatch.c) ---------------------------- */

size_t qc_io_gso_run(const size_t *len, size_t n) {
    if (!n) return 0;
    size_t seg = len[0], bytes = seg, k = 1;
    if (!seg) return 1;
    while (k < n && k < QC_GSO_SEGS) {
        size_t l = len[k];
        if (!l || l > seg || bytes + l > QC_GSO_BYTES) break;
        bytes += l;
        k++;
        if (l < seg) break;         /* короткая — только последняя в пачке */
    }
    return k;
}

int qc_io_gso_fatal(int err) {
    /* Нет UDP_SEGMENT в ядре (EINVAL, ENOPROTOOPT) или нет контрольной суммы в устройстве (EIO): так
     * будет и со следующей пачкой. Всё остальное — обычная потеря отправки (буфер полон, порт закрыт),
     * её отмечать «отказом GSO» нельзя. */
    return err == EIO || err == EINVAL || err == ENOPROTOOPT || err == EOPNOTSUPP || err == EPROTONOSUPPORT;
}

size_t qc_io_gro_next(size_t total, size_t seg, size_t off) {
    if (off >= total) return 0;
    size_t rem = total - off;
    if (!seg) return rem;
    return rem < seg ? rem : seg;
}

/* Размер сегмента из дополнительных данных приёма (UDP_GRO); 0 — приём не склеен. Ядро кладёт int. */
static size_t gro_seg(struct msghdr *mh) {
    /* Обход вручную, а не CMSG_NXTHDR: у musl его проверка границы даёт -Wsign-compare. */
    size_t off = 0, end = mh->msg_controllen;
    while (off + sizeof(struct cmsghdr) <= end) {
        struct cmsghdr *c = (struct cmsghdr *)((char *)mh->msg_control + off);
        size_t clen = c->cmsg_len;
        if (clen < CMSG_LEN(0) || clen > end - off) break;
        if (c->cmsg_level == SOL_UDP && c->cmsg_type == UDP_GRO) {
            size_t l = clen - CMSG_LEN(0);
            if (l >= sizeof(int)) { int v; memcpy(&v, CMSG_DATA(c), sizeof v); return v > 0 ? (size_t)v : 0; }
            if (l == sizeof(uint16_t)) { uint16_t v; memcpy(&v, CMSG_DATA(c), sizeof v); return v; }
        }
        off += CMSG_ALIGN(clen);
    }
    return 0;
}

/* Отправить n готовых датаграмм (iov). Подряд идущие одного размера (последняя может быть короче) —
 * одним вызовом с UDP_SEGMENT: ядро (или сетевая карта) нарезает сегменты, а к нам один вызов вместо
 * десятков. Остальные — sendmmsg по датаграмме на сообщение. Отказ GSO (qc_io_gso_fatal) выключает его
 * для сокета, и пачка уходит sendmmsg; потерянное при EAGAIN ngtcp2 пересдаёт сама. */
static void send_batch(struct qc *q, struct iovec *iov, size_t n) {
    struct sockaddr_storage to;
    socklen_t tl = tx_dest(q, &to);
    size_t i = 0;
    while (i < n) {
        size_t m = n - i < QC_GSO_SEGS ? n - i : QC_GSO_SEGS;
        size_t cnt = 1;
        if (q->gso_ok && m >= 2) {
            size_t lens[QC_GSO_SEGS];
            for (size_t k = 0; k < m; k++) lens[k] = iov[i + k].iov_len;
            size_t run = qc_io_gso_run(lens, m);
            if (run >= 2) {
                union { char b[CMSG_SPACE(sizeof(uint16_t))]; struct cmsghdr a; } cu;
                memset(&cu, 0, sizeof cu);
                struct msghdr mh = { .msg_name = tl ? (void *)&to : NULL, .msg_namelen = tl,
                                     .msg_iov = &iov[i], .msg_iovlen = run,
                                     .msg_control = cu.b, .msg_controllen = sizeof cu.b };
                struct cmsghdr *c = CMSG_FIRSTHDR(&mh);
                c->cmsg_level = SOL_UDP;
                c->cmsg_type = UDP_SEGMENT;
                c->cmsg_len = CMSG_LEN(sizeof(uint16_t));
                uint16_t sz = (uint16_t)lens[0];
                memcpy(CMSG_DATA(c), &sz, sizeof sz);
                q->tx_calls++;
                if (sendmsg(q->fd, &mh, MSG_DONTWAIT) >= 0 || !qc_io_gso_fatal(errno)) { i += run; continue; }
                q->gso_ok = 0;      /* ядро без GSO или устройство без контрольной суммы */
            }
        }
        if (!q->gso_ok) cnt = m;
        struct mmsghdr mm[QC_GSO_SEGS];
        for (size_t k = 0; k < cnt; k++) {
            memset(&mm[k], 0, sizeof mm[k]);
            mm[k].msg_hdr.msg_name = tl ? (void *)&to : NULL;
            mm[k].msg_hdr.msg_namelen = tl;
            mm[k].msg_hdr.msg_iov = &iov[i + k];
            mm[k].msg_hdr.msg_iovlen = 1;
        }
        q->tx_calls++;
        int r = sendmmsg(q->fd, mm, (unsigned)cnt, MSG_DONTWAIT);
        if (r > 0) { i += (size_t)r; continue; }
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) return;
        i++;                        /* эту датаграмму сокет не принял (порт закрыт, слишком велика) — к следующей */
    }
}

/* Что отдать ngtcp2 из потока: не более двух блоков подряд, начиная со смещения sent. */
static size_t stream_vecs(struct qc_stream *s, ngtcp2_vec v[2], uint64_t *covered) {
    struct qc_chunk *c = s->cur;
    /* Хвостовой блок не пропускаем даже исчерпанным: в него допишут (stream_append). */
    while (c && c->off + c->len <= s->sent && c->next) c = c->next;
    s->cur = c;
    size_t nv = 0;
    *covered = 0;
    for (; c && nv < 2; c = c->next) {
        uint64_t start = c->off > s->sent ? c->off : s->sent;
        size_t skip = (size_t)(start - c->off);
        if (skip >= c->len) continue;
        v[nv].base = c->data + skip;
        v[nv].len = c->len - skip;
        *covered += v[nv].len;
        nv++;
    }
    return nv;
}

/* Записать один пакет: датаграмма RFC 9221, если есть очередь, иначе поток по кругу, иначе только
 * служебное (ACK, рукопожатие). Возврат — как у ngtcp2_write_pkt: длина, 0 или отрицательная. */
static ngtcp2_ssize write_pkt_cb(ngtcp2_conn *conn, ngtcp2_path *path, ngtcp2_pkt_info *pi,
                                 uint8_t *dest, size_t destlen, ngtcp2_tstamp ts, void *ud) {
    struct qc *q = ud;
    ngtcp2_ssize nw;
    ngtcp2_ssize dl = -1;

    /* Голова очереди, что уже не влезает в пакет (путь уже, чем было при постановке), не должна
     * стоять вечно: ngtcp2 на такую отвечает «0, не принята», как на окно перегрузки, и очередь
     * вместе с потоками замирала (I-480). Датаграммы ненадёжны — выбрасываем и считаем. */
    while (q->dg_n > 0 && q->hs_done && q->dgq[q->dg_head].n > qc_datagram_max(q)) {
        free(q->dgq[q->dg_head].d);
        q->dg_head = (q->dg_head + 1) % QC_DG_QUEUE;
        q->dg_n--;
        q->dg_dropped++;
    }
    if (q->dg_n > 0 && q->hs_done) {
        struct qc_dg *g = &q->dgq[q->dg_head];
        ngtcp2_vec v = { .base = g->d, .len = g->n };
        int accepted = 0;
        nw = ngtcp2_conn_writev_datagram(conn, path, pi, dest, destlen, &accepted, 0, 0, &v, 1, ts);
        if (accepted || nw < 0) {
            /* Принята — уходит в пакете. Отвергнута с ошибкой — не влезет и потом (размер пакета
             * упал): выбрасываем, датаграммы ненадёжны, а зацикливаться на ней нельзя. Отказ
             * без ошибки (nw == 0, не принята) — окно перегрузки: оставляем до следующего круга. */
            free(g->d);
            q->dg_head = (q->dg_head + 1) % QC_DG_QUEUE;
            q->dg_n--;
            if (!accepted) q->dg_dropped++;
        }
        return nw < 0 ? 0 : nw;
    }

    /* Потоки по кругу: первый, у кого есть что отдать и кого не держит окно потока. */
    size_t cnt = 0;
    for (struct qc_stream *t = q->streams; t; t = t->next) cnt++;
    struct qc_stream *s = q->rr ? q->rr : q->streams;
    /* До рукопожатия потоки отдаются только при 0-RTT: ngtcp2 положит их в пакеты 0-RTT. */
    for (size_t i = 0; i < cnt && s && (q->hs_done || q->early_ok); i++, s = s->next ? s->next : q->streams) {
        uint64_t avail = s->total - s->sent;
        int want_fin = s->fin_req && !s->fin_sent;
        if ((avail == 0 && !want_fin) || s->blocked) continue;
        ngtcp2_vec v[2];
        uint64_t cov = 0;
        size_t nv = avail ? stream_vecs(s, v, &cov) : 0;
        /* FIN — только вместе с последним байтом: если в двух блоках всё не поместилось, она
         * уйдёт на одном из следующих пакетов. */
        uint32_t flags = want_fin && cov == avail ? NGTCP2_WRITE_STREAM_FLAG_FIN : 0;
        nw = ngtcp2_conn_writev_stream(conn, path, pi, dest, destlen, &dl, flags, s->id, v, nv, ts);
        if (nw < 0) {
            if (nw == NGTCP2_ERR_STREAM_DATA_BLOCKED) { s->blocked = 1; continue; }
            if (nw == NGTCP2_ERR_STREAM_SHUT_WR) { s->fin_sent = 1; s->sent = s->total; continue; }
            return nw;
        }
        if (dl >= 0) {
            s->sent += (uint64_t)dl;
            if (flags && s->sent == s->total) s->fin_sent = 1;
        }
        q->rr = s->next ? s->next : q->streams;    /* следующий пакет — со следующего потока */
        return nw;
    }
    /* Нечего отдавать из данных: служебный пакет (рукопожатие, ACK, PING). */
    return ngtcp2_conn_writev_stream(conn, path, pi, dest, destlen, &dl, 0, -1, NULL, 0, ts);
}

static void closed(struct qc *q, int reason, const char *why) {
    if (q->closed) return;
    q->closed = 1;
    if (q->ops.on_closed) {
        q->in_cb++;
        q->ops.on_closed(q->user, reason, why);
        q->in_cb--;
    }
}

/* Отправить всё, что можно сейчас. Возврат — 0 или причина закрытия (<0 из ngtcp2). */
static int flush(struct qc *q) {
    if (q->closed || !q->conn) return QC_ECLOSED;
    q->credit_dirty = 0;
    if (ngtcp2_conn_in_closing_period(q->conn) || ngtcp2_conn_in_draining_period(q->conn)) return 0;
    for (int rounds = 0; rounds < 64; rounds++) {
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        size_t gso = 0;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize nw = ngtcp2_conn_write_aggregate_pkt(q->conn, &ps.path, &pi, q->txbuf, QC_TXBUF,
                                                          &gso, write_pkt_cb, now_ns());
        if (nw < 0) return (int)nw;
        if (nw == 0) return 0;
        if (gso == 0) gso = (size_t)nw;
        if (q->filter.tx_multi) {
            for (size_t off = 0; off < (size_t)nw; off += gso)
                send_udp(q, q->txbuf + off, (size_t)nw - off < gso ? (size_t)nw - off : gso);
        } else {
            struct iovec iov[QC_GSO_SEGS];
            size_t cnt = 0, oo = 0;
            for (size_t off = 0; off < (size_t)nw; off += gso) {
                size_t n = (size_t)nw - off < gso ? (size_t)nw - off : gso;
                const uint8_t *p = q->txbuf + off;
                if (q->filter.tx) {
                    /* Фильтр вправе отказать (0): пакет пропадает, как в сети, и ngtcp2 его пересдаст. */
                    n = q->filter.tx(q->filter.user, q->obuf + oo, p, n);
                    if (!n) continue;
                    p = q->obuf + oo;
                    oo += n;
                }
                iov[cnt].iov_base = (void *)p;
                iov[cnt].iov_len = n;
                if (++cnt == QC_GSO_SEGS) { send_batch(q, iov, cnt); cnt = 0; oo = 0; }
            }
            if (cnt) send_batch(q, iov, cnt);
        }
        /* Пачка кончилась раньше, чем данные: продолжим на следующем круге, если пейсинг позволит
         * (иначе ngtcp2 вернёт 0, а срок — в get_expiry). */
    }
    return 0;
}

static void fail_close(struct qc *q, int err) {
    int reason = QC_CLOSE_ERROR;
    const char *why = q->why ? q->why : ngtcp2_strerror(err);
    if (q->why) reason = QC_CLOSE_HANDSHAKE;
    else if (err == NGTCP2_ERR_IDLE_CLOSE) reason = QC_CLOSE_IDLE;
    else if (err == NGTCP2_ERR_HANDSHAKE_TIMEOUT || err == NGTCP2_ERR_CRYPTO) reason = QC_CLOSE_HANDSHAKE;
    else if (err == NGTCP2_ERR_DRAINING) reason = QC_CLOSE_PEER;
    /* Если ещё можно — отправить CONNECTION_CLOSE: сервер узнает причину, а не будет ждать idle. */
    if (q->conn && !ngtcp2_conn_in_closing_period(q->conn) && !ngtcp2_conn_in_draining_period(q->conn) &&
        err != NGTCP2_ERR_IDLE_CLOSE && err != NGTCP2_ERR_HANDSHAKE_TIMEOUT) {
        ngtcp2_ccerr ce;
        ngtcp2_path_storage ps;
        ngtcp2_pkt_info pi;
        ngtcp2_ccerr_default(&ce);
        if (err == NGTCP2_ERR_CRYPTO)
            ngtcp2_ccerr_set_tls_alert(&ce, ngtcp2_conn_get_tls_alert(q->conn), NULL, 0);
        else
            ngtcp2_ccerr_set_liberr(&ce, err, NULL, 0);
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_ssize n = ngtcp2_conn_write_connection_close(q->conn, &ps.path, &pi, q->txbuf, QC_TXBUF, &ce, now_ns());
        if (n > 0) send_udp(q, q->txbuf, (size_t)n);
    }
    closed(q, reason, why);
}

/* Окна продлены (qc_stream_consumed вне колбэка), а сервер о них ещё не знает — отправить. Без этого
 * у потока, который сервер остановил окном, обновление ждало бы любого другого события QUIC: пакета
 * от сервера (а он молчит — остановлен нами же), срока таймера (PING по молчанию, до десяти секунд)
 * или чужой отправки. Медленный клиент, прочитавший восемь мегабайт, получал остальное пачками раз
 * в десять секунд. */
void qc_flush_credit(struct qc *q) {
    if (!q || !q->credit_dirty || q->in_cb || q->closed || !q->conn) return;
    int rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) fail_close(q, rv);
}

static void settings_fill(ngtcp2_settings *st, ngtcp2_transport_params *tp, uint64_t brutal_bps,
                          size_t datagram_max, unsigned idle_ms, unsigned hs_ms, uint64_t max_data,
                          uint64_t max_stream_data, uint64_t max_streams);
static int addr_parse(const char *host, uint16_t port, struct sockaddr_storage *ss, socklen_t *len);
static int sock_tune(int fd);
static struct qc *qc_alloc(const struct qc_ops *ops, void *user);

#ifdef QC_WITH_SERVER
/* ---- сервер для стендов ----------------------------------------------------------------------
 * Не входит в libsteer: ключ QC_WITH_SERVER задают только стенды (tests/qcloop.c, tests/qcserver.c).
 * Одно соединение на сокет — принимается первый же Initial, остальные пакеты чужих адресов
 * отбрасываются. Этого хватает эхо-серверу для проверки клиента на настоящем рукопожатии, потоках,
 * датаграммах и Brutal, и не тянет в движок то, что ему не нужно (Retry, токены, ротация
 * соединений, ограничение частоты). */
static const ngtcp2_callbacks g_server_cbs = {
    .recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
    .recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
    .handshake_completed = handshake_completed_cb,
    .encrypt = ngtcp2_crypto_encrypt_cb,
    .decrypt = ngtcp2_crypto_decrypt_cb,
    .hp_mask = ngtcp2_crypto_hp_mask_cb,
    .recv_stream_data = recv_stream_data_cb,
    .acked_stream_data_offset = acked_stream_data_offset_cb,
    .rand = rand_cb,
    .update_key = ngtcp2_crypto_update_key_cb,
    .extend_max_stream_data = extend_max_stream_data_cb,
    .delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
    .delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
    .recv_datagram = recv_datagram_cb,
    .get_new_connection_id2 = new_cid_cb,
    .get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb,
    .stream_close2 = stream_close_cb,
};

static int srv_accept(struct qc *q, const struct sockaddr_storage *from, socklen_t fl,
                      const uint8_t *pkt, size_t n) {
    ngtcp2_pkt_hd hd;
    if (ngtcp2_accept(&hd, pkt, n) != 0) return -1;
    q->remote = *from;
    q->remote_len = fl;
    q->ssl = qcssl_new(q->ctx, &q->ref, NULL, q->alpn, 1, 0);
    if (!q->ssl) return -1;
    ngtcp2_settings st;
    ngtcp2_transport_params tp;
    settings_fill(&st, &tp, q->brutal_bps, q->datagram_max, q->idle_ms, 0, q->max_data,
                  q->max_stream_data, q->max_streams);
    ngtcp2_cid scid;
    scid.datalen = QC_CID_LEN;
    fill_random(scid.data, scid.datalen);
    tp.original_dcid = hd.dcid;
    tp.original_dcid_present = 1;
    tp.stateless_reset_token_present = 1;
    if (ngtcp2_crypto_generate_stateless_reset_token(tp.stateless_reset_token, q->secret,
                                                     sizeof q->secret, &scid) != 0) return -1;
    ngtcp2_path path = {
        .local = { .addr = (ngtcp2_sockaddr *)&q->local, .addrlen = q->local_len },
        .remote = { .addr = (ngtcp2_sockaddr *)&q->remote, .addrlen = q->remote_len },
    };
    if (ngtcp2_conn_server_new(&q->conn, &hd.scid, &scid, &path, hd.version, &g_server_cbs, &st, &tp,
                               NULL, q) != 0) { q->conn = NULL; return -1; }
    ngtcp2_conn_set_tls_native_handle(q->conn, q->ssl);
    return 0;
}

int qc_listen(const struct qc_srv_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out) {
    if (!cfg || !ops || !out || !cfg->bind_host || !cfg->alpn) return QC_EINVAL;
    *out = NULL;
    struct qc *q = qc_alloc(ops, user);
    if (!q) return QC_ENOMEM;
    int rc = QC_ESOCK;
    q->server = 1;
    if (addr_parse(cfg->bind_host, cfg->port, &q->local, &q->local_len) != 0) { rc = QC_EINVAL; goto fail; }
    q->fd = socket(q->local.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (q->fd < 0) goto fail;
    q->gro_on = sock_tune(q->fd);
    if (bind(q->fd, (struct sockaddr *)&q->local, q->local_len) != 0) goto fail;
    q->local_len = sizeof q->local;
    if (getsockname(q->fd, (struct sockaddr *)&q->local, &q->local_len) != 0) goto fail;
    q->ctx = qcssl_ctx_server(cfg->cert_der, cfg->cert_n, cfg->key_der, cfg->key_n);
    if (!q->ctx) { rc = QC_ETLS; goto fail; }
    q->own_ctx = 1;
    snprintf(q->alpn, sizeof q->alpn, "%s", cfg->alpn);
    q->brutal_bps = cfg->brutal_bps;
    q->brutal = cfg->brutal_bps != 0;
    q->datagram_max = cfg->datagram_max;
    q->idle_ms = cfg->idle_ms;
    q->max_data = cfg->max_data;
    q->max_stream_data = cfg->max_stream_data;
    q->max_streams = cfg->max_streams;
    q->send_buf = cfg->send_buf ? cfg->send_buf : (1u << 20);
    *out = q;
    return 0;
fail:
    qc_free(q);
    return rc;
}

uint16_t qc_local_port(const struct qc *q) {
    if (q->local.ss_family == AF_INET6) return ntohs(((const struct sockaddr_in6 *)&q->local)->sin6_port);
    return ntohs(((const struct sockaddr_in *)&q->local)->sin_port);
}
#endif

/* ---- события --------------------------------------------------------------------------------- */

int qc_timeout_ms(struct qc *q) {
    if (!q || q->closed || !q->conn) return -1;
    uint64_t exp = ngtcp2_conn_get_expiry(q->conn), now = now_ns();
    if (exp == UINT64_MAX) return -1;
    if (exp <= now) return 0;
    uint64_t ms = (exp - now + NGTCP2_MILLISECONDS - 1) / NGTCP2_MILLISECONDS;
    return ms > 0x7fffffff ? 0x7fffffff : (int)ms;
}

int qc_on_timer(struct qc *q) {
    if (q->closed) return QC_ECLOSED;
    if (!q->conn) return 0;         /* сервер стенда до первого пакета */
    int rv = ngtcp2_conn_handle_expiry(q->conn, now_ns());
    if (rv != 0) { fail_close(q, rv); return QC_ECLOSED; }
    rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) { fail_close(q, rv); return QC_ECLOSED; }
    return q->closed ? QC_ECLOSED : 0;
}

/* Одна принятая датаграмма: отбор по адресу, фильтр, ngtcp2. 0 — идём дальше (в том числе когда
 * датаграмма отброшена), QC_ECLOSED — соединение закрылось. */
static int rx_dgram(struct qc *q, uint8_t *buf, size_t n, const struct sockaddr_storage *src, socklen_t fl) {
    struct sockaddr_storage from = *src;
#ifdef QC_WITH_SERVER
    if (!q->conn && q->server && srv_accept(q, &from, fl, buf, n) != 0) return 0;
#endif
    if (!q->conn) return 0;     /* клиент без соединения бывает только после qc_free — сюда не дойти */
    if (q->hop_n) {
        /* Ответ пришёл с порта диапазона, а ngtcp2 знает один путь — базовый адрес сервера.
         * Чужой хозяин или порт вне диапазона — посторонний пакет: отбросить. Порт в пути
         * подменяется базовым, и для ngtcp2 «прыжков» нет вовсе: это и есть смысл приёма
         * эталона — QUIC не замечает смены порта. */
        uint16_t fp = ntohs(*sa_port(&from)), ok = 0;
        for (unsigned h = 0; h < q->hop_n; h++)
            if (fp >= q->hop[2 * h] && fp <= q->hop[2 * h + 1]) ok = 1;
        struct sockaddr_storage cmp = from;
        *sa_port(&cmp) = *sa_port(&q->remote);
        if (!ok || fl != q->remote_len || memcmp(&cmp, &q->remote, fl) != 0) return 0;
        from = q->remote;
        fl = q->remote_len;
    }
    if (q->filter.rx) {
        size_t m = q->filter.rx(q->filter.user, buf, buf, n);
        if (!m) return 0;
        n = m;
    }
    ngtcp2_path path = {
        .local = { .addr = (ngtcp2_sockaddr *)&q->local, .addrlen = q->local_len },
        .remote = { .addr = (ngtcp2_sockaddr *)&from, .addrlen = fl },
    };
    ngtcp2_pkt_info pi = { 0 };
    int rv = ngtcp2_conn_read_pkt(q->conn, &path, &pi, buf, n, now_ns());
    if (rv != 0) {
        if (rv == NGTCP2_ERR_DRAINING) { closed(q, QC_CLOSE_PEER, "peer closed"); return QC_ECLOSED; }
        if (rv == NGTCP2_ERR_DROP_CONN) { closed(q, QC_CLOSE_ERROR, "dropped"); return QC_ECLOSED; }
        fail_close(q, rv);
        return QC_ECLOSED;
    }
    return q->closed ? QC_ECLOSED : 0;
}

/* Принять, что есть в сокете, одним системным вызовом (recvmmsg). С UDP_GRO каждое сообщение — до 64 КиБ:
 * ядро склеило подряд пришедшие датаграммы одного потока в одну, размер сегмента — в дополнительных
 * данных (gro_seg). Без него — по QC_RX_BATCH датаграмм в слоты по QC_RX_SLOT байт. Возврат — число сообщений
 * (в q->rx->mm[i].msg_len длина, в from[i] отправитель), 0 — сокет пуст, -1 — порт закрыт (ICMP),
 * -2 — иная ошибка. */
static int rx_batch(const struct qc *q) { return q->gro_on ? QC_RX_GRO_BATCH : QC_RX_BATCH; }
static uint8_t *rx_slot(const struct qc *q, int i) {
    return q->rxbuf + (size_t)i * (q->gro_on ? 65536 : QC_RX_SLOT);
}

static int rx_recv(struct qc *q) {
    struct qc_rx *r = q->rx;
    int cnt = rx_batch(q);
    for (int i = 0; i < cnt; i++) {
        r->iov[i].iov_base = rx_slot(q, i);
        r->iov[i].iov_len = q->gro_on ? 65536 : QC_RX_SLOT;
        memset(&r->mm[i], 0, sizeof r->mm[i]);
        r->mm[i].msg_hdr.msg_name = &r->from[i];
        r->mm[i].msg_hdr.msg_namelen = sizeof r->from[i];
        r->mm[i].msg_hdr.msg_iov = &r->iov[i];
        r->mm[i].msg_hdr.msg_iovlen = 1;
        if (q->gro_on) {
            r->mm[i].msg_hdr.msg_control = r->ctl[i].b;
            r->mm[i].msg_hdr.msg_controllen = sizeof r->ctl[i].b;
        }
    }
    for (;;) {
        q->rx_calls++;
        int got = recvmmsg(q->fd, r->mm, (unsigned)cnt, MSG_DONTWAIT, NULL);
        if (got >= 0) return got;
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return errno == ECONNREFUSED ? -1 : -2;
    }
}

int qc_on_readable(struct qc *q) {
    if (q->closed) return QC_ECLOSED;
    /* Не больше 256 датаграмм за проход (как было): линия событий потребителя не должна стоять в
     * одном соединении, остальное её ждёт по уровню (EPOLLIN не гасится). */
    for (int budget = 256; budget > 0;) {
        int cnt = rx_recv(q);
        if (cnt == 0) break;
        if (cnt == -1) { /* ICMP «порт закрыт»: сервера нет */
            /* Причина — первой: fail_close закрыл бы соединение своим текстом («ERR_CLOSING»), и
             * человек читал бы про состояние ngtcp2 вместо «порт закрыт». CONNECTION_CLOSE
             * слать некому — порт ответил ICMP. */
            closed(q, QC_CLOSE_ERROR, "connection refused");
            return QC_ECLOSED;
        }
        if (cnt < 0) break;
        for (int m = 0; m < cnt; m++) {
            struct msghdr *mh = &q->rx->mm[m].msg_hdr;
            if (mh->msg_flags & MSG_TRUNC) continue;    /* не влезла в слот: ngtcp2 такую всё равно не примет */
            uint8_t *base = rx_slot(q, m);
            size_t total = q->rx->mm[m].msg_len;
            size_t seg = q->gro_on ? gro_seg(mh) : 0;
            size_t n;
            for (size_t off = 0; (n = qc_io_gro_next(total, seg, off)) != 0; off += n) {
                budget--;
                int rv = rx_dgram(q, base + off, n, &q->rx->from[m], mh->msg_namelen);
                if (rv != 0) return rv;
            }
        }
        /* recvmmsg вернул меньше, чем просили, — сокет опустел: лишний вызов с EAGAIN не нужен. */
        if (cnt < rx_batch(q)) break;
    }
    int rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) { fail_close(q, rv); return QC_ECLOSED; }
    return q->closed ? QC_ECLOSED : 0;
}

int qc_run(struct qc *q, int timeout_ms) {
    if (q->closed) return QC_ECLOSED;
    if (q->epfd < 0) {
        q->epfd = epoll_create1(EPOLL_CLOEXEC);
        if (q->epfd < 0) return QC_ESOCK;
        struct epoll_event ev = { .events = EPOLLIN, .data.fd = q->fd };
        if (epoll_ctl(q->epfd, EPOLL_CTL_ADD, q->fd, &ev) != 0) return QC_ESOCK;
    }
    int t = qc_timeout_ms(q);
    if (t >= 0 && (timeout_ms < 0 || t < timeout_ms)) timeout_ms = t;
    struct epoll_event ev;
    int r = epoll_wait(q->epfd, &ev, 1, timeout_ms);
    if (r > 0) return qc_on_readable(q);
    /* Срок мог наступить и без пакета; вызов безвреден, если наступил не он: handle_expiry
     * проверяет время сам. */
    return qc_on_timer(q);
}

/* ---- открытие -------------------------------------------------------------------------------- */

struct qc_tls *qc_tls_new(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file) {
    struct qc_tls *t = calloc(1, sizeof *t);
    if (!t) return NULL;
    t->ctx = qcssl_ctx_client(insecure, ca_pem, ca_pem_n, ca_file);
    if (!t->ctx) { free(t); return NULL; }
    pthread_mutex_init(&t->mu, NULL);
    return t;
}

void qc_tls_early(struct qc_tls *t) {
    if (!t || t->early) return;
    qcssl_ctx_sessions(t->ctx);
    t->early = 1;
}

void qc_tls_free(struct qc_tls *t) {
    if (!t) return;
    qcssl_ctx_free(t->ctx);
    for (unsigned i = 0; i < QC_SESS_MAX; i++) sess_clear(&t->sess[i]);
    pthread_mutex_destroy(&t->mu);
    free(t);
}

static void settings_fill(ngtcp2_settings *st, ngtcp2_transport_params *tp, uint64_t brutal_bps,
                          size_t datagram_max, unsigned idle_ms, unsigned hs_ms, uint64_t max_data,
                          uint64_t max_stream_data, uint64_t max_streams) {
    ngtcp2_settings_default(st);       /* без суффикса версии: поле Brutal есть только у последней */
    ngtcp2_transport_params_default(tp);
    st->initial_ts = now_ns();
    st->handshake_timeout = (hs_ms ? hs_ms : 10000) * NGTCP2_MILLISECONDS;    if (brutal_bps) {
        st->cc_algo = NGTCP2_CC_ALGO_BRUTAL;
        /* Потолок — чтобы bps * RTT не переполнял 64 бита (ngtcp2_brutal.c): 2^31 байт/с — 17 Гбит/с. */
        st->cc_brutal_bps = brutal_bps > 0x7fffffffULL ? 0x7fffffffULL : brutal_bps;
    } else {
        st->cc_algo = NGTCP2_CC_ALGO_CUBIC;
    }
    tp->initial_max_data = max_data ? max_data : 8u << 20;
    tp->initial_max_stream_data_bidi_local = max_stream_data ? max_stream_data : 2u << 20;
    tp->initial_max_stream_data_bidi_remote = tp->initial_max_stream_data_bidi_local;
    tp->initial_max_stream_data_uni = tp->initial_max_stream_data_bidi_local;
    tp->initial_max_streams_bidi = max_streams ? max_streams : 16;
    tp->initial_max_streams_uni = 3;
    tp->max_idle_timeout = (idle_ms ? idle_ms : 30000) * NGTCP2_MILLISECONDS;
    tp->max_datagram_frame_size = datagram_max;
}

static int addr_parse(const char *host, uint16_t port, struct sockaddr_storage *ss, socklen_t *len) {
    memset(ss, 0, sizeof *ss);
    struct sockaddr_in *a4 = (struct sockaddr_in *)ss;
    struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)ss;
    if (inet_pton(AF_INET, host, &a4->sin_addr) == 1) {
        a4->sin_family = AF_INET;
        a4->sin_port = htons(port);
        *len = sizeof *a4;
        return 0;
    }
    if (inet_pton(AF_INET6, host, &a6->sin6_addr) == 1) {
        a6->sin6_family = AF_INET6;
        a6->sin6_port = htons(port);
        *len = sizeof *a6;
        return 0;
    }
    return -1;
}

/* Возврат — 1, если включён UDP_GRO (приём склеенных датаграмм; ядро Linux с 5.0, на роутерах 6.6 и
 * новее есть); отказ setsockopt — 0 и приём пачками recvmmsg. */
static int sock_tune(int fd) {
    /* Буферы побольше: пачка Brutal и приём на скорости в десятки мегабит. Потолок задаёт ядро
     * (rmem_max/wmem_max); отказ безвреден. */
    int sz = 1 << 20;
    (void)setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    (void)setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    int one = 1;
    return setsockopt(fd, SOL_UDP, UDP_GRO, &one, sizeof one) == 0;
}

static struct qc *qc_alloc(const struct qc_ops *ops, void *user) {
    struct qc *q = calloc(1, sizeof *q);
    if (!q) return NULL;
    q->fd = q->epfd = -1;
    q->ops = *ops;
    q->user = user;
    q->txbuf = malloc(QC_TXBUF);
    q->rxbuf = malloc(QC_RXBUF_GRO);
    q->obuf = malloc(QC_OBUF);
    q->rx = calloc(1, sizeof *q->rx);
    q->gso_ok = 1;
    if (!q->txbuf || !q->rxbuf || !q->obuf || !q->rx) {
        free(q->txbuf); free(q->rxbuf); free(q->obuf); free(q->rx); free(q);
        return NULL;
    }
    fill_random(q->secret, sizeof q->secret);
    q->ref.get_conn = get_conn_cb;
    q->ref.user_data = q;
    return q;
}

int qc_open(const struct qc_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out) {
    if (!cfg || !ops || !out || !cfg->host || !cfg->port || !cfg->alpn) return QC_EINVAL;
    *out = NULL;
    struct qc *q = qc_alloc(ops, user);
    if (!q) return QC_ENOMEM;
    int rc = QC_ESOCK;

    if (addr_parse(cfg->host, cfg->port, &q->remote, &q->remote_len) != 0) { rc = QC_EINVAL; goto fail; }
    q->fd = socket(q->remote.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (q->fd < 0) goto fail;
    q->gro_on = sock_tune(q->fd);
    if (cfg->sock_mark && setsockopt(q->fd, SOL_SOCKET, SO_MARK, &cfg->sock_mark, sizeof cfg->sock_mark) != 0 &&
        cfg->mark_required) {
        rc = QC_ESOCK;
        goto fail;
    }
    if (cfg->filter) q->filter = *cfg->filter;
    q->flow_manual = cfg->flow_manual;
    if (cfg->pin_sha256) { memcpy(q->pin, cfg->pin_sha256, 32); q->pin_on = 1; }
    if (cfg->hop_n) {
        if (cfg->hop_n > QC_HOP_RANGES) { rc = QC_EINVAL; goto fail; }
        for (unsigned i = 0; i < cfg->hop_n; i++) {
            if (cfg->hop[2 * i] > cfg->hop[2 * i + 1] || !cfg->hop[2 * i]) { rc = QC_EINVAL; goto fail; }
            q->hop[2 * i] = cfg->hop[2 * i];
            q->hop[2 * i + 1] = cfg->hop[2 * i + 1];
        }
        q->hop_n = cfg->hop_n;
        q->hop_ms = cfg->hop_ms;
    }
    if (q->hop_n) {
        /* Без connect(): адрес назначения меняется с каждым прыжком. Локальный адрес для пути
         * ngtcp2 берём из связанного сокета — bind на любой порт, семейство по серверу. Платим
         * ICMP-ошибками connect() (мёртвый порт виден только по истечению рукопожатия) — у
         * прыжков «мёртвый порт» и так обычное дело, не всякий порт диапазона открыт. */
        struct sockaddr_storage any;
        memset(&any, 0, sizeof any);
        any.ss_family = q->remote.ss_family;
        if (bind(q->fd, (struct sockaddr *)&any, q->remote_len) != 0) goto fail;
    } else {
        /* connect() выбирает локальный адрес и включает ICMP-ошибки (ECONNREFUSED), которых у
         * несвязанного сокета нет: без них мёртвый порт виден только по истечению рукопожатия. */
        if (connect(q->fd, (struct sockaddr *)&q->remote, q->remote_len) != 0) goto fail;
        q->connected = 1;
    }
    q->local_len = sizeof q->local;
    if (getsockname(q->fd, (struct sockaddr *)&q->local, &q->local_len) != 0) goto fail;

    if (cfg->tls) {
        q->ctx = cfg->tls->ctx;
    } else {
        q->ctx = qcssl_ctx_client(cfg->insecure || cfg->pin_sha256, cfg->ca_pem, cfg->ca_pem_n, cfg->ca_file);
        if (!q->ctx) { rc = QC_ETLS; goto fail; }
        q->own_ctx = 1;
    }
    q->ssl = qcssl_new(q->ctx, &q->ref, cfg->sni, cfg->alpn, 0, !(cfg->insecure || cfg->pin_sha256));
    if (!q->ssl) { rc = QC_ETLS; goto fail; }

    ngtcp2_settings st;
    ngtcp2_transport_params tp;
    settings_fill(&st, &tp, cfg->brutal_bps, cfg->datagram_max, cfg->idle_ms, cfg->handshake_ms,
                  cfg->max_data, cfg->max_stream_data, cfg->max_streams);
    /* BBR — когда скорость не задана (hysteria2 без up: эталон берёт BBR, а не CUBIC). */
    if (cfg->bbr && !cfg->brutal_bps) st.cc_algo = NGTCP2_CC_ALGO_BBR;
    q->datagram_max = cfg->datagram_max;
    q->send_buf = cfg->send_buf ? cfg->send_buf : (1u << 20);
    q->brutal = cfg->brutal_bps != 0;

    ngtcp2_cid dcid, scid;
    dcid.datalen = 18;
    fill_random(dcid.data, dcid.datalen);
    scid.datalen = QC_CID_LEN;
    fill_random(scid.data, scid.datalen);
    ngtcp2_path path = {
        .local = { .addr = (ngtcp2_sockaddr *)&q->local, .addrlen = q->local_len },
        .remote = { .addr = (ngtcp2_sockaddr *)&q->remote, .addrlen = q->remote_len },
    };
    if (ngtcp2_conn_client_new(&q->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &g_client_cbs,
                               &st, &tp, NULL, q) != 0) { rc = QC_EQUIC; goto fail; }
    ngtcp2_conn_set_tls_native_handle(q->conn, q->ssl);
    /* PING по молчанию: соединение без обмена умирает по idle_ms, а поток hysteria2 живёт часами
     * без байта (ssh, долгий запрос). Эталон шлёт keepalive раз в 10 с. */
    if (cfg->keepalive_ms)
        ngtcp2_conn_set_keep_alive_timeout(q->conn, (uint64_t)cfg->keepalive_ms * NGTCP2_MILLISECONDS);
    q->keepalive_ms = cfg->keepalive_ms;
    q->idle_local_ms = cfg->idle_ms ? cfg->idle_ms : 30000;

    /* 0-RTT: билет прошлой сессии этого сервера (sni и порт), если он разрешает early data, ставится
     * в TLS ДО первого пакета, а параметры транспорта той сессии — в ngtcp2 (без них он не знает
     * лимитов потоков и не даст открыть поток до рукопожатия). Билет без early data всё равно
     * ставится: рукопожатие по PSK короче и не тащит сертификат. Отказ на любом шаге — обычное
     * рукопожатие: 0-RTT ускорение, а не условие. */
    if (cfg->early_data && cfg->tls && cfg->tls->early) {
        q->shared = cfg->tls;
        q->want_sess = 1;
        snprintf(q->skey, sizeof q->skey, "%s:%u", cfg->sni && cfg->sni[0] ? cfg->sni : cfg->host,
                 (unsigned)cfg->port);
        uint8_t *der = NULL, *tpb = NULL;
        size_t der_n = 0, tp_n = 0;
        if (sess_get(cfg->tls, q->skey, &der, &der_n, &tpb, &tp_n)) {
            int er = qcssl_set_session(q->ssl, der, der_n);
            if (er == 1 && ngtcp2_conn_decode_and_set_0rtt_transport_params(q->conn, tpb, tp_n) == 0) {
                q->early_tried = q->early_ok = 1;
            } else if (er < 0) {
                sess_drop(cfg->tls, q->skey);          /* запись негодна — не мешать следующему соединению */
            }
            free(der);
            free(tpb);
        }
    }

    /* Первый пакет рукопожатия. Отказ отправки здесь — отказ открытия, а не «закрыто потом»:
     * потребитель ещё не получил объект, on_closed ему не нужен. */
    int rv = flush(q);
    if (rv != 0) { rc = QC_EQUIC; goto fail; }
    *out = q;
    return 0;
fail:
    qc_free(q);
    return rc;
}

/* ---- потоки, датаграммы, закрытие ------------------------------------------------------------- */

int qc_handshake_done(const struct qc *q) { return q && q->hs_done; }
int qc_early_ready(const struct qc *q) { return q && q->early_ok && !q->hs_done && !q->closed; }
int qc_fd(const struct qc *q) { return q->fd; }

int qc_stream_open(struct qc *q, int64_t *sid) {
    if (!q || q->closed) return QC_ECLOSED;
    if (!q->hs_done && !q->early_ok) return QC_EAGAIN;
    int rv = ngtcp2_conn_open_bidi_stream(q->conn, sid, NULL);
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) return QC_EAGAIN;
    if (rv != 0) return QC_EQUIC;
    if (!stream_get(q, *sid)) return QC_ENOMEM;
    return 0;
}

int qc_stream_open_uni(struct qc *q, int64_t *sid) {
    if (!q || q->closed) return QC_ECLOSED;
    if (!q->hs_done) return QC_EAGAIN;
    int rv = ngtcp2_conn_open_uni_stream(q->conn, sid, NULL);
    if (rv == NGTCP2_ERR_STREAM_ID_BLOCKED) return QC_EAGAIN;
    if (rv != 0) return QC_EQUIC;
    if (!stream_get(q, *sid)) return QC_ENOMEM;
    return 0;
}

ssize_t qc_stream_send(struct qc *q, int64_t sid, const uint8_t *d, size_t n, int fin) {
    if (!q || q->closed) return QC_ECLOSED;
    struct qc_stream *s = stream_get(q, sid);
    if (!s) return QC_ENOMEM;
    if (s->fin_req) return QC_EINVAL;       /* передача уже закрыта */
    size_t used = (size_t)(s->total - s->acked);
    size_t room = used < q->send_buf ? q->send_buf - used : 0;
    size_t take = n < room ? n : room;
    if (take > 0 && stream_append(s, d, take) != 0) return QC_ENOMEM;
    if (fin && take == n) s->fin_req = 1;
    int rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) fail_close(q, rv);
    return (ssize_t)take;
}

size_t qc_stream_buffered(const struct qc *q, int64_t sid) {
    for (const struct qc_stream *s = q->streams; s; s = s->next)
        if (s->id == sid) return (size_t)(s->total - s->acked);
    return 0;
}

int qc_stream_reset(struct qc *q, int64_t sid, uint64_t app_err) {
    if (!q || q->closed) return QC_ECLOSED;
    int rv = ngtcp2_conn_shutdown_stream(q->conn, 0, sid, app_err);
    if (rv != 0) return QC_ENOSTREAM;
    rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) fail_close(q, rv);
    return 0;
}

size_t qc_datagram_max(const struct qc *q) {
    if (!q || !q->conn || !q->hs_done) return 0;
    const ngtcp2_transport_params *rp = ngtcp2_conn_get_remote_transport_params2(q->conn);
    if (!rp || rp->max_datagram_frame_size == 0) return 0;
    /* Пакет: короткий заголовок (1 + cid + номер до 4) + тег 16 + кадр (тип 1 + длина до 2). */
    /* Размер пути, а не потолок настроек: пакет больше пути ngtcp2 не собирает (до разведки PMTU —
     * 1200), и датаграмма по потолку застревала бы в очереди навсегда (I-480). */
    size_t udp = ngtcp2_conn_get_path_max_tx_udp_payload_size2(q->conn);
    size_t over = 1 + QC_CID_LEN + 4 + 16 + 3;
    size_t cap = udp > over ? udp - over : 0;
    size_t peer = rp->max_datagram_frame_size > 3 ? (size_t)rp->max_datagram_frame_size - 3 : 0;
    return cap < peer ? cap : peer;
}

int qc_datagram_send(struct qc *q, const uint8_t *d, size_t n) {
    if (!q || q->closed) return QC_ECLOSED;
    if (!q->hs_done) return QC_EAGAIN;
    if (n > qc_datagram_max(q)) return QC_ETOOBIG;
    if (q->dg_n >= QC_DG_QUEUE) return QC_EAGAIN;
    uint8_t *c = malloc(n ? n : 1);
    if (!c) return QC_ENOMEM;
    memcpy(c, d, n);
    struct qc_dg *g = &q->dgq[(q->dg_head + q->dg_n) % QC_DG_QUEUE];
    g->d = c;
    g->n = n;
    q->dg_n++;
    int rv = flush(q);
    if (rv != 0 && rv != QC_ECLOSED) fail_close(q, rv);
    return 0;
}

void qc_close(struct qc *q, uint64_t app_err) {
    if (!q || q->closed || !q->conn) return;
    ngtcp2_ccerr ce;
    ngtcp2_path_storage ps;
    ngtcp2_pkt_info pi;
    ngtcp2_ccerr_default(&ce);
    ngtcp2_ccerr_set_application_error(&ce, app_err, NULL, 0);
    ngtcp2_path_storage_zero(&ps);
    ngtcp2_ssize n = ngtcp2_conn_write_connection_close(q->conn, &ps.path, &pi, q->txbuf, QC_TXBUF, &ce, now_ns());
    if (n > 0) send_udp(q, q->txbuf, (size_t)n);
    closed(q, QC_CLOSE_LOCAL, "closed by us");
}

void qc_free(struct qc *q) {
    if (!q) return;
    if (q->conn) ngtcp2_conn_del(q->conn);
    qcssl_free(q->ssl);
    if (q->own_ctx) qcssl_ctx_free(q->ctx);
    while (q->streams) stream_drop(q, q->streams);
    while (q->dg_n) {
        free(q->dgq[q->dg_head].d);
        q->dg_head = (q->dg_head + 1) % QC_DG_QUEUE;
        q->dg_n--;
    }
    if (q->epfd >= 0) close(q->epfd);
    if (q->fd >= 0) close(q->fd);
    free(q->txbuf);
    free(q->rxbuf);
    free(q->obuf);
    free(q->rx);
    free(q);
}

void qc_io_force(struct qc *q, int gso, int gro) {
    q->gso_ok = gso != 0;
    int v = gro != 0;
    q->gro_on = setsockopt(q->fd, SOL_UDP, UDP_GRO, &v, sizeof v) == 0 && v;
}

void qc_stats_get(struct qc *q, struct qc_stats *st) {
    memset(st, 0, sizeof *st);
    if (!q || !q->conn) return;
    ngtcp2_conn_info ci;
    ngtcp2_conn_get_conn_info2(q->conn, &ci);
    st->rtt_us = ci.smoothed_rtt / NGTCP2_MICROSECONDS;
    st->cwnd = ci.cwnd;
    st->in_flight = ci.bytes_in_flight;
    st->pkt_sent = ci.pkt_sent;
    st->pkt_recv = ci.pkt_recv;
    st->bytes_sent = ci.bytes_sent;
    st->bytes_recv = ci.bytes_recv;
    st->pkt_lost = ci.pkt_lost;
    st->handshake_done = q->hs_done;
    st->brutal = q->brutal;
    st->dg_dropped = q->dg_dropped;
    st->tx_calls = q->tx_calls;
    st->rx_calls = q->rx_calls;
}
