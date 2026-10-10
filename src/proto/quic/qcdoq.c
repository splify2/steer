/* Сторона QUIC шва резолвера (src/dnsd/dupq.h): соединения DoQ поверх обёртки quic.h. Зачем шов и
 * почему файл здесь, а не в src/dnsd — в шапке dupq.h. Логики DoQ тут нет (кадры — src/dnsd/doq.c,
 * потоки и очередь — src/dnsd/dup.c): только перевод вызовов и общий контекст TLS. */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include "dupq.h"
#include "quic.h"

_Static_assert(DUPQ_EAGAIN == QC_EAGAIN, "dup.c ждёт от шва то же «сейчас нельзя», что отдаёт обёртка");

/* Контекст TLS для соединений DoQ — один на процесс. Корни (около 140 сертификатов, ~200 КБ PEM)
 * разбираются при создании, и делать это на каждое соединение значило бы каждый раз останавливать
 * цикл резолвера на разбор файла: его создаёт поток установки (dupq_prepare), цикл берёт готовый.
 * Не освобождается: живёт, пока живёт процесс. Если файла корней нет, контекст не создаётся, и
 * DoQ-апстрим честно отказывает, а не соединяется без проверки. */
static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static struct qc_tls *g_tls;

int dupq_prepare(const char *roots) {
    pthread_mutex_lock(&g_mu);
    if (!g_tls) {
        g_tls = qc_tls_new(0, NULL, 0, roots);
        /* 0-RTT по билету прошлой сессии — по умолчанию: вопрос DNS идемпотентен, и RFC 9250 (5.5)
         * прямо разрешает слать его в early data. STEER_DOQ_EARLY_DATA=0 выключает: для сервера, который
         * принимает 0-RTT неверно, или чтобы сравнить время. Билеты живут в памяти процесса. */
        const char *e = getenv("STEER_DOQ_EARLY_DATA");
        if (g_tls && !(e && e[0] == '0')) qc_tls_early(g_tls);
    }
    int ok = g_tls != NULL;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

int dupq_ready(void) {
    pthread_mutex_lock(&g_mu);
    int ok = g_tls != NULL;
    pthread_mutex_unlock(&g_mu);
    return ok;
}

/* Обратные вызовы обёртки и шва одной формы: сводим к одной таблице. Структуры разные по типу, но
 * поля совпадают по смыслу, поэтому переносим их явно, а не приведением типов. */
int dupq_open(const struct dupq_cfg *c, const struct dupq_ops *o, void *user, struct dupq **out) {
    struct qc_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = c->host;
    cfg.port = c->port;
    cfg.sni = c->sni;                       /* проверка имени в сертификате — по нему (verify_name) */
    cfg.alpn = c->alpn ? c->alpn : "doq";   /* RFC 9250, 4.1.1; "h3" у DoH по HTTP/3 (RFC 9114, 3.1) */
    cfg.tls = g_tls;
    cfg.sock_mark = c->sock_mark;
    cfg.mark_required = c->sock_mark != 0;  /* без метки уйти мимо выхода нельзя */
    cfg.handshake_ms = c->handshake_ms;
    cfg.idle_ms = c->idle_ms;
    cfg.early_data = c->early_data;
    struct qc_ops ops;
    memset(&ops, 0, sizeof(ops));
    ops.on_early_rejected = o->on_early_rejected;
    ops.on_handshake = o->on_handshake;
    ops.on_stream_data = o->on_stream_data;
    ops.on_stream_close = o->on_stream_close;
    ops.on_closed = o->on_closed;
    struct qc *q = NULL;
    int rc = qc_open(&cfg, &ops, user, &q);
    *out = (struct dupq *)q;
    return rc;
}

void dupq_close(struct dupq *q, uint64_t e) { qc_close((struct qc *)q, e); }
void dupq_free(struct dupq *q) { qc_free((struct qc *)q); }
int dupq_fd(const struct dupq *q) { return qc_fd((const struct qc *)q); }
int dupq_timeout_ms(struct dupq *q) { return qc_timeout_ms((struct qc *)q); }
int dupq_on_readable(struct dupq *q) { return qc_on_readable((struct qc *)q); }
int dupq_on_timer(struct dupq *q) { return qc_on_timer((struct qc *)q); }
int dupq_early_ready(const struct dupq *q) { return qc_early_ready((const struct qc *)q); }
int dupq_stream_open(struct dupq *q, int64_t *sid) { return qc_stream_open((struct qc *)q, sid); }
int dupq_stream_open_uni(struct dupq *q, int64_t *sid) { return qc_stream_open_uni((struct qc *)q, sid); }
ssize_t dupq_stream_send(struct dupq *q, int64_t sid, const uint8_t *d, size_t n, int fin) {
    return qc_stream_send((struct qc *)q, sid, d, n, fin);
}
int dupq_stream_reset(struct dupq *q, int64_t sid, uint64_t e) { return qc_stream_reset((struct qc *)q, sid, e); }
