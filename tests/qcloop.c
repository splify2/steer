/* QUIC клиент против QUIC-сервера в одном процессе, по настоящему UDP на 127.0.0.1 (шаг 7
 * выпуска 1.10).
 *
 * ЗАЧЕМ. Обёртка src/proto/quic — это ngtcp2 на нашем wolfSSL, и проверить её можно только
 * рукопожатием с живым собеседником: ключи по уровням шифрования, защита заголовков (AES-ECB
 * из user_settings.h), TLS 1.3 wolfSSL с ALPN и SNI, потоки, датаграммы RFC 9221, закрытие. Ни
 * одну из этих частей стенд чистых функций не увидит. Собеседник — та же обёртка в режиме сервера
 * (QC_WITH_SERVER: одно соединение, эхо), что заодно проверяет обе роли одним кодом.
 *
 * Что проверяется:
 *   - рукопожатие с ALPN; эхо потока в 300 КБ с fin и сверкой каждого байта; эхо 40 датаграмм;
 *   - то же с Brutal у клиента (cc_algo BRUTAL из патча ngtcp2) — и что алгоритм действительно
 *     Brutal (stats.brutal);
 *   - проверка сертификата ВКЛЮЧЕНА: свой корень + верное имя — проходит; чужой корень и неверное
 *     имя — рукопожатие срывается; мусор вместо корней и несуществующий файл — отказ qc_open (не
 *     «проверка молча выключена»);
 *   - ALPN не совпал — соединение не устанавливается;
 *   - закрытие клиентом доходит до сервера; мёртвый порт закрывает соединение быстро (ICMP);
 *   - датаграммы: сервер их не принимает — qc_datagram_max() == 0 и отказ QC_ETOOBIG.
 *
 * Нужны wolfSSL и ngtcp2 — поэтому стенд собирает tests/ext-test.sh, а не `make test`.
 *
 *     cc -O2 -w -DQC_WITH_SERVER $(make -s print-inc) -Itests -o build/qcloop tests/qcloop.c \
 *        src/proto/quic/quic.c src/proto/quic/qcssl.c <ngtcp2.a> <wolfssl.a> -lpthread
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "quic.h"
#include "qccert.h"
#include "unit.h"

#define ALPN "qcecho"
#define STREAM_N (300 * 1000)
#define DG_N 40

static uint64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static uint8_t pat(size_t i) { return (uint8_t)((i * 7 + 3) & 0xff); }

/* ---- сервер стенда: эхо потоков и датаграмм ---------------------------------------------------- */
struct srv {
    struct qc *q;
    int hs, closed, close_reason;
    size_t stream_in, dg_in;
};

static void srv_hs(void *u) { ((struct srv *)u)->hs = 1; }
static void srv_stream(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct srv *s = u;
    s->stream_in += n;
    /* Буфер потока 1 МиБ, тест шлёт 300 КБ: принимается всё; иначе стенд упал бы в проверке ниже. */
    if (qc_stream_send(s->q, sid, d, n, fin) != (ssize_t)n) s->stream_in = (size_t)-1;
}
static void srv_dg(void *u, const uint8_t *d, size_t n) {
    struct srv *s = u;
    s->dg_in++;
    (void)qc_datagram_send(s->q, d, n);
}
static void srv_closed(void *u, int reason, const char *why) {
    struct srv *s = u;
    (void)why;
    s->closed = 1;
    s->close_reason = reason;
}

/* ---- клиент стенда ---------------------------------------------------------------------------- */
struct cli {
    struct qc *q;
    int hs, closed, close_reason;
    int64_t sid;
    size_t got, bad;
    int fin;
    int dg_got, dg_bad;
    uint8_t *sendbuf;
    size_t sent;
};

static void cli_hs(void *u) { ((struct cli *)u)->hs = 1; }
static void cli_stream(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct cli *c = u;
    (void)sid;
    for (size_t i = 0; i < n; i++)
        if (d[i] != pat(c->got + i)) c->bad++;
    c->got += n;
    if (fin) c->fin = 1;
}
static void cli_dg(void *u, const uint8_t *d, size_t n) {
    struct cli *c = u;
    /* Датаграмма i — n = 1 + i*20 байт, все равны i. */
    if (n == 0 || n > 1 + DG_N * 20 || d[0] >= DG_N || n != (size_t)(1 + d[0] * 20)) c->dg_bad++;
    for (size_t i = 0; i < n; i++) if (d[i] != d[0]) c->dg_bad++;
    c->dg_got++;
}
static void cli_closed(void *u, int reason, const char *why) {
    struct cli *c = u;
    (void)why;
    c->closed = 1;
    c->close_reason = reason;
}

static const struct qc_ops srv_ops = { srv_hs, srv_stream, NULL, srv_dg, srv_closed };
static const struct qc_ops cli_ops = { cli_hs, cli_stream, NULL, cli_dg, cli_closed };

static int start_srv(struct srv *s, size_t dg_max, uint64_t brutal, uint16_t *port) {
    struct qc_srv_cfg sc = {
        .bind_host = "127.0.0.1", .alpn = ALPN,
        .cert_der = qc_cert_der, .cert_n = sizeof qc_cert_der,
        .key_der = qc_key_der, .key_n = sizeof qc_key_der,
        .datagram_max = dg_max, .brutal_bps = brutal,
    };
    memset(s, 0, sizeof *s);
    int rc = qc_listen(&sc, &srv_ops, s, &s->q);
    if (rc == 0) *port = qc_local_port(s->q);
    return rc;
}

static void cfg_default(struct qc_cfg *c, uint16_t port) {
    memset(c, 0, sizeof *c);
    c->host = "127.0.0.1";
    c->port = port;
    c->alpn = ALPN;
    c->sni = "localhost";
    c->ca_pem = (const uint8_t *)qc_cert_pem;
    c->ca_pem_n = sizeof qc_cert_pem - 1;
    c->handshake_ms = 3000;
}

/* Гонять обе стороны, пока cond() не станет истиной или не выйдет время. */
static int pump(struct srv *s, struct cli *c, int (*cond)(struct srv *, struct cli *), unsigned limit_ms) {
    uint64_t end = ms_now() + limit_ms;
    while (ms_now() < end) {
        if (cond(s, c)) return 1;
        if (s->q && !s->closed) qc_run(s->q, 1);
        if (c->q && !c->closed) qc_run(c->q, 1);
    }
    return cond(s, c);
}

static int c_hs(struct srv *s, struct cli *c) { return s->hs && c->hs; }
static int c_closed_any(struct srv *s, struct cli *c) { (void)s; return c->closed; }
static int c_srv_closed(struct srv *s, struct cli *c) { (void)c; return s->closed; }
static int c_echo_done(struct srv *s, struct cli *c) { (void)s; return c->fin && c->dg_got >= DG_N; }

/* Эхо потока и датаграмм на уже установленном соединении. */
static void echo_round(const char *tag, struct srv *s, struct cli *c) {
    char nm[96];
    c->sendbuf = malloc(STREAM_N);
    for (size_t i = 0; i < STREAM_N; i++) c->sendbuf[i] = pat(i);
    int rc = qc_stream_open(c->q, &c->sid);
    snprintf(nm, sizeof nm, "%s: поток открылся", tag);
    check(nm, 0, rc);
    /* Порциями: буфер потока 1 МиБ, но проверяем и путь «принято меньше, чем дали». */
    size_t off = 0;
    uint64_t end = ms_now() + 5000;
    while (off < STREAM_N && ms_now() < end) {
        size_t n = STREAM_N - off > 64 * 1024 ? 64 * 1024 : STREAM_N - off;
        ssize_t w = qc_stream_send(c->q, c->sid, c->sendbuf + off, n, off + n == STREAM_N);
        if (w < 0) break;
        off += (size_t)w;
        qc_run(s->q, 0);
        qc_run(c->q, 0);
    }
    snprintf(nm, sizeof nm, "%s: все 300000 байт приняты в очередь", tag);
    check(nm, STREAM_N, (long)off);
    int dg_rc = 0;
    for (int i = 0; i < DG_N; i++) {
        uint8_t d[1 + DG_N * 20];
        size_t n = (size_t)(1 + i * 20);
        memset(d, i, n);
        int r;
        uint64_t e2 = ms_now() + 2000;
        while ((r = qc_datagram_send(c->q, d, n)) == QC_EAGAIN && ms_now() < e2) {
            qc_run(s->q, 1);
            qc_run(c->q, 1);
        }
        if (r != 0) dg_rc = r;
    }
    snprintf(nm, sizeof nm, "%s: 40 датаграмм в очереди", tag);
    check(nm, 0, dg_rc);
    int ok = pump(s, c, c_echo_done, 10000);
    snprintf(nm, sizeof nm, "%s: эхо потока и 40 датаграмм вернулось", tag);
    check(nm, 1, ok);
    snprintf(nm, sizeof nm, "%s: поток вернулся целиком (300000 байт)", tag);
    check(nm, STREAM_N, (long)c->got);
    snprintf(nm, sizeof nm, "%s: ни одного искажённого байта", tag);
    check(nm, 0, (long)c->bad);
    snprintf(nm, sizeof nm, "%s: fin от сервера дошёл", tag);
    check(nm, 1, c->fin);
    snprintf(nm, sizeof nm, "%s: датаграммы без искажений", tag);
    check(nm, 0, c->dg_bad);
    free(c->sendbuf);
    c->sendbuf = NULL;
}

/* Свободный UDP-порт, на котором никто не слушает: занять и закрыть. */
static uint16_t dead_port(void) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t l = sizeof a;
    bind(fd, (struct sockaddr *)&a, sizeof a);
    getsockname(fd, (struct sockaddr *)&a, &l);
    close(fd);
    return ntohs(a.sin_port);
}

/* gso/gro: -1 — как есть (что дало ядро), 0 — выключить, 1 — включить (qc_io_force) у ОБЕИХ сторон. */
static void scenario_echo(const char *tag, uint64_t cli_brutal, int gso, int gro) {
    struct srv s;
    struct cli c;
    uint16_t port = 0;
    char nm[96];
    memset(&c, 0, sizeof c);
    int rc = start_srv(&s, 1200, 0, &port);
    snprintf(nm, sizeof nm, "%s: сервер стенда поднялся", tag);
    check(nm, 0, rc);
    if (rc) return;
    struct qc_cfg cfg;
    cfg_default(&cfg, port);
    cfg.datagram_max = 1200;
    cfg.brutal_bps = cli_brutal;
    rc = qc_open(&cfg, &cli_ops, &c, &c.q);
    snprintf(nm, sizeof nm, "%s: qc_open", tag);
    check(nm, 0, rc);
    if (rc) { qc_free(s.q); return; }
    if (gso >= 0) { qc_io_force(c.q, gso, gro); qc_io_force(s.q, gso, gro); }
    snprintf(nm, sizeof nm, "%s: рукопожатие TLS 1.3 + ALPN + проверка сертификата", tag);
    check(nm, 1, pump(&s, &c, c_hs, 5000));
    snprintf(nm, sizeof nm, "%s: клиент знает, что рукопожатие завершено", tag);
    check(nm, 1, qc_handshake_done(c.q));
    if (c.hs) {
        struct qc_stats st;
        qc_stats_get(c.q, &st);
        snprintf(nm, sizeof nm, "%s: алгоритм перегрузки — %s", tag, cli_brutal ? "Brutal" : "не Brutal");
        check(nm, cli_brutal ? 1 : 0, st.brutal);
        snprintf(nm, sizeof nm, "%s: датаграммы разрешены (max > 1000)", tag);
        check(nm, 1, qc_datagram_max(c.q) > 1000);
        echo_round(tag, &s, &c);
        qc_stats_get(c.q, &st);
        snprintf(nm, sizeof nm, "%s: статистика идёт (отправлено > 300 КБ, RTT задан)", tag);
        check(nm, 1, st.bytes_sent > STREAM_N && st.rtt_us > 0);
        /* Пакетный ввод-вывод: вызовов UDP заметно меньше, чем пакетов (раньше — по вызову на пакет). */
        snprintf(nm, sizeof nm, "%s: отправка пачками (вызовов %llu на %llu пакетов)", tag,
                 (unsigned long long)st.tx_calls, (unsigned long long)st.pkt_sent);
        check(nm, 1, st.tx_calls * 2 < st.pkt_sent);
        snprintf(nm, sizeof nm, "%s: приём пачками (вызовов %llu на %llu пакетов)", tag,
                 (unsigned long long)st.rx_calls, (unsigned long long)st.pkt_recv);
        check(nm, 1, st.rx_calls * 2 < st.pkt_recv);
        /* Закрытие клиентом доходит до сервера. */
        qc_close(c.q, 7);
        snprintf(nm, sizeof nm, "%s: закрытие клиентом — сервер видит (peer)", tag);
        check(nm, 1, pump(&s, &c, c_srv_closed, 3000) && s.close_reason == QC_CLOSE_PEER);
        snprintf(nm, sizeof nm, "%s: клиент получил on_closed (local)", tag);
        check(nm, QC_CLOSE_LOCAL, c.close_reason);
    }
    qc_free(c.q);
    qc_free(s.q);
}

/* want_reason: причина закрытия у клиента; -1 — либо QC_CLOSE_HANDSHAKE, либо QC_CLOSE_PEER (когда
 * отказывает сервер, клиент узнаёт об этом закрытием от него). Сертификат проверяет клиент —
 * там причина обязана быть именно рукопожатием, а не «что-то сломалось». */
static void scenario_fail(const char *name, const char *alpn, const char *sni, const char *ca_pem,
                          size_t ca_n, int expect_open_rc, int want_reason) {
    struct srv s;
    struct cli c;
    uint16_t port = 0;
    memset(&c, 0, sizeof c);
    if (start_srv(&s, 0, 0, &port) != 0) { check(name, 0, 1); return; }
    struct qc_cfg cfg;
    cfg_default(&cfg, port);
    cfg.alpn = alpn;
    cfg.sni = sni;
    if (ca_pem) { cfg.ca_pem = (const uint8_t *)ca_pem; cfg.ca_pem_n = ca_n; }
    int rc = qc_open(&cfg, &cli_ops, &c, &c.q);
    if (expect_open_rc != 0) {
        char nm[128];
        snprintf(nm, sizeof nm, "%s: qc_open отказывает", name);
        check(nm, expect_open_rc, rc);
        qc_free(s.q);
        return;
    }
    if (rc != 0) { check(name, 0, rc); qc_free(s.q); return; }
    pump(&s, &c, c_closed_any, 4000);
    char nm[128];
    snprintf(nm, sizeof nm, "%s: рукопожатие не состоялось", name);
    check(nm, 1, c.closed && !c.hs);
    snprintf(nm, sizeof nm, "%s: причина закрытия", name);
    check(nm, 1, want_reason >= 0 ? c.close_reason == want_reason
                                  : (c.close_reason == QC_CLOSE_HANDSHAKE || c.close_reason == QC_CLOSE_PEER));
    qc_free(c.q);
    qc_free(s.q);
}

/* Крупные датаграммы: всё, что qc_datagram_max() обещает, обязано уйти, а очередь датаграмм не
 * должна застревать — следом идут поток и ещё одна датаграмма. Дефект I-480: датаграмма,
 * не влезавшая в пакет, оставалась головой очереди навсегда, и всё соединение замирало. */
static int c_bigdg_done(struct srv *s, struct cli *c) { (void)s; return c->fin; }

static void scenario_bigdg(void) {
    struct srv s;
    struct cli c;
    uint16_t port = 0;
    char nm[96];
    memset(&c, 0, sizeof c);
    int rc = start_srv(&s, 65535, 0, &port);
    check("крупные датаграммы: сервер поднялся", 0, rc);
    if (rc) return;
    struct qc_cfg cfg;
    cfg_default(&cfg, port);
    cfg.datagram_max = 65535;
    rc = qc_open(&cfg, &cli_ops, &c, &c.q);
    check("крупные датаграммы: qc_open", 0, rc);
    if (rc) { qc_free(s.q); return; }
    check("крупные датаграммы: рукопожатие", 1, pump(&s, &c, c_hs, 5000));
    size_t mx = qc_datagram_max(c.q);
    static uint8_t d[4096];
    memset(d, 0x5a, sizeof d);
    int sent = 0;
    for (size_t n = mx > 80 ? mx - 80 : 1; n <= mx + 100 && n <= sizeof d; n += 4) {
        int r = qc_datagram_send(c.q, d, n);
        if (r == 0) sent++;
        else if (r != QC_ETOOBIG) check("крупные датаграммы: отказ только QC_ETOOBIG", 0, r);
        qc_run(s.q, 0);
        qc_run(c.q, 0);
    }
    pump(&s, &c, c_closed_any, 800);
    size_t got_before = s.dg_in;
    snprintf(nm, sizeof nm, "крупные датаграммы: дошла хотя бы одна из %d (max=%zu)", sent, mx);
    check(nm, 1, got_before > 0);
    /* Очередь жива: поток эхом и маленькая датаграмма. */
    c.sendbuf = malloc(STREAM_N);
    for (size_t i = 0; i < STREAM_N; i++) c.sendbuf[i] = pat(i);
    int64_t sid = 0;
    check("крупные датаграммы: поток открылся", 0, qc_stream_open(c.q, &sid));
    check("крупные датаграммы: поток принят", 1000, qc_stream_send(c.q, sid, c.sendbuf, 1000, 1));
    uint8_t small[21];
    memset(small, 1, sizeof small);
    check("крупные датаграммы: малая датаграмма принята", 0, qc_datagram_send(c.q, small, sizeof small));
    check("крупные датаграммы: после них эхо потока вернулось (соединение не замерло)", 1,
          pump(&s, &c, c_bigdg_done, 3000));
    check("крупные датаграммы: после них дошла и малая", 1, s.dg_in > got_before);
    free(c.sendbuf);
    qc_free(c.q);
    qc_free(s.q);
}

int main(void) {
    scenario_echo("CUBIC", 0, -1, -1);
    scenario_echo("Brutal", 50u * 1000 * 1000, -1, -1);
    /* Запасные пути ввода-вывода: без GSO — sendmmsg, без GRO — recvmmsg, без обоих; с GRO принудительно. */
    scenario_echo("CUBIC без GSO", 0, 0, 1);
    scenario_echo("CUBIC без GRO", 0, 1, 0);
    scenario_echo("CUBIC без GSO и GRO", 0, 0, 0);
    scenario_echo("Brutal с GSO и GRO", 50u * 1000 * 1000, 1, 1);
    scenario_bigdg();

    /* Проверка сертификата. */
    scenario_fail("чужой корень", ALPN, "localhost", qc_other_pem, sizeof qc_other_pem - 1, 0, QC_CLOSE_HANDSHAKE);
    scenario_fail("неверное имя", ALPN, "example.org", NULL, 0, 0, QC_CLOSE_HANDSHAKE);
    scenario_fail("ALPN не совпал", "other", "localhost", NULL, 0, 0, -1);
    scenario_fail("мусор вместо корней", ALPN, "localhost", "not a pem", 9, QC_ETLS, 0);
    {
        struct cli c;
        struct qc_cfg cfg;
        memset(&c, 0, sizeof c);
        cfg_default(&cfg, 4433);
        cfg.ca_pem = NULL;
        cfg.ca_file = "/nonexistent/ca-bundle.crt";
        check("нет файла корней: qc_open отказывает (не «без проверки»)", QC_ETLS,
              qc_open(&cfg, &cli_ops, &c, &c.q));
    }

    /* Мёртвый порт: ICMP «порт закрыт» закрывает соединение быстро, не по таймауту рукопожатия. */
    {
        struct cli c;
        struct srv s = { 0 };
        struct qc_cfg cfg;
        memset(&c, 0, sizeof c);
        cfg_default(&cfg, dead_port());
        cfg.handshake_ms = 20000;
        int rc = qc_open(&cfg, &cli_ops, &c, &c.q);
        check("мёртвый порт: qc_open", 0, rc);
        uint64_t t0 = ms_now();
        pump(&s, &c, c_closed_any, 3000);
        check("мёртвый порт: соединение закрыто быстро (< 2 с)", 1, c.closed && ms_now() - t0 < 2000);
        qc_free(c.q);
    }

    /* Сервер без датаграмм. */
    {
        struct srv s;
        struct cli c;
        uint16_t port = 0;
        memset(&c, 0, sizeof c);
        start_srv(&s, 0, 0, &port);
        struct qc_cfg cfg;
        cfg_default(&cfg, port);
        qc_open(&cfg, &cli_ops, &c, &c.q);
        pump(&s, &c, c_hs, 5000);
        uint8_t d[10] = { 0 };
        check("сервер без датаграмм: qc_datagram_max() == 0", 0, (long)qc_datagram_max(c.q));
        check("сервер без датаграмм: отправка — QC_ETOOBIG", QC_ETOOBIG, qc_datagram_send(c.q, d, sizeof d));
        qc_free(c.q);
        qc_free(s.q);
    }
    return unit_done("qcloop");
}
