/* Транспорт grpc: конец потока от сервера не должен съедать данные и обязан быть замечен (issue 39).
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Xray (grpc-go) кончает поток, когда цель закрылась: последние данные,
 * концевые HEADERS с END_STREAM и RST_STREAM(NO_ERROR) уходят одним сбросом буфера — одной записью
 * TLS. Две поломки, и обе видны только на ЭТОМ сочетании:
 *
 *   1. h2_read, встретив RST_STREAM, возвращал отказ, а набранные в том же вызове данные пропадали —
 *      вызывающие смотрят на код раньше, чем на got. Проба узла (ответ цели — один пакет и FIN)
 *      падала «ответа нет: поток закрыт сервером (RST/GOAWAY)» на исправном узле, сторож после двух
 *      таких проб объявлял узел мёртвым и останавливал трафик, а у каждого третьего клиентского
 *      соединения терялся хвост ответа. Это проверяет tests/h2match.c на уровне кадров;
 *   2. когда данные отданы, а конец потока уже известен (END_STREAM пришёл в той же записи или отказ
 *      отложен), сказать о нём можно только следующим чтением, а сокет молчит — сервер всё отправил.
 *      Цикл туннеля читает сокет по событию, поэтому клиент не получал FIN до уборки по простою
 *      (120 с): ответ целиком, а соединение висит. Транспорт обязан говорить об этом через
 *      transport_has_data (transport_ops.pending) — это проверяется здесь, на настоящем транспорте.
 *
 * КАК. Транспорт и h2.c настоящие и компонуются отдельными объектами (XHUPMATCH_SRC в Makefile; include .c из
 * src стенды больше не плодят — храповик в tests/buildmatch.sh), связь голая (security=none) на
 * сокетной паре: «сервер» стенда пишет на другой конец кадры HTTP/2 руками — одним write, чтобы
 * h2_read увидел их одной записью. TLS и Reality заглушены: до них дело не доходит. Сетей и прав не
 * нужно, поэтому стенд живёт в `make test`. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include "transport.h"
#include "reality.h"

/* ---- заглушки TLS и Reality: связь стенда голая, до них дело не доходит ------------ */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n)
    { (void)in; (void)out; (void)out_n; return -1; }
int tls13_has_record(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_buffered(const struct tls13 *t) { (void)t; return 0; }
size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap)
    { (void)t; (void)out; (void)cap; return 0; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n)
    { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
    { (void)t; (void)o; (void)cap; *got = 0; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *bn)
    { (void)t; *b = NULL; *bn = 0; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }

/* ---- стенд ----------------------------------------------------------------------- */

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-84s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* сторона «сервера» у сокетной пары */

static void srv_drain(void) {
    unsigned char b[8192];
    while (recv(g_srv, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

static void s_put32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v >> 24); p[1] = (unsigned char)(v >> 16);
    p[2] = (unsigned char)(v >> 8);  p[3] = (unsigned char)v;
}

/* Кадр HTTP/2 в out; возвращает длину. */
static size_t frame(unsigned char *out, unsigned char type, unsigned char flags, uint32_t sid,
                    const unsigned char *body, size_t n) {
    out[0] = (unsigned char)(n >> 16); out[1] = (unsigned char)(n >> 8); out[2] = (unsigned char)n;
    out[3] = type; out[4] = flags;
    s_put32(out + 5, sid);
    if (n) memcpy(out + 9, body, n);
    return 9 + n;
}

/* Сообщение gRPC с Hunk { data = d } внутри: [0][длина u32][0x0A][длина varint][данные]. */
static size_t grpc_msg(unsigned char *out, const char *d) {
    size_t n = strlen(d);
    out[0] = 0;
    s_put32(out + 1, (uint32_t)(2 + n));      /* короткие данные: тег и один байт длины */
    out[5] = 0x0A;
    out[6] = (unsigned char)n;
    memcpy(out + 7, d, n);
    return 7 + n;
}

#define FRH 0x01
#define FRD 0x00
#define FRR 0x03
#define FEND_HEADERS 0x04
#define FEND_STREAM  0x01

static int open_stream(struct transport *c) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    /* Срок чтения: на сломанном коде чтение, которого нечем разбудить, повисло бы, а стенд должен падать. */
    struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
    setsockopt(sp[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memset(c, 0, sizeof(*c));
    c->fr = &tr_grpc;
    c->link.fd = sp[0];
    c->link.plain = 1;
    struct tr_node n;
    memset(&n, 0, sizeof(n));
    n.host = "stand.example"; n.sni = "stand.example"; n.service = "svc"; n.mode = "gun";
    int rc = tr_grpc.open(c, &n, 5);
    srv_drain();
    return rc;
}

static void t_end_in_one_record(int with_rst, int with_end_stream, const char *what) {
    struct transport c;
    check(open_stream(&c) == 0, "поток открыт");
    unsigned char w[512];
    size_t n = 0;
    static const unsigned char ok[1] = { 0x88 };
    n += frame(w + n, FRH, FEND_HEADERS, 1, ok, 1);                       /* :status 200 */
    unsigned char m[64];
    size_t mn = grpc_msg(m, "hello");
    n += frame(w + n, FRD, 0, 1, m, mn);
    if (with_end_stream) n += frame(w + n, FRH, FEND_HEADERS | FEND_STREAM, 1, ok, 1);  /* концевые */
    if (with_rst) { unsigned char z[4] = { 0, 0, 0, 0 }; n += frame(w + n, FRR, 0, 1, z, 4); }
    if (write(g_srv, w, n) != (ssize_t)n) { perror("write"); exit(2); }

    /* Всё — одной записью: одно чтение разбирает её целиком. */
    unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got = 0;
    int rc = transport_read(&c, buf, sizeof(buf), &got);
    char line[200];
    snprintf(line, sizeof(line), "%s: данные «hello» отданы, а не потеряны", what);
    check(rc == 0 && got == 5 && !memcmp(buf, "hello", 5), line);
    if (with_rst || with_end_stream) {
        snprintf(line, sizeof(line), "%s: конец потока виден без нового события сокета (has_data)", what);
        check(transport_has_data(&c) == 1, line);
        rc = transport_read(&c, buf, sizeof(buf), &got);
        snprintf(line, sizeof(line), "%s: следующее чтение — конец потока", what);
        check(rc == H2_ERESET, line);
    } else {
        snprintf(line, sizeof(line), "%s: без конца потока has_data молчит", what);
        check(transport_has_data(&c) == 0, line);
    }
    transport_close(&c);
}

static void t_trailers_only(const char *what) {
    /* Ответ из одних концевых HEADERS: сервер отказал в методе. Данных нет вовсе, поток закончен. */
    struct transport c;
    check(open_stream(&c) == 0, "поток открыт");
    unsigned char w[64];
    static const unsigned char ok[1] = { 0x88 };
    size_t n = frame(w, FRH, FEND_HEADERS | FEND_STREAM, 1, ok, 1);
    if (write(g_srv, w, n) != (ssize_t)n) { perror("write"); exit(2); }
    unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got = 0;
    int rc = transport_read(&c, buf, sizeof(buf), &got);
    int pend = transport_has_data(&c);
    int rc2 = transport_read(&c, buf, sizeof(buf), &got);
    char line[160];
    snprintf(line, sizeof(line), "%s: первое чтение без ошибки и без данных", what);
    check(rc == 0 && got == 0, line);
    snprintf(line, sizeof(line), "%s: конец потока объявлен через has_data", what);
    check(pend == 1, line);
    snprintf(line, sizeof(line), "%s: следующее чтение — конец потока", what);
    check(rc2 == H2_ERESET, line);
    transport_close(&c);
}

int main(void) {
    t_end_in_one_record(1, 1, "данные + END_STREAM + RST_STREAM одной записью");
    t_end_in_one_record(0, 1, "данные + END_STREAM без RST_STREAM");
    t_end_in_one_record(1, 0, "данные + RST_STREAM без END_STREAM");
    t_end_in_one_record(0, 0, "только данные");
    t_trailers_only("ответ из одних концевых HEADERS");
    printf(g_fail ? "\ngrpcmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
