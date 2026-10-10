/* Ответ сервера на выгрузку xhttp (stream-up и packet-up): отказ обязан дойти до отправителя.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. У stream-up и packet-up выгрузка идёт своей связью, и её ответы
 * читает только up_drain — попутно с отправкой. Прежде он был void и всё прочитанное
 * выбрасывал, включая отказ: сервер xhttp отвечает 400 на кусок с неверной набивкой, а
 * vless_send возвращал успех, и узел выглядел живым, хотя данные не шли (I-219). У packet-up
 * было хуже: ответ на кусок приходит, когда открыт уже следующий, и h2.c таких кадров не
 * разбирал вовсе — «не наш поток». Стенды tests/run-tunnel*.sh до этого не достают: у
 * поддельного сервера там голый tcp, без xhttp.
 *
 * КАК. Файл включает транспорт xhttp целиком — src/proto/transport/trxhttp.c (up_drain и
 * up_request статические; до шага 2 выпуска 1.10 они жили в клиенте VLESS, client.c) — и берёт
 * настоящий h2.c и остальные ярусы транспорта отдельными объектами. Связь выгрузки — голая
 * (plain, как при security=none) на сокетной паре: что клиент пишет, стенд вычитывает и
 * выбрасывает, а «сервер» пишет на другой конец кадры HTTP/2 руками. TLS и Reality стенду не
 * нужны и подменены заглушками; заглушек заголовков не нужно вовсе: tls13.h включает только
 * src/lib/scrypto.h, а в нём нет типов криптобиблиотеки. Сетей и прав не нужно, поэтому стенд
 * живёт в `make test`. */
#include "../src/proto/transport/trxhttp.c"

#include <stdlib.h>
#include <sys/socket.h>
#include "reality.h"

/* ---- заглушки TLS и Reality: связь стенда голая, до них дело не доходит ------------ */

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)out; (void)out_n; *out_len = 0; return -1; }
/* С шага 5 выпуска 1.10 trsec.c зовёт и вариант с носителем — ради ALPN http/1.1 у ws и
 * httpupgrade; до него здесь тоже не доходит. */
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)cfg; (void)st; (void)car; (void)out; (void)out_n; *out_len = 0; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth)
    { (void)t; (void)fd; (void)ch; (void)n; (void)ss; (void)auth; return -1; }
const char *tls13_verify_reason(void) { return ""; }
/* trsec.c разбирает ключ pqv (reality.c) — до него у стенда дело не доходит. */
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
    printf("%-74s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

static int g_srv = -1;                /* сторона «сервера» у сокетной пары */

/* Выбросить всё, что клиент успел написать: преамбулу, HEADERS, DATA. */
static void srv_drain(void) {
    unsigned char b[8192];
    while (recv(g_srv, b, sizeof(b), MSG_DONTWAIT) > 0) {}
}

/* HEADERS от сервера на поток sid с одним байтом HPACK: статический индекс :status.
 * 0x88 — 200, 0x8C — 400 (RFC 7541, приложение A). */
static void srv_headers(uint32_t sid, unsigned char hpack, int end_stream) {
    unsigned char f[10] = { 0, 0, 1, 0x01, (unsigned char)(0x04 | (end_stream ? 0x01 : 0)),
                            (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, hpack };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

static void conn_init(struct transport *c, enum xhttp_mode xh, int fd) {
    memset(c, 0, sizeof(*c));
    c->link.fd = -1;
    c->fr = &tr_xhttp;
    c->xh.mode = xh;
    c->xh.up.link.fd = fd;
    c->xh.up.link.plain = 1;
    snprintf(c->xh.authority, sizeof(c->xh.authority), "stand.example");
    snprintf(c->xh.up_path, sizeof(c->xh.up_path), "/xh/0f1e2d3c");
}

static int new_pair(int *cli) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sp) != 0) return -1;
    if (g_srv >= 0) close(g_srv);
    g_srv = sp[1];
    *cli = sp[0];
    return 0;
}

static const unsigned char piece[] = "кусок выгрузки";

/* packet-up: ответ на кусок 0 приходит, когда открыт уже кусок 1. */
static void t_packet_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* кусок 0, поток 1 */
    srv_drain();
    srv_headers(1, hpack, 1);                                /* ответ на кусок 0 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* кусок 1, поток 3 */
    srv_drain();
    if (want_refused)
        check(rc0 == 0 && rc1 == H2_ESTATUS &&
              strstr(transport_strerror(rc1), "400") != NULL, what);
    else
        check(rc0 == 0 && rc1 == 0, what);
    close(fd);
}

/* stream-up: один длинный POST, отказ приходит на него самого. */
static void t_stream_up(unsigned char hpack, int want_refused, const char *what) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);                        /* как up_open: POST открыт сразу */
    srv_drain();
    srv_headers(1, hpack, 0);
    int rc = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    if (want_refused)
        check(ro == 0 && rc == H2_ESTATUS && strstr(transport_strerror(rc), "400") != NULL, what);
    else
        check(ro == 0 && rc == 0, what);
    close(fd);
}

/* packet-up: запись больше scMaxEachPostBytes уходит несколькими кусками, а не одним POST, на который
 * сервер отвечает 413. Номер куска растёт на каждый. */
static void t_post_max(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    c.xh.post_max = 4;
    unsigned char d[10];
    memset(d, 'p', sizeof(d));
    int rc = transport_write(&c, d, sizeof(d));
    srv_drain();
    check(rc == 0 && c.xh.seq == 3, "packet-up: запись в 10 байт при пределе 4 — три куска (4+4+2)");
    c.xh.post_max = 0;
    rc = transport_write(&c, d, sizeof(d));
    srv_drain();
    check(rc == 0 && c.xh.seq == 4, "packet-up: без предела запись остаётся одним куском");
    close(fd);
}


/* Тела POST, которые клиент записал на связь выгрузки: сумма DATA по потокам, в порядке появления
 * потока. Читает всё, что лежит у «сервера», и разбирает кадры HTTP/2 (преамбула, SETTINGS, HEADERS,
 * DATA). */
static int srv_posts(unsigned *sizes, int cap) {
    static unsigned char b[1 << 18];
    size_t n = 0;
    ssize_t r;
    while (n < sizeof(b) && (r = recv(g_srv, b + n, sizeof(b) - n, MSG_DONTWAIT)) > 0) n += (size_t)r;
    size_t p = 0;
    if (n >= 24 && !memcmp(b, "PRI ", 4)) p = 24;
    uint32_t sids[256];
    int cnt = 0;
    while (p + 9 <= n) {
        uint32_t len = ((uint32_t)b[p] << 16) | ((uint32_t)b[p + 1] << 8) | b[p + 2];
        unsigned char type = b[p + 3];
        uint32_t sid = (((uint32_t)b[p + 5] << 24) | ((uint32_t)b[p + 6] << 16) |
                        ((uint32_t)b[p + 7] << 8) | b[p + 8]) & 0x7FFFFFFF;
        if (p + 9 + len > n) break;
        if (type == 1 && cnt < cap && cnt < 256) { sids[cnt] = sid; sizes[cnt++] = 0; }
        if (type == 0)
            for (int i = 0; i < cnt; i++) if (sids[i] == sid) sizes[i] += len;
        p += 9 + len;
    }
    return cnt;
}

/* packet-up: размер каждого POST — случайный в [post_min, post_max], как у клиента Xray, и не больше
 * post_max; куски записи в сумме дают её целиком; окно неотвеченных кусков соблюдается. */
static void t_post_range(void) {
    int fd;
    unsigned sz[256];
    unsigned char d[30000];
    memset(d, 'r', sizeof(d));

    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    c.xh.post_min = 1000;
    c.xh.post_max = 3000;
    int rc = transport_write(&c, d, sizeof(d));
    int cnt = srv_posts(sz, 256);
    unsigned sum = 0, big = 0, small_mid = 0, distinct = 0;
    for (int i = 0; i < cnt; i++) {
        sum += sz[i];
        if (sz[i] > 3000) big++;
        if (i < cnt - 1 && sz[i] < 1000) small_mid++;
        int seen = 0;
        for (int j = 0; j < i; j++) if (sz[j] == sz[i]) seen = 1;
        if (!seen) distinct++;
    }
    check(rc == 0 && sum == sizeof(d), "packet-up: куски диапазона в сумме дают запись целиком");
    check(cnt >= 10 && big == 0, "packet-up: ни один POST не больше post_max (3000)");
    check(small_mid == 0, "packet-up: все POST, кроме хвоста записи, не меньше post_min (1000)");
    check(distinct >= 5, "packet-up: размеры POST случайны в диапазоне (разных не меньше пяти)");
    close(fd);

    /* Запись в один POST, пока диапазон её вмещает: 20000..40000 и 30000 байт — либо один POST, либо
     * два, но никак не пятнадцать по 2 КБ (прежний потолок сборки). */
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_PACKET_UP, fd);
    c.xh.post_min = 20000;
    c.xh.post_max = 40000;
    rc = transport_write(&c, d, sizeof(d));
    cnt = srv_posts(sz, 256);
    check(rc == 0 && cnt >= 1 && cnt <= 2, "packet-up: запись в 30000 при 20000-40000 — один-два POST");
    close(fd);

    /* Окно по seq: когда один неотвеченный POST уже есть, запись, которой нужно больше свободных
     * мест, чем осталось (сверх PACKET_INFLIGHT), отказывается целиком — H2_EWINDOW и ни байта. */
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_PACKET_UP, fd);
    c.xh.post_min = 1000;
    c.xh.post_max = 1000;
    rc = transport_write(&c, d, 100);                 /* один POST остался без ответа */
    srv_posts(sz, 256);
    int rc2 = transport_write(&c, d, 20 * 1000);      /* 20 POST: больше свободных мест */
    cnt = srv_posts(sz, 256);
    check(rc == 0 && rc2 == H2_EWINDOW && cnt == 0,
          "packet-up: запись, которой не хватает мест в окне seq, отказана целиком");
    int rc3 = transport_write(&c, d, 10 * 1000);      /* 10 POST помещаются */
    cnt = srv_posts(sz, 256);
    check(rc3 == 0 && cnt == 10, "packet-up: запись, которой мест хватает, уходит");
    close(fd);

    /* Большие записи принимает только packet-up. */
    conn_init(&c, XH_PACKET_UP, -1);
    check(transport_big_write(&c) == 1, "packet-up принимает записи крупнее записи TLS одним вызовом");
    conn_init(&c, XH_STREAM_UP, -1);
    check(transport_big_write(&c) == 0, "stream-up: большая запись не обещана");
    conn_init(&c, XH_STREAM_ONE, -1);
    check(transport_big_write(&c) == 0, "stream-one: большая запись не обещана");
}

/* auto решается как у клиента Xray: stream-one при reality, иначе packet-up; названный режим не
 * трогается. Сервер packet-up отвечает на stream-one 400. */
static void t_auto_mode(void) {
    struct tr_node n;
    memset(&n, 0, sizeof(n));
    n.mode = "";
    n.security = "reality";
    check(xhttp_mode_of(&n) == XH_STREAM_ONE, "auto при reality — stream-one");
    n.security = "tls";
    check(xhttp_mode_of(&n) == XH_PACKET_UP, "auto при tls — packet-up");
    n.security = "none";
    check(xhttp_mode_of(&n) == XH_PACKET_UP, "auto без защиты — packet-up");
    n.mode = "auto";
    n.security = "tls";
    check(xhttp_mode_of(&n) == XH_PACKET_UP, "mode=auto при tls — packet-up");
    n.mode = "stream-one";
    check(xhttp_mode_of(&n) == XH_STREAM_ONE, "stream-one, названный явно, при tls остаётся");
    n.mode = "stream-up";
    n.security = "reality";
    check(xhttp_mode_of(&n) == XH_STREAM_UP, "stream-up, названный явно, остаётся");
}

/* WINDOW_UPDATE на 500000 для соединения и потока. */
static void srv_window_update(uint32_t sid) {
    unsigned char f[13] = { 0, 0, 4, 0x08, 0, (unsigned char)(sid >> 24), (unsigned char)(sid >> 16),
                            (unsigned char)(sid >> 8), (unsigned char)sid, 0, 0x07, 0xA1, 0x20 };
    if (write(g_srv, f, sizeof(f)) != (ssize_t)sizeof(f)) { perror("write"); exit(2); }
}

/* Связь выгрузки цикл туннеля не читает: низкое место должно сначала слить её, иначе WINDOW_UPDATE
 * сервера лежат непрочитанными, окно клиента остаётся закрытым, и выгрузка встаёт (stream-up падал с
 * 3 ГБ до 14 МБ за 20 с). */
static void t_room_drains_up_link(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);
    srv_drain();
    srv_window_update(0);
    srv_window_update(1);
    long room = transport_room(&c);
    check(ro == 0 && room > 500000, "stream-up: место читает WINDOW_UPDATE связи выгрузки, окно не стоит закрытым");
    close(fd);

    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_PACKET_UP, fd);
    static unsigned char big[60000];
    int rc = transport_write(&c, big, sizeof(big));         /* окно соединения почти выбрано */
    srv_drain();
    long before = packet_room(&c.xh.up);
    /* Окно потока у настоящего сервера — мегабайт (SETTINGS); без кадра SETTINGS стенд держит прежние
     * 65535, и они, а не места под куски, оказались бы потолком. */
    c.xh.up.h2.peer_init_win = 1 << 20;
    c.xh.post_max = 8192;                                   /* место = свободные места × наименьший POST */
    srv_window_update(0);
    room = transport_room(&c);
    check(rc == 0 && before < 10000 && room == (PACKET_INFLIGHT - 1) * 8192L,
          "packet-up: место читает WINDOW_UPDATE связи выгрузки (потолок — свободные места под куски)");
    close(fd);
}

/* Осталось ли в сокете «клиента» непрочитанное от «сервера». */
static int unread(int fd) {
    char b;
    return recv(fd, &b, 1, MSG_PEEK | MSG_DONTWAIT) > 0;
}

/* packet-up: сервер отвечает на куски в любом порядке. Здесь ТЕКУЩИЙ кусок (поток 3) отвечен первым,
 * а старый (поток 1) — следующим чтением. up_drain переставал читать, как только текущий поток
 * закончен, и ответ на старый оставался непрочитанным: кусок считался неотвеченным навсегда, окно по
 * seq заполнялось, и выгрузка вставала, когда слать уже было нечего. */
static void t_packet_up_order(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* кусок 0, поток 1 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* кусок 1, поток 3 */
    srv_drain();
    srv_headers(3, 0x88, 1);                                 /* сначала новый кусок */
    long r1 = transport_room(&c);
    srv_headers(1, 0x88, 1);                                 /* затем старый */
    long r2 = transport_room(&c);
    check(rc0 == 0 && rc1 == 0 && r1 >= 0 && r2 > 0 && h2_open_streams(&c.xh.up.h2) == 0 &&
          !unread(fd), "packet-up: ответ 200 на старый кусок после ответа на текущий прочитан");
    close(fd);
}

/* Окно по seq: не больше PACKET_INFLIGHT неотвеченных кусков, дальше запись ждёт (H2_EWINDOW), а
 * место, о котором узнаёт стек, нулевое; ответ на самый старый открывает его снова. */
static void t_packet_up_window_over_seq(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    int rc = 0;
    for (int i = 0; i < PACKET_INFLIGHT && !rc; i++) rc = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    int over = transport_write(&c, piece, sizeof(piece));
    long full = transport_room(&c);
    srv_headers(1, 0x88, 1);                                 /* ответ на самый старый кусок */
    int again = transport_write(&c, piece, sizeof(piece));
    check(rc == 0 && over == H2_EWINDOW && full == 0 && again == 0,
          "packet-up: окно по seq — за PACKET_INFLIGHT неотвеченными запись ждёт, ответ на старый открывает");
    close(fd);
}

/* Вторая связь под наблюдение цикла: ответ на кусок не будит цикл по событию основного сокета, а клиент,
 * которому отказано в окне, молчит до своего таймера — выгрузка packet-up шла «окно, пауза» (5-7 Мбит/с
 * при 150 у stream-up). Транспорт называет дескриптор связи выгрузки (aux_fd) и сам сливает её (aux_drain). */
static void t_aux(void) {
    int fd;
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    struct transport c;
    conn_init(&c, XH_PACKET_UP, fd);
    check(transport_aux_fd(&c) == -1, "packet-up: пока не отправлено ничего, второй связи для слежки нет");
    int rc0 = transport_write(&c, piece, sizeof(piece));     /* кусок 0, поток 1 */
    int rc1 = transport_write(&c, piece, sizeof(piece));     /* кусок 1, поток 3 */
    srv_drain();
    check(rc0 == 0 && rc1 == 0 && transport_aux_fd(&c) == fd,
          "packet-up: после первого куска связь выгрузки названа для слежки");
    long slots_before = packet_slots(&c.xh.up);
    srv_headers(1, 0x88, 1);                                 /* ответ на самый старый кусок */
    srv_headers(3, 0x88, 1);
    /* Ничего не пишем и не спрашиваем место: только слив по событию связи. */
    int dr = transport_aux_drain(&c);
    check(dr == 0 && h2_open_streams(&c.xh.up.h2) == 0 && packet_slots(&c.xh.up) > slots_before &&
          !unread(fd), "packet-up: слив по событию связи читает ответы и освобождает места под куски");
    close(fd);

    /* Отказ сервера, прочитанный слежкой, не теряется: его вернёт следующая отправка (I-219). */
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_PACKET_UP, fd);
    rc0 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    srv_headers(1, 0x8C, 1);                                 /* 400 на кусок */
    dr = transport_aux_drain(&c);
    int wr = transport_write(&c, piece, sizeof(piece));
    check(rc0 == 0 && dr == H2_ESTATUS && wr == H2_ESTATUS && transport_write(&c, piece, sizeof(piece)) == 0,
          "packet-up: 400, прочитанный слежкой, возвращён следующей отправкой, и один раз");
    close(fd);

    /* Закрытая сервером связь: слушать её дальше нельзя, иначе она будила бы цикл на каждом витке. */
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_PACKET_UP, fd);
    rc0 = transport_write(&c, piece, sizeof(piece));
    srv_drain();
    close(g_srv);
    g_srv = -1;
    check(rc0 == 0 && transport_aux_drain(&c) != 0, "packet-up: связь, закрытая сервером, больше не слушается");
    close(fd);

    /* stream-up наблюдается так же, stream-one второй связи не имеет. */
    if (new_pair(&fd) != 0) { check(0, "сокетная пара"); return; }
    conn_init(&c, XH_STREAM_UP, fd);
    int ro = up_request(&c, -1);
    srv_drain();
    check(ro == 0 && transport_aux_fd(&c) == fd, "stream-up: связь выгрузки названа для слежки");
    conn_init(&c, XH_STREAM_ONE, fd);
    check(transport_aux_fd(&c) == -1, "stream-one: второй связи нет");
    close(fd);
}

int main(void) {
    t_aux();
    t_packet_up_window_over_seq();
    t_packet_up_order();
    t_packet_up(0x8C, 1, "I-219: packet-up — 400 на прошлый кусок возвращён отправке");
    t_packet_up(0x88, 0, "I-219: packet-up — 200 на прошлый кусок отказом не считается");
    t_stream_up(0x8C, 1, "I-219: stream-up — 400 на выгрузку возвращён отправке");
    t_stream_up(0x88, 0, "I-219: stream-up — 200 на выгрузку отказом не считается");
    t_post_max();
    t_post_range();
    t_auto_mode();
    t_room_drains_up_link();
    printf(g_fail ? "\nxhupmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
