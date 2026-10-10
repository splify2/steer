/* Дайлеры steer-proxy без сети и криптографии: trojan (разбор UDP вниз) и http (CONNECT) через
 * таблицы dialer_ops, как их зовёт стек. Транспорт подменён заглушками ниже: запись копится в
 * буфер, чтение отдаёт заготовленный ответ сервера. Провод против настоящего сервера — run-proxy.sh. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include "proxy.h"
#include "pxdial.h"
#include "pxwire.h"
#include "scrypto.h"
#include "unit.h"

/* ---- заглушки ------------------------------------------------------------------------------ */

static unsigned char g_tx[8192];
static size_t g_tx_n;
static const unsigned char *g_rx;     /* ответ сервера: отдаётся кусками по g_rx_chunk */
static size_t g_rx_n, g_rx_off, g_rx_chunk = 4096;

time_t stack_now_s(void) { return time(NULL); }
const char *px_strerror(int rc) { (void)rc; return "?"; }
int px_stream_open(const struct px_node *n, struct transport *t, int timeout_s) {
    (void)n; (void)timeout_s; t->link.fd = 99; return 0;
}
int transport_write(struct transport *t, const unsigned char *d, size_t n) {
    (void)t;
    if (g_tx_n + n > sizeof g_tx) return TR_EIO;
    memcpy(g_tx + g_tx_n, d, n); g_tx_n += n;
    return 0;
}
int transport_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    (void)t;
    size_t k = g_rx_n - g_rx_off;
    if (!k) return TR_ECLOSED;
    if (k > g_rx_chunk) k = g_rx_chunk;
    if (k > cap) k = cap;
    memcpy(d, g_rx + g_rx_off, k); g_rx_off += k; *got = k;
    return 0;
}
int transport_read_zc(struct transport *t, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    *data = buf; *got = 0;
    return transport_read(t, buf, cap, got);
}
int transport_has_data(const struct transport *t) { (void)t; return 0; }
void transport_moved(struct transport *t) { (void)t; }
void transport_close(struct transport *t) { t->link.fd = -1; }
int sc_hash(enum sc_hash h, const void *d, size_t n, unsigned char *out) {
    (void)h; (void)d; (void)n; memset(out, 0xab, 28); return 0;
}
size_t px_socks_addr(unsigned char *out, uint32_t dst_net, uint16_t dport_host) {
    out[0] = 1; memcpy(out + 1, &dst_net, 4);
    out[5] = (unsigned char)(dport_host >> 8); out[6] = (unsigned char)dport_host;
    return 7;
}

/* vmess: слой scrypto и вывод ключей (pxwire.c) — заглушки; g_shake_fail — отказ SHAKE128. */
static int g_shake_fail;
size_t sc_aead_key_len(enum sc_aead_alg a) { return a == SC_AES128_GCM ? 16 : 32; }
int sc_aead_setkey(struct sc_aead *k, enum sc_aead_alg a, const unsigned char *key) {
    (void)key; k->alg = (int)a; return 0;
}
void sc_aead_free(struct sc_aead *k) { k->alg = 0; }
int sc_aead_seal(struct sc_aead *k, const unsigned char nonce[12], const void *aad, size_t aad_n,
                 unsigned char *buf, size_t n, unsigned char tag[16]) {
    (void)k; (void)nonce; (void)aad; (void)aad_n; (void)buf; (void)n; memset(tag, 0, 16); return 0;
}
int sc_aead_open(struct sc_aead *k, const unsigned char nonce[12], const void *aad, size_t aad_n,
                 unsigned char *buf, size_t n, const unsigned char tag[16]) {
    (void)k; (void)nonce; (void)aad; (void)aad_n; (void)buf; (void)n; (void)tag; return 0;
}
int sc_shake128_init(struct sc_shake *s, const void *in, size_t n) {
    (void)in; (void)n; s->ready = !g_shake_fail; return g_shake_fail ? SC_ECRYPTO : 0;
}
int sc_shake128_read(struct sc_shake *s, unsigned char *out, size_t n) {
    if (!s->ready) return SC_EINVAL;
    memset(out, 0, n); return 0;
}
void sc_shake128_free(struct sc_shake *s) { s->ready = 0; }
void px_vmess_cmdkey(const unsigned char uuid[16], unsigned char cmdkey[16]) { memcpy(cmdkey, uuid, 16); }
void px_vmess_kdf(const unsigned char key[16], const struct px_kdf_path *paths, size_t npaths,
                  unsigned char *out, size_t out_n) {
    (void)paths; (void)npaths; memset(out, key[0], out_n);
}
void px_vmess_authid(const unsigned char cmdkey[16], uint64_t ts, const unsigned char rand4[4],
                     unsigned char out[16]) {
    (void)ts; (void)rand4; memcpy(out, cmdkey, 16);
}
uint32_t px_fnv1a(const unsigned char *p, size_t n) { (void)p; (void)n; return 0; }
/* shadowsocks: вывод ключей и UDP — заглушки (AEAD-заглушка выше не шифрует: открытый текст на месте). */
void px_ss_evp_key(const char *pass, unsigned char *key, size_t key_n) { (void)pass; memset(key, 1, key_n); }
int px_ss_subkey(const unsigned char *key, size_t key_n, const unsigned char *salt, unsigned char *subkey) {
    (void)key; (void)salt; memset(subkey, 2, key_n); return 0;
}
void px_ss2022_subkey(const unsigned char *psk, size_t key_n, const unsigned char *salt, unsigned char *subkey) {
    (void)psk; (void)salt; memset(subkey, 3, key_n);
}
int px_ss2022_eih(const unsigned char *ipsk, size_t key_n, const unsigned char *upsk,
                  const unsigned char *salt, unsigned char out[16]) {
    (void)ipsk; (void)key_n; (void)upsk; (void)salt; memset(out, 4, 16); return 0;
}
int tr_dial_udp(const char *host, uint16_t port) { (void)host; (void)port; return -1; }

static unsigned char g_em[8192];
static size_t g_em_n, g_em_calls;
static int emit(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    if (g_em_n + n <= sizeof g_em) { memcpy(g_em + g_em_n, p, n); g_em_n += n; }
    g_em_calls++;
    return 0;
}

static void feed_reset(const unsigned char *rx, size_t n) {
    g_rx = rx; g_rx_n = n; g_rx_off = 0; g_tx_n = 0; g_em_n = 0; g_em_calls = 0;
}

/* ---- trojan: UDP вниз ---------------------------------------------------------------------- */

static void trojan_deliver_bytes(const unsigned char *pkt, size_t n, size_t step) {
    const struct dialer_ops *ops = &proxy_trojan_dialer;
    struct px_node node; memset(&node, 0, sizeof node);
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&node, sess, &k, 1);
    feed_reset(NULL, 0);
    for (size_t o = 0; o < n; o += step)
        ops->deliver(&node, sess, 1, pkt + o, n - o < step ? n - o : step, emit, NULL);
    free(sess);
}

static void test_trojan_udp(void) {
    /* Ответ с адресом-именем (ATYP 3): [3][len][имя][порт][длина(2)][CRLF][данные]. */
    static const unsigned char dom[] = {
        3, 11, 'e','x','a','m','p','l','e','.','c','o','m', 0x00, 0x35,
        0x00, 0x04, '\r', '\n', 'p','o','n','g',
        1, 1, 2, 3, 4, 0x00, 0x35, 0x00, 0x02, '\r', '\n', 'o','k',
    };
    trojan_deliver_bytes(dom, sizeof dom, sizeof dom);
    check("trojan udp: адрес-имя, затем IPv4 — две датаграммы", 2, (long)g_em_calls);
    check("trojan udp: нагрузка «pongok»", 1, g_em_n == 6 && !memcmp(g_em, "pongok", 6));
    /* Неизвестный ATYP — поток UDP уже не разобрать: соединению конец, а не тихий сдвиг. */
    {
        const struct dialer_ops *ops = &proxy_trojan_dialer;
        struct px_node node; memset(&node, 0, sizeof node);
        void *sess = calloc(1, ops->sess_size);
        ops->clear(sess);
        struct flow_key k; memset(&k, 0, sizeof k);
        ops->flow_open(&node, sess, &k, 1);
        static const unsigned char bad[] = { 9, 0, 0, 0, 0, 0, 0, 0x00, 0x02, '\r', '\n', 'x', 'y' };
        check("trojan udp: неизвестный ATYP — конец соединения", -1,
              ops->deliver(&node, sess, 1, bad, sizeof bad, emit, NULL));
        free(sess);
    }
    trojan_deliver_bytes(dom, sizeof dom, 1);
    check("trojan udp: адрес-имя по байту — две датаграммы", 2, (long)g_em_calls);
    check("trojan udp: по байту — нагрузка «pongok»", 1, g_em_n == 6 && !memcmp(g_em, "pongok", 6));
}

/* ---- http CONNECT ------------------------------------------------------------------------- */

static void http_node(struct px_node *n, const char *user, const char *pass) {
    memset(n, 0, sizeof *n);
    n->proto = PX_HTTP;
    snprintf(n->user, sizeof n->user, "%s", user);
    snprintf(n->pass, sizeof n->pass, "%s", pass);
}

static int http_connect_with(const struct px_node *n, const char *resp, size_t resp_n, void **sessp) {
    const struct dialer_ops *ops = &proxy_http_dialer;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    inet_pton(AF_INET, "1.2.3.4", &k.dst); k.dport = 443;
    ops->flow_open(n, sess, &k, 0);
    feed_reset((const unsigned char *)resp, resp_n);
    int rc = ops->connect(n, sess, 2);
    if (sessp) *sessp = sess; else free(sess);
    return rc;
}

static void test_http_long_auth(void) {
    /* Имя и пароль наибольшей длины, какую держит узел: запрос обязан уйти целиком. */
    char user[PX_USER_MAX], pass[PX_PASS_MAX];
    memset(user, 'u', sizeof user - 1); user[sizeof user - 1] = 0;
    memset(pass, 'p', sizeof pass - 1); pass[sizeof pass - 1] = 0;
    struct px_node n;
    http_node(&n, user, pass);
    static const char ok[] = "HTTP/1.1 200 Connection established\r\n\r\n";
    check("http: длинные имя и пароль — CONNECT прошёл", 0, http_connect_with(&n, ok, sizeof ok - 1, NULL));
    g_tx[g_tx_n < sizeof g_tx ? g_tx_n : sizeof g_tx - 1] = 0;
    check("http: запрос кончается пустой строкой", 1,
          g_tx_n >= 4 && !memcmp(g_tx + g_tx_n - 4, "\r\n\r\n", 4));
    /* base64 от «u…u:p…p»: 127 + 1 + 255 = 383 байта → 512 знаков. */
    const char *b = strstr((const char *)g_tx, "Proxy-Authorization: Basic ");
    size_t bl = b ? strcspn(b + 27, "\r") : 0;
    check("http: Basic целиком (512 знаков)", 512, (long)bl);
}

static void test_http_early_bytes(void) {
    /* Сервер цели говорит первым (SSH, SMTP): его байты приходят тем же чтением, что ответ 200.
     * Они — начало потока цели и обязаны дойти до клиента. */
    struct px_node n;
    http_node(&n, "", "");
    static const char resp[] = "HTTP/1.1 200 OK\r\n\r\nSSH-2.0-x\r\n";
    void *sess = NULL;
    check("http: ответ 200 с данными цели — CONNECT прошёл", 0, http_connect_with(&n, resp, sizeof resp - 1, &sess));
    const struct dialer_ops *ops = &proxy_http_dialer;
    static unsigned char buf[TUNNEL_BUF];
    const unsigned char *data = NULL;
    size_t got = 0;
    g_em_n = 0;
    int rr = ops->read(sess, buf, sizeof buf, &data, &got);
    if (rr == 0 && got) ops->deliver(&n, sess, 0, data, got, emit, NULL);
    check("http: байты цели после заголовков дошли", 1, g_em_n == 11 && !memcmp(g_em, "SSH-2.0-x\r\n", 11));
    free(sess);
}

/* ---- vmess ---------------------------------------------------------------------------------- */

static void test_vmess_key_fail(void) {
    /* Маска длины (SHAKE128) не завелась: отправлять с неинициализированной маской нельзя —
     * сервер получит мусорную длину. Отказ отправки — честный исход. */
    const struct dialer_ops *ops = &proxy_vmess_dialer;
    struct px_node n; memset(&n, 0, sizeof n);
    n.proto = PX_VMESS; n.vmess_sec = VMESS_AES128_GCM;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&n, sess, &k, 0);
    ops->connect(&n, sess, 2);
    feed_reset(NULL, 0);
    g_shake_fail = 1;
    int sr = ops->send(&n, sess, &k, 0, (const unsigned char *)"GET /", 5);
    g_shake_fail = 0;
    check("vmess: SHAKE128 не завёлся — SEND_FATAL", SEND_FATAL, sr);
    check("vmess: на провод ничего не ушло", 0, (long)g_tx_n);
    ops->close(sess);
    free(sess);
    /* Контроль: без отказа запрос уходит. */
    sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    ops->flow_open(&n, sess, &k, 0);
    ops->connect(&n, sess, 2);
    feed_reset(NULL, 0);
    check("vmess: обычный запрос — SEND_OK", SEND_OK, ops->send(&n, sess, &k, 0, (const unsigned char *)"GET /", 5));
    ops->close(sess);
    free(sess);
}

/* ---- shadowsocks 2022 ----------------------------------------------------------------------- */

static void test_ss2022_big_chunk(void) {
    /* SIP022: кусок нагрузки — до 0xFFFF байт (у AEAD до 2022 — 0x3FFF). Ответ сервера с куском в
     * 20480 байт обязан дойти, а не рвать поток. */
    const struct dialer_ops *ops = &proxy_ss_dialer;
    struct px_node n; memset(&n, 0, sizeof n);
    n.proto = PX_SS; n.ss_method = SS_2022_AES128; n.ss_key_n = 16;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&n, sess, &k, 0);
    ops->connect(&n, sess, 2);
    feed_reset(NULL, 0);
    check("ss 2022: запрос ушёл", SEND_OK, ops->send(&n, sess, &k, 0, (const unsigned char *)"GET /", 5));
    unsigned char reqsalt[16];
    memcpy(reqsalt, g_tx, 16);

    enum { BIG = 20480 };
    static unsigned char rx[16 + (11 + 16 + 16) + (100 + 16) + (2 + 16) + (BIG + 16)];
    size_t o = 0;
    memset(rx + o, 7, 16); o += 16;                                  /* соль ответа */
    rx[o++] = 1; memset(rx + o, 0, 8); o += 8;                        /* type, timestamp */
    memcpy(rx + o, reqsalt, 16); o += 16;                             /* соль запроса */
    rx[o++] = 0; rx[o++] = 100; memset(rx + o, 0, 16); o += 16;       /* длина первого куска + тег */
    memset(rx + o, 'a', 100); o += 100; memset(rx + o, 0, 16); o += 16;
    rx[o++] = BIG >> 8; rx[o++] = BIG & 0xff; memset(rx + o, 0, 16); o += 16;
    memset(rx + o, 'b', BIG); o += BIG; memset(rx + o, 0, 16); o += 16;
    g_em_n = 0; g_em_calls = 0;
    int dr = 0;
    for (size_t off = 0; off < o && !dr; off += 4096)
        dr = ops->deliver(&n, sess, 0, rx + off, o - off < 4096 ? o - off : 4096, emit, NULL);
    check("ss 2022: кусок 20480 байт — поток цел", 0, dr);
    check("ss 2022: оба куска отданы", 2, (long)g_em_calls);
    ops->close(sess);
    free(sess);
}


/* ---- нисходящий поток: свободное место кольца клиента ---------------------------------------- */

/* Модель стека. Перед каждым проходом (read + deliver) стек убеждается, что в кольце повтора есть
 * CLIENT_ROOM_RESERVE = TUNNEL_BUF + 1024 байт, и больше за проход эмитить нельзя: отказ emit —
 * это обрыв соединения (emit_to_client: «буфер повтора полон»). Дайлер, который за один проход
 * отдаёт больше, рвёт исправный поток. */
#define ROOM_RESERVE (TUNNEL_BUF + 1024)
static unsigned char g_big[1 << 21];
static size_t g_big_n, g_pass_n, g_pass_max;
static int g_overflow;
static int emit_room(void *arg, const unsigned char *p, size_t n) {
    (void)arg;
    if (g_pass_n + n > ROOM_RESERVE) { g_overflow++; return -1; }
    g_pass_n += n;
    if (g_pass_n > g_pass_max) g_pass_max = g_pass_n;
    if (g_big_n + n <= sizeof g_big) { memcpy(g_big + g_big_n, p, n); g_big_n += n; }
    return 0;
}

/* Гоняет ответ сервера так, как гоняет стек: read при непустом, deliver, снова — пока не
 * кончится вход и не опустеет has_data. Возвращает 0 либо код отказа дайлера. */
static int pump_down(const struct dialer_ops *ops, const struct px_node *n, void *sess,
                     const unsigned char *rx, size_t rxn) {
    static unsigned char buf[TUNNEL_BUF];
    feed_reset(rx, rxn);
    g_rx_chunk = TUNNEL_BUF;
    g_big_n = 0; g_pass_max = 0; g_overflow = 0;
    int rc = 0;
    for (int guard = 0; guard < 100000 && (g_rx_off < g_rx_n || ops->has_data(sess)); guard++) {
        const unsigned char *data = buf; size_t got = 0;
        g_pass_n = 0;
        if (ops->read(sess, buf, sizeof buf, &data, &got)) { rc = -2; break; }
        if (got && (rc = ops->deliver(n, sess, 0, data, got, emit_room, NULL)) != 0) break;
    }
    g_rx_chunk = 4096;
    return rc;
}

static size_t put_pat(unsigned char *o, size_t len, unsigned char seed) {
    for (size_t i = 0; i < len; i++) o[i] = (unsigned char)(seed + i * 7);
    return len;
}

/* Ответ shadowsocks из nch кусков по plen байт (AEAD заглушена: шифртекст = открытый текст).
 * Эталон нагрузки — в want. 2022: заголовок ответа с солью запроса, как в тесте выше. */
static size_t ss_stream(unsigned char *rx, unsigned char *want, size_t *want_n, int is2022,
                        const unsigned char reqsalt[16], int nch, size_t plen) {
    size_t o = 0; *want_n = 0;
    memset(rx + o, 7, 16); o += 16;
    if (is2022) {
        rx[o++] = 1; memset(rx + o, 0, 8); o += 8;
        memcpy(rx + o, reqsalt, 16); o += 16;
        rx[o++] = (unsigned char)(plen >> 8); rx[o++] = (unsigned char)plen;
        memset(rx + o, 0, 16); o += 16;
    }
    for (int i = 0; i < nch; i++) {
        if (!(is2022 && i == 0)) {
            rx[o++] = (unsigned char)(plen >> 8); rx[o++] = (unsigned char)plen;
            memset(rx + o, 0, 16); o += 16;
        }
        put_pat(rx + o, plen, (unsigned char)i);
        put_pat(want + *want_n, plen, (unsigned char)i);
        o += plen; *want_n += plen;
        memset(rx + o, 0, 16); o += 16;
    }
    return o;
}

static void ss_down_case(const char *name, int method, int is2022, int nch, size_t plen) {
    const struct dialer_ops *ops = &proxy_ss_dialer;
    struct px_node n; memset(&n, 0, sizeof n);
    n.proto = PX_SS; n.ss_method = method; n.ss_key_n = 16;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&n, sess, &k, 0);
    ops->connect(&n, sess, 2);
    feed_reset(NULL, 0);
    ops->send(&n, sess, &k, 0, (const unsigned char *)"GET /", 5);
    unsigned char reqsalt[16]; memcpy(reqsalt, g_tx, 16);
    unsigned char *rx = malloc(nch * (plen + 40) + 200), *want = malloc((size_t)nch * plen);
    size_t want_n, rxn = ss_stream(rx, want, &want_n, is2022, reqsalt, nch, plen);
    char t[160];
    int rc = pump_down(ops, &n, sess, rx, rxn);
    snprintf(t, sizeof t, "%s: поток цел при месте в кольце TUNNEL_BUF+1024 за проход", name);
    check(t, 0, rc);
    snprintf(t, sizeof t, "%s: отказов emit из-за места нет", name);
    check(t, 0, g_overflow);
    snprintf(t, sizeof t, "%s: вся нагрузка отдана", name);
    check(t, (long)want_n, (long)g_big_n);
    snprintf(t, sizeof t, "%s: нагрузка без искажений и в порядке", name);
    check(t, 1, g_big_n == want_n && !memcmp(g_big, want, want_n));
    ops->close(sess); free(sess); free(rx); free(want);
}

static void test_ss_down_room(void) {
    ss_down_case("ss aes-gcm, куски 8158 (Xray)", SS_AES128_GCM, 0, 40, 8158);
    ss_down_case("ss aes-gcm, куски 16383", SS_AES128_GCM, 0, 20, 0x3FFF);
    ss_down_case("ss 2022, куски 8158", SS_2022_AES128, 1, 40, 8158);
    ss_down_case("ss 2022, кусок 40000 больше кольца за проход", SS_2022_AES128, 1, 4, 40000);
    ss_down_case("ss 2022, кусок 65535 (предел SIP022)", SS_2022_AES128, 1, 3, 0xFFFF);
}

static void test_vmess_down_room(void) {
    const struct dialer_ops *ops = &proxy_vmess_dialer;
    struct px_node n; memset(&n, 0, sizeof n);
    n.proto = PX_VMESS; n.vmess_sec = VMESS_AES128_GCM;
    void *sess = calloc(1, ops->sess_size);
    ops->clear(sess);
    struct flow_key k; memset(&k, 0, sizeof k);
    ops->flow_open(&n, sess, &k, 0);
    ops->connect(&n, sess, 2);
    feed_reset(NULL, 0);
    ops->send(&n, sess, &k, 0, (const unsigned char *)"GET /", 5);
    unsigned char respv = g_tx[16 + 18 + 8 + 33];      /* H[33] заголовка запроса (заглушки не шифруют) */
    enum { NCH = 40, PL = 8158 };
    static unsigned char rx[(2 + 16) + (4 + 16) + NCH * (2 + PL + 16)], want[NCH * PL];
    size_t o = 0, wn = 0;
    rx[o++] = 0; rx[o++] = 4; memset(rx + o, 0, 16); o += 16;       /* длина заголовка ответа + тег */
    rx[o++] = respv; rx[o++] = 0; rx[o++] = 0; rx[o++] = 0; memset(rx + o, 0, 16); o += 16;
    for (int i = 0; i < NCH; i++) {
        size_t L = PL + 16;
        rx[o++] = (unsigned char)(L >> 8); rx[o++] = (unsigned char)L;
        put_pat(rx + o, PL, (unsigned char)i); put_pat(want + wn, PL, (unsigned char)i);
        o += PL; wn += PL; memset(rx + o, 0, 16); o += 16;
    }
    int rc = pump_down(ops, &n, sess, rx, o);
    check("vmess: поток цел при месте в кольце TUNNEL_BUF+1024 за проход", 0, rc);
    check("vmess: отказов emit из-за места нет", 0, g_overflow);
    check("vmess: нагрузка без искажений и в порядке", 1, g_big_n == wn && !memcmp(g_big, want, wn));
    ops->close(sess); free(sess);
}

int main(void) {
    test_ss2022_big_chunk();
    test_ss_down_room();
    test_vmess_down_room();
    test_vmess_key_fail();
    test_http_early_bytes();
    test_trojan_udp();
    test_http_long_auth();
    return unit_done("pxdialmatch");
}
