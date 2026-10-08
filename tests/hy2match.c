/* Стенд провода hysteria2 и узлов (src/proto/hysteria2/hy2wire.c, hy2sub.c): ни сети, ни QUIC.
 *
 * ВЕКТОРЫ — не из головы: их считала программа на Go из исходников apernet/hysteria
 * (core/internal/protocol: UDPMessage.Serialize, quicvarint; x/crypto/blake2b; quic-go/qpack — той
 * же библиотеки, которой сервер эталона пишет ответ авторизации, вместе с Huffman) и лежит она в
 * отчёте шага, а не в дереве: обновить их нечем, кроме как пересчитать заново тем же способом.
 * Сквозная сверка — с настоящим сервером — tests/run-hy2.sh.
 *
 * Что проверяется:
 *   - целые QUIC: границы 1/2/4/8 байт в обе стороны;
 *   - BLAKE2b-256: пустая строка, «abc» (вектор RFC 7693), строка, длиннее одного блока (300 байт
 *     — переход через блок с флагом «последний» на неполном блоке);
 *   - UDPMessage: заголовок байт в байт и разбор его же; отказы (короткое, фрагмент за счётом);
 *   - Salamander: пакет, собранный по формуле эталона с известной солью, разворачивается в исходные
 *     байты; наш tx с той же солью даёт тот же пакет; разворот на месте;
 *   - ответ авторизации: три ответа quic-go/qpack (233 с Huffman-строками, 233 с UDP false и числом,
 *     404 без Huffman), разрезанные на все возможные длины — «мало данных» вместо ошибки;
 *   - запрос авторизации: разбирается обратно нашим же разборщиком полей (проверка формы) и имеет
 *     ожидаемые байты статической части;
 *   - TCPRequest/TCPResponse: круг и разбор чужого ответа с набивкой;
 *   - ссылки и подписки: разбор всех ключей, отказы, Xray-конфиг. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "hy2.h"

static int g_fail;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "hy2match: %s:%d: не выполнено: %s\n", __FILE__, __LINE__, #c); g_fail++; } } while (0)

static size_t unhex(const char *h, uint8_t *out) {
    size_t n = 0;
    for (; h[0] && h[1]; h += 2) {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (uint8_t)v;
    }
    return n;
}

static void hex_eq(const uint8_t *got, size_t n, const char *want, int line) {
    uint8_t w[4096];
    size_t wn = unhex(want, w);
    if (wn != n || memcmp(w, got, n) != 0) {
        fprintf(stderr, "hy2match: строка %d: байты не совпали\n", line);
        g_fail++;
    }
}

static void test_varint(void) {
    static const struct { uint64_t v; const char *h; } T[] = {
        { 0, "00" }, { 63, "3f" }, { 64, "4040" }, { 16383, "7fff" }, { 16384, "80004000" },
        { 1073741823, "bfffffff" }, { 1073741824, "c000000040000000" },
        { 4611686018427387903ull, "ffffffffffffffff" },
    };
    for (size_t i = 0; i < sizeof T / sizeof T[0]; i++) {
        uint8_t b[8];
        size_t l = hy2_varint_put(b, sizeof b, T[i].v);
        hex_eq(b, l, T[i].h, __LINE__);
        uint64_t back = 0;
        CHECK(hy2_varint_get(b, l, &back) == l && back == T[i].v);
        CHECK(l > 1 ? hy2_varint_get(b, l - 1, &back) == 0 : 1);      /* обрезанное — «мало» */
    }
    uint8_t b[8];
    CHECK(hy2_varint_put(b, sizeof b, 1ull << 62) == 0);              /* не влезает в 62 бита */
    CHECK(hy2_varint_put(b, 1, 64) == 0);                             /* мал буфер */
}

static void test_blake2b(void) {
    uint8_t h[32];
    hy2_blake2b256(h, (const uint8_t *)"", 0);
    hex_eq(h, 32, "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8", __LINE__);
    hy2_blake2b256(h, (const uint8_t *)"abc", 3);
    hex_eq(h, 32, "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319", __LINE__);
    hy2_blake2b256(h, (const uint8_t *)"hysteria", 8);
    hex_eq(h, 32, "c80e221a4def76cb0af764aecf4574adce7098174c3301495ae8d4484ab10f7b", __LINE__);
    uint8_t big[300];
    for (int i = 0; i < 300; i++) big[i] = (uint8_t)('0' + i % 10);
    hy2_blake2b256(h, big, sizeof big);
    hex_eq(h, 32, "142340594b7962cbcfbdac060663c2252eee0d543e01f7236eac6717fe0897fb", __LINE__);
}

static void test_udp(void) {
    uint8_t b[64];
    size_t l = hy2_udp_header(b, sizeof b, 0x01020304, 0x0506, 1, 3, "1.2.3.4:53");
    memcpy(b + l, "hello", 5);
    hex_eq(b, l + 5, "01020304050601030a312e322e332e343a353368656c6c6f", __LINE__);
    struct hy2_udp_msg m;
    CHECK(hy2_udp_parse(b, l + 5, &m) == 0);
    CHECK(m.sid == 0x01020304 && m.pkt == 0x0506 && m.frag == 1 && m.nfrag == 3);
    CHECK(!strcmp(m.addr, "1.2.3.4:53") && m.n == 5 && !memcmp(m.data, "hello", 5));
    CHECK(hy2_udp_parse(b, 8, &m) != 0);                              /* короче заголовка */
    b[7] = 0;
    CHECK(hy2_udp_parse(b, l + 5, &m) != 0);                          /* нулевое число фрагментов */
    b[7] = 3; b[6] = 3;
    CHECK(hy2_udp_parse(b, l + 5, &m) != 0);                          /* номер за счётом */
    CHECK(hy2_udp_header(b, 9, 1, 1, 0, 1, "1.2.3.4:53") == 0);       /* не влезло */
}

static void test_salamander(void) {
    struct hy2_salamander s;
    hy2_salamander_init(&s, "salamander-pass");
    uint8_t wire[256], want[256];
    size_t wn = unhex("0102030405060708879b1db43a423ee7bc5d57f05628877b382d2f0574280b4bdfe6fb36396c1cabbb9658f82a4d2ea4b31252ae196fd8696d76621329655f1b9cf7a673682b0ae8ebca", wire);
    const char *plain = "The quick brown fox jumps over the lazy dog, 0123456789 0123456789";
    size_t pn = strlen(plain);
    CHECK(wn == pn + 8);
    /* Разворот на месте. */
    uint8_t buf[256];
    memcpy(buf, wire, wn);
    size_t r = hy2_salamander_rx(&s, buf, buf, wn);
    CHECK(r == pn && !memcmp(buf, plain, pn));
    /* Наш tx с той же солью даёт пакет эталона. */
    static const uint8_t salt[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
    size_t t = hy2_salamander_tx_salt(&s, salt, want, (const uint8_t *)plain, pn);
    CHECK(t == wn && !memcmp(want, wire, wn));
    /* Круг с настоящей солью. */
    t = hy2_salamander_tx(&s, want, (const uint8_t *)plain, pn);
    CHECK(t == pn + 8);
    CHECK(hy2_salamander_rx(&s, buf, want, t) == pn && !memcmp(buf, plain, pn));
    CHECK(hy2_salamander_rx(&s, buf, want, 8) == 0);                  /* короче соли + байт */
    /* Чужой пароль даёт мусор, а не отказ (как у эталона). */
    struct hy2_salamander o;
    hy2_salamander_init(&o, "other-pass");
    CHECK(hy2_salamander_rx(&o, buf, want, t) == pn && memcmp(buf, plain, pn) != 0);
}

/* Gecko: круг через наши tx и rx, кадр, собранный по описанию проводa эталона руками, отказы. */
struct gk_out { uint8_t d[8][2700]; size_t n[8]; int cnt; };
static void gk_collect(void *ctx, const uint8_t *d, size_t n) {
    struct gk_out *o = ctx;
    if (o->cnt < 8) { memcpy(o->d[o->cnt], d, n); o->n[o->cnt++] = n; }
}

static void test_gecko(void) {
    struct hy2_gecko g;
    CHECK(hy2_gecko_init(&g, "geckopass", 0, 0) == 0 && g.minp == 512 && g.maxp == 1200);
    struct hy2_gecko bad;
    CHECK(hy2_gecko_init(&bad, "x", 900, 800) == -1 && hy2_gecko_init(&bad, "x", 100, 3000) == -1);
    uint8_t pkt[1200], back[2200];
    for (size_t i = 0; i < sizeof pkt; i++) pkt[i] = (uint8_t)(i * 7 + 3);
    pkt[0] = 0xc3;                                       /* длинный заголовок: режется */
    for (int round = 0; round < 40; round++) {           /* число кусков и набивка случайны */
        struct gk_out o;
        memset(&o, 0, sizeof o);
        CHECK(hy2_gecko_tx(&g, pkt, sizeof pkt, gk_collect, &o) == 0);
        CHECK(o.cnt >= 2 && o.cnt <= 8);
        for (int i = 0; i < o.cnt; i++) CHECK(o.n[i] >= 512 && o.n[i] <= 1200);   /* в [min, max] */
        /* Куски приходят в обратном порядке; собранный пакет выходит ровно на последнем. */
        size_t got = 0;
        for (int i = o.cnt - 1; i >= 0; i--) {
            size_t r = hy2_gecko_rx(&g, back, o.d[i], o.n[i]);
            if (i > 0) CHECK(r == 0); else got = r;
        }
        CHECK(got == sizeof pkt && !memcmp(back, pkt, sizeof pkt));
    }
    /* Короткий заголовок идёт как есть (только Salamander). */
    uint8_t sh[100];
    memset(sh, 0x41, sizeof sh);
    struct gk_out o;
    memset(&o, 0, sizeof o);
    CHECK(hy2_gecko_tx(&g, sh, sizeof sh, gk_collect, &o) == 0 && o.cnt == 1 && o.n[0] == 108);
    CHECK(hy2_gecko_rx(&g, back, o.d[0], o.n[0]) == sizeof sh && !memcmp(back, sh, sizeof sh));
    /* Кадр по описанию эталона: 0x80, msgID, номер<<4|число, длина набивки, набивка, кусок. Два
     * куска "AAAA" и "BBBB", у первого набивка из трёх байт. */
    struct hy2_salamander sm;
    hy2_salamander_init(&sm, "geckopass");
    static const uint8_t salt[8] = { 9, 9, 9, 9, 9, 9, 9, 9 };
    uint8_t f0[] = { 0x80, 0x11, 0x02, 0x00, 0x03, 0xee, 0xee, 0xee, 'A', 'A', 'A', 'A' };
    uint8_t f1[] = { 0x80, 0x11, 0x12, 0x00, 0x00, 'B', 'B', 'B', 'B' };
    uint8_t w0[64], w1[64];
    size_t n0 = hy2_salamander_tx_salt(&sm, salt, w0, f0, sizeof f0);
    size_t n1 = hy2_salamander_tx_salt(&sm, salt, w1, f1, sizeof f1);
    CHECK(hy2_gecko_rx(&g, back, w1, n1) == 0);
    CHECK(hy2_gecko_rx(&g, back, w0, n0) == 8 && !memcmp(back, "AAAABBBB", 8));
    /* Повтор куска, несогласованное число кусков, номер за счётом — молча отбрасываются. */
    CHECK(hy2_gecko_rx(&g, back, w0, n0) == 0);
    uint8_t bad1[] = { 0x80, 0x22, 0x50, 0x00, 0x00, 'x' };        /* номер 5 при счёте 0 */
    size_t nb = hy2_salamander_tx_salt(&sm, salt, w0, bad1, sizeof bad1);
    CHECK(hy2_gecko_rx(&g, back, w0, nb) == 0);
    uint8_t bad2[] = { 0x80, 0x23, 0x01, 0x00, 0x00, 'x' };        /* один кусок — не бывает */
    nb = hy2_salamander_tx_salt(&sm, salt, w0, bad2, sizeof bad2);
    CHECK(hy2_gecko_rx(&g, back, w0, nb) == 0);
    hy2_gecko_free(&g);
}

static void test_auth_response(void) {
    static const char *R233 = "01406800005f0983132cff2f029fd2125b0c35ad92bf834d96972f039fd2125b0c358845acf3831da93f2f059fd2125b0c35ab1c921aa9bfb21c6490b2cd39ba75a29a8f5f6b109b7bf8f3ebdc376f5fc187163c997367d1a756bd9b776fe1c797e73fd0044cb4db8ebcff";
    static const char *R404 = "01040000dbf5";
    static const char *R233B = "012b00005f0983132cff2f029fd2125b0c35ad92bf84947420bf2f039fd2125b0c358845acf386089b0000007f";
    uint8_t b[512];
    struct hy2_auth_resp r;
    size_t n = unhex(R233, b);
    CHECK(hy2_auth_response(b, n, &r, NULL) == 1);
    CHECK(r.status == HY2_AUTH_OK && r.udp == 1 && r.rx_auto == 1 && r.rx == 0);
    for (size_t k = 0; k < n; k++) CHECK(hy2_auth_response(b, k, &r, NULL) == 0);   /* любой обрез — «мало» */
    n = unhex(R233B, b);
    CHECK(hy2_auth_response(b, n, &r, NULL) == 1);
    CHECK(r.status == 233 && r.udp == 0 && r.rx_auto == 0 && r.rx == 12500000);
    n = unhex(R404, b);
    CHECK(hy2_auth_response(b, n, &r, NULL) == 1);
    CHECK(r.status == 404);
    /* Набивка ответа настоящего сервера — сотни знаков (эталон: 256..2048), в Huffman: длиннее
     * места под значение, но ответ обязан разобраться, а нужные поля — прочитаться. Первый прогон
     * против сервера эталона упал именно здесь. */
    static const char *R233PAD = "01417b00005f0983132cff2f029fd2125b0c35ad92bf834d96972f039fd2125b0c358845acf386089b0000007f2f059fd2125b0c35ab1c921aa9bfffc1011dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f836781dd67cf3f6f83678";
    uint8_t bp[1024];
    n = unhex(R233PAD, bp);
    CHECK(n == 3 + 379);
    CHECK(hy2_auth_response(bp, n, &r, NULL) == 1);
    CHECK(r.status == 233 && r.udp == 1 && r.rx == 12500000 && !r.rx_auto);
    /* Незнакомый кадр перед HEADERS пропускается (GREASE: тип 0x21, длина 2). */
    uint8_t g[600];
    size_t gl = 0;
    g[gl++] = 0x21; g[gl++] = 2; g[gl++] = 0xaa; g[gl++] = 0xbb;
    n = unhex(R404, b);
    memcpy(g + gl, b, n);
    CHECK(hy2_auth_response(g, gl + n, &r, NULL) == 1 && r.status == 404);
    /* DATA раньше заголовков — негодный ответ. */
    uint8_t d[] = { 0x00, 0x01, 0x41 };
    const char *why = NULL;
    CHECK(hy2_auth_response(d, sizeof d, &r, &why) == -1 && why);
    /* Ссылка на динамическую таблицу (Required Insert Count != 0) — отказ. */
    uint8_t dyn[] = { 0x01, 0x03, 0x01, 0x00, 0x80 };
    CHECK(hy2_auth_response(dyn, sizeof dyn, &r, NULL) == -1);
}

/* Разбор запроса нашими же руками: проверяется форма (что кадр самосогласован и статическая часть
 * — байты из RFC 9204), не смысл — смысл проверяет настоящий сервер. */
static void test_auth_request(void) {
    uint8_t b[2048];
    size_t l = hy2_auth_request(b, sizeof b, "s3cret", 12500000, 40);
    CHECK(l > 0);
    uint64_t type, len;
    size_t a = hy2_varint_get(b, l, &type);
    size_t c = hy2_varint_get(b + a, l - a, &len);
    CHECK(type == 1 && a + c + len == l);
    const uint8_t *s = b + a + c;
    CHECK(s[0] == 0 && s[1] == 0);                                    /* Required Insert Count, Base */
    CHECK(s[2] == 0xd4 && s[3] == 0xd7);                              /* :method POST, :scheme https */
    CHECK(s[4] == 0x50 && s[5] == 8 && !memcmp(s + 6, "hysteria", 8));/* :authority */
    CHECK(s[14] == 0x51 && s[15] == 5 && !memcmp(s + 16, "/auth", 5));/* :path */
    CHECK(memmem(s, len, "hysteria-auth", 13) != NULL && memmem(s, len, "s3cret", 6) != NULL);
    CHECK(memmem(s, len, "12500000", 8) != NULL);
    CHECK(hy2_auth_request(b, 30, "s3cret", 1, 40) == 0);             /* не влезло */
    uint8_t ctl[16];
    size_t cl = hy2_h3_control(ctl, sizeof ctl);
    hex_eq(ctl, cl, "000400", __LINE__);       /* тип 0 · SETTINGS · длина 0: ни одной настройки */
}

static void test_tcp(void) {
    uint8_t b[1024];
    size_t l = hy2_tcp_request(b, sizeof b, "example.com", 443, 10);
    uint64_t v;
    size_t k = hy2_varint_get(b, l, &v);
    CHECK(v == 0x401 && k == 2);
    uint64_t al;
    size_t k2 = hy2_varint_get(b + k, l - k, &al);
    CHECK(al == 15 && !memcmp(b + k + k2, "example.com:443", 15));
    uint64_t pl;
    size_t k3 = hy2_varint_get(b + k + k2 + al, l - k - k2 - al, &pl);
    CHECK(pl == 10 && k + k2 + al + k3 + pl == l);
    l = hy2_tcp_request(b, sizeof b, "2001:db8::1", 80, 0);
    CHECK(memmem(b, l, "[2001:db8::1]:80", 16) != NULL);            /* IPv6 в скобках */

    /* Ответ сервера: статус 0, сообщение «ok», набивка 5 байт, следом данные потока. */
    uint8_t r[64] = { 0x00, 0x02, 'o', 'k', 0x05, 'x', 'x', 'x', 'x', 'x', 'D', 'A', 'T', 'A' };
    struct hy2_tcp_resp tr;
    CHECK(hy2_tcp_response(r, sizeof r, &tr) == 10 && tr.ok && !strcmp(tr.msg, "ok"));
    for (size_t i = 0; i < 10; i++) CHECK(hy2_tcp_response(r, i, &tr) == 0);   /* мало */
    uint8_t bad[] = { 0x01, 0x0b, 'c','o','n','n','r','e','f','u','s','e','d', 0x00 };
    CHECK(hy2_tcp_response(bad, sizeof bad, &tr) == (int)sizeof bad && !tr.ok && !strcmp(tr.msg, "connrefused"));
    uint8_t bad2[] = { 0x01, 0x03, 'n', 'o', 'p', 0x00 };
    CHECK(hy2_tcp_response(bad2, sizeof bad2, &tr) == 6 && !tr.ok && !strcmp(tr.msg, "nop"));
    uint8_t huge[] = { 0x00, 0x7f, 0xff };                            /* длина сообщения 16383 > предела */
    CHECK(hy2_tcp_response(huge, sizeof huge, &tr) == -1);
}

static void test_urls(void) {
    struct hy2_node n;
    int rc = hy2_parse_url("hysteria2://s3cr%40t@example.com:8443/?sni=front.example&insecure=1&obfs=salamander"
                           "&obfs-password=hunter22&up=100&down=200%20mbps&mport=20000-30000&hop-interval=15"
                           "#%D0%9C%D0%BE%D1%81%D0%BA%D0%B2%D0%B0", &n);
    CHECK(rc == 0);
    CHECK(!strcmp(n.host, "example.com") && n.port == 8443 && !strcmp(n.auth, "s3cr@t"));
    CHECK(!strcmp(n.sni, "front.example") && n.insecure && n.obfs && !strcmp(n.obfs_pass, "hunter22"));
    CHECK(n.up_bps == 12500000 && n.down_bps == 25000000);
    CHECK(n.hop_n == 1 && n.hop[0] == 20000 && n.hop[1] == 30000 && n.hop_s == 15);
    CHECK(!strcmp(n.name, "Москва"));

    rc = hy2_parse_url("hy2://user:pass@[2001:db8::1]:443,5000-6000/?pinSHA256=AA:bb:CC:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:"
                       "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99", &n);
    CHECK(rc == 0 && !strcmp(n.host, "2001:db8::1") && n.port == 443 && !strcmp(n.auth, "user:pass"));
    CHECK(n.hop_n == 2 && n.hop[2] == 5000 && n.hop[3] == 6000);
    CHECK(n.has_pin && n.pin[0] == 0xaa && n.pin[1] == 0xbb && n.pin[31] == 0x99);
    CHECK(!n.sni[0]);                                                  /* у адреса SNI нет */
    CHECK(!strcmp(n.name, "2001:db8::1:443"));

    rc = hy2_parse_url("hysteria2://pw@host.example/", &n);            /* порт по умолчанию */
    CHECK(rc == 0 && n.port == 443 && !strcmp(n.sni, "host.example") && !n.up_bps && !n.hop_n);
    CHECK(hy2_parse_url("hysteria2://pw@h:1/?obfs=xyz", &n) == 1);     /* чужой obfs — пропуск с причиной */
    CHECK(n.skip_reason[0]);
    CHECK(hy2_parse_url("hysteria2://pw@h:1/?obfs=salamander&obfs-password=abc", &n) == 1);  /* короткий пароль */
    CHECK(hy2_parse_url("hysteria2://pw@h:1/?pinSHA256=zz", &n) == 1);
    CHECK(hy2_parse_url("hysteria2://pw@h:0/", &n) == 1);
    CHECK(hy2_parse_url("vless://x@h:1", &n) == -1);
    CHECK(hy2_parse_url("hysteria2://pw@h:1/?obfs=gecko&obfs-password=abcd", &n) == 0 && n.obfs == 2 &&
          !strcmp(n.obfs_pass, "abcd") && !n.gecko_min);
    CHECK(hy2_parse_bandwidth("100") == 12500000 && hy2_parse_bandwidth("1 gbps") == 125000000);
    CHECK(hy2_parse_bandwidth("8mbps") == 1000000 && hy2_parse_bandwidth("abc") == 0);
}

static void test_sub(void) {
    struct hy2_node nodes[8];
    struct hy2_sub_stats st;
    const char *txt =
        "vless://11111111-1111-1111-1111-111111111111@a.example:443?security=tls#v\n"
        "hysteria2://p1@a.example:443/?sni=a.example#one\n"
        "hysteria2://p2@b.example:443/?obfs=xyz#bad\n"
        "hy2://p3@c.example:8443#three\n";
    size_t n = hy2_parse_sub(txt, nodes, 8, &st);
    CHECK(n == 2 && st.skipped == 1 && st.foreign == 1 && st.reasons_n == 1);
    CHECK(!strcmp(nodes[0].name, "one") && !strcmp(nodes[1].host, "c.example"));

    /* Конфиг Xray-core: outbound hysteria, finalmask salamander + udphop + quicParams. */
    const char *js =
        "{\"remarks\":\"x\",\"outbounds\":[{\"protocol\":\"freedom\",\"tag\":\"direct\"},"
        "{\"protocol\":\"hysteria\",\"tag\":\"hy\",\"settings\":{\"version\":2,\"address\":\"h.example\",\"port\":443},"
        "\"streamSettings\":{\"network\":\"hysteria\",\"security\":\"tls\","
        "\"tlsSettings\":{\"serverName\":\"front.example\","
        "\"pinnedPeerCertSha256\":\"00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff\"},"
        "\"hysteriaSettings\":{\"version\":2,\"auth\":\"pa\\\"ss\"},"
        "\"finalmask\":{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"obfspass\"}},"
        "{\"type\":\"udphop\",\"settings\":{\"remotePorts\":\"20000-20100\",\"interval\":\"10-20\"}}],"
        "\"quicParams\":{\"congestion\":\"brutal\",\"brutalUp\":\"50 mbps\",\"brutalDown\":\"100 mbps\"}}}},"
        "{\"protocol\":\"hysteria\",\"settings\":{\"version\":1,\"address\":\"old\",\"port\":1}}]}";
    n = hy2_parse_sub(js, nodes, 8, &st);
    CHECK(n == 1 && st.skipped == 1);
    CHECK(!strcmp(nodes[0].name, "hy") && !strcmp(nodes[0].host, "h.example") && nodes[0].port == 443);
    CHECK(!strcmp(nodes[0].auth, "pa\"ss") && !strcmp(nodes[0].sni, "front.example") && nodes[0].has_pin);
    CHECK(nodes[0].obfs && !strcmp(nodes[0].obfs_pass, "obfspass"));
    CHECK(nodes[0].hop_n == 1 && nodes[0].hop[0] == 20000 && nodes[0].hop[1] == 20100 && nodes[0].hop_s == 10);
    CHECK(nodes[0].up_bps == 6250000 && nodes[0].down_bps == 12500000);

    /* Имя в записи \u с суррогатной парой (панели на Python/PHP): ⚡ 📱 Германия — один знак вне BMP, не два CESU. */
    const char *jsn =
        "{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"\\u26a1 \\ud83d\\udcf1 \\u0413\\u0435\\u0440\","
        "\"settings\":{\"version\":2,\"address\":\"h.example\",\"port\":443},"
        "\"streamSettings\":{\"hysteriaSettings\":{\"version\":2,\"auth\":\"a\"}}}]}";
    n = hy2_parse_sub(jsn, nodes, 8, &st);
    CHECK(n == 1 && !strcmp(nodes[0].name, "\xE2\x9A\xA1 \xF0\x9F\x93\xB1 \xD0\x93\xD0\xB5\xD1\x80"));

    /* salamander с packetSize в Xray-core — Gecko. */
    const char *js2 =
        "[{\"outbounds\":[{\"protocol\":\"hysteria\",\"tag\":\"g\",\"settings\":{\"version\":2,\"address\":\"g.example\",\"port\":443},"
        "\"streamSettings\":{\"hysteriaSettings\":{\"version\":2,\"auth\":\"a\"},"
        "\"finalmask\":{\"udp\":[{\"type\":\"salamander\",\"settings\":{\"password\":\"gpass1\",\"packetSize\":\"600-1100\"}}]}}}]}]";
    n = hy2_parse_sub(js2, nodes, 8, &st);
    CHECK(n == 1 && nodes[0].obfs == 2 && nodes[0].gecko_min == 600 && nodes[0].gecko_max == 1100);

    /* Тело подписки в base64 разворачивается. */
    char dec[1024];
    const char *b64 = "aHlzdGVyaWEyOi8vcHdAaC5leGFtcGxlOjQ0My8/c25pPWguZXhhbXBsZSNuYW1l";
    const char *t = hy2_sub_text(b64, strlen(b64), dec, sizeof dec);
    CHECK(t == dec && strstr(dec, "hysteria2://pw@h.example:443/") != NULL);
    n = hy2_parse_sub(t, nodes, 8, &st);
    CHECK(n == 1 && !strcmp(nodes[0].name, "name"));
    CHECK(hy2_sub_text(txt, strlen(txt), dec, sizeof dec) == txt);
}

/* Пределы: подписка на 500 узлов из файла, ссылка длиннее стекового буфера, диапазонов портов
 * больше предела с числом в причине. */
static void test_limits(void) {
    char path[64];
    snprintf(path, sizeof(path), "/tmp/hy2match-500.%d", (int)getpid());
    FILE *f = fopen(path, "w");
    for (int i = 0; f && i < 500; i++) fprintf(f, "hysteria2://p@h%d.example:443/#node%d\n", i, i);
    if (f) fclose(f);
    struct hy2_sub_stats st;
    size_t n = 0;
    struct hy2_node *nodes = hy2_load_sub(path, &n, &st);
    unlink(path);
    CHECK(nodes && n == 500 && st.skipped == 0);
    if (nodes && n == 500) CHECK(!strcmp(nodes[499].name, "node499") && !strcmp(nodes[0].host, "h0.example"));
    free(nodes);
    CHECK(hy2_load_sub("/tmp/hy2match-нет-такого-файла", &n, &st) == NULL && n == 0);

    static char big[6000];
    int k = snprintf(big, sizeof big, "hysteria2://p@long.example:443/?sni=long.example&pad=");
    memset(big + k, 'x', 3000);
    snprintf(big + k + 3000, sizeof big - (size_t)k - 3000, "#long\n");
    struct hy2_node one[2];
    CHECK(hy2_parse_sub(big, one, 2, &st) == 1 && !strcmp(one[0].name, "long"));

    struct hy2_node nd;
    CHECK(hy2_parse_url("hysteria2://p@h:1000,2000-3000,4000,5000,6000,7000,8000,9000/", &nd) == 0 && nd.hop_n == 8);
    CHECK(hy2_parse_url("hysteria2://p@h:1000,2000,3000,4000,5000,6000,7000,8000,9000/", &nd) == 1);
    CHECK(strstr(nd.skip_reason, "диапазонов больше 8") != NULL);
}

int main(void) {
    test_limits();
    test_varint();
    test_blake2b();
    test_udp();
    test_salamander();
    test_gecko();
    test_auth_response();
    test_auth_request();
    test_tcp();
    test_urls();
    test_sub();
    if (g_fail) { fprintf(stderr, "hy2match: провалено %d\n", g_fail); return 1; }
    printf("hy2match: ok\n");
    return 0;
}
