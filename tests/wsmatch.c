/* Транспорты ws и httpupgrade (шаг 5 выпуска 1.10): путь, запрос Upgrade, ответ 101, кадры.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Обе ошибки, которые здесь возможны, снаружи выглядят одинаково — «узел
 * не работает». Не тот путь или не тот запрос — сервер Xray отвечает 404 или молча рвёт
 * соединение; не тот кадр — gorilla на той стороне закрывает поток, и видно это только по пропаже
 * трафика. Поэтому проверяется не «похоже ли на WebSocket», а совпадение до байта с эталоном:
 *
 *   - путь (trpath.c) и запрос Upgrade (trupgrade.c) — против того, что печатает сам Go: значения
 *     ниже сняты программой на net/url и net/http Go 1.22, повторяющей код Xray (infra/conf Build,
 *     websocket/dialer.go с gorilla client.go, httpupgrade/dialer.go) с нашей версией Chrome. Порядок
 *     заголовков и `%3F` у httpupgrade сверх того сверены перехватом настоящего Xray 26.3.27
 *     (в docker);
 *   - Sec-WebSocket-Accept — против примера RFC 6455 (1.3);
 *   - кадр клиента — против примера RFC 6455 (5.7, «Hello» с маской 37 fa 21 3d);
 *   - разбор кадров сервера — фрагменты, служебный кадр посреди сообщения, длины 125/126/65536,
 *     подача по байту, разбор на месте и все нарушения RFC, на которых gorilla рвёт соединение;
 *   - ответ 101 и отказы: не 101 (код в тексте причины), нет Upgrade, неверный Accept, таймаут,
 *     сервер закрылся; остаток за ответом тем же куском — и у ws (первый кадр), и у httpupgrade
 *     (начало потока) — не теряется и виден как готовность без сокета (transport_has_data);
 *   - ping → pong с тем же телом и маской, close → ответный close и конец потока.
 *
 * КАК. Все ярусы транспорта настоящие и компонуются отдельными объектами (без #include .c: храповик
 * tests/buildmatch.sh). Связь — security=none на настоящем сокете 127.0.0.1: сервер-стенд в потоке
 * слушает порт, transport_open дозванивается до него обычным tr_dial. TLS и Reality здесь не
 * нужны и подменены заглушками; поверх tls и reality с настоящей библиотекой ws и httpupgrade
 * проверяет vlessmatch в ext-test. Сетей, прав и docker не нужно — стенд в `make test`. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <pthread.h>
#include <dirent.h>
#include <poll.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "transport.h"
#include "trpath.h"
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

static int g_fail, g_pass;
static void check(int ok, const char *what) {
    if (ok) { g_pass++; return; }
    printf("%-74s ПРОВАЛ\n", what);
    g_fail = 1;
}
static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && !strcmp(want, got);
    if (!ok) printf("  ждали «%s»\n  вышло «%s»\n", want, got ? got : "(NULL)");
    check(ok, what);
}

static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    int n = 0;
    if (!d) return -1;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}

/* ---- 1. путь ------------------------------------------------------------------------ */

static void test_path(void) {
    /* Путь узла, строка запроса у ws, у httpupgrade. NULL — отказ (у Go — ошибка url.Parse). */
    static const struct { const char *path, *ws, *hu; } V[] = {
        { "", "/", "/" },
        { "/", "/", "/" },
        { "ws", "/ws", "/ws" },
        { "/p/q?x=1&ed=2048", "/p/q?x=1", "/p/q%3Fx=1" },
        { "/p?ed=2048", "/p", "/p" },
        { "/p?ed=", "/p?ed=", "/p%3Fed=" },
        { "/p?ed=abc&b=2&a=1&a=0", "/p?a=1&a=0&b=2", "/p%3Fa=1&a=0&b=2" },
        { "/a b?ed=1", "/a%20b", "/a%2520b" },
        { "/a%41?ed=1", "/a%41", "/a%2541" },
        { "/a%41", "/a%41", "/a%2541" },
        { "/a b", "/a%20b", "/a%20b" },
        { "/p?", "/p?", "/p%3F" },
        { "/p?x=a+b&ed=1", "/p?x=a+b", "/p%3Fx=a+b" },
        { "/p?x=%zz&ed=1&y=/", "/p?y=%2F", "/p%3Fy=%252F" },
        { "/\xd0\xb6?ed=9", "/%D0%B6", "/%25D0%25B6" },
        { "/a%zz", NULL, "/a%25zz" },
        { "/a%zz?ed=1", NULL, "/a%25zz%3Fed=1" },
        { "/p?q=1;2&ed=1&r", "/p?r=", "/p%3Fr=" },
        { "/(x)*!", "/(x)*!", "/%28x%29%2A%21" },
        { "/p?ed=1&ed=2&e=3", "/p?e=3", "/p%3Fe=3" },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(*V); i++) {
        char out[1024], what[160];
        for (int ws = 1; ws >= 0; ws--) {
            const char *want = ws ? V[i].ws : V[i].hu;
            int rc = tr_upgrade_target(V[i].path, ws, out, sizeof(out), NULL);
            snprintf(what, sizeof(what), "путь «%s» у %s — как у Xray", V[i].path, ws ? "ws" : "httpupgrade");
            if (!want) check(rc != 0, what);
            else if (rc != 0) check(0, what);
            else check_str(what, want, out);
        }
    }
    /* Отказы, которых у Go нет в таблице: пути, которые Xray разобрал бы неоднозначно. */
    static const char *bad[] = { "/a\nb", "/a#b", "//h/p", "a:b/c" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char out[64];
        const char *why = NULL;
        check(tr_upgrade_target(bad[i], 1, out, sizeof(out), &why) != 0 && why && why[0],
              "необычный путь — отказ с причиной");
        check(strlen(why) < 64, "причина влезает в skip_reason");
    }
    char tiny[4];
    check(tr_upgrade_target("/long/path", 1, tiny, sizeof(tiny), NULL) != 0, "не влезло в out — отказ");

    /* Ed — как Build у Xray: uint32(strconv.Atoi(первое значение ed)), если ed вырезан. */
    static const struct { const char *path; uint32_t ed; } E[] = {
        { "/w?ed=2048", 2048 }, { "/w?x=1&ed=16", 16 }, { "/w?ed=", 0 }, { "/w?ed=abc", 0 },
        { "/w?ed=+5", 0 } /* «+» в запросе — пробел */, { "/w?ed=%2B5", 5 }, { "/w?ed=-1", 4294967295u }, { "/w?ed=4294967296", 0 }, { "/w", 0 },
        { "/a%zz?ed=9", 0 },
    };
    for (size_t i = 0; i < sizeof(E) / sizeof(*E); i++) {
        char out[256], what[96];
        uint32_t ed = 7;
        tr_upgrade_target_ed(E[i].path, 0, out, sizeof(out), NULL, &ed);
        snprintf(what, sizeof(what), "Ed пути «%s» — %u, как у Xray", E[i].path, E[i].ed);
        check(ed == E[i].ed, what);
    }
}

/* ---- 2. запрос Upgrade ------------------------------------------------------------- */

#define UA "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
#define CH "\"Google Chrome\";v=\"149\", \"Chromium\";v=\"149\", \"Not)A;Brand\";v=\"24\""

static void node0(struct tr_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    n->host = "127.0.0.1"; n->port = 1; n->type = type; n->security = "none";
    n->sni = ""; n->fp = ""; n->pbk = ""; n->sid = ""; n->path = "/w"; n->service = ""; n->mode = "";
}

static void test_request(void) {
    struct tr_node n;
    char out[4096];
    const char *key = "dGhlIHNhbXBsZSBub25jZQ==";

    node0(&n, "ws");
    n.path = "/w?ed=2048";
    n.http_host = "cdn.example.com";
    n.headers = "x-custom: v1\naccept: text/x\n";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check_str("ws: запрос как у Xray (свои заголовки — канонически, Accept узла главнее)",
        "GET /w HTTP/1.1\r\n"
        "Host: cdn.example.com\r\n"
        "User-Agent: " UA "\r\n"
        "Accept: text/x\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: Upgrade\r\n"
        "DNT: 1\r\n"
        "Pragma: no-cache\r\n"
        "Sec-CH-UA: " CH "\r\n"
        "Sec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Sec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n"
        "X-Custom: v1\r\n"
        "\r\n", out);

    node0(&n, "httpupgrade");
    n.path = "/w?ed=2048";
    n.http_host = "cdn.example.com";
    n.headers = "x-custom: v1\nPragma: p\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check_str("httpupgrade: запрос как у Xray (свой ключ — как написан, Pragma узла главнее)",
        "GET /w HTTP/1.1\r\n"
        "Host: cdn.example.com\r\n"
        "User-Agent: " UA "\r\n"
        "Accept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Connection: Upgrade\r\n"
        "DNT: 1\r\n"
        "Pragma: p\r\n"
        "Sec-CH-UA: " CH "\r\n"
        "Sec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\n"
        "Sec-Fetch-Dest: empty\r\n"
        "Sec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\n"
        "Upgrade: websocket\r\n"
        "x-custom: v1\r\n"
        "\r\n", out);

    node0(&n, "ws");
    n.http_host = "h";
    n.headers = "User-Agent: MyUA/1\n";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check_str("ws: свой User-Agent — облика браузера нет",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: MyUA/1\r\nConnection: Upgrade\r\n"
        "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n\r\n", out);

    node0(&n, "httpupgrade");
    n.http_host = "h";
    n.headers = "user-agent: MyUA/1\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check(strstr(out, "\r\nUser-Agent: " UA "\r\n") && strstr(out, "\r\nuser-agent: MyUA/1\r\n"),
          "httpupgrade: user-agent строчными — не узнан (как у Go), облик остаётся");

    /* Host: host, иначе sni, иначе адрес узла. */
    node0(&n, "ws");
    n.sni = "mask.example";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: mask.example\r\n") != NULL, "Host без host — sni");
    node0(&n, "ws");
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: 127.0.0.1\r\n") != NULL, "Host без host и sni — адрес узла");
    node0(&n, "ws");
    n.host = "2001:db8::1";
    tr_h1_request(&n, 1, key, NULL,out, sizeof(out));
    check(strstr(out, "\r\nHost: [2001:db8::1]\r\n") != NULL, "Host по адресу IPv6 — в скобках");

    char small[64];
    node0(&n, "ws");
    check(tr_h1_request(&n, 1, key, NULL, small, sizeof(small)) == 0, "запрос не влез — 0, а не обрезок");

    /* Ранние данные и облики по слову в User-Agent — против той же программы на Go (net/http,
     * browser.go и dialer.go Xray с нашими зашитыми версиями). */
    node0(&n, "ws");
    n.http_host = "h";
    tr_h1_request(&n, 1, key, "aGVsbG8sIGVhcmx5IGRhdGEA_w", out, sizeof(out));
    check_str("ws: ранние данные в Sec-WebSocket-Protocol — между Key и Version, как у Xray",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "\r\nAccept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
        "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: " CH "\r\nSec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
        "Sec-WebSocket-Protocol: aGVsbG8sIGVhcmx5IGRhdGEA_w\r\nSec-WebSocket-Version: 13\r\n"
        "Upgrade: websocket\r\n\r\n", out);
    static const struct { const char *word, *want; } B[] = {
        { "firefox",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:153.0) "
          "Gecko/20100101 Firefox/153.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\n"
          "Cache-Control: no-cache\r\nConnection: Upgrade\r\nDNT: 1\r\nPragma: no-cache\r\n"
          "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "safari",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
          "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.6 Safari/605.1.15\r\nAccept: */*\r\n"
          "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
          "Pragma: no-cache\r\nSec-Fetch-Dest: websocket\r\nSec-Fetch-Mode: websocket\r\n"
          "Sec-Fetch-Site: same-origin\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
          "Sec-WebSocket-Version: 13\r\nUpgrade: websocket\r\n\r\n" },
        { "edge",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "Edg/149.0.0.0\r\nAccept: */*\r\n"
          "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
          "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: \"Microsoft Edge\";v=\"149\", \"Chromium\";v=\"149\", "
          "\"Not)A;Brand\";v=\"24\"\r\nSec-CH-UA-Mobile: ?0\r\nSec-CH-UA-Platform: \"Windows\"\r\n"
          "Sec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\nSec-Fetch-Site: same-origin\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "curl",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: curl/8.20.0\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
        { "golang",
          "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: Go-http-client/1.1\r\nConnection: Upgrade\r\n"
          "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n"
          "Upgrade: websocket\r\n\r\n" },
    };
    for (size_t i = 0; i < sizeof(B) / sizeof(*B); i++) {
        char hv[64], what[96];
        snprintf(hv, sizeof(hv), "User-Agent: %s\n", B[i].word);
        node0(&n, "ws");
        n.http_host = "h";
        n.headers = hv;
        tr_h1_request(&n, 1, key, NULL, out, sizeof(out));
        snprintf(what, sizeof(what), "ws: User-Agent «%s» — облик Xray", B[i].word);
        check_str(what, B[i].want, out);
    }
    node0(&n, "httpupgrade");
    n.http_host = "h";
    n.headers = "connection: keep-alive\nUpgrade: h2c\n";
    tr_h1_request(&n, 0, NULL, NULL, out, sizeof(out));
    check_str("httpupgrade: свои Connection и Upgrade — как у Xray (Set перекрывает только точный ключ)",
        "GET /w HTTP/1.1\r\nHost: h\r\nUser-Agent: " UA "\r\nAccept: */*\r\n"
        "Accept-Language: en-US,en;q=0.9\r\nCache-Control: no-cache\r\nConnection: Upgrade\r\n"
        "DNT: 1\r\nPragma: no-cache\r\nSec-CH-UA: " CH "\r\nSec-CH-UA-Mobile: ?0\r\n"
        "Sec-CH-UA-Platform: \"Windows\"\r\nSec-Fetch-Dest: empty\r\nSec-Fetch-Mode: websocket\r\n"
        "Sec-Fetch-Site: same-origin\r\nUpgrade: websocket\r\nconnection: keep-alive\r\n\r\n", out);
}

/* ---- 3. Accept и кадр клиента ------------------------------------------------------ */

static void test_frames_out(void) {
    char acc[29];
    tr_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", acc);
    check_str("Sec-WebSocket-Accept — пример RFC 6455, 1.3", "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", acc);

    unsigned char f[80000];
    const unsigned char key[4] = { 0x37, 0xfa, 0x21, 0x3d };
    size_t n = tr_ws_frame(f, sizeof(f), 1, 1, key, (const unsigned char *)"Hello", 5);
    static const unsigned char rfc[] = { 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    check(n == sizeof(rfc) && !memcmp(f, rfc, n), "кадр «Hello» с маской — пример RFC 6455, 5.7");

    static unsigned char d[70000];
    for (size_t i = 0; i < sizeof(d); i++) d[i] = (unsigned char)(i * 7);
    static const struct { size_t len, hdr; unsigned char b1; } L[] = {
        { 0, 2, 0x80 }, { 125, 2, 0x80 | 125 }, { 126, 4, 0x80 | 126 }, { 65535, 4, 0x80 | 126 },
        { 65536, 10, 0x80 | 127 },
    };
    for (size_t i = 0; i < sizeof(L) / sizeof(*L); i++) {
        n = tr_ws_frame(f, sizeof(f), 2, 0, key, d, L[i].len);
        int ok = n == L[i].hdr + 4 + L[i].len && f[0] == 0x02 && f[1] == L[i].b1 &&
                 !memcmp(f + L[i].hdr, key, 4);
        for (size_t k = 0; ok && k < L[i].len; k++)
            if ((f[L[i].hdr + 4 + k] ^ key[k & 3]) != d[k]) ok = 0;
        char what[160];
        snprintf(what, sizeof(what), "кадр %zu байт: заголовок %zu, маска у каждого байта", L[i].len, L[i].hdr);
        check(ok, what);
    }
    check(tr_ws_frame(f, 10, 2, 1, key, d, 125) == 0, "кадр не влез — 0");
}

/* ---- 4. разбор кадров сервера ------------------------------------------------------ */

static size_t srv_frame(unsigned char *out, int op, int fin, const void *d, size_t n) {
    size_t h = 0;
    out[h++] = (unsigned char)((fin ? 0x80 : 0) | op);
    if (n > 65535) {
        out[h++] = 127;
        for (int i = 0; i < 8; i++) out[h++] = (unsigned char)((uint64_t)n >> (56 - 8 * i));
    } else if (n > 125) {
        out[h++] = 126; out[h++] = (unsigned char)(n >> 8); out[h++] = (unsigned char)n;
    } else {
        out[h++] = (unsigned char)n;
    }
    memcpy(out + h, d, n);
    return h + n;
}

static int parse_all(const unsigned char *in, size_t n, unsigned char *out, size_t cap, size_t *on,
                     struct ws_rx *r) {
    memset(r, 0, sizeof(*r));
    return tr_ws_parse(r, in, n, out, cap, on);
}

static void test_frames_in(void) {
    static unsigned char in[200000], out[200000];
    struct ws_rx r;
    size_t n = 0, on = 0;

    n = srv_frame(in, 2, 1, "Hello", 5);
    check(parse_all(in, n, out, sizeof(out), &on, &r) == 0 && on == 5 && !memcmp(out, "Hello", 5),
          "binary «Hello» одним кадром");

    /* Фрагменты и ping посреди сообщения (RFC 6455, 5.4 и 5.5). */
    n = srv_frame(in, 1, 0, "Hel", 3);
    n += srv_frame(in + n, 9, 1, "pp", 2);
    n += srv_frame(in + n, 0, 1, "lo", 2);
    check(parse_all(in, n, out, sizeof(out), &on, &r) == 0 && on == 5 && !memcmp(out, "Hello", 5),
          "фрагменты с ping посредине — «Hello» целиком");
    check(r.pong_due && r.pong_n == 2 && !memcmp(r.pong, "pp", 2), "ping — ответ pong с тем же телом");

    /* Подача по байту — тот же итог: границы записи и кадра не совпадают. */
    memset(&r, 0, sizeof(r));
    size_t tot = 0;
    int rc = 0;
    for (size_t i = 0; i < n && !rc; i++) {
        size_t o1 = 0;
        rc = tr_ws_parse(&r, in + i, 1, out + tot, sizeof(out) - tot, &o1);
        tot += o1;
    }
    check(!rc && tot == 5 && !memcmp(out, "Hello", 5), "подача по одному байту");

    /* Длины 125, 126 и 65536+ и разбор на месте (out == in). */
    static const size_t lens[] = { 125, 126, 65535, 65536, 70000 };
    static unsigned char d[70000];
    for (size_t i = 0; i < sizeof(d); i++) d[i] = (unsigned char)(i * 13 + 1);
    for (size_t k = 0; k < sizeof(lens) / sizeof(*lens); k++) {
        n = srv_frame(in, 2, 1, d, lens[k]);
        n += srv_frame(in + n, 2, 1, "z", 1);
        rc = parse_all(in, n, in, sizeof(in), &on, &r);
        char what[96];
        snprintf(what, sizeof(what), "кадр %zu байт и следом ещё один — разбор на месте", lens[k]);
        check(!rc && on == lens[k] + 1 && !memcmp(in, d, lens[k]) && in[lens[k]] == 'z', what);
    }

    /* close: данные до него отдаются, дальше — конец. */
    n = srv_frame(in, 2, 1, "ab", 2);
    n += srv_frame(in + n, 8, 1, "\x03\xe8", 2);
    n += srv_frame(in + n, 2, 1, "zz", 2);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && on == 2 && r.closed && r.close_code == 1000, "close 1000: данные до него — отданы, после — нет");
    n = srv_frame(in, 8, 1, "", 0);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && r.closed && r.close_code == 1005, "close без кода — 1005");
    n = srv_frame(in, 2, 1, "", 0);
    rc = parse_all(in, n, out, sizeof(out), &on, &r);
    check(!rc && on == 0 && !r.in_payload, "пустой кадр данных — законно");

    /* Нарушения RFC — отказ, как у gorilla. */
    struct { const char *what; unsigned char b[16]; size_t n; } bad[] = {
        { "маска у кадра сервера", { 0x82, 0x81, 1, 2, 3, 4, 'x' }, 7 },
        { "RSV1 без расширений", { 0xC2, 0x01, 'x' }, 3 },
        { "служебный кадр длиннее 125", { 0x89, 126, 0, 126 }, 4 },
        { "служебный кадр без FIN", { 0x09, 0x01, 'x' }, 3 },
        { "continuation вне сообщения", { 0x80, 0x01, 'x' }, 3 },
        { "новое сообщение внутри разрезанного", { 0x02, 0x01, 'x', 0x82, 0x01, 'y' }, 6 },
        { "опкод 3", { 0x83, 0x01, 'x' }, 3 },
        { "опкод 11", { 0x8B, 0x00 }, 2 },
        { "старший бит 64-битной длины", { 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }, 10 },
        { "close из одного байта", { 0x88, 0x01, 0x03 }, 3 },
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        char what[96];
        snprintf(what, sizeof(what), "отказ: %s", bad[i].what);
        check(parse_all(bad[i].b, bad[i].n, out, sizeof(out), &on, &r) == TR_EWSFRAME, what);
    }
    n = srv_frame(in, 2, 1, "abcdef", 6);
    check(parse_all(in, n, out, 3, &on, &r) == H2_ETOOBIG, "не влезло в out — отказ, а не обрезка");
}

/* ---- 5. ответ 101 ----------------------------------------------------------------- */

static void test_resp(void) {
    char acc[29];
    tr_ws_accept("dGhlIHNhbXBsZSBub25jZQ==", acc);
    char ok[256];
    snprintf(ok, sizeof(ok), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
             "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\nTAIL", acc);
    struct h1_resp r;
    size_t used;

    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 1, acc, (const unsigned char *)ok, strlen(ok), &used);
    check(r.done && tr_h1_resp_verdict(&r, 1) == 0 && used == strlen(ok) - 4,
          "101 с верным Accept — принят, остаток за заголовками не съеден");

    memset(&r, 0, sizeof(r));
    size_t tot = 0;
    for (size_t i = 0; i < strlen(ok) && !r.done; i++) {
        tr_h1_resp_feed(&r, 1, acc, (const unsigned char *)ok + i, 1, &used);
        tot += used;
    }
    check(r.done && tr_h1_resp_verdict(&r, 1) == 0 && tot == strlen(ok) - 4, "ответ по байту — тот же итог");

    static const struct { const char *what, *resp; int ws, want; } V[] = {
        { "404", "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 1, TR_EUPSTATUS },
        { "200", "HTTP/1.1 200 OK\r\n\r\n", 0, TR_EUPSTATUS },
        { "101 без Upgrade", "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n\r\n", 0, TR_ENOUPGRADE },
        { "101 без Connection", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n", 0, TR_ENOUPGRADE },
        { "101 с неверным Accept", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n", 1, TR_EWSACCEPT },
        { "101 без Accept", "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
          "Connection: Upgrade\r\n\r\n", 1, TR_EWSACCEPT },
        { "httpupgrade: 101 без Accept — законно", "HTTP/1.1 101 Switching Protocols\r\nupgrade: WebSocket\r\n"
          "connection: upgrade\r\n\r\n", 0, 0 },
        { "ws: Connection списком — слово найдено (gorilla)", "HTTP/1.1 101 x\r\nUpgrade: websocket\r\n"
          "Connection: keep-alive, Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n", 1, 0 },
        { "httpupgrade: Connection списком — отказ (Xray сравнивает целиком)",
          "HTTP/1.1 101 x\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n\r\n", 0, TR_ENOUPGRADE },
        { "не HTTP", "SSH-2.0-OpenSSH\r\n\r\n", 1, TR_EUPTOOBIG },
        { "строки через голый \\n", "HTTP/1.1 101 x\nUpgrade: websocket\nConnection: Upgrade\n\n", 0, 0 },
    };
    for (size_t i = 0; i < sizeof(V) / sizeof(*V); i++) {
        memset(&r, 0, sizeof(r));
        tr_h1_resp_feed(&r, V[i].ws, acc, (const unsigned char *)V[i].resp, strlen(V[i].resp), &used);
        check(tr_h1_resp_verdict(&r, V[i].ws) == V[i].want, V[i].what);
    }
    /* Длинная строка посредника — не отказ, бесконечный ответ — отказ. */
    static char big[20000];
    int k = snprintf(big, sizeof(big), "HTTP/1.1 101 x\r\nSet-Cookie: ");
    memset(big + k, 'c', 1000);
    snprintf(big + k + 1000, sizeof(big) - (size_t)k - 1000, "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n");
    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 0, NULL, (const unsigned char *)big, strlen(big), &used);
    check(tr_h1_resp_verdict(&r, 0) == 0, "строка в 1000 байт посредине — не помеха");
    memset(big, 'x', sizeof(big));
    memcpy(big, "HTTP/1.1 101 x\r\nX: ", 19);
    memset(&r, 0, sizeof(r));
    tr_h1_resp_feed(&r, 0, NULL, (const unsigned char *)big, sizeof(big), &used);
    check(r.bad && tr_h1_resp_verdict(&r, 0) == TR_EUPTOOBIG, "заголовки длиннее 16 КБ — отказ");
}

/* ---- 6. на сокете: сервер-стенд ----------------------------------------------------- */

enum plan { P_WS_OK, P_HU_OK, P_404, P_NOUP, P_BADACC, P_SILENT, P_HANGUP,
            /* ранние данные (Ed > 0) — srv_ed */
            P_WS_ED, P_WS_EDBIG, P_HU_ED };

struct srv {
    int lfd, port;
    enum plan plan;
    char req[4096];                /* что прислал клиент */
    int rc;
    /* для P_WS_OK: что пришло кадрами от клиента */
    unsigned char got[9000 + 8192];
    size_t got_n;
    int frames, masked_all, pong_ok, close_ok, ops_ok;
    /* ранние данные: что было в Sec-WebSocket-Protocol, пришли ли данные до ответа (httpupgrade),
     * пришёл ли close 1000 при закрытии клиентом */
    char proto[128];
    int early_before_101, close1000;
};

static int rd_until(int fd, char *buf, size_t cap, const char *end) {
    size_t n = 0;
    while (n + 1 < cap) {
        ssize_t k = read(fd, buf + n, 1);
        if (k <= 0) return -1;
        n++;
        buf[n] = '\0';
        if (strstr(buf, end)) return (int)n;
    }
    return -1;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t g = 0;
    while (g < n) {
        ssize_t k = read(fd, b + g, n - g);
        if (k <= 0) return -1;
        g += (size_t)k;
    }
    return 0;
}

/* Кадр клиента: обязательно с маской. Тело — снятое с маски. */
static int rd_cframe(int fd, int *op, int *fin, int *masked, unsigned char *body, size_t cap, size_t *bn) {
    unsigned char h[2];
    if (rd_all(fd, h, 2)) return -1;
    *op = h[0] & 15; *fin = h[0] >> 7; *masked = h[1] >> 7;
    uint64_t len = h[1] & 0x7f;
    if (len == 126) { unsigned char e[2]; if (rd_all(fd, e, 2)) return -1; len = (e[0] << 8) | e[1]; }
    else if (len == 127) { unsigned char e[8]; if (rd_all(fd, e, 8)) return -1; len = 0; for (int i = 0; i < 8; i++) len = (len << 8) | e[i]; }
    unsigned char key[4] = { 0 };
    if (*masked && rd_all(fd, key, 4)) return -1;
    if (len > cap) return -1;
    if (rd_all(fd, body, (size_t)len)) return -1;
    for (size_t i = 0; i < len; i++) body[i] ^= key[i & 3];
    *bn = (size_t)len;
    return 0;
}

/* Ранние данные. P_WS_ED: клиент первой записью шлёт «hello» (не длиннее Ed) — она обязана
 * приехать в Sec-WebSocket-Protocol запроса, а вторая запись (9000 байт, сделанная ДО ответа) —
 * кадрами строго после ответа 101. P_WS_EDBIG: первая запись 9000 байт длиннее Ed — запрос без
 * ранних данных, запись — кадрами после 101. P_HU_ED: запрос приходит сразу при открытии, данные
 * клиента — следом, не дожидаясь ответа. Во всех трёх в конце клиент закрывается сам — у ws обязан
 * прийти close 1000. */
static void *srv_ed(struct srv *s, int fd) {
    const char *p = strstr(s->req, "\r\nSec-WebSocket-Protocol: ");
    if (p) sscanf(p + 26, "%127[^\r]", s->proto);
    unsigned char resp[512];
    int n;
    if (s->plan == P_HU_ED) {
        /* security=none: ответ клиент ждёт и при Ed > 0 (trupgrade.c: сервер Xray теряет данные,
         * приехавшие одним сегментом с запросом). До ответа — тишина, после — «echo». */
        struct pollfd pf0 = { .fd = fd, .events = POLLIN, .revents = 0 };
        s->early_before_101 = poll(&pf0, 1, 200) > 0;
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nRAW-START");
        if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
        char b[8];
        s->got_n = rd_all(fd, (unsigned char *)b, 4) == 0 && !memcmp(b, "echo", 4);
        s->rc = 0;
        close(fd);
        return NULL;
    }
    /* До ответа от клиента не должно прийти НИЧЕГО сверх запроса (gorilla рвёт такое). */
    struct pollfd pf = { .fd = fd, .events = POLLIN, .revents = 0 };
    s->early_before_101 = poll(&pf, 1, 200) > 0;
    char acc[29] = "";
    const char *k = strstr(s->req, "\r\nSec-WebSocket-Key: ");
    if (k) { char key[32]; sscanf(k + 21, "%31[^\r]", key); tr_ws_accept(key, acc); }
    n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                 "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
    n += (int)srv_frame(resp + n, 2, 1, "FIRST", 5);
    if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
    int op, fin, masked;
    size_t bn;
    unsigned char body[8192];
    s->masked_all = 1;
    while (s->got_n < 9000) {
        if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn)) { close(fd); return NULL; }
        if (!masked) s->masked_all = 0;
        memcpy(s->got + s->got_n, body, bn);
        s->got_n += bn;
        s->frames++;
    }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->close1000 = op == 8 && masked && bn == 2 && body[0] == 0x03 && body[1] == 0xe8;
    s->rc = 0;
    close(fd);
    return NULL;
}

static void *srv_main(void *arg) {
    struct srv *s = arg;
    int fd = accept(s->lfd, NULL, NULL);
    s->rc = -1;
    if (fd < 0) return NULL;
    /* Закрыться, не ответив, — ПОСЛЕ того как запрос прочитан: закрытие сокета с непрочитанным
     * запросом ядро отдаёт сбросом (RST), и клиент видел то конец потока, то обрыв — по тому,
     * успел ли запрос прийти до close (на нагруженной машине стенд падал через раз). */
    if (rd_until(fd, s->req, sizeof(s->req), "\r\n\r\n") < 0) { close(fd); return NULL; }
    if (s->plan == P_HANGUP) { close(fd); s->rc = 0; return NULL; }
    if (s->plan == P_SILENT) { sleep(2); close(fd); s->rc = 0; return NULL; }
    if (s->plan >= P_WS_ED) return srv_ed(s, fd);

    char acc[29] = "";
    const char *k = strstr(s->req, "\r\nSec-WebSocket-Key: ");
    if (k) {
        char key[32];
        sscanf(k + 21, "%31[^\r]", key);
        tr_ws_accept(key, acc);
    }
    unsigned char resp[1024];
    int n = 0;
    switch (s->plan) {
    case P_404:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
        break;
    case P_NOUP:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\n"
                     "Sec-WebSocket-Accept: %s\r\n\r\n", acc);
        break;
    case P_BADACC:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: AAAAAAAAAAAAAAAAAAAAAAAAAAA=\r\n\r\n");
        break;
    case P_HU_OK:
        /* Ответ и начало потока ОДНОЙ записью в сокет: остаток обязан дойти. */
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nRAW-START");
        break;
    default:
        n = snprintf((char *)resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        /* И первый кадр тем же куском. */
        n += (int)srv_frame(resp + n, 2, 1, "FIRST", 5);
    }
    if (write(fd, resp, (size_t)n) != n) { close(fd); return NULL; }
    if (s->plan != P_WS_OK && s->plan != P_HU_OK) { usleep(200000); close(fd); s->rc = 0; return NULL; }

    if (s->plan == P_HU_OK) {
        /* Поток как есть: эхо того, что пришло. */
        char b[64];
        ssize_t r = read(fd, b, sizeof(b));
        if (r > 0 && write(fd, b, (size_t)r) != r) r = -1;
        s->got_n = r > 0 ? (size_t)r : 0;
        memcpy(s->got, b, s->got_n);
        s->rc = 0;
        close(fd);
        return NULL;
    }

    /* ws: 9000 байт одной записью клиента — три кадра по правилу Xray (4096, 4096, 808). */
    s->masked_all = 1;
    s->ops_ok = 1;
    int op, fin, masked;
    size_t bn;
    unsigned char body[8192];
    while (s->got_n < 9000) {
        if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn)) { close(fd); return NULL; }
        int want_op = s->frames == 0 ? 2 : 0;
        int want_fin = s->got_n + bn == 9000;
        size_t want_n = 9000 - s->got_n > 4096 ? 4096 : 9000 - s->got_n;
        if (op != want_op || fin != want_fin || bn != want_n) s->ops_ok = 0;
        if (!masked) s->masked_all = 0;
        memcpy(s->got + s->got_n, body, bn);
        s->got_n += bn;
        s->frames++;
    }
    /* ping → ждём pong с тем же телом. */
    unsigned char f[64];
    size_t fl = srv_frame(f, 9, 1, "hb", 2);
    if (write(fd, f, fl) != (ssize_t)fl) { close(fd); return NULL; }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->pong_ok = op == 10 && fin && masked && bn == 2 && !memcmp(body, "hb", 2);
    /* close 1001 → ждём ответный close с тем же кодом. */
    fl = srv_frame(f, 8, 1, "\x03\xe9", 2);
    if (write(fd, f, fl) != (ssize_t)fl) { close(fd); return NULL; }
    if (rd_cframe(fd, &op, &fin, &masked, body, sizeof(body), &bn) == 0)
        s->close_ok = op == 8 && masked && bn == 2 && body[0] == 0x03 && body[1] == 0xe9;
    s->rc = 0;
    close(fd);
    return NULL;
}

static int srv_start(struct srv *s, enum plan p, pthread_t *th) {
    memset(s, 0, sizeof(*s));
    s->plan = p;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof(a);
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof(a)) || listen(s->lfd, 1) ||
        getsockname(s->lfd, (struct sockaddr *)&a, &al))
        return -1;
    s->port = ntohs(a.sin_port);
    return pthread_create(th, NULL, srv_main, s);
}

static void srv_stop(struct srv *s, pthread_t th) {
    pthread_join(th, NULL);
    close(s->lfd);
}

/* Ждать, как цикл туннеля: своё непрочитанное транспорта или готовность сокета. Чтение голого сокета
 * не ждёт (tr_sock_read), но этот стенд ждёт готовности сам — чтобы не крутиться впустую. */
static int ready(struct transport *t) {
    if (transport_has_data(t)) return 1;
    struct pollfd p = { .fd = transport_fd(t), .events = POLLIN, .revents = 0 };
    return poll(&p, 1, 3000) > 0;
}

/* Прочитать через транспорт, пока что-то не придёт или не выйдет срок. */
static int tread(struct transport *t, unsigned char *b, size_t cap, size_t *got) {
    for (int i = 0; i < 20; i++) {
        *got = 0;
        if (!ready(t)) return 0;
        int rc = transport_read(t, b, cap, got);
        if (rc || *got) return rc;
    }
    return 0;
}

/* Чтение голого сокета не ждёт: цикл туннеля больше не спрашивает poll перед чтением (drain_conn_reads),
 * и чтение на пустом сокете, ждавшее срока SO_RCVTIMEO, остановило бы все соединения разом. Срок
 * сокета здесь — 2 с, как у настоящих связей (trdial.c ставит больше), а ждать позволено не дольше 200 мс. */
static int64_t ms_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void test_nowait(void) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { check(0, "пара сокетов"); return; }
    struct timeval tv = { 2, 0 };
    setsockopt(sv[0], SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    struct tr_link l;
    memset(&l, 0, sizeof(l));
    l.fd = sv[0];
    l.plain = 1;
    unsigned char b[64];
    size_t got = 99;
    int64_t t0 = ms_now();
    int rc = tr_link_read(&l, b, sizeof(b), &got);
    check(rc == 0 && got == 0 && ms_now() - t0 < 200, "голый сокет: чтение на пустом не ждёт и ничего не отдаёт");
    check(write(sv[1], "abc", 3) == 3, "голый сокет: запись в пару");
    rc = tr_link_read(&l, b, sizeof(b), &got);
    check(rc == 0 && got == 3 && !memcmp(b, "abc", 3), "голый сокет: пришедшее читается");
    l.rx_direct = 1;
    got = 99;
    t0 = ms_now();
    rc = tr_link_read(&l, b, sizeof(b), &got);
    check(rc == 0 && got == 0 && ms_now() - t0 < 200, "прямое копирование: чтение на пустом не ждёт");
    close(sv[1]);
    rc = tr_link_read(&l, b, sizeof(b), &got);
    check(rc == TR_ECLOSED, "голый сокет: закрытие узлом — конец потока");
    close(sv[0]);
}

static void test_socket(void) {
    struct srv s;
    pthread_t th;
    struct transport t;
    struct tr_node n;
    static unsigned char buf[TRANSPORT_MIN_READ_CAP];
    size_t got;
    int fd0 = fd_count();

    /* ws: апгрейд, первый кадр тем же куском, выгрузка кадрами по 4096, ping, close. */
    if (srv_start(&s, P_WS_OK, &th)) { check(0, "сервер-стенд поднялся"); return; }
    node0(&n, "ws");
    n.port = (uint16_t)s.port;
    n.path = "/w?ed=0";                        /* ed вырезается, Ed = 0: апгрейд сразу */
    n.http_host = "cdn.example.com";
    int rc = transport_open(&t, &n, 3);
    check(rc == 0, "ws: апгрейд на сокете прошёл");
    if (!rc) {
        check(transport_has_data(&t), "ws: первый кадр за ответом 101 виден как готовность без сокета");
        rc = tread(&t, buf, sizeof(buf), &got);
        check(!rc && got == 5 && !memcmp(buf, "FIRST", 5), "ws: первый кадр за ответом 101 не потерян");
        static unsigned char up[9000];
        for (size_t i = 0; i < sizeof(up); i++) up[i] = (unsigned char)(i * 31);
        check(transport_write(&t, up, sizeof(up)) == 0, "ws: запись 9000 байт");
        /* Дальше сервер шлёт ping (ноль байт данных, а не отказ) и close (конец потока). */
        size_t data = 0;
        rc = 0;
        for (int i = 0; i < 20 && !rc && ready(&t); i++) {
            rc = transport_read(&t, buf, sizeof(buf), &got);
            data += got;
        }
        if (rc != TR_ECLOSED || data) printf("  код %d (%s), данных %zu\n", rc, transport_strerror(rc), data);
        check(rc == TR_ECLOSED && data == 0, "ws: ping — без данных, close сервера — конец потока");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(!strncmp(s.req, "GET /w HTTP/1.1\r\nHost: cdn.example.com\r\n", 40), "ws: строка запроса и Host");
    check(strstr(s.req, "Sec-WebSocket-Protocol") == NULL, "ws: ранних данных нет (ed вырезан из пути)");
    check(s.frames == 3 && s.ops_ok, "ws: 9000 байт — кадры 4096+4096+808, binary и continuation, FIN на последнем");
    check(s.masked_all, "ws: каждый кадр клиента с маской");
    int same = s.got_n == 9000;
    for (size_t i = 0; same && i < 9000; i++) if (s.got[i] != (unsigned char)(i * 31)) same = 0;
    check(same, "ws: сервер получил ровно записанное");
    check(s.pong_ok, "ws: на ping ушёл pong с тем же телом");
    check(s.close_ok, "ws: на close ушёл close с тем же кодом");

    /* httpupgrade: остаток за ответом и эхо. */
    if (srv_start(&s, P_HU_OK, &th)) { check(0, "сервер-стенд поднялся"); return; }
    node0(&n, "httpupgrade");
    n.port = (uint16_t)s.port;
    rc = transport_open(&t, &n, 3);
    check(rc == 0, "httpupgrade: апгрейд на сокете прошёл");
    if (!rc) {
        check(transport_has_data(&t), "httpupgrade: остаток за ответом виден как готовность");
        const unsigned char *data = NULL;
        rc = transport_read_zc(&t, buf, sizeof(buf), &data, &got);
        check(!rc && got == 9 && !memcmp(data, "RAW-START", 9), "httpupgrade: начало потока за ответом 101 не потеряно");
        check(!transport_has_data(&t), "httpupgrade: остаток забран — готовности без сокета нет");
        check(transport_write(&t, (const unsigned char *)"echo", 4) == 0, "httpupgrade: запись как есть");
        rc = tread(&t, buf, sizeof(buf), &got);
        check(!rc && got == 4 && !memcmp(buf, "echo", 4), "httpupgrade: поток без кадров в обе стороны");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(strstr(s.req, "Sec-WebSocket-Key") == NULL && strstr(s.req, "\r\nUpgrade: websocket\r\n"),
          "httpupgrade: Upgrade без ключа WebSocket");

    /* Ранние данные — как у Xray: ws откладывает запрос до первой записи. */
    static unsigned char big[9000];
    for (size_t i = 0; i < sizeof(big); i++) big[i] = (unsigned char)(i * 31);
    for (int v = 0; v < 2; v++) {
        const int small = v == 0;
        if (srv_start(&s, small ? P_WS_ED : P_WS_EDBIG, &th)) { check(0, "сервер-стенд поднялся"); return; }
        node0(&n, "ws");
        n.port = (uint16_t)s.port;
        n.path = small ? "/w?ed=2048" : "/w?ed=16";
        rc = transport_open(&t, &n, 3);
        const char *tag = small ? "ws ed=2048, первая запись 5 байт" : "ws ed=16, первая запись 9000 байт";
        char what[160];
        snprintf(what, sizeof(what), "%s: открытие без запроса", tag);
        check(rc == 0, what);
        if (!rc) {
            if (small) check(transport_write(&t, (const unsigned char *)"hello", 5) == 0, "ws ed: ранние данные записаны");
            snprintf(what, sizeof(what), "%s: запись 9000 байт до ответа 101 — в очередь", tag);
            check(transport_write(&t, big, sizeof(big)) == 0, what);
            rc = tread(&t, buf, sizeof(buf), &got);
            snprintf(what, sizeof(what), "%s: ответ 101 принят, первый кадр за ним", tag);
            check(!rc && got == 5 && !memcmp(buf, "FIRST", 5), what);
            transport_close(&t);
        }
        srv_stop(&s, th);
        snprintf(what, sizeof(what), "%s: Sec-WebSocket-Protocol", tag);
        check_str(what, small ? "aGVsbG8" : "", s.proto);
        snprintf(what, sizeof(what), "%s: до ответа 101 кадров нет", tag);
        check(!s.early_before_101, what);
        same = s.got_n == 9000 && s.masked_all;
        for (size_t i = 0; same && i < 9000; i++) if (s.got[i] != big[i]) same = 0;
        snprintf(what, sizeof(what), "%s: 9000 байт кадрами с маской после 101", tag);
        check(same, what);
        snprintf(what, sizeof(what), "%s: при закрытии — close 1000", tag);
        check(s.close1000, what);
    }

    /* httpupgrade с ed поверх security=none: ответ ждём (почему — trupgrade.c, tr_h1_upgrade);
     * ленивый разбор ответа поверх TLS и REALITY проверяет vlessmatch в ext-test. */
    if (srv_start(&s, P_HU_ED, &th)) { check(0, "сервер-стенд поднялся"); return; }
    node0(&n, "httpupgrade");
    n.port = (uint16_t)s.port;
    n.path = "/u?ed=1";
    rc = transport_open(&t, &n, 3);
    check(rc == 0, "httpupgrade ed без TLS: открытие с ответом 101");
    if (!rc) {
        check(transport_write(&t, (const unsigned char *)"echo", 4) == 0, "httpupgrade ed: запись после 101");
        const unsigned char *data = NULL;
        size_t tot = 0;
        char acc[32] = "";
        for (int i = 0; i < 20 && tot < 9 && ready(&t); i++) {
            rc = transport_read_zc(&t, buf, sizeof(buf), &data, &got);
            if (rc) break;
            if (tot + got < sizeof(acc)) memcpy(acc + tot, data, got);
            tot += got;
        }
        check(!rc && tot == 9 && !memcmp(acc, "RAW-START", 9), "httpupgrade ed: остаток за ответом цел");
        transport_close(&t);
    }
    srv_stop(&s, th);
    check(!s.early_before_101 && s.got_n == 1, "httpupgrade ed без TLS: данные — только после ответа");
    check(!strncmp(s.req, "GET /u HTTP/1.1\r\n", 17), "httpupgrade ed: ed вырезан из пути");

    /* Отказы. */
    static const struct { enum plan p; const char *type; int want; const char *what; } F[] = {
        { P_404, "ws", TR_EUPSTATUS, "ws: ответ 404 — отказ" },
        { P_404, "httpupgrade", TR_EUPSTATUS, "httpupgrade: ответ 404 — отказ" },
        { P_NOUP, "ws", TR_ENOUPGRADE, "ws: 101 без Upgrade — отказ" },
        { P_BADACC, "ws", TR_EWSACCEPT, "ws: неверный Accept — отказ" },
        { P_SILENT, "ws", TR_EUPTIMEOUT, "ws: сервер молчит — таймаут" },
        { P_HANGUP, "httpupgrade", TR_ECLOSED, "httpupgrade: сервер закрылся — отказ" },
    };
    for (size_t i = 0; i < sizeof(F) / sizeof(*F); i++) {
        if (srv_start(&s, F[i].p, &th)) { check(0, "сервер-стенд поднялся"); return; }
        node0(&n, F[i].type);
        n.port = (uint16_t)s.port;
        rc = transport_open(&t, &n, 1);
        if (rc != F[i].want) printf("  %s: код %d (%s)\n", F[i].what, rc, transport_strerror(rc));
        check(rc == F[i].want, F[i].what);
        if (F[i].p == P_404)
            check(strstr(transport_strerror(rc), "404") != NULL, "текст отказа называет код ответа");
        if (!rc) transport_close(&t);
        srv_stop(&s, th);
    }
    check(fd_count() == fd0, "дескрипторы вернулись к исходному числу");
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("wsmatch: путь\n");
    test_path();
    printf("wsmatch: запрос Upgrade\n");
    test_request();
    printf("wsmatch: кадры клиента\n");
    test_frames_out();
    printf("wsmatch: кадры сервера\n");
    test_frames_in();
    printf("wsmatch: ответ 101\n");
    test_resp();
    printf("wsmatch: на сокете\n");
    test_socket();
    printf("wsmatch: чтение без ожидания\n");
    test_nowait();
    printf("wsmatch: %d проверок, %s\n", g_pass + g_fail, g_fail ? "ЕСТЬ ПРОВАЛЫ" : "все прошли");
    return g_fail ? 1 : 0;
}
