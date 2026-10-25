/* HTTP/1.1-клиент libsteer (src/proto/tls/httpc.c): стенд против настоящего сервера на сокете.
 *
 * Сервер — потоки в этом же файле, слушает 127.0.0.1 на случайном порту и ведёт себя по пути запроса:
 * отдаёт Content-Length и chunked (с расширениями и трейлерами), закрывает соединение вместо длины,
 * переадресует (цепочки, относительные и абсолютные Location, петля, 307, 302 без Location), требует
 * cookie, отвечает 304 на If-None-Match, молчит, зависает посреди заголовков и тела, обрывает тело,
 * шлёт 100 Continue, мусор и бесконечные заголовки. Ни сети, ни криптобиблиотеки: TLS подменён
 * заглушками (https:// здесь проверяется только отказом); настоящий HTTPS и проверка сертификата — в
 * tests/httpsmatch.sh (make ext-test) на python-сервере со своим корнем.
 *
 * Большие тела — 48 МиБ без Content-Length, 40 МиБ с ним и 40 МиБ chunked — идут потоком через body_cb и
 * сверяются с шаблоном на лету, без накопления: видно, что клиент не упёрся ни в какой предел. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "unit.h"
#include "reality.h"
#include "tls13.h"
#include "roots.h"
#include "httpc.h"

/* ---- заглушки TLS: рукопожатия в этом стенде нет ----------------------------------------------- */
const char *tls_cert_roots(void) { return NULL; }
const char *tls13_verify_reason(void) { return ""; }
void tls13_free(struct tls13 *t) { (void)t; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n) { (void)t; (void)d; (void)n; return -1; }
int tls13_read_ref(struct tls13 *t, const unsigned char **b, size_t *n) { (void)t; (void)b; (void)n; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *h, size_t hn, const unsigned char *s,
                         const struct tls13_auth *a) { (void)t; (void)fd; (void)h; (void)hn; (void)s; (void)a; return -1; }
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st, const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len) {
    (void)cfg; (void)st; (void)car; (void)out; (void)out_n; (void)out_len;
    return -1;
}

/* ---- сервер ------------------------------------------------------------------------------------ */

static int g_lfd, g_port;

static void sendall(int fd, const void *p, size_t n) {
    const char *c = p;
    while (n) {
        ssize_t w = send(fd, c, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return;
        c += w;
        n -= (size_t)w;
    }
}
static void sends(int fd, const char *s) { sendall(fd, s, strlen(s)); }

static unsigned char pat(unsigned long long i) { return (unsigned char)((i * 131 + 17) & 0xff); }

static void send_pattern(int fd, unsigned long long n) {
    unsigned char buf[65536];
    unsigned long long off = 0;
    while (off < n) {
        size_t k = n - off < sizeof buf ? (size_t)(n - off) : sizeof buf;
        for (size_t i = 0; i < k; i++) buf[i] = pat(off + i);
        sendall(fd, buf, k);
        off += k;
    }
}

static void *serve(void *arg) {
    int fd = (int)(long)arg;
    char req[8192];
    size_t n = 0;
    while (n < sizeof req - 1) {
        ssize_t r = recv(fd, req + n, sizeof req - 1 - n, 0);
        if (r <= 0) { close(fd); return NULL; }
        n += (size_t)r;
        req[n] = 0;
        if (strstr(req, "\r\n\r\n")) break;
    }
    char method[16], path[512];
    if (sscanf(req, "%15s %511s", method, path) != 2) { close(fd); return NULL; }
    int head = !strcmp(method, "HEAD");
    char hdr[1024];
    #define R(fmt, ...) do { snprintf(hdr, sizeof hdr, fmt, ##__VA_ARGS__); sends(fd, hdr); } while (0)

    if (!strcmp(path, "/ok")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world");
    } else if (!strcmp(path, "/echo")) {
        R("HTTP/1.1 200 OK\r\nContent-Length: %zu\r\n\r\n", n);
        sendall(fd, req, n);
    } else if (!strcmp(path, "/chunked")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3;ext=1\r\nHel\r\n3\r\nlo \r\n8\r\nworld!!!\r\n0\r\nX-Trailer: 1\r\n\r\n");
    } else if (!strcmp(path, "/chunked-up")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\nA\r\n0123456789\r\n0\r\n\r\n");
    } else if (!strcmp(path, "/chunked-bad")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nxx\r\n");
    } else if (!strcmp(path, "/chunked-huge")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\nx");
    } else if (!strcmp(path, "/big")) {            /* без длины: до закрытия */
        sends(fd, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n");
        send_pattern(fd, 48ULL << 20);
    } else if (!strcmp(path, "/bigcl")) {
        R("HTTP/1.1 200 OK\r\nContent-Length: %llu\r\n\r\n", 40ULL << 20);
        send_pattern(fd, 40ULL << 20);
    } else if (!strcmp(path, "/bigchunk")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
        for (int i = 0; i < 40; i++) {
            R("%x\r\n", 1u << 20);
            send_pattern(fd, 1ULL << 20);        /* каждый кусок с начала шаблона — стенд знает */
            sends(fd, "\r\n");
        }
        sends(fd, "0\r\n\r\n");
    } else if (!strcmp(path, "/r1")) {
        sends(fd, "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/r2")) {
        sends(fd, "HTTP/1.1 301 Moved\r\nLocation: /r1\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/dir/rel")) {
        sends(fd, "HTTP/1.1 302 Found\r\nLocation: sibling?x=1\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/dir/sibling?x=1")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nsib");
    } else if (!strcmp(path, "/rabs")) {
        R("HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/ok\r\nContent-Length: 0\r\n\r\n", g_port);
    } else if (!strcmp(path, "/rscheme")) {
        R("HTTP/1.1 302 Found\r\nLocation: //127.0.0.1:%d/ok\r\nContent-Length: 0\r\n\r\n", g_port);
    } else if (!strcmp(path, "/r307")) {
        sends(fd, "HTTP/1.1 307 Temporary\r\nLocation: /echo\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/rloop")) {
        sends(fd, "HTTP/1.1 302 Found\r\nLocation: /rloop\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/rnoloc")) {
        sends(fd, "HTTP/1.1 302 Found\r\nContent-Length: 4\r\n\r\nnope");
    } else if (!strcmp(path, "/rtls")) {
        R("HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1:%d/ok\r\nContent-Length: 0\r\n\r\n", g_port);
    } else if (!strcmp(path, "/cookie")) {
        if (strstr(req, "Cookie: sid=abc; theme=dark\r\n"))
            sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\ncookie ok");
        else
            sends(fd, "HTTP/1.1 302 Found\r\nSet-Cookie: sid=abc; Path=/; HttpOnly\r\nSet-Cookie: theme=dark\r\nLocation: /cookie\r\nContent-Length: 0\r\n\r\n");
    } else if (!strcmp(path, "/etag")) {
        if (strstr(req, "If-None-Match: \"v1\"\r\n"))
            sends(fd, "HTTP/1.1 304 Not Modified\r\nETag: \"v1\"\r\n\r\n");
        else
            sends(fd, "HTTP/1.1 200 OK\r\nETag: \"v1\"\r\nContent-Length: 7\r\n\r\netagged");
    } else if (!strcmp(path, "/404")) {
        sends(fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 4\r\n\r\nnope");
    } else if (!strcmp(path, "/head")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-Quota: 42\r\n\r\n");
        if (!head) sends(fd, "12345");
    } else if (!strcmp(path, "/silent")) {
        sleep(3);
    } else if (!strcmp(path, "/stall")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789");
        sleep(3);
    } else if (!strcmp(path, "/drip")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");
        for (int i = 0; i < 10; i++) { sendall(fd, "x", 1); usleep(100000); }
    } else if (!strcmp(path, "/trunc")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n");
        send_pattern(fd, 50);
    } else if (!strcmp(path, "/chunktrunc")) {
        sends(fd, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n");
    } else if (!strcmp(path, "/hdrtrunc")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Le");
    } else if (!strcmp(path, "/100")) {
        sends(fd, "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    } else if (!strcmp(path, "/garbage")) {
        sends(fd, "this is not http\r\n\r\n");
    } else if (!strcmp(path, "/badcl")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n");
    } else if (!strcmp(path, "/hugehdr")) {
        sends(fd, "HTTP/1.1 200 OK\r\n");
        char line[1024];
        memset(line, 'a', sizeof line - 3);
        memcpy(line, "X-Pad: ", 7);
        memcpy(line + sizeof line - 3, "\r\n", 3);
        for (int i = 0; i < 1400; i++) sendall(fd, line, sizeof line - 1);
    } else if (!strcmp(path, "/cookie-del")) {
        sends(fd, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n");
    } else {
        sends(fd, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n");
    }
    close(fd);
    return NULL;
}

static void *acceptor(void *arg) {
    (void)arg;
    for (;;) {
        int fd = accept(g_lfd, NULL, NULL);
        if (fd < 0) continue;
        pthread_t th;
        pthread_attr_t at;
        pthread_attr_init(&at);
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_create(&th, &at, serve, (void *)(long)fd);
        pthread_attr_destroy(&at);
    }
    return NULL;
}

/* ---- помощники стенда ------------------------------------------------------------------------- */

static char URL[256];
static const char *url(const char *path) {
    snprintf(URL, sizeof URL, "http://127.0.0.1:%d%s", g_port, path);
    return URL;
}

struct acc { unsigned char *b; size_t n, cap; unsigned long long cnt, sum; int stop_after; };
static int collect(void *arg, const void *d, size_t n) {
    struct acc *a = arg;
    if (a->b) {
        if (a->n + n > a->cap) { a->cap = (a->n + n) * 2; a->b = realloc(a->b, a->cap); }
        memcpy(a->b + a->n, d, n);
        a->n += n;
    }
    a->cnt += n;
    if (a->stop_after && a->cnt >= (unsigned long long)a->stop_after) return 1;
    return 0;
}
static int is_text(const struct acc *a, const char *s) { return a->n == strlen(s) && !memcmp(a->b, s, a->n); }

/* Сверка большого тела с шаблоном потоком: без накопления. */
struct patchk { unsigned long long off, bad, period; };
static int patcb(void *arg, const void *d, size_t n) {
    struct patchk *p = arg;
    const unsigned char *c = d;
    for (size_t i = 0; i < n; i++) {
        unsigned long long k = p->period ? (p->off + i) % p->period : p->off + i;
        if (c[i] != pat(k)) p->bad++;
    }
    p->off += n;
    return 0;
}

static int get(const char *path, struct acc *a, struct http_resp *r, char *why, size_t wn) {
    struct http_req q = { .url = url(path), .body_cb = collect, .cb_arg = a, .idle_ms = 2000 };
    return http_get(&q, r, why, wn);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(g_lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t sl = sizeof sa;
    if (bind(g_lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_lfd, 64) != 0) { perror("listen"); return 2; }
    getsockname(g_lfd, (struct sockaddr *)&sa, &sl);
    g_port = ntohs(sa.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, acceptor, NULL);

    char why[300];
    struct http_resp r;
    struct acc a;
    #define NEW() do { memset(&a, 0, sizeof a); a.b = malloc(16); a.cap = 16; } while (0)
    #define DONE() do { free(a.b); http_resp_free(&r); } while (0)

    /* ---- обычный ответ, заголовки, последний вызов -------------------------------------------------- */
    NEW();
    check("GET /ok", 0, get("/ok", &a, &r, why, sizeof why));
    check("  статус 200", 200, r.status);
    check("  тело «hello world»", 1, is_text(&a, "hello world"));
    check("  body_n = 11", 11, (long)r.body_n);
    size_t vn;
    const char *v = http_resp_header(&r, "content-type", &vn);
    check("  заголовок Content-Type (регистр имени не важен)", 1, v && vn == 10 && !memcmp(v, "text/plain", 10));
    check("  заголовка нет — NULL", 1, http_resp_header(&r, "X-Nope", NULL) == NULL);
    check("  заголовки начинаются со статусной строки без \\r", 1, r.headers && !strncmp(r.headers, "HTTP/1.1 200 OK\n", 16) && !strchr(r.headers, '\r'));
    check("  адрес конечного ответа", 1, r.url && strstr(r.url, "/ok") != NULL);
    check("  не 304", 0, r.not_modified);
    DONE();

    /* ---- что клиент посылает ---------------------------------------------------------------------- */
    NEW();
    check("GET /echo (что ушло серверу)", 0, get("/echo", &a, &r, why, sizeof why));
    a.b[a.n] = 0;
    check("  строка запроса GET /echo HTTP/1.1", 1, !strncmp((char *)a.b, "GET /echo HTTP/1.1\r\n", 20));
    char hostline[64];
    snprintf(hostline, sizeof hostline, "Host: 127.0.0.1:%d\r\n", g_port);
    check("  Host с нестандартным портом", 1, strstr((char *)a.b, hostline) != NULL);
    check("  User-Agent steer/", 1, strstr((char *)a.b, "User-Agent: steer/") != NULL);
    check("  Connection: close", 1, strstr((char *)a.b, "Connection: close\r\n") != NULL);
    DONE();
    {
        NEW();
        struct http_req q = { .url = url("/echo"), .body_cb = collect, .cb_arg = &a, .headers = "User-Agent: custom/1\r\nX-HWID: abc\r\nAccept: text/x\r\n", .etag = "\"v9\"" };
        check("добавочные заголовки и If-None-Match", 0, http_get(&q, &r, why, sizeof why));
        a.b[a.n] = 0;
        check("  свой User-Agent вместо нашего", 1, strstr((char *)a.b, "User-Agent: custom/1\r\n") && !strstr((char *)a.b, "steer/"));
        check("  X-HWID дошёл", 1, strstr((char *)a.b, "X-HWID: abc\r\n") != NULL);
        check("  свой Accept вместо нашего", 1, strstr((char *)a.b, "Accept: text/x\r\n") && !strstr((char *)a.b, "Accept: */*"));
        check("  If-None-Match", 1, strstr((char *)a.b, "If-None-Match: \"v9\"\r\n") != NULL);
        DONE();
    }

    /* ---- chunked ---------------------------------------------------------------------------------- */
    NEW();
    check("chunked: расширения, трейлер, шестнадцатеричные размеры", 0, get("/chunked", &a, &r, why, sizeof why));
    check("  тело склеено", 1, is_text(&a, "Hello world!!!"));
    DONE();
    NEW();
    check("Transfer-Encoding: Chunked (регистр)", 0, get("/chunked-up", &a, &r, why, sizeof why));
    check("  тело", 1, is_text(&a, "0123456789"));
    DONE();
    NEW();
    check("chunked: мусор вместо размера", HTTPC_EPROTO, get("/chunked-bad", &a, &r, why, sizeof why));
    check("  причина названа", 1, why[0] != 0);
    DONE();
    NEW();
    check("chunked: размер куска не влезает в 64 бита", HTTPC_EPROTO, get("/chunked-huge", &a, &r, why, sizeof why));
    DONE();
    NEW();
    check("chunked: оборван без нулевого куска", HTTPC_ETRUNC, get("/chunktrunc", &a, &r, why, sizeof why));
    check("  то, что пришло, доставлено (5 байт)", 5, (long)a.cnt);
    DONE();

    /* ---- большие тела потоком: пределов нет ---------------------------------------------------------- */
    {
        struct patchk pk = {0};
        struct http_req q = { .url = url("/big"), .body_cb = patcb, .cb_arg = &pk, .idle_ms = 5000 };
        check("48 МиБ до закрытия соединения", 0, http_get(&q, &r, why, sizeof why));
        check("  байт получено", 48 << 20, (long)pk.off);
        check("  байт расходится с шаблоном", 0, (long)pk.bad);
        check("  body_n", 48 << 20, (long)r.body_n);
        http_resp_free(&r);
        memset(&pk, 0, sizeof pk);
        q.url = url("/bigcl");
        check("40 МиБ с Content-Length", 0, http_get(&q, &r, why, sizeof why));
        check("  байт получено", 40 << 20, (long)pk.off);
        check("  байт расходится с шаблоном", 0, (long)pk.bad);
        http_resp_free(&r);
        memset(&pk, 0, sizeof pk);
        pk.period = 1u << 20;
        q.url = url("/bigchunk");
        check("40 МиБ chunked по 1 МиБ", 0, http_get(&q, &r, why, sizeof why));
        check("  байт получено", 40 << 20, (long)pk.off);
        check("  байт расходится с шаблоном", 0, (long)pk.bad);
        http_resp_free(&r);
    }

    /* ---- файл ---------------------------------------------------------------------------------------- */
    {
        char tmpl[] = "/tmp/httpmatch.XXXXXX";
        char *dir = mkdtemp(tmpl);
        char fp[300];
        snprintf(fp, sizeof fp, "%s/body", dir);
        struct http_req q = { .url = url("/bigcl"), .dest_path = fp, .idle_ms = 5000 };
        check("тело в файл (40 МиБ)", 0, http_get(&q, &r, why, sizeof why));
        struct stat st;
        check("  размер файла", 40 << 20, stat(fp, &st) == 0 ? (long)st.st_size : -1);
        http_resp_free(&r);
        /* Файл и колбэк разом. */
        struct acc cnt = {0};
        q.url = url("/ok");
        q.body_cb = collect;
        q.cb_arg = &cnt;
        check("файл и колбэк одновременно", 0, http_get(&q, &r, why, sizeof why));
        check("  файл усечён и перезаписан (11 байт)", 11, stat(fp, &st) == 0 ? (long)st.st_size : -1);
        check("  колбэк видел те же 11", 11, (long)cnt.cnt);
        http_resp_free(&r);
        /* Обрыв — файл не остаётся. */
        q.url = url("/trunc");
        q.body_cb = NULL;
        check("обрыв тела: код", HTTPC_ETRUNC, http_get(&q, &r, why, sizeof why));
        check("  недокачанный файл удалён", -1, stat(fp, &st));
        http_resp_free(&r);
        /* 404 — файл не создаётся и не трогается. */
        FILE *f = fopen(fp, "w"); fputs("old", f); fclose(f);
        q.url = url("/404");
        check("404: ответ получен", 0, http_get(&q, &r, why, sizeof why));
        check("  статус 404", 404, r.status);
        check("  старый файл не тронут", 3, stat(fp, &st) == 0 ? (long)st.st_size : -1);
        http_resp_free(&r);
        /* Нельзя писать. */
        snprintf(fp, sizeof fp, "%s/нет/каталога/body", dir);
        q.url = url("/ok");
        check("файл нельзя создать", HTTPC_ESINK, http_get(&q, &r, why, sizeof why));
        check("  причина называет файл", 1, strstr(why, "body") != NULL);
        http_resp_free(&r);
        snprintf(fp, sizeof fp, "%s/body", dir);
        unlink(fp);
        rmdir(dir);
    }

    /* ---- приёмник прерывает -------------------------------------------------------------------------- */
    {
        memset(&a, 0, sizeof a);
        a.stop_after = 1000;
        struct http_req q = { .url = url("/bigcl"), .body_cb = collect, .cb_arg = &a, .idle_ms = 5000 };
        check("body_cb прервал загрузку", HTTPC_ESINK, http_get(&q, &r, why, sizeof why));
        check("  остановились сразу, не дочитав 40 МиБ", 1, a.cnt < (1 << 20));
        http_resp_free(&r);
    }

    /* ---- переадресации -------------------------------------------------------------------------------- */
    NEW();
    check("302 -> /ok", 0, get("/r1", &a, &r, why, sizeof why));
    check("  тело конечного ответа", 1, is_text(&a, "hello world"));
    check("  переадресаций: 1", 1, r.redirects);
    check("  адрес — конечный", 1, r.url && strstr(r.url, "/ok") != NULL);
    DONE();
    NEW();
    check("цепочка 301 -> 302 -> /ok", 0, get("/r2", &a, &r, why, sizeof why));
    check("  переадресаций: 2", 2, r.redirects);
    check("  тело", 1, is_text(&a, "hello world"));
    DONE();
    NEW();
    check("относительный Location: sibling?x=1 от /dir/rel", 0, get("/dir/rel", &a, &r, why, sizeof why));
    check("  тело «sib»", 1, is_text(&a, "sib"));
    DONE();
    NEW();
    check("абсолютный Location", 0, get("/rabs", &a, &r, why, sizeof why));
    check("  тело", 1, is_text(&a, "hello world"));
    DONE();
    NEW();
    check("Location без схемы (//host/path)", 0, get("/rscheme", &a, &r, why, sizeof why));
    check("  тело", 1, is_text(&a, "hello world"));
    DONE();
    NEW();
    check("307", 0, get("/r307", &a, &r, why, sizeof why));
    check("  метод тот же (GET /echo)", 1, a.n > 10 && !memcmp(a.b, "GET /echo", 9));
    DONE();
    NEW();
    check("петля: отказ по пределу переадресаций", HTTPC_EREDIR, get("/rloop", &a, &r, why, sizeof why));
    check("  причина называет число (10)", 1, strstr(why, "10") != NULL);
    DONE();
    {
        NEW();
        struct http_req q = { .url = url("/rloop"), .body_cb = collect, .cb_arg = &a, .max_redirects = 3, .idle_ms = 2000 };
        check("max_redirects = 3", HTTPC_EREDIR, http_get(&q, &r, why, sizeof why));
        check("  причина называет число (3)", 1, strstr(why, "3") != NULL);
        DONE();
        NEW();
        q.url = url("/r1");
        q.max_redirects = -1;
        check("max_redirects < 0: 3xx отдаётся как ответ", 0, http_get(&q, &r, why, sizeof why));
        check("  статус 302", 302, r.status);
        check("  Location в заголовках", 1, http_resp_header(&r, "Location", NULL) != NULL);
        check("  тело не читалось", 0, (long)a.cnt);
        DONE();
    }
    NEW();
    check("302 без Location — конечный ответ", 0, get("/rnoloc", &a, &r, why, sizeof why));
    check("  статус 302", 302, r.status);
    DONE();
    NEW();
    check("cookie возвращается на тот же адрес (302 с Set-Cookie)", 0, get("/cookie", &a, &r, why, sizeof why));
    check("  тело «cookie ok»", 1, is_text(&a, "cookie ok"));
    check("  одна переадресация", 1, r.redirects);
    DONE();
    NEW();
    check("переадресация http -> https (в стенде TLS нет): отказ TLS", HTTPC_ETLS, get("/rtls", &a, &r, why, sizeof why));
    DONE();

    /* ---- If-None-Match / ETag ------------------------------------------------------------------------ */
    NEW();
    check("без If-None-Match: 200 и ETag", 0, get("/etag", &a, &r, why, sizeof why));
    check("  ETag в ответе", 1, r.etag && !strcmp(r.etag, "\"v1\""));
    check("  тело", 1, is_text(&a, "etagged"));
    DONE();
    {
        NEW();
        struct http_req q = { .url = url("/etag"), .body_cb = collect, .cb_arg = &a, .etag = "\"v1\"", .idle_ms = 2000 };
        check("If-None-Match совпал: 304", 0, http_get(&q, &r, why, sizeof why));
        check("  статус 304", 304, r.status);
        check("  not_modified", 1, r.not_modified);
        check("  тела нет", 0, (long)a.cnt);
        check("  ETag отдан и с 304", 1, r.etag && !strcmp(r.etag, "\"v1\""));
        DONE();
        NEW();
        q.etag = "\"v0\"";
        check("If-None-Match не совпал: 200 с телом", 0, http_get(&q, &r, why, sizeof why));
        check("  тело", 1, is_text(&a, "etagged"));
        DONE();
    }

    /* ---- HEAD, статусы, прочее ------------------------------------------------------------------------ */
    {
        NEW();
        struct http_req q = { .url = url("/head"), .method = "HEAD", .body_cb = collect, .cb_arg = &a, .idle_ms = 2000 };
        check("HEAD", 0, http_get(&q, &r, why, sizeof why));
        check("  статус 200", 200, r.status);
        check("  тела нет, хотя Content-Length: 5", 0, (long)a.cnt);
        v = http_resp_header(&r, "x-quota", &vn);
        check("  X-Quota: 42", 1, v && vn == 2 && !memcmp(v, "42", 2));
        DONE();
        NEW();
        q.method = "POST";
        check("метод POST не поддержан", HTTPC_EURL, http_get(&q, &r, why, sizeof why));
        DONE();
        NEW();
        q.method = NULL;
        q.body_cb = NULL;
        q.url = url("/ok");
        check("без приёмника тело не читается, статус есть", 0, http_get(&q, &r, why, sizeof why));
        check("  статус 200", 200, r.status);
        check("  body_n = 0", 0, (long)r.body_n);
        DONE();
    }
    NEW();
    check("404 — ответ, а не отказ", 0, get("/404", &a, &r, why, sizeof why));
    check("  статус 404", 404, r.status);
    check("  тело 404 не отдано приёмнику", 0, (long)a.cnt);
    DONE();
    NEW();
    check("100 Continue перед ответом пропущен", 0, get("/100", &a, &r, why, sizeof why));
    check("  статус 200, тело", 1, r.status == 200 && is_text(&a, "ok"));
    DONE();
    NEW();
    check("ответ не HTTP", HTTPC_EPROTO, get("/garbage", &a, &r, why, sizeof why));
    DONE();
    NEW();
    check("Content-Length не число", HTTPC_EPROTO, get("/badcl", &a, &r, why, sizeof why));
    DONE();
    NEW();
    check("заголовки длиннее предела", HTTPC_EHDR, get("/hugehdr", &a, &r, why, sizeof why));
    check("  причина называет число", 1, strstr(why, "1048576") != NULL);
    DONE();
    NEW();
    check("обрыв посреди заголовков", HTTPC_ETRUNC, get("/hdrtrunc", &a, &r, why, sizeof why));
    DONE();
    NEW();
    check("тело короче Content-Length", HTTPC_ETRUNC, get("/trunc", &a, &r, why, sizeof why));
    check("  причина называет счёт", 1, strstr(why, "50") != NULL);
    DONE();

    /* ---- сроки ---------------------------------------------------------------------------------------- */
    {
        NEW();
        struct http_req q = { .url = url("/silent"), .body_cb = collect, .cb_arg = &a, .idle_ms = 300 };
        long t0 = (long)time(NULL);
        check("сервер молчит: срок молчания", HTTPC_ETIMEOUT, http_get(&q, &r, why, sizeof why));
        check("  уложились (не 3 с сервера)", 1, (long)time(NULL) - t0 < 3);
        check("  причина называет 300 мс", 1, strstr(why, "300") != NULL);
        DONE();
        NEW();
        q.url = url("/stall");
        check("сервер замолчал посреди тела", HTTPC_ETIMEOUT, http_get(&q, &r, why, sizeof why));
        check("  10 байт получено", 10, (long)a.cnt);
        DONE();
        NEW();
        q.url = url("/drip");
        q.idle_ms = 500;
        check("медленная капля (100 мс/байт) при idle 500 — проходит", 0, http_get(&q, &r, why, sizeof why));
        check("  10 байт", 10, (long)a.cnt);
        DONE();
        NEW();
        q.total_ms = 400;
        check("то же при общем сроке 400 мс — не проходит", HTTPC_ETIMEOUT, http_get(&q, &r, why, sizeof why));
        check("  причина про общий срок", 1, strstr(why, "общий") != NULL);
        DONE();
    }

    /* ---- ссылки и соединение --------------------------------------------------------------------------- */
    {
        const char *bad[] = { "ftp://127.0.0.1/x", "http://", "http:///x", "http://h:99999/", "http://h:0/", "http://u:p@h/x",
                              "127.0.0.1/ok", "", "http://h:ab/", "http://[::1/x" };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            struct http_req q = { .url = bad[i] };
            char w[200];
            snprintf(w, sizeof w, "плохая ссылка «%s»", bad[i]);
            check(w, HTTPC_EURL, http_get(&q, &r, why, sizeof why));
            http_resp_free(&r);
        }
        struct http_req q0 = { .url = NULL };
        check("ссылка NULL", HTTPC_EURL, http_get(&q0, &r, why, sizeof why));
        http_resp_free(&r);
    }
    {
        /* Порт, на котором никто не слушает: заведём сокет и закроем. */
        int t = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in z = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
        socklen_t zl = sizeof z;
        bind(t, (struct sockaddr *)&z, sizeof z);
        getsockname(t, (struct sockaddr *)&z, &zl);
        close(t);
        char u[100];
        snprintf(u, sizeof u, "http://127.0.0.1:%d/", ntohs(z.sin_port));
        struct http_req q = { .url = u };
        check("порт закрыт", HTTPC_ECONNECT, http_get(&q, &r, why, sizeof why));
        check("  причина названа", 1, why[0] != 0);
        http_resp_free(&r);
        struct http_req q2 = { .url = "http://nonexistent.invalid/" };
        check("имя не разрешилось", HTTPC_ERESOLVE, http_get(&q2, &r, why, sizeof why));
        http_resp_free(&r);
        char u3[100];
        snprintf(u3, sizeof u3, "https://127.0.0.1:%d/ok", g_port);
        struct http_req q3 = { .url = u3 };
        check("https без TLS в стенде: отказ TLS, а не падение", HTTPC_ETLS, http_get(&q3, &r, why, sizeof why));
        http_resp_free(&r);
    }

    return unit_done("httpmatch");
}
