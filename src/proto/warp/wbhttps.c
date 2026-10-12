/* HTTPS-запрос модуля steer-warpbox: регистрация в API Cloudflare и проверки через туннель.
 *
 * ПОЧЕМУ СВОЙ, А НЕ curl. Регистрация — POST и PATCH с телом и заголовками, проверки — запросы через
 * устройство туннеля. curl на роутере есть не всегда, на телефоне его нет вовсе, а TLS 1.3 с проверкой
 * цепочки до корней в libsteer уже есть и проверен на живых узлах (тот же путь, что у замера HTTPS
 * группы, src/proto/tls/urltls.c): ClientHello — reality_build_hello_carry с plain и alpn_http11, рукопожатие —
 * tls13_handshake_auth, корни — tls_cert_roots. Запрос обычный HTTP/1.1 с Connection: close; ответ
 * читается до закрытия, с Content-Length или chunked.
 *
 * Блокирующий, со сроком на всё: модуль — свой процесс, и ждать ему некого (у демона так нельзя —
 * поэтому там рабочий поток). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "reality.h"
#include "tls13.h"
#include "roots.h"
#include "wbhttps.h"
#include "sockmark.h"

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int set_timeo(int fd, long deadline) {
    long left = deadline - mono_ms();
    if (left <= 0) return -1;
    struct timeval tv = { left / 1000, (left % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    return 0;
}

static int write_all(int fd, const unsigned char *p, size_t n) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

#define WHY(...) do { if (why) snprintf(why, wn, __VA_ARGS__); } while (0)

/* Соединение с одним адресом в срок. fd или -1. */
static int connect_one(const struct sockaddr *sa, socklen_t sl, const struct wb_route *rt,
                       long deadline, char *why, size_t wn) {
    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { WHY("socket: %s", strerror(errno)); return -1; }
    if (steer_sock_mark(fd, rt ? rt->mark : 0) != 0) {
        WHY("метка сокета: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (rt && rt->dev && rt->dev[0] &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, rt->dev, (socklen_t)strlen(rt->dev) + 1) != 0) {
        WHY("привязка к %s: %s", rt->dev, strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, sa, sl) != 0) {
        if (errno != EINPROGRESS) { WHY("соединение: %s", strerror(errno)); close(fd); return -1; }
        struct pollfd p = { fd, POLLOUT, 0 };
        long left = deadline - mono_ms();
        int pr = 0;
        if (left > 0) do pr = poll(&p, 1, (int)left); while (pr < 0 && errno == EINTR);
        int err = 0;
        socklen_t el = sizeof(err);
        if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            WHY("соединение: %s", pr <= 0 ? "срок вышел" : strerror(err ? err : errno));
            close(fd);
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    return fd;
}

/* Разобрать ответ целиком: статус, заголовки, тело (Content-Length, chunked или до закрытия). Тело
 * пишется на место в buf (chunked сжимается). 0 — разобрано. */
static int parse_resp(char *buf, size_t n, int *status, size_t *body_off, size_t *body_n) {
    if (n < 12 || strncmp(buf, "HTTP/1.", 7) || buf[8] != ' ') return -1;
    *status = atoi(buf + 9);
    char *end = memmem(buf, n, "\r\n\r\n", 4);
    if (!end) return -1;
    size_t hoff = (size_t)(end - buf) + 4;
    int chunked = 0;
    long clen = -1;
    for (char *l = memchr(buf, '\n', hoff); l && l < end; l = memchr(l + 1, '\n', (size_t)(end - l))) {
        const char *h = l + 1;
        if (!strncasecmp(h, "Transfer-Encoding:", 18) && strstr(h, "chunked") && strstr(h, "chunked") < end)
            chunked = 1;
        if (!strncasecmp(h, "Content-Length:", 15)) clen = atol(h + 15);
    }
    *body_off = hoff;
    if (!chunked) {
        size_t have = n - hoff;
        *body_n = clen >= 0 && (size_t)clen < have ? (size_t)clen : have;
        return 0;
    }
    /* chunked: <hex>\r\n<data>\r\n ... 0\r\n\r\n — данные сдвигаются к началу тела. */
    size_t r = hoff, w = hoff;
    for (;;) {
        if (r >= n) break;
        char *nl = memchr(buf + r, '\n', n - r);
        if (!nl) break;
        size_t len = strtoul(buf + r, NULL, 16);
        r = (size_t)(nl - buf) + 1;
        if (!len || r + len > n) break;
        memmove(buf + w, buf + r, len);
        w += len;
        r += len + 2;
    }
    *body_n = w - hoff;
    return 0;
}

int wb_https(const struct wb_req *q, const struct wb_route *rt, struct wb_resp *out, char *why, size_t wn) {
    long deadline = mono_ms() + (q->timeout_ms > 0 ? q->timeout_ms : 20000);
    out->status = 0;
    out->body = NULL;
    out->body_n = 0;
    if (why && wn) why[0] = '\0';
    char port[12];
    snprintf(port, sizeof(port), "%u", q->port ? q->port : 443u);
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    const char *addr = q->addr && q->addr[0] ? q->addr : q->host;
    int gr = getaddrinfo(addr, port, &hints, &res);
    if (gr != 0 || !res) { WHY("имя %s не разрешилось: %s", addr, gai_strerror(gr)); return -1; }
    int fd = -1;
    /* Сначала IPv4: у роутера без глобального IPv6 попытка по AAAA отваливается сразу, но на
     * телефоне в сети с «сломанным» IPv6 она ждала бы весь срок. */
    for (int fam = 0; fam < 2 && fd < 0; fam++)
        for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next)
            if ((fam == 0) == (a->ai_family == AF_INET))
                fd = connect_one(a->ai_addr, a->ai_addrlen, rt, deadline, why, wn);
    freeaddrinfo(res);
    if (fd < 0) return -1;
    if (set_timeo(fd, deadline)) { WHY("срок вышел до рукопожатия"); close(fd); return -1; }

    /* Только http/1.1 в ALPN (alpn_http11): с парой «h2, http/1.1», как у браузера, Cloudflare
     * выбирает h2 и присылает кадры HTTP/2 вместо ответа. */
    struct reality_cfg cfg = { .sni = q->host, .alpn = "http/1.1", .plain = 1 };
    struct reality_carrier car = { .alpn_http11 = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    struct tls13 *t = NULL;
    char *buf = NULL;
    int rc = -1;
    if (reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof(hello), &hello_n) != 0) { WHY("ClientHello не собрался"); goto out; }
    if (write_all(fd, hello, hello_n) != 0) { WHY("ClientHello не отправился"); goto out; }
    t = calloc(1, sizeof(*t));
    if (!t) { WHY("нет памяти"); goto out; }
    struct tls13_auth auth = { .host = q->host, .roots = tls_cert_roots() };
    int hrc = tls13_handshake_auth(t, fd, hello, hello_n, rst.priv, &auth);
    if (hrc != 0) {
        const char *vr = hrc == TLS13_ECERT ? tls13_verify_reason() : NULL;
        if (vr && vr[0]) WHY("сертификат %s не принят: %s", q->host, vr);
        else WHY("рукопожатие TLS с %s не удалось (код %d)", q->host, hrc);
        goto out;
    }
    size_t cap = 2048 + (q->body ? q->body_n : 0) + (q->headers ? strlen(q->headers) : 0);
    char *req = malloc(cap);
    if (!req) { WHY("нет памяти"); goto out; }
    int rn = snprintf(req, cap, "%s %s HTTP/1.1\r\nHost: %s\r\n%sConnection: close\r\n", q->method,
                      q->path, q->host, q->headers ? q->headers : "");
    if (rn > 0 && q->body && (size_t)rn < cap)
        rn += snprintf(req + rn, cap - (size_t)rn, "Content-Type: application/json\r\nContent-Length: %zu\r\n",
                       q->body_n);
    if (rn > 0 && (size_t)rn < cap) rn += snprintf(req + rn, cap - (size_t)rn, "\r\n");
    if (rn <= 0 || (size_t)rn >= cap) { free(req); WHY("запрос не уместился"); goto out; }
    int wr = tls13_write(t, (const unsigned char *)req, (size_t)rn);
    free(req);
    if (wr == 0 && q->body && q->body_n) wr = tls13_write(t, (const unsigned char *)q->body, q->body_n);
    if (wr != 0) { WHY("запрос не отправился"); goto out; }

    size_t bcap = 64 * 1024, bn = 0;
    buf = malloc(bcap + 1);
    if (!buf) { WHY("нет памяти"); goto out; }
    for (;;) {
        if (set_timeo(fd, deadline)) break;
        size_t got = 0;
        /* Место под целую запись: tls13_read кладёт расшифрованную запись целиком. */
        if (bcap - bn < TLS13_MAX_PLAIN) {
            if (bcap >= WB_RESP_MAX) { WHY("ответ длиннее %d байт", WB_RESP_MAX); goto out; }
            char *nb = realloc(buf, bcap * 2 + 1);
            if (!nb) { WHY("нет памяти"); goto out; }
            buf = nb;
            bcap *= 2;
        }
        int rrc = tls13_read(t, (unsigned char *)buf + bn, bcap - bn, &got);
        if (rrc != 0) break;                    /* закрытие (Connection: close) или срок */
        bn += got;
    }
    buf[bn] = '\0';
    size_t off = 0, blen = 0;
    if (parse_resp(buf, bn, &out->status, &off, &blen) != 0) { WHY("ответ не похож на HTTP (%zu байт)", bn); goto out; }
    memmove(buf, buf + off, blen);
    buf[blen] = '\0';
    out->body = buf;
    out->body_n = blen;
    buf = NULL;
    rc = 0;
out:
    free(buf);
    if (t) { tls13_free(t); free(t); }
    close(fd);
    return rc;
}

void wb_resp_free(struct wb_resp *r) {
    free(r->body);
    r->body = NULL;
    r->body_n = 0;
}
