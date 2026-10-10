/* Установка соединения с апстримом DoT и DoH: bootstrap, connect, рукопожатие TLS — в потоке.
 *
 * ПОЧЕМУ ПОТОК. Рукопожатие нашего TLS (src/proto/tls/tls13.c) блокирующее: оно читает сокет до
 * следующей записи сервера, с таймаутом SO_RCVTIMEO, и с середины не продолжается. Вести его из
 * цикла резолвера значило бы остановить DNS всей сети на время round trip'ов до сервера (сотни
 * миллисекунд через туннель, секунды при потерях). Переписывать его в автомат ради этого не стали:
 * то же рукопожатие обслуживает VLESS, xsteer и замер групп, и второй, неблокирующий вариант был
 * бы вторым местом, где живёт отпечаток ClientHello и проверка сертификата. Поток заводится на
 * установку соединения — а не на запрос: готовое соединение потом живёт в цикле, тысячи запросов
 * идут по нему без потоков. Так же устроен замер urltest по HTTPS (src/proto/tls/urltls.c).
 *
 * ЧТО В ПОТОКЕ: всё блокирующее и редкое. Порядок такой:
 *   1. Адреса сервера: сам адрес, если имя — адрес; иначе `ips` из спеки; иначе прежде найденные,
 *      если срок не вышел; иначе bootstrap. Если bootstrap не ответил, а прежние адреса есть, —
 *      прежние (устаревший адрес лучше отказа: серверы DNS меняют адреса раз в годы).
 *   2. connect с меткой пути (SO_MARK) — по адресам по очереди, в пределах срока.
 *   3. ClientHello (reality_build_hello_carry в режиме plain — тот же облик, что у остального TLS
 *      движка), tls13_handshake_auth: цепочка проверяется до корней (sc_chain_verify) и имя — по
 *      SNI. ALPN — обычная пара «h2, http/1.1»: у DoH сервер выбирает HTTP/2 или HTTP/1.1
 *      (d->h2 сообщает выбор циклу), сервер DoT (RFC 7858) ALPN не требует и его не проверяет
 *      (dnsproxy — проверено стендом tests/doqup.sh).
 *   4. Сокет — обратно неблокирующий; поток пишет в wfd байт и больше структуры не касается.
 *
 * TLS в сборке может не быть (статический steerd без пакета TLS, мини-сборка): функции TLS здесь
 * слабые ссылки, и без них соединение просто не устанавливается, с причиной в err. Это не
 * отказ сборки, а отказ апстрима с пояснением в status. */

#define _GNU_SOURCE
#include "dnsd_int.h"
#include "dupint.h"
#include <poll.h>
#include <netinet/tcp.h>
#include <pthread.h>
#include "tls13.h"
#include "reality.h"
#include "dupq.h"

/* Контекст TLS соединений DoQ (корни разбираются один раз на процесс) готовит шов dupq.h — здесь,
 * в потоке установки: разбор файла корней блокирует, а цикл резолвера — нет. Корни те же, что у DoT:
 * --ca-file стенда, иначе хранилище движка (tls_cert_roots), иначе умолчание обёртки. Слабая ссылка:
 * без обёртки QUIC в сборке DoQ отказывает в dup.c, а не здесь. */
extern int dupq_prepare(const char *roots) __attribute__((weak));
extern const char *tls_cert_roots(void) __attribute__((weak));

extern int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *client_hello,
                                size_t hello_n, const unsigned char *shared_secret,
                                const struct tls13_auth *auth) __attribute__((weak));
extern int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                                     const struct reality_carrier *car, unsigned char *out, size_t out_n,
                                     size_t *out_len) __attribute__((weak));
extern void tls13_free(struct tls13 *t) __attribute__((weak));
extern int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) __attribute__((weak));
extern const char *tls_cert_roots(void) __attribute__((weak));
extern const char *tls13_verify_reason(void) __attribute__((weak));

int dup_have_tls(void) {
    return tls13_handshake_auth && reality_build_hello_carry && tls13_free && tls13_write;
}

const char *g_dup_ca_file;

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int sa_len(const struct sockaddr_storage *a) {
    return a->ss_family == AF_INET6 ? (int)sizeof(struct sockaddr_in6) : (int)sizeof(struct sockaddr_in);
}

/* Адрес строкой -> sockaddr. */
static int sa_from(const char *s, unsigned short port, struct sockaddr_storage *a) {
    memset(a, 0, sizeof(*a));
    struct sockaddr_in *v4 = (struct sockaddr_in *)a;
    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)a;
    if (inet_pton(AF_INET, s, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port = htons(port);
        return 0;
    }
    if (inet_pton(AF_INET6, s, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port = htons(port);
        return 0;
    }
    return -1;
}

/* ---- bootstrap ------------------------------------------------------------------------------ */

static size_t put_qname(uint8_t *b, size_t cap, const char *host) {
    size_t o = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t l = dot ? (size_t)(dot - p) : strlen(p);
        if (!l || l > 63 || o + l + 2 > cap) return 0;
        b[o++] = (uint8_t)l;
        memcpy(b + o, p, l);
        o += l;
        p += l + (dot ? 1 : 0);
        if (dot && !*p) break;
    }
    if (o + 1 > cap) return 0;
    b[o++] = 0;
    return o;
}

/* Один вопрос одному серверу bootstrap. Возвращает число найденных адресов A (или AAAA при
 * qtype 28), -1 — сервер не ответил или ответил не то. */
static int boot_ask(const struct sockaddr_storage *srv, unsigned mark, const char *host, int qtype,
                    long deadline, struct sockaddr_storage *out, size_t max, long *ttl) {
    uint8_t q[300], r[1500];
    uint16_t id = 0;
    if (getrandom(&id, sizeof(id), 0) != (ssize_t)sizeof(id)) id = (uint16_t)(rand() ^ time(NULL));
    memset(q, 0, 12);
    q[0] = (uint8_t)(id >> 8); q[1] = (uint8_t)id;
    q[2] = 0x01;                                   /* RD */
    q[5] = 1;                                      /* один вопрос */
    size_t nl = put_qname(q + 12, sizeof(q) - 17, host);
    if (!nl) return -1;
    size_t qn = 12 + nl;
    q[qn++] = (uint8_t)(qtype >> 8); q[qn++] = (uint8_t)qtype;
    q[qn++] = 0; q[qn++] = 1;
    int fd = socket(srv->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) { close(fd); return -1; }
    int found = -1;
    if (connect(fd, (const struct sockaddr *)srv, (socklen_t)sa_len(srv)) == 0 &&
        send(fd, q, qn, MSG_NOSIGNAL) == (ssize_t)qn) {
        for (;;) {
            long left = deadline - mono_ms();
            if (left <= 0) break;
            struct pollfd p = { fd, POLLIN, 0 };
            int pr = poll(&p, 1, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) break;
            ssize_t n = recv(fd, r, sizeof(r), 0);
            if (n < 12 || r[0] != q[0] || r[1] != q[1] || !(r[2] & 0x80)) continue;
            if ((r[3] & 0x0F) != 0) break;
            char qn_[MAX_HOSTNAME];
            uint16_t qt = 0;
            size_t qend = 0;
            struct answer_ip ips[8];
            struct answer_ip6 ips6[8];
            int n6 = 0;
            int na = parse_response(r, (size_t)n, qn_, sizeof(qn_), &qt, &qend, ips, 8, ips6, 8, &n6);
            if (na < 0) break;
            size_t k = 0;
            if (qtype == 1)
                for (int i = 0; i < na && k < max; i++, k++) {
                    struct sockaddr_in *a = (struct sockaddr_in *)&out[k];
                    memset(&out[k], 0, sizeof(out[k]));
                    a->sin_family = AF_INET;
                    a->sin_addr.s_addr = ips[i].addr;
                    if (!*ttl || (long)ips[i].ttl < *ttl) *ttl = (long)ips[i].ttl;
                }
            else
                for (int i = 0; i < n6 && k < max; i++, k++) {
                    struct sockaddr_in6 *a = (struct sockaddr_in6 *)&out[k];
                    memset(&out[k], 0, sizeof(out[k]));
                    a->sin6_family = AF_INET6;
                    memcpy(&a->sin6_addr, ips6[i].addr, 16);
                    if (!*ttl || (long)ips6[i].ttl < *ttl) *ttl = (long)ips6[i].ttl;
                }
            found = (int)k;
            break;
        }
    }
    close(fd);
    return found;
}

int dup_bootstrap(const char *host, const char (*boot)[46], size_t boot_n, unsigned mark,
                  int timeout_ms, struct sockaddr_storage *out, size_t max, long *ttl) {
    long end = mono_ms() + timeout_ms;
    *ttl = 0;
    for (size_t i = 0; i < boot_n; i++) {
        struct sockaddr_storage srv;
        if (sa_from(boot[i], 53, &srv) != 0) continue;
        /* Серверу — не больше доли срока, чтобы первый молчащий не съел остальных. */
        long slice = (end - mono_ms()) / (long)(boot_n - i);
        if (slice > 2000) slice = 2000;
        if (slice <= 0) break;
        for (int qt = 1; qt <= 28; qt += 27) {           /* A, потом AAAA — только если A пуст */
            int n = boot_ask(&srv, mark, host, qt, mono_ms() + slice, out, max, ttl);
            if (n > 0) return n;
            if (n < 0) break;                             /* не ответил — следующий сервер */
        }
    }
    return -1;
}

/* ---- соединение и рукопожатие ---------------------------------------------------------------- */

static int connect_to(const struct sockaddr_storage *a, unsigned mark, long deadline) {
    int fd = socket(a->ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    if (mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0) goto fail;
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (const struct sockaddr *)a, (socklen_t)sa_len(a)) != 0) {
        if (errno != EINPROGRESS) goto fail;
        struct pollfd p = { fd, POLLOUT, 0 };
        for (;;) {
            long left = deadline - mono_ms();
            if (left <= 0) goto fail;
            int pr = poll(&p, 1, (int)left);
            if (pr < 0 && errno == EINTR) continue;
            if (pr <= 0) goto fail;
            break;
        }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) goto fail;
    }
    return fd;
fail:
    close(fd);
    return -1;
}

static void set_timeo(int fd, long deadline) {
    long left = deadline - mono_ms();
    if (left < 1) left = 1;
    struct timeval tv = { left / 1000, (left % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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

/* ---- ClientHello в две записи ------------------------------------------------------------------- */

/* Имя SNI в Hello: смещение первого байта имени и его длина; 0 — нет. Разбор по длинам, с проверкой
 * границ на каждом шаге: Hello строит наш же код, но функция берёт любые байты. */
static size_t hello_sni(const unsigned char *h, size_t n, size_t *len) {
    if (n < 5 + 4 + 2 + 32 + 1 || h[0] != 0x16 || h[5] != 0x01) return 0;
    size_t o = 5 + 4 + 2 + 32;
    if (o + 1 > n) return 0;
    o += 1 + h[o];                                      /* session_id */
    if (o + 2 > n) return 0;
    o += 2 + (((size_t)h[o] << 8) | h[o + 1]);          /* cipher_suites */
    if (o + 1 > n) return 0;
    o += 1 + h[o];                                      /* compression */
    if (o + 2 > n) return 0;
    size_t ext_end = o + 2 + (((size_t)h[o] << 8) | h[o + 1]);
    o += 2;
    if (ext_end > n) ext_end = n;
    while (o + 4 <= ext_end) {
        size_t type = ((size_t)h[o] << 8) | h[o + 1], l = ((size_t)h[o + 2] << 8) | h[o + 3];
        o += 4;
        if (o + l > ext_end) return 0;
        if (type == 0) {                                /* server_name: список 2, тип 1, длина 2, имя */
            if (l < 5 || h[o + 2] != 0) return 0;
            size_t nl = ((size_t)h[o + 3] << 8) | h[o + 4];
            if (5 + nl > l) return 0;
            *len = nl;
            return o + 5;
        }
        o += l;
    }
    return 0;
}

size_t dup_hello_split(const unsigned char *h, size_t n, unsigned rnd) {
    if (n < 5 + 4 || h[0] != 0x16) return 0;
    size_t nl = 0, at = hello_sni(h, n, &nl);
    if (at && nl >= 2) return at + 1 + rnd % (nl - 1);          /* внутри имени: обе части непусты */
    if (n < 5 + 80 + 1) return 0;
    return 5 + 30 + rnd % 51;                                   /* 30..80 байт сообщения */
}

int dup_hello_send(int fd, const unsigned char *h, size_t n, int frag) {
    unsigned rnd = 0;
    if (frag && getrandom(&rnd, sizeof(rnd), 0) != (ssize_t)sizeof(rnd)) rnd = (unsigned)(rand() ^ time(NULL));
    size_t at = frag ? dup_hello_split(h, n, rnd) : 0;
    if (!at || at <= 5 || at >= n) return write_all(fd, h, n);
    /* Запись как есть режется на две: заголовок (тип, версия) тот же, длина своя. */
    unsigned char rec[5 + 2048];
    if (n > sizeof(rec)) return write_all(fd, h, n);
    size_t p1 = at - 5, p2 = n - at;
    memcpy(rec, h, 3);
    rec[3] = (unsigned char)(p1 >> 8); rec[4] = (unsigned char)p1;
    memcpy(rec + 5, h + 5, p1);
    if (write_all(fd, rec, 5 + p1) != 0) return -1;
    struct timespec ts = { 0, 2 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    memcpy(rec, h, 3);
    rec[3] = (unsigned char)(p2 >> 8); rec[4] = (unsigned char)p2;
    memcpy(rec + 5, h + at, p2);
    return write_all(fd, rec, 5 + p2);
}

static void dial_run(struct dial *d) {
    long deadline = mono_ms() + d->timeout_ms;
    d->rc = -1;
    d->fd = -1;
    d->tls = NULL;
    if (!d->quic && !dup_have_tls()) {
        snprintf(d->err, sizeof(d->err), "в этой сборке нет TLS: DoT и DoH недоступны");
        return;
    }
    /* 1. Адреса. */
    struct sockaddr_storage list[DIAL_MAXADDR];
    int ln = 0, from_res = 0;
    struct sockaddr_storage lit;
    if (sa_from(d->u.host, d->u.port, &lit) == 0) {
        list[ln++] = lit;
    } else if (d->u.ips_n) {
        for (size_t i = 0; i < d->u.ips_n && ln < DIAL_MAXADDR; i++)
            if (sa_from(d->u.ips[i], d->u.port, &list[ln]) == 0) ln++;
    } else {
        if (d->cached_n && d->cached_fresh) {
            for (int i = 0; i < d->cached_n; i++) list[ln++] = d->cached[i];
        } else {
            long ttl = 0;
            struct sockaddr_storage found[DIAL_MAXADDR];
            int n = dup_bootstrap(d->u.host, d->u.boot, d->u.boot_n, d->mark,
                                  d->timeout_ms > 6000 ? 6000 : d->timeout_ms, found, DIAL_MAXADDR, &ttl);
            if (n > 0) {
                for (int i = 0; i < n; i++) {
                    struct sockaddr_storage a = found[i];
                    if (a.ss_family == AF_INET) ((struct sockaddr_in *)&a)->sin_port = htons(d->u.port);
                    else ((struct sockaddr_in6 *)&a)->sin6_port = htons(d->u.port);
                    d->res[d->res_n++] = a;
                    list[ln++] = a;
                }
                d->res_ttl = ttl < 60 ? 60 : ttl > 3600 ? 3600 : ttl;
                from_res = 1;
            } else if (d->cached_n) {
                for (int i = 0; i < d->cached_n; i++) list[ln++] = d->cached[i];      /* устаревшие */
            } else {
                snprintf(d->err, sizeof(d->err), "bootstrap не разрешил имя %.60s", d->u.host);
                return;
            }
        }
    }
    if (!ln) {
        snprintf(d->err, sizeof(d->err), "нет адреса сервера %.60s", d->u.host);
        return;
    }
    /* DoQ: дальше — не блокирующее. qc_open только создаёт сокет UDP и шлёт первый пакет, а
     * рукопожатие QUIC идёт в цикле резолвера событиями (qc_on_readable, qc_on_timer), поэтому
     * потоку остаётся отдать адреса — то единственное блокирующее (bootstrap), что у DoQ есть. */
    if (d->quic) {
        if (dupq_prepare)                              /* корни разобрать здесь, а не в цикле */
            dupq_prepare(g_dup_ca_file ? g_dup_ca_file : (tls_cert_roots ? tls_cert_roots() : NULL));
        for (int i = 0; i < ln; i++) d->addr[d->addr_n++] = list[i];
        d->rc = 0;
        return;
    }
    /* 2. connect. */
    int fd = -1, at = -1;
    for (int i = 0; i < ln && fd < 0; i++) {
        long left = deadline - mono_ms();
        if (left <= 0) break;
        /* Каждому адресу — доля срока: первый молчащий не должен съедать рукопожатие остальных. */
        long slice = left / (ln - i);
        if (slice < 500 && left > 500) slice = 500;
        fd = connect_to(&list[i], d->mark, mono_ms() + slice);
        if (fd >= 0) at = i;
    }
    if (fd < 0) {
        snprintf(d->err, sizeof(d->err), "нет соединения с %.60s:%u", d->u.host, d->u.port);
        return;
    }
    d->peer_i = at;
    d->peer_from_res = from_res;
    /* 3. TLS. */
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    set_timeo(fd, deadline);
    /* ALPN — обычная пара «h2, http/1.1», как у остального TLS движка и у DoT. Выбор за сервером: h2
     * ведёт мультиплексный клиент в dup.c (doh2.c), http/1.1 — прежний разбор. Так надо потому, что
     * RFC 8484 требует от сервера DoH поддержки HTTP/2, а HTTP/1.1 — нет: Quad9 на HTTP/1.1 отвечает
     * 505. Раньше DoH предлагал ТОЛЬКО http/1.1 (носитель alpn_http11) и отказывал серверу, выбравшему
     * h2; работали лишь серверы, знающие один HTTP/1.1.
     *
     * Расширение ALPS из Hello DoH убрано (no_alps): dns.google, выбрав h2, принимал его и ждал от
     * клиента блок настроек приложения, которого у нас нет, — и рвал рукопожатие оповещением
     * unexpected_message до первого кадра (подробнее в reality.h). У DoT сервер h2 не выбирает,
     * поэтому его Hello остаётся байт в байт прежним. */
    struct reality_cfg cfg = { .sni = d->u.host, .alpn = NULL, .plain = 1 };
    struct reality_carrier car = { .no_alps = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    if (reality_build_hello_carry(&cfg, &rst, d->doh ? &car : NULL, hello, sizeof(hello), &hello_n) != 0 ||
        dup_hello_send(fd, hello, hello_n, d->u.frag) != 0) {
        snprintf(d->err, sizeof(d->err), "ClientHello не ушёл");
        close(fd);
        return;
    }
    struct tls13 *t = calloc(1, sizeof(*t));
    if (!t) { close(fd); snprintf(d->err, sizeof(d->err), "нет памяти"); return; }
    const char *roots = d->ca[0] ? d->ca : (tls_cert_roots ? tls_cert_roots() : NULL);
    struct tls13_auth auth = { .host = d->u.host, .roots = roots };
    int rc = tls13_handshake_auth(t, fd, hello, hello_n, rst.priv, &auth);
    if (rc != 0) {
        const char *why = tls13_verify_reason ? tls13_verify_reason() : NULL;
        snprintf(d->err, sizeof(d->err), "рукопожатие TLS с %.50s не удалось (%d%s%.30s)", d->u.host, rc,
                 why && *why ? ": " : "", why && *why ? why : "");
        tls13_free(t);
        free(t);
        close(fd);
        return;
    }
    d->h2 = d->doh && strcmp(t->alpn, "h2") == 0;
    if (d->doh && t->alpn[0] && !d->h2 && strcmp(t->alpn, "http/1.1") != 0) {
        snprintf(d->err, sizeof(d->err), "сервер выбрал протокол %.20s вместо h2 или http/1.1", t->alpn);
        tls13_free(t);
        free(t);
        close(fd);
        return;
    }
    /* 4. Обратно в неблокирующий режим: дальше сокетом владеет цикл. */
    struct timeval tv = { 0, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    d->fd = fd;
    d->tls = t;
    d->rc = 0;
}

static void *dial_thread(void *arg) {
    struct dial *d = arg;
    dial_run(d);
    int wfd = d->wfd;                 /* после записи байта структура принадлежит циклу */
    char b = 1;
    while (send(wfd, &b, 1, MSG_NOSIGNAL) < 0 && errno == EINTR) {}
    close(wfd);
    return NULL;
}

int dial_launch(struct dial *d) {
    pthread_attr_t at;
    int attr_ok = pthread_attr_init(&at) == 0;
    if (attr_ok) {
        pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
        pthread_attr_setstacksize(&at, 256 * 1024);
    }
    pthread_t th;
    int rc = pthread_create(&th, attr_ok ? &at : NULL, dial_thread, d);
    if (attr_ok) pthread_attr_destroy(&at);
    if (rc != 0) {
        d->rc = -1;
        snprintf(d->err, sizeof(d->err), "поток установки соединения не запустился");
        return -1;
    }
    return 0;
}
