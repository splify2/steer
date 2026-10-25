/* HTTP/1.1-клиент libsteer (httpc.h).
 *
 * ЗАЧЕМ ОН ЗДЕСЬ. Подписки качал внешний curl/wget (subfetch.c запускал его execvp'ом), замер HTTPS в
 * urltls.c и регистрация WARP в wbhttps.c ходили каждый своим куском кода, а менеджеру плагинов нужны
 * ещё и потоковая запись пакета в файл без предела размера, If-None-Match и переадресации. Четвёртая
 * копия «соединиться, рукопожатие, GET» не нужна: клиент один, а то, что качается (подписка, пакет,
 * каталог), ему безразлично. TLS — тот же, что у узлов и замеров: ClientHello сборщика Reality без
 * Reality (plain, ALPN только http/1.1 — иначе Cloudflare выберет h2 и пришлёт кадры вместо ответа),
 * рукопожатие tls13_handshake_auth с проверкой цепочки до корней tls_cert_roots.
 *
 * УСТРОЙСТВО. Блокирующий, со сроками: свой процесс (модуль или steer-tools) ждёт спокойно; демону
 * его звать из цикла нельзя — рабочим потоком, как urltls.c. Одно соединение — один запрос
 * (Connection: close): keep-alive выигрывает на десятках запросов подряд, а клиент делает один-два
 * на вызов; зато конец ответа без Content-Length — закрытие, и разбор остаётся без хитростей.
 *
 * ТЕЛО — ПОТОКОМ. Из сокета порцией (64 КиБ у TCP, запись у TLS), оттуда сразу в файл и/или колбэк:
 * ни целиком, ни по частям в памяти оно не копится, поэтому размера у скачиваемого нет. Chunked
 * разбирается побайтно конечным автоматом поверх порций (размер куска хоть 64-битный, расширения и
 * трейлеры пропускаются). Обрыв ловится: Content-Length — по счёту, chunked — по отсутствию
 * нулевого куска; закрытие без длины — конец, но для TLS только close_notify (обрыв TCP — ETRUNC).
 *
 * ЧТО НЕ СДЕЛАНО: keep-alive, POST, Range, сжатие (Accept-Encoding не посылается — тело как есть),
 * прокси, куки по правилам RFC 6265 (хватает того, что нужно панелям подписок: имя=значение на
 * тот же хост на время вызова — без Domain, Path и срока). Cookie-проверка перед панелью подписки
 * отвечает 302 на тот же адрес с Set-Cookie; без возврата cookie клиент ходил бы по кругу (subfetch.c). */
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
#include "wipe.h"
#include "tls13.h"
#include "roots.h"
#include "httpc.h"
#include "sockmark.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

#define WHY(...) do { if (why && wn) snprintf(why, wn, __VA_ARGS__); } while (0)

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* ---- ссылка ------------------------------------------------------------------------------------ */

struct url {
    int tls;
    char *host;                     /* без скобок у IPv6 */
    unsigned port;
    char *target;                   /* путь и запрос, начинается с '/' */
};

static void url_free(struct url *u) {
    free(u->host);
    free(u->target);
    memset(u, 0, sizeof *u);
}

static int ci_prefix(const char *s, const char *p) {
    return strncasecmp(s, p, strlen(p)) == 0;
}

/* 0 — разобрано; HTTPC_EURL / HTTPC_ENOMEM. Фрагмент отбрасывается. */
static int url_parse(const char *s, struct url *u) {
    memset(u, 0, sizeof *u);
    if (ci_prefix(s, "https://")) { u->tls = 1; s += 8; }
    else if (ci_prefix(s, "http://")) { s += 7; }
    else return HTTPC_EURL;
    size_t al = strcspn(s, "/?#");
    const char *a = s, *rest = s + al;
    for (size_t i = 0; i < al; i++)
        if (a[i] == '@' || (unsigned char)a[i] <= ' ') return HTTPC_EURL;
    const char *hs, *he;
    if (al && a[0] == '[') {
        const char *rb = memchr(a, ']', al);
        if (!rb) return HTTPC_EURL;
        hs = a + 1;
        he = rb;
        a = rb + 1;
        al -= (size_t)(a - s);
    } else {
        hs = a;
        const char *colon = memchr(a, ':', al);
        he = colon ? colon : a + al;
        a = he;
        al -= (size_t)(he - s);
    }
    if (he == hs) return HTTPC_EURL;
    unsigned port = u->tls ? 443 : 80;
    if (al) {
        if (a[0] != ':' || al < 2) return HTTPC_EURL;
        unsigned long p = 0;
        for (size_t i = 1; i < al; i++) {
            if (a[i] < '0' || a[i] > '9') return HTTPC_EURL;
            p = p * 10 + (unsigned long)(a[i] - '0');
            if (p > 65535) return HTTPC_EURL;
        }
        if (!p) return HTTPC_EURL;
        port = (unsigned)p;
    }
    u->port = port;
    u->host = strndup(hs, (size_t)(he - hs));
    size_t tl = strcspn(rest, "#");
    if (rest[0] == '/') u->target = strndup(rest, tl);
    else {                                           /* «http://host?x» или «http://host» */
        u->target = malloc(tl + 2);
        if (u->target) { u->target[0] = '/'; memcpy(u->target + 1, rest, tl); u->target[tl + 1] = 0; }
    }
    if (!u->host || !u->target) { url_free(u); return HTTPC_ENOMEM; }
    return 0;
}

/* Значение «Host»: порт — только нестандартный (RFC 9110 §7.2), IPv6 в скобках. */
static char *host_header(const struct url *u) {
    int v6 = strchr(u->host, ':') != NULL;
    size_t n = strlen(u->host) + 16;
    char *h = malloc(n);
    if (!h) return NULL;
    if (u->port == (u->tls ? 443u : 80u)) snprintf(h, n, v6 ? "[%s]" : "%s", u->host);
    else snprintf(h, n, v6 ? "[%s]:%u" : "%s:%u", u->host, u->port);
    return h;
}

/* Адрес переадресации Location относительно base. malloc, NULL — нет памяти. */
static char *resolve_loc(const struct url *base, const char *loc, size_t ll) {
    char *l = strndup(loc, ll);
    if (!l) return NULL;
    char *out = NULL;
    if (ci_prefix(l, "http://") || ci_prefix(l, "https://")) return l;
    char *hh = host_header(base);
    if (!hh) { free(l); return NULL; }
    const char *scheme = base->tls ? "https" : "http";
    size_t cap = strlen(hh) + strlen(base->target) + ll + 16;
    out = malloc(cap);
    if (out) {
        if (l[0] == '/' && l[1] == '/') snprintf(out, cap, "%s:%s", scheme, l);
        else if (l[0] == '/') snprintf(out, cap, "%s://%s%s", scheme, hh, l);
        else {
            /* Относительно каталога текущего пути (без запроса). */
            size_t pl = strcspn(base->target, "?");
            while (pl > 1 && base->target[pl - 1] != '/') pl--;
            if (l[0] == '?') pl = strcspn(base->target, "?");
            snprintf(out, cap, "%s://%s%.*s%s", scheme, hh, (int)pl, base->target, l);
        }
    }
    free(hh);
    free(l);
    return out;
}

/* ---- cookie (в памяти, на время вызова) -------------------------------------------------------- */

struct cookie { char *host, *name, *val; };
struct jar { struct cookie *v; size_t n; };

static void jar_free(struct jar *j) {
    for (size_t i = 0; i < j->n; i++) { free(j->v[i].host); free(j->v[i].name); free(j->v[i].val); }
    free(j->v);
    memset(j, 0, sizeof *j);
}

/* Set-Cookie: имя=значение; атрибуты. Max-Age<=0 удаляет. Domain и Path не читаются: cookie ходит
 * только на тот же хост. */
static void jar_set(struct jar *j, const char *host, const char *sc, size_t len) {
    char *c = strndup(sc, len);
    if (!c) return;
    char *semi = strchr(c, ';');
    char *eq = strchr(c, '=');
    if (!eq || (semi && eq > semi)) { free(c); return; }
    int del = 0;
    if (semi) {
        for (char *a = semi; a; a = strchr(a + 1, ';')) {
            const char *p = a + 1;
            while (*p == ' ') p++;
            if (ci_prefix(p, "max-age=") && atol(p + 8) <= 0) del = 1;
        }
        *semi = 0;
    }
    *eq = 0;
    char *name = c, *val = eq + 1;
    for (size_t i = 0; i < j->n; i++)
        if (!strcmp(j->v[i].host, host) && !strcmp(j->v[i].name, name)) {
            free(j->v[i].val);
            if (del) {
                free(j->v[i].host); free(j->v[i].name);
                j->v[i] = j->v[--j->n];
            } else j->v[i].val = strdup(val);
            free(c);
            return;
        }
    if (!del) {
        struct cookie *nv = realloc(j->v, (j->n + 1) * sizeof *nv);
        if (nv) {
            j->v = nv;
            j->v[j->n].host = strdup(host);
            j->v[j->n].name = strdup(name);
            j->v[j->n].val = strdup(val);
            if (j->v[j->n].host && j->v[j->n].name && j->v[j->n].val) j->n++;
        }
    }
    free(c);
}

/* ---- строка запроса --------------------------------------------------------------------------- */

struct sb { char *p; size_t n, cap; int oom; };

static void sb_add(struct sb *b, const char *s, size_t n) {
    if (b->oom) return;
    if (b->n + n + 1 > b->cap) {
        size_t nc = (b->n + n + 1) * 2;
        char *np = realloc(b->p, nc);
        if (!np) { b->oom = 1; return; }
        b->p = np;
        b->cap = nc;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = 0;
}
static void sb_str(struct sb *b, const char *s) { sb_add(b, s, strlen(s)); }

/* Есть ли в «Имя: значение\r\n…» поле name. */
static int has_field(const char *h, const char *name) {
    size_t nl = strlen(name);
    for (const char *p = h; p && *p; ) {
        if (strncasecmp(p, name, nl) == 0 && p[nl] == ':') return 1;
        p = strchr(p, '\n');
        if (p) p++;
    }
    return 0;
}

/* ---- разбор ответа ----------------------------------------------------------------------------- */

/* Значение поля в тексте заголовков (строки через '\n'): указатель и длина, пробелы по краям срезаны. */
static const char *field_find(const char *h, size_t hn, const char *name, size_t *vn, const char **next) {
    size_t nl = strlen(name);
    const char *p = h, *end = h + hn;
    /* Первая строка — статус, поля после неё. */
    const char *nlp = memchr(p, '\n', (size_t)(end - p));
    p = nlp ? nlp + 1 : end;
    if (next && *next) p = *next;
    while (p < end) {
        const char *e = memchr(p, '\n', (size_t)(end - p));
        size_t ll = e ? (size_t)(e - p) : (size_t)(end - p);
        if (ll > nl && strncasecmp(p, name, nl) == 0 && p[nl] == ':') {
            const char *v = p + nl + 1, *ve = p + ll;
            while (v < ve && (*v == ' ' || *v == '\t')) v++;
            while (ve > v && (ve[-1] == ' ' || ve[-1] == '\t')) ve--;
            *vn = (size_t)(ve - v);
            if (next) *next = e ? e + 1 : end;
            return v;
        }
        p = e ? e + 1 : end;
    }
    return NULL;
}

const char *http_resp_header(const struct http_resp *r, const char *name, size_t *n) {
    size_t d;
    if (!n) n = &d;
    if (!r->headers) return NULL;
    return field_find(r->headers, r->headers_n, name, n, NULL);
}

void http_resp_free(struct http_resp *r) {
    free(r->headers);
    free(r->url);
    free(r->etag);
    memset(r, 0, sizeof *r);
}

/* ---- соединение -------------------------------------------------------------------------------- */

struct conn {
    int fd;
    struct tls13 *t;                /* NULL — открытый TCP */
    unsigned char buf[65536];       /* чтение TCP */
};

struct ctx {
    const struct http_req *q;
    struct http_resp *r;
    char *why;
    size_t wn;
    long end_ms;                    /* общий срок (mono_ms), 0 — нет */
    int sink_fd;
    struct jar jar;
};

/* Сколько ждать: want мс, но не дольше общего срока. 0 — срок вышел. */
static long budget(const struct ctx *c, long want) {
    if (!c->end_ms) return want;
    long left = c->end_ms - mono_ms();
    if (left <= 0) return 0;
    return left < want ? left : want;
}

static void set_timeo(int fd, long ms) {
    struct timeval tv = { ms / 1000, (ms % 1000) * 1000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
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

static void conn_close(struct conn *k) {
    if (k->t) { tls13_free(k->t); free(k->t); k->t = NULL; }
    if (k->fd >= 0) close(k->fd);
    k->fd = -1;
}

/* Одно соединение с адресом в срок wait мс. */
static int connect_one(struct ctx *c, const struct sockaddr *sa, socklen_t sl, long wait) {
    int fd = socket(sa->sa_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    char *why = c->why;
    size_t wn = c->wn;
    if (fd < 0) { WHY("socket: %s", strerror(errno)); return -1; }
    if (steer_sock_mark(fd, c->q->mark) != 0) { WHY("метка сокета: %s", strerror(errno)); close(fd); return -1; }
    if (c->q->dev && c->q->dev[0] &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, c->q->dev, (socklen_t)strlen(c->q->dev) + 1) != 0) {
        WHY("привязка к %s: %s", c->q->dev, strerror(errno));
        close(fd);
        return -1;
    }
    if (connect(fd, sa, sl) != 0) {
        if (errno != EINPROGRESS) { WHY("соединение: %s", strerror(errno)); close(fd); return -1; }
        struct pollfd p = { fd, POLLOUT, 0 };
        int pr;
        long t0 = mono_ms();
        do {
            long left = wait - (mono_ms() - t0);
            pr = left > 0 ? poll(&p, 1, (int)left) : 0;
        } while (pr < 0 && errno == EINTR);
        int err = 0;
        socklen_t el = sizeof err;
        if (pr <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            WHY("соединение: %s", pr <= 0 ? "срок вышел" : strerror(err ? err : errno));
            close(fd);
            return pr <= 0 ? -2 : -1;
        }
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    return fd;
}

static int conn_open(struct ctx *c, const struct url *u, struct conn *k) {
    char *why = c->why;
    size_t wn = c->wn;
    k->fd = -1;
    k->t = NULL;
    int cms = c->q->connect_ms > 0 ? c->q->connect_ms : 10000;
    char port[12];
    snprintf(port, sizeof port, "%u", u->port);
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_STREAM }, *res = NULL;
    int gr = getaddrinfo(u->host, port, &hints, &res);
    if (gr != 0 || !res) { WHY("имя %s не разрешилось: %s", u->host, gr ? gai_strerror(gr) : "нет адресов"); return HTTPC_ERESOLVE; }
    int fd = -1, timed = 0;
    /* Сначала IPv4: у роутера без глобального IPv6 попытка по AAAA отваливается сразу, но в сети со
     * «сломанным» IPv6 она ждала бы весь срок. */
    for (int fam = 0; fam < 2 && fd < 0; fam++)
        for (struct addrinfo *a = res; a && fd < 0; a = a->ai_next)
            if ((fam == 0) == (a->ai_family == AF_INET)) {
                long b = budget(c, cms);
                if (!b) { WHY("общий срок вышел до соединения"); freeaddrinfo(res); return HTTPC_ETIMEOUT; }
                fd = connect_one(c, a->ai_addr, a->ai_addrlen, b);
                if (fd == -2) { timed = 1; fd = -1; }
            }
    freeaddrinfo(res);
    if (fd < 0) return timed ? HTTPC_ETIMEOUT : HTTPC_ECONNECT;
    k->fd = fd;
    if (!u->tls) return 0;

    long b = budget(c, cms);
    if (!b) { WHY("общий срок вышел до рукопожатия"); conn_close(k); return HTTPC_ETIMEOUT; }
    set_timeo(fd, b);
    /* Только http/1.1 в ALPN (alpn_http11): с парой «h2, http/1.1», как у браузера, Cloudflare и Google
     * выбирают h2 и присылают кадры HTTP/2 вместо ответа. */
    struct reality_cfg cfg = { .sni = u->host, .alpn = "http/1.1", .plain = 1 };
    struct reality_carrier car = { .alpn_http11 = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    if (reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof hello, &hello_n) != 0) {
        WHY("ClientHello не собрался");
        conn_close(k);
        return HTTPC_ETLS;
    }
    if (write_all(fd, hello, hello_n) != 0) { WHY("ClientHello не отправился: %s", strerror(errno)); steer_wipe(&rst, sizeof rst); conn_close(k); return HTTPC_EIO; }
    k->t = calloc(1, sizeof *k->t);
    if (!k->t) { steer_wipe(&rst, sizeof rst); WHY("нет памяти"); conn_close(k); return HTTPC_ENOMEM; }
    struct tls13_auth auth = { .host = u->host, .roots = c->q->roots ? c->q->roots : tls_cert_roots() };
    int hrc = tls13_handshake_auth(k->t, fd, hello, hello_n, rst.priv, &auth);
    /* Эфемерный ключ нужен только до конца рукопожатия: дальше его держит лишь стек. */
    steer_wipe(&rst, sizeof rst);
    if (hrc != 0) {
        const char *vr = hrc == TLS13_ECERT ? tls13_verify_reason() : NULL;
        if (vr && vr[0]) WHY("сертификат %s не принят: %s", u->host, vr);
        else if (hrc == TLS13_ETIMEOUT) WHY("рукопожатие TLS с %s не уложилось в срок", u->host);
        else WHY("рукопожатие TLS с %s не удалось (код %d)", u->host, hrc);
        int rc = hrc == TLS13_ETIMEOUT ? HTTPC_ETIMEOUT : HTTPC_ETLS;
        conn_close(k);
        return rc;
    }
    if (k->t->alpn[0] && strcmp(k->t->alpn, "http/1.1") != 0) {
        WHY("сервер выбрал ALPN %.20s, а нужен http/1.1", k->t->alpn);
        conn_close(k);
        return HTTPC_ETLS;
    }
    return 0;
}

/* Порция входа. 0 — данные в *p, *n (у TLS n бывает 0: пустая запись); 1 — закрытие; HTTPC_ETIMEOUT,
 * HTTPC_EIO. wait — мс до срока молчания. */
static int conn_recv(struct conn *k, long wait, const unsigned char **p, size_t *n) {
    set_timeo(k->fd, wait);
    if (k->t) {
        int rc = tls13_read_ref(k->t, p, n);
        if (rc == 0) return 0;
        if (rc == TLS13_ECLOSED) return 1;
        return rc == TLS13_ETIMEOUT ? HTTPC_ETIMEOUT : HTTPC_EIO;
    }
    ssize_t r = recv(k->fd, k->buf, sizeof k->buf, 0);
    if (r == 0) return 1;
    if (r < 0) {
        if (errno == EINTR) { *p = k->buf; *n = 0; return 0; }
        return (errno == EAGAIN || errno == EWOULDBLOCK) ? HTTPC_ETIMEOUT : HTTPC_EIO;
    }
    *p = k->buf;
    *n = (size_t)r;
    return 0;
}

/* ---- тело ---------------------------------------------------------------------------------------- */

enum { B_NONE, B_LEN, B_CHUNKED, B_CLOSE };
enum { CK_SIZE, CK_EXT, CK_LF, CK_DATA, CK_DATA_CR, CK_DATA_LF, CK_TRAILER, CK_TRAILER_LF, CK_END };

struct body {
    int mode;
    unsigned long long left;        /* B_LEN: сколько ещё; CK_DATA: сколько осталось в куске */
    int ck;
    unsigned long long size;        /* размер текущего куска при разборе */
    int digits;
    int line_empty;                 /* в трейлере: строка пока пустая */
    int done;
};

static int sink_write(struct ctx *c, const unsigned char *d, size_t n) {
    if (c->sink_fd >= 0)
        for (size_t o = 0; o < n;) {
            ssize_t w = write(c->sink_fd, d + o, n - o);
            if (w < 0 && errno == EINTR) continue;
            if (w <= 0) {
                if (c->why && c->wn) snprintf(c->why, c->wn, "запись в %s: %s", c->q->dest_path, strerror(errno));
                return HTTPC_ESINK;
            }
            o += (size_t)w;
        }
    if (c->q->body_cb && c->q->body_cb(c->q->cb_arg, d, n) != 0) {
        if (c->why && c->wn) snprintf(c->why, c->wn, "приёмник тела прервал загрузку");
        return HTTPC_ESINK;
    }
    c->r->body_n += n;
    return 0;
}

static int hexv(int ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

/* Подать порцию входа. 0 — разобрано (b->done — тело кончилось); отрицательное — код. */
static int body_push(struct ctx *c, struct body *b, const unsigned char *p, size_t n) {
    if (b->mode == B_CLOSE) return n ? sink_write(c, p, n) : 0;
    if (b->mode == B_LEN) {
        size_t take = n < b->left ? n : (size_t)b->left;
        int rc = take ? sink_write(c, p, take) : 0;
        b->left -= take;
        if (!b->left) b->done = 1;
        return rc;
    }
    /* chunked */
    size_t i = 0;
    while (i < n && !b->done) {
        int ch = p[i];
        switch (b->ck) {
        case CK_SIZE: {
            int v = hexv(ch);
            if (v >= 0) {
                if (b->size >> 60) { if (c->why && c->wn) snprintf(c->why, c->wn, "размер куска не влезает в 64 бита"); return HTTPC_EPROTO; }
                b->size = b->size << 4 | (unsigned)v;
                b->digits++;
                i++;
            } else if (ch == ';' || ch == ' ' || ch == '\t' || ch == '\r') {
                if (!b->digits) return HTTPC_EPROTO;
                b->ck = CK_EXT;
            } else if (ch == '\n') {
                if (!b->digits) return HTTPC_EPROTO;
                b->ck = CK_LF;
            } else return HTTPC_EPROTO;
            break;
        }
        case CK_EXT:                                    /* расширение куска: до конца строки */
            i++;
            if (ch == '\n') b->ck = CK_LF;
            break;
        case CK_LF:
            if (b->size == 0) { b->ck = CK_TRAILER; b->line_empty = 1; }
            else { b->left = b->size; b->ck = CK_DATA; }
            break;
        case CK_DATA: {
            size_t take = n - i < b->left ? n - i : (size_t)b->left;
            int rc = sink_write(c, p + i, take);
            if (rc) return rc;
            i += take;
            b->left -= take;
            if (!b->left) b->ck = CK_DATA_CR;
            break;
        }
        case CK_DATA_CR:
            i++;
            if (ch == '\r') b->ck = CK_DATA_LF;
            else if (ch == '\n') { b->ck = CK_SIZE; b->size = 0; b->digits = 0; }
            else return HTTPC_EPROTO;
            break;
        case CK_DATA_LF:
            i++;
            if (ch != '\n') return HTTPC_EPROTO;
            b->ck = CK_SIZE;
            b->size = 0;
            b->digits = 0;
            break;
        case CK_TRAILER:                                /* трейлеры: строки до пустой */
            i++;
            if (ch == '\n') {
                if (b->line_empty) { b->done = 1; b->ck = CK_END; }
                else b->line_empty = 1;
            } else if (ch != '\r') b->line_empty = 0;
            break;
        default:
            i++;
        }
    }
    return 0;
}

/* Есть ли в значении v (n байт) слово tok (через запятую или пробел, без регистра). */
static int has_token(const char *v, size_t n, const char *tok) {
    size_t tl = strlen(tok);
    for (size_t i = 0; i + tl <= n; i++)
        if (strncasecmp(v + i, tok, tl) == 0 && (i == 0 || v[i - 1] == ',' || v[i - 1] == ' ') &&
            (i + tl == n || v[i + tl] == ',' || v[i + tl] == ' ' || v[i + tl] == ';'))
            return 1;
    return 0;
}

/* ---- заголовки ответа -------------------------------------------------------------------------- */

/* Конец блока заголовков в h[0..n): индекс после пустой строки, 0 — ещё нет. from — откуда искать. */
static size_t hdr_end(const char *h, size_t n, size_t from) {
    for (size_t i = from; i < n; i++)
        if (h[i] == '\n' && ((i >= 1 && h[i - 1] == '\n') || (i >= 2 && h[i - 1] == '\r' && h[i - 2] == '\n')))
            return i + 1;
    return 0;
}

/* Один заход: соединение, запрос, заголовки. На 0: *hdrs — текст заголовков без '\r' (malloc), *status,
 * лишние байты после заголовков остаются в raw после hdr_len. */
struct reply {
    char *raw;                      /* сырой ввод до конца заголовков и чуть дальше; free */
    size_t raw_n;
    size_t hdr_len;                 /* длина блока заголовков в raw */
    char *text;                     /* заголовки без '\r'; free */
    size_t text_n;
    int status;
};

static void reply_free(struct reply *y) {
    free(y->raw);
    free(y->text);
    memset(y, 0, sizeof *y);
}

static int read_head(struct ctx *c, struct conn *k, struct reply *y) {
    char *why = c->why;
    size_t wn = c->wn;
    int ims = c->q->idle_ms > 0 ? c->q->idle_ms : 30000;
    size_t cap = 0, scan = 0;
    for (;;) {
        /* 1xx — промежуточный ответ: отбрасываем и ждём настоящий. */
        size_t e = hdr_end(y->raw, y->raw_n, scan);
        if (e) {
            int st = 0;
            if (e < 12 || strncmp(y->raw, "HTTP/1.", 7) != 0 || y->raw[8] != ' ' ||
                sscanf(y->raw + 9, "%3d", &st) != 1 || st < 100 || st > 599) {
                WHY("ответ не похож на HTTP");
                return HTTPC_EPROTO;
            }
            if (st >= 100 && st < 200 && st != 101) {
                memmove(y->raw, y->raw + e, y->raw_n - e);
                y->raw_n -= e;
                scan = 0;
                continue;
            }
            if (st == 101) { WHY("сервер предлагает смену протокола (101)"); return HTTPC_EPROTO; }
            y->status = st;
            y->hdr_len = e;
            y->text = malloc(e + 1);
            if (!y->text) return HTTPC_ENOMEM;
            size_t w = 0;
            for (size_t i = 0; i < e; i++) if (y->raw[i] != '\r') y->text[w++] = y->raw[i];
            y->text[w] = 0;
            y->text_n = w;
            return 0;
        }
        scan = y->raw_n > 3 ? y->raw_n - 3 : 0;
        if (y->raw_n > HTTPC_HDR_MAX) { WHY("заголовки ответа длиннее %u байт", HTTPC_HDR_MAX); return HTTPC_EHDR; }
        long b = budget(c, ims);
        if (!b) { WHY("общий срок вышел: ответа нет"); return HTTPC_ETIMEOUT; }
        const unsigned char *p;
        size_t n;
        int rc = conn_recv(k, b, &p, &n);
        if (rc == 1) { WHY(y->raw_n ? "соединение закрыто посреди заголовков ответа" : "соединение закрыто до ответа"); return y->raw_n ? HTTPC_ETRUNC : HTTPC_EIO; }
        if (rc == HTTPC_ETIMEOUT) { WHY("срок вышел: сервер молчит (%d мс)", ims); return rc; }
        if (rc) { WHY("обрыв чтения ответа"); return rc; }
        if (y->raw_n + n + 1 > cap) {
            size_t nc = (y->raw_n + n + 1) * 2;
            char *np = realloc(y->raw, nc);
            if (!np) return HTTPC_ENOMEM;
            y->raw = np;
            cap = nc;
        }
        memcpy(y->raw + y->raw_n, p, n);
        y->raw_n += n;
    }
}

/* ---- запрос --------------------------------------------------------------------------------------- */

static int send_request(struct ctx *c, struct conn *k, const struct url *u, const char *method) {
    char *hh = host_header(u);
    if (!hh) return HTTPC_ENOMEM;
    struct sb b = {0};
    sb_str(&b, method);
    sb_str(&b, " ");
    sb_str(&b, u->target);
    sb_str(&b, " HTTP/1.1\r\nHost: ");
    sb_str(&b, hh);
    sb_str(&b, "\r\n");
    free(hh);
    const char *extra = c->q->headers;
    if (!extra || !has_field(extra, "User-Agent")) sb_str(&b, "User-Agent: steer/" STEER_VERSION "\r\n");
    if (!extra || !has_field(extra, "Accept")) sb_str(&b, "Accept: */*\r\n");
    sb_str(&b, "Connection: close\r\n");
    if (c->q->etag && *c->q->etag) {
        sb_str(&b, "If-None-Match: ");
        sb_str(&b, c->q->etag);
        sb_str(&b, "\r\n");
    }
    int first = 1;
    for (size_t i = 0; i < c->jar.n; i++)
        if (!strcmp(c->jar.v[i].host, u->host)) {
            sb_str(&b, first ? "Cookie: " : "; ");
            sb_str(&b, c->jar.v[i].name);
            sb_str(&b, "=");
            sb_str(&b, c->jar.v[i].val);
            first = 0;
        }
    if (!first) sb_str(&b, "\r\n");
    if (extra) sb_str(&b, extra);
    if (extra && *extra && (b.n < 2 || b.p[b.n - 1] != '\n')) sb_str(&b, "\r\n");
    sb_str(&b, "\r\n");
    if (b.oom) { free(b.p); return HTTPC_ENOMEM; }
    int rc = 0;
    if (k->t) {
        if (tls13_write(k->t, (const unsigned char *)b.p, b.n) != 0) rc = HTTPC_EIO;
    } else if (write_all(k->fd, (const unsigned char *)b.p, b.n) != 0) rc = HTTPC_EIO;
    free(b.p);
    if (rc && c->why && c->wn) snprintf(c->why, c->wn, "запрос не отправился");
    return rc;
}

static int is_redirect(int st) { return st == 301 || st == 302 || st == 303 || st == 307 || st == 308; }

int http_get(const struct http_req *q, struct http_resp *r, char *why, size_t wn) {
    memset(r, 0, sizeof *r);
    if (why && wn) why[0] = 0;
    const char *method = q->method && *q->method ? q->method : "GET";
    int head = !strcasecmp(method, "HEAD");
    if (!head && strcasecmp(method, "GET")) { WHY("метод %s не поддержан (только GET и HEAD)", method); return HTTPC_EURL; }
    struct ctx c = { .q = q, .r = r, .why = why, .wn = wn, .sink_fd = -1 };
    if (q->total_ms > 0) c.end_ms = mono_ms() + q->total_ms;
    int max_redir = q->max_redirects == 0 ? 10 : q->max_redirects;
    struct url u;
    int rc = url_parse(q->url ? q->url : "", &u);
    if (rc) { WHY(rc == HTTPC_ENOMEM ? "нет памяти" : "ссылка не http:// и не https:// или разобрана не до конца: %.200s", q->url ? q->url : ""); return rc; }
    int ims = q->idle_ms > 0 ? q->idle_ms : 30000;

    for (;;) {
        struct conn k;
        struct reply y = {0};
        struct body b = {0};
        rc = conn_open(&c, &u, &k);
        if (rc) goto out;
        rc = send_request(&c, &k, &u, method);
        if (!rc) rc = read_head(&c, &k, &y);
        if (rc) { conn_close(&k); reply_free(&y); goto out; }

        /* Куки этого ответа — в банку, пока нужны следующему запросу. */
        {
            const char *next = NULL;
            size_t vn;
            const char *v;
            while ((v = field_find(y.text, y.text_n, "Set-Cookie", &vn, &next)) != NULL) jar_set(&c.jar, u.host, v, vn);
        }

        if (is_redirect(y.status) && max_redir >= 0) {
            size_t ln;
            const char *loc = field_find(y.text, y.text_n, "Location", &ln, NULL);
            if (loc && ln) {
                if (r->redirects >= max_redir) {
                    WHY("больше %d переадресаций", max_redir);
                    rc = HTTPC_EREDIR;
                    conn_close(&k); reply_free(&y);
                    goto out;
                }
                char *nu = resolve_loc(&u, loc, ln);
                struct url nx;
                int pr = nu ? url_parse(nu, &nx) : HTTPC_ENOMEM;
                if (pr) {
                    WHY(pr == HTTPC_ENOMEM ? "нет памяти" : "переадресация на непонятный адрес: %.200s", nu ? nu : "");
                    free(nu);
                    rc = pr == HTTPC_ENOMEM ? pr : HTTPC_EREDIR;
                    conn_close(&k); reply_free(&y);
                    goto out;
                }
                if (u.tls && !nx.tls) {
                    WHY("переадресация с https на http отвергнута: %.200s", nu);
                    free(nu); url_free(&nx);
                    rc = HTTPC_EREDIR;
                    conn_close(&k); reply_free(&y);
                    goto out;
                }
                free(nu);
                url_free(&u);
                u = nx;
                r->redirects++;
                conn_close(&k);
                reply_free(&y);
                continue;
            }
        }

        /* Конечный ответ. */
        r->status = y.status;
        r->not_modified = y.status == 304;
        r->headers = y.text;
        r->headers_n = y.text_n;
        y.text = NULL;
        {
            size_t vn;
            const char *v = field_find(r->headers, r->headers_n, "ETag", &vn, NULL);
            if (v && vn) r->etag = strndup(v, vn);
            char *hh = host_header(&u);
            size_t ul = strlen(u.target) + (hh ? strlen(hh) : 0) + 16;
            r->url = malloc(ul);
            if (r->url && hh) snprintf(r->url, ul, "%s://%s%s", u.tls ? "https" : "http", hh, u.target);
            free(hh);
        }
        int want_body = !head && y.status / 100 == 2 && y.status != 204 && (q->dest_path || q->body_cb);
        if (!want_body) { conn_close(&k); reply_free(&y); rc = 0; goto out; }

        /* Как кончается тело. */
        size_t ten = 0, cln = 0;
        const char *te = field_find(r->headers, r->headers_n, "Transfer-Encoding", &ten, NULL);
        const char *cl = field_find(r->headers, r->headers_n, "Content-Length", &cln, NULL);
        if (te && has_token(te, ten, "chunked")) b.mode = B_CHUNKED;
        else if (cl) {
            unsigned long long len = 0;
            if (!cln) { WHY("пустой Content-Length"); rc = HTTPC_EPROTO; conn_close(&k); reply_free(&y); goto out; }
            for (size_t i = 0; i < cln; i++) {
                if (cl[i] < '0' || cl[i] > '9' || (len >> 60)) { WHY("Content-Length не число"); rc = HTTPC_EPROTO; conn_close(&k); reply_free(&y); goto out; }
                len = len * 10 + (unsigned)(cl[i] - '0');
            }
            b.mode = B_LEN;
            b.left = len;
            if (!len) b.done = 1;
        } else b.mode = B_CLOSE;
        if (b.mode == B_CHUNKED) b.ck = CK_SIZE;

        if (q->dest_path) {
            c.sink_fd = open(q->dest_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            if (c.sink_fd < 0) { WHY("файл %s: %s", q->dest_path, strerror(errno)); rc = HTTPC_ESINK; conn_close(&k); reply_free(&y); goto out; }
        }
        /* Байты тела, что пришли вместе с заголовками. */
        rc = body_push(&c, &b, (const unsigned char *)y.raw + y.hdr_len, y.raw_n - y.hdr_len);
        reply_free(&y);
        while (!rc && !b.done) {
            long w = budget(&c, ims);
            if (!w) { WHY("общий срок вышел при скачивании"); rc = HTTPC_ETIMEOUT; break; }
            const unsigned char *p;
            size_t n;
            int rr = conn_recv(&k, w, &p, &n);
            if (rr == 1) {
                if (b.mode == B_CLOSE) { b.done = 1; break; }
                WHY(b.mode == B_LEN ? "тело оборвано: пришло %llu байт, не хватает %llu" : "тело оборвано: нет завершающего куска (пришло %llu байт, %llu не учтено)",
                    r->body_n, b.mode == B_LEN ? b.left : 0ULL);
                rc = HTTPC_ETRUNC;
                break;
            }
            if (rr == HTTPC_ETIMEOUT) { WHY("срок вышел: сервер молчит (%d мс), получено %llu байт", ims, r->body_n); rc = rr; break; }
            if (rr) { WHY("обрыв чтения тела, получено %llu байт", r->body_n); rc = HTTPC_EIO; break; }
            rc = body_push(&c, &b, p, n);
        }
        if (rc == HTTPC_EPROTO && why && wn && !why[0]) WHY("тело ответа разобрать не удалось (chunked)");
        conn_close(&k);
        goto out;
    }
out:
    if (c.sink_fd >= 0) {
        if (close(c.sink_fd) != 0 && !rc) { WHY("запись в %s: %s", q->dest_path, strerror(errno)); rc = HTTPC_ESINK; }
        if (rc && q->dest_path) unlink(q->dest_path);
    }
    jar_free(&c.jar);
    url_free(&u);
    return rc;
}
