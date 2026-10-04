/* HTTPS для замера задержки члена группы (urltest, src/daemon/urltest.c) — полный пакет.
 *
 * ЗАЧЕМ ПОТОК. Рукопожатие tls13.c блокирующее по устройству: оно читает сокет со SO_RCVTIMEO и
 * ждёт записи целиком (tls13.h, TLS13_ETIMEOUT). Цикл демона ждать не вправе — на нём status,
 * apply и сторож, — а второй, неблокирующий TLS ради одного запроса раз в несколько минут значил
 * бы вторую реализацию того, что уже проверено на живых узлах. Поэтому замер HTTPS целиком идёт в
 * отсоединённом рабочем потоке — по образцу разрешения имён (src/daemon/gaiw.c): поток получает
 * копию параметров, делает соединение, рукопожатие, запрос и чтение первого байта обычными
 * блокирующими вызовами со сроком, а итог — одно число — пишет в сокет-пару, конец которой лежит
 * в epoll цикла. Отмена — закрыть свой конец: запись потока получит отказ (MSG_NOSIGNAL), поток
 * освободит своё и уйдёт сам. Процесса на замер нет.
 *
 * ЧЕМ ГОВОРИТ. ClientHello — тот же сборщик, что у узлов VLESS с security=tls (reality_build_hello
 * с plain: облик браузера живёт в одном месте), ALPN — http/1.1: запрос обычный HTTP/1.1, и
 * сервер, согласившийся на h2, ответил бы кадрами, которые здесь читать нечем. Подлинность
 * сервера проверяется по цепочке до корня (auth.host): страница плена провайдера с чужим
 * сертификатом — это не «быстрый член», а отказ. Корни — те же, что у транспорта security=tls
 * (tls_cert_roots в roots.c: на телефоне склейка системного каталога, на роутере умолчание
 * certverify).
 *
 * ВРЕМЯ — от начала соединения до первого прикладного байта ответа, по CLOCK_MONOTONIC: как у
 * HTTP в urltest.c плюс рукопожатие TLS — два оборота того же пути, что и сам запрос. Годен ответ
 * со статусом 204 или 200. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/time.h>
#include <netinet/in.h>

#include "loop.h"
#include "reality.h"
#include "tls13.h"
#include "roots.h"
#include "urltls.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

const int steer_urltls_present = 1;

/* Итог потока: время и, если не вышло, почему — строкой для журнала (urltest_why в urltest.c). */
struct urltls_res {
    int ms;
    char why[192];
};

struct urltls {
    struct loop *l;
    int fd;
    void (*cb)(void *arg, int ms, const char *why);
    void *arg;
    unsigned char got[sizeof(struct urltls_res)];
    size_t gn;
};

struct urltls_work {
    int fd;
    struct sockaddr_storage dst;
    char host[128];
    char path[160];
    uint32_t mark;
    char dev[32];
    int timeout_ms;
};

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* Остаток срока — в SO_RCVTIMEO/SO_SNDTIMEO. 0 — поставлено; -1 — срок вышел. */
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

static int status_ok(const unsigned char *b, size_t n) {
    if (n < 12 || memcmp(b, "HTTP/1.", 7) != 0 || b[8] != ' ') return 0;
    for (int i = 9; i < 12; i++)
        if (b[i] < '0' || b[i] > '9') return 0;
    int code = (b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0');
    return code == 204 || code == 200;
}

/* Длина s до конца последнего ЦЕЛОГО символа UTF-8: недобитый хвост (ведущий байт без всех
 * продолжений) отбрасывается. Причину проверки сертификата (tls13_verify_reason) обрезает буфер
 * tls13.c в 96 байт — у двух самых длинных фраз это посреди буквы (R-120, I-236), и недобитый байт
 * в журнале выглядит как «…на это и�». Буфер — защищённый путь, его правит владелец; здесь не
 * пропускаем в журнал половину буквы. */
static size_t utf8_whole(const char *s, size_t n) {
    size_t i = n;
    while (i > 0 && ((unsigned char)s[i - 1] & 0xC0) == 0x80) i--;   /* продолжения в хвосте */
    if (i == 0) return 0;
    unsigned char lead = (unsigned char)s[i - 1];
    size_t have = n - (i - 1);                                       /* байт хвостового символа */
    size_t need = lead >= 0xF0 ? 4 : lead >= 0xE0 ? 3 : lead >= 0xC0 ? 2 : 1;
    return have < need ? i - 1 : n;
}

/* Весь замер — в потоке. Итог: мс или -1; при -1 в why — почему (одна строка). */
#define WHY(...) snprintf(why, wn, __VA_ARGS__)
static int measure(const struct urltls_work *w, char *why, size_t wn) {
    long t0 = mono_ms(), deadline = t0 + w->timeout_ms;
    int v6 = w->dst.ss_family == AF_INET6;
    why[0] = '\0';
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { WHY("socket: %s", strerror(errno)); return -1; }
    if (w->mark && setsockopt(fd, SOL_SOCKET, SO_MARK, &w->mark, sizeof(w->mark)) != 0) {
        WHY("метка члена не поставилась: %s", strerror(errno));
        goto fail;
    }
    if (!w->mark && w->dev[0] &&
        setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, w->dev, (socklen_t)strlen(w->dev) + 1) != 0) {
        WHY("привязка к устройству %s: %s", w->dev, strerror(errno));
        goto fail;
    }
    socklen_t dl = v6 ? (socklen_t)sizeof(struct sockaddr_in6) : (socklen_t)sizeof(struct sockaddr_in);
    if (connect(fd, (const struct sockaddr *)&w->dst, dl) != 0) {
        if (errno != EINPROGRESS) { WHY("соединение: %s", strerror(errno)); goto fail; }
        struct pollfd p = { fd, POLLOUT, 0 };
        long left = deadline - mono_ms();
        if (left <= 0) { WHY("срок вышел до соединения"); goto fail; }
        int pr;
        do pr = poll(&p, 1, (int)left); while (pr < 0 && errno == EINTR);
        if (pr <= 0) { WHY("соединение не установилось за срок"); goto fail; }
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            WHY("соединение: %s", strerror(err ? err : errno));
            goto fail;
        }
    }
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK);
    if (set_timeo(fd, deadline)) { WHY("срок вышел до рукопожатия TLS"); goto fail; }

    struct reality_cfg cfg = { .sni = w->host, .alpn = "http/1.1", .plain = 1 };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    if (reality_build_hello(&cfg, &rst, hello, sizeof(hello), &hello_n) != 0) {
        WHY("ClientHello не собрался");
        goto fail;
    }
    if (write_all(fd, hello, hello_n) != 0) { WHY("ClientHello не отправился: %s", strerror(errno)); goto fail; }

    struct tls13 *t = calloc(1, sizeof(*t));
    if (!t) { WHY("нет памяти"); goto fail; }
    struct tls13_auth auth = { .host = w->host, .roots = tls_cert_roots() };
    int res = -1;
    int hrc = tls13_handshake_auth(t, fd, hello, hello_n, rst.priv, &auth);
    if (hrc != 0) {
        /* Сертификат не принят — самая частая причина, и она же самая непонятная снаружи: нет
         * пакета ca-bundle, часы без NTP (сертификат «ещё не действует»), страница плена или чужой
         * узел с другим сертификатом. Причину называет сама проверка (tls13_verify_reason). */
        if (hrc == TLS13_ECERT) {
            const char *vr = tls13_verify_reason();
            if (vr && vr[0]) WHY("сертификат не принят: %.*s", (int)utf8_whole(vr, strlen(vr)), vr);
            else WHY("сертификат не принят: причина не названа");
        } else if (hrc == TLS13_ETIMEOUT) {
            WHY("рукопожатие TLS не уложилось в срок");
        } else {
            WHY("рукопожатие TLS не удалось (код %d)", hrc);
        }
        goto done;
    }
    if (t->alpn[0] && strcmp(t->alpn, "http/1.1") != 0) {
        WHY("сервер выбрал ALPN %.20s, а нужен http/1.1", t->alpn);
        goto done;
    }

    /* Порт в Host — только нестандартный (RFC 9110 §7.2), как у HTTP в urltest.c. */
    char hh[160], req[512];
    unsigned port = ntohs(v6 ? ((const struct sockaddr_in6 *)&w->dst)->sin6_port
                             : ((const struct sockaddr_in *)&w->dst)->sin_port);
    if (port != 443)
        snprintf(hh, sizeof(hh), "%.127s:%u", w->host, port);
    else
        snprintf(hh, sizeof(hh), "%s", w->host);
    int rn = snprintf(req, sizeof(req),
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: steer/%s\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n", w->path, hh, STEER_VERSION);
    if (rn <= 0 || (size_t)rn >= sizeof(req)) { WHY("запрос не уместился в буфер"); goto done; }
    if (tls13_write(t, (const unsigned char *)req, (size_t)rn) != 0) { WHY("запрос не отправился"); goto done; }

    /* Первый прикладной байт: пустые чтения — пропущенные NewSessionTicket и набивка. */
    static __thread unsigned char buf[TLS13_MAX_PLAIN];
    unsigned char line[64];
    size_t ln = 0;
    long t_first = 0;
    for (;;) {
        if (set_timeo(fd, deadline)) { WHY("срок вышел: ответа нет"); goto done; }
        size_t got = 0;
        int rrc = tls13_read(t, buf, sizeof(buf), &got);
        if (rrc != 0) {
            if (rrc == TLS13_ETIMEOUT) WHY("срок вышел: ответа нет");
            else WHY("соединение закрыто до ответа (код %d)", rrc);
            goto done;
        }
        if (!got) continue;
        if (!t_first) t_first = mono_ms();
        size_t take = got < sizeof(line) - ln ? got : sizeof(line) - ln;
        memcpy(line + ln, buf, take);
        ln += take;
        if (memchr(line, '\n', ln) || ln >= sizeof(line)) break;
    }
    if (status_ok(line, ln)) {
        res = (int)(t_first - t0 > 0 ? t_first - t0 : 0);
    } else if (ln >= 12 && !memcmp(line, "HTTP/1.", 7) && line[8] == ' ') {
        WHY("ответ %.3s вместо 204/200", (const char *)line + 9);
    } else {
        WHY("ответ не похож на HTTP");
    }
done:
    tls13_free(t);
    free(t);
    close(fd);
    return res;
fail:
    close(fd);
    return -1;
}

static void *urltls_thread(void *arg) {
    struct urltls_work *w = arg;
    struct urltls_res res;
    memset(&res, 0, sizeof(res));
    res.ms = measure(w, res.why, sizeof(res.why));
    const unsigned char *p = (const unsigned char *)&res;
    size_t left = sizeof(res);
    while (left) {
        ssize_t k = send(w->fd, p, left, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k <= 0) break;     /* отменено: другой конец закрыт */
        p += k;
        left -= (size_t)k;
    }
    close(w->fd);
    free(w);
    return NULL;
}

static void urltls_free(struct urltls *t) {
    loop_fd_del(t->l, t->fd);
    close(t->fd);
    free(t);
}

static void urltls_ready(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct urltls *t = arg;
    for (;;) {
        if (t->gn >= sizeof(t->got)) break;
        ssize_t k = recv(fd, t->got + t->gn, sizeof(t->got) - t->gn, 0);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (k <= 0) break;
        t->gn += (size_t)k;
    }
    struct urltls_res res;
    memset(&res, 0, sizeof(res));
    res.ms = -1;
    if (t->gn == sizeof(t->got)) memcpy(&res, t->got, sizeof(res));
    else snprintf(res.why, sizeof(res.why), "поток HTTPS оборвался");
    res.why[sizeof(res.why) - 1] = '\0';
    void (*cb)(void *, int, const char *) = t->cb;
    void *a = t->arg;
    urltls_free(t);
    cb(a, res.ms, res.why);
}

struct urltls *urltls_start(struct loop *l, const struct sockaddr_storage *dst, const char *host,
                            const char *path, uint32_t mark, const char *dev, int timeout_ms,
                            void (*cb)(void *arg, int ms, const char *why), void *arg) {
    struct urltls *t = calloc(1, sizeof(*t));
    struct urltls_work *w = calloc(1, sizeof(*w));
    int sv[2] = { -1, -1 };
    if (!t || !w || socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) goto fail;
    fcntl(sv[0], F_SETFL, fcntl(sv[0], F_GETFL) | O_NONBLOCK);
    t->l = l;
    t->fd = sv[0];
    t->cb = cb;
    t->arg = arg;
    w->fd = sv[1];
    w->dst = *dst;
    snprintf(w->host, sizeof(w->host), "%s", host);
    snprintf(w->path, sizeof(w->path), "%s", path);
    w->mark = mark;
    if (dev) snprintf(w->dev, sizeof(w->dev), "%s", dev);
    w->timeout_ms = timeout_ms > 0 ? timeout_ms : 1;
    if (loop_fd_add(l, sv[0], EPOLLIN, urltls_ready, t) != 0) goto fail;
    pthread_attr_t at;
    int attr_ok = pthread_attr_init(&at) == 0;
    if (attr_ok) pthread_attr_setdetachstate(&at, PTHREAD_CREATE_DETACHED);
    pthread_t th;
    int rc = pthread_create(&th, attr_ok ? &at : NULL, urltls_thread, w);
    if (attr_ok) pthread_attr_destroy(&at);
    if (rc != 0) {
        loop_fd_del(l, sv[0]);
        goto fail;
    }
    return t;
fail:
    if (sv[0] >= 0) close(sv[0]);
    if (sv[1] >= 0) close(sv[1]);
    free(t);
    free(w);
    return NULL;
}

void urltls_cancel(struct urltls *t) {
    if (t) urltls_free(t);
}
