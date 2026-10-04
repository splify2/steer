/* urltest — задержка члена группы запросом к адресу проверки через этого члена.
 *
 * ЗАЧЕМ ЗАПРОС, А НЕ РУКОПОЖАТИЕ TCP. Прежде задержку члена меряло установление соединения TCP с
 * 1.1.1.1:80 через его устройство (SO_BINDTODEVICE). Для интерфейса ядра (wireguard) это честная
 * мера пути: SYN уходит в туннель, SYN-ACK приходит оттуда же. Для VLESS — нет: его TUN завершает
 * TCP у себя, в нашем же процессе, и SYN-ACK приходит от собственного стека клиента за доли
 * миллисекунды, какой бы ни был путь до сервера. Замер «через VLESS» мерил скорость нашего TUN, и
 * выбор по задержке между VLESS и wireguard всегда выигрывал VLESS. Первый байт ОТВЕТА на запрос
 * так подделать нечем: он приходит только после того, как запрос доехал до сервера туннеля, тот
 * соединился с проверочным узлом и ответ вернулся тем же путём. Так же меряет urltest у sing-box
 * (решение владельца, docs/architecture.md, «4в»).
 *
 * ПОЧЕМУ ВРЕМЯ ДО ПЕРВОГО БАЙТА, а не до конца ответа. Ответ проверочного узла — 204 без тела, и
 * всё, что после первого байта, — это та же строка статуса в том же сегменте. Первый байт отвечает
 * ровно на вопрос «сколько идёт оборот через этого члена», а конец ответа прибавил бы к нему
 * закрытие соединения, которое к пути отношения не имеет. Статус всё равно дочитывается и
 * проверяется (204 или 200): страница плена провайдера или заглушка на 302/403 — это не «быстрый
 * член», а член, через который проверочный узел не виден.
 *
 * ЧЕРЕЗ ЧЛЕНА — SO_MARK. У именованного члена (спека v2) есть своя метка, правило fwmark и таблица,
 * которую сторож привязывает к его устройству. Сокет с этой меткой ядро ведёт ровно тем путём,
 * которым пошёл бы трафик члена: таблица члена, его устройство, его TUN (VLESS), его цепочка `over`
 * — тот же механизм, которым туннель едет поверх своей подложки. SO_BINDTODEVICE этого не даёт: он
 * решает только «через какое устройство», а не «по какой таблице», и у члена-группы (вложенность)
 * устройства своего нет вовсе. Безымянные члены пулов v1 (`devices`) своей метки не имеют — им
 * остаётся SO_BINDTODEVICE, как у прежней пробы.
 *
 * НЕ БЛОКИРУЕТСЯ НИЧЕГО. HTTP — неблокирующий сокет в epoll цикла демона со сроком на таймере
 * цикла. Имя узла разрешается рабочим потоком (gaiw.h: getaddrinfo блокирует, а неблокирующего нет
 * ни в musl, ни в bionic) с маленьким кэшем: интервал замера — минуты, а членов несколько, и
 * спрашивать DNS на каждого незачем. HTTPS — рабочим потоком src/proto/tls/urltls.c: рукопожатие
 * tls13.c блокирующее по устройству (читает сокет со SO_RCVTIMEO), и переписывать его ради замера
 * раз в три минуты — второй TLS рядом с первым. Поток — не процесс: fork на замер нет. В сборке без
 * TLS (steer-mini) urltls нет вовсе — слабая ссылка, — и адрес https:// отвергает ещё разбор спеки
 * (urltest_https_ok в grpurl.c).
 *
 * СЕМЕЙСТВО — параметр замера. Группа, все живые члены которой несут IPv6 (KC_IPV6), меряется
 * дважды — по IPv4 и по IPv6 (src/daemon/folat.c): путь IPv6 через туннель — свой, и член, быстрый
 * по IPv4, может не везти IPv6 вовсе. Замер по IPv6 — тот же запрос из сокета AF_INET6 к адресу из
 * AAAA; метка члена ведёт его по правилу и таблице IPv6 члена (ip -6 rule), как трафик группы. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdarg.h>
#include <unistd.h>
#include <fcntl.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "loop.h"
#include "gaiw.h"
#include "urltest.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

/* HTTPS — только в полном пакете (src/proto/tls/urltls.c). Слабые ссылки: в мини-сборке адреса
 * этих функций — ноль. Объявлены здесь, а не заголовком urltls.h: каталог TLS — слой полного
 * пакета, и ядро о нём знает только эти две строки. */
struct urltls;
extern struct urltls *urltls_start(struct loop *l, const struct sockaddr_storage *dst, const char *host,
                                   const char *path, uint32_t mark, const char *dev, int timeout_ms,
                                   void (*cb)(void *arg, int ms, const char *why), void *arg)
    __attribute__((weak));
extern void urltls_cancel(struct urltls *t) __attribute__((weak));

/* ---- кэш имён ---------------------------------------------------------------------------- */

/* Запись — на имя и семейство: у одного адреса проверки ответы A и AAAA живут порознь (замер по
 * IPv6 спрашивает только AAAA, и отказ AAAA не должен стереть годный A). */
#define DNS_CACHE_N    8
#define DNS_OK_MS      (300L * 1000L)
#define DNS_FAIL_MS    (30L * 1000L)

struct dns_ent {
    char host[128];
    int fam;
    int ok;
    struct sockaddr_storage a;
    long until;
};
static struct dns_ent g_dns[DNS_CACHE_N];

/* 1 — в кэше годный адрес; 0 — в кэше отказ (свежий); -1 — нет записи. */
static int dns_get(const char *host, int fam, struct sockaddr_storage *a) {
    long now = loop_now_ms();
    for (size_t i = 0; i < DNS_CACHE_N; i++)
        if (g_dns[i].host[0] && g_dns[i].fam == fam && !strcmp(g_dns[i].host, host) &&
            g_dns[i].until > now) {
            if (g_dns[i].ok) *a = g_dns[i].a;
            return g_dns[i].ok;
        }
    return -1;
}

static void dns_put(const char *host, int fam, int ok, const struct sockaddr_storage *a) {
    size_t slot = 0;
    long oldest = 0;
    for (size_t i = 0; i < DNS_CACHE_N; i++) {
        if (g_dns[i].fam == fam && !strcmp(g_dns[i].host, host)) { slot = i; break; }
        if (i == 0 || g_dns[i].until < oldest) { oldest = g_dns[i].until; slot = i; }
    }
    struct dns_ent *e = &g_dns[slot];
    snprintf(e->host, sizeof(e->host), "%s", host);
    e->fam = fam;
    e->ok = ok;
    if (ok) e->a = *a;
    e->until = loop_now_ms() + (ok ? DNS_OK_MS : DNS_FAIL_MS);
}

/* ---- замер ------------------------------------------------------------------------------- */

enum { UT_DNS, UT_CONN, UT_SEND, UT_RECV, UT_TLS };

struct urltest {
    struct loop *l;
    struct urltest_url u;
    int fam;                    /* AF_INET или AF_INET6 */
    uint32_t mark;
    char dev[32];
    urltest_cb cb;
    void *arg;
    struct loop_timer *tm;
    long deadline;
    int st;
    int fd;
    struct gaiw *gw;
    struct urltls *tls;
    struct sockaddr_storage dst;
    long t0, t_first;
    char req[512];
    size_t req_n, req_off;
    char buf[80];
    size_t bn;
    /* Почему замер не удался — для журнала (urltest_why): пишется перед ut_finish(-1). */
    char why[192];
    /* Пока идёт urltest_start, итог не отдаётся обратным вызовом, а запоминается: договор —
     * «NULL и итог в *ms», когда замер кончился сразу. */
    int in_start, done, res;
};

/* ПРИЧИНА НЕУДАЧИ — строкой, для журнала. Замер отвечает числом (-1 — не измерилось), и по числу
 * не отличить «адрес не разрешился» от «ответ 503» и от «сертификат не принят»: а именно это человек
 * и спрашивает, когда группа «самый быстрый» идёт по порядку из-за того, что мерить не вышло.
 * Причина доступна, пока выполняется обратный вызов, и сразу после urltest_start, вернувшего NULL
 * (urltest_why); у удавшегося замера — пустая. Цикл демона один, и глобальной строки хватает. */
static char g_why[192];

const char *urltest_why(void) {
    return g_why;
}

static void ut_why(struct urltest *u, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void ut_why(struct urltest *u, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(u->why, sizeof(u->why), fmt, ap);
    va_end(ap);
}

static void ut_free(struct urltest *u) {
    if (u->fd >= 0) {
        loop_fd_del(u->l, u->fd);
        close(u->fd);
        u->fd = -1;
    }
    if (u->gw) gaiw_cancel(u->gw);
    if (u->tls && urltls_cancel) urltls_cancel(u->tls);
    loop_timer_free(u->tm);
    free(u);
}

static void ut_finish(struct urltest *u, int ms) {
    snprintf(g_why, sizeof(g_why), "%s", ms >= 0 ? "" : u->why);
    if (u->in_start) {
        u->done = 1;
        u->res = ms;
        return;
    }
    urltest_cb cb = u->cb;
    void *arg = u->arg;
    ut_free(u);
    cb(arg, ms);
}

static void ut_timeout(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct urltest *u = arg;
    /* По порядку состояний (UT_DNS … UT_TLS): на каком шаге вышел срок. */
    static const char *const at[] = { "имя не разрешилось", "соединение не установилось",
                                      "запрос не ушёл", "ответа нет", "рукопожатие TLS и ответ не пришли" };
    ut_why(u, "срок вышел: %s", at[u->st]);
    ut_finish(u, -1);
}

/* Строка статуса «HTTP/1.x NNN …»: годен ли ответ. */
static int status_ok(const char *b, size_t n) {
    if (n < 12 || strncmp(b, "HTTP/1.", 7) != 0 || b[8] != ' ') return 0;
    if (b[9] < '0' || b[9] > '9' || b[10] < '0' || b[10] > '9' || b[11] < '0' || b[11] > '9')
        return 0;
    int code = (b[9] - '0') * 100 + (b[10] - '0') * 10 + (b[11] - '0');
    return code == 204 || code == 200;
}

/* Почему ответ негоден: код статуса, если он есть, иначе «не HTTP». */
static void ut_status_why(struct urltest *u) {
    if (u->bn >= 12 && !strncmp(u->buf, "HTTP/1.", 7) && u->buf[8] == ' ')
        ut_why(u, "ответ %.3s вместо 204/200", u->buf + 9);
    else
        ut_why(u, "ответ не похож на HTTP");
}

static void ut_io(struct loop *l, int fd, uint32_t ev, void *arg);

static void ut_send(struct urltest *u) {
    while (u->req_off < u->req_n) {
        ssize_t k = send(u->fd, u->req + u->req_off, u->req_n - u->req_off, MSG_NOSIGNAL);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (u->st != UT_SEND) { u->st = UT_SEND; loop_fd_mod(u->l, u->fd, EPOLLOUT); }
            return;
        }
        if (k <= 0) {
            ut_why(u, "запрос не отправился: %s", k < 0 ? strerror(errno) : "соединение закрыто");
            ut_finish(u, -1);
            return;
        }
        u->req_off += (size_t)k;
    }
    u->st = UT_RECV;
    if (loop_fd_mod(u->l, u->fd, EPOLLIN | EPOLLRDHUP) != 0) {
        ut_why(u, "цикл событий не принял сокет");
        ut_finish(u, -1);
    }
}

static void ut_recv(struct urltest *u) {
    for (;;) {
        char tmp[512];
        ssize_t k = recv(u->fd, tmp, sizeof(tmp), 0);
        if (k < 0 && errno == EINTR) continue;
        if (k < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (k <= 0) {                                /* закрыто или сброшено до строки статуса */
            if (k < 0) ut_why(u, "чтение: %s", strerror(errno));
            else ut_why(u, "соединение закрыто до ответа");
            ut_finish(u, -1);
            return;
        }
        if (!u->t_first) u->t_first = loop_now_ms();
        size_t take = (size_t)k;
        if (take > sizeof(u->buf) - 1 - u->bn) take = sizeof(u->buf) - 1 - u->bn;
        memcpy(u->buf + u->bn, tmp, take);
        u->bn += take;
        u->buf[u->bn] = '\0';
        char *eol = memchr(u->buf, '\n', u->bn);
        if (eol || u->bn >= 64) {
            long ms = u->t_first - u->t0;
            if (ms < 0) ms = 0;
            int ok = status_ok(u->buf, u->bn);
            if (!ok) ut_status_why(u);
            ut_finish(u, ok ? (int)ms : -1);
            return;
        }
    }
}

static void ut_io(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)fd;
    struct urltest *u = arg;
    if (u->st == UT_CONN) {
        int err = 0;
        socklen_t el = sizeof(err);
        if (getsockopt(u->fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0 || err) {
            ut_why(u, "соединение: %s", strerror(err ? err : errno));
            ut_finish(u, -1);
            return;
        }
        ut_send(u);
        return;
    }
    if (u->st == UT_SEND) {
        if (ev & (EPOLLERR | EPOLLHUP)) {
            ut_why(u, "соединение сброшено при отправке запроса");
            ut_finish(u, -1);
            return;
        }
        ut_send(u);
        return;
    }
    if (u->st == UT_RECV) ut_recv(u);
}

static void ut_tls_cb(void *arg, int ms, const char *why) {
    struct urltest *u = arg;
    u->tls = NULL;              /* поток отдал итог и освободил своё */
    if (ms < 0) ut_why(u, "%s", why && why[0] ? why : "HTTPS не удался");
    ut_finish(u, ms);
}

/* Адрес известен — соединяться. Порт — из адреса проверки, семейство — из самого адреса. */
static void ut_connect(struct urltest *u, const struct sockaddr_storage *a) {
    u->dst = *a;
    socklen_t dl;
    if (u->dst.ss_family == AF_INET6) {
        ((struct sockaddr_in6 *)&u->dst)->sin6_port = htons(u->u.port);
        dl = sizeof(struct sockaddr_in6);
    } else {
        ((struct sockaddr_in *)&u->dst)->sin_port = htons(u->u.port);
        dl = sizeof(struct sockaddr_in);
    }
    long left = u->deadline - loop_now_ms();
    if (left <= 0) { ut_why(u, "срок вышел до соединения"); ut_finish(u, -1); return; }

    if (u->u.https) {
        if (!urltls_start) { ut_why(u, "https:// в этой сборке нет"); ut_finish(u, -1); return; }
        u->st = UT_TLS;
        u->tls = urltls_start(u->l, &u->dst, u->u.host, u->u.path, u->mark, u->dev[0] ? u->dev : NULL,
                              (int)left, ut_tls_cb, u);
        if (!u->tls) { ut_why(u, "поток HTTPS не завёлся"); ut_finish(u, -1); }
        return;
    }

    int fd = socket(u->dst.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) { ut_why(u, "socket: %s", strerror(errno)); ut_finish(u, -1); return; }
    if (u->mark) {
        if (setsockopt(fd, SOL_SOCKET, SO_MARK, &u->mark, sizeof(u->mark)) != 0) {
            ut_why(u, "метка члена не поставилась: %s", strerror(errno));
            close(fd);
            ut_finish(u, -1);
            return;
        }
    } else if (u->dev[0]) {
        if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, u->dev, (socklen_t)strlen(u->dev) + 1) != 0) {
            ut_why(u, "привязка к устройству %s: %s", u->dev, strerror(errno));
            close(fd);
            ut_finish(u, -1);
            return;
        }
    }
    u->t0 = loop_now_ms();
    int rc = connect(fd, (struct sockaddr *)&u->dst, dl);
    if (rc != 0 && errno != EINPROGRESS) {
        ut_why(u, "соединение: %s", strerror(errno));
        close(fd);
        ut_finish(u, -1);
        return;
    }
    u->fd = fd;
    u->st = rc == 0 ? UT_SEND : UT_CONN;
    if (loop_fd_add(u->l, fd, EPOLLOUT, ut_io, u) != 0) {
        ut_why(u, "цикл событий не принял сокет");
        close(fd);
        u->fd = -1;
        ut_finish(u, -1);
        return;
    }
    if (rc == 0) ut_send(u);
}

static void ut_gai_cb(void *arg, const struct kind_name *names, size_t n) {
    struct urltest *u = arg;
    u->gw = NULL;
    socklen_t need = u->fam == AF_INET6 ? (socklen_t)sizeof(struct sockaddr_in6)
                                        : (socklen_t)sizeof(struct sockaddr_in);
    int ok = n >= 1 && names[0].rc == 0 && names[0].addr_len >= need &&
             names[0].addr.ss_family == u->fam;
    dns_put(u->u.host, u->fam, ok, &names[0].addr);
    if (!ok) {
        ut_why(u, "имя %s не разрешилось (%s)", u->u.host, u->fam == AF_INET6 ? "AAAA" : "A");
        ut_finish(u, -1);
        return;
    }
    ut_connect(u, &names[0].addr);
}

struct urltest *urltest_start(struct loop *l, const char *url, int fam, uint32_t mark,
                              const char *dev, int timeout_ms, urltest_cb cb, void *arg, int *ms) {
    *ms = -1;
    g_why[0] = '\0';
    struct urltest_url pu;
    if (urltest_url_parse(url, &pu, NULL, 0) != 0) {
        snprintf(g_why, sizeof(g_why), "адрес проверки негоден");
        return NULL;
    }
    if (pu.https && !urltls_start) {
        snprintf(g_why, sizeof(g_why), "https:// в этой сборке нет");
        return NULL;
    }
    if (fam != AF_INET6) fam = AF_INET;
    struct urltest *u = calloc(1, sizeof(*u));
    if (!u) {
        snprintf(g_why, sizeof(g_why), "нет памяти");
        return NULL;
    }
    u->l = l;
    u->u = pu;
    u->fam = fam;
    u->mark = mark;
    if (dev) snprintf(u->dev, sizeof(u->dev), "%s", dev);
    u->cb = cb;
    u->arg = arg;
    u->fd = -1;
    u->tm = loop_timer_new(l, ut_timeout, u);
    if (!u->tm) {
        snprintf(g_why, sizeof(g_why), "нет памяти");
        free(u);
        return NULL;
    }
    if (timeout_ms <= 0) timeout_ms = 1;
    u->deadline = loop_now_ms() + timeout_ms;
    loop_timer_set(u->tm, timeout_ms);
    const char *hp = "";
    char portbuf[16];
    if (pu.port != (pu.https ? 443 : 80)) { snprintf(portbuf, sizeof(portbuf), ":%u", pu.port); hp = portbuf; }
    int rn = snprintf(u->req, sizeof(u->req),
                      "GET %s HTTP/1.1\r\nHost: %s%s\r\nUser-Agent: steer/%s\r\nAccept: */*\r\n"
                      "Connection: close\r\n\r\n", pu.path, pu.host, hp, STEER_VERSION);
    u->req_n = rn > 0 && (size_t)rn < sizeof(u->req) ? (size_t)rn : 0;

    u->in_start = 1;
    struct sockaddr_storage a;
    memset(&a, 0, sizeof(a));
    struct in_addr a4;
    if (!u->req_n) {
        ut_why(u, "запрос не уместился в буфер");
        ut_finish(u, -1);
    } else if (inet_pton(AF_INET, pu.host, &a4) == 1) {
        /* Литерал IPv4 — замера по IPv6 у такого адреса нет: AAAA не спросить. */
        if (fam == AF_INET6) {
            ut_finish(u, -1);
        } else {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&a;
            s4->sin_family = AF_INET;
            s4->sin_addr = a4;
            ut_connect(u, &a);
        }
    } else {
        int c = dns_get(pu.host, fam, &a);
        if (c == 1) ut_connect(u, &a);
        else if (c == 0) {
            ut_why(u, "имя %s не разрешилось (%s, недавний отказ)", pu.host, fam == AF_INET6 ? "AAAA" : "A");
            ut_finish(u, -1);
        } else {
            struct kind_name nm;
            memset(&nm, 0, sizeof(nm));
            snprintf(nm.host, sizeof(nm.host), "%s", pu.host);
            nm.port = pu.port;
            nm.v4only = fam == AF_INET;
            nm.v6only = fam == AF_INET6;
            u->st = UT_DNS;
            u->gw = gaiw_start(l, &nm, 1, ut_gai_cb, u);
            if (!u->gw) ut_gai_cb(u, &nm, 1);   /* поток не создался — разрешено синхронно */
        }
    }
    u->in_start = 0;
    if (u->done) {
        *ms = u->res;
        ut_free(u);
        return NULL;
    }
    return u;
}

void urltest_cancel(struct urltest *u) {
    if (u) ut_free(u);
}
