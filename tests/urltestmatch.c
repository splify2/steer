/* Стенд замера urltest (src/daemon/urltest.c) и разбора адреса проверки (src/kinds/grpurl.c).
 *
 * Без сети наружу: ответчики — потоки этого же стенда на 127.0.0.1, каждый со своим поведением
 * (204 сразу, 204 через 300 мс, 200, 404, молчание, закрытие без ответа, мусор, статус кусками).
 * Замер крутит свой цикл loop.h, как демон. SO_MARK без root не ставится, и путь «через члена»
 * (метка, таблица, устройство) проверяет netns-стенд групп; здесь mark = 0 и dev = NULL.
 *
 * Сборка (цель build/urltestmatch в Makefile):
 *   cc $(make -s print-inc) -O2 -Wall -Wextra -o build/urltestmatch tests/urltestmatch.c \
 *      src/daemon/urltest.c src/kinds/grpurl.c src/daemon/loop.c src/daemon/gaiw.c -lpthread */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "loop.h"
#include "urltest.h"
#include "unit.h"

enum { M204, M204SLOW, M200, M404, MSILENT, MCLOSE, MGARBAGE, MSPLIT, M_N };

struct srv {
    int mode;
    int lfd;
    unsigned short port;
    int hits;
    char last_req[512];
};
static struct srv g_srv[M_N];

static void nap(long ms) {
    struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };
    while (nanosleep(&ts, &ts) != 0 && errno == EINTR) {}
}

static void send_s(int fd, const char *s) {
    size_t n = strlen(s);
    while (n) {
        ssize_t k = send(fd, s, n, MSG_NOSIGNAL);
        if (k <= 0) return;
        s += k;
        n -= (size_t)k;
    }
}

static void *srv_thread(void *arg) {
    struct srv *s = arg;
    for (;;) {
        int c = accept(s->lfd, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; return NULL; }
        char req[512];
        size_t n = 0;
        while (n < sizeof(req) - 1) {
            ssize_t k = recv(c, req + n, sizeof(req) - 1 - n, 0);
            if (k <= 0) break;
            n += (size_t)k;
            req[n] = '\0';
            if (strstr(req, "\r\n\r\n")) break;
        }
        req[n] = '\0';
        __atomic_add_fetch(&s->hits, 1, __ATOMIC_SEQ_CST);
        snprintf(s->last_req, sizeof(s->last_req), "%s", req);
        switch (s->mode) {
        case M204: send_s(c, "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n"); break;
        case M204SLOW: nap(300); send_s(c, "HTTP/1.1 204 No Content\r\n\r\n"); break;
        case M200: send_s(c, "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok"); break;
        case M404: send_s(c, "HTTP/1.1 404 Not Found\r\n\r\n"); break;
        case MSILENT: nap(1500); break;
        case MCLOSE: break;
        case MGARBAGE: send_s(c, "garbage, not http at all\r\n"); break;
        case MSPLIT: send_s(c, "HTT"); nap(100); send_s(c, "P/1.1 204 No Content\r\n\r\n"); break;
        }
        close(c);
    }
}

static void srv_up(int mode) {
    struct srv *s = &g_srv[mode];
    s->mode = mode;
    s->lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s->lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t al = sizeof(a);
    if (bind(s->lfd, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(s->lfd, 16) != 0 ||
        getsockname(s->lfd, (struct sockaddr *)&a, &al) != 0) {
        perror("ответчик");
        exit(2);
    }
    s->port = ntohs(a.sin_port);
    pthread_t th;
    pthread_create(&th, NULL, srv_thread, s);
    pthread_detach(th);
}

/* ---- один замер на своём цикле ---------------------------------------------------------- */

static struct loop *g_l;
static int g_ms, g_calls;
/* Причина неудачи последнего замера (urltest_why), снятая в обратном вызове или сразу после
 * urltest_start, вернувшего NULL: дальше её затирает следующий замер. */
static char g_whyc[192];

static void on_done(void *arg, int ms) {
    (void)arg;
    g_ms = ms;
    g_calls++;
    snprintf(g_whyc, sizeof(g_whyc), "%s", urltest_why());
    loop_stop(g_l, 0);
}

/* Цикл одноразовый: после loop_stop он не крутится снова (так живёт и демон — один цикл на
 * процесс). Свой на каждый замер — как у `steer failover` на каждый проход (run_sync). */
static void fresh(void) {
    if (g_l) loop_free(g_l);
    g_l = loop_new();
    if (!g_l) { perror("loop_new"); exit(2); }
}

static void on_guard(struct loop *l, struct loop_timer *t, void *arg) {
    (void)t; (void)arg;
    loop_stop(l, 0);
}

/* Замер url по семейству fam со сроком timeout_ms; возврат — мс или -1; *took — сколько длился по
 * стенным часам. */
static int run_fam(const char *url, int fam, int timeout_ms, long *took) {
    g_calls = 0;
    g_ms = -2;
    g_whyc[0] = '\0';
    fresh();
    long t0 = loop_now_ms();
    int ms = -2;
    struct urltest *u = urltest_start(g_l, url, fam, 0, NULL, timeout_ms, on_done, NULL, &ms);
    if (!u) snprintf(g_whyc, sizeof(g_whyc), "%s", urltest_why());
    if (u) {
        struct loop_timer *g = loop_timer_new(g_l, on_guard, NULL);
        loop_timer_set(g, timeout_ms + 3000);
        loop_run(g_l);
        loop_timer_free(g);
        ms = g_calls == 1 ? g_ms : -3;
    }
    if (took) *took = loop_now_ms() - t0;
    return ms;
}

static int run(const char *url, int timeout_ms, long *took) {
    return run_fam(url, AF_INET, timeout_ms, took);
}

/* Ответчик 204 на [::1] (поток, как у IPv4); порт — в *port. 0 — IPv6 на петле нет. */
static int g_lfd6 = -1;
static void *srv6_thread(void *arg) {
    int *hits = arg;
    for (;;) {
        int c = accept(g_lfd6, NULL, NULL);
        if (c < 0) { if (errno == EINTR) continue; return NULL; }
        char req[512];
        size_t n = 0;
        while (n < sizeof(req) - 1) {
            ssize_t k = recv(c, req + n, sizeof(req) - 1 - n, 0);
            if (k <= 0) break;
            n += (size_t)k;
            req[n] = '\0';
            if (strstr(req, "\r\n\r\n")) break;
        }
        __atomic_add_fetch(hits, 1, __ATOMIC_SEQ_CST);
        send_s(c, "HTTP/1.1 204 No Content\r\n\r\n");
        close(c);
    }
}

static int srv6_up(unsigned short *port, int *hits) {
    g_lfd6 = socket(AF_INET6, SOCK_STREAM, 0);
    if (g_lfd6 < 0) return 0;
    int one = 1;
    setsockopt(g_lfd6, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(g_lfd6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    struct sockaddr_in6 a = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
    socklen_t al = sizeof(a);
    if (bind(g_lfd6, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(g_lfd6, 16) != 0 ||
        getsockname(g_lfd6, (struct sockaddr *)&a, &al) != 0) {
        close(g_lfd6);
        g_lfd6 = -1;
        return 0;
    }
    *port = ntohs(a.sin6_port);
    pthread_t th;
    pthread_create(&th, NULL, srv6_thread, hits);
    pthread_detach(th);
    return 1;
}

/* Имя, у которого есть AAAA на ::1 (/etc/hosts машины стенда): NULL — нет такого. */
static const char *v6_name(void) {
    static const char *const names[] = { "localhost", "ip6-localhost", "ip6-loopback", NULL };
    for (size_t i = 0; names[i]; i++) {
        struct addrinfo h = { .ai_family = AF_INET6, .ai_socktype = SOCK_STREAM }, *res = NULL;
        if (getaddrinfo(names[i], "80", &h, &res) == 0 && res) {
            int ok = IN6_IS_ADDR_LOOPBACK(&((struct sockaddr_in6 *)res->ai_addr)->sin6_addr);
            freeaddrinfo(res);
            if (ok) return names[i];
        }
    }
    return NULL;
}

static void url_of(char *b, size_t n, int mode, const char *path) {
    snprintf(b, n, "http://127.0.0.1:%u%s", g_srv[mode].port, path);
}

int main(void) {
    for (int m = 0; m < M_N; m++) srv_up(m);
    fresh();

    /* ---- разбор адреса ---- */
    struct urltest_url u;
    char why[160];
    check("разбор: умолчание годно", 0, urltest_url_parse(GROUP_URL_DEFAULT, &u, why, sizeof(why)));
    check_str("  хост", "cp.cloudflare.com", u.host);
    check("  порт 80", 80, u.port);
    check_str("  путь", "/generate_204", u.path);
    check("  не https", 0, u.https);
    check("разбор: https с портом и без пути", 0,
          urltest_url_parse("https://www.gstatic.com:8443", &u, why, sizeof(why)));
    check("  https", 1, u.https);
    check("  порт 8443", 8443, u.port);
    check_str("  путь по умолчанию «/»", "/", u.path);
    check("разбор: https без порта — 443", 0, urltest_url_parse("https://1.2.3.4/x?y=1", &u, why, sizeof(why)));
    check("  порт 443", 443, u.port);
    check_str("  путь с запросом", "/x?y=1", u.path);
    check("разбор: ftp — отказ", -1, urltest_url_parse("ftp://a/b", &u, why, sizeof(why)));
    check("  текст отказа про схему", 1, strstr(why, "http://") != NULL);
    check("разбор: пустой хост — отказ", -1, urltest_url_parse("http:///x", &u, why, sizeof(why)));
    check("разбор: порт 0 — отказ", -1, urltest_url_parse("http://a:0/", &u, why, sizeof(why)));
    check("разбор: порт 70000 — отказ", -1, urltest_url_parse("http://a:70000/", &u, why, sizeof(why)));
    check("разбор: порт не число — отказ", -1, urltest_url_parse("http://a:8x/", &u, why, sizeof(why)));
    check("разбор: пробел — отказ", -1, urltest_url_parse("http://a/b c", &u, why, sizeof(why)));
    check("разбор: кавычка — отказ", -1, urltest_url_parse("http://a/\"", &u, why, sizeof(why)));
    check("разбор: IPv6 — отказ", -1, urltest_url_parse("http://[::1]/", &u, why, sizeof(why)));
    check("  текст про IPv6", 1, strstr(why, "IPv6") != NULL);
    check("разбор: имя с паролем — отказ", -1, urltest_url_parse("http://u:p@a/", &u, why, sizeof(why)));
    char longu[300];
    memset(longu, 'a', sizeof(longu) - 1);
    longu[sizeof(longu) - 1] = '\0';
    memcpy(longu, "http://", 7);
    check("разбор: длиннее предела — отказ", -1, urltest_url_parse(longu, &u, why, sizeof(why)));

    /* ---- HTTPS в этой сборке нет ---- */
    check("HTTPS в сборке без urltls — нет", 0, urltest_https_ok());
    int ms = 5;
    check("https:// без urltls — итог сразу (NULL)", 1,
          urltest_start(g_l, "https://127.0.0.1/", AF_INET, 0, NULL, 1000, on_done, NULL, &ms) == NULL);
    check("  и это -1", -1, ms);
    check("  причина названа: https:// в этой сборке нет", 1, strstr(urltest_why(), "https://") != NULL);
    check("негодный адрес — итог сразу", 1,
          urltest_start(g_l, "gopher://x/", AF_INET, 0, NULL, 1000, on_done, NULL, &ms) == NULL && ms == -1);
    check("  причина названа: адрес негоден", 1, strstr(urltest_why(), "негоден") != NULL);
    ms = 5;
    check("IPv6 к литералу IPv4 — итог сразу: -1 (AAAA не спросить)", 1,
          urltest_start(g_l, "http://127.0.0.1/", AF_INET6, 0, NULL, 1000, on_done, NULL, &ms) == NULL &&
          ms == -1);
    check("  причина пустая: по построению, а не неудача", 0, (int)strlen(urltest_why()));

    /* ---- замеры ---- */
    char url[128];
    long took;
    url_of(url, sizeof(url), M204, "/generate_204");
    int r = run(url, 2000, &took);
    check("204 сразу — замер есть", 1, r >= 0 && r < 200);
    check("  причина пустая", 0, (int)strlen(g_whyc));
    check("  запрос — GET пути", 1, strncmp(g_srv[M204].last_req, "GET /generate_204 HTTP/1.1\r\n", 28) == 0);
    char hh[64];
    snprintf(hh, sizeof(hh), "Host: 127.0.0.1:%u\r\n", g_srv[M204].port);
    check("  Host с нестандартным портом", 1, strstr(g_srv[M204].last_req, hh) != NULL);
    check("  Connection: close", 1, strstr(g_srv[M204].last_req, "Connection: close\r\n") != NULL);
    check("  User-Agent steer", 1, strstr(g_srv[M204].last_req, "User-Agent: steer/") != NULL);

    url_of(url, sizeof(url), M204SLOW, "/");
    r = run(url, 3000, &took);
    check("204 через 300 мс — замер ≈ 300 мс", 1, r >= 280 && r < 900);
    url_of(url, sizeof(url), M200, "/");
    check("200 — тоже годен", 1, run(url, 2000, NULL) >= 0);
    url_of(url, sizeof(url), M404, "/");
    check("404 — не измерилось", -1, run(url, 2000, NULL));
    check("  причина: ответ 404 вместо 204/200", 1, strstr(g_whyc, "ответ 404 вместо 204/200") != NULL);
    url_of(url, sizeof(url), MGARBAGE, "/");
    check("мусор вместо HTTP — не измерилось", -1, run(url, 2000, NULL));
    check("  причина: не похож на HTTP", 1, strstr(g_whyc, "не похож на HTTP") != NULL);
    url_of(url, sizeof(url), MCLOSE, "/");
    check("закрыл без ответа — не измерилось", -1, run(url, 2000, NULL));
    check("  причина: закрыто до ответа", 1, strstr(g_whyc, "закрыто до ответа") != NULL);
    url_of(url, sizeof(url), MSILENT, "/");
    r = run(url, 500, &took);
    check("молчит — не измерилось по сроку", -1, r);
    check("  причина: срок вышел, ответа нет", 1, strstr(g_whyc, "срок вышел: ответа нет") != NULL);
    check("  срок соблюдён (≈500 мс)", 1, took >= 450 && took < 1400);
    url_of(url, sizeof(url), MSPLIT, "/");
    r = run(url, 2000, NULL);
    check("статус кусками — время по ПЕРВОМУ байту", 1, r >= 0 && r < 90);

    /* Никто не слушает: отказ соединения. */
    int dead = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in da = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
    socklen_t dl = sizeof(da);
    bind(dead, (struct sockaddr *)&da, sizeof(da));
    getsockname(dead, (struct sockaddr *)&da, &dl);
    close(dead);
    snprintf(url, sizeof(url), "http://127.0.0.1:%u/", ntohs(da.sin_port));
    check("порт закрыт — не измерилось", -1, run(url, 2000, NULL));
    check("  причина: соединение отвергнуто", 1, strstr(g_whyc, "соединение:") != NULL &&
          strstr(g_whyc, strerror(ECONNREFUSED)) != NULL);

    /* Имя, а не литерал: через рабочий поток gaiw, затем из кэша. */
    snprintf(url, sizeof(url), "http://localhost:%u/", g_srv[M204].port);
    int h0 = g_srv[M204].hits;
    check("имя localhost — замер есть", 1, run(url, 3000, NULL) >= 0);
    check("  второй раз (из кэша) — тоже", 1, run(url, 3000, NULL) >= 0);
    check("  оба дошли до ответчика", 2, g_srv[M204].hits - h0);

    /* Отмена: обратного вызова нет. */
    url_of(url, sizeof(url), M204SLOW, "/");
    g_calls = 0;
    fresh();
    struct urltest *ut = urltest_start(g_l, url, AF_INET, 0, NULL, 2000, on_done, NULL, &ms);
    check("отмена: замер начат", 1, ut != NULL);
    urltest_cancel(ut);
    struct loop_timer *g = loop_timer_new(g_l, on_guard, NULL);
    loop_timer_set(g, 600);
    loop_run(g_l);
    loop_timer_free(g);
    check("  после отмены обратный вызов не звался", 0, g_calls);

    /* Имя, которого нет: -1 (по отказу DNS или по сроку). */
    check("несуществующее имя — не измерилось", -1, run("http://no-such-host.invalid/", 2500, NULL));
    check("  причина: имя не разрешилось (или срок на DNS вышел)", 1,
          strstr(g_whyc, "не разрешилось") != NULL);

    /* IPv6: имя с AAAA на ::1 — запрос из сокета AF_INET6 доходит до ответчика на [::1], а тот же
     * адрес по IPv4 — нет (там ответчика на этом порту нет). Нет IPv6 на петле или имени с AAAA —
     * пропуск (стенд машины, а не движка). */
    unsigned short p6 = 0;
    int hits6 = 0;
    const char *n6 = v6_name();
    if (n6 && srv6_up(&p6, &hits6)) {
        snprintf(url, sizeof(url), "http://%s:%u/generate_204", n6, p6);
        check("IPv6: замер через AAAA — есть", 1, run_fam(url, AF_INET6, 3000, NULL) >= 0);
        check("  запрос дошёл до ответчика на [::1]", 1, hits6);
        check("  второй раз (кэш AAAA отдельно от A) — тоже", 1, run_fam(url, AF_INET6, 3000, NULL) >= 0);
    } else {
        printf("urltestmatch: IPv6 на петле нет — замер по IPv6 пропущен\n");
    }

    loop_free(g_l);
    return unit_done("urltestmatch");
}
