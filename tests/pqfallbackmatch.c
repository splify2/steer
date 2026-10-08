/* Запасной путь при потере длинного ClientHello (R-144): tr_link_open (src/proto/transport/trsec.c).
 *
 * Посредник, который молча роняет Hello с постквантовым обменом (около 1760 байт, два сегмента),
 * даёт клиенту TLS13_ETIMEOUT. Стенд ставит вместо TLS и Reality заглушки: «сервер» не отвечает
 * (ETIMEOUT) на Hello длиннее одного сегмента на узле «dpi» и отвечает на короткий. Проверяется:
 * повтор коротким, ровно один; память о решении (следующее соединение сразу коротким, без
 * таймаута); срок памяти; мёртвый узел не запоминается и не повторяется бесконечно; узел без
 * посредника сохраняет гибрид. Дальше TLS не идёт — только выбор Hello. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

#include "transport.h"
#include "reality.h"
#include "ech.h"

extern long tr_nopq_ttl_s;      /* шов trsec.c */

/* ---- заглушки -------------------------------------------------------------------- */
static char g_cur[64];
static int g_dials, g_hs, g_last_pq;

int tr_dial(const char *host, uint16_t port, int timeout_s) {
    (void)port; (void)timeout_s;
    g_dials++;
    snprintf(g_cur, sizeof g_cur, "%s", host);
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return TR_ECONNECT;
    /* Второй конец держим открытым: на закрытый send() Hello вернул бы EPIPE, а не дошёл до заглушки. */
    static int peer = -1;
    if (peer >= 0) close(peer);
    peer = sv[1];
    return sv[0];
}

int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len) {
    (void)out_n;
    memset(st, 0, sizeof *st);
    st->pq = cfg->pq;
    g_last_pq = cfg->pq;
    *out_len = cfg->pq ? 1760 : 537;
    memset(out, 0x16, *out_len);
    return 0;
}
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len)
    { (void)car; return reality_build_hello(cfg, st, out, out_n, out_len); }
/* dpi.invalid роняет длинный Hello; dead.invalid молчит на любой; прочие отвечают. */
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *ch, size_t n,
                         const unsigned char *ss, const struct tls13_auth *auth) {
    (void)t; (void)fd; (void)ch; (void)ss; (void)auth;
    g_hs++;
    if (!strcmp(g_cur, "dead.invalid")) return TLS13_ETIMEOUT;
    if ((!strcmp(g_cur, "dpi.invalid") || !strcmp(g_cur, "exp.invalid")) && n > 1400) return TLS13_ETIMEOUT;
    return 0;
}
const char *tls13_verify_reason(void) { return ""; }
const char *tls_cert_roots(void) { return NULL; }
int xc_b64url_decode(const char *in, unsigned char *out, size_t out_n)
    { (void)in; (void)out; (void)out_n; return -1; }
void tls13_free(struct tls13 *t) { (void)t; }
int ech_b64_decode(const char *in, uint8_t *out, size_t cap) { (void)in; (void)out; (void)cap; return -1; }
int ech_pick(const uint8_t *list, size_t n, struct ech_cfg *out) { (void)list; (void)n; (void)out; return ECH_ENOCONFIG; }
int ech_wrap(const struct ech_cfg *cfg, const uint8_t *hello, size_t hello_n, uint8_t *out, size_t cap,
             size_t *out_n, struct ech_state *st)
    { (void)cfg; (void)hello; (void)hello_n; (void)out; (void)cap; (void)out_n; (void)st; return ECH_ENOCONFIG; }

/* ---- стенд ----------------------------------------------------------------------- */
static int fails;
static void check(const char *what, long want, long got) {
    if (want != got) { printf("ПРОВАЛ %s: ждали %ld, получили %ld\n", what, want, got); fails++; }
    else printf("ok   %s\n", what);
}

/* Открыть связь к узлу; вернуть код, в dials/hs — сколько соединений и рукопожатий это стоило. */
static int open_to(const char *host, const char *sec, int *dials, int *hs, int *pq) {
    struct tr_node n = { .host = host, .port = 443, .type = "tcp", .security = sec,
                         .sni = "www.example.com", .fp = "chrome",
                         .pbk = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA", .sid = "0123456789abcdef" };
    struct tr_link l;
    g_dials = g_hs = 0;
    int rc = tr_link_open(&l, &n, NULL, 1);
    if (rc == 0) close(l.fd);
    *dials = g_dials; *hs = g_hs; *pq = g_last_pq;
    return rc;
}

int main(void) {
    unsetenv("STEER_NOPQ");
    int d, h, pq;

    /* Срок памяти: 0 — не помнить, каждый раз гибрид и запасной путь (два соединения). */
    tr_nopq_ttl_s = 0;
    check("срок 0: удалось", 0, open_to("exp.invalid", "reality", &d, &h, &pq));
    check("срок 0: первый раз два соединения", 2, d);
    check("срок 0: второй раз снова два соединения", 0, open_to("exp.invalid", "reality", &d, &h, &pq));
    check("срок 0: память истекла, гибрид пробуется снова", 2, d);
    tr_nopq_ttl_s = 3600;

    /* Узел без посредника: гибрид остаётся, повтора нет. */
    check("чистый узел: рукопожатие удалось", 0, open_to("ok.invalid", "reality", &d, &h, &pq));
    check("чистый узел: одно соединение", 1, d);
    check("чистый узел: Hello с гибридом", 1, pq);

    /* Посредник роняет длинный Hello: первая попытка таймаут, вторая — коротким. */
    check("dpi: удалось через запасной путь", 0, open_to("dpi.invalid", "reality", &d, &h, &pq));
    check("dpi: ровно два соединения (один повтор)", 2, d);
    check("dpi: два рукопожатия", 2, h);
    check("dpi: последний Hello без гибрида", 0, pq);

    /* Память: следующее соединение сразу коротким, без таймаута и без повтора. */
    check("dpi, второй раз: удалось", 0, open_to("dpi.invalid", "reality", &d, &h, &pq));
    check("dpi, второй раз: одно соединение", 1, d);
    check("dpi, второй раз: сразу без гибрида", 0, pq);
    /* Память — по узлу: другой узел за тем же посредником не наследует решение. */
    check("другой узел: гибрид, как был", 0, open_to("ok.invalid", "tls", &d, &h, &pq));
    check("другой узел: гибрид предложен", 1, pq);

    /* Мёртвый узел: один повтор, не цикл, и в память не попадает. */
    check("dead: отказ таймаутом", TLS13_ETIMEOUT, open_to("dead.invalid", "reality", &d, &h, &pq));
    check("dead: ровно два соединения", 2, d);
    check("dead, второй раз: снова два соединения (запоминать нечего)", TLS13_ETIMEOUT,
          open_to("dead.invalid", "reality", &d, &h, &pq));
    check("dead, второй раз: два соединения", 2, d);

    /* security=none: Hello нет, повтора нет. */
    check("none: удалось", 0, open_to("ok.invalid", "none", &d, &h, &pq));
    check("none: одно соединение, TLS не трогали", 10, d * 10 + h);

    /* STEER_NOPQ: гибрида нет с самого начала, повтора тоже. */
    setenv("STEER_NOPQ", "1", 1);
    check("STEER_NOPQ: чистый узел, Hello без гибрида", 0, open_to("ok.invalid", "reality", &d, &h, &pq));
    check("STEER_NOPQ: без гибрида", 0, pq);
    check("STEER_NOPQ: мёртвый узел — одно соединение", TLS13_ETIMEOUT,
          open_to("dead.invalid", "reality", &d, &h, &pq));
    check("STEER_NOPQ: повтора нет", 1, d);

    printf(fails ? "pqfallbackmatch: ПРОВАЛОВ %d\n" : "pqfallbackmatch: всё сошлось\n", fails);
    return fails ? 1 : 0;
}
