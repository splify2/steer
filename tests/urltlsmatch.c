/* Hello замера по https:// (src/proto/tls/urltls.c): носитель с alpn_http11.
 *
 * ЗАЧЕМ. С обычной парой «h2, http/1.1» Google и Cloudflare выбирают h2, а запрос замера — HTTP/1.1:
 * замер кончался отказом «сервер выбрал ALPN h2». Стенд urlhttps.sh этого не ловит: его сервер на
 * python ssl h2 не предлагает. Здесь смотрится не сервер, а то, ЧТО замер просит у сборщика Hello:
 * cfg.alpn == "http/1.1" и car->alpn_http11 == 1 (носитель обязателен — без него сборщик кладёт в
 * ALPN пару из облика браузера).
 *
 * Файл включает исходник urltls.c — measure статическая. Сборщик Hello, рукопожатие и цикл
 * подменены заглушками: нужна лишь фиксация того, с чем сборщик позвали (тот же приём, что в
 * tlsprobematch.c). */
#include "../src/proto/tls/urltls.c"

static int g_calls, g_carry, g_http11;
static char g_alpn[32];

int loop_fd_add(struct loop *l, int fd, uint32_t events, loop_fd_cb cb, void *arg)
                                        { (void)l; (void)fd; (void)events; (void)cb; (void)arg; return 0; }
void loop_fd_del(struct loop *l, int fd) { (void)l; (void)fd; }
const char *tls_cert_roots(void) { return NULL; }
const char *tls13_verify_reason(void) { return ""; }
void tls13_free(struct tls13 *t) { (void)t; }
int tls13_write(struct tls13 *t, const unsigned char *d, size_t n) { (void)t; (void)d; (void)n; return -1; }
int tls13_read(struct tls13 *t, unsigned char *o, size_t cap, size_t *got)
                                        { (void)t; (void)o; (void)cap; (void)got; return -1; }
int tls13_handshake_auth(struct tls13 *t, int fd, const unsigned char *h, size_t hn,
                         const unsigned char *s, const struct tls13_auth *a) {
    (void)t; (void)fd; (void)h; (void)hn; (void)s; (void)a;
    return 1;                           /* рукопожатие не нужно: Hello уже зафиксирован */
}
int reality_build_hello(const struct reality_cfg *cfg, struct reality_state *st,
                        unsigned char *out, size_t out_n, size_t *out_len) {
    (void)cfg; (void)st; (void)out; (void)out_n; (void)out_len;
    return -1;                          /* прямой вызов без носителя — это и есть регрессия */
}
int reality_build_hello_carry(const struct reality_cfg *cfg, struct reality_state *st,
                              const struct reality_carrier *car,
                              unsigned char *out, size_t out_n, size_t *out_len) {
    (void)st;
    g_calls++;
    g_carry = car != NULL;
    g_http11 = car && car->alpn_http11;
    snprintf(g_alpn, sizeof(g_alpn), "%s", cfg->alpn ? cfg->alpn : "");
    if (out_n < 100) return REALITY_ETOOBIG;
    memset(out, 0x16, 100);
    *out_len = 100;
    return 0;
}

static int fails;

static void eq(const char *what, long got, long want) {
    if (got == want) { printf("%-64s ok\n", what); return; }
    printf("%-64s БРАК: получили %ld, ждали %ld\n", what, got, want);
    fails++;
}

int main(void) {
    struct sockaddr_in sa;
    socklen_t sl = sizeof(sa);
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (ls < 0 || bind(ls, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(ls, 4) != 0 ||
        getsockname(ls, (struct sockaddr *)&sa, &sl) != 0) {
        printf("нет петлевого сокета — проверка невозможна\n");
        return 2;
    }

    struct urltls_work w;
    memset(&w, 0, sizeof(w));
    memcpy(&w.dst, &sa, sizeof(sa));
    snprintf(w.host, sizeof(w.host), "www.google.com");
    snprintf(w.path, sizeof(w.path), "/generate_204");
    w.timeout_ms = 2000;

    char why[192];
    int ms = measure(&w, why, sizeof(why));
    eq("замер дошёл до сборки Hello (один вызов)", g_calls, 1);
    eq("Hello собран с носителем", g_carry, 1);
    eq("носитель: alpn_http11", g_http11, 1);
    eq("в ALPN только http/1.1", strcmp(g_alpn, "http/1.1"), 0);
    eq("рукопожатие заглушки отклонено — замер вернул отказ", ms < 0, 1);
    close(ls);
    if (fails) { printf("urltlsmatch: БРАК (%d)\n", fails); return 1; }
    printf("urltlsmatch: всё хорошо\n");
    return 0;
}
