/* Разбор пакетов туннеля VLESS без сети: handle_packet и его соседи на подменённом клиенте.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Стенды tests/run-tunnel*.sh гоняют туннель целиком, но до
 * некоторых дорожек не достают: закрытое окно HTTP/2 (SEND_AGAIN) бывает только у grpc и
 * xhttp, а у поддельного сервера стенда транспорт голый tcp; отказ создания установщиков
 * нельзя вызвать по заказу; номер адреса устройства зависит от записи в реестре. Здесь все
 * эти случаи задаются руками, а смотрится то, что видно снаружи: пакеты, ушедшие в
 * устройство, и то, осталось ли соединение живым.
 *
 * КАК. Стенд включает стек туннеля src/tunnel/stack.c целиком (всё нужное в нём статическое),
 * берёт настоящий дайлер VLESS (src/proto/vless/vldial.c: заголовок, Vision, разбор ответа) и
 * подменяет под ним соединение с узлом: vless_connect и transport_* отвечают так, как велит
 * проверка. До шага 2 выпуска 1.10 стек и VLESS были одним файлом (tunnel.c), и подменялся
 * клиент VLESS — граница подмены осталась той же, изменились только имена. Устройство —
 * сокетная пара: что туннель пишет в «TUN», стенд читает с другого конца и разбирает тем же
 * ip_parse. Дескриптор «сессии» — канал с непрочитанным байтом: poll на нём всегда видит
 * готовность к чтению, а читает из него только подменённый транспорт, то есть никто.
 *
 * ОТКАЗ СОЗДАНИЯ ПОТОКОВ (I-322). Прежде его давал сам glibc: таблица соединений жила в
 * __thread, около 14 МБ на поток, glibc кладёт статический TLS в стек потока, и установщик со
 * стеком 128 КБ не создавался. Теперь таблица в куче (см. «таблицы потока» в stack.c), TLS
 * маленький, и отказ стенд делает сам: пока велено (g_refuse_threads), подменённый
 * pthread_attr_setstacksize просит невозможный стек, и pthread_create отказывает — на любой
 * libc, а не только там, где TLS случайно не влез.
 *
 * Сетей, прав и криптобиблиотеки не нужно: типов библиотеки в заголовках нет (они видят только
 * src/lib/scrypto.h), поэтому и заглушки заголовков не нужны, а всё, что требует TLS, подменено.
 * Поэтому стенд живёт в `make test`.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/uio.h>

/* ---- стек установщиков --------------------------------------------------------- */

static int g_refuse_threads;

int pthread_attr_setstacksize(pthread_attr_t *a, size_t s) {
    static int (*real)(pthread_attr_t *, size_t);
    if (!real) real = (int (*)(pthread_attr_t *, size_t))dlsym(RTLD_NEXT,
                                                               "pthread_attr_setstacksize");
    /* 2^62 байт — больше любого адресного пространства: отображение под стек не выделится, и
     * pthread_create вернёт отказ, не создав потока. */
    if (g_refuse_threads) s = (size_t)1 << 62;
    return real(a, s);
}

/* ---- счёт poll ------------------------------------------------------------------ */

/* Проход чтения у узла (drain_conn_reads) не спрашивает poll перед каждым чтением: чтение дайлера
 * не ждёт само. Стенд считает вызовы poll, чтобы это было видно: вызов за каждое чтение — это
 * ~2 % цикла и 36-116 системных вызовов на МБ (замер профилировщика). */
static int g_poll_calls;

int poll(struct pollfd *fds, nfds_t n, int timeout) {
    static int (*real)(struct pollfd *, nfds_t, int);
    g_poll_calls++;
    if (!real) real = (int (*)(struct pollfd *, nfds_t, int))dlsym(RTLD_NEXT, "poll");
    return real(fds, n, timeout);
}

/* ---- счёт writev ---------------------------------------------------------------------- */

/* Запись клиенту (sock_flush) — одним writev по кольцу недописанного за проход. Стенд считает вызовы:
 * запись на каждое чтение у узла стоила бы системного вызова и отправки TCP на каждые 16 КБ. */
static int g_writev_calls;

ssize_t writev(int fd, const struct iovec *iov, int n) {
    static ssize_t (*real)(int, const struct iovec *, int);
    g_writev_calls++;
    if (!real) real = (ssize_t (*)(int, const struct iovec *, int))dlsym(RTLD_NEXT, "writev");
    return real(fd, iov, n);
}

/* ---- сон установщика ----------------------------------------------------------- */

/* connq_release ждёт доклада установщиков сном по 10 мс до 15 с. Проверке I-193 нужен не
 * срок, а то, что решается после ПОСЛЕДНЕГО сна: сны не спят, а на заданном по счёту
 * «докладывает» заявка g_sleep_c. Вне проверки — настоящий сон. */
static int g_sleep_hook;
static int g_sleep_n;
static int g_sleep_report_at;
static int *g_sleep_c;             /* поле done заявки, которая «доложит» */

int nanosleep(const struct timespec *req, struct timespec *rem) {
    static int (*real)(const struct timespec *, struct timespec *);
    if (g_sleep_hook) {
        if (++g_sleep_n == g_sleep_report_at && g_sleep_c)
            __atomic_store_n(g_sleep_c, 1, __ATOMIC_RELEASE);
        return 0;
    }
    if (!real) real = (int (*)(const struct timespec *, struct timespec *))dlsym(RTLD_NEXT,
                                                                           "nanosleep");
    return real(req, rem);
}

/* ---- подменённое окружение движка ---------------------------------------------- */

static char g_cmd[16][256];
static int  g_cmd_n;

int run_quiet(const char *const argv[]) {
    char joined[256];
    size_t jn = 0;
    for (int i = 0; argv[i] && jn < sizeof(joined) - 2; i++)
        jn += (size_t)snprintf(joined + jn, sizeof(joined) - jn, i ? " %s" : "%s", argv[i]);
    if (g_cmd_n < 16) snprintf(g_cmd[g_cmd_n++], sizeof(g_cmd[0]), "%s", joined);
    return 0;
}

#include "../src/model/spec.h"
/* Заглушки bind_device здесь больше нет: с 1.10 (шаг 3) стек маршрут не привязывает — это работа
 * демона по up с именем устройства (src/daemon/supd.c, route_up), и стек без failover.c
 * компонуется сам. Вернись вызов в stack.c — стенд не соберётся, и это нарочно. */

#include "jsonw.h"
#include "../src/tunnel/stack.c"
#include "vldial.h"
#include "client.h"
#include "../src/tunnel/pool.c"

/* ---- подменённое соединение с узлом -------------------------------------------- */

static int g_sess_pipe[2] = { -1, -1 };
static int g_send_rc;                 /* что вернёт transport_write: 0 или H2_EWINDOW */
static int g_send_again_n;            /* столько раз подряд вернуть H2_EWINDOW, потом 0 */
static int g_send_calls;              /* сколько раз вызван transport_write */
static size_t g_send_last_n;          /* длина последнего transport_write */
static size_t g_send_max_n;           /* самая длинная запись с последнего обнуления стендом */
/* Место у узла (transport_room): -1 — без предела. g_room_on_read, если не -2, станет местом при
 * следующем чтении, как его сделал бы прочитанный у узла WINDOW_UPDATE. */
static long g_room = -1;
static long g_room_on_read = -2;
static int g_recv_calls;
static int g_recv_rc;                 /* что вернёт transport_read_zc: 0 или -1 (конец потока) */
static unsigned char g_recv_buf[TUNNEL_BUF];
static size_t g_recv_n;               /* сколько отдать при g_recv_rc == 0 (разово) */
/* Поток-образец для проверки склейки записей клиенту: g_recv_rep раз подряд по g_recv_rep_n байт,
 * байт номер i потока равен (i * 7 + i / 251), чтобы сдвиг или порча на краю кольца были видны. */
static int g_recv_rep;
static size_t g_recv_rep_n;
static int g_recv_empty;              /* сколько первых чтений вернут 0 байт при коде 0 — как съеденный служебный кадр */
static size_t g_stream_pos;
static unsigned char stream_byte(size_t i) { return (unsigned char)(i * 7 + i / 251); }

int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    (void)node; (void)timeout_s;
    memset(conn, 0, sizeof(*conn));
    conn->link.fd = g_sess_pipe[0];
    conn->link.plain = 1;
    return 0;
}
/* Что ушло узлу, подряд — ради стенда переупорядочивания: байты обязаны уйти в порядке потока. */
static unsigned char g_sent[65536];
static size_t g_sent_n;
int transport_write(struct transport *c, const unsigned char *d, size_t n) {
    (void)c;
    g_send_calls++;
    g_send_last_n = n;
    if (n > g_send_max_n) g_send_max_n = n;
    if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
    if (g_send_rc == 0 && g_sent_n + n <= sizeof(g_sent)) { memcpy(g_sent + g_sent_n, d, n); g_sent_n += n; }
    return g_send_rc;
}
int transport_read_zc(struct transport *c, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    (void)c; (void)buf; (void)cap;
    g_recv_calls++;
    if (g_room_on_read != -2) { g_room = g_room_on_read; g_room_on_read = -2; }
    *got = 0;
    if (g_recv_rc) return g_recv_rc;
    if (g_recv_empty > 0) { g_recv_empty--; *data = g_recv_buf; return 0; }
    if (!g_recv_n && g_recv_rep > 0) {
        for (size_t i = 0; i < g_recv_rep_n; i++) g_recv_buf[i] = stream_byte(g_stream_pos + i);
        g_stream_pos += g_recv_rep_n;
        g_recv_n = g_recv_rep_n;
        g_recv_rep--;
    }
    *data = g_recv_buf;
    *got = g_recv_n;
    g_recv_n = 0;
    return 0;
}
int transport_has_data(const struct transport *c) { (void)c; return 0; }
/* Вторая связь транспорта (transport_aux_fd): дескриптор, который назовёт стенд, и что случится при
 * сливе — место у узла вырастет (g_room_on_aux, как от ответа на кусок) и вернётся g_aux_rc. */
static int g_aux_fd = -1;
static int g_aux_drains;
static int g_aux_rc;
static long g_room_on_aux = -2;
int transport_aux_fd(const struct transport *c) { (void)c; return g_aux_fd; }
int transport_aux_drain(struct transport *c) {
    (void)c;
    char b[64];
    ssize_t r = g_aux_fd >= 0 ? read(g_aux_fd, b, sizeof(b)) : 0;
    (void)r;
    g_aux_drains++;
    if (g_room_on_aux != -2) { g_room = g_room_on_aux; g_room_on_aux = -2; }
    return g_aux_rc;
}
long transport_room(struct transport *c) { (void)c; return g_room; }
/* Принимает ли транспорт запись любой длины (xhttp packet-up). */
static int g_big_write;
int transport_big_write(const struct transport *c) { (void)c; return g_big_write; }
void transport_close(struct transport *c) { c->link.fd = -1; }   /* канал общий — не закрываем */
void transport_moved(struct transport *c) { (void)c; }
void transport_direct(struct transport *c) { c->link.rx_direct = 1; }
const char *vless_strerror(int rc) { (void)rc; return "подмена"; }
int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; return -1;
}
int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    (void)node; (void)timeout_s; (void)why; (void)why_n; (void)handshake_ms; (void)ttfb_ms;
    return -1;
}

/* ---- устройство и пакеты клиента ----------------------------------------------- */

static struct tun_dev g_tun;
static int g_dev_peer = -1;           /* второй конец «TUN»: сюда приходит написанное туннелем */
static struct vless_node g_node;
/* Дайлер стека: настоящий VLESS к узлу стенда. ctx подменяется на время проверки негодного
 * узла (syn_bad) — так же, как прежде туда уходил другой узел аргументом handle_packet. */
static struct dialer g_dial = { .ops = &vless_dialer, .ctx = &g_node };

#define CLI_IP  0x0164330au           /* 10.51.100.1 в сетевом порядке — как читает ip_parse */
#define SRV_IP  0x0771cbcbu
#define CLI_PORT 40000
#define SRV_PORT 443

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-72s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

/* ---- сторона клиента: сокет (R-152) ---------------------------------------------------------- */

/* TCP клиентов завершает ядро: соединение приходит в модуль принятым сокетом (kaccept → conn_accept),
 * назначение — у ядра (SO_ORIGINAL_DST). Стенд задаёт его сам: сторона клиента — пара сокетов, один конец
 * принимает conn_accept, второй — «клиент», у которого стенд пишет и читает. AF_UNIX — для данных (буфер
 * ядра известен и велик), TCP на петле — когда важно различие RST и FIN (conn_reset закрывает с SO_LINGER 0:
 * по AF_UNIX клиент этого не увидит). Готовность по фронту epoll (CRD) стенд ставит сам, как событие. */
#define TEST_SLOTS 320                /* потолок слотов стенда: полная таблица достижима за мгновение */
static int g_cfd[TEST_SLOTS];          /* клиентский конец сокета соединения по номеру слота; -1 — нет */

static int cli_pair_unix(int sv[2]) {
    return socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv);
}

static int cli_pair_tcp(int sv[2]) {
    int l = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (l < 0) return -1;
    if (bind(l, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(l, 1) != 0 ||
        getsockname(l, (struct sockaddr *)&sa, &sl) != 0) { close(l); return -1; }
    int c = socket(AF_INET, SOCK_STREAM, 0);
    if (c < 0 || connect(c, (struct sockaddr *)&sa, sizeof sa) != 0) { close(l); if (c >= 0) close(c); return -1; }
    int a = accept(l, NULL, NULL);
    close(l);
    if (a < 0) { close(c); return -1; }
    fcntl(a, F_SETFL, fcntl(a, F_GETFL) | O_NONBLOCK);
    fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
    sv[0] = a; sv[1] = c;
    return 0;
}

/* Принять srv как соединение клиента CLI_IP:sport -> dst:443; cli — клиентский конец. NULL — соединения нет
 * (conn_accept закрыл srv сам); клиентский конец тогда закрывается здесь. */
static struct conn *sock_conn_fd(int srv, int cli, uint16_t sport, uint32_t dst) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src = CLI_IP; k.dst = dst; k.sport = sport; k.dport = SRV_PORT; k.proto = 6;
    struct conn *c = conn_accept(srv, &k, &g_tun);
    if (!c) { close(cli); return NULL; }
    size_t i = (size_t)(c - g_conns);
    if (g_cfd[i] >= 0) close(g_cfd[i]);
    g_cfd[i] = cli;
    return c;
}

static struct conn *sock_conn(uint16_t sport, uint32_t dst) {
    int sv[2];
    return cli_pair_unix(sv) == 0 ? sock_conn_fd(sv[0], sv[1], sport, dst) : NULL;
}

static struct conn *sock_conn_tcp(uint16_t sport, uint32_t dst) {
    int sv[2];
    return cli_pair_tcp(sv) == 0 ? sock_conn_fd(sv[0], sv[1], sport, dst) : NULL;
}

static int cli_fd(const struct conn *c) { return g_cfd[c - g_conns]; }

/* Клиент пишет в сокет; ядро сообщило бы о данных событием epoll — стенд ставит готовность (CRD) сам. */
static void cli_put(struct conn *c, const void *d, size_t n) {
    int fd = cli_fd(c);
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, (const char *)d + off, n - off);
        if (w > 0) off += (size_t)w;
        else if (w < 0 && errno == EINTR) continue;
        else break;
    }
    if (off != n) check(0, "стенд: клиент не смог записать в свой сокет");
    c->carmed |= CRD;
}

/* Всё, что дошло до клиента (до cap байт). */
static size_t cli_get(int fd, unsigned char *buf, size_t cap) {
    size_t n = 0;
    while (n < cap) {
        ssize_t r = read(fd, buf + n, cap - n);
        if (r > 0) n += (size_t)r;
        else if (r < 0 && errno == EINTR) continue;
        else break;
    }
    return n;
}

/* Сколько байт лежит в сокете непрочитанным (fd — клиентский конец: дошедшее до клиента). */
static int cli_pending(int fd) {
    int n = 0;
    if (ioctl(fd, FIONREAD, &n) != 0) return -1;
    return n;
}

/* Сколько байт клиента лежит в принятом сокете, не прочитанное стеком. */
static int srv_pending(const struct conn *c) { return cli_pending(conn_cfd(c)); }

/* Чем кончилось для клиента, когда он вычитал всё: 0 — соединение открыто, 1 — FIN (EOF), 2 — RST. */
static int cli_end(int fd) {
    unsigned char b[4096];
    for (;;) {
        ssize_t r = read(fd, b, sizeof b);
        if (r > 0) continue;
        if (r == 0) return 1;
        if (errno == EINTR) continue;
        return errno == ECONNRESET ? 2 : 0;
    }
}

/* То, что делает цикл по событию сокета клиента: готовность + чтение, если узел принимает. */
static void cli_pump(struct conn *c) {
    c->carmed |= CRD;
    if (c->used && sock_want_read(c)) sock_read(c, &g_tun);
}

/* Образец потока клиента узлу: байт i = (i * 13 + i / 7). */
static void up_fill(unsigned char *p, size_t n, size_t from) {
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)((from + i) * 13 + (from + i) / 7);
}

/* Сколько байт буфера не совпало с потоком-образцом узла (stream_byte), начиная с позиции pos. */
static int stream_bad(const unsigned char *b, size_t n, size_t pos) {
    int bad = 0;
    for (size_t i = 0; i < n; i++)
        if (b[i] != stream_byte(pos + i)) bad++;
    return bad;
}

/* Вычитать всё, что туннель написал в устройство. Возвращает число пакетов, в last — ключ
 * последнего (там номер подтверждения). */
static int dev_drain(struct flow_key *last) {
    unsigned char p[70000];
    int cnt = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) { if (last) *last = k; cnt++; }
    }
    return cnt;
}

static struct flow_key cli_key(void) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src = CLI_IP; k.dst = SRV_IP; k.sport = CLI_PORT; k.dport = SRV_PORT; k.proto = 6;
    return k;
}

/* То, что делает цикл по готовности заявки (worker_loop): ждать установщика до срока. */
static int wait_ready(struct conn *c, int ms) {
    for (int i = 0; i < ms; i++) {
        if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE)) {
            c->pending = 0;
            c->fd = g_dl->ops->fd(SESS(c));
            if (c->early) early_flush(c);
            return 0;
        }
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    return -1;
}

/* Соединение до «поток готов и сервер ответил заголовком и 1000 байт», ответ у клиента вычитан. */
static struct conn *ready_conn(struct conn *c) {
    if (!c || !c->pending || wait_ready(c, 2000) != 0) return NULL;
    g_recv_rc = 0;
    g_recv_buf[0] = 0; g_recv_buf[1] = 0;                 /* ответ VLESS: версия, длина доп. */
    memset(g_recv_buf + 2, 'r', 1000);
    g_recv_n = 1002;
    drain_conn(c, &g_tun);
    unsigned char b[2000];
    size_t got = cli_get(cli_fd(c), b, sizeof b);
    /* Стенд сам себя проверяет: без этого «провал» мог бы означать сломанную подготовку.
     * «Ответ VLESS снят» — состояние дайлера, оно в его сессии. */
    const struct vl_sess *vs = SESS(c);
    if (!vs->established || got != 1000 || c->srv_closed || c->rtx.len) return NULL;
    g_sent_n = 0;
    return c;
}

static struct conn *open_conn(void) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    return ready_conn(sock_conn(CLI_PORT, SRV_IP));
}

/* ---- проверки ------------------------------------------------------------------ */

/* I-322: установщиков не создалось ни одного. Прежде очередь считалась запущенной, SYN
 * получал SYN-ACK, а заявка висела pending навсегда — ни RST, ни повторной попытки. Теперь соединение
 * принято сокетом: без установщиков оно сбрасывается сразу, RST — клиенту. */
static void t_no_connectors(void) {
    g_refuse_threads = 1;
    struct flow_key k = cli_key();
    int sv[2];
    if (cli_pair_tcp(sv) != 0) { check(0, "I-322: стенд — пара сокетов"); return; }
    struct conn *c = conn_accept(sv[0], &k, &g_tun);
    int end = cli_end(sv[1]);
    close(sv[1]);
    check(!c && !conn_find(&k) && end == 2,
          "I-322: без установщиков соединение сброшено сразу (клиенту RST), заявка не висит");
    if (c) conn_drop(c);

    /* Стек дали — следующее соединение обязано получить установщика: отказ не залипает. */
    g_refuse_threads = 0;
    c = sock_conn(CLI_PORT, SRV_IP);
    check(c && c->pending && wait_ready(c, 2000) == 0,
          "I-322: после отказа установщики заводятся на следующем соединении");
    if (c) conn_drop(c);
}

/* R-152: TCP в устройство не несётся — его завершает ядро на слушателе модуля. Попавший в TUN пакет TCP
 * (перенаправления ещё нет или раскладка старого ядра) получает сброс, а не тишину; соединения в таблице
 * не заводится и установщик не просится. RST клиента отвечать не надо. */
static void t_tcp_tun_rst(void) {
    struct flow_key k = cli_key(), last;
    unsigned char p[128];
    dev_drain(NULL);
    int live0 = g_live_n;
    unsigned head0 = g_cq.head;
    unsigned long long rst0 = g_tcp_tun_rst;

    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1000, 0, TCP_SYN, NULL, 0,
                         65535, 1460, -1);
    handle_packet(&g_tun, p, l);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_RST) && (last.tcp_flags & TCP_ACK) && last.ack == 1001 &&
          last.seq == 0 && last.src == SRV_IP && last.dst == CLI_IP && last.sport == SRV_PORT &&
          last.dport == CLI_PORT,
          "TCP в устройстве: SYN получает RST+ACK с номером подтверждения ISN + 1 от имени сервера");
    check(g_tcp_tun_rst == rst0 + 1, "TCP в устройстве: счётчик g_tcp_tun_rst вырос");
    check(!conn_find(&k) && g_live_n == live0 && g_cq.head == head0,
          "TCP в устройстве: соединение в таблицу не заводится, установщик не просится");

    /* Данные и подтверждение: RST с номером из подтверждения (RFC 793, 3.4). */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1001, 777, TCP_ACK | TCP_PSH, d,
                  sizeof(d) - 1, 65535, 0, -1);
    handle_packet(&g_tun, p, l);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_RST) && last.seq == 777 && last.ack == 1001 + sizeof(d) - 1 &&
          g_tcp_tun_rst == rst0 + 2 && !conn_find(&k),
          "TCP в устройстве: данные тоже получают RST с его номером подтверждения");

    /* RST клиента — без ответа и без счёта. */
    l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1001, 0, TCP_RST, NULL, 0, 0, 0, -1);
    handle_packet(&g_tun, p, l);
    check(dev_drain(NULL) == 0 && g_tcp_tun_rst == rst0 + 2, "TCP в устройстве: RST клиента — без ответа");
}

/* I-322: номер адреса устройства из таблицы выхода. Таблица приходит из файла реестра, и
 * отрицательное число оттуда давало адрес 198.51.100.-N. */
static void t_bring_up_table(void) {
    g_cmd_n = 0;
    int save = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    tun_bring_up("vl", -7);
    fflush(stderr);
    dup2(save, 2); close(save); close(nul);
    int host = -1;
    const char *p = g_cmd_n ? strstr(g_cmd[0], "198.51.100.") : NULL;
    if (p) host = atoi(p + 11);
    check(host >= 1 && host <= 200, "I-322: таблица -7 даёт адрес 198.51.100.1..200");
}

/* I-323 и I-320: поток к узлу ставится, пока клиент уже пишет. Данные клиента лежат в его сокете — окно
 * держит ядро — и узлу не уходят, пока поток не готов; после готовности уходят все, по порядку, байт в байт. */
static void t_early_wait(void) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    g_sent_n = 0;
    c = sock_conn(CLI_PORT, SRV_IP);
    if (!c || !c->pending) { check(0, "ранние данные: соединение не принято"); return; }
    static unsigned char d[20000], got[20000 + 64];
    up_fill(d, sizeof d, 0);
    int calls = g_send_calls;
    cli_put(c, d, sizeof d);
    check(c->pending && c->early_n == 0 && g_send_calls == calls &&
          srv_pending(c) == (int)sizeof d,
          "ранние данные: пока поток ставится, клиент пишет в сокет — узлу ничего, в таблице ничего не копится");
    check(wait_ready(c, 2000) == 0 && !c->pending && g_send_calls == calls,
          "ранние данные: поток готов — узлу по-прежнему ничего, пока цикл не прочитает сокет");
    conn_deadlines(c, &g_tun, c->estab_ns + 1);
    memcpy(got, g_sent, g_sent_n < sizeof got ? g_sent_n : sizeof got);
    check(c->used && g_sent_n == 26 + sizeof d && memcmp(got + 26, d, sizeof d) == 0 &&
          c->sent_any && srv_pending(c) == 0,
          "ранние данные: после готовности ушло всё накопленное — заголовок и 20000 байт, порядок и содержимое целы");
    conn_drop(c);
}

/* I-320: узел не принимает (окно HTTP/2 закрыто, SEND_AGAIN). Принятое у клиента не теряется и не
 * переставляется: остаток ждёт в буфере (early), сокет клиента не читается, пока он не ушёл, — окно клиенту
 * держит ядро. Узел снова принимает — уходит остаток, потом то, что клиент дописал за это время. */
static void t_sendagain_hold(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    static unsigned char d1[3000], d2[5000], want[8000];
    up_fill(d1, sizeof d1, 0);
    up_fill(d2, sizeof d2, 3000);
    memcpy(want, d1, sizeof d1);
    memcpy(want + sizeof d1, d2, sizeof d2);
    g_send_rc = H2_EWINDOW;
    cli_put(c, d1, sizeof d1);
    cli_pump(c);
    check(c->early_n == sizeof d1 && !sock_want_read(c) && g_sent_n == 0,
          "I-320: узел не принял — данные клиента остались у стека (early), сокет читать не просят");
    cli_put(c, d2, sizeof d2);
    cli_pump(c);
    check(c->early_n == sizeof d1 && srv_pending(c) == (int)sizeof d2,
          "I-320: пока остаток не ушёл, свежие данные клиента остаются в его сокете (порядок байт дороже скорости)");
    cli_pump(c);                                            /* повторное событие: ничего не меняет */
    check(c->early_n == sizeof d1 && srv_pending(c) == (int)sizeof d2, "  и повторное событие их не трогает");

    g_send_rc = 0;
    conn_deadlines(c, &g_tun, c->estab_ns + 1);
    check(c->used && !c->early && g_sent_n == 26 + sizeof want && memcmp(g_sent + 26, want, sizeof want) == 0 &&
          srv_pending(c) == 0,
          "I-320: узел принял — сначала остаток, потом дописанное клиентом: 8000 байт по порядку, без потерь и повторов");

    /* Остаток уходит и когда узел принимает не с первой попытки (SEND_AGAIN несколько раз подряд). */
    g_sent_n = 0;
    g_send_again_n = 2;
    cli_put(c, d1, sizeof d1);
    cli_pump(c);
    check(c->early_n == sizeof d1, "I-320: отказ узла — остаток снова в early");
    conn_deadlines(c, &g_tun, c->estab_ns + 1);             /* второй отказ */
    check(c->early_n == sizeof d1 && g_sent_n == 0, "  второй отказ — остаток цел");
    conn_deadlines(c, &g_tun, c->estab_ns + 1);             /* принял */
    check(!c->early && g_sent_n == sizeof d1 && memcmp(g_sent, d1, sizeof d1) == 0,
          "  и принятый наконец остаток уходит целиком");
    g_send_again_n = 0;
    conn_drop(c);
}

/* Сокет клиента полон (клиент не читает): у узла не читаем больше, чем уместится в кольцо недописанного
 * (client_can_take_record), — прочитанное за кольцо было бы потеряно. Клиент читает — остаток дописывается
 * (sock_flush по EPOLLOUT), чтение у узла возобновляется, и поток доходит целиком, по порядку. */
static void fill_client(struct conn *c, int *total_reads) {
    g_stream_pos = 0;
    g_recv_rep = 100; g_recv_rep_n = 4000;                  /* 400000 байт у узла */
    int calls = g_recv_calls;
    drain_conn_reads(c, &g_tun);                            /* читает, пока кольцу есть куда; записи клиенту нет */
    *total_reads = g_recv_calls - calls;
}

static void t_client_full(void) {
    int sv[2];
    if (cli_pair_unix(sv) != 0) { check(0, "стенд: пара сокетов"); return; }
    int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);   /* принимает мало: клиент не читает */
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    c = ready_conn(sock_conn_fd(sv[0], sv[1], CLI_PORT, SRV_IP));
    if (!c) { check(0, "кольцо и сокет клиента: соединение не открылось"); return; }

    int reads;
    fill_client(c, &reads);
    size_t read_from_node = g_stream_pos;
    check(c->used && !c->srv_closed && !client_can_take_record(c) && c->rtx.len <= RTX_CAP &&
          c->rx_ready && read_from_node < 100 * 4000 && read_from_node == c->rtx.len,
          "сокет клиента полон: прочитанное у узла лежит в кольце целиком — ничего не потеряно, остальное у узла");
    check(RTX_CAP - c->rtx.len < CLIENT_ROOM_RESERVE && reads >= 2 && reads < 100,
          "  и остановились, как только в кольце не стало места под целую запись (client_can_take_record)");
    sock_flush(c);
    check(c->rtx.len > 0 && read_from_node == c->rtx.len + (size_t)cli_pending(cli_fd(c)),
          "  сокет принял сколько мог (4 КБ буфера), остаток ждёт EPOLLOUT: кольцо и сокет вместе — всё прочитанное");

    /* Клиент читает: остаток дописывается по готовности записи, чтение у узла возобновляется (как в цикле:
     * у узла читаем, только когда кольцо принимает целую запись). */
    static unsigned char buf[400000 + 64];
    size_t got = 0;
    int resumed = 0;
    for (int it = 0; it < 400 && g_stream_pos < 400000; it++) {
        got += cli_get(cli_fd(c), buf + got, sizeof(buf) - got);
        c->carmed |= CWR;
        if (c->rtx.len) sock_flush(c);
        if (client_can_take_record(c)) { drain_conn(c, &g_tun); resumed++; }
    }
    for (int it = 0; it < 50 && (c->rtx.len || cli_pending(cli_fd(c))); it++) {
        got += cli_get(cli_fd(c), buf + got, sizeof(buf) - got);
        c->carmed |= CWR;
        if (c->rtx.len) sock_flush(c);
    }
    got += cli_get(cli_fd(c), buf + got, sizeof(buf) - got);
    check(g_stream_pos == 400000 && got == 400000 && stream_bad(buf, got, 0) == 0 && c->rtx.len == 0,
          "после чтения клиентом дописан весь остаток: 400000 байт, порядок и содержимое целы");
    check(resumed > 0 && g_overemit == 0, "  чтение у узла возобновлялось при месте в кольце, нарушений договора нет");
    g_recv_rep = 0;
    conn_drop(c);
}

/* I-320, закрытие сервером: узел закрыл поток, а клиенту не всё дописано (сокет полон). Соединение живёт, пока
 * клиент не примет остаток (до CLOSE_DRAIN_MS), и закрывается только после него. */
static void t_srv_close_drain(void) {
    int sv[2];
    if (cli_pair_unix(sv) != 0) { check(0, "стенд: пара сокетов"); return; }
    int small = 4096;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    c = ready_conn(sock_conn_fd(sv[0], sv[1], CLI_PORT, SRV_IP));
    if (!c) { check(0, "закрытие сервером: соединение не открылось"); return; }
    int cfd = cli_fd(c);
    g_stream_pos = 0;
    g_recv_rep = 12; g_recv_rep_n = 4000;                   /* 48000 байт: клиент их сразу не примет */
    drain_conn(c, &g_tun);
    g_recv_rc = -1;                                         /* и узел закрыл поток */
    drain_conn(c, &g_tun);
    g_recv_rc = 0;
    g_recv_rep = 0;
    check(c->srv_closed && !c->aborted && c->rtx.len > 0,
          "I-320: узел закрыл поток, клиенту не всё дописано — srv_closed, остаток ждёт в кольце");
    int alive = conn_deadlines(c, &g_tun, c->closed_at + 1000000ull) == 0 && c->used;
    check(alive, "  пока клиент не принял остаток, соединение живо (CLOSE_DRAIN_MS не вышел)");
    static unsigned char buf[48000 + 64];
    size_t got = 0;
    int closed = 0;
    for (int it = 0; it < 2000 && !closed; it++) {
        got += cli_get(cfd, buf + got, sizeof(buf) - got);
        c->carmed |= CWR;
        closed = conn_deadlines(c, &g_tun, c->closed_at + 1000000ull) != 0;
        if (!closed) usleep(1000);
    }
    got += cli_get(cfd, buf + got, sizeof(buf) - got);
    int end = cli_end(cfd);
    check(closed && got == 48000 && stream_bad(buf, got, 0) == 0 && end == 1,
          "  клиент принял остаток — 48000 байт целиком, затем закрытие (EOF)");
}

/* I-193: установщик доложил за время ПОСЛЕДНЕГО сна ожидания. Прежде проверка стояла перед
 * сном, результат последнего не спрашивался, и приговор «не доложил за 15 с» ставился по
 * счётчику кругов — таблица при этом намеренно не освобождается. */
static void t_release_last_sleep(void) {
    struct conn *c = &g_conns[g_nslots - 1];
    struct conn save = *c;
    c->used = 1;
    c->pending = 1;
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    g_sleep_c = (int *)&c->done;
    g_sleep_n = 0;
    g_sleep_report_at = 1500;
    g_sleep_hook = 1;
    int save_err = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    int rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == 0, "I-193: доклад за последний сон ожидания принят, таблица освобождается");

    /* И обратное: не доложил вовсе — приговор прежний. */
    __atomic_store_n(&c->done, 0, __ATOMIC_RELEASE);
    c->pending = 1;
    g_sleep_n = 0;
    g_sleep_report_at = 0;
    g_sleep_hook = 1;
    save_err = dup(2); nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    rc = connq_release(g_conns);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    g_sleep_hook = 0;
    check(rc == -1 && g_sleep_n == 1500, "I-193: не доложивший за 15 с — отказ, снов 1500");
    g_sleep_c = NULL;
    *c = save;
}

/* Выполнить f с stderr в файл и вернуть, нашлась ли в написанном строка needle. */
static int stderr_has(void (*f)(void *), void *arg, const char *needle) {
    char path[] = "/tmp/tunnelmatch-err.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return 0;
    fflush(stderr);
    int save = dup(2);
    dup2(fd, 2);
    f(arg);
    fflush(stderr);
    dup2(save, 2); close(save);
    char buf[4096];
    ssize_t r = pread(fd, buf, sizeof(buf) - 1, 0);
    close(fd); unlink(path);
    buf[r > 0 ? r : 0] = 0;
    return strstr(buf, needle) != NULL;
}

static void syn_bad(void *arg) {
    struct vless_node *bad = arg;
    struct flow_key k = cli_key();
    int sv[2];
    if (cli_pair_unix(sv) != 0) return;
    g_dial.ctx = bad;
    struct conn *c = conn_accept(sv[0], &k, &g_tun);
    g_dial.ctx = &g_node;
    if (c) conn_drop(c);
    close(sv[1]);
}

static int g_run_rc;
static void run_bad(void *arg) {
    struct output o;
    memset(&o, 0, sizeof(o));
    /* Имя длиннее 15 символов: tun_open откажет и сам, так что устройство не появится ни до
     * правки, ни после — различается только названа ли причина. */
    snprintf(o.device, sizeof(o.device), "tunnelmatch-no-such-dev");
    /* Подъём — на пуле узлов (src/tunnel/pool.h): первый активный узел — негодный. */
    struct pool_cfg pc;
    memset(&pc, 0, sizeof(pc));
    pc.nodes = arg;
    pc.stride = sizeof(struct vless_node);
    pc.first = 0;
    g_run_rc = vless_tunnel_run(&o, &pc, NULL, NULL);
}

/* I-097: UUID узла не разбирается. Прежде соединение закрывалось молча — ни строки, ни
 * причины, — а подъём (tunnel_run, теперь vless_tunnel_run) поднимал устройство, которое
 * закрывало бы всё подряд. */
static void t_bad_uuid(void) {
    struct vless_node bad = g_node;
    /* Короче 31 знака — законный «производный» UUID (sha1 строки, как у Xray); длиннее 36
     * не разбирается никак. */
    memset(bad.uuid, 0, sizeof(bad.uuid));
    memset(bad.uuid, 'x', 40);
    snprintf(bad.name, sizeof(bad.name), "узел-стенда");
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    g_now_s += 10;                                   /* ограничитель строки не мешает */
    int said = stderr_has(syn_bad, &bad, "не разбирается UUID");
    c = conn_find(&k);
    check(said && !c, "I-097: соединение к узлу с негодным UUID — отказ назван в журнале");
    if (c) conn_drop(c);
    dev_drain(NULL);
    said = stderr_has(run_bad, &bad, "не разбирается UUID");
    check(said && g_run_rc == 1, "I-097: подъём называет негодный UUID до подъёма устройства");
}

static void send_refused(void *arg) {
    struct conn *c = arg;
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_ESTATUS;
    cli_put(c, d, sizeof(d) - 1);
    cli_pump(c);
    g_send_rc = 0;
}

/* I-219: сервер xhttp не принял кусок выгрузки (vless_send вернул H2_ESTATUS). Соединение
 * закрывается, как при любой неудаче отправки, но причину обязан услышать человек: прежде
 * RST уходил молча, и узел выглядел живым. */
static void t_send_refused(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "I-219: соединение не открылось"); return; }
    g_now_s += 10;
    int said = stderr_has(send_refused, c, "не принял данные");
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(said && !c, "I-219: отказ сервера на отправку назван в журнале, соединение закрыто");
    if (c) conn_drop(c);
}

/* Датаграммы UDP, придержанные до готовности потока, уходят узлу по одной (каждая — своим вызовом
 * send), а не одним куском. У hysteria2 обрамления длиной нет (dgram_frame отдаёт датаграмму как
 * есть, границы несёт сама датаграмма QUIC), и склеенные три датаграммы клиента (1000, 2300 и
 * 3000 байт) сервер получал одной в 6300 (Xray 26.7.28) или двумя (apernet) — первый залп QUIC
 * (два Initial или Initial с 0-RTT) терялся. */
static size_t g_es_len[8];
static int g_es_n;
static size_t es_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > cap) return 0;
    memcpy(out, p, n);
    return n;
}
static int es_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx; (void)sess; (void)k; (void)udp; (void)d;
    if (g_es_n < 8) g_es_len[g_es_n] = n;
    g_es_n++;
    return SEND_OK;
}
static void t_udp_early_bounds(void) {
    static const struct dialer_ops es_ops = { .name = "границы", .dgram_frame = es_frame,
                                              .send = es_send };
    static const struct dialer es_dl = { &es_ops, NULL, 0 };
    const struct dialer *save = g_dl;
    g_dl = &es_dl;
    struct conn *c = conn_new(&g_tun);
    memset(c, 0, sizeof(*c));
    c->used = 1;
    c->fd = -1;
    c->key = cli_key();
    c->key.proto = 17;
    c->key.sport = 30001;
    c->is_udp = 1;
    c->pending = 1;
    conn_link(c);
    static unsigned char d[3000];
    memset(d, 0x5a, sizeof d);
    g_es_n = 0;
    int ok = udp_send_dgram(c, d, 1000) == SEND_OK && udp_send_dgram(c, d, 2300) == SEND_OK &&
             udp_send_dgram(c, d, 3000) == SEND_OK;
    check(ok && g_es_n == 0, "UDP до готовности потока: три датаграммы придержаны");
    c->pending = 0;
    int fr = early_flush(c);
    check(fr == 0 && g_es_n == 3 && g_es_len[0] == 1000 && g_es_len[1] == 2300 && g_es_len[2] == 3000,
          "UDP после готовности: придержанные ушли по одной — 1000, 2300, 3000");
    if (fr != 0 || g_es_n != 3)
        fprintf(stderr, "  вызовов send %d: %zu %zu %zu\n", g_es_n, g_es_len[0], g_es_len[1], g_es_len[2]);
    g_dl = save;
    conn_drop(c);
    dev_drain(NULL);
}

/* ---- сборка фрагментов UDP из TUN ------------------------------------------------------
 * Фрагменты кладутся прямо в udp_defrag: он принимает пакет IPv4 и либо отдаёт собранную
 * датаграмму (длина > 0), либо молчит (0). Собранное сверяется с отправленным побайтно. */
#define FR_SRC 0x0100a8c0u
#define FR_DST 0x0771cbcbu
static unsigned char g_fr_dgram[70000];       /* UDP-датаграмма целиком: заголовок + данные */
static size_t g_fr_len;

/* Заготовить датаграмму из n байт данных с настоящим заголовком UDP и узором в теле. */
static void fr_make(size_t n, unsigned char seed) {
    g_fr_len = 8 + n;
    g_fr_dgram[0] = 0x9c; g_fr_dgram[1] = 0x40; g_fr_dgram[2] = 0x01; g_fr_dgram[3] = 0xbb;
    g_fr_dgram[4] = (unsigned char)(g_fr_len >> 8); g_fr_dgram[5] = (unsigned char)g_fr_len;
    g_fr_dgram[6] = g_fr_dgram[7] = 0;
    for (size_t i = 0; i < n; i++) g_fr_dgram[8 + i] = (unsigned char)(seed + i * 7);
}

/* Фрагмент [off, off+len) датаграммы g_fr_dgram с номером id. */
static size_t fr_pkt(unsigned char *out, uint32_t src, uint16_t id, size_t off, size_t len,
                     int more) {
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (unsigned char)((20 + len) >> 8); out[3] = (unsigned char)(20 + len);
    out[4] = (unsigned char)(id >> 8); out[5] = (unsigned char)id;
    unsigned f = (unsigned)(off / 8) | (more ? 0x2000u : 0u);
    out[6] = (unsigned char)(f >> 8); out[7] = (unsigned char)f;
    out[8] = 64; out[9] = 17;
    memcpy(out + 12, &src, 4);
    uint32_t dst = FR_DST;
    memcpy(out + 16, &dst, 4);
    memcpy(out + 20, g_fr_dgram + off, len);
    return 20 + len;
}

/* Отдать фрагмент и вернуть длину собранного (0 — ждём или отказ). */
static unsigned char g_fr_out[20 + 8 + 70000];
static size_t fr_feed(uint32_t src, uint16_t id, size_t off, size_t len, int more) {
    static unsigned char pk[2048 + 20];
    size_t n = fr_pkt(pk, src, id, off, len, more);
    return udp_defrag(pk, n, g_fr_out, sizeof g_fr_out);
}

static int fr_same(size_t got) {
    return got == 20 + g_fr_len && memcmp(g_fr_out + 20, g_fr_dgram, g_fr_len) == 0;
}

static void t_udp_defrag(void) {
    uint64_t t0 = 1000ull * 1000000000ull;
    g_now_ns = t0;
    fr_make(3000, 1);                                   /* UDP 3008: 1480 + 1480 + 48 */
    size_t a = fr_feed(FR_SRC, 11, 0, 1480, 1);
    size_t b = fr_feed(FR_SRC, 11, 1480, 1480, 1);
    size_t c = fr_feed(FR_SRC, 11, 2960, 48, 0);
    check(!a && !b && fr_same(c), "UDP: три фрагмента по порядку — датаграмма собрана целиком");

    fr_make(3000, 2);
    a = fr_feed(FR_SRC, 12, 2960, 48, 0);
    b = fr_feed(FR_SRC, 12, 0, 1480, 1);
    c = fr_feed(FR_SRC, 12, 1480, 1480, 1);
    check(!a && !b && fr_same(c), "UDP: хвост первым, потом начало и середина — собрана");

    fr_make(3000, 3);
    a = fr_feed(FR_SRC, 13, 1480, 1480, 1);
    b = fr_feed(FR_SRC, 13, 2960, 48, 0);
    c = fr_feed(FR_SRC, 13, 0, 1480, 1);
    check(!a && !b && fr_same(c), "UDP: середина, хвост, начало — собрана");

    fr_make(3000, 4);
    a = fr_feed(FR_SRC, 14, 0, 1480, 1);
    b = fr_feed(FR_SRC, 14, 0, 1480, 1);                /* точный повтор */
    c = fr_feed(FR_SRC, 14, 1480, 1480, 1);
    size_t d = fr_feed(FR_SRC, 14, 1480, 1480, 1);      /* и ещё повтор */
    size_t e = fr_feed(FR_SRC, 14, 2960, 48, 0);
    check(!a && !b && !c && !d && fr_same(e),
          "UDP: точные повторы фрагментов не мешают — датаграмма собрана один раз");

    /* Две датаграммы вперемешку: два клиента за раз, или один шлёт без пауз. */
    static unsigned char first[70000];
    fr_make(3000, 5);
    memcpy(first, g_fr_dgram, g_fr_len);
    size_t first_len = g_fr_len;
    fr_feed(FR_SRC, 21, 0, 1480, 1);
    fr_make(2500, 6);                                   /* UDP 2508: 1480 + 1028 */
    fr_feed(FR_SRC + 1, 21, 0, 1480, 1);                /* тот же id, другой отправитель */
    memcpy(g_fr_dgram, first, first_len); g_fr_len = first_len;
    a = fr_feed(FR_SRC, 21, 1480, 1480, 1);
    b = fr_feed(FR_SRC, 21, 2960, 48, 0);
    int ok1 = fr_same(b) && !a;
    fr_make(2500, 6);
    c = fr_feed(FR_SRC + 1, 21, 1480, 1028, 0);
    check(ok1 && fr_same(c),
          "UDP: две датаграммы вперемешку (разные отправители, один id) — обе собраны");

    /* Наложение: кусок с иными границами поверх пришедшего — отказ целиком. */
    fr_make(3000, 7);
    fr_feed(FR_SRC, 31, 0, 1480, 1);
    a = fr_feed(FR_SRC, 31, 1000, 1480, 1);
    b = fr_feed(FR_SRC, 31, 1480, 1480, 1);
    c = fr_feed(FR_SRC, 31, 2960, 48, 0);
    check(!a && !b && !c, "UDP: наложение фрагментов — датаграмма отброшена, не собрана");

    /* Длинный фрагмент поверх двух коротких: края совпали, а фрагментов было два. */
    fr_make(3000, 8);
    fr_feed(FR_SRC, 32, 0, 800, 1);
    fr_feed(FR_SRC, 32, 800, 680, 1);
    a = fr_feed(FR_SRC, 32, 0, 1480, 1);
    b = fr_feed(FR_SRC, 32, 1480, 1480, 1);
    c = fr_feed(FR_SRC, 32, 2960, 48, 0);
    check(!a && !b && !c, "UDP: фрагмент, накрывший два прежних, — отказ, а не повтор");

    /* Не последний фрагмент не кратен восьми — так не бывает. */
    fr_make(3000, 9);
    a = fr_feed(FR_SRC, 33, 0, 1479, 1);
    b = fr_feed(FR_SRC, 33, 1480, 1480, 1);
    c = fr_feed(FR_SRC, 33, 2960, 48, 0);
    check(!a && !b && !c, "UDP: длина не последнего фрагмента не кратна восьми — отказ");

    /* Срок сборки: хвост позже срока — отказ; потом тот же id собирается заново. */
    fr_make(3000, 10);
    g_now_ns = t0;
    fr_feed(FR_SRC, 41, 0, 1480, 1);
    g_now_ns = t0 + 31ull * 1000000000ull;
    a = fr_feed(FR_SRC, 41, 1480, 1480, 1);
    b = fr_feed(FR_SRC, 41, 2960, 48, 0);
    check(!a && !b, "UDP: хвост через 31 с после начала — сборка просрочена, датаграммы нет");
    /* Просроченный хвост завёл новую сборку без начала — она сама просрочится ещё через 30 с. */
    g_now_ns = t0 + 62ull * 1000000000ull;
    a = fr_feed(FR_SRC, 41, 0, 1480, 1);
    b = fr_feed(FR_SRC, 41, 1480, 1480, 1);
    c = fr_feed(FR_SRC, 41, 2960, 48, 0);
    check(!a && !b && fr_same(c), "UDP: тот же id после просрочки (и просроченного хвоста) собирается заново");

    g_now_ns = t0 + 100ull * 1000000000ull;
    fr_make(3000, 11);
    fr_feed(FR_SRC, 42, 0, 1480, 1);
    g_now_ns += 29ull * 1000000000ull;
    a = fr_feed(FR_SRC, 42, 1480, 1480, 1);
    b = fr_feed(FR_SRC, 42, 2960, 48, 0);
    check(!a && fr_same(b), "UDP: хвост через 29 с — сборка ещё живая, собрана");

    /* Слотов шестнадцать: семнадцатая незавершённая вытесняет самую старую, остальные живы. */
    g_now_ns = t0 + 200ull * 1000000000ull;
    fr_make(3000, 13);
    for (uint16_t i = 0; i < 17; i++) {
        g_now_ns += 1000000ull;
        fr_feed(FR_SRC, (uint16_t)(100 + i), 0, 1480, 1);
    }
    a = fr_feed(FR_SRC, 116, 1480, 1480, 1);            /* самая новая жива */
    b = fr_feed(FR_SRC, 116, 2960, 48, 0);
    check(!a && fr_same(b), "UDP: самая новая из 17 сборок жива и собрана");
    a = fr_feed(FR_SRC, 101, 1480, 1480, 1);            /* вторая по возрасту не тронута */
    b = fr_feed(FR_SRC, 101, 2960, 48, 0);
    check(!a && fr_same(b), "UDP: вторая по возрасту сборка не тронута вытеснением");
    a = fr_feed(FR_SRC, 100, 1480, 1480, 1);            /* вытеснена: середина осиротела */
    b = fr_feed(FR_SRC, 100, 2960, 48, 0);
    check(!a && !b, "UDP: 17-я сборка вытеснила самую старую (id 100) — её датаграммы нет");

    /* Длина в заголовке UDP не равна собранному — отказ. */
    fr_make(3000, 12);
    g_fr_dgram[4] = 0x0f; g_fr_dgram[5] = 0x00;
    fr_feed(FR_SRC, 43, 0, 1480, 1);
    fr_feed(FR_SRC, 43, 1480, 1480, 1);
    c = fr_feed(FR_SRC, 43, 2960, 48, 0);
    check(!c, "UDP: длина в заголовке не равна собранному — отказ");
}

/* ---- крупные датаграммы UDP: выше 4096 байт ---------------------------------------------
 * Датаграмма в 4097 байт данных приходит от клиента тремя фрагментами (1480 + 1480 + 1145 байт
 * UDP) и раньше терялась на пределе в 4096, хотя собиралась. Здесь: сборка, обрамление
 * дайлера с dgram_max, разбор от узла VLESS и обратная запись клиенту с нарезкой. */
static struct { size_t n[8]; int cnt; int bad; } g_em;
static int em_chk(void *arg, const unsigned char *d, size_t n) {
    (void)arg;
    size_t i = g_em.cnt == 3 ? 4 : (size_t)g_em.cnt;    /* четвёртой (65535) не будет */
    for (size_t j = 0; j < n; j++) if (d[j] != (unsigned char)(i * 31 + j)) { g_em.bad = 1; break; }
    if (g_em.cnt < 8) g_em.n[g_em.cnt] = n;
    g_em.cnt++;
    return 0;
}

static void t_udp_big(void) {
    g_now_ns = 5000ull * 1000000000ull;
    fr_make(4097, 21);                                  /* UDP 4105: 1480 + 1480 + 1145 */
    size_t a = fr_feed(FR_SRC, 61, 0, 1480, 1);
    size_t b = fr_feed(FR_SRC, 61, 1480, 1480, 1);
    size_t c = fr_feed(FR_SRC, 61, 2960, 1145, 0);
    check(!a && !b && fr_same(c), "UDP: 4097 байт данных тремя фрагментами — собрана");

    /* Предельная датаграмма: 65507 байт данных, 45 фрагментов, в обратном порядке. */
    fr_make(UDP_DGRAM_ABS, 22);                         /* UDP 65515 */
    size_t total = g_fr_len, got = 0;
    int nfr = 0;
    for (size_t off = (total - 1) / 1480 * 1480;; off -= 1480) {
        size_t len = total - off < 1480 ? total - off : 1480;
        got = fr_feed(FR_SRC, 62, off, len, off + len < total);
        nfr++;
        if (!off) break;
    }
    check(nfr == 45 && fr_same(got), "UDP: 65507 байт данных, 45 фрагментов в обратном порядке — собрана");

    /* Один байт сверх предела протокола: фрагмент выходит за 65515 — отказ. */
    fr_make(UDP_DGRAM_ABS, 23);
    size_t over = fr_feed(FR_SRC, 63, 65512, 8, 0);
    check(!over, "UDP: фрагмент за пределом 65515 байт — отказ");

    /* Обрамление и придержанные ранние данные: крупнее предела дайлера — отказ, в пределе — ок. */
    static const struct dialer_ops big_ops = { .name = "крупные", .dgram_frame = es_frame,
                                               .send = es_send, .dgram_max = UDP_DGRAM_ABS };
    static const struct dialer_ops small_ops = { .name = "мелкие", .dgram_frame = es_frame,
                                                 .send = es_send };
    static const struct dialer big_dl = { &big_ops, NULL, 0 }, small_dl = { &small_ops, NULL, 0 };
    const struct dialer *save = g_dl;
    static unsigned char dg[UDP_DGRAM_ABS + 1];
    struct conn *k = conn_new(&g_tun);
    memset(k, 0, sizeof(*k));
    k->used = 1; k->fd = -1; k->key = cli_key(); k->key.proto = 17; k->key.sport = 30002;
    k->is_udp = 1;
    conn_link(k);
    g_dl = &small_dl;
    g_es_n = 0;
    int r1 = udp_send_dgram(k, dg, 4096), r2 = udp_send_dgram(k, dg, 4097);
    check(r1 == SEND_OK && r2 == SEND_FATAL,
          "дайлер без dgram_max: 4096 байт уходят, 4097 — отказ (прежнее поведение)");
    g_dl = &big_dl;
    int r3 = udp_send_dgram(k, dg, 4097), r4 = udp_send_dgram(k, dg, UDP_DGRAM_ABS),
        r5 = udp_send_dgram(k, dg, UDP_DGRAM_ABS + 1);
    check(r3 == SEND_OK && r4 == SEND_OK && r5 == SEND_FATAL && g_es_len[2] == UDP_DGRAM_ABS,
          "дайлер с dgram_max: 4097 и 65507 байт уходят целиком, 65508 — отказ");
    g_dl = save;
    conn_drop(k);
    dev_drain(NULL);

    /* Первая датаграмма потока крупнее буфера ранних данных (8 КиБ): раньше терялась без повтора,
     * теперь буфер растёт до её размера; вторая крупная, пока первая не ушла, — отказ. */
    g_dl = &big_dl;
    struct conn *e = conn_new(&g_tun);
    memset(e, 0, sizeof(*e));
    e->used = 1; e->fd = -1; e->key = cli_key(); e->key.proto = 17; e->key.sport = 30003;
    e->is_udp = 1; e->pending = 1;
    conn_link(e);
    g_es_n = 0;
    int h1 = udp_send_dgram(e, dg, 60000);
    int h2 = udp_send_dgram(e, dg, 20000);
    e->pending = 0;
    int fl = early_flush(e);
    check(h1 == SEND_OK && h2 == SEND_AGAIN && fl == 0 && g_es_n == 1 && g_es_len[0] == 60000 &&
              e->early == NULL && e->early_cap == 0,
          "ранние данные: первая датаграмма 60000 байт придержана и ушла целиком, вторая крупная — отказ");
    e->pending = 1;
    int h3 = udp_send_dgram(e, dg, 1000), h4 = udp_send_dgram(e, dg, 20000);
    check(h3 == SEND_OK && h4 == SEND_AGAIN,
          "ранние данные: крупная после мелкой в буфере — отказ (растёт только пустой буфер)");
    e->pending = 0;
    (void)early_flush(e);
    g_dl = save;
    conn_drop(e);
    dev_drain(NULL);
    check(vless_dialer.dgram_max == TUNNEL_BUF - 2048 - 512 && vless_dialer.dgram_frame(dg, vless_dialer.dgram_max,
          g_fr_out, sizeof g_fr_out) != 0 &&
          vless_dialer.dgram_frame(dg, vless_dialer.dgram_max + 1, g_fr_out, sizeof g_fr_out) == 0,
          "VLESS: вверх несёт датаграмму до TUNNEL_BUF - 2560 байт, на байт больше — не берётся");

    /* Запись клиенту: 60000 байт нарезаются под MTU, и собранное совпадает с исходным. */
    fr_make(60000, 24);
    int w = udp_write_to_client(&g_tun, FR_DST, FR_SRC, 443, 40000, g_fr_dgram + 8, 60000, 77);
    unsigned char p[2048];
    size_t pk = 0, asm_n = 0, maxlen = 0;
    ssize_t rn;
    while ((rn = recv(g_dev_peer, p, sizeof p, MSG_DONTWAIT)) > 0) {
        pk++;
        if ((size_t)rn > maxlen) maxlen = (size_t)rn;
        asm_n = udp_defrag(p, (size_t)rn, g_fr_out, sizeof g_fr_out);
    }
    check(w == 0 && pk == 41 && maxlen <= TUN_MTU && asm_n == 20 + 8 + 60000 &&
          memcmp(g_fr_out + 28, g_fr_dgram + 8, 60000) == 0,
          "клиенту: 60000 байт нарезаны на 41 фрагмент не больше MTU и собираются обратно");
    if (pk != 41 || asm_n != 20 + 8 + 60000) fprintf(stderr, "  пакетов %zu, собрано %zu\n", pk, asm_n);

    /* От узла VLESS: датаграммы [длина(2)][данные] — 100, 20000, 65507 и 65535 (за пределом) и
     * ещё 50 за ними; записи режутся по 1000 байт, как приходят от узла по кускам TLS. */
    struct vl_sess *vs = calloc(1, sizeof *vs);
    vs->established = 1;
    static unsigned char wire[300000];
    size_t wl = 0;
    size_t lens[] = { 100, 20000, 65507, 65535, 50 };
    for (size_t i = 0; i < 5; i++) {
        wire[wl++] = (unsigned char)(lens[i] >> 8);
        wire[wl++] = (unsigned char)lens[i];
        for (size_t j = 0; j < lens[i]; j++) wire[wl++] = (unsigned char)(i * 31 + j);
    }
    memset(&g_em, 0, sizeof g_em);
    int drc = 0;
    int save_err = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    for (size_t off = 0; off < wl && !drc; off += 1000)
        drc = vless_dialer.deliver(&g_node, vs, 1, wire + off, wl - off < 1000 ? wl - off : 1000,
                                   em_chk, NULL);
    fflush(stderr);
    dup2(save_err, 2); close(save_err); close(nul);
    check(!drc && g_em.cnt == 4 && g_em.n[0] == 100 && g_em.n[1] == 20000 && g_em.n[2] == 65507 &&
              g_em.n[3] == 50 && !g_em.bad,
          "VLESS от узла: 100, 20000 и 65507 байт отданы целиком, 65535 выброшена по длине, 50 после неё живы");
    if (g_em.cnt != 4) fprintf(stderr, "  отдано %d: %zu %zu %zu %zu\n", g_em.cnt, g_em.n[0], g_em.n[1], g_em.n[2], g_em.n[3]);
    vless_dialer.clear(vs);
    check(vs->dgbig == NULL, "VLESS: куча крупной датаграммы возвращена при закрытии сессии");
    free(vs);
}

/* Заполнить таблицу целиком свежими TCP, кроме одного потока UDP с заданными портом и
 * возрастом, и спросить conn_new о новом месте. Возвращает, отдали ли место этого потока. */
static int full_table_gives_udp(uint16_t dport, int idle_s) {
    struct conn *u = NULL;
    int n = 0;
    while (conn_slot_avail()) {
        struct conn *c = conn_new(&g_tun);
        memset(c, 0, sizeof(*c));
        c->used = 1;
        c->fd = -1;
        c->key = cli_key();
        c->key.sport = (uint16_t)(20000 + n++);
        c->last = g_now_s;
        if (!u) {
            u = c;
            c->is_udp = 1;
            c->key.proto = 17;
            c->key.dport = dport;
            c->last = g_now_s - idle_s;
        }
        conn_link(c);
    }
    int save = dup(2), nul = open("/dev/null", O_WRONLY);
    dup2(nul, 2);
    struct conn *got = conn_new(&g_tun);
    fflush(stderr);
    dup2(save, 2); close(save); close(nul);
    int gave = got && got == u;
    if (got) {                          /* выданное место — в таблицу, чтобы уборка его вернула */
        memset(got, 0, sizeof(*got));
        got->used = 1;
        got->fd = -1;
        got->key = cli_key();
        got->key.sport = 19999;
        conn_link(got);
    }
    /* Уборка: всё живое — обратно в свободные. */
    while (g_live_n) conn_drop(&g_conns[g_live[g_live_n - 1]]);
    dev_drain(NULL);
    return gave;
}

/* I-055: таблица полна, свободных мест нет. Поток DNS (UDP на порт 53), молчащий 15 с, своё
 * уже сделал — запрос и ответ, — но выглядел активным все 120 с, и conn_new отказывал новым
 * соединениям, включая обычный TCP. Живой поток QUIC с тем же простоем не трогается, и DNS,
 * ответ на который ещё может прийти, тоже. */
static void t_dns_evict(void) {
    /* Сам стенд: поток, молчащий дольше IDLE_EVICT_S, вытеснялся и прежде. */
    check(full_table_gives_udp(443, IDLE_EVICT_S + 10), "I-055: стенд — молчащий дольше 120 с вытесняется");
    check(full_table_gives_udp(53, 15), "I-055: таблица полна — молчащий 15 с поток DNS уступает место");
    check(!full_table_gives_udp(443, 15), "I-055: поток UDP не на порт 53 с тем же простоем не вытесняется");
    check(!full_table_gives_udp(53, 3), "I-055: поток DNS, молчащий 3 с, не вытесняется");
}

/* Пул запасных: готовая сессия отдаётся соединению, и слот после этого пуст. Жило в
 * tests/devupmatch.c вместе с проверкой самоуказателей; самоуказатели теперь чинит транспорт
 * (xhttp_moved) по вызову дайлера (vl_take), и их проверка осталась там, на настоящем
 * транспорте, а слот пула — забота стека, и проверяется здесь. */
static void t_spare_slot(void) {
    static struct vl_sess spare;
    memset(&spare, 0, sizeof(spare));
    spare.t.link.fd = -1;
    struct spare *sp = &g_spares[0];
    struct spare save = *sp;
    sp->sess = &spare;
    sp->state = SPARE_READY;
    sp->born_ns = now_ns();
    static struct vl_sess out;
    memset(&out, 0, sizeof(out));
    check(spare_checkout(&out) == 0, "пул запасных: готовая сессия взята");
    check(sp->state == SPARE_EMPTY, "пул запасных: слот освобождён");
    *sp = save;
}


/* Событие epoll прежнего владельца слота. События берутся из epoll_wait ДО разбора порции из
 * TUN; если порция освободила соединение и тут же новый SYN занял тот же слот (запасная сессия
 * делает его не pending), цикл применял старое событие к новому соединению и читал его свежую
 * связь — блокирующую и пустую: поток цикла вставал до срока соединения. Цикл пропускает
 * соединение, родившееся в этом же витке (c->born_turn == g_turn). Сам цикл здесь не гоняется,
 * проверяется то, на чём пропуск держится: слот помнит виток своего рождения. */
static void t_born_turn(void) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    g_turn = 41;
    c = sock_conn(CLI_PORT, SRV_IP);
    check(c && c->born_turn == 41, "виток рождения: новое TCP-соединение помнит свой виток");
    g_turn = 42;
    check(c && c->born_turn != g_turn, "виток рождения: в следующем витке событие уже его собственное");
    if (c) {
        wait_ready(c, 2000);
        conn_drop(c);
    }
}

/* Сторона клиента — сокет (conn_accept): данные клиента доходят до дайлера байт в байт (порциями под одну
 * запись TLS), ответ дайлера — клиенту в сокет, закрытие клиентом (FIN) — после данных, не раньше. */
static void t_sock_path(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "сокет клиента: соединение не открылось"); return; }
    int cfd = cli_fd(c);
    static unsigned char up[50000], down[12000 + 64];

    /* Вверх: размер не кратен порции, заголовок VLESS клеится к первой. */
    up_fill(up, sizeof up, 0);
    int calls = g_send_calls;
    cli_put(c, up, sizeof up);
    cli_pump(c);
    check(g_sent_n == 26 + sizeof up && memcmp(g_sent + 26, up, sizeof up) == 0 && srv_pending(c) == 0,
          "conn_accept: 50000 байт клиента дошли до дайлера байт в байт (заголовок 26 + данные)");
    check(g_send_calls - calls == 4 && g_send_last_n <= SOCK_SEND_CHUNK,
          "  порциями SOCK_SEND_CHUNK под одну запись TLS: четыре отправки, а не по 1,4 КБ");

    /* Вниз: три чтения у узла — одна запись в сокет клиента. */
    g_stream_pos = 0;
    g_recv_rep = 3; g_recv_rep_n = 4000;
    drain_conn(c, &g_tun);
    size_t got = cli_get(cfd, down, sizeof down);
    check(got == 12000 && stream_bad(down, got, 0) == 0 && c->rtx.len == 0,
          "conn_accept: ответ дайлера — 12000 байт — дошёл до клиента в сокете целиком и по порядку");
    g_recv_rep = 0;

    /* Клиент закрыл свою половину: дописанное до FIN дошло, FIN — после него. */
    static unsigned char tail[700];
    up_fill(tail, sizeof tail, 50000);
    g_sent_n = 0;
    cli_put(c, tail, sizeof tail);
    shutdown(cfd, SHUT_WR);
    cli_pump(c);
    check(c->used && g_sent_n == sizeof tail && memcmp(g_sent, tail, sizeof tail) == 0 && c->client_fin,
          "клиент закрыл половину (FIN): данные до него ушли узлу, затем отмечено client_fin");
    /* Ответ сервера клиенту после его FIN ещё идёт (I-319). */
    g_recv_rep = 1; g_recv_rep_n = 500; g_stream_pos = 0;
    drain_conn(c, &g_tun);
    check(cli_get(cfd, down, sizeof down) == 500 && stream_bad(down, 500, 0) == 0,
          "  а ответ узла клиенту после его FIN доходит (I-319)");
    g_recv_rep = 0;
    conn_drop(c);
}

/* SERVER_FIRST_MS: сервер говорит первым (SSH, SMTP), клиент молчит. VLESS сообщает узлу назначение только
 * в заголовке запроса, поэтому стек обязан сам послать один заголовок через SERVER_FIRST_MS, один раз и без
 * кадра Vision (как клиент Xray). Прежде такой поток не открывался: узел ждал заголовка, клиент приветствия. */
static void server_first(const char *flow, size_t header_n) {
    snprintf(g_node.flow, sizeof(g_node.flow), "%s", flow);
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    c = sock_conn(CLI_PORT, SRV_IP);
    if (!c || wait_ready(c, 2000) != 0) {
        check(0, "сервер первым: тестовое соединение не открылось");
        if (c) conn_drop(c);
        g_node.flow[0] = 0;
        return;
    }
    char what[128];
    int calls = g_send_calls;
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS / 2) * 1000000ull);
    snprintf(what, sizeof(what), "сервер первым%s: до %d мс ничего не отправлено",
             flow[0] ? ", Vision" : "", SERVER_FIRST_MS);
    check(g_send_calls == calls, what);
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS + 50) * 1000000ull);
    const struct vl_sess *vs = SESS(c);
    snprintf(what, sizeof(what), "сервер первым%s: затем один заголовок в %zu байт",
             flow[0] ? ", Vision" : "", header_n);
    check(g_send_calls == calls + 1 && g_send_last_n == header_n && vs->header_sent, what);
    conn_deadlines(c, &g_tun, c->estab_ns + (SERVER_FIRST_MS + 100) * 1000000ull);
    snprintf(what, sizeof(what), "сервер первым%s: и только один раз", flow[0] ? ", Vision" : "");
    check(g_send_calls == calls + 1, what);
    conn_drop(c);
    g_node.flow[0] = 0;
}

static void t_server_first(void) {
    server_first("", 26);                    /* версия, UUID, без доп., команда, порт, IPv4 */
    server_first("xtls-rprx-vision", 44);    /* плюс дополнение flow: 0a 10 "xtls-rprx-vision" */
}

/* Место у узла (dialer_ops.room) ограничивает чтение сокета клиента: нет места — не читаем, данные ждут в
 * сокете (окно клиенту держит ядро); есть — читаем не больше места за раз. Прежде место объявлялось клиенту
 * окном в пакетах, и выгрузка против окна HTTP/2 в 94 КБ стоила таймаутов повтора. */
static void t_room_window(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "место у узла: тестовое соединение не открылось"); return; }
    static unsigned char d[20000];
    up_fill(d, sizeof d, 0);

    g_room = 0;
    int calls = g_send_calls;
    cli_put(c, d, 1000);
    cli_pump(c);
    check(!sock_want_read(c) && g_send_calls == calls && srv_pending(c) == 1000,
          "место у узла: места нет — сокет клиента не читается, данные ждут в нём");

    ((struct vl_sess *)SESS(c))->header_sent = 1;           /* заголовок считаем ушедшим: размеры — одни данные */
    g_room = 5000;
    g_send_max_n = 0;
    g_sent_n = 0;
    cli_put(c, d + 1000, sizeof d - 1000);
    check(sock_want_read(c), "место у узла: место есть — сокет читается");
    cli_pump(c);
    check(g_send_calls - calls >= 4 && g_send_max_n <= 5000 && g_sent_n == sizeof d &&
          memcmp(g_sent, d, sizeof d) == 0 && srv_pending(c) == 0,
          "место у узла: 5000 — за один раз узлу не больше места (не меньше четырёх отправок), 20000 байт целы");
    g_room = -1;
    conn_drop(c);
}

/* Пустое чтение не значит «сокет пуст»: у связи съеден служебный кадр (билет сессии TLS, WINDOW_UPDATE
 * HTTP/2), а за ним в сокете лежат данные. Чтение стоит в epoll по фронту — нового события на эти данные
 * не будет, — поэтому проход проверяет сокет poll'ом и читает дальше. Здесь сокет «готов» (байт в канале
 * сессии), и данные после пустого чтения обязаны дойти до клиента в том же проходе. */
static void t_empty_read(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "пустое чтение: тестовое соединение не открылось"); return; }
    g_stream_pos = 0;
    g_recv_empty = 1;
    g_recv_rep = 3; g_recv_rep_n = 4000;
    drain_conn(c, &g_tun);
    g_recv_empty = 0;
    static unsigned char b[12000 + 64];
    size_t got = cli_get(cli_fd(c), b, sizeof b);
    check(got == 12000 && stream_bad(b, got, 0) == 0,
          "пустое чтение (служебный кадр) при готовом сокете: данные за ним дошли в том же проходе");
    g_recv_rep = 0;
    conn_drop(c);
}

/* Дайлер-нарушитель: разбор отдаёт прочитанное дважды — как накопитель, отдающий накопленное плюс прочитанное. */
static int dup_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                       dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n) != 0 || emit(arg, d, n) != 0 ? -1 : 0;
}

/* Склейка записей клиенту (R-147): порция чтений у узла уходит в сокет клиента ОДНОЙ записью (writev по кольцу
 * недописанного), а не записью на каждое чтение: вызов и отправка TCP на каждые 16 КБ дороже копии в кольцо.
 * Проверяются и перенос через край кольца (вторая порция идёт через его конец — writev с двумя кусками), и
 * порядок, и то, что прочитанное у узла не теряется. */
static void t_tx_batch(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "склейка записей: тестовое соединение не открылось"); return; }
    static unsigned char b[40000 + 64];
    g_stream_pos = 0;
    size_t pos = 0;

    g_recv_rep = 10; g_recv_rep_n = 4000;
    /* Канал «сессии» пуст на время прохода: с непрочитанным байтом poll видит готовность всегда, и порция
     * не кончалась бы, пока чтения не упрутся в свой предел. */
    unsigned char hold;
    int held = read(g_sess_pipe[0], &hold, 1) == 1;
    g_poll_calls = 0;
    g_writev_calls = 0;
    drain_conn(c, &g_tun);
    int polls = g_poll_calls;
    if (held && write(g_sess_pipe[1], &hold, 1) != 1) check(0, "канал сессии не восстановлен");
    size_t got = cli_get(cli_fd(c), b, sizeof b);
    check(polls <= 1, "чтение у узла: десять чтений подряд — не больше одного poll (на конце порции, не на каждом чтении)");
    check(got == 40000 && stream_bad(b, got, pos) == 0, "склейка: все 40000 байт дошли по порядку и без порчи");
    check(g_writev_calls == 1, "склейка: десять чтений у узла — одна запись в сокет клиента (один writev)");
    check(c->rtx.len == 0, "склейка: клиент принял всё — кольцо пусто");
    pos += got;

    /* Вторая порция ложится через конец кольца. */
    uint32_t head = c->rtx.head;
    g_recv_rep = 10; g_recv_rep_n = 4000;
    g_writev_calls = 0;
    drain_conn(c, &g_tun);
    got = cli_get(cli_fd(c), b, sizeof b);
    check(got == 40000 && stream_bad(b, got, pos) == 0 && g_writev_calls == 1,
          "склейка: порция через конец кольца уходит одной записью и без порчи");
    check(head + 40000 > c->rtx.cap && c->rtx.head < head && c->rtx.cap == 64 * 1024,
          "склейка: проверка идёт через край кольца");
    pos += got;

    /* Договор дайлера: за проход не больше запаса кольца (CLIENT_ROOM_RESERVE). Верная раздача — тишина,
     * раздача вдвое больше прочитанного (накопитель, как был у ss и vmess) — строка в журнале и счёт. */
    check(g_overemit == 0, "договор дайлера: порция в рамках запаса — нарушений нет");
    /* Нарушение договора: один проход отдаёт 2 x 18000 при запасе TUNNEL_BUF + 1024. */
    struct dialer_ops over = *g_dl->ops;
    over.deliver = dup_deliver;
    struct dialer over_dl = *g_dl;
    over_dl.ops = &over;
    const struct dialer *real_dl = g_dl;
    g_dl = &over_dl;
    g_recv_rep = 1; g_recv_rep_n = 18000;
    drain_conn(c, &g_tun);
    g_dl = real_dl;
    check(g_overemit == 1, "договор дайлера: проход отдал 36000 байт при запасе 19472 — нарушение сосчитано и названо");
    (void)cli_get(cli_fd(c), b, sizeof b);                  /* поток испорчен намеренно — только вычерпать сокет */
    g_recv_rep = 0;
    conn_drop(c);
}

/* Вторая связь дайлера (xhttp: ответы на выгрузку) стоит в epoll цикла. Прежде освободившееся ответом место
 * замечалось, лишь когда цикл просыпался по пакету клиента, а клиент, которому отказано в окне, молчит до
 * своего таймера: выгрузка packet-up шла кусками «окно, пауза». Теперь событие связи сливает её, и сокет
 * клиента, ждавший места у узла, читается со следующим проходом сроков — без нового события на сокете (оно
 * по фронту, второго не будет). */
static void t_aux_wake(void) {
    struct conn *c = open_conn();
    if (!c) { check(0, "вторая связь: тестовое соединение не открылось"); return; }
    int ap[2], ep = epoll_create1(0);
    if (pipe(ap) != 0 || ep < 0) { check(0, "вторая связь: канал или epoll"); return; }
    struct epoll_event ev[4];
    unsigned char d[100];
    memset(d, 'u', sizeof(d));

    g_room = 0;
    cli_put(c, d, sizeof(d));
    cli_pump(c);
    check(!sock_want_read(c) && g_sent_n == 0, "вторая связь: места у узла нет — клиент не читается, данные ждут в сокете");

    g_aux_fd = ap[0];
    aux_sync(ep, c);
    check(c->aux == ap[0], "вторая связь: дескриптор, названный дайлером, поставлен в epoll");
    aux_sync(ep, c);
    check(epoll_wait(ep, ev, 4, 0) == 0, "вторая связь: пока ответов нет, цикл не будят");

    if (write(ap[1], "x", 1) != 1) return;
    int n = epoll_wait(ep, ev, 4, 0);
    check(n == 1 && (ev[0].data.u32 & AUX_BIT) && (ev[0].data.u32 & ~AUX_BIT) == (uint32_t)(c - g_conns),
          "вторая связь: ответ на выгрузку будит цикл событием этого соединения");
    g_room_on_aux = 60000;
    g_aux_drains = 0;
    g_turn++;
    aux_event(ep, c);
    check(g_aux_drains == 1 && sock_want_read(c),
          "вторая связь: слив по событию — место выросло, сокет клиента снова читается без нового события на нём");
    conn_deadlines(c, &g_tun, c->estab_ns + 1);
    check(g_sent_n == 26 + sizeof(d) && memcmp(g_sent + 26, d, sizeof(d)) == 0 && srv_pending(c) == 0,
          "вторая связь: проход сроков дочитал клиента — 100 байт ушли узлу");

    /* Связь, которую дайлер слушать больше не просит, снимается навсегда. */
    if (write(ap[1], "x", 1) != 1) return;
    g_aux_rc = -1;
    aux_event(ep, c);
    check(c->aux == -2, "вторая связь: отказ слива — слушать её больше не будем");
    if (write(ap[1], "x", 1) != 1) return;
    aux_sync(ep, c);
    check(c->aux == -2 && epoll_wait(ep, ev, 4, 0) == 0,
          "вторая связь: снятая связь заново в epoll не ставится и не будит цикл");
    g_aux_rc = 0;

    /* Связи у сессии нет (-1): с epoll снимается, если стояла. */
    c->aux = -1;
    aux_sync(ep, c);
    check(c->aux == ap[0], "вторая связь: после снятия слежка возобновляется при новом соединении");
    g_aux_fd = -1;
    aux_sync(ep, c);
    check(c->aux == -1, "вторая связь: дайлер связи больше не называет — с epoll снята");

    g_room = -1;
    close(ep);
    close(ap[0]);
    close(ap[1]);
    conn_drop(c);
}

/* Порции клиента узлу (sock_read): читаем крупно, отдаём по SOCK_SEND_CHUNK — столько, сколько с обёртками
 * дайлера ложится в ОДНУ запись TLS. Транспорт, который режет запись сам (xhttp packet-up), получает
 * порцию крупнее: меньше POST на тот же трафик. Но только когда заголовок VLESS уже ушёл и у узла нет flow:
 * Vision держит кадр в одной записи, а заголовок клеится к данным в буфер TUNNEL_BUF. */
static void t_sock_chunks(void) {
    static unsigned char d[60000];
    up_fill(d, sizeof d, 0);
    struct conn *c = open_conn();
    if (!c) { check(0, "порции узлу: тестовое соединение не открылось"); return; }

    /* Первая отправка несёт заголовок (он клеится к данным в буфер TUNNEL_BUF): потолок прежний,
     * даже у транспорта с большой записью. */
    g_big_write = 1;
    struct vl_sess *vs = SESS(c);
    uint8_t was = vs->header_sent;
    vs->header_sent = 0;
    check(vless_dialer.up_max(&g_node, vs) == 0, "порции узлу: пока заголовок не ушёл, потолок прежний");
    vs->header_sent = 1;
    check(vless_dialer.up_max(&g_node, vs) == TUNNEL_GATHER_MAX, "порции узлу: заголовок ушёл — большой потолок");
    vs->header_sent = was;
    int calls;
    vs->header_sent = 1;                                    /* заголовок считаем ушедшим */

    /* Заголовок ушёл, flow нет: все 60000 байт — одна отправка. */
    g_sent_n = 0;
    calls = g_send_calls;
    cli_put(c, d, sizeof d);
    cli_pump(c);
    check(g_send_calls == calls + 1 && g_send_last_n == 60000 && g_sent_n == 60000 &&
          memcmp(g_sent, d, sizeof d) == 0,
          "порции узлу: packet-up без flow — 60000 байт одной отправкой, байт в байт");

    /* Транспорт без большой записи: порции SOCK_SEND_CHUNK. */
    g_big_write = 0;
    g_sent_n = 0;
    calls = g_send_calls;
    cli_put(c, d, sizeof d);
    cli_pump(c);
    check(g_send_calls - calls == 4 && g_send_last_n <= UP_MAX && g_sent_n == 60000 &&
          memcmp(g_sent, d, sizeof d) == 0,
          "порции узлу: транспорт без большой записи — не крупнее UP_MAX, поток цел");

    /* Узел с flow (Vision): даже при большой записи транспорта — прежний потолок. */
    g_big_write = 1;
    snprintf(g_node.flow, sizeof(g_node.flow), "xtls-rprx-vision");
    calls = g_send_calls;
    cli_put(c, d, sizeof d);
    cli_pump(c);
    check(g_send_calls - calls >= 4 && g_send_last_n <= UP_MAX + 2048,
          "порции узлу: узел с flow (Vision) большой записи не получает");
    g_node.flow[0] = 0;
    g_big_write = 0;
    conn_drop(c);
}

/* ==== ПУЛ УЗЛОВ ВЫХОДА И СБРОС СОЕДИНЕНИЙ (src/tunnel/pool.c) ================================
 *
 * ЧТО ПРОВЕРЯЕТСЯ. Две половины одной задачи (узел умер, а соединения через него висят):
 *
 *   стек (src/tunnel/stack.c) — связь с узлом ОБОРВАНА (RST узла, срок ядра) — клиенту RST, а не
 *   FIN, и слежке за узлом сказано lost; узел закрыл связь штатно (FIN) — клиенту FIN, как прежде;
 *   отправка узлу не удалась — RST, а не молчаливое закрытие; данные на соединение, которого нет в
 *   таблице (клиент выхода перезапустился), — RST; порог молчания встаёт на сокет связи
 *   (TCP_USER_TIMEOUT, keepalive); узел соединения больше не активен — RST, а соединения живого
 *   узла не тронуты;
 *
 *   пул (src/tunnel/pool.c) — раздача by: site держит сайт на одном узле и не двигает сайты живых
 *   узлов, когда один лёг; connection делит поровну; мёртвый узел заменяется следующим свободным
 *   кандидатом (занятые пропускаются), пустой слот находит узел сам; запасная связь годится только
 *   своему слоту (site) или переезжает с соединением на свой узел (connection); серия отказов и
 *   обрыв зовут проверку раньше срока; файл состояния называет активные узлы.
 *
 * КАК. Стенд включает pool.c целиком, как и stack.c (всё нужное в них статическое; отдельным стендом
 * с #include это было бы ещё одно нарушение храповика tests/buildmatch.sh), а протокол под пулом —
 * поддельный дайлер: его связь — настоящий TCP через петлю к слушателю стенда, поэтому RST и FIN
 * узла — настоящие, и состояние сокета (TCP_INFO) стек спрашивает у ядра, а не у подделки.
 * Устройство — та же сокетная пара. Проверка узла — флаг alive у подделки.
 * Само молчание узла (ядро обрывает связь по порогу) здесь не воспроизвести — петля пакетов не
 * теряет; его гоняет tests/run-silence.sh в сетевом пространстве. */

/* ---- поддельный протокол: узел и связь ------------------------------------------------------ */

struct fnode { char name[16]; char host[16]; int alive; int delay_ms; };
static struct fnode g_fn[80];

struct fsess { int fd; const struct fnode *node; int flow_opens; };

static int g_lfd = -1;
static uint16_t g_lport;
static pthread_mutex_t g_srv_mu = PTHREAD_MUTEX_INITIALIZER;
static int g_srv[256];
static const struct fnode *g_srv_node[256];
static int g_srv_n;

static const char *f_peer(const void *ctx) { return ((const struct fnode *)ctx)->host; }
static void f_describe(const void *ctx, char *out, size_t n) {
    snprintf(out, n, "%s", ((const struct fnode *)ctx)->name);
}
static const char *f_strerror(int rc) { (void)rc; return "подмена"; }
static int f_connect(const void *ctx, void *sess, int t) {
    (void)t;
    const struct fnode *n = ctx;
    struct fsess *s = sess;
    if (!n->alive) return TR_ECONNECT;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET, .sin_port = htons(g_lport) };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (fd < 0 || connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) return TR_ECONNECT;
    int a = accept(g_lfd, NULL, NULL);
    pthread_mutex_lock(&g_srv_mu);
    g_srv_node[g_srv_n] = n;
    g_srv[g_srv_n++] = a;
    pthread_mutex_unlock(&g_srv_mu);
    s->fd = fd;
    return 0;
}
static void f_take(void *dst, void *src) {
    struct fsess *d = dst, *s = src;
    d->fd = s->fd;
    s->fd = -1;
}
static void f_close(void *sess) {
    struct fsess *s = sess;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}
static void f_clear(void *sess) {
    struct fsess *s = sess;
    s->fd = -1;
    s->node = NULL;
    s->flow_opens = 0;
}
static int f_fd(const void *sess) { return ((const struct fsess *)sess)->fd; }
static int f_has_data(const void *sess) { (void)sess; return 0; }
static int f_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k; (void)udp;
    struct fsess *s = sess;
    s->node = ctx;
    s->flow_opens++;
    return 0;
}
static int f_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                  const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    struct fsess *s = sess;
    return send(s->fd, d, n, MSG_NOSIGNAL) == (ssize_t)n ? SEND_OK : SEND_FATAL;
}
static size_t f_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n + 2 > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return n + 2;
}
static int f_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct fsess *s = sess;
    *got = 0;
    ssize_t r = recv(s->fd, buf, cap, MSG_DONTWAIT);
    if (r > 0) { *data = buf; *got = (size_t)r; return 0; }
    return -1;
}
static int f_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                     dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}

static const struct dialer_ops f_ops = {
    .name = "подмена", .caps = DC_PRECONNECT, .sess_size = sizeof(struct fsess),
    .peer = f_peer, .describe = f_describe, .strerror = f_strerror, .connect = f_connect,
    .take = f_take, .close = f_close, .clear = f_clear, .fd = f_fd, .has_data = f_has_data,
    .flow_open = f_flow_open, .send = f_send, .dgram_frame = f_dgram_frame, .read = f_read,
    .deliver = f_deliver,
};

static int f_probe(const void *node, int t, char *why, size_t n) {
    (void)t;
    int dl = ((const struct fnode *)node)->delay_ms;
    if (dl > 0) {
        struct timespec ts = { dl / 1000, (long)(dl % 1000) * 1000000L };
        nanosleep(&ts, NULL);
    }
    if (((const struct fnode *)node)->alive) return 0;
    snprintf(why, n, "узел стенда молчит");
    return -1;
}
static const char *f_name(const void *node) { return ((const struct fnode *)node)->name; }
static const struct pool_proto f_proto = { .ops = &f_ops, .probe = f_probe, .name = f_name, .tag = "pm" };

static int g_sel[80] = { 0, 1, 2, 3, 4 };

static int g_pick, g_tol = -1;

/* Пул заново: active слотов, кандидаты 0..ncand-1, первый — узел 0; выбор — g_pick и g_tol. */
static void pool_new(int active, int by, int ncand, const char *out) {
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    free(g_pl.slot);
    memset(&g_pl.cf, 0, sizeof g_pl.cf);
    g_pl.sig[0] = '\0';
    g_pl.said_up = 0;
    g_pl.why[0] = '\0';
    struct pool_cfg pc = {
        .proto = &f_proto, .nodes = g_fn, .stride = sizeof(struct fnode), .sel = g_sel,
        .sel_n = (size_t)ncand, .first = 0, .checked = 1, .active = active, .by = by,
        .interval_s = 60, .silence_s = 20, .out = out, .pick = g_pick, .tolerance_ms = g_tol,
    };
    const struct dialer *d = pool_setup(&pc);
    g_spare_want = 0;
    stack_setup(d);
}


/* TCP, пришедший в устройство, — только для проверки сброса (R-152): соединения клиентов приходят сокетом. */
static void pm_send(uint16_t sport, uint32_t dst, uint32_t seq, uint32_t ack, unsigned char flags,
                     const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, dst, sport, 443, seq, ack, flags, d, n, 65535, 0, -1);
    handle_packet(&g_tun, p, l);
}

/* Пакеты, написанные стеком в устройство: сколько, флаги всех вместе, номер последнего. */
static int pm_drain(unsigned *flags, uint32_t *seq) {
    unsigned char p[70000];
    int cnt = 0;
    if (flags) *flags = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0) {
            if (flags) *flags |= k.tcp_flags;
            if (seq) *seq = k.seq;
            cnt++;
        }
    }
    return cnt;
}

static struct flow_key pm_key(uint16_t sport, uint32_t dst) {
    struct flow_key k;
    memset(&k, 0, sizeof(k));
    k.src = CLI_IP; k.dst = dst; k.sport = sport; k.dport = 443; k.proto = 6;
    return k;
}

/* Соединение до «поток готов»: принятый сокет (TCP на петле — клиент видит различие RST и FIN), установщик,
 * готовность (conn_ready). */
static struct conn *pm_open(uint16_t sport, uint32_t dst) {
    struct conn *c = sock_conn_tcp(sport, dst);
    if (!c || !c->pending) return NULL;
    for (int i = 0; i < 3000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) || conn_ready(c, &g_tun)) return NULL;
    return c;
}

static int pm_srv_of(const struct conn *c) {
    /* Серверный конец связи соединения — по номеру порта: локальный порт клиента = удалённый у
     * сервера. */
    struct sockaddr_in a;
    socklen_t al = sizeof a;
    if (getsockname(c->fd, (struct sockaddr *)&a, &al) != 0) return -1;
    pthread_mutex_lock(&g_srv_mu);
    int found = -1;
    for (int i = 0; i < g_srv_n; i++) {
        struct sockaddr_in b;
        socklen_t bl = sizeof b;
        if (g_srv[i] >= 0 && getpeername(g_srv[i], (struct sockaddr *)&b, &bl) == 0 &&
            b.sin_port == a.sin_port) found = g_srv[i];
    }
    pthread_mutex_unlock(&g_srv_mu);
    return found;
}

static void pm_srv_rst(int fd) {
    struct linger lg = { 1, 0 };
    setsockopt(fd, SOL_SOCKET, SO_LINGER, &lg, sizeof lg);
    close(fd);
    struct timespec ts = { 0, 50000000 };
    nanosleep(&ts, NULL);
}

static void pm_sweep(void) {
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);
    static unsigned seen;
    nodes_sweep(&seen, g_now_ns);
    for (int li = 0; li < g_live_n; ) {
        struct conn *c = &g_conns[g_live[li]];
        if (c->pending || !conn_deadlines(c, &g_tun, g_now_ns)) li++;
    }
}

/* ---- стек ---------------------------------------------------------------------------------- */

static void t_pool_stack(void) {
    pool_new(1, BY_CONNECTION, 2, NULL);
    unsigned fl;
    uint32_t sq;

    /* Данные на соединение, которого нет. */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    pm_send(50001, 0x0a0a0a0au, 5000, 777, TCP_ACK | TCP_PSH, d, sizeof d - 1);
    int n = pm_drain(&fl, &sq);
    check(n == 1 && (fl & TCP_RST) && sq == 777,
          "TCP в устройстве (данные без соединения) — RST с номером его подтверждения");
    pm_send(50001, 0x0a0a0a0au, 5000, 778, TCP_ACK, NULL, 0);
    n = pm_drain(&fl, &sq);
    check(n == 1 && (fl & TCP_RST) && sq == 778,
          "подтверждение без соединения (challenge ACK на наш RST) — RST с его номером");
    pm_send(50001, 0x0a0a0a0au, 5000, 779, TCP_RST, NULL, 0);
    check(pm_drain(NULL, NULL) == 0, "RST без соединения — без ответа");

    /* Порог молчания на сокете связи. */
    struct conn *c = pm_open(50002, 0x0a0a0a0bu);
    check(c != NULL, "стенд: соединение через пул открылось");
    if (!c) return;
    unsigned uto = 0;
    int ka = 0, idle = 0;
    socklen_t l = sizeof uto;
    getsockopt(c->fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &uto, &l);
    l = sizeof ka;
    getsockopt(c->fd, SOL_SOCKET, SO_KEEPALIVE, &ka, &l);
    l = sizeof idle;
    getsockopt(c->fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, &l);
    check(uto == 20000 && ka == 1 && idle == 20,
          "порог молчания 20 с — на сокете связи TCP_USER_TIMEOUT 20000 мс, keepalive через 20 с");

    /* Узел сбросил связь посреди ответа. */
    g_pl.slot[0].checked_at = 0;
    g_pl.slot[0].kick = 0;
    int s = pm_srv_of(c);
    if (send(s, "abc", 3, 0) != 3) check(0, "стенд: сервер не отправил");
    struct timespec ts = { 0, 30000000 };
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    int cfd = cli_fd(c);
    pm_srv_rst(s);
    drain_conn(c, &g_tun);
    check(c->srv_closed && c->aborted, "RST узла — связь оборвана (aborted), а не закрыта");
    check(g_pl.slot[0].kick == 1 && g_pl.slot[0].lost == 1, "обрыв связи — слежке: проверить узел сейчас (lost)");
    pm_sweep();
    struct flow_key k = pm_key(50002, 0x0a0a0a0bu);
    check(cli_end(cfd) == 2 && !conn_find(&k),
          "оборванная связь — клиенту RST, а не FIN (обрезанный ответ не выглядит целым)");

    /* Узел закрыл связь штатно. */
    c = pm_open(50003, 0x0a0a0a0bu);
    if (!c) { check(0, "стенд: второе соединение не открылось"); return; }
    s = pm_srv_of(c);
    cfd = cli_fd(c);
    shutdown(s, SHUT_WR);
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    check(c->srv_closed && !c->aborted, "FIN узла — закрытие, не обрыв");
    pm_sweep();
    k = pm_key(50003, 0x0a0a0a0bu);
    check(cli_end(cfd) == 1 && !conn_find(&k), "закрытая узлом связь — клиенту FIN, как прежде");
    close(s);

    /* Отправка узлу не удалась. */
    c = pm_open(50004, 0x0a0a0a0bu);
    if (!c) { check(0, "стенд: третье соединение не открылось"); return; }
    cfd = cli_fd(c);
    pm_srv_rst(pm_srv_of(c));
    cli_put(c, d, sizeof d - 1);
    cli_pump(c);
    k = pm_key(50004, 0x0a0a0a0bu);
    check(cli_end(cfd) == 2 && !conn_find(&k), "отправка узлу не удалась — клиенту RST, а не молчание");
}

/* Узел соединения перестал быть активным: его соединения — RST, соединения живого слота — живы. */
static void t_pool_stale(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(2, BY_CONNECTION, 4, NULL);
    pl_check(1);                                         /* пустой слот нашёл узел */
    check(g_pl.slot[1].node == 1 && g_pl.slot[1].up, "пустой слот при подъёме — первый свободный кандидат (1)");
    struct conn *a = NULL, *b = NULL;
    for (uint16_t p = 51000; p < 51100 && (!a || !b); p++) {
        struct conn *c = pm_open(p, 0x0b0b0b0bu);
        if (!c) continue;
        const struct pl_sess *ps = SESS(c);
        if (ps->slot == 0 && !a) a = c;
        else if (ps->slot == 1 && !b) b = c;
        else conn_reset(c, &g_tun);
    }
    pm_drain(NULL, NULL);
    check(a && b, "раздача connection — соединения есть на обоих узлах");
    if (!a || !b) return;
    struct flow_key ka = a->key, kb = b->key;
    int fa = cli_fd(a);
    unsigned ep0 = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "одна неудачная проверка — узел ещё жив (повтор через 3 с)");
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 2,
          "две неудачи подряд — замена следующим свободным кандидатом (1 занят, взят 2)");
    check(__atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep0, "смена узла — стеку: набор узлов изменился");
    pm_sweep();
    check(!conn_find(&ka) && cli_end(fa) == 2, "соединение мёртвого узла — RST клиенту, без перезапуска процесса");
    check(conn_find(&kb) != NULL, "соединение живого узла — не тронуто");
    struct conn *cb = conn_find(&kb);
    if (cb) conn_reset(cb, &g_tun);
    pm_drain(NULL, NULL);
}

/* ---- пул ------------------------------------------------------------------------------------ */

static void t_pool_pick(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(3, BY_SITE, 5, NULL);
    pl_check(1);
    pl_check(2);
    check(g_pl.slot[1].node == 1 && g_pl.slot[2].node == 2, "три слота — узлы 0, 1, 2 по порядку кандидатов");
    int at[200], per[3] = { 0, 0, 0 }, same = 1;
    struct flow_key k = pm_key(1, 0);
    for (int i = 0; i < 200; i++) {
        k.dst = htonl(0x5db80000u + (uint32_t)i * 7919u);
        k.sport = (uint16_t)(1000 + i);
        at[i] = pl_pick(&k);
        k.sport = (uint16_t)(2000 + i);
        if (pl_pick(&k) != at[i]) same = 0;
        per[at[i]]++;
    }
    check(same, "by: site — сайт на одном узле при любом порте и соединении");
    check(per[0] > 30 && per[1] > 30 && per[2] > 30, "by: site — сайты разошлись по всем трём узлам");
    g_pl.slot[1].up = 0;
    int kept = 1, moved = 1;
    for (int i = 0; i < 200; i++) {
        k.dst = htonl(0x5db80000u + (uint32_t)i * 7919u);
        int now = pl_pick(&k);
        if (at[i] != 1 && now != at[i]) kept = 0;
        if (at[i] == 1 && now == 1) moved = 0;
    }
    check(kept, "узел лёг — сайты живых узлов остаются на своих местах");
    check(moved, "узел лёг — его сайты ушли на живые");
    g_pl.slot[1].up = 1;

    pool_new(3, BY_SITE_CLIENT, 5, NULL);
    pl_check(1);
    pl_check(2);
    k.dst = htonl(0x5db80001u);
    int seen[3] = { 0, 0, 0 };
    for (uint32_t c = 0; c < 60; c++) {
        k.src = htonl(0x0a000002u + c);
        seen[pl_pick(&k)] = 1;
    }
    check(seen[0] + seen[1] + seen[2] >= 2, "by: site_client — один сайт у разных клиентов на разных узлах");

    pool_new(3, BY_CONNECTION, 5, NULL);
    pl_check(1);
    pl_check(2);
    int cnt[3] = { 0, 0, 0 };
    for (int i = 0; i < 3000; i++) cnt[pl_pick(&k)]++;
    check(cnt[0] > 800 && cnt[1] > 800 && cnt[2] > 800, "by: connection — новые соединения поровну");
}

/* active до 65536 допустимо спекой: новые соединения by: connection идут на все живые слоты, а не на
 * первые 64 (pl_pick держал живых в live[64]). */
static void t_pool_many(void) {
    for (int i = 0; i < 80; i++) g_fn[i].alive = 1;
    pool_new(70, BY_CONNECTION, 70, NULL);
    for (int s = 1; s < 70; s++) pl_check(s);
    struct flow_key k = pm_key(1, htonl(0x5db80001u));
    int hit[70] = { 0 }, hi = 0;
    for (int i = 0; i < 20000; i++) { int s = pl_pick(&k); if (s >= 0) hit[s] = 1; }
    for (int s = 64; s < 70; s++) hi += hit[s];
    check(hi == 6, "by: connection — слоты с 65-го по 70-й тоже получают соединения (не только первые 64)");
}

static void t_pool_refill(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    g_fn[1].alive = 0;
    pool_new(3, BY_CONNECTION, 5, NULL);
    pl_check(1);
    pl_check(2);
    check(g_pl.slot[1].node == 2 && g_pl.slot[2].node == 3,
          "пустые слоты — по порядку кандидатов, молчащий кандидат пропущен");
    for (int i = 0; i < 5; i++) g_fn[i].alive = 0;
    pl_check(0);
    pl_check(0);
    check(!g_pl.slot[0].up && g_pl.slot[0].node == 0 && g_pl.slot[0].retry == PL_RETRY_S * 2,
          "замены нет — слот ждёт круга, пауза растёт вдвое");
    check(g_pl.said_up == 1, "живые слоты остались — выход по-прежнему up");
    for (int s = 1; s < 3; s++) { pl_check(s); pl_check(s); }
    check(g_pl.said_up == 0, "живых слотов нет — демону down");
    g_fn[3].alive = 1;
    pl_check(0);
    check(!g_pl.slot[0].up, "круг: узел, который ждёт свой мёртвый слот, другому слоту не отдаётся");
    pl_check(2);
    check(g_pl.slot[2].up && g_pl.slot[2].node == 3 && g_pl.said_up == 1,
          "круг: свой прежний узел ответил — слот жив на нём же, демону снова up");
    g_fn[4].alive = 1;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 4, "круг: ответил свободный кандидат — слот на нём");
    int ids = 0;
    for (int i = 0; i < 3; i++)
        for (int j = i + 1; j < 3; j++)
            if (g_pl.slot[i].up && g_pl.slot[j].up && g_pl.slot[i].node == g_pl.slot[j].node) ids = 1;
    check(!ids, "два живых слота на одном узле не бывают");
}

static void t_pool_spares(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(2, BY_SITE, 3, NULL);
    pl_check(1);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)], src[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst, *s = (struct pl_sess *)src;
    pl_clear(dst);
    pl_clear(src);
    struct flow_key k = pm_key(1, htonl(0x5db80001u));
    pl_flow_open(&g_pl, dst, &k, 0);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 1 - d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    check(pl_match(&g_pl, dst, src) == 0, "by: site — запасная к чужому узлу соединению сайта не годится");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    check(pl_match(&g_pl, dst, src) == 1, "by: site — запасная своего узла годится");
    g_pl.slot[d->slot].gen++;
    check(pl_match(&g_pl, dst, src) == -1, "запасная к узлу, который больше не активен, — выбросить");

    pool_new(2, BY_CONNECTION, 3, NULL);
    pl_check(1);
    pl_clear(dst);
    pl_clear(src);
    pl_flow_open(&g_pl, dst, &k, 0);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(s, 1 - d->slot);
    pthread_mutex_unlock(&g_pl.mu);
    const void *want = s->node;
    check(pl_match(&g_pl, dst, src) == 1, "by: connection — годится запасная любого живого узла");
    ((struct fsess *)INNER(src))->fd = -1;
    pl_take(dst, src);
    const struct fsess *fd = INNER(dst);
    check(d->node == want && fd->node == want && fd->flow_opens == 2,
          "запасная другого узла — соединение переезжает на него, поток заведён заново под узел");

    /* Серия отказов установления — проверка раньше срока. */
    g_pl.slot[0].kick = 0;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_seen(d, -1);
    pl_seen(d, -1);
    check(!g_pl.slot[0].kick, "два отказа установления — проверки раньше срока ещё нет");
    pl_seen(d, -1);
    check(g_pl.slot[0].kick == 1, "три отказа подряд — проверить узел сейчас");
    g_pl.slot[0].kick = 0;
    g_pl.slot[0].checked_at = pl_now_ms();
    pl_lost(&g_pl, d);
    check(!g_pl.slot[0].kick, "обрыв сразу после проверки — второй проверки не зовёт (пачка обрывов)");
    /* После обрыва по порогу молчания узел мёртв с первой неудачной проверки. */
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(2, BY_CONNECTION, 3, NULL);
    pl_check(1);
    g_pl.slot[0].checked_at = 0;
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    pl_lost(&g_pl, d);
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 2,
          "обрыв по порогу молчания и одна неудачная проверка — узел заменён без повтора через 3 с");
    g_fn[0].alive = 1;
}

/* Серия отказов установления зовёт проверку узла один раз, а не на каждый следующий отказ: пока
 * клиенты повторяют соединения к молчащему узлу, проверки (каждая — соединение к узлу) шли бы одна
 * за другой. */
static void t_pool_kick_once(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(1, BY_CONNECTION, 1, NULL);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 3; i++) pl_seen(d, -1);
    check(g_pl.slot[0].kick == 1, "серия: три отказа подряд зовут проверку");
    g_pl.slot[0].kick = 0;                      /* поток слежки взял просьбу */
    pl_seen(d, -1);
    check(!g_pl.slot[0].kick, "серия: следующий отказ после взятой просьбы проверку заново не зовёт");
    pl_seen(d, -1);
    pl_seen(d, -1);
    check(g_pl.slot[0].kick == 1, "серия: ещё три отказа — проверка зовётся снова");
}

/* Узел, который принимает проверку, а живые соединения не несёт (сервер с ограничением соединений:
 * одиночный запрос проходит, а на параллельные ClientHello отвечает молчанием), — мёртв для группы.
 * Раньше удачная проверка обнуляла счёт отказов, и такой узел оставался «жив» навсегда: выход
 * числился up, группа не уходила на запасного члена. */
static void t_pool_unproven(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(1, BY_CONNECTION, 1, NULL);
    static unsigned char dst[PL_HDR + sizeof(struct fsess)];
    struct pl_sess *d = (struct pl_sess *)dst;
    pl_clear(dst);
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 3; i++) pl_seen(d, -1);
    pl_check(0);
    check(g_pl.slot[0].up, "проверка проходит после первой серии отказов — узел ещё жив");
    pl_seen(d, 0);                              /* соединение открылось — счёт заново */
    for (int i = 0; i < 3; i++) pl_seen(d, -1);
    pl_check(0);
    check(g_pl.slot[0].up, "между сериями было удачное соединение — вторая серия счёт не продолжает");
    for (int i = 0; i < 3; i++) pl_seen(d, -1);
    pl_check(0);
    check(!g_pl.slot[0].up && g_pl.said_up == 0,
          "две серии отказов подряд, и проверка проходила, — узел мёртв, демону down");
    check(strstr(g_pl.why, "соединения не открываются") != NULL, "причина называет соединения, а не молчание узла");
    uint64_t retry = g_pl.slot[0].retry;
    pl_check(0);                                /* круг: свой прежний узел отвечает на проверку */
    check(g_pl.slot[0].up, "круг: узел ответил на проверку — слот снова жив");
    pthread_mutex_lock(&g_pl.mu);
    pl_bind(d, 0);                              /* поколение слота сменилось */
    pthread_mutex_unlock(&g_pl.mu);
    for (int i = 0; i < 3; i++) pl_seen(d, -1);
    pl_check(0);
    check(!g_pl.slot[0].up && g_pl.slot[0].retry >= retry,
          "ожил без удачных соединений — первой же серии хватает, пауза круга не сбрасывается");
}

/* Круг поиска узла у мёртвого слота не растёт до минут: сервер вернулся, а группа возвращается на него
 * только когда круг дойдёт до проверки (на стенде QEMU — через 313 с). Пауза растёт 15, 30 с и
 * остаётся на PL_RETRY_MAX_S. */
static void t_pool_retry_cap(void) {
    for (int i = 0; i < 5; i++) g_fn[i].alive = 0;
    pool_new(1, BY_CONNECTION, 2, NULL);
    pl_check(0);
    pl_check(0);                                /* мёртв: первый круг пуст */
    uint64_t at[8];
    for (int k = 0; k < 8; k++) { pl_check(0); at[k] = g_pl.slot[0].retry; }
    check(at[7] == PL_RETRY_MAX_S && PL_RETRY_MAX_S <= 30,
          "круг пустого слота: пауза после восьми пустых кругов — не больше 30 с");
    g_fn[0].alive = 1;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].retry == PL_RETRY_S, "круг: узел вернулся — слот жив, пауза круга заново 15 с");
}

static void t_pool_state(void) {
    char dir[] = "/tmp/poolmatch.XXXXXX";
    if (!mkdtemp(dir)) { check(0, "стенд: каталог состояния"); return; }
    steer_set_state_dir(dir);
    for (int i = 0; i < 5; i++) g_fn[i].alive = 1;
    pool_new(3, BY_SITE, 5, "vl");
    pl_publish();
    pl_check(1);
    pl_check(2);
    char path[200], buf[1024] = "";
    snprintf(path, sizeof path, "%s/pm-vl", dir);
    FILE *f = fopen(path, "r");
    size_t r = f ? fread(buf, 1, sizeof buf - 1, f) : 0;
    if (f) fclose(f);
    buf[r] = '\0';
    char want[300];
    snprintf(want, sizeof want, "\"want\":3,\"slots\":3,\"by\":\"site\",\"active\":[{\"index\":0,\"name\":\"n0\"},"
             "{\"index\":1,\"name\":\"n1\"},{\"index\":2,\"name\":\"n2\"}]}");
    check(strstr(buf, want) != NULL && strstr(buf, "\"pid\":"), "файл состояния — активные узлы с номерами и именами");
    unlink(path);
    rmdir(dir);
}

/* pick: latency — самые быстрые узлы подписки в одном туннеле: замер всех кандидатов, пересадка слота
 * на быстрого с допуском, соединения прежнего живого узла доживают на нём, а смерть узла по-прежнему
 * рвёт только его соединения. */
static void t_pool_latency(void) {
    for (int i = 0; i < 5; i++) { g_fn[i].alive = 1; g_fn[i].delay_ms = 0; }
    g_fn[0].delay_ms = 120;
    g_fn[1].delay_ms = 10;
    g_fn[2].alive = 0;
    g_fn[3].delay_ms = 50;
    g_pick = POOL_PICK_LATENCY;
    g_tol = -1;
    pool_new(1, BY_CONNECTION, 4, NULL);
    check(g_pl.cf.tolerance_ms == POOL_LAT_TOLERANCE_MS, "pick: latency — допуск по умолчанию 50 мс");
    uint64_t t0 = pl_now_ms();
    pl_lat_measure();
    uint64_t took = pl_now_ms() - t0;
    check(g_pl.lat[1] >= 0 && g_pl.lat[3] >= 0 && g_pl.lat[0] >= 0 && g_pl.lat[2] == -1 &&
          g_pl.lat[1] < g_pl.lat[3] && g_pl.lat[3] < g_pl.lat[0],
          "замер: время проверки каждого кандидата, не ответивший — -1");
    check(took < 250, "замер: кандидаты меряются разом, а не один за другим");

    /* Соединение на узле 0 до пересадки. */
    struct conn *a = NULL;
    for (uint16_t p = 52000; p < 52010 && !a; p++) a = pm_open(p, 0x0c0c0c0cu);
    check(a && ((const struct pl_sess *)SESS(a))->nidx == 0, "стенд: соединение на узле 0");
    if (!a) goto out;
    struct flow_key ka = a->key;
    unsigned gen0 = g_pl.slot[0].gen;
    pl_lat_rebalance();
    check(g_pl.slot[0].node == 1 && g_pl.slot[0].up && g_pl.slot[0].gen != gen0,
          "пересадка: слот — на самый быстрый узел (1), поколение новое");
    pm_sweep();
    check(conn_find(&ka) != NULL, "пересадка: соединение прежнего живого узла не рвётся");
    struct conn *b = NULL;
    for (uint16_t p = 52100; p < 52110 && !b; p++) b = pm_open(p, 0x0c0c0c0du);
    check(b && ((const struct pl_sess *)SESS(b))->nidx == 1, "пересадка: новое соединение — на быстрый узел");
    if (!b) goto out;
    struct flow_key kb = b->key;

    /* Допуск: 3 быстрее 1 меньше чем на 50 мс — слот остаётся. */
    pthread_mutex_lock(&g_pl.mu);
    g_pl.lat[1] = 80;
    g_pl.lat[3] = 40;
    pthread_mutex_unlock(&g_pl.mu);
    pl_lat_rebalance();
    check(g_pl.slot[0].node == 1, "допуск: быстрее меньше чем на 50 мс — узел не меняется");
    pthread_mutex_lock(&g_pl.mu);
    g_pl.lat[1] = 200;
    pthread_mutex_unlock(&g_pl.mu);
    pl_lat_rebalance();
    check(g_pl.slot[0].node == 3, "допуск: быстрее больше чем на 50 мс — узел меняется");

    /* Новый узел (3) умер: замена — по замеру, а не по порядку (0: 120 мс быстрее 1: 200 мс). Сброс —
     * только соединений умершего узла. */
    struct conn *c = NULL;
    for (uint16_t p = 52200; p < 52210 && !c; p++) c = pm_open(p, 0x0c0c0c0eu);
    check(c && ((const struct pl_sess *)SESS(c))->nidx == 3, "стенд: соединение на узле 3");
    if (!c) goto out;
    struct flow_key kc = c->key;
    g_fn[3].alive = 0;
    pl_check(0);
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "смерть узла: замена — самый быстрый по замеру из живых");
    pm_sweep();
    check(!conn_find(&kc), "смерть узла: его соединение — в сброс");
    check(conn_find(&ka) && conn_find(&kb), "смерть узла: соединения прежних живых узлов не тронуты");

    /* tolerance: 0 — менять на любой более быстрый. */
    g_tol = 0;
    g_fn[3].alive = 1;
    pool_new(1, BY_CONNECTION, 4, NULL);
    check(g_pl.cf.tolerance_ms == 0, "tolerance: 0 — значение, а не «умолчание»");
    pthread_mutex_lock(&g_pl.mu);
    g_pl.lat[0] = 31; g_pl.lat[1] = 30; g_pl.lat[2] = -1; g_pl.lat[3] = 90;
    pthread_mutex_unlock(&g_pl.mu);
    pl_lat_rebalance();
    check(g_pl.slot[0].node == 1, "tolerance: 0 — узел меняется и на 1 мс быстрее");

    /* Файл состояния: замер кандидатов, и diag по-прежнему считает активные узлы по "index". */
    char dir[] = "/tmp/poolmatch.XXXXXX";
    if (mkdtemp(dir)) {
        steer_set_state_dir(dir);
        pool_new(1, BY_CONNECTION, 4, "lt");
        pthread_mutex_lock(&g_pl.mu);
        g_pl.lat[0] = 120; g_pl.lat[1] = 10; g_pl.lat[2] = -1;
        pthread_mutex_unlock(&g_pl.mu);
        __atomic_add_fetch(&g_pl.lat_round, 1, __ATOMIC_RELAXED);
        pl_publish();
        char path[200], buf[1024] = "";
        snprintf(path, sizeof path, "%s/pm-lt", dir);
        FILE *f = fopen(path, "r");
        size_t r = f ? fread(buf, 1, sizeof buf - 1, f) : 0;
        if (f) fclose(f);
        buf[r] = '\0';
        int idx = 0;
        for (const char *q = buf; (q = strstr(q, "\"index\":")); q++) idx++;
        check(strstr(buf, "\"pick\":\"latency\",\"latency\":{\"0\":120,\"1\":10,\"2\":-1}}") && idx == 1,
              "файл состояния: замер кандидатов, не мерянный узел не назван, активный — один \"index\"");
        unlink(path);
        rmdir(dir);
    }
out:
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    pm_drain(NULL, NULL);
    for (int i = 0; i < 5; i++) { g_fn[i].alive = 1; g_fn[i].delay_ms = 0; }
    g_pick = 0;
    g_tol = -1;
}

/* ---- дайлер в цикле рабочего (DC_INLOOP) ------------------------------------------------------- */

/* Поддельный дайлер без дескрипторов и без установщика: связь — готовая сессия, нагрузка лежит в ней же
 * (как у hysteria2: очередь блоков), стенд кладёт и забирает руками. Проверяется то, что видно снаружи:
 * connect зовётся самим стеком в его потоке (установщиков нет вовсе), исход приходит через
 * stack_sess_ready — сразу или позже, пока соединение ждёт (данные клиента лежат в его сокете), — чтение
 * отдаёт указатель в сессию, место у узла (room) решает, читается ли сокет клиента, а оборванная связь —
 * RST, а не FIN. Само ожидание
 * в epoll и таймеры дайлера — дело worker_loop, и его гоняет стенд в сетевых пространствах
 * (tests/run-hy2.sh). */
struct hsess { int fd; };           /* общий вид для прочих поддельных дайлеров стенда: поле fd первым */
static const char *h_peer(const void *ctx) { (void)ctx; return "подмена"; }
static void h_describe(const void *ctx, char *out, size_t n) { (void)ctx; snprintf(out, n, "подмена"); }
static const char *h_strerror(int rc) { (void)rc; return "подмена"; }
static int h_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx; (void)sess; (void)k; (void)udp;
    return 0;
}
static int h_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                  const unsigned char *d, size_t n) {
    (void)ctx; (void)k; (void)udp;
    ssize_t w = send(((struct hsess *)sess)->fd, d, n, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (w == (ssize_t)n) return SEND_OK;
    return w < 0 && errno == EAGAIN ? SEND_AGAIN : SEND_FATAL;
}
static int h_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    ssize_t r = recv(((struct hsess *)sess)->fd, buf, cap, MSG_DONTWAIT);
    *data = buf;
    *got = r > 0 ? (size_t)r : 0;
    return 0;
}
static int h_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t n,
                     dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)sess; (void)udp;
    return emit(arg, d, n);
}
struct isess {
    int linked;
    unsigned char q[3000];
    size_t qn;
    int rx_fin, aborted;
    long room;
};
static int g_in_connects, g_in_same_thread, g_in_mode, g_in_rc;     /* mode 1 — исход скажет стенд позже */
static pthread_t g_in_thr;
static struct isess *g_in_late;
static size_t g_in_sent;

static int in_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)t;
    struct isess *s = sess;
    g_in_connects++;
    g_in_same_thread = pthread_equal(pthread_self(), g_in_thr);
    if (g_in_rc) return g_in_rc;                 /* отказ на месте: стек сам записывает исход */
    if (g_in_mode) { g_in_late = s; return 0; }
    s->linked = 1;
    stack_sess_ready(sess, 0);                   /* из самого connect — можно */
    return 0;
}
static void in_close(void *sess) { ((struct isess *)sess)->linked = 0; }
static void in_clear(void *sess) { ((struct isess *)sess)->linked = 0; }
static int in_fd(const void *sess) { return ((const struct isess *)sess)->linked ? 77 : -1; }
static int in_has_data(const void *sess) { return ((const struct isess *)sess)->qn > 0; }
static int in_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)ctx; (void)k; (void)udp;
    memset(sess, 0, sizeof(struct isess));
    ((struct isess *)sess)->room = 20000;
    return 0;
}
static int in_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *d, size_t n) {
    (void)ctx; (void)sess; (void)k; (void)udp; (void)d;
    g_in_sent += n;
    return SEND_OK;
}
static long in_room(const void *ctx, void *sess) { (void)ctx; return ((struct isess *)sess)->room; }
static int in_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct isess *s = sess;
    (void)buf; (void)cap;
    *got = 0;
    if (s->aborted) return -1;
    if (!s->qn) return s->rx_fin ? -1 : 0;
    *data = s->q;                                /* указатель в саму сессию, без копии в буфер стека */
    *got = s->qn;
    s->qn = 0;
    return 0;
}
static int in_aborted(const void *sess) { return ((const struct isess *)sess)->aborted; }
static void in_loop_start(int w, int n) { (void)w; (void)n; }
static void in_loop_poll(int r) { (void)r; }
static int in_loop_wait(void) { return -1; }
static void in_loop_stop(void) {}

static const struct dialer_ops in_ops = {
    .name = "в цикле", .caps = DC_INLOOP, .sess_size = sizeof(struct isess),
    .peer = h_peer, .describe = h_describe, .strerror = h_strerror, .connect = in_connect,
    .close = in_close, .clear = in_clear, .fd = in_fd, .has_data = in_has_data,
    .flow_open = in_flow_open, .send = in_send, .room = in_room, .dgram_frame = f_dgram_frame,
    .read = in_read, .deliver = h_deliver, .loop_start = in_loop_start, .loop_poll = in_loop_poll,
    .loop_wait = in_loop_wait, .loop_stop = in_loop_stop, .aborted = in_aborted,
};

static void t_inloop(void) {
    static const struct dialer hd = { .ops = &in_ops, .ctx = NULL };
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    g_spare_want = 0;
    stack_setup(&hd);
    g_in_thr = pthread_self();
    g_in_rc = 0;
    g_in_mode = 0;
    g_in_connects = 0;
    pm_drain(NULL, NULL);
    check(g_inloop, "в цикле: бит DC_INLOOP принят стеком");

    /* Исход сразу, из самого connect: ни установщика, ни потока. Установщики от прежних проверок могут уже
     * стоять (g_cq.started), поэтому смотрим на очередь: заявка в неё не ложится. */
    unsigned head0 = g_cq.head;
    struct conn *c = pm_open(41000, SRV_IP);
    check(c != NULL && g_in_connects == 1 && g_in_same_thread,
          "в цикле: connect зовёт сам стек, в своём потоке");
    check(g_cq.head == head0 && g_cq.n == 0, "  заявка установщику не ставилась (очередь не двигалась)");
    if (!c) return;
    check(c->fd == 77 && !c->armed, "  связь есть, а в epoll соединению ставить нечего (дескриптора нет)");

    /* Данные вниз: сессия говорит stack_sess_rx, стек читает указатель в неё и отдаёт клиенту в сокет. */
    int cfd = cli_fd(c);
    struct isess *is = SESS(c);
    memset(is->q, 'q', 1000);
    is->qn = 1000;
    g_rx_kick = 0;
    c->rx_ready = 0;
    stack_sess_rx(is);
    check(c->rx_ready && g_rx_kick, "в цикле: stack_sess_rx ставит чтение и признак витка");
    drain_conn(c, &g_tun);
    unsigned char qb[1100];
    check(cli_get(cfd, qb, sizeof qb) == 1000 && qb[0] == 'q' && qb[999] == 'q',
          "  клиенту ушло 1000 байт из сессии");

    /* Место у узла (room) решает, читается ли сокет клиента: нет места — данные ждут в сокете, вырастет —
     * stack_sess_room будит цикл, и проход сроков дочитывает без нового события на сокете. */
    unsigned char ud[100];
    memset(ud, 'u', sizeof ud);
    size_t was_sent = g_in_sent;
    is->room = 0;
    cli_put(c, ud, sizeof ud);
    cli_pump(c);
    check(!sock_want_read(c) && g_in_sent == was_sent && srv_pending(c) == (int)sizeof ud,
          "в цикле: места у узла нет — сокет клиента не читается, данные ждут в нём");
    is->room = 30000;
    g_rx_kick = 0;
    stack_sess_room(is);
    check(g_rx_kick && sock_want_read(c), "  выросшее место: цикл будится, сокет снова читается");
    conn_deadlines(c, &g_tun, c->estab_ns + 1);
    check(g_in_sent == was_sent + sizeof ud && srv_pending(c) == 0, "  проход сроков дочитал клиента — 100 байт ушли узлу");

    /* Оборванная связь — RST, а не FIN. */
    is->aborted = 1;
    stack_sess_rx(is);
    drain_conn(c, &g_tun);
    check(c->srv_closed && c->aborted, "в цикле: чтение с ошибкой при оборванной связи — соединение оборвано");
    conn_deadlines(c, &g_tun, g_now_ns ? g_now_ns : now_ns());
    check(cli_end(cfd) == 2, "  клиенту RST, а не FIN");

    /* Исход позже: соединение ждёт (pending), клиент пишет в сокет, исход приходит из дайлера. */
    g_in_mode = 1;
    g_in_late = NULL;
    uint16_t sp = 41001;
    c = sock_conn_tcp(sp, SRV_IP);
    check(c && c->pending && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) && g_in_late,
          "в цикле: исход не сразу — заявка ждёт, соединение недотрогаемо");
    if (c && g_in_late) {
        unsigned char d[100];
        memset(d, 'e', sizeof d);
        cli_put(c, d, sizeof d);
        size_t was = g_in_sent;
        check(c->early_n == 0 && g_in_sent == was && srv_pending(c) == (int)sizeof d,
              "  данные клиента ждут в его сокете, в буфере ничего, узлу не уходят");
        g_in_late->linked = 1;
        stack_sess_ready(g_in_late, 0);
        check(__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) && c->rc == 0, "  stack_sess_ready поднимает готовность заявки");
        check(!conn_ready(c, &g_tun) && g_in_sent == was, "  разбор готовности — поток поднят, сокет ещё не читали");
        conn_deadlines(c, &g_tun, c->estab_ns + 1);
        check(g_in_sent == was + sizeof d, "  проход сроков прочитал сокет — данные ушли узлу");
        conn_drop(c);
    }

    /* Отказ на месте: код из connect — исход заявки, клиенту RST. */
    g_in_mode = 0;
    g_in_rc = -2;
    sp = 41002;
    c = sock_conn_tcp(sp, SRV_IP);
    check(c && c->pending && __atomic_load_n(&c->done, __ATOMIC_ACQUIRE) && c->rc == -2,
          "в цикле: отказ connect — исход заявки без ожидания");
    if (c) {
        int rfd = cli_fd(c);
        check(conn_ready(c, &g_tun) == 1, "  разбор готовности закрывает соединение");
        check(cli_end(rfd) == 2, "  клиенту RST");
    }
    g_in_rc = 0;
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    pm_drain(NULL, NULL);
    g_inloop = 0;
}

/* Пул узлов и сброс соединений — после проверок разбора: пул заводит свой дайлер (pool_new), и
 * таблица соединений с этого места живёт с ним. */
static int pool_part(void) {
    signal(SIGPIPE, SIG_IGN);
    for (int i = 0; i < 80; i++) {
        g_sel[i] = i;
        snprintf(g_fn[i].name, sizeof g_fn[i].name, "n%d", i);
        snprintf(g_fn[i].host, sizeof g_fn[i].host, "h%d", i);
        g_fn[i].alive = 1;
    }
    g_lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = { .sin_family = AF_INET };
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    socklen_t sl = sizeof sa;
    if (g_lfd < 0 || bind(g_lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(g_lfd, 64) != 0 ||
        getsockname(g_lfd, (struct sockaddr *)&sa, &sl) != 0) return 2;
    g_lport = ntohs(sa.sin_port);
    dev_drain(NULL);
    t_pool_stack();
    t_pool_stale();
    t_pool_pick();
    t_pool_many();
    t_pool_refill();
    t_pool_spares();
    t_pool_kick_once();
    t_pool_unproven();
    t_pool_retry_cap();
    t_pool_state();
    t_pool_latency();
    t_inloop();
    return 0;
}

/* ---- пополнение запасных не молотит узел ------------------------------------------------------- */

/* Жалоба (Telegram, splify2 26.10, узел 3x-ui): после нескольких «пингов» узла из интерфейса роутер
 * открывает соединения к узлу и без правил, узел начинает молчать на ClientHello и приходит в себя через
 * 10-15 с. Каждое соединение, пришедшее после затишья, тянуло за собой ещё четыре запасных, а отказ узла
 * отодвигал пополнение на одни и те же пять секунд. Здесь считаются попытки установления к узлу на
 * подменённом дайлере и подменённых часах (g_spare_clock_ns): минуты — без ожидания. */
struct csess { int fd; };
static int g_cd_rc;                  /* что вернёт connect */
static int g_cd_total, g_cd_spare;   /* попыток всего и в запасные слоты */
static int g_cd_busy;                /* connect сейчас идёт */

static int cd_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)t;
    __atomic_add_fetch(&g_cd_busy, 1, __ATOMIC_SEQ_CST);
    __atomic_add_fetch(&g_cd_total, 1, __ATOMIC_SEQ_CST);
    for (int i = 0; i < SPARE_MAX; i++)
        if (g_spares[i].sess == sess) __atomic_add_fetch(&g_cd_spare, 1, __ATOMIC_SEQ_CST);
    int rc = g_cd_rc;
    ((struct csess *)sess)->fd = rc == 0 ? 99 : -1;
    __atomic_sub_fetch(&g_cd_busy, 1, __ATOMIC_SEQ_CST);
    return rc;
}
static void cd_take(void *dst, void *src) { (void)dst; (void)src; }
static void cd_close(void *sess) { ((struct csess *)sess)->fd = -1; }
static void cd_clear(void *sess) { ((struct csess *)sess)->fd = -1; }
static int cd_fd(const void *sess) { (void)sess; return -1; }   /* poll в checkout: -1 не опрашивается */
static int cd_has_data(const void *sess) { (void)sess; return 0; }
static const struct dialer_ops cd_ops = {
    .name = "счёт", .caps = DC_PRECONNECT, .sess_size = sizeof(struct csess),
    .peer = h_peer, .describe = h_describe, .strerror = h_strerror, .connect = cd_connect,
    .take = cd_take, .close = cd_close, .clear = cd_clear, .fd = cd_fd, .has_data = cd_has_data,
    .flow_open = h_flow_open, .send = h_send, .dgram_frame = f_dgram_frame, .read = h_read,
    .deliver = h_deliver,
};

/* Дождаться, пока установщики разберут очередь и закончат. */
static void cd_settle(void) {
    for (int i = 0; i < 400; i++) {
        pthread_mutex_lock(&g_cq.mu);
        int n = (int)g_cq.n;
        pthread_mutex_unlock(&g_cq.mu);
        if (!n && !__atomic_load_n(&g_cd_busy, __ATOMIC_SEQ_CST)) { usleep(20000); return; }
        usleep(5000);
    }
}

/* Одно «соединение клиента» в момент t мс: то, что делает SYN в stack.c, — взять запасную и
 * пополнить пул. */
static void cd_syn(uint64_t t_ms) {
    g_spare_clock_ns = t_ms * 1000000ull + 1000000000000ull;
    static struct csess out;
    spare_sweep();
    if (spare_checkout(&out) == 0) cd_close(&out);
    spare_refill();
    cd_settle();
}

static void t_spare_churn(void) {
    static struct dialer cd = { .ops = &cd_ops, .ctx = NULL };
    const struct dialer *save_dl = g_dl;
    int save_want = g_spare_want;
    g_spare_want = 4;
    stack_setup(&cd);
    g_spare_fail_ns = 0;
    g_spare_syn_ns = 0;
    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].state = SPARE_EMPTY;

    /* Одиночные соединения раз в десять секунд (проверка отклика из интерфейса): по одному
     * соединению к узлу на проверку, без запасных. */
    g_cd_rc = 0; g_cd_total = g_cd_spare = 0;
    for (int k = 0; k < 6; k++) cd_syn((uint64_t)k * 10000);
    check(g_cd_spare == 0, "запасные: одиночные соединения раз в 10 с запасных не заводят");

    /* Поток соединений к здоровому узлу — запасные копятся, выгода пула цела. */
    g_cd_total = g_cd_spare = 0;
    for (int k = 0; k < 5; k++) cd_syn(100000 + (uint64_t)k * 100);
    check(g_cd_spare >= 3, "запасные: поток соединений к здоровому узлу пополняет пул");

    /* Затишье: ни одной попытки установления, пока соединений нет. */
    g_cd_total = 0;
    cd_settle();
    g_spare_clock_ns += 300ull * 1000000000ull;
    spare_sweep();
    check(g_cd_total == 0, "запасные: в затишье без соединений узлу не уходит ни одной попытки");

    /* Узел отказывает на каждом соединении, клиент открывает соединение каждую секунду две минуты. */
    for (int i = 0; i < SPARE_MAX; i++) { g_spares[i].state = SPARE_EMPTY; }
    g_spare_fail_ns = 0; g_spare_fail_n = 0; g_spare_syn_ns = 0;
    g_cd_rc = -1; g_cd_total = g_cd_spare = 0;
    for (int k = 0; k < 120; k++) cd_syn(1000000 + (uint64_t)k * 1000);
    printf("  отказ узла, 120 соединений за 120 с: запасных попыток %d\n", g_cd_spare);
    check(g_cd_spare <= 16, "запасные: узел отказывает две минуты — попыток в запасные не больше шестнадцати (было 96)");

    /* Узел ожил — первое же удачное установление снимает паузу, пул снова копится. */
    g_cd_rc = 0; g_cd_total = g_cd_spare = 0;
    g_spare_clock_ns += 100ull * 1000000000ull;
    for (int k = 0; k < 4; k++) cd_syn(2000000 + (uint64_t)k * 100);
    check(g_cd_spare >= 1, "запасные: узел ожил — пополнение возобновляется");

    for (int i = 0; i < SPARE_MAX; i++) g_spares[i].state = SPARE_EMPTY;
    g_spare_clock_ns = 0;
    g_spare_want = save_want;
    stack_setup(save_dl);
}

/* ---- раздача пакетов по рабочим потокам (R-146) ---------------------------------------------
 * Хэш владельца (stack_owner) — единственное, на чём держится «обе половины соединения у одного
 * потока»: читатель раздаёт им, рабочий проверяет им же. Проверяется то, что от него требуется:
 *   - один владелец у всех пакетов одного соединения, что бы в них ни менялось (флаги, номера,
 *     окно, размер, нагрузка), и у фрагментов одной датаграммы;
 *   - соединения расходятся по рабочим ровно, а не кучей, и не по тем же признакам, что корзины
 *     таблицы потока (иначе рабочий использовал бы 1/N корзин);
 *   - собранная из фрагментов датаграмма уходит владельцу своей пятёрки через почту, а не
 *     открывает вторую сессию у собравшего. */
static size_t own_pkt(unsigned char *p, uint32_t src, uint32_t dst, unsigned proto, unsigned sport,
                      unsigned dport, size_t pay, unsigned flags) {
    size_t hl = proto == 6 ? 40 : 28;
    memset(p, 0, hl + pay);
    p[0] = 0x45;
    p[2] = (unsigned char)((hl + pay) >> 8); p[3] = (unsigned char)(hl + pay);
    p[8] = 64; p[9] = (unsigned char)proto;
    memcpy(p + 12, &src, 4); memcpy(p + 16, &dst, 4);
    p[20] = (unsigned char)(sport >> 8); p[21] = (unsigned char)sport;
    p[22] = (unsigned char)(dport >> 8); p[23] = (unsigned char)dport;
    if (proto == 6) { p[32] = 0x50; p[33] = (unsigned char)flags; p[24] = (unsigned char)flags; p[28] = (unsigned char)(pay); }
    return hl + pay;
}

static void t_owner(void) {
    static unsigned char p[2048];
    int ok = 1;
    /* Один и тот же поток TCP: меняются флаги, номера, окно, нагрузка — владелец один. */
    for (unsigned nw = 2; nw <= 9; nw++) {
        size_t n0 = own_pkt(p, 0x0100a8c0u, 0x0771cbcbu, 6, 40001, 443, 0, 0x02);
        unsigned o = stack_owner(p, n0, nw);
        for (unsigned fl = 0; fl < 256; fl += 17)
            for (size_t pay = 0; pay < 1400; pay += 233) {
                size_t n = own_pkt(p, 0x0100a8c0u, 0x0771cbcbu, 6, 40001, 443, pay, fl);
                p[24] = (unsigned char)(fl * 3); p[28] = (unsigned char)pay; p[34] = (unsigned char)fl;
                if (stack_owner(p, n, nw) != o) ok = 0;
            }
        if (o >= nw) ok = 0;
    }
    check(ok, "владелец: все пакеты одного соединения (флаги, номера, нагрузка) — у одного рабочего");

    /* Расход: 8000 соединений от одного клиента по разным портам на 4 и 8 рабочих. */
    for (unsigned nw = 4; nw <= 8; nw += 4) {
        unsigned cnt[8] = { 0 };
        unsigned char used[8][CONN_BUCKETS];
        memset(used, 0, sizeof used);
        for (unsigned i = 0; i < 8000; i++) {
            size_t n = own_pkt(p, 0x0100a8c0u, 0x0771cbcbu + (i % 7) * 0x01000000u, i & 1 ? 6 : 17,
                               30000 + i, 443 + (i % 3), 0, 0x10);
            unsigned o = stack_owner(p, n, nw);
            cnt[o]++;
            struct flow_key k;
            size_t off;
            if (ip_parse(p, n, &k, &off) == 0) used[o][flow_hash(&k) & (CONN_BUCKETS - 1)] = 1;
        }
        unsigned lo = 8000, hi = 0, minb = CONN_BUCKETS;
        for (unsigned w = 0; w < nw; w++) {
            if (cnt[w] < lo) lo = cnt[w];
            if (cnt[w] > hi) hi = cnt[w];
            unsigned b = 0;
            for (unsigned j = 0; j < CONN_BUCKETS; j++) b += used[w][j];
            if (b < minb) minb = b;
        }
        printf("  %u рабочих: меньше всего %u, больше всего %u соединений из 8000; корзин у худшего %u из %d\n",
               nw, lo, hi, minb, CONN_BUCKETS);
        check(lo * 100 >= (8000 / nw) * 90 && hi * 100 <= (8000 / nw) * 110,
              nw == 4 ? "владелец: 8000 соединений на 4 рабочих — доли в пределах ±10%" :
                        "владелец: 8000 соединений на 8 рабочих — доли в пределах ±10%");
        check(minb >= CONN_BUCKETS * 8 / 10,
              "владелец не совпадает с корзиной таблицы: у каждого рабочего занято не меньше 80% корзин (при общем хэше было бы 1/N)");
    }

    /* Фрагменты: первый несёт порты, остальные нет, а хэш один. */
    fr_make(3000, 1);
    static unsigned char f1[2048], f2[2048], f3[2048];
    fr_pkt(f1, FR_SRC, 77, 0, 1480, 1);
    fr_pkt(f2, FR_SRC, 77, 1480, 1480, 1);
    fr_pkt(f3, FR_SRC, 77, 2960, 48, 0);
    int same = 1;
    for (unsigned nw = 2; nw <= 9; nw++) {
        unsigned a = stack_owner(f1, 20 + 1480, nw), b = stack_owner(f2, 20 + 1480, nw),
                 c = stack_owner(f3, 20 + 48, nw);
        if (a != b || b != c) same = 0;
    }
    check(same, "владелец: все фрагменты одной датаграммы — у одного рабочего");

    /* Мусор не роняет: короткий, не IPv4, нулевые длины. */
    unsigned char junk[8] = { 0x60 };
    check(stack_owner(junk, 8, 4) == 0 && stack_owner(p, 0, 4) == 0 && stack_owner(p, 20, 1) == 0,
          "владелец: короткий и не-IPv4 пакет и один рабочий — ноль, без чтения за границей");
}

/* Собранная из фрагментов датаграмма уходит владельцу пятёрки, а не остаётся у собравшего. */
static void t_owner_mail(void) {
    enum { NW = 4 };
    struct ring_work *rws;
    if (posix_memalign((void **)&rws, 64, NW * sizeof(*rws)) != 0) { check(0, "почта: нет памяти"); return; }
    memset(rws, 0, NW * sizeof(*rws));
    for (int i = 0; i < NW; i++) { pthread_mutex_init(&rws[i].mail.mu, NULL); rws[i].ring.efd = -1; }
    struct ring_work *save_rw = g_rw;
    unsigned save_nw = g_nwork;
    int save_worker = g_worker;
    g_rw = rws;
    g_nwork = NW;

    /* Подобрать отправителя, у которого владелец фрагментов (по адресам) не тот, что у пятёрки. */
    uint32_t src = FR_SRC;
    unsigned fo = 0, so = 0;
    static unsigned char fp[2048];
    for (int tries = 0; tries < 64; tries++, src += 0x01000000u) {
        fr_make(3000, 12);
        size_t n = fr_pkt(fp, src, 90, 0, 1480, 1);
        fo = stack_owner(fp, n, NW);
        static unsigned char whole[20 + 8 + 3000];
        size_t wn = own_pkt(whole, src, FR_DST, 17, 0x9c40, 0x01bb, 3000, 0);
        so = stack_owner(whole, wn, NW);
        if (fo != so) break;
    }
    check(fo != so, "почта: нашёлся отправитель с разными владельцами фрагментов и сессии");

    g_worker = (int)fo;
    g_now_ns = 3000ull * 1000000000ull;
    g_now_s = (time_t)(g_now_ns / 1000000000ull);
    unsigned long long no0 = g_not_owner;
    int live0 = g_live_n;
    fr_make(3000, 12);
    static unsigned char q[2048];
    size_t n1 = fr_pkt(q, src, 90, 0, 1480, 1);   handle_packet(&g_tun, q, n1);
    size_t n2 = fr_pkt(q, src, 90, 1480, 1480, 1); handle_packet(&g_tun, q, n2);
    size_t n3 = fr_pkt(q, src, 90, 2960, 48, 0);   handle_packet(&g_tun, q, n3);
    dev_drain(NULL);
    check(g_not_owner == no0, "почта: фрагменты пришли своему рабочему — «не у владельца» не растёт");
    check(g_live_n == live0, "почта: у собравшего сессии не появилось");
    check(rws[so].mail.n == 1 && rws[fo].mail.n == 0,
          "почта: собранная датаграмма лежит в почте владельца пятёрки, и только там");
    struct xpkt *x = xmail_take(&rws[so].mail);
    int whole_ok = x && x->n == 20 + g_fr_len && memcmp(x->d + 20, g_fr_dgram, g_fr_len) == 0 &&
                   stack_owner(x->d, x->n, NW) == so;
    check(whole_ok, "почта: пакет в ней — собранная датаграмма целиком, и хэш называет получателя");
    free(x);

    /* Пакет чужого рабочего считается и называется. */
    g_worker = (int)((so + 1) % NW);
    static unsigned char own[64];
    size_t on = own_pkt(own, src, FR_DST, 17, 0x9c40, 0x01bb, 3000 > 40 ? 8 : 0, 0);
    own[2] = 0; own[3] = 36;
    unsigned char *pk = own;
    no0 = g_not_owner;
    handle_packet(&g_tun, pk, on);
    dev_drain(NULL);
    check(g_not_owner == no0 + 1, "владелец: пакет, пришедший не тому рабочему, попал в счётчик");

    g_rw = save_rw;
    g_nwork = save_nw;
    g_worker = save_worker;
    free(rws);
}

/* I-529: таблица растёт, а не упирается в 320 и не вытесняет живых. Поток свой — таблицы у потока
 * свои (__thread), и главная таблица стенда с потолком TEST_SLOTS остаётся нетронутой. */
#define GROW_N 3000
static void *grow_thread(void *arg) {
    int *res = arg;     /* [0] ошибка, [1] слотов, [2] найдено, [3] указатель стабилен, [4] вытеснено */
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);
    size_t save_want = g_slots_want;
    g_slots_want = 8192;
    if (conn_table_init() != 0) { res[0] = 1; g_slots_want = save_want; return NULL; }
    struct conn *first = NULL;
    uint32_t first_sport = 0;
    for (int i = 0; i < GROW_N; i++) {
        struct conn *c = conn_new(&g_tun);
        if (!c) { res[0] = 2; break; }
        memset(c, 0, sizeof(*c));
        c->used = 1;
        c->fd = -1;
        c->aux = -1;
        c->livepos = -1;
        c->hnext = -1;
        c->key = cli_key();
        c->key.src = htonl(0x0a000000u + (uint32_t)(i / 60000));
        c->key.sport = (uint16_t)(1024 + i % 60000);
        c->last = g_now_s - 1;           /* свежее: вытеснять нельзя */
        conn_link(c);
        if (!first) { first = c; first_sport = c->key.sport; }
    }
    res[1] = (int)g_nslots;
    for (int i = 0; i < GROW_N; i++) {
        struct flow_key k = cli_key();
        k.src = htonl(0x0a000000u + (uint32_t)(i / 60000));
        k.sport = (uint16_t)(1024 + i % 60000);
        struct conn *c = conn_find(&k);
        if (c && c->used) res[2]++;
    }
    res[3] = first == &g_conns[0] && first->key.sport == first_sport;
    res[4] = (int)g_live_n;
    while (g_live_n) conn_drop(&g_conns[g_live[g_live_n - 1]]);
    res[5] = g_free_n;
    conn_table_free();
    g_slots_want = save_want;
    return NULL;
}

static void t_table_grow(void) {
    int res[8] = { 0 };
    pthread_t t;
    if (pthread_create(&t, NULL, grow_thread, res) != 0) { check(0, "I-529: стенд — поток"); return; }
    pthread_join(t, NULL);
    check(!res[0] && res[1] == GROW_N && res[4] == GROW_N,
          "I-529: 3000 свежих соединений в одной таблице — все слоты выданы, ни одно не вытеснено (было 320)");
    check(res[2] == GROW_N, "I-529: все 3000 находятся по хэшу (корзины выросли вместе с таблицей)");
    check(res[3], "I-529: слот 0 не сдвинулся и сохранил содержимое при росте (указатели установщиков живы)");
    check(res[5] == GROW_N, "I-529: после закрытия все слоты вернулись в свободные");
}

/* I-529: очередь установки без предела. Сто заявок разом при медленном узле: ни одна не отклонена, установщиков
 * заведено сверх постоянных четырёх (иначе 100 заявок по 150 мс на 4 потока — 3,75 с), и все исполнены. */
static int g_slow_run, g_slow_max, g_slow_done;
static int slow_connect(const void *ctx, void *sess, int timeout_s) {
    (void)ctx; (void)sess; (void)timeout_s;
    int r = __atomic_add_fetch(&g_slow_run, 1, __ATOMIC_RELAXED);
    int m = __atomic_load_n(&g_slow_max, __ATOMIC_RELAXED);
    while (r > m && !__atomic_compare_exchange_n(&g_slow_max, &m, r, 0, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {}
    struct timespec ts = { 0, 150 * 1000 * 1000 };
    nanosleep(&ts, NULL);
    __atomic_sub_fetch(&g_slow_run, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&g_slow_done, 1, __ATOMIC_RELAXED);
    return 0;
}

static void t_connectors_burst(void) {
    enum { N = 100 };
    static struct conn jobs[N];
    static struct dialer_ops slow_ops;
    static struct dialer slow_dl;
    memset(jobs, 0, sizeof(jobs));
    slow_ops = *g_dl->ops;
    slow_ops.connect = slow_connect;
    slow_dl = *g_dl;
    slow_dl.ops = &slow_ops;
    const struct dialer *save = g_dl;
    g_dl = &slow_dl;
    g_slow_run = g_slow_max = g_slow_done = 0;
    uint64_t t0 = now_ns();
    int refused = 0;
    for (int i = 0; i < N; i++) {
        struct connjob j = { .c = &jobs[i], .sess = &jobs[i], .sp = NULL, .efd = -1 };
        if (connq_push(&j) != 0) refused++;
    }
    for (int w = 0; w < 600 && __atomic_load_n(&g_slow_done, __ATOMIC_RELAXED) < N; w++) usleep(10000);
    double dt = (double)(now_ns() - t0) / 1e9;
    int done = g_slow_done, mx = g_slow_max;
    g_dl = save;
    check(refused == 0, "I-529: сто заявок разом — ни одна не отклонена (очередь была в 32)");
    check(done == N && mx > CONNECTORS && dt < 3.0,
          "I-529: установщики заведены по нагрузке — все 100 исполнены быстрее, чем четырьмя потоками");
    if (done != N || mx <= CONNECTORS) fprintf(stderr, "  исполнено %d, одновременно до %d, %.2f с\n", done, mx, dt);
}

/* I-534: запись в устройство не стоит в цикле. Устройство стенда — пара AF_UNIX/SOCK_DGRAM, и при полной
 * очереди write отвечает EAGAIN, как у TUN. Прежде udp_write_to_client ждал освобождения до 200 мс (poll по
 * миллисекунде); теперь датаграмма уходит в очередь потока, вызов возвращается сразу, а после слива всё
 * доходит по порядку. */
static void t_tun_wq(void) {
    dev_drain(NULL);
    int fl = fcntl(g_tun.fd, F_GETFL);
    fcntl(g_tun.fd, F_SETFL, fl | O_NONBLOCK);
    int small = 4096, old_buf = 0;
    socklen_t ol = sizeof old_buf;
    getsockopt(g_tun.fd, SOL_SOCKET, SO_SNDBUF, &old_buf, &ol);
    setsockopt(g_tun.fd, SOL_SOCKET, SO_SNDBUF, &small, sizeof small);
    unsigned char payload[600];
    memset(payload, 'q', sizeof payload);
    int sent = 0, queued_at = -1;
    uint64_t t0 = now_ns();
    for (int i = 0; i < 400; i++) {
        payload[0] = (unsigned char)i;
        payload[1] = (unsigned char)(i >> 8);
        if (udp_write_to_client(&g_tun, SRV_IP, CLI_IP, SRV_PORT, CLI_PORT, payload, sizeof payload, 1) != 0) break;
        sent++;
        if (queued_at < 0 && tun_wq_pending()) queued_at = i;
    }
    double dt = (double)(now_ns() - t0) / 1e9;
    check(sent == 400 && queued_at > 0 && tun_wq_pending() && dt < 0.15,
          "I-534: заполненная очередь устройства — запись не ждёт (400 датаграмм за <150 мс), остаток в очереди потока");
    if (sent != 400 || queued_at <= 0 || dt >= 0.15) fprintf(stderr, "  ушло %d, очередь с %d, %.3f с\n", sent, queued_at, dt);
    /* Слив: устройство читают, очередь выпускается по порядку; ни одной потери и ни одной перестановки. */
    int got = 0, bad = 0, next = 0;
    for (int round = 0; round < 2000 && (got < 400); round++) {
        unsigned char p[2000];
        ssize_t r;
        while ((r = recv(g_dev_peer, p, sizeof p, MSG_DONTWAIT)) > 0) {
            int id = p[28] | (p[29] << 8);          /* IPv4 (20) + UDP (8): первые два байта нагрузки */
            if (id != next) bad++;
            next = id + 1;
            got++;
        }
        if (tun_wq_pending()) tun_wq_flush();
        else if (got < 400) usleep(1000);
    }
    check(got == 400 && !bad && !tun_wq_pending() && tun_wq_dropped() == 0,
          "I-534: после слива доставлены все 400 датаграмм по порядку, очередь пуста, отброшенных нет");
    setsockopt(g_tun.fd, SOL_SOCKET, SO_SNDBUF, &old_buf, sizeof old_buf);   /* дальше стенду нужны прежние буферы */
    fcntl(g_tun.fd, F_SETFL, fl);
    dev_drain(NULL);
}

/* I-535: проба кандидатов наперегонки. Мёртвые узлы молчат до срока (здесь 2 с — вместо 8), живой отвечает
 * за 50 мс. Последовательный перебор отдал бы 4 × 2 с + 50 мс, гонка — задержку запуска пятого (4 × 250 мс). */
struct race_t { int alive_from; int alive_ms; int dead_ms; };
static int race_probe(void *arg, int id, char *why, size_t n) {
    const struct race_t *r = arg;
    int alive = id >= r->alive_from;
    struct timespec ts = { 0, (long)(alive ? r->alive_ms : r->dead_ms) * 1000000L };
    nanosleep(&ts, NULL);
    if (alive) { snprintf(why, n, "жив %d", id); return 0; }
    snprintf(why, n, "молчит %d", id);
    return -1;
}
static void t_race(void) {
    static const int ids[6] = { 10, 11, 12, 13, 14, 15 };
    static struct race_t dead4 = { .alive_from = 14, .alive_ms = 50, .dead_ms = 2000 };
    char why[64];
    struct pool_race pr = { .n = 6, .ids = ids, .probe = race_probe, .arg = &dead4 };
    uint64_t t0 = now_ns();
    int w = pool_race_first(&pr, why, sizeof why);
    double dt = (double)(now_ns() - t0) / 1e9;
    check(w == 14 && !strcmp(why, "жив 14") && dt < 1.6,
          "I-535: четыре мёртвых узла по 2 с и живой пятый — ответ за ~1 с (последовательно было бы 8 с)");
    if (w != 14 || dt >= 1.6) fprintf(stderr, "  победитель %d (%s), %.2f с\n", w, why, dt);

    /* Порядок предпочтения: первый живой ответил за 50 мс, второй стартует через 250 — побеждает первый. */
    static struct race_t both = { .alive_from = 10, .alive_ms = 50, .dead_ms = 0 };
    pr.arg = &both;
    w = pool_race_first(&pr, why, sizeof why);
    check(w == 10, "I-535: живые первый и второй — побеждает первый, порядок предпочтения сохранён");

    /* Не ответил никто: -1 и причина последнего отказа; быстрые отказы не ждут задержки запуска. */
    static struct race_t none = { .alive_from = 99, .alive_ms = 0, .dead_ms = 100 };
    pr.arg = &none;
    t0 = now_ns();
    w = pool_race_first(&pr, why, sizeof why);
    dt = (double)(now_ns() - t0) / 1e9;
    check(w == -1 && !strncmp(why, "молчит", 6) && dt < 1.0,
          "I-535: ни один не ответил — -1 с причиной, быстрые отказы идут один за другим без задержки запуска");
    /* Один кандидат и ни одного. */
    pr.n = 1;
    pr.arg = &both;
    check(pool_race_first(&pr, why, sizeof why) == 10, "I-535: один кандидат — проверяется он");
    pr.n = 0;
    check(pool_race_first(&pr, why, sizeof why) == -1, "I-535: кандидатов нет — -1");
}

int main(void) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0 || pipe(g_sess_pipe) != 0) return 2;
    if (write(g_sess_pipe[1], "x", 1) != 1) return 2;
    for (int i = 0; i < TEST_SLOTS; i++) g_cfd[i] = -1;
    memset(&g_tun, 0, sizeof(g_tun));
    g_tun.fd = sp[0];
    g_dev_peer = sp[1];
    snprintf(g_node.uuid, sizeof(g_node.uuid), "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(g_node.host, sizeof(g_node.host), "stand");
    /* То, что stack_run делает до потоков: дайлер и шаг сессий. Пул запасных выключен —
     * stack_setup тогда и памяти под него не берёт. */
    g_spare_want = 0;
    stack_setup(&g_dial);
    g_slots_want = TEST_SLOTS;
    if (conn_table_init() != 0) return 2;
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);

    t_no_connectors();
    t_connectors_burst();
    t_race();
    t_tun_wq();
    t_table_grow();
    t_tcp_tun_rst();
    t_bring_up_table();
    t_early_wait();
    t_sendagain_hold();
    t_client_full();
    t_srv_close_drain();
    t_sock_path();
    t_release_last_sleep();
    t_bad_uuid();
    t_send_refused();
    t_dns_evict();
    t_spare_slot();
    t_spare_churn();
    t_born_turn();
    t_server_first();
    t_room_window();
    t_aux_wake();
    t_tx_batch();
    t_empty_read();
    t_sock_chunks();
    t_udp_early_bounds();
    t_udp_defrag();
    t_owner();
    t_owner_mail();
    t_udp_big();
    if (pool_part() != 0) check(0, "стенд пула: слушатель на петле не завёлся");

    printf(g_fail ? "\ntunnelmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
