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
/* Место у узла (transport_room): -1 — без предела. g_room_on_read, если не -2, станет местом при
 * следующем чтении, как его сделал бы прочитанный у узла WINDOW_UPDATE. */
static long g_room = -1;
static long g_room_on_read = -2;
static int g_recv_calls;
static int g_recv_rc;                 /* что вернёт transport_read_zc: 0 или -1 (конец потока) */
static unsigned char g_recv_buf[4096];
static size_t g_recv_n;               /* сколько отдать при g_recv_rc == 0 (разово) */

int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    (void)node; (void)timeout_s;
    memset(conn, 0, sizeof(*conn));
    conn->link.fd = g_sess_pipe[0];
    conn->link.plain = 1;
    return 0;
}
int transport_write(struct transport *c, const unsigned char *d, size_t n) {
    (void)c; (void)d;
    g_send_calls++;
    g_send_last_n = n;
    if (g_send_again_n > 0) { g_send_again_n--; return H2_EWINDOW; }
    return g_send_rc;
}
int transport_read_zc(struct transport *c, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    (void)c; (void)buf; (void)cap;
    g_recv_calls++;
    if (g_room_on_read != -2) { g_room = g_room_on_read; g_room_on_read = -2; }
    *got = 0;
    if (g_recv_rc) return g_recv_rc;
    *data = g_recv_buf;
    *got = g_recv_n;
    g_recv_n = 0;
    return 0;
}
int transport_has_data(const struct transport *c) { (void)c; return 0; }
long transport_room(struct transport *c) { (void)c; return g_room; }
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

/* Один пакет клиента посреди порции из TUN: собранные данные остаются собранными. */
static void cli_send_more(uint32_t seq, uint32_t ack, unsigned char flags, uint16_t win,
                          const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, seq, ack, flags,
                         d, n, win, 0, -1);
    handle_packet(&g_tun, p, l);
}

/* Один пакет клиента как целая порция из TUN: то, что цикл делает после порции, up_flush. */
static void cli_send(uint32_t seq, uint32_t ack, unsigned char flags, uint16_t win,
                     const unsigned char *d, size_t n) {
    cli_send_more(seq, ack, flags, win, d, n);
    up_flush(&g_tun);
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

/* Открыть соединение до состояния «поток готов, сервер ответил заголовком и 1000 байт,
 * клиент их ещё не подтвердил». Клиентский ISN 1000. */
static struct conn *open_conn(uint16_t win) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    cli_send(1000, 0, TCP_SYN, win, NULL, 0);
    c = conn_find(&k);
    if (!c || !c->pending || wait_ready(c, 2000) != 0) return NULL;
    cli_send(1001, 2, TCP_ACK, win, NULL, 0);
    g_recv_rc = 0;
    g_recv_buf[0] = 0; g_recv_buf[1] = 0;                 /* ответ VLESS: версия, длина доп. */
    memset(g_recv_buf + 2, 'r', 1000);
    g_recv_n = 1002;
    drain_conn(c, &g_tun);
    dev_drain(NULL);
    /* Стенд сам себя проверяет: без этого «провал» мог бы означать сломанную подготовку.
     * «Ответ VLESS снят» — состояние дайлера, оно в его сессии. */
    const struct vl_sess *vs = SESS(c);
    if (!vs->established || c->rtx.len != 1000 || c->srv_closed) return NULL;
    return c;
}

/* ---- проверки ------------------------------------------------------------------ */

/* I-322: установщиков не создалось ни одного. Прежде очередь считалась запущенной, SYN
 * получал SYN-ACK, а заявка висела pending навсегда — ни RST, ни повторной попытки. */
static void t_no_connectors(void) {
    g_refuse_threads = 1;
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    struct flow_key last;
    int synack = 0;
    int n = dev_drain(&last);
    if (n && (last.tcp_flags & TCP_SYN)) synack = 1;
    check(!c && !synack, "I-322: без установщиков SYN отклонён, SYN-ACK не ушёл");
    if (c) conn_drop(c);

    /* Стек дали — следующий SYN обязан получить установщика: отказ не залипает. */
    g_refuse_threads = 0;
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    c = conn_find(&k);
    check(c && c->pending && wait_ready(c, 2000) == 0,
          "I-322: после отказа установщики заводятся на следующем SYN");
    if (c) conn_drop(c);
    dev_drain(NULL);
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

/* I-320: окно HTTP/2 закрыто (SEND_AGAIN), и туннель читает у сервера, надеясь на
 * WINDOW_UPDATE. Читать можно только то, что клиент в силах принять: прочитанное за его
 * окно уходит в пустоту и лечится лишь повтором по таймауту. */
static void t_sendagain_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    /* Клиент принял не всё и объявил окно ровно под уже отправленное: места нет. */
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_EWINDOW;
    g_recv_rc = 0;
    memset(g_recv_buf, 'r', 1000);
    g_recv_n = 1000;
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 1000, d, sizeof(d) - 1);
    check(g_recv_calls == calls, "I-320: при закрытом окне клиента у сервера не читаем");
    g_send_rc = 0;
    g_recv_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* I-320, обратная сторона: окно клиента открыто — чтение у сервера делается (оттуда
 * приходит WINDOW_UPDATE), повторная отправка удаётся, пакет подтверждён. */
static void t_sendagain_retry(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_again_n = 1;
    g_recv_rc = 0;
    g_recv_n = 0;                                       /* служебный кадр: данных нет */
    int calls = g_recv_calls;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    check(g_recv_calls > calls && c->used && c->client_seq == 1001 + sizeof(d) - 1,
          "I-320: окно клиента открыто — читаем, повтор отправки удался");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
}

/* I-320: на том же чтении сервер закрыл поток. Соединение обязано дожить до подтверждения
 * уже отправленного (srv_closed, как в drain_conn), а не пропасть вместе с кольцом. */
static void t_sendagain_eof(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-320: соединение не открылось"); return; }
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_EWINDOW;
    g_recv_rc = -1;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(c && c->srv_closed && c->rtx.len == 1000,
          "I-320: конец потока при SEND_AGAIN — соединение живо, 1000 байт ждут подтверждения");
    g_send_rc = 0;
    g_recv_rc = 0;
    if (c) conn_drop(c);
    dev_drain(NULL);
}

/* I-321: сегмент не по порядку отбрасывается (буфера переупорядочивания нет), но ответить
 * на него обязаны подтверждением ожидаемого номера: без дубликатов ACK у клиента не
 * срабатывает быстрый повтор, и дыра закрывается только по таймауту. Тот же ответ нужен и
 * на повтор уже принятого — иначе потерянный наш ACK не восстанавливается ничем. */
static void t_out_of_order_dupack(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-321: соединение не открылось"); return; }
    const unsigned char d[100] = { 0 };
    struct flow_key last;
    cli_send(1001 + 500, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_ACK) && last.ack == 1001 && c->client_seq == 1001,
          "I-321: сегмент за дырой — не принят, ушёл ACK ожидаемого номера");

    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* по порядку */
    flush_acks(&g_tun);
    dev_drain(NULL);
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));      /* его же повтор */
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n == 1 && last.ack == 1101 && c->client_seq == 1101,
          "I-321: повтор принятого — не принят дважды, ACK с текущим номером");
    conn_drop(c);
    dev_drain(NULL);
}

/* Масштаб окна приёма (RFC 7323). Клиент с опцией масштаба в SYN получает в SYN-ACK нашу опцию и окно без
 * масштаба (в SYN и SYN-ACK окно не масштабируется никогда); в данных и подтверждениях поле окна — потолок,
 * делённый на наш множитель, то есть настоящее окно выше 64 КБ. Клиент без опции в SYN не получает её в
 * ответ (опция в SYN-ACK без опции в SYN — нарушение RFC 7323, 2.2) и видит 65535 во всех пакетах, как
 * прежде.
 *
 * Стенд проверяет и сам расчёт множителя (rcv_window_set): наименьший, при котором поле вмещает потолок, и
 * поле окна с округлением вверх (rcv_win_field): прежние 65535 при множителе 7 не должны стать 65408. */
static void syn_opts(uint32_t seq, int wscale) {
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, seq, 0, TCP_SYN, NULL, 0,
                         65535, 1460, wscale);
    handle_packet(&g_tun, p, l);
}

/* Подтверждение 100 байт данных клиента: ключ последнего пакета, ушедшего в «устройство» (n — сколько их). */
static int ack_after_data(uint32_t seq, struct flow_key *last) {
    static const unsigned char d[100] = { 0 };
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    flush_acks(&g_tun);
    memset(last, 0, sizeof(*last));
    return dev_drain(last);
}

static void t_window_scale(void) {
    uint32_t keep_wnd = g_rcv_wnd;
    uint8_t keep_shift = g_rcv_shift;

    rcv_window_set(100);
    check(g_rcv_wnd == 65535 && g_rcv_shift == 0, "масштаб окна: потолок ниже 65535 — 65535, без множителя");
    rcv_window_set(65535);
    check(g_rcv_wnd == 65535 && g_rcv_shift == 0, "  ровно 65535 — множитель 0");
    rcv_window_set(65536);
    check(g_rcv_wnd == 65536 && g_rcv_shift == 1, "  65536 — множитель 1 (65535 << 0 не вмещает)");
    rcv_window_set(1u << 20);
    check(g_rcv_wnd == (1u << 20) && g_rcv_shift == 5, "  1 МиБ — множитель 5 (65535 << 4 = 1048560 не вмещает)");
    rcv_window_set(4u << 20);
    check(g_rcv_wnd == (4u << 20) && g_rcv_shift == 7, "  4 МиБ — множитель 7 (65535 << 6 = 4194240 не вмещает)");
    rcv_window_set(0xFFFFFFFFu);
    check(g_rcv_shift == 14 && g_rcv_wnd == (65535u << 14), "  больше предела — множитель 14 (RFC 7323, 2.3), потолок 65535 << 14");

    /* Дальше — потолок 1 МиБ, множитель 5: в поле окна 32768. */
    rcv_window_set(1u << 20);
    struct flow_key k = cli_key(), last;
    struct conn *c0 = conn_find(&k);
    if (c0) conn_drop(c0);
    dev_drain(NULL);

    syn_opts(1000, 7);                                    /* клиент: опция масштаба 7 */
    struct conn *c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(c && n == 1 && (last.tcp_flags & (TCP_SYN | TCP_ACK)) == (TCP_SYN | TCP_ACK) && last.ws_seen &&
              last.wscale == 5,
          "SYN с опцией масштаба: SYN-ACK несёт нашу опцию с множителем 5");
    check(n == 1 && last.window == EARLY_CAP, "  окно в самом SYN-ACK — без масштаба, по буферу ранних данных (установщик работает)");
    check(c && c->ws_on && c->client_wscale == 7, "  у соединения: масштаб включён, множитель клиента 7 прочитан");
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
        n = ack_after_data(1001, &last);
        check(n == 1 && (last.tcp_flags & TCP_ACK) && last.ack == 1101 && last.window == 32768,
              "  подтверждение данных: поле окна 32768 — с множителем 5 это 1 МиБ");
        check(((uint32_t)last.window << g_rcv_shift) == g_rcv_wnd, "  и настоящее окно (поле << 5) равно потолку");
    } else {
        check(0, "  установщик не доложил");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);

    /* Множитель 7 и потолок 65535 (STEER_TUN_RCVWND=0 при клиенте с масштабом): поле округляется вверх. */
    rcv_window_set(65535);
    check(g_rcv_shift == 0, "потолок 65535 — множитель 0, окно прежнее");
    rcv_window_set(65536 + 100);
    c = NULL;
    syn_opts(1500, 3);
    c = conn_find(&k);
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(1501, 2, TCP_ACK, 65535, NULL, 0);
        dev_drain(NULL);
        n = ack_after_data(1501, &last);
        check(n == 1 && last.window == (65636 + 1) / 2 && ((uint32_t)last.window << g_rcv_shift) >= g_rcv_wnd,
              "потолок не кратен множителю: поле округлено вверх (окно не меньше потолка)");
    } else {
        check(0, "  установщик не доложил (округление)");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);
    rcv_window_set(1u << 20);

    /* Опция масштаба с множителем 0 — всё равно опция: ответ обязателен, и окно масштабируется. */
    syn_opts(2000, 0);
    c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(c && c->ws_on && n == 1 && last.ws_seen && last.wscale == 5 && c->client_wscale == 0,
          "SYN с опцией масштаба 0: опция есть (ws_seen), SYN-ACK с нашим множителем");
    if (c) wait_ready(c, 2000);                           /* заявка в работе закрыть нельзя */
    if (c) conn_drop(c);
    dev_drain(NULL);

    /* SYN без опции масштаба. */
    syn_opts(3000, -1);
    c = conn_find(&k);
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(c && !c->ws_on && n == 1 && !last.ws_seen && last.window == EARLY_CAP,
          "SYN без опции масштаба: SYN-ACK без опции, окно по буферу ранних данных");
    if (c && wait_ready(c, 2000) == 0) {
        cli_send(3001, 2, TCP_ACK, 65535, NULL, 0);
        n = ack_after_data(3001, &last);
        check(n == 1 && last.ack == 3101 && last.window == 65535,
              "  и подтверждение данных — окно 65535, масштаб не применяется");
    } else {
        check(0, "  установщик не доложил");
    }
    if (c) conn_drop(c);
    dev_drain(NULL);

    rcv_window_set(keep_wnd);
    g_rcv_shift = keep_shift;
}

/* I-193: установщик доложил за время ПОСЛЕДНЕГО сна ожидания. Прежде проверка стояла перед
 * сном, результат последнего не спрашивался, и приговор «не доложил за 15 с» ставился по
 * счётчику кругов — таблица при этом намеренно не освобождается. */
static void t_release_last_sleep(void) {
    struct conn *c = &g_conns[MAX_CONNS - 1];
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

/* Окно клиента, пока установщик ещё работает: не больше места в буфере ранних данных (EARLY_CAP).
 * Прежде SYN-ACK и подтверждения обещали полное окно, клиент отправлял десять сегментов, в буфер
 * влезало пять, а остальные handle_packet не подтверждал: дыра, таймаут повтора у клиента (200 мс,
 * потом вдвое чаще каждый круг: без SACK Linux после него в состоянии потери, дубликаты ACK быстрый
 * повтор не запускают, а сегменты за дырой мы выбрасываем) — и выгрузка на нагрузке стояла больше
 * десяти секунд (tests/sigpipe.sh: «ни одна выгрузка не застряла на записи»). */
static void t_early_window(void) {
    struct flow_key k = cli_key();
    struct conn *c = conn_find(&k);
    if (c) conn_drop(c);
    dev_drain(NULL);
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct flow_key last;
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    c = conn_find(&k);
    check(c && c->pending && (last.tcp_flags & TCP_SYN) && last.window <= EARLY_CAP,
          "ранние данные: SYN-ACK при работающем установщике обещает не больше EARLY_CAP");
    if (!c || !c->pending) return;
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);

    /* Десять сегментов подряд, как первое окно клиента: в буфер влезает пять. */
    unsigned char d[1460];
    memset(d, 'e', sizeof(d));
    uint32_t seq = 1001;
    for (int i = 0; i < 10; i++) {
        cli_send_more(seq, 2, TCP_ACK, 65535, d, sizeof(d));
        seq += sizeof(d);
    }
    uint32_t held = c->early_n;
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(held == 5 * sizeof(d) && last.ack == 1001 + held,
          "ранние данные: подтверждено ровно то, что поместилось в буфер");
    check(last.window == EARLY_CAP - held,
          "ранние данные: подтверждение обещает остаток буфера, а не полное окно");

    /* Клиент, который послушался окна, дыры не получает: остаток помещается. */
    seq = 1001 + held;
    cli_send(seq, 2, TCP_ACK, 65535, d, EARLY_CAP - held);
    check(c->early_n == EARLY_CAP, "ранние данные: сегмент в пределах окна принят");
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(last.window == 0, "ранние данные: буфер полон — нулевое окно");

    /* Установщик доложил: окно снова полное и клиенту об этом сказано сразу, а не по его пробе. */
    for (int i = 0; i < 2000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    int rd = __atomic_load_n(&c->done, __ATOMIC_ACQUIRE) ? conn_ready(c, &g_tun) : -1;
    check(rd == 0 && !c->pending, "ранние данные: соединение готово");
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n >= 1 && last.ack == 1001 + EARLY_CAP && last.window == 65535,
          "ранние данные: на готовности клиент получает обновление окна");
    conn_drop(c);
    dev_drain(NULL);
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
    unsigned char p[128];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, SRV_IP, CLI_PORT, SRV_PORT, 1000, 0, TCP_SYN,
                         NULL, 0, 65535, 0, -1);
    g_dial.ctx = bad;
    handle_packet(&g_tun, p, l);
    g_dial.ctx = &g_node;
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
    check(said && !c, "I-097: SYN к узлу с негодным UUID — отказ назван в журнале");
    if (c) conn_drop(c);
    dev_drain(NULL);
    said = stderr_has(run_bad, &bad, "не разбирается UUID");
    check(said && g_run_rc == 1, "I-097: подъём называет негодный UUID до подъёма устройства");
}

static void send_refused(void *arg) {
    (void)arg;
    const unsigned char d[] = "GET / HTTP/1.1\r\n";
    g_send_rc = H2_ESTATUS;
    cli_send(1001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d) - 1);
    g_send_rc = 0;
}

/* I-219: сервер xhttp не принял кусок выгрузки (vless_send вернул H2_ESTATUS). Соединение
 * закрывается, как при любой неудаче отправки, но причину обязан услышать человек: прежде
 * RST уходил молча, и узел выглядел живым. */
static void t_send_refused(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "I-219: соединение не открылось"); return; }
    g_now_s += 10;
    int said = stderr_has(send_refused, NULL, "не принял данные");
    struct flow_key k = cli_key();
    c = conn_find(&k);
    check(said && !c, "I-219: отказ сервера на отправку назван в журнале, соединение закрыто");
    if (c) conn_drop(c);
    dev_drain(NULL);
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
    while (g_free_n) {
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
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    c = conn_find(&k);
    check(c && c->born_turn == 41, "виток рождения: новое TCP-соединение помнит свой виток");
    g_turn = 42;
    check(c && c->born_turn != g_turn, "виток рождения: в следующем витке событие уже его собственное");
    if (c) {
        wait_ready(c, 2000);
        conn_drop(c);
    }
    dev_drain(NULL);
}

/* Наш FIN, когда сервер закрыл первым, обязан нести открытое окно. FIN занимает номер, а Linux не
 * шлёт ничего в нулевое окно: прежний FIN с окном 0 оставлял собственный FIN клиента ждать
 * обновления окна, которое не придёт, и сокет клиента навсегда застревал в LAST-ACK. */
static void t_fin_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "окно в FIN: соединение не открылось"); return; }
    cli_send(1001, 1002, TCP_ACK, 65535, NULL, 0);        /* клиент подтвердил всё принятое */
    c->srv_closed = 1;
    c->closed_at = now_ns();
    dev_drain(NULL);
    conn_deadlines(c, &g_tun, now_ns());
    struct flow_key last;
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && (last.tcp_flags & TCP_FIN) && last.window != 0,
          "окно в FIN: FIN сервера уходит клиенту с открытым окном, не с нулевым");
}

/* Сервер говорит первым (SSH, SMTP): клиент после рукопожатия молчит. VLESS сообщает узлу
 * назначение только в заголовке запроса, поэтому стек обязан сам послать один заголовок через
 * SERVER_FIRST_MS, один раз и без кадра Vision (как клиент Xray). Прежде такой поток не
 * открывался: узел ждал заголовка, клиент приветствия. */
static void server_first(const char *flow, size_t header_n) {
    snprintf(g_node.flow, sizeof(g_node.flow), "%s", flow);
    struct flow_key k = cli_key();
    cli_send(1000, 0, TCP_SYN, 65535, NULL, 0);
    struct conn *c = conn_find(&k);
    if (!c || wait_ready(c, 2000) != 0) {
        check(0, "сервер первым: тестовое соединение не открылось");
        if (c) conn_drop(c);
        g_node.flow[0] = 0;
        return;
    }
    char what[128];
    int calls = g_send_calls;
    /* SYN-ACK потерян: клиент его не подтвердил и повторит SYN. Откроем поток сейчас — ответ
     * сервера уйдёт раньше рукопожатия, и повторный SYN уже не получит ответа: ничего не должно
     * уходить, сколько бы ни прошло времени. */
    conn_deadlines(c, &g_tun, g_now_ns + 2000 * 1000000ull);
    snprintf(what, sizeof(what), "сервер первым%s: до ACK клиента ничего не отправлено",
             flow[0] ? ", Vision" : "");
    check(g_send_calls == calls && c->our_seq == 2, what);
    cli_send(1001, 2, TCP_ACK, 65535, NULL, 0);
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
    dev_drain(NULL);
    g_node.flow[0] = 0;
}

static void t_server_first(void) {
    server_first("", 26);                    /* версия, UUID, без доп., команда, порт, IPv4 */
    server_first("xtls-rprx-vision", 44);    /* плюс дополнение flow: 0a 10 "xtls-rprx-vision" */
}

/* Место у узла ограничивает окно клиента (dialer_ops.room). Прежде клиенту отдавалось полное
 * окно, сколько бы узел ни мог принять: против окна HTTP/2 в 94 КБ каждый отказ выглядел
 * потерей и стоил таймаута повторной передачи, выгрузка через grpc шла 10-20 Мбит/с с
 * остановками. */
static void t_room_window(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "место у узла: тестовое соединение не открылось"); return; }
    unsigned char d[100];
    memset(d, 'u', sizeof(d));
    struct flow_key last;
    uint32_t seq = 1001;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));        /* заголовок уходит */
    seq += sizeof(d);
    flush_acks(&g_tun);
    dev_drain(&last);
    check(last.window == 65535, "место у узла: транспорт без предела — полное окно");

    g_room = 5000;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    seq += sizeof(d);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(last.ack == seq && last.window == 5000, "место у узла: окно ограничено местом у узла");

    g_room = 0;
    cli_send(seq, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    seq += sizeof(d);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(last.ack == seq && last.window == 0, "место у узла: места нет — нулевое окно");

    /* Проба нулевого окна от клиента: номер на единицу меньше ожидаемого, без данных. */
    cli_send(seq - 1, 2, TCP_ACK, 65535, NULL, 0);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    int n = dev_drain(&last);
    check(n == 1 && last.ack == seq && last.window == 0, "место у узла: проба нулевого окна получает ответ");

    /* WINDOW_UPDATE от узла: обновление окна уходит клиенту, не дожидаясь пакета от него. */
    g_room_on_read = 60000;
    g_win_woke = 0;
    drain_conn(c, &g_tun);
    check(c->ack_due && g_win_woke, "место у узла: выросло от чтения у узла — обновление окна назначено");
    flush_acks(&g_tun);
    g_win_woke = 0;
    memset(&last, 0, sizeof(last));
    n = dev_drain(&last);
    check(n >= 1 && last.ack == seq && last.window == 60000, "место у узла: обновление несёт новое окно");

    /* Рост меньше WIN_UPDATE_MIN при открытом окне ждёт следующего ACK. */
    g_room_on_read = 60000 + WIN_UPDATE_MIN - 1;
    drain_conn(c, &g_tun);
    check(!c->ack_due && !g_win_woke, "место у узла: малый рост сам ничего не шлёт");

    g_room = -1;
    g_room_on_read = -2;

    /* Цикл отстаёт от устройства (порция из TUN упёрлась в TUN_DRAIN_MAX): клиент с масштабом
     * получает не больше RCV_WND_BACKLOG, чтобы его неподтверждённые данные, ждущие в очереди
     * устройства перед ACK скачиваний, оставались короткими; цикл успевает — снова полное окно. */
    uint32_t save_wnd = g_rcv_wnd;
    uint8_t save_shift = g_rcv_shift;
    rcv_window_set(4u << 20);
    c->ws_on = 1;
    uint32_t full = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    g_tun_backlog = 1;
    uint32_t held = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    g_tun_backlog = 0;
    uint32_t back = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    check(full >= (4u << 20) && held <= RCV_WND_BACKLOG && held > RCV_WND_BACKLOG / 2 && back == full,
          "отставание цикла: окно падает до RCV_WND_BACKLOG и возвращается");
    c->ws_on = 0;
    g_rcv_wnd = save_wnd;
    g_rcv_shift = save_shift;
    conn_drop(c);
    dev_drain(NULL);
}

/* Подряд идущие сегменты одного потока в одной порции из TUN уходят узлу ОДНОЙ отправкой (g_up
 * в stack.c): одна запись TLS и один write вместо одной на каждый сегмент в 1,4 КБ, что стоило
 * выгрузке 80% цикла. Подтверждаются, только когда узел их принял, как и прежде. */
static void t_gather(void) {
    struct conn *c = open_conn(65535);
    if (!c) { check(0, "сборка: тестовое соединение не открылось"); return; }
    unsigned char d[1000];
    memset(d, 'g', sizeof(d));
    struct flow_key last;
    int calls = g_send_calls;
    cli_send_more(1001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(2001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(3001, 2, TCP_ACK | TCP_PSH, 65535, d, sizeof(d));
    check(g_send_calls == calls && c->client_seq == 1001,
          "сборка: три сегмента порции — пока ничего не отправлено и не подтверждено");
    up_flush(&g_tun);
    flush_acks(&g_tun);
    memset(&last, 0, sizeof(last));
    dev_drain(&last);
    check(g_send_calls == calls + 1 && g_send_last_n == 26 + 3000 && c->client_seq == 4001 &&
          last.ack == 4001, "сборка: конец порции — одна отправка (заголовок + 3000), один ACK на всё");

    /* FIN после собранных данных: сначала данные, затем отдельный сегмент FIN. */
    calls = g_send_calls;
    cli_send_more(4001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(5001, 2, TCP_ACK | TCP_FIN, 65535, d, 10);
    check(g_send_calls == calls + 2 && c->client_seq == 5012 && c->client_fin,
          "сборка: FIN сначала отправляет собранное, по порядку");
    conn_drop(c);
    dev_drain(NULL);

    /* Дыра: собранное уходит, сегмент за дырой не принят. */
    c = open_conn(65535);
    if (!c) { check(0, "сборка: тестовое соединение не открылось"); return; }
    calls = g_send_calls;
    cli_send_more(1001, 2, TCP_ACK, 65535, d, sizeof(d));
    cli_send_more(3001, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(g_send_calls == calls + 1 && c->client_seq == 2001,
          "сборка: сегмент за дырой отправляет собранное и сам не принят");

    /* Узел отказал собранной отправке (окно закрыто): ничего не подтверждено, и продолжение в
     * той же порции тоже не принято: клиент повторит с 2001. */
    g_send_again_n = 1;
    g_recv_rc = -1;                     /* WINDOW_UPDATE не приходит: ожидание читает конец потока */
    cli_send_more(2001, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(c->client_seq == 2001, "сборка: отправка отказана — ничего не подтверждено");
    g_send_again_n = 0;
    g_recv_rc = 0;
    conn_drop(c);
    dev_drain(NULL);

    /* Буфер полон, а следующий сегмент вынуждает отправку, и узел её отказывает (окно закрыто и
     * после ожидания). Этот сегмент идёт за байтами, которые НЕ приняты: нового накопления он
     * начинать не вправе, иначе поток перескочил бы через них. */
    c = open_conn(65535);
    if (!c) { check(0, "сборка: тестовое соединение не открылось"); return; }
    uint32_t seq = 1001;
    while (seq - 1001 + sizeof(d) <= UP_MAX) {
        cli_send_more(seq, 2, TCP_ACK, 65535, d, sizeof(d));
        seq += sizeof(d);
    }
    g_send_again_n = 2;                 /* отправка и её повтор после ожидания */
    g_recv_rc = 0;
    g_recv_n = 0;
    cli_send_more(seq, 2, TCP_ACK, 65535, d, sizeof(d));
    up_flush(&g_tun);
    check(c->client_seq == 1001 && g_up.c == NULL,
          "сборка: отказ при полном буфере — следующий сегмент тоже не принят");
    g_send_again_n = 0;
    conn_drop(c);
    dev_drain(NULL);
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

struct fnode { char name[16]; char host[16]; int alive; };
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
    if (((const struct fnode *)node)->alive) return 0;
    snprintf(why, n, "узел стенда молчит");
    return -1;
}
static const char *f_name(const void *node) { return ((const struct fnode *)node)->name; }
static const struct pool_proto f_proto = { .ops = &f_ops, .probe = f_probe, .name = f_name, .tag = "pm" };

static int g_sel[80] = { 0, 1, 2, 3, 4 };

/* Пул заново: active слотов, кандидаты 0..ncand-1, первый — узел 0. */
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
        .interval_s = 60, .silence_s = 20, .out = out,
    };
    const struct dialer *d = pool_setup(&pc);
    g_spare_want = 0;
    stack_setup(d);
}


static void pm_send(uint16_t sport, uint32_t dst, uint32_t seq, uint32_t ack, unsigned char flags,
                     const unsigned char *d, size_t n) {
    unsigned char p[2048];
    size_t l = tcp_build(p, sizeof(p), CLI_IP, dst, sport, 443, seq, ack, flags, d, n, 65535, 0, -1);
    handle_packet(&g_tun, p, l);
    up_flush(&g_tun);                       /* пакет здесь — целая порция, как в cli_send */
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

/* Соединение до «поток готов»: SYN, установщик, готовность (conn_ready), ACK клиента. */
static struct conn *pm_open(uint16_t sport, uint32_t dst) {
    struct flow_key k = pm_key(sport, dst);
    pm_send(sport, dst, 1000, 0, TCP_SYN, NULL, 0);
    struct conn *c = conn_find(&k);
    if (!c || !c->pending) return NULL;
    for (int i = 0; i < 3000 && !__atomic_load_n(&c->done, __ATOMIC_ACQUIRE); i++) {
        struct timespec ts = { 0, 1000000 };
        nanosleep(&ts, NULL);
    }
    if (!__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) || conn_ready(c, &g_tun)) return NULL;
    pm_send(sport, dst, 1001, 2, TCP_ACK, NULL, 0);
    pm_drain(NULL, NULL);
    return conn_find(&k);
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
          "данные без соединения (клиент выхода перезапущен) — RST с номером его подтверждения");
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
    pm_drain(NULL, NULL);
    pm_send(50002, 0x0a0a0a0bu, 1001, c->our_seq, TCP_ACK, NULL, 0);
    pm_srv_rst(s);
    drain_conn(c, &g_tun);
    check(c->srv_closed && c->aborted, "RST узла — связь оборвана (aborted), а не закрыта");
    check(g_pl.slot[0].kick == 1 && g_pl.slot[0].lost == 1, "обрыв связи — слежке: проверить узел сейчас (lost)");
    pm_sweep();
    n = pm_drain(&fl, NULL);
    struct flow_key k = pm_key(50002, 0x0a0a0a0bu);
    check(n == 1 && (fl & TCP_RST) && !(fl & TCP_FIN) && !conn_find(&k),
          "оборванная связь — клиенту RST, а не FIN (обрезанный ответ не выглядит целым)");

    /* Обрыв, когда клиент ещё не подтвердил отданное: какой номер он ждёт, неизвестно — RST обоими. */
    c = pm_open(50005, 0x0a0a0a0bu);
    if (!c) { check(0, "стенд: соединение для двух RST не открылось"); return; }
    s = pm_srv_of(c);
    if (send(s, "abcdef", 6, 0) != 6) check(0, "стенд: сервер не отправил");
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    pm_drain(NULL, NULL);
    uint32_t ca = c->client_ack, os = c->our_seq;
    pm_srv_rst(s);
    drain_conn(c, &g_tun);
    pm_sweep();
    {
        unsigned char p[2048];
        uint32_t seqs[4];
        int m = 0;
        ssize_t r;
        while (m < 4 && (r = recv(g_dev_peer, p, sizeof p, MSG_DONTWAIT)) > 0) {
            struct flow_key kk;
            size_t off;
            if (ip_parse(p, (size_t)r, &kk, &off) == 0 && (kk.tcp_flags & TCP_RST)) seqs[m++] = kk.seq;
        }
        check(os == ca + 6 && m == 2 && seqs[0] == ca && seqs[1] == os,
              "обрыв при неподтверждённом — RST и с подтверждённым номером, и с отправленным (RFC 5961)");
    }

    /* Узел закрыл связь штатно. */
    c = pm_open(50003, 0x0a0a0a0bu);
    if (!c) { check(0, "стенд: второе соединение не открылось"); return; }
    s = pm_srv_of(c);
    shutdown(s, SHUT_WR);
    nanosleep(&ts, NULL);
    drain_conn(c, &g_tun);
    check(c->srv_closed && !c->aborted, "FIN узла — закрытие, не обрыв");
    pm_sweep();
    n = pm_drain(&fl, NULL);
    check(n == 1 && (fl & TCP_FIN) && !(fl & TCP_RST), "закрытая узлом связь — клиенту FIN, как прежде");
    close(s);

    /* Отправка узлу не удалась. */
    c = pm_open(50004, 0x0a0a0a0bu);
    if (!c) { check(0, "стенд: третье соединение не открылось"); return; }
    pm_srv_rst(pm_srv_of(c));
    pm_send(50004, 0x0a0a0a0bu, 1001, 2, TCP_ACK | TCP_PSH, d, sizeof d - 1);
    n = pm_drain(&fl, NULL);
    k = pm_key(50004, 0x0a0a0a0bu);
    check((fl & TCP_RST) && !conn_find(&k), "отправка узлу не удалась — клиенту RST, а не молчание");
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
    unsigned ep0 = __atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE);
    g_fn[0].alive = 0;
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 0, "одна неудачная проверка — узел ещё жив (повтор через 3 с)");
    pl_check(0);
    check(g_pl.slot[0].up && g_pl.slot[0].node == 2,
          "две неудачи подряд — замена следующим свободным кандидатом (1 занят, взят 2)");
    check(__atomic_load_n(&g_nodes_epoch, __ATOMIC_ACQUIRE) != ep0, "смена узла — стеку: набор узлов изменился");
    pm_sweep();
    unsigned fl;
    pm_drain(&fl, NULL);
    check(!conn_find(&ka) && (fl & TCP_RST), "соединение мёртвого узла — RST клиенту, без перезапуска процесса");
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

/* ---- подтверждения привязаны к очереди дайлера (DC_ACK_PACED) ------------------------------- */

/* Поддельный дайлер с ограниченной очередью: связь — пара SOCK_SEQPACKET (как у hysteria2), второй
 * конец g_hpeer — «мультиплексор», который стенд разбирает руками. Очередь мала (буфер отправки
 * 16 КиБ, готовность записи — пока в ней не больше четверти), чтобы заполнить её несколькими пакетами.
 * Стенд проверяет то, что видно снаружи: подтверждение клиенту не уходит, пока очередь выше нижней
 * отметки, и уходит, когда она опустела. Ожидание готовности в epoll (ARM_OUT) — дело цикла
 * worker_loop, и его гоняет стенд в сетевых пространствах (tests/run-hy2.sh, раздел 8). */
struct hsess { int fd; };
static int g_hpeer = -1;

static const char *h_peer(const void *ctx) { (void)ctx; return "очередь"; }
static void h_describe(const void *ctx, char *out, size_t n) { (void)ctx; snprintf(out, n, "очередь"); }
static const char *h_strerror(int rc) { (void)rc; return "подмена"; }
static int h_connect(const void *ctx, void *sess, int t) {
    (void)ctx; (void)t;
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK, 0, sv) != 0) return -1;
    int sz = 16 * 1024;
    setsockopt(sv[0], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
    g_hpeer = sv[1];
    ((struct hsess *)sess)->fd = sv[0];
    return 0;
}
static void h_take(void *dst, void *src) { (void)dst; (void)src; }
static void h_close(void *sess) {
    struct hsess *s = sess;
    if (s->fd >= 0) close(s->fd);
    s->fd = -1;
}
static void h_clear(void *sess) { ((struct hsess *)sess)->fd = -1; }
static int h_fd(const void *sess) { return ((const struct hsess *)sess)->fd; }
static int h_has_data(const void *sess) { (void)sess; return 0; }
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

static const struct dialer_ops h_ops = {
    .name = "очередь", .caps = DC_ACK_PACED, .rcv_wnd_max = 100000, .sess_size = sizeof(struct hsess),
    .peer = h_peer, .describe = h_describe, .strerror = h_strerror, .connect = h_connect,
    .take = h_take, .close = h_close, .clear = h_clear, .fd = h_fd, .has_data = h_has_data,
    .flow_open = h_flow_open, .send = h_send, .dgram_frame = f_dgram_frame, .read = h_read,
    .deliver = h_deliver,
};

/* Подтверждения, ушедшие в устройство: сколько и номер подтверждения последнего. */
static int h_acks(uint32_t *ack) {
    unsigned char p[70000];
    int cnt = 0;
    for (;;) {
        ssize_t r = recv(g_dev_peer, p, sizeof(p), MSG_DONTWAIT);
        if (r <= 0) break;
        struct flow_key k;
        size_t off;
        if (ip_parse(p, (size_t)r, &k, &off) == 0 && (k.tcp_flags & TCP_ACK)) {
            if (ack) *ack = k.ack;
            cnt++;
        }
    }
    return cnt;
}

static int h_writable(int fd) {
    struct pollfd pf = { .fd = fd, .events = POLLOUT };
    return poll(&pf, 1, 0) > 0 && (pf.revents & POLLOUT);
}

static void t_ack_paced(void) {
    static const struct dialer hd = { .ops = &h_ops, .ctx = NULL };
    while (g_conns && g_live_n) conn_drop(&g_conns[g_live[0]]);
    g_spare_want = 0;
    stack_setup(&hd);
    pm_drain(NULL, NULL);
    struct conn *c = pm_open(41000, SRV_IP);
    check(c != NULL, "очередь: соединение открылось, дескриптор — пара SEQPACKET");
    if (!c) return;

    /* Окно клиента. Потолок стека — мегабайты (rcv_window_set), очередь пары их не вместит, и
     * дайлер называет свой предел: клиенту с масштабом объявляется он, а не потолок; без масштаба —
     * 65535, как у любого. */
    uint32_t save_wnd = g_rcv_wnd;
    uint8_t save_shift = g_rcv_shift;
    rcv_window_set(4u << 20);
    c->ws_on = 1;
    uint32_t seen = (uint32_t)rcv_win_field(c) << g_rcv_shift;
    check(seen >= h_ops.rcv_wnd_max && seen < h_ops.rcv_wnd_max + (1u << g_rcv_shift),
          "окно клиента с масштабом — предел дайлера (rcv_wnd_max), а не потолок стека в 4 МиБ");
    c->ws_on = 0;
    check(rcv_win_field(c) == 65535, "  без масштаба — 65535, как у любого дайлера");
    g_rcv_wnd = save_wnd;
    g_rcv_shift = save_shift;

    unsigned char d[1000];
    memset(d, 'x', sizeof d);
    uint32_t seq = 1001, ack = 0;

    /* Очередь пуста: подтверждение уходит сразу, как у любого дайлера. */
    pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
    seq += sizeof d;
    flush_acks(&g_tun);
    check(h_acks(&ack) == 1 && ack == seq && !c->ack_hold && !c->ack_due,
          "очередь пуста: данные приняты и подтверждены сразу");

    /* Наполняем, пока очередь не выйдет за нижнюю отметку. Каждый пакет принят — мультиплексор
     * ничего не разбирает, — подтверждений между ними нет (их шлёт flush_acks, а его зовёт цикл
     * после порции пакетов, не после каждого). */
    int sent = 0;
    while (h_writable(c->fd) && sent < 200) {
        pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
        seq += sizeof d;
        sent++;
    }
    check(sent > 1 && sent < 200 && !h_writable(c->fd),
          "очередь: после нескольких пакетов запись не готова (выше нижней отметки)");
    check(c->client_seq == seq, "очередь: все пакеты приняты и отданы дайлеру (счётчик продвинут)");

    /* Запись не готова — подтверждение придержано, соединение просит ждать записи. */
    h_acks(NULL);
    flush_acks(&g_tun);
    check(h_acks(NULL) == 0 && c->ack_hold && c->ack_due,
          "очередь выше нижней отметки: подтверждение придержано, ждём готовности записи");

    /* Ещё порция при придержанном подтверждении — по-прежнему тишина (клиент ограничен окном). */
    pm_send(41000, SRV_IP, seq, 2, TCP_ACK | TCP_PSH, d, sizeof d);
    seq += sizeof d;
    flush_acks(&g_tun);
    check(h_acks(NULL) == 0 && c->ack_hold, "  и дальше, пока мультиплексор не разобрал очередь");

    /* Мультиплексор разобрал очередь: запись готова, подтверждение уходит и покрывает всё принятое. */
    unsigned char sink[4096];
    while (recv(g_hpeer, sink, sizeof sink, MSG_DONTWAIT) > 0) {}
    check(h_writable(c->fd), "очередь разобрана: запись готова");
    flush_acks(&g_tun);
    check(h_acks(&ack) == 1 && ack == seq && !c->ack_hold && !c->ack_due,
          "запись готова: подтверждение ушло и покрывает всё принятое, придержки нет");

    conn_drop(c);
    close(g_hpeer);
    g_hpeer = -1;
    pm_drain(NULL, NULL);
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
    t_ack_paced();
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
    .name = "счёт", .caps = DC_PRECONNECT, .rcv_wnd_max = 100000, .sess_size = sizeof(struct csess),
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

int main(void) {
    int sp[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sp) != 0 || pipe(g_sess_pipe) != 0) return 2;
    if (write(g_sess_pipe[1], "x", 1) != 1) return 2;
    memset(&g_tun, 0, sizeof(g_tun));
    g_tun.fd = sp[0];
    g_dev_peer = sp[1];
    snprintf(g_node.uuid, sizeof(g_node.uuid), "8f7d3b1a-2c4e-4f60-9a81-b5d7e6c30124");
    snprintf(g_node.host, sizeof(g_node.host), "stand");
    /* То, что stack_run делает до потоков: дайлер и шаг сессий. Пул запасных выключен —
     * stack_setup тогда и памяти под него не берёт. */
    g_spare_want = 0;
    stack_setup(&g_dial);
    if (conn_table_init() != 0) return 2;
    g_now_ns = now_ns();
    g_now_s = (time_t)(g_now_ns / 1000000000ull);

    t_no_connectors();
    t_bring_up_table();
    t_sendagain_window();
    t_sendagain_retry();
    t_sendagain_eof();
    t_out_of_order_dupack();
    t_window_scale();
    t_release_last_sleep();
    t_bad_uuid();
    t_send_refused();
    t_dns_evict();
    t_spare_slot();
    t_spare_churn();
    t_born_turn();
    t_server_first();
    t_room_window();
    t_gather();
    t_fin_window();
    t_udp_early_bounds();
    t_udp_defrag();
    t_udp_big();
    t_early_window();
    if (pool_part() != 0) check(0, "стенд пула: слушатель на петле не завёлся");

    printf(g_fail ? "\ntunnelmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
