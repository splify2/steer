/* Соединение hysteria2: QUIC к узлу живёт в цикле рабочего потока стека, потоки клиента — поверх него.
 *
 * МОДЕЛЬ. У VLESS каждому соединению клиента стек (src/tunnel/stack.c) заводит свою связь с узлом —
 * дескриптор, который сам же и опрашивает. У hysteria2 связь одна на рабочего: QUIC-соединение, в нём
 * потоки (по одному на TCP-соединение клиента) и датаграммы (UDP), и сокет у соединения общий. Прежде
 * между стеком и QUIC стоял мультиплексор — отдельный поток процесса и пара SOCK_SEQPACKET на каждое
 * соединение клиента, — и каждый байт делал круг стек → пара → поток QUIC → пара → стек: два системных
 * вызова на кусок, побудки потоков, копия через буфер ядра в обе стороны. Замер (perf-tb, 2 ядра,
 * скачивание одним потоком): 2621 Мбит/с при 5,58 с процессора на ГиБ против 3270 и 3,27 у sing-box.
 *
 * Теперь дайлер встаёт в сам цикл рабочего (DC_INLOOP, dialer.h): сокет QUIC стоит в epoll рабочего,
 * таймеры ngtcp2 — в его ожидании, а колбэки QUIC кладут нагрузку прямо в сессию потока клиента
 * (очередь блоков), откуда стек забирает её вызовом read без копии. Вверх то же самое: send стека — это
 * qc_stream_send. Ни потока QUIC, ни пар сокетов, ни побудок между потоками.
 *
 * РАБОЧИХ НЕСКОЛЬКО — СОЕДИНЕНИЙ ТОЖЕ. Пакеты клиента раздаются по рабочим хэшем соединения (stack.c, R-146), и
 * соединение клиента живёт у одного рабочего всю жизнь, поэтому поток QUIC открывает тот же рабочий.
 * Одно соединение QUIC на всех значило бы, что рабочий, не владеющий им, отдаёт нагрузку владельцу через
 * очередь и побудку — ровно то, от чего избавились. Поэтому у каждого рабочего своё соединение к узлу (своё
 * рукопожатие и авторизация, свой сокет и порт). Что это стоит:
 *   • узел видит N клиентов вместо одного (N — число рабочих, ядер у процесса): у сервера hysteria это N
 *     обычных соединений одного пароля;
 *   • память под рукопожатие и буферы — N раз; окна приёма делятся поровну (win_for), чтобы наихудший
 *     расход на очереди оставался прежними 16 МиБ на туннель (пока N не больше четырёх);
 *   • Brutal у каждого соединения со своей полной скоростью (up и down из узла, как у одного прежде):
 *     делить на N нельзя — одно скачивание живёт у одного рабочего и получило бы 1/N скорости. Платит за
 *     это только тот, кто нагрузил все N рабочих разом на канале, равном заданной скорости, — у него
 *     суммарная скорость до N раз выше заданной (BBR, умолчание, такого не знает: каждое соединение
 *     само меряет канал).
 *
 * ОБРАТНОЕ ДАВЛЕНИЕ. Окно приёма QUIC продлевается не сразу, а когда байты ушли стеку (cfg.flow_manual,
 * qc_stream_consumed в hy2c_read): медленный клиент тормозит сервер, а не копит очередь в памяти роутера.
 * Очередь к клиенту (pblk) копит ровно то, что сервер прислал, а клиент ещё не принял; её предел — окно
 * потока (RX_STREAM_WIN). В сторону узла окно клиента — это место в буфере потока QUIC (hy2c_room): стек
 * не объявляет клиенту больше, чем влезет, а освободившееся место (ACK узла) возвращается клиенту
 * обновлением окна (stack_sess_room). Подтверждений, привязанных к очереди пары, как у прежнего пути
 * (DC_ACK_PACED), больше нет: нечему переполняться. Остаток, который qc_stream_send всё же не принял
 * (клиент вышел за объявленное окно), ждёт в сессии (up) и досылается по ACK, а не теряется: потерянное
 * внутри окна клиент повторял бы по таймауту.
 *
 * ЖИЗНЬ СОЕДИНЕНИЯ. Открывается, когда рабочий встал, и держится, сколько живёт процесс, — с потоками и
 * без: PING QUIC (keepalive, quic.c) не даёт ему умереть по сроку простоя. Прежде соединение без единого
 * потока закрывалось через минуту, и это стоило дорого (живой роутер, туннель в группе, которая выбрала
 * другой выход): переподключение раз в 1,5–3 минуты, диагностика «соединение не поднято» у здорового узла,
 * а замер задержки группы ловил рукопожатие следующего потока и прыгал втрое, переключая группу между
 * туннелями. Оборвалось — поднимается снова само (bg_*: первая попытка через секунду, дальше пауза
 * удваивается до BG_MAX_MS, пока узел не ответит), и поток клиента, пришедший при упавшем соединении, тоже
 * поднимает его и ждёт (в пределах срока открытия). После неудачного подъёма поток не повторяет попытку
 * раньше чем через секунду — иначе серия SYN клиентов стучалась бы в мёртвый узел с частотой SYN.
 *
 * АДРЕС УЗЛА. Имя разрешается не в цикле (getaddrinfo блокирует, а в цикле ждут все потоки клиентов
 * рабочего): при старте (hy2c_init) и потом из потока состояния модуля (hy2c_refresh_addr). Цикл берёт готовый.
 *
 * ЧТО ДЕЛАЕТ СЕРВЕР С ПОТОКОМ. TCP: клиент пишет TCPRequest (адрес назначения), сервер отвечает
 * TCPResponse (статус, сообщение) и дальше поток — прозрачный байтовый канал. UDP: датаграммы QUIC
 * с UDPMessage (идентификатор сессии, адрес, данные), сессия на сервере рождается с первой; ответа на
 * «открытие» нет, поэтому открытие UDP-потока завершается сразу. */
#define _GNU_SOURCE
#include <errno.h>
#include <netdb.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "dialer.h"
#include "hy2conn.h"
#include "quic.h"
#include "roots.h"
#include "tun.h"

#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

#if HY2_HOP_RANGES != QC_HOP_RANGES
#error "диапазонов прыжков в узле и в обёртке QUIC должно быть поровну"
#endif

/* Потоков клиента одновременно — не константа: сессии лежат в таблице стека (MAX_CONNS на рабочего), а
 * пределом служит сам QUIC — сколько двунаправленных потоков разрешил сервер (qc_stream_open отвечает
 * отказом, открытие получает HY2E_BUSY). */
#define CHUNK       16384      /* блок очереди к клиенту: не больше буфера стека (TUNNEL_BUF) */
#define FREE_BLOCKS 32         /* свободных блоков про запас: 512 КиБ на рабочего, чтобы не звать malloc на каждый кусок */

/* Окна приёма, которые мы выдаём серверу, — это и есть предел памяти под очереди к клиентам.
 *
 * Очередь к клиенту (flow.ph) копит ровно то, что сервер прислал, а клиент ещё не принял, и окно
 * продлевается только за принятое (qc_stream_consumed). Поэтому во всех очередях туннеля лежит не
 * больше RX_CONN_WIN байт, у одного потока — не больше RX_STREAM_WIN: сервер, соблюдающий
 * управление потоком, сверх окна не пришлёт ни байта, а несоблюдающего ngtcp2 закрывает ошибкой
 * управления потоком. Числа взяты не с потолка, а от двух вещей:
 *   • пропускная способность на длинном пути: окно обязано вмещать «скорость × задержка» с
 *     запасом вдвое (BBR держит в пути до двух BDP). 16 МиБ вмещают BDP в 8 МиБ — 270 Мбит/с при
 *     250 мс; больше процессору роутера QUIC всё равно не тянет. Окно потока вдвое меньше: одна
 *     закачка занимает не больше половины окна соединения (у самого hysteria — 8 и 20 МиБ);
 *   • память: окно соединения — наихудший расход на очереди одного туннеля, и он назван числом.
 *     Платится он только пока клиент медленнее сети: быстрый клиент держит очередь пустой, а
 *     окно при этом стоит лишь строкой в параметрах транспорта.
 * Цена меньшего окна — потолок скорости «окно / задержка» (4 МиБ на поток при 250 мс — 134
 * Мбит/с), так что менять эти два числа вместе с замером на длинном пути.
 *
 * Соединений теперь по числу рабочих, и окна у каждого — доля (win_for): одна закачка живёт у одного
 * рабочего, поэтому и потолок скорости потока — доля окна. 16 МиБ на туннель сохраняются, пока рабочих не
 * больше четырёх; дальше пол в WIN_FLOOR (на потоке — 2 МиБ, 67 Мбит/с при 250 мс) растит сумму до
 * WIN_FLOOR на рабочего, а не режет окно до нуля. */
#define RX_CONN_WIN    (16u << 20)
#define RX_STREAM_WIN  (8u << 20)
#define WIN_FLOOR      (4u << 20)
/* Очередь одного потока не больше окна потока; запас — на округление окна, а не на нарушителя:
 * нарушителя закрывает ngtcp2, и если очередь всё же вышла за окно, это ошибка счёта кредита —
 * такой поток закрывается с числами в журнале, а не растит память. */
#define PEND_MAX(h)    ((h)->stream_win + (1u << 20))
#define AUTH_S      10          /* срок ответа на авторизацию */
#define RETRY_MS    1000
#define BG_MAX_MS   30000       /* потолок паузы между попытками поднять упавшее соединение */
#define OPEN_TICK_MS 100        /* как часто смотрим сроки открытия потоков, пока они есть */
#define STATUS_MS   1000        /* как часто обновляем RTT для статуса и считаем выброшенные датаграммы */

enum { FL_WAIT = 1, FL_RESP, FL_OPEN };
enum { S_IDLE, S_HS, S_AUTH, S_UP };

/* Блок очереди к клиенту: ровно один кусок, который стек заберёт за один read. off — сколько с головы
 * уже отдано, len — сколько лежит. */
struct pblk {
    struct pblk *next;
    uint32_t off, len;
    uint8_t d[CHUNK];
};

/* Датаграмма UDP от сервера, собранная целиком. */
struct udg {
    struct udg *next;
    uint32_t len;
    uint8_t d[];
};

/* Что нужно только потоку UDP: адрес назначения для заголовка, счётчик пакетов и сборки фрагментов. */
struct hy2_udpx {
    char addr[64];              /* «хост:порт» назначения, у IPv6 «[хост]:порт» */
    uint16_t pkt;               /* счётчик пакетов UDP */
    struct hy2_rasm *ras;         /* сборки фрагментов от сервера (hy2wire.h) */
};

static void udpx_free(struct hy2_udpx *x) {
    hy2_rasm_free(&x->ras);
    free(x);
}

/* Соединение рабочего потока. Всё, кроме pub (под g_mu) и атомарных полей, — только поток рабочего. */
struct hq {
    int worker, nworkers;
    unsigned conn_win, stream_win;
    struct qc *qc;
    struct qc_tls *tls;             /* корни проверки разобраны один раз на рабочего, а не на каждый подъём */
    int state;
    int want_up;                    /* поднять соединение при старте, не дожидаясь потока */
    int dead;                       /* on_closed сработал: разобрать после возврата из qc_* */
    int dead_reason;
    char dead_why[160];
    uint64_t state_at_ms, next_try_ms, bg_try_ms;
    unsigned bg_ms;                 /* текущая пауза попыток поднять упавшее: растёт при отказах, 0 — после подъёма */
    uint64_t timer_due_ms;          /* срок таймера QUIC, снятый перед ожиданием; 0 — нет */
    uint64_t open_at_ms, status_at_ms, dg_seen, dg_log_ms;
    struct obfs_state *ob;          /* обфускация текущего соединения (make_cfg) */
    int64_t auth_sid;
    uint8_t abuf[4096];
    size_t an;
    uint64_t hs_start_ms;
    struct hy2_flow *fl;            /* все потоки рабочего, список */
    struct hy2_flow *act;           /* потоки, у которых отправка ещё не подтверждена узлом */
    unsigned nopen;                 /* открываются сейчас (ждут срока) */
    struct pblk *freeb;             /* свободные блоки, список */
    unsigned nfree;
    struct hy2_flow *by_sid[4096];  /* корзины цепочек по номеру потока (sid / 4) */
    struct hy2_flow *by_usid[1024]; /* по идентификатору сессии UDP */
    /* Для чтения из других потоков (hy2c_status, hy2c_alive). */
    struct hy2c_status st;          /* под g_mu */
    uint64_t tx_bytes, tx_prev;     /* отправлено вверх всего / к прошлому тику STATUS_MS (только поток рабочего) */
    uint64_t cap_bps, cur_bps;      /* предел Brutal узла после ответа сервера (0 — BBR) / доля, что стоит сейчас */
    int busy;                       /* учтён в g_nbusy */
    uint64_t rx_at_ms;              /* последний пакет от узла: атомарно */
    unsigned nflows;                /* атомарно */
};

static const struct hy2_node *g_node;
static uint32_t g_mark;
static int g_mark_req;
static struct {
    pthread_mutex_t mu;
    struct hq **v;
    unsigned n;
} g_hq = { .mu = PTHREAD_MUTEX_INITIALIZER };
#define g_mu g_hq.mu
static __thread struct hq *H;
/* Сколько рабочих сейчас гонят данные вверх: Brutal узла делится между ними (rebalance). Атомарно. */
static unsigned g_nbusy;
static __thread char g_lasterr[160];

/* Кэш разрешённого адреса сервера: пишет hy2c_init (старт) и поток состояния, читают рабочие. */
static struct {
    char ip[64];
    uint64_t at_ms;
} g_ip;

/* Часы. Внутри цикла — время витка стека (stack_now_ns, снято один раз и без системного вызова), а до
 * первого витка и в других потоках — CLOCK_MONOTONIC: это те же часы. */
static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}
static uint64_t now_ms(void) {
    uint64_t ns = stack_now_ns();
    return ns ? ns / 1000000ull : mono_ms();
}

void hy2c_set_mark(uint32_t mark, int required) {
    g_mark = mark;
    g_mark_req = required;
}

/* Срок простоя QUIC (ключ `silence` выхода): узел, от которого ничего нет дольше срока, — соединение
 * закрыто, потоки клиентов кончаются, следующий поток поднимает соединение заново. PING QUIC шлёт
 * чаще срока втрое, но не реже прежних 10 с. Умолчание — прежнее: 30 с и 10 с. */
static unsigned g_idle_ms = 30000;
void hy2c_set_idle(int silence_s) {
    if (silence_s > 0) g_idle_ms = (unsigned)silence_s * 1000u;
}

/* Причина отказа: в статус соединения (пока оно не поднято) и в локальный буфер потока — его читает
 * hy2c_strerror, когда стек разбирает исход открытия (conn_ready), в том же потоке. */
static void set_err(struct hq *h, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
static void set_err(struct hq *h, const char *fmt, ...) {
    char e[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(e, sizeof e, fmt, ap);
    va_end(ap);
    snprintf(g_lasterr, sizeof g_lasterr, "%s", e);
    if (!h) return;
    pthread_mutex_lock(&g_mu);
    snprintf(h->st.err, sizeof h->st.err, "%s", e);
    pthread_mutex_unlock(&g_mu);
}

const char *hy2c_strerror(int rc) {
    static __thread char buf[256];
    switch (rc) {
    case HY2E_TIMEOUT: return "узел не ответил вовремя";
    case HY2E_DOWN: snprintf(buf, sizeof buf, "нет соединения с узлом: %s", g_lasterr); return buf;
    case HY2E_DENIED: snprintf(buf, sizeof buf, "сервер отказал: %s", g_lasterr); return buf;
    case HY2E_NOUDP: return "сервер не принимает UDP";
    case HY2E_BUSY: return "нет свободных потоков";
    case HY2E_SYS: return "нет памяти или соединение с узлом не заведено";
    }
    return "ошибка";
}

/* Окно соединения и потока этого рабочего: доля общего (см. «окна приёма» выше). */
static void win_for(int nworkers, unsigned *conn, unsigned *stream) {
    unsigned c = RX_CONN_WIN / (unsigned)(nworkers > 0 ? nworkers : 1);
    if (c < WIN_FLOOR) c = WIN_FLOOR;
    *conn = c;
    *stream = c / 2;
}

/* ---- адрес сервера ----------------------------------------------------------------------------- */

/* Числовой адрес узла. Имя разрешается не в цикле рабочего: getaddrinfo блокирует, а в цикле ждут все
 * потоки клиентов разом. Зовут при старте, поток состояния модуля и проба. IPv4 предпочтителен: путь до
 * узла чаще есть по нему, а QUIC не пробует адреса по очереди. */
static int resolve_ip(const struct hy2_node *n, char *ip, size_t cap) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, n->host, &a4) == 1 || inet_pton(AF_INET6, n->host, &a6) == 1) {
        if (strlen(n->host) >= cap) return -1;
        memcpy(ip, n->host, strlen(n->host) + 1);
        return 0;
    }
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = SOCK_DGRAM };
    struct addrinfo *res = NULL, *p, *pick = NULL;
    if (getaddrinfo(n->host, NULL, &hints, &res) != 0 || !res) return -1;
    for (p = res; p; p = p->ai_next)
        if (p->ai_family == AF_INET) { pick = p; break; }
    if (!pick) pick = res;
    int rc = -1;
    if (pick->ai_family == AF_INET)
        rc = inet_ntop(AF_INET, &((struct sockaddr_in *)pick->ai_addr)->sin_addr, ip, (socklen_t)cap) ? 0 : -1;
    else if (pick->ai_family == AF_INET6)
        rc = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)pick->ai_addr)->sin6_addr, ip, (socklen_t)cap) ? 0 : -1;
    freeaddrinfo(res);
    return rc;
}

/* Готовый адрес для цикла: что разрешили в последний раз, каким бы старым он ни был (узел с именем меняет
 * адрес редко, а блокировать цикл ради обновления нельзя — его освежает hy2c_refresh_addr). */
static int cached_ip(char *ip, size_t cap) {
    pthread_mutex_lock(&g_mu);
    int ok = g_ip.ip[0] != '\0';
    if (ok) snprintf(ip, cap, "%s", g_ip.ip);
    pthread_mutex_unlock(&g_mu);
    return ok ? 0 : -1;
}

static int addr_store(void) {
    char ip[64];
    if (resolve_ip(g_node, ip, sizeof ip) != 0) return -1;
    pthread_mutex_lock(&g_mu);
    snprintf(g_ip.ip, sizeof g_ip.ip, "%s", ip);
    g_ip.at_ms = mono_ms();
    pthread_mutex_unlock(&g_mu);
    return 0;
}

void hy2c_refresh_addr(void) {
    if (!g_node) return;
    pthread_mutex_lock(&g_mu);
    int fresh = g_ip.ip[0] && mono_ms() - g_ip.at_ms < 120000;
    pthread_mutex_unlock(&g_mu);
    if (!fresh) (void)addr_store();
}

int hy2c_init(const struct hy2_node *node) {
    g_node = node;
    if (addr_store() != 0)
        fprintf(stderr, LOG_W2 "hysteria2: адрес узла %s не разрешился — соединения не будет, пока он не "
                        "разрешится\n", node->host);
    return 0;
}

/* ---- настройка QUIC по узлу -------------------------------------------------------------------- */

/* Состояние обфускации соединения: живёт, пока живёт qc (фильтр держит указатель на него). */
struct obfs_state {
    struct hy2_salamander sm;
    struct hy2_gecko gk;
    struct qc_filter flt;
};

/* 0 — готово; -1 — настройки обфускации узла негодны (Gecko: min > max или max > 2048): соединение
 * без неё сервер отверг бы как чужой трафик, и узел «молча не работал» без причины. */
static int make_cfg(const struct hy2_node *n, const char *ip, struct qc_cfg *c,
                     struct obfs_state *ob, uint32_t mark, int mark_req,
                     unsigned conn_win, unsigned stream_win, struct qc_tls *tls) {
    memset(c, 0, sizeof *c);
    c->host = ip;
    c->port = n->port;
    /* Без sni имя сертификата сверяется с хостом узла — и с адресом тоже: у адреса SNI не уходит, а
     * проверка идёт по SAN IP (qcssl_new), как у эталона (Go кладёт хост в ServerName). Прежде при
     * адресе без sni имени не сверял никто, и годился сертификат любого имени от признанного корня. */
    c->sni = n->sni[0] ? n->sni : n->host[0] ? n->host : NULL;
    c->alpn = "h3";
    c->insecure = n->insecure;
    /* Корни — те же, что у security=tls и DoH/DoT (tls_cert_roots, roots.c): на телефоне это
     * склейка системного хранилища, на роутере NULL — файл ca-bundle. Прежде hysteria2 брал
     * только умолчание qcssl (файл роутера), и на Android узел, который по vless+tls
     * проверялся, по hysteria2 не поднимался: файла роутера там нет (по PR #16). Нужен и здесь, а не
     * только в общем контексте рабочего: замер узла (hy2_probe) идёт со своим. */
    c->ca_file = tls_cert_roots();
    if (n->has_pin) c->pin_sha256 = n->pin;
    else c->tls = tls;                  /* с отпечатком цепочка не проверяется — свой контекст без корней */
    /* Скорость: заданный up включает Brutal сразу, без него — BBR. Ответ сервера на авторизацию
     * может это изменить (apply_cc). */
    c->brutal_bps = n->up_bps;
    c->bbr = n->up_bps == 0;
    c->datagram_max = 1500;
    c->idle_ms = g_idle_ms;
    c->keepalive_ms = g_idle_ms / 3 < 10000 ? g_idle_ms / 3 : 10000;
    c->flow_manual = 1;
    c->max_data = conn_win;
    c->max_stream_data = stream_win;
    c->sock_mark = mark;
    c->mark_required = mark_req;
    memset(ob, 0, sizeof *ob);
    if (n->obfs == 2) {
        if (hy2_gecko_init(&ob->gk, n->obfs_pass, n->gecko_min, n->gecko_max) != 0) return -1;
        ob->flt.tx_multi = hy2_gecko_tx;
        ob->flt.rx = hy2_gecko_rx;
        ob->flt.user = &ob->gk;
        c->filter = &ob->flt;
    } else if (n->obfs == 1) {
        hy2_salamander_init(&ob->sm, n->obfs_pass);
        ob->flt.tx = hy2_salamander_tx;
        ob->flt.rx = hy2_salamander_rx;
        ob->flt.user = &ob->sm;
        c->filter = &ob->flt;
    }
    if (n->hop_n) {
        c->hop_n = n->hop_n;
        c->hop_ms = n->hop_s * 1000u;
        memcpy(c->hop, n->hop, sizeof c->hop);
    }
    return 0;
}

/* ---- авторизация (общая у рабочего и разовой проверки) ------------------------------------------ */

/* Начало сессии HTTP/3: управляющий поток с SETTINGS и запрос POST /auth. Вызывается, когда
 * рукопожатие QUIC завершено. Возвращает 0 или причину. */
static const char *auth_begin(struct qc *q, const struct hy2_node *n, int64_t *asid) {
    uint8_t b[1400];
    int64_t ctl;
    if (qc_stream_open_uni(q, &ctl) != 0) return "не открылся управляющий поток HTTP/3";
    size_t l = hy2_h3_control(b, sizeof b);
    if (!l || qc_stream_send(q, ctl, b, l, 0) != (ssize_t)l) return "управляющий поток не принял SETTINGS";
    if (qc_stream_open(q, asid) != 0) return "не открылся поток авторизации";
    uint8_t r;
    if (getrandom(&r, 1, 0) != 1) r = 64;
    l = hy2_auth_request(b, sizeof b, n->auth, n->down_bps, 32 + (size_t)r % 192);
    if (!l || qc_stream_send(q, *asid, b, l, 1) != (ssize_t)l) return "запрос авторизации не ушёл";
    return NULL;
}

/* Разобрать накопленный ответ. Возвращает 1 — принят (r заполнен), 0 — ждать, -1 — отказ (why). */
static int auth_check(const uint8_t *d, size_t n, struct hy2_auth_resp *r, char *why, size_t whyn) {
    const char *w = NULL;
    int rc = hy2_auth_response(d, n, r, &w);
    if (rc < 0) { snprintf(why, whyn, "%s", w ? w : "ответ авторизации негоден"); return -1; }
    if (rc == 0) return 0;
    if (r->status != HY2_AUTH_OK) {
        /* Не 233 — сервер не узнал пароль и отвечает как обычный HTTP/3-сайт (эталон: маскировка). */
        snprintf(why, whyn, "сервер отказал в авторизации (HTTP %d)", r->status);
        return -1;
    }
    return 1;
}

/* Применить ответ сервера к перегрузке. Возвращает скорость Brutal, с которой соединение работает
 * дальше (0 — BBR).
 *
 * Правило ядра hysteria2 (core/client/client.go): сервер ответил `auto` (у него ignoreClientBandwidth)
 * — BBR; иначе Brutal на меньшую из «своя скорость» и «предел приёма сервера», причём предел 0
 * значит «без предела» и остаётся своя скорость. Клиент Xray-core (transport/internet/hysteria/
 * dialer.go) при пределе 0 тоже уходит в BBR — это расходится с ядром, и здесь выбрано ядро:
 * сервер без bandwidth в настройках отвечает именно 0, и по правилу Xray заданный в узле `up`
 * не действовал бы ни против одного такого сервера. Свой up не задан — BBR при любом ответе (у обоих
 * эталонов). Начинали мы с Brutal на своём up (или BBR без up), поэтому меняем только при
 * расхождении. */
static uint64_t apply_cc(struct qc *q, const struct hy2_node *n, const struct hy2_auth_resp *r) {
    if (!n->up_bps) return 0;                                /* уже BBR */
    uint64_t want = r->rx_auto ? 0 : ((r->rx == 0 || r->rx > n->up_bps) ? n->up_bps : r->rx);
    if (want == n->up_bps) return want;
    if (qc_set_cc(q, want) != 0) {
        fprintf(stderr, LOG_W2 "hysteria2: сервер просит %s, а сменить перегрузку на ходу не вышло — "
                        "остаётся Brutal на up узла\n", want ? "меньшую скорость" : "BBR");
        return n->up_bps;
    }
    return want;
}

/* Brutal узла — один на всех рабочих: у каждого своё соединение QUIC, и с полной скоростью у каждого
 * сумма была бы до N× заданной. Поэтому cap делится на число рабочих, занятых вверх (g_nbusy), а
 * простаивающий рабочий считается за одного — при старте загрузки он получает долю, не отнимая у других
 * больше положенного. Одна загрузка идёт на полной скорости, параллельные на разных рабочих делят её.
 * Делить по фактическому спросу точнее, но спрос Brutal не виден (он шлёт ровно то, что дано), поэтому
 * мерой служит доля отправленного от положенного (hy2_worker_busy). Занятость обновляется раз в STATUS_MS,
 * так что при смене состава рабочих сумма может превышать cap до одного такта. */
static void rebalance(struct hq *h, int busy_now) {
    if (busy_now != h->busy) {
        if (busy_now) __atomic_add_fetch(&g_nbusy, 1, __ATOMIC_RELAXED);
        else __atomic_sub_fetch(&g_nbusy, 1, __ATOMIC_RELAXED);
        h->busy = busy_now;
    }
    if (!h->cap_bps || !h->qc) return;
    unsigned n = __atomic_load_n(&g_nbusy, __ATOMIC_RELAXED);
    if (!h->busy) n++;
    uint64_t want = hy2_brutal_share(h->cap_bps, n);
    if (want == h->cur_bps) return;
    if (qc_set_cc(h->qc, want) == 0) h->cur_bps = want;
}

/* ---- разовая проверка узла --------------------------------------------------------------------- */

/* Проба живёт одним потоком и одним соединением, поэтому колбэки берут всё из неё. qc колбэки
 * получают уже после возврата qc_open (рукопожатие идёт в qc_run), так что указатель на месте. */
struct probe {
    const struct hy2_node *n;
    struct qc *q;
    int stage;                  /* 0 рукопожатие, 1 ждём ответ, 2 принят, -1 отказ */
    int64_t asid;
    uint8_t buf[2048];
    size_t bn;
    char why[160];
    int closed;
};

static void p_hs(void *u) {
    struct probe *p = u;
    const char *w = auth_begin(p->q, p->n, &p->asid);
    if (w) { snprintf(p->why, sizeof p->why, "%s", w); p->stage = -1; return; }
    p->stage = 1;
}
static void p_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct probe *p = u;
    (void)fin;
    if (sid != p->asid) { qc_stream_consumed(p->q, sid, n); return; }
    if (p->bn + n > sizeof p->buf) n = sizeof p->buf - p->bn;
    memcpy(p->buf + p->bn, d, n);
    p->bn += n;
    qc_stream_consumed(p->q, sid, n);
    struct hy2_auth_resp r;
    int rc = auth_check(p->buf, p->bn, &r, p->why, sizeof p->why);
    if (rc > 0) p->stage = 2;
    else if (rc < 0) p->stage = -1;
}
static void p_closed(void *u, int reason, const char *why) {
    struct probe *p = u;
    (void)reason;
    p->closed = 1;
    if (p->stage != 2 && p->stage != -1)
        snprintf(p->why, sizeof p->why, "%s", why && *why ? why : "соединение закрыто");
    if (p->stage != 2) p->stage = -1;
}

int hy2_probe(const struct hy2_node *n, int timeout_s, char *why, size_t why_n, int *hs_ms) {
    char ip[64];
    if (resolve_ip(n, ip, sizeof ip) != 0) {
        snprintf(why, why_n, "адрес узла %s не разрешился", n->host);
        return -1;
    }
    struct obfs_state ob;
    struct qc_cfg c;
    if (make_cfg(n, ip, &c, &ob, g_mark, g_mark_req, RX_CONN_WIN, RX_STREAM_WIN, NULL) != 0) {
        snprintf(why, why_n, "обфускация Gecko: размеры пакетов заданы неверно (min %u, max %u)",
                 n->gecko_min, n->gecko_max);
        return -1;
    }
    struct probe *pr = calloc(1, sizeof *pr);
    if (!pr) { snprintf(why, why_n, "нет памяти"); return -1; }
    pr->n = n;
    struct qc_ops ops = { .on_handshake = p_hs, .on_stream_data = p_data, .on_closed = p_closed };
    int rc = qc_open(&c, &ops, pr, &pr->q);
    if (rc != 0) {
        snprintf(why, why_n, "QUIC не открылся (%d)", rc);
        free(pr);
        return -1;
    }
    uint64_t t0 = mono_ms(), lim = t0 + (uint64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    int ret = -1;
    while (!pr->closed && pr->stage >= 0 && pr->stage != 2) {
        uint64_t t = mono_ms();
        if (t >= lim) { snprintf(pr->why, sizeof pr->why, "узел не ответил за %d с", timeout_s); break; }
        if (qc_run(pr->q, (int)(lim - t > 200 ? 200 : lim - t)) == QC_ECLOSED) break;
    }
    if (pr->stage == 2) {
        ret = 0;
        if (hs_ms) *hs_ms = (int)(mono_ms() - t0);
        why[0] = '\0';
    } else {
        snprintf(why, why_n, "%s", pr->why[0] ? pr->why : "узел не ответил");
    }
    if (!pr->closed) qc_close(pr->q, 0x100);
    qc_free(pr->q);
    hy2_gecko_free(&ob.gk);
    free(pr);
    return ret;
}

/* ---- таблицы потоков --------------------------------------------------------------------------- */

/* Индексы потоков — корзины с цепочками: число одновременных потоков от размера таблицы не
 * зависит. Вставка — в голову цепочки, снятие — по указателю (снять нестоящего безвредно). */
static struct hy2_flow **sid_bucket(struct hq *h, int64_t sid) { return &h->by_sid[(uint64_t)(sid / 4) & 4095]; }
static struct hy2_flow **usid_bucket(struct hq *h, uint32_t u) { return &h->by_usid[u & 1023]; }
static void sid_add(struct hq *h, struct hy2_flow *f) { struct hy2_flow **b = sid_bucket(h, f->sid); f->hn = *b; *b = f; }
static void usid_add(struct hq *h, struct hy2_flow *f) { struct hy2_flow **b = usid_bucket(h, f->usid); f->hn = *b; *b = f; }
static void sid_del(struct hq *h, struct hy2_flow *f) {
    for (struct hy2_flow **p = sid_bucket(h, f->sid); *p; p = &(*p)->hn)
        if (*p == f) { *p = f->hn; break; }
    f->hn = NULL;
}
static void usid_del(struct hq *h, struct hy2_flow *f) {
    for (struct hy2_flow **p = usid_bucket(h, f->usid); *p; p = &(*p)->hn)
        if (*p == f) { *p = f->hn; break; }
    f->hn = NULL;
}
static struct hy2_flow *usid_find(struct hq *h, uint32_t u) {
    for (struct hy2_flow *f = *usid_bucket(h, u); f; f = f->hn)
        if (f->usid == u) return f;
    return NULL;
}
static struct hy2_flow *flow_by_sid(struct hq *h, int64_t sid) {
    if (sid < 0 || (sid & 3) != 0) return NULL;
    for (struct hy2_flow *f = *sid_bucket(h, sid); f; f = f->hn)
        if (f->sid == sid) return f;
    return NULL;
}

static void list_add(struct hq *h, struct hy2_flow *f) {
    f->pv = NULL;
    f->nx = h->fl;
    if (h->fl) h->fl->pv = f;
    h->fl = f;
}
static void list_del(struct hq *h, struct hy2_flow *f) {
    if (f->pv) f->pv->nx = f->nx; else h->fl = f->nx;
    if (f->nx) f->nx->pv = f->pv;
    f->nx = f->pv = NULL;
}
static void act_add(struct hq *h, struct hy2_flow *f) {
    if (f->act) return;
    f->act = 1;
    f->apv = NULL;
    f->anx = h->act;
    if (h->act) h->act->apv = f;
    h->act = f;
}
static void act_del(struct hq *h, struct hy2_flow *f) {
    if (!f->act) return;
    f->act = 0;
    if (f->apv) f->apv->anx = f->anx; else h->act = f->anx;
    if (f->anx) f->anx->apv = f->apv;
    f->anx = f->apv = NULL;
}

/* ---- очередь к клиенту ------------------------------------------------------------------------ */

/* Очередь к клиенту — цепочка блоков по CHUNK байт, а не один растущий буфер.
 *
 * Прежде это был один буфер со смещением «уже отдано», и отданное место возвращалось, только когда
 * очередь пустела ЦЕЛИКОМ. Под непрерывной загрузкой клиент отстаёт от узла постоянно (сеть быстрее
 * его приёма — а здесь это обычное дело: узким местом бывает сама сторона клиента), и очередь не
 * пустела никогда: дописывалось всё дальше, буфер удваивался (до 256 МиБ на поток), а живых байт в
 * нём лежали мегабайты — их держало в узде окно потока, а отданный хвост не держал никто. Восемь
 * потоков за двадцать секунд раздували процесс с 14 до 700 МБ (замер 2026-10-04). Блоки отдают
 * память по мере отдачи клиенту и не копируются при росте: занято ровно то, что лежит, плюс
 * неполный хвостовой блок. Предел самой очереди — окно потока (hq.stream_win).
 *
 * Теперь это ещё и единственный путь байтов вниз: колбэк QUIC кладёт сюда, стек забирает указатель на
 * блок без копии (hy2c_read). Копий две — из пакета QUIC в блок и из блока в кольцо повтора, — а не
 * четыре, как через пару сокетов (в сокет, из сокета в буфер стека, дальше то же кольцо). */

static struct pblk *pb_get(struct hq *h) {
    struct pblk *b = h->freeb;
    if (b) { h->freeb = b->next; h->nfree--; return b; }
    return malloc(sizeof *b);
}
static void pb_put(struct hq *h, struct pblk *b) {
    if (h->nfree < FREE_BLOCKS) { b->next = h->freeb; h->freeb = b; h->nfree++; }
    else free(b);
}

/* Дописать n байт в хвост. -1 — нет памяти: что успело лечь, осталось (pend_n честный). */
static int pend_add(struct hq *h, struct hy2_flow *f, const uint8_t *d, size_t n) {
    while (n) {
        struct pblk *b = f->pt;
        if (!b || b->len == CHUNK) {
            b = pb_get(h);
            if (!b) return -1;
            b->next = NULL;
            b->off = b->len = 0;
            if (f->pt) f->pt->next = b; else f->ph = b;
            f->pt = b;
        }
        size_t k = CHUNK - b->len < n ? CHUNK - b->len : n;
        memcpy(b->d + b->len, d, k);
        b->len += (uint32_t)k;
        f->pend_n += k;
        d += k;
        n -= k;
    }
    return 0;
}

static void pend_free(struct hq *h, struct hy2_flow *f) {
    while (f->ph) {
        struct pblk *b = f->ph;
        f->ph = b->next;
        pb_put(h, b);
    }
    f->pt = NULL;
    f->pend_n = 0;
    if (f->spent_b) { pb_put(h, f->spent_b); f->spent_b = NULL; }
    while (f->uh) {
        struct udg *u = f->uh;
        f->uh = u->next;
        free(u);
    }
    f->ut = NULL;
    free(f->spent_u);
    f->spent_u = NULL;
}

/* Датаграмма UDP в очередь к клиенту. Предела у очереди нет: стек читает её в этом же витке, где она
 * пришла (stack_sess_rx), а за виток QUIC принимает не больше 256 датаграмм (qc_on_readable). */
static void udg_push(struct hy2_flow *f, const uint8_t *d, size_t n) {
    struct udg *u = malloc(sizeof *u + n);
    if (!u) return;                     /* нет памяти — датаграмма пропала, как в сети */
    u->next = NULL;
    u->len = (uint32_t)n;
    memcpy(u->d, d, n);
    if (f->ut) f->ut->next = u; else f->uh = u;
    f->ut = u;
    stack_sess_rx(f);
}

/* ---- жизнь потока клиента ---------------------------------------------------------------------- */

static void status_flows(struct hq *h, int delta) {
    __atomic_add_fetch(&h->nflows, (unsigned)delta, __ATOMIC_RELAXED);
}

/* Освободить сессию: из таблиц, списков, очередей; сбросить поток QUIC, если он ещё жив (reset); вернуть
 * окно соединения за то, что клиент так и не принял. Пустую сессию (q == NULL) не трогает. */
static void flow_release(struct hy2_flow *f, int reset) {
    struct hq *h = f->q;
    if (!h) return;
    if (h->qc && !f->gone && !f->sclosed && !f->udp && f->state >= FL_RESP) {
        if (reset) (void)qc_stream_reset(h->qc, f->sid, 0);
    }
    /* Окно соединения возвращаем и за то, что так и не отдали клиенту. */
    if (f->pend_n && h->qc && !f->gone) qc_stream_consumed(h->qc, f->udp ? 0 : f->sid, f->pend_n);
    if (f->state >= FL_RESP && !f->gone) {
        if (!f->udp) sid_del(h, f); else usid_del(h, f);
    }
    list_del(h, f);
    act_del(h, f);
    if (f->opening) { f->opening = 0; h->nopen--; }
    free(f->hbuf);
    free(f->up);
    if (f->ux) udpx_free(f->ux);
    pend_free(h, f);
    f->hbuf = NULL;
    f->up = NULL;
    f->up_n = f->up_off = f->up_cap = 0;
    f->ux = NULL;
    f->q = NULL;
    f->state = 0;
    status_flows(h, -1);
}

/* Открытие не удалось: освободить поток и сказать стеку и слежке за узлом. Исход «сервер отказал в этом
 * адресе» узел не порочит — он ответил. */
static void flow_fail(struct hy2_flow *f, int rc, const char *msg, int reset) {
    struct hq *h = f->q;
    if (msg) set_err(h, "%s", msg);
    flow_release(f, reset);
    hy2_watch_seen(rc == HY2E_DENIED || rc == HY2E_NOUDP ? 0 : rc);
    stack_sess_ready(f, rc);
}

static void flow_ready(struct hy2_flow *f) {
    struct hq *h = f->q;
    f->state = FL_OPEN;
    if (f->opening) { f->opening = 0; h->nopen--; }
    hy2_watch_seen(0);
    stack_sess_ready(f, 0);
}

/* Поток оборван (очередь вышла за окно, отправка не удалась): стек увидит ошибку чтения и ответит
 * клиенту RST. */
static void flow_kill(struct hy2_flow *f, int reset) {
    struct hq *h = f->q;
    if (reset && h->qc && !f->gone && !f->sclosed && !f->udp) (void)qc_stream_reset(h->qc, f->sid, 0);
    f->sclosed = 1;
    f->aborted = 1;
    f->rx_fin = 1;
    act_del(h, f);
    stack_sess_rx(f);
}

/* Байты от сервера — в очередь клиента. */
static void flow_down(struct hy2_flow *f, const uint8_t *d, size_t n) {
    struct hq *h = f->q;
    if (f->pend_n + n > PEND_MAX(h)) {
        /* Окно не бывает больше очереди: сюда доходят только при ошибке счёта кредита. Рвём
         * поток, а не растим память, и называем числа. */
        fprintf(stderr, LOG_W2 "hysteria2: очередь к клиенту %zu КиБ вышла за окно потока %u КиБ — "
                        "поток закрыт\n", (f->pend_n + n) >> 10, (unsigned)(PEND_MAX(h) >> 10));
        qc_stream_consumed(h->qc, f->sid, n);
        flow_kill(f, 1);
        return;
    }
    size_t before = f->pend_n;
    if (pend_add(h, f, d, n) != 0) {
        /* Что успело лечь в очередь, вернёт flow_release: кредит возвращаем только за остальное. */
        qc_stream_consumed(h->qc, f->sid, n - (f->pend_n - before));
        flow_kill(f, 1);
        return;
    }
    stack_sess_rx(f);
}

/* Дослать серверу остаток, который не принял буфер потока. Принятое снимается сдвигом начала, а не
 * memmove хвоста: при остатке в окно (мегабайты) и подтверждениях по пакету сдвиг на каждую досылку
 * переписывал весь остаток — квадрат по объёму. */
static void flow_up_flush(struct hy2_flow *f) {
    struct hq *h = f->q;
    if (!f->up_n || f->gone || f->sclosed) return;
    ssize_t k = qc_stream_send(h->qc, f->sid, f->up + f->up_off, f->up_n, 0);
    if (k < 0) { flow_kill(f, 0); return; }
    h->tx_bytes += (uint64_t)k;
    f->up_off += (size_t)k;
    f->up_n -= (size_t)k;
    if (!f->up_n) f->up_off = 0;   /* буфер остаётся до конца потока: следующий остаток ляжет без malloc */
}

/* Положить в остаток n байт. Места не хватает: снятое начало не меньше остатка — сдвиг (переносится
 * не больше уже отправленного); иначе новое место вдвое больше нужного. Каждый байт так переносится
 * O(1) раз, память — не больше четырёх окон. 0 — легло; -1 — нет памяти. */
static int up_append(struct hy2_flow *f, const uint8_t *d, size_t n) {
    if (f->up_off + f->up_n + n > f->up_cap) {
        if (f->up_off >= f->up_n && f->up_n + n <= f->up_cap) {
            memmove(f->up, f->up + f->up_off, f->up_n);
        } else {
            size_t cap = f->up_cap ? f->up_cap : 4096;
            while (cap < 2 * (f->up_n + n)) cap *= 2;
            uint8_t *nb = malloc(cap);
            if (!nb) return -1;
            if (f->up_n) memcpy(nb, f->up + f->up_off, f->up_n);
            free(f->up);
            f->up = nb;
            f->up_cap = cap;
        }
        f->up_off = 0;
    }
    memcpy(f->up + f->up_off + f->up_n, d, n);
    f->up_n += n;
    return 0;
}

/* Сколько датаграмм не влезло и их пришлось потерять — слать: нечем. UDP клиента — датаграммами QUIC. */
static int udp_send(struct hy2_flow *f, const uint8_t *d, size_t n) {
    struct hq *h = f->q;
    uint8_t msg[1600];
    uint8_t hdr[320];
    size_t dmax = qc_datagram_max(h->qc);
    size_t hl = hy2_udp_header(hdr, sizeof hdr, f->usid, 0, 0, 1, f->ux->addr);
    if (!hl || dmax <= hl) return SEND_OK;                  /* сервер датаграмм не принимает */
    size_t room = dmax - hl;
    if (room > sizeof msg - hl) room = sizeof msg - hl;
    size_t nfrag = (n + room - 1) / room;
    if (nfrag > 255) return SEND_OK;
    /* Целая датаграмма идёт с packet id 0, как у эталона; у фрагментированной id ненулевой и
     * свой на каждую: приёмник эталона склеивает фрагменты одного id, а нулевой у него
     * значит «состояния нет». */
    uint16_t pid = 0;
    if (nfrag > 1 && ++f->ux->pkt == 0) f->ux->pkt = 1;
    if (nfrag > 1) pid = f->ux->pkt;
    for (size_t fi = 0; fi < nfrag; fi++) {
        size_t off = fi * room, len = n - off < room ? n - off : room;
        hl = hy2_udp_header(msg, sizeof msg, f->usid, pid, (uint8_t)fi, (uint8_t)nfrag, f->ux->addr);
        memcpy(msg + hl, d + off, len);
        (void)qc_datagram_send(h->qc, msg, hl + len);       /* очередь полна — датаграмма пропала, как в сети */
    }
    return SEND_OK;
}

int hy2c_send(struct hy2_flow *f, const unsigned char *d, size_t n) {
    struct hq *h = f->q;
    if (!h || !h->qc || h->dead || f->gone || f->sclosed || f->state != FL_OPEN) return SEND_FATAL;
    if (f->udp) return udp_send(f, d, n);
    if (!n) return SEND_OK;         /* запрос потока ушёл при открытии: серверу, говорящему первым, нечего добавить */
    if (f->up_n) {
        /* Остаток ещё ждёт места: порядок байт дороже скорости, новое — за ним. */
        if (up_append(f, d, n) != 0) return SEND_FATAL;
        act_add(h, f);
        return SEND_OK;
    }
    ssize_t k = qc_stream_send(h->qc, f->sid, d, n, 0);
    if (k < 0) return SEND_FATAL;
    h->tx_bytes += (uint64_t)k;
    if ((size_t)k < n) {
        if (up_append(f, d + k, n - (size_t)k) != 0) return SEND_FATAL;
    }
    act_add(h, f);          /* пока узел не подтвердил, ждём ACK: он освободит место и вернёт клиенту окно */
    return SEND_OK;
}

int hy2c_read(struct hy2_flow *f, size_t cap, const unsigned char **data, size_t *got) {
    struct hq *h = f->q;
    *got = 0;
    if (!h) return -1;
    /* Предыдущий отданный блок стеку больше не нужен: он разобрал его в том же проходе. */
    if (f->spent_b) { pb_put(h, f->spent_b); f->spent_b = NULL; }
    if (f->spent_u) { free(f->spent_u); f->spent_u = NULL; }
    if (f->aborted) return -1;
    if (f->udp) {
        struct udg *u = f->uh;
        if (!u) return f->rx_fin ? -1 : 0;
        f->uh = u->next;
        if (!f->uh) f->ut = NULL;
        f->spent_u = u;
        *data = u->d;
        *got = u->len;
        return 0;
    }
    struct pblk *b = f->ph;
    if (!b) return f->rx_fin ? -1 : 0;      /* 0 — сервер закончил передачу, иначе пока пусто */
    size_t n = b->len - b->off;
    if (n > cap) n = cap;
    *data = b->d + b->off;
    *got = n;
    b->off += (uint32_t)n;
    f->pend_n -= n;
    /* Окно приёма — за то, что отдаём стеку: он положит это в кольцо повтора в этом же проходе. Пакет с
     * обновлением уйдёт одним на виток (hy2c_loop_wait). */
    if (h->qc && !f->gone) qc_stream_consumed(h->qc, f->sid, n);
    if (b->off == b->len) {
        f->ph = b->next;
        if (!f->ph) f->pt = NULL;
        f->spent_b = b;
    }
    return 0;
}

int hy2c_has_data(const struct hy2_flow *f) {
    return f->q && (f->udp ? f->uh != NULL : f->pend_n > 0);
}

long hy2c_room(const struct hy2_flow *f) {
    struct hq *h = f->q;
    if (f->udp) return -1;
    if (!h || !h->qc || f->gone || f->sclosed) return 0;
    size_t r = qc_stream_room(h->qc, f->sid);
    return (long)(r > f->up_n ? r - f->up_n : 0);
}

int hy2c_fd(const struct hy2_flow *f) {
    return f->q && f->q->qc ? qc_fd(f->q->qc) : -1;
}

int hy2c_aborted(const struct hy2_flow *f) {
    return f->aborted;
}

void hy2c_close(struct hy2_flow *f) {
    flow_release(f, 1);
}

/* ---- сроки и жизнь соединения: объявления ------------------------------------------------------ */

static int connect_now(struct hq *h);
static void bg_schedule(struct hq *h, int failed);

/* ---- начало потока ----------------------------------------------------------------------------- */

static void start_flow(struct hy2_flow *f) {
    struct hq *h = f->q;
    char host[INET6_ADDRSTRLEN];
    inet_ntop(f->v6 ? AF_INET6 : AF_INET, f->dst, host, sizeof host);
    if (f->udp) {
        if (!h->st.udp_ok) { flow_fail(f, HY2E_NOUDP, NULL, 0); return; }
        f->ux = calloc(1, sizeof *f->ux);
        if (!f->ux) { flow_fail(f, HY2E_BUSY, NULL, 0); return; }
        /* IPv6 — в скобках: «[::1]:443», как и в запросе TCP (hy2_tcp_request). */
        snprintf(f->ux->addr, sizeof f->ux->addr, f->v6 ? "[%s]:%u" : "%s:%u", host, f->dport);
        /* Идентификатор сессии — случайный, свободный в таблице. */
        for (int tries = 0; tries < 16; tries++) {
            uint32_t u;
            if (getrandom(&u, sizeof u, 0) != sizeof u) u = (uint32_t)now_ms() * 2654435761u;
            if (!u || usid_find(h, u)) continue;
            f->usid = u;
            break;
        }
        if (!f->usid) { flow_fail(f, HY2E_BUSY, NULL, 0); return; }
        f->state = FL_RESP;             /* в таблицах: flow_release снимет их */
        usid_add(h, f);
        flow_ready(f);
        return;
    }
    int64_t sid;
    if (qc_stream_open(h->qc, &sid) != 0) {     /* потоков больше нет: лимит сервера (MAX_STREAMS) */
        flow_fail(f, HY2E_BUSY, NULL, 0);
        return;
    }
    f->sid = sid;
    f->state = FL_RESP;
    sid_add(h, f);
    uint8_t pad;
    if (getrandom(&pad, 1, 0) != 1) pad = 16;
    uint8_t b[600];
    size_t l = hy2_tcp_request(b, sizeof b, host, f->dport, pad % 64);
    if (!l || qc_stream_send(h->qc, sid, b, l, 0) != (ssize_t)l)
        flow_fail(f, HY2E_BUSY, "запрос не ушёл", 1);
}

int hy2c_connect(struct hy2_flow *f, int timeout_s) {
    struct hq *h = H;
    if (!h) { snprintf(g_lasterr, sizeof g_lasterr, "соединение с узлом не заведено"); return HY2E_SYS; }
    uint64_t now = now_ms();
    f->q = h;
    f->state = FL_WAIT;
    f->opening = 1;
    h->nopen++;
    f->deadline_ms = now + (uint64_t)(timeout_s > 0 ? timeout_s : 10) * 1000;
    list_add(h, f);
    status_flows(h, 1);
    if (h->dead) return 0;              /* соединение закрыто в этом же витке: следующий разбор (teardown) откажет */
    if (h->state == S_UP) { start_flow(f); return 0; }
    if (h->state == S_IDLE) {
        /* Упавшее соединение поднимает и поток клиента, и ждёт; но не раньше паузы после неудачи — иначе
         * серия SYN стучалась бы в мёртвый узел с частотой SYN. */
        if (now < h->next_try_ms) {
            char e[160];
            snprintf(e, sizeof e, "%s", h->st.err);
            flow_fail(f, HY2E_DOWN, e[0] ? e : "узел недоступен", 0);
            return 0;
        }
        if (connect_now(h) != 0) {
            char e[160];
            snprintf(e, sizeof e, "%s", h->st.err);
            flow_fail(f, HY2E_DOWN, e, 0);
        }
    }
    return 0;                           /* рукопожатие и авторизация идут: поток ждёт в списке */
}

/* Соединение поднято: потоки, ждавшие его, открываются. */
static void start_waiting(struct hq *h) {
    for (struct hy2_flow *f = h->fl, *nx; f; f = nx) {
        nx = f->nx;
        if (f->state == FL_WAIT) start_flow(f);
    }
}

/* ---- колбэки QUIC ----------------------------------------------------------------------------- */

static void status_up(struct hq *h, int up) {
    pthread_mutex_lock(&g_mu);
    h->st.up = up;
    pthread_mutex_unlock(&g_mu);
}

static void dead_mark(struct hq *h, int reason, const char *why) {
    h->dead = 1;
    h->dead_reason = reason;
    snprintf(h->dead_why, sizeof h->dead_why, "%s", why);
}

static void on_handshake(void *u) {
    struct hq *h = u;
    h->hs_start_ms = h->hs_start_ms ? h->hs_start_ms : now_ms();
    const char *w = auth_begin(h->qc, g_node, &h->auth_sid);
    if (w) {
        dead_mark(h, QC_CLOSE_ERROR, w);
        qc_close(h->qc, 0x101);
        return;
    }
    h->state = S_AUTH;
    h->state_at_ms = now_ms();
    h->an = 0;
}

static void auth_data(struct hq *h, const uint8_t *d, size_t n) {
    if (h->an + n > sizeof h->abuf) n = sizeof h->abuf - h->an;
    memcpy(h->abuf + h->an, d, n);
    h->an += n;
    struct hy2_auth_resp r;
    char why[160];
    int rc = auth_check(h->abuf, h->an, &r, why, sizeof why);
    if (rc == 0) return;
    if (rc < 0) {
        dead_mark(h, QC_CLOSE_ERROR, why);
        qc_close(h->qc, 0x101);
        return;
    }
    h->state = S_UP;
    h->bg_ms = 0;
    uint64_t eff = apply_cc(h->qc, g_node, &r);
    h->cap_bps = eff;
    h->cur_bps = eff;
    h->tx_prev = h->tx_bytes;
    h->status_at_ms = now_ms();
    /* Новое соединение считается занятым: до первого замера доля — как при полной нагрузке всех. */
    if (eff && h->nworkers > 1) {
        if (!h->busy) { h->busy = 1; __atomic_add_fetch(&g_nbusy, 1, __ATOMIC_RELAXED); }
        uint64_t sh = hy2_brutal_share(eff, (unsigned)h->nworkers);
        if (qc_set_cc(h->qc, sh) == 0) h->cur_bps = sh;
        if (g_node->down_bps)
            fprintf(stderr, LOG_W2 "hysteria2: рабочих %d, у каждого своё соединение, и серверу объявлена скорость "
                    "приёма down у каждого: сервер может слать до down на каждое, а не на все (Brutal вверх "
                    "рабочие делят)\n", h->nworkers);
    }
    pthread_mutex_lock(&g_mu);
    h->st.up = 1;
    h->st.udp_ok = r.udp;
    h->st.brutal = eff != 0;
    h->st.brutal_bps = eff;
    h->st.hs_ms = (uint32_t)(now_ms() - h->hs_start_ms);
    h->st.err[0] = '\0';
    pthread_mutex_unlock(&g_mu);
    char who[24] = "";
    if (h->nworkers > 1) snprintf(who, sizeof who, " [рабочий %d]", h->worker);
    fprintf(stderr, LOG_I2 "hysteria2: узел %s принял авторизацию за %u мс (%s%s%s%s)%s\n",
            g_node->name, (unsigned)h->st.hs_ms, eff ? "Brutal" : "BBR",
            r.udp ? ", UDP" : ", без UDP", g_node->obfs == 2 ? ", Gecko" : g_node->obfs ? ", Salamander" : "",
            g_node->hop_n ? ", прыжки по портам" : "", who);
    start_waiting(h);
}

static void on_stream_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct hq *h = u;
    if (h->state == S_AUTH && sid == h->auth_sid) {
        qc_stream_consumed(h->qc, sid, n);
        auth_data(h, d, n);
        return;
    }
    struct hy2_flow *f = flow_by_sid(h, sid);
    if (!f) { qc_stream_consumed(h->qc, sid, n); return; }
    if (f->state == FL_RESP) {
        if (!f->hbuf) f->hbuf = malloc(4300);
        if (!f->hbuf) { qc_stream_consumed(h->qc, sid, n); flow_fail(f, HY2E_BUSY, NULL, 1); return; }
        /* Ответ короче hbuf (сообщение и набивка ограничены при разборе), поэтому не влезшее — уже
         * негодный ответ. Копится вся порция: разбор скажет, где ответ кончился. */
        size_t before = f->hn_;
        int bad = n > (size_t)(4300 - f->hn_);
        struct hy2_tcp_resp resp;
        int used = -1;
        if (!bad) {
            memcpy(f->hbuf + f->hn_, d, n);
            f->hn_ += (uint16_t)n;
            used = hy2_tcp_response(f->hbuf, f->hn_, &resp);
        }
        if (used == 0) { qc_stream_consumed(h->qc, sid, n); return; }   /* ответ пришёл не весь */
        if (used < 0 || !resp.ok) {
            qc_stream_consumed(h->qc, sid, n);
            const char *m = used < 0 ? "негодный ответ на запрос потока" : resp.msg;
            flow_fail(f, HY2E_DENIED, m, 1);
            return;
        }
        /* Окно возвращаем за сам ответ; данные потока, пришедшие с ним, вернёт hy2c_read по мере
         * того, как стек их заберёт. */
        size_t resp_here = (size_t)used - before;
        qc_stream_consumed(h->qc, sid, resp_here);
        free(f->hbuf);
        f->hbuf = NULL;
        f->hn_ = 0;
        flow_ready(f);
        if (n > resp_here) flow_down(f, d + resp_here, n - resp_here);
        if (fin) { f->rx_fin = 1; stack_sess_rx(f); }
        return;
    }
    if (n) flow_down(f, d, n);
    if (fin && f->q) { f->rx_fin = 1; stack_sess_rx(f); }
}

static void on_stream_close(void *u, int64_t sid, uint64_t err) {
    struct hq *h = u;
    (void)err;
    struct hy2_flow *f = flow_by_sid(h, sid);
    if (!f) return;
    f->sclosed = 1;                         /* потока QUIC больше нет: ни слать, ни сбрасывать */
    act_del(h, f);
    if (f->state == FL_RESP) {
        flow_fail(f, HY2E_DENIED, "сервер закрыл поток, не ответив", 0);
        return;
    }
    /* Закрыт с обеих сторон: клиенту остался конец потока (после очереди), и стек ответит FIN. */
    f->rx_fin = 1;
    stack_sess_rx(f);
}

static void on_datagram(void *u, const uint8_t *d, size_t n) {
    struct hq *h = u;
    struct hy2_udp_msg m;
    if (hy2_udp_parse(d, n, &m) != 0) return;
    struct hy2_flow *f = usid_find(h, m.sid);
    if (!f || f->state != FL_OPEN) return;
    if (m.nfrag == 1) { udg_push(f, m.data, m.n); return; }
    /* Фрагмент датаграммы: сборка ведётся по packet id, их может идти несколько вперемешку (hy2wire.c). */
    size_t tot = 0;
    uint8_t *blk = hy2_rasm_feed(&f->ux->ras, &m, now_ms(), offsetof(struct udg, d), &tot);
    if (!blk) return;
    struct udg *ug = (struct udg *)blk;
    ug->next = NULL;
    ug->len = (uint32_t)tot;
    if (f->ut) f->ut->next = ug; else f->uh = ug;
    f->ut = ug;
    stack_sess_rx(f);
}

static void on_closed(void *u, int reason, const char *why) {
    struct hq *h = u;
    h->dead = 1;
    if (!h->dead_why[0]) {
        h->dead_reason = reason;
        snprintf(h->dead_why, sizeof h->dead_why, "%s", why && *why ? why : "соединение закрыто");
    }
}

static const struct qc_ops G_OPS = {
    .on_handshake = on_handshake,
    .on_stream_data = on_stream_data,
    .on_stream_close = on_stream_close,
    .on_datagram = on_datagram,
    .on_closed = on_closed,
};

/* ---- подъём и обрыв соединения ----------------------------------------------------------------- */

/* Следующая попытка поднять соединение без потока: сразу после обрыва — через секунду, после
 * отказа подъёма — с удвоенной паузой, до BG_MAX_MS. */
static void bg_schedule(struct hq *h, int failed) {
    if (!failed) h->bg_ms = RETRY_MS;
    else h->bg_ms = h->bg_ms ? (h->bg_ms * 2 > BG_MAX_MS ? BG_MAX_MS : h->bg_ms * 2) : RETRY_MS;
    h->bg_try_ms = now_ms() + h->bg_ms;
    h->want_up = 1;
}

static void ob_drop(struct hq *h) {
    if (!h->ob) return;
    hy2_gecko_free(&h->ob->gk);
    free(h->ob);
    h->ob = NULL;
}

static int connect_now(struct hq *h) {
    char ip[64];
    if (cached_ip(ip, sizeof ip) != 0) {
        set_err(h, "адрес узла %s не разрешился", g_node->host);
        h->next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(h, 1);
        return -1;
    }
    struct qc_cfg c;
    h->ob = calloc(1, sizeof *h->ob);
    if (!h->ob) { set_err(h, "нет памяти"); h->next_try_ms = now_ms() + RETRY_MS; bg_schedule(h, 1); return -1; }
    if (make_cfg(g_node, ip, &c, h->ob, g_mark, g_mark_req, h->conn_win, h->stream_win, h->tls) != 0) {
        set_err(h, "обфускация Gecko: размеры пакетов заданы неверно (min %u, max %u)",
                g_node->gecko_min, g_node->gecko_max);
        ob_drop(h);
        h->next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(h, 1);
        return -1;
    }
    h->dead = 0;
    h->dead_why[0] = '\0';
    h->hs_start_ms = now_ms();
    int rc = qc_open(&c, &G_OPS, h, &h->qc);
    if (rc != 0) {
        set_err(h, "QUIC не открылся (%d)", rc);
        h->next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(h, 1);
        h->qc = NULL;
        ob_drop(h);
        return -1;
    }
    /* Сокет QUIC — в epoll рабочего. Регистрируется при каждом подъёме: закрытие дескриптора убрало
     * прежнюю запись, а номер нового мог совпасть со старым. */
    if (stack_loop_watch(qc_fd(h->qc)) != 0) {
        qc_free(h->qc);
        h->qc = NULL;
        ob_drop(h);
        set_err(h, "сокет QUIC не встал в epoll");
        h->next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(h, 1);
        return -1;
    }
    h->state = S_HS;
    h->state_at_ms = now_ms();
    return 0;
}

/* Соединение кончилось: открывающиеся потоки отказывают, открытые — оборваны (связь пропала, а не закрыта:
 * клиенту RST, и стек увидит это при чтении). Сами сессии остаются у стека, пока он их не закроет. */
static void teardown(struct hq *h, const char *why) {
    if (h->busy) { h->busy = 0; __atomic_sub_fetch(&g_nbusy, 1, __ATOMIC_RELAXED); }
    h->cap_bps = h->cur_bps = 0;
    if (h->qc) { qc_free(h->qc); h->qc = NULL; }
    ob_drop(h);
    h->state = S_IDLE;
    h->dead = 0;
    h->timer_due_ms = 0;
    set_err(h, "%s", why);
    for (struct hy2_flow *f = h->fl, *nx; f; f = nx) {
        nx = f->nx;
        if (f->state == FL_WAIT || f->state == FL_RESP) {
            if (f->opening) {
                f->gone = 1;                /* потока QUIC уже нет: сбрасывать нечего */
                flow_fail(f, HY2E_DOWN, why, 0);
                continue;
            }
        }
        f->gone = 1;
        f->aborted = 1;
        f->rx_fin = 1;
        act_del(h, f);
        stack_sess_rx(f);
    }
    memset(h->by_sid, 0, sizeof h->by_sid);
    memset(h->by_usid, 0, sizeof h->by_usid);
    status_up(h, 0);
}

static void expire(struct hq *h, uint64_t now) {
    if (h->nopen && now - h->open_at_ms >= OPEN_TICK_MS) {
        h->open_at_ms = now;
        for (struct hy2_flow *f = h->fl, *nx; f; f = nx) {
            nx = f->nx;
            if (f->opening && f->deadline_ms <= now) flow_fail(f, HY2E_TIMEOUT, NULL, 1);
        }
    }
    if (h->state == S_AUTH && now - h->state_at_ms > AUTH_S * 1000u && h->qc && !h->dead) {
        char why[160];
        snprintf(why, sizeof why, "узел не ответил на авторизацию за %d с", AUTH_S);
        dead_mark(h, QC_CLOSE_HANDSHAKE, why);
        qc_close(h->qc, 0x101);
    }
}

/* Отправка, которую узел ещё не подтвердил: остаток досылается, а место, которое освободили подтверждения,
 * возвращается клиенту обновлением окна (stack_sess_room). Зовётся после событий QUIC. */
static void act_run(struct hq *h) {
    for (struct hy2_flow *f = h->act, *nx; f; f = nx) {
        nx = f->anx;
        if (f->up_n) flow_up_flush(f);
        stack_sess_room(f);
        if (f->act && !f->up_n && (f->gone || f->sclosed || qc_stream_buffered(h->qc, f->sid) == 0))
            act_del(h, f);
    }
}

/* ---- цикл рабочего ----------------------------------------------------------------------------- */

void hy2c_loop_start(int worker, int nworkers) {
    struct hq *h = g_node ? calloc(1, sizeof *h) : NULL;
    if (!h) {
        fprintf(stderr, LOG_W2 "hysteria2: нет памяти под соединение рабочего %d — потоки через него отказывают\n", worker);
        return;
    }
    h->worker = worker;
    h->nworkers = nworkers;
    win_for(nworkers, &h->conn_win, &h->stream_win);
    h->want_up = 1;                     /* соединение — сразу: первый поток клиента не платит за рукопожатие */
    h->bg_try_ms = 0;
    if (!g_node->has_pin) {
        h->tls = qc_tls_new(g_node->insecure, NULL, 0, tls_cert_roots());   /* корни — как в make_cfg */
        if (!h->tls)
            fprintf(stderr, LOG_W2 "hysteria2: корни проверки сертификата не разобрались — каждый подъём разбирает их заново\n");
    }
    pthread_mutex_lock(&g_mu);
    struct hq **nv = realloc(g_hq.v, (g_hq.n + 1) * sizeof *nv);
    if (nv) { g_hq.v = nv; g_hq.v[g_hq.n++] = h; }
    pthread_mutex_unlock(&g_mu);
    if (!nv) { qc_tls_free(h->tls); free(h); return; }
    H = h;
}

/* Сроки соединения и разбор сокета, сразу после epoll_wait. */
void hy2c_loop_poll(int ready) {
    struct hq *h = H;
    if (!h) return;
    uint64_t now = now_ms();
    int ev = 0;
    if (h->want_up && h->state == S_IDLE && !h->dead && now >= h->bg_try_ms) {
        h->want_up = 0;
        (void)connect_now(h);
    }
    if (ready && h->qc) {
        __atomic_store_n(&h->rx_at_ms, now, __ATOMIC_RELAXED);
        if (qc_on_readable(h->qc) == QC_ECLOSED && !h->dead) h->dead = 1;
        ev = 1;
    }
    /* Срок таймера QUIC снят перед ожиданием (hy2c_loop_wait): виток без пакета и без срока QUIC не трогает. */
    if (h->qc && !h->dead && h->timer_due_ms && now >= h->timer_due_ms) {
        h->timer_due_ms = 0;
        if (qc_on_timer(h->qc) == QC_ECLOSED && !h->dead) h->dead = 1;
        ev = 1;
    }
    if (ev && h->qc && !h->dead) act_run(h);
    if (h->dead) {
        char why[160];
        snprintf(why, sizeof why, "%s", h->dead_why[0] ? h->dead_why : "соединение закрыто");
        int wasup = h->state == S_UP;
        int reason = h->dead_reason;
        char who[24] = "";
        if (h->nworkers > 1) snprintf(who, sizeof who, " [рабочий %d]", h->worker);
        if (h->state == S_UP && reason != QC_CLOSE_LOCAL)
            fprintf(stderr, LOG_W2 "hysteria2: соединение с узлом оборвалось: %s%s\n", why, who);
        else if (h->state != S_UP && h->state != S_IDLE)
            fprintf(stderr, LOG_W2 "hysteria2: узел %s не принял соединение: %s%s\n", g_node->name, why, who);
        teardown(h, why);
        /* Пауза перед повтором — только после провала подъёма или обрыва; своё закрытие
         * поднятого соединения повтора не ждёт. Без потока соединение поднимается снова само
         * (bg_schedule): туннель держит связь с узлом всё время, а не по первому потоку. */
        h->next_try_ms = (wasup && reason == QC_CLOSE_LOCAL) ? 0 : now + RETRY_MS;
        bg_schedule(h, !wasup);
        h->dead_why[0] = '\0';
        h->dead_reason = 0;
    }
    expire(h, now);
    if (h->qc && h->state == S_UP && now - h->status_at_ms >= STATUS_MS) {
        if (h->nworkers > 1 && h->cap_bps) {
            rebalance(h, hy2_worker_busy(h->tx_bytes - h->tx_prev, now - h->status_at_ms, h->cur_bps));
            h->tx_prev = h->tx_bytes;
        }
        h->status_at_ms = now;
        struct qc_stats qs;
        qc_stats_get(h->qc, &qs);
        pthread_mutex_lock(&g_mu);
        h->st.rtt_us = qs.rtt_us;
        pthread_mutex_unlock(&g_mu);
        /* Датаграмма, не влезшая в пакет, выбрасывается (как потеря в сети) — но не молча:
         * строка в журнал не чаще раза в десять секунд, с числом выброшенных. */
        if (qs.dg_dropped > h->dg_seen && now - h->dg_log_ms >= 10000) {
            fprintf(stderr, LOG_W2 "hysteria2: выброшено датаграмм UDP, не влезших в пакет: %llu\n",
                    (unsigned long long)qs.dg_dropped);
            h->dg_seen = qs.dg_dropped;
            h->dg_log_ms = now;
        }
    }
}

/* Перед ожиданием: окна, которые продлили hy2c_read и закрытие потоков за виток, уходят одним пакетом —
 * сервер, остановленный окном, о них иначе не узнает до следующего события QUIC. Возвращает, через сколько
 * миллисекунд нужен виток (-1 — сроков нет). */
int hy2c_loop_wait(void) {
    struct hq *h = H;
    if (!h) return -1;
    int tmo = -1;
    if (h->qc && !h->dead) {
        qc_flush_credit(h->qc);
        int t = qc_timeout_ms(h->qc);
        h->timer_due_ms = 0;
        if (t >= 0) {
            tmo = t > 1000 ? 1000 : t;
            h->timer_due_ms = now_ms() + (uint64_t)t;
        }
    } else if (h->want_up) {
        uint64_t t = now_ms();
        tmo = h->bg_try_ms <= t ? 0 : (h->bg_try_ms - t > 1000 ? 1000 : (int)(h->bg_try_ms - t));
    }
    if (h->dead) tmo = 0;
    if (h->nopen && (tmo < 0 || tmo > OPEN_TICK_MS)) tmo = OPEN_TICK_MS;
    return tmo;
}

void hy2c_loop_stop(void) {
    struct hq *h = H;
    if (!h) return;
    if (h->qc) {
        if (h->state == S_UP && !h->dead) qc_close(h->qc, 0x100);
        qc_free(h->qc);
        h->qc = NULL;
    }
    ob_drop(h);
    qc_tls_free(h->tls);
    while (h->fl) flow_release(h->fl, 0);
    while (h->freeb) {
        struct pblk *b = h->freeb;
        h->freeb = b->next;
        free(b);
    }
    pthread_mutex_lock(&g_mu);
    for (unsigned i = 0; i < g_hq.n; i++)
        if (g_hq.v[i] == h) { g_hq.v[i] = g_hq.v[--g_hq.n]; break; }
    pthread_mutex_unlock(&g_mu);
    free(h);
    H = NULL;
}

/* ---- сводка для статуса и слежки --------------------------------------------------------------- */

int hy2c_alive(void) {
    /* Окно — два PING с запасом: на каждый узел отвечает ACK, так что живое соединение без
     * трафика получает пакет не реже срока PING (make_cfg; после рукопожатия он бывает и короче).
     * Узел жив, если жив хотя бы один из соединений рабочих. */
    unsigned ka = g_idle_ms / 3 < 10000 ? g_idle_ms / 3 : 10000;
    uint64_t within_ms = 2ull * ka + 1000, now = mono_ms();
    int alive = 0;
    pthread_mutex_lock(&g_mu);
    for (unsigned i = 0; i < g_hq.n && !alive; i++) {
        struct hq *h = g_hq.v[i];
        uint64_t rx = __atomic_load_n(&h->rx_at_ms, __ATOMIC_RELAXED);
        alive = h->st.up && rx && now - rx <= within_ms;
    }
    pthread_mutex_unlock(&g_mu);
    return alive;
}

void hy2c_status(struct hy2c_status *st) {
    memset(st, 0, sizeof *st);
    struct hq *first_up = NULL;
    unsigned flows = 0;
    pthread_mutex_lock(&g_mu);
    for (unsigned i = 0; i < g_hq.n; i++) {
        struct hq *h = g_hq.v[i];
        flows += __atomic_load_n(&h->nflows, __ATOMIC_RELAXED);
        if (h->st.up && !first_up) first_up = h;
    }
    if (first_up) {
        *st = first_up->st;
        st->err[0] = '\0';
    } else {
        for (unsigned i = 0; i < g_hq.n && !st->err[0]; i++)
            snprintf(st->err, sizeof st->err, "%s", g_hq.v[i]->st.err);
    }
    st->flows = flows;
    pthread_mutex_unlock(&g_mu);
}
