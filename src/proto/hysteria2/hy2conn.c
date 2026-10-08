/* Соединение hysteria2: одно QUIC на туннель, потоки клиента — поверх него.
 *
 * МОДЕЛЬ. У VLESS каждому соединению клиента стек (src/tunnel/stack.c) заводит свою связь с узлом —
 * дескриптор, который сам же и опрашивает. У hysteria2 связь одна: QUIC-соединение, в нём потоки
 * (по одному на TCP-соединение клиента) и датаграммы (UDP), и сокет у соединения общий. Стек
 * устроен под «дескриптор на соединение» (dialer.h: fd, read, send), а переделывать его под
 * мультиплексирование — менять модель всех дайлеров (см. «чего здесь нет» в dialer.h). Поэтому
 * мультиплексор стоит между: это ОТДЕЛЬНЫЙ ПОТОК процесса модуля, который владеет QUIC и держит
 * для каждого соединения клиента пару сокетов SOCK_SEQPACKET. Один конец у стека — обычный
 * дескриптор, который тот опрашивает через epoll, как любой другой, второй — у мультиплексора.
 * Стек видит то, что привык видеть: connect (блокирует установщик, пока сервер не ответит на запрос
 * потока), send, read, EOF.
 *
 * ПОЧЕМУ SEQPACKET, А НЕ STREAM. Запись в SOCK_STREAM бывает частичной, а дайлер обязан вернуть
 * SEND_OK («всё принято») или SEND_AGAIN («ничего не принято»): третьего исхода у стека нет.
 * Запись в SEQPACKET либо кладёт сообщение целиком, либо отказывает (EAGAIN) — то, что нужно.
 * Заодно UDP получает границы датаграмм даром: одна запись — одна датаграмма. Цена — потолок
 * длины сообщения: мультиплексор пишет клиентской стороне куски не длиннее 16000 байт (стек читает
 * буфером TUNNEL_BUF, 18 КБ; сообщение длиннее обрезалось бы).
 *
 * ОБРАТНОЕ ДАВЛЕНИЕ. Стек перестаёт читать дескриптор, когда окно клиента закрыто. Окно приёма
 * QUIC поэтому продлевается не сразу, а когда байты ушли в сокет клиента (cfg.flow_manual,
 * qc_stream_consumed): медленный клиент тормозит сервер, а не копит очередь в памяти роутера.
 * Сама очередь к клиенту — цепочка блоков (pblk), память которых возвращается по мере отдачи, а её
 * предел — окно потока (RX_STREAM_WIN), а не «сколько вырастет».
 * В обратную сторону (клиент → узел) тормозит стек, а не мы: он не подтверждает данные клиента,
 * пока очередь пары выше нижней отметки (DC_ACK_PACED, dialer.h), — то есть окно клиента равно
 * месту в очереди, и она не переполняется. Мы же разбираем очередь по мере сил: qc_stream_send
 * принимает не всё (буфер потока — send_buf), остаток ждёт в потоке (flow.up) и досылается после
 * каждого события QUIC, пока не освободится буфер, а пока он ждёт, поток не читается.
 *
 * ЖИЗНЬ СОЕДИНЕНИЯ. Открывается сразу при запуске и держится, сколько живёт процесс, — с потоками и
 * без: PING QUIC (keepalive, quic.c) не даёт ему умереть по сроку простоя. Прежде соединение без
 * единого потока закрывалось через минуту, и это стоило дорого (живой роутер, туннель в группе,
 * которая выбрала другой выход): переподключение раз в 1,5–3 минуты, диагностика «соединение не
 * поднято» у здорового узла, а замер задержки группы ловил рукопожатие следующего потока и прыгал
 * втрое, переключая группу между туннелями. Оборвалось — поднимается снова само (bg_*: первая
 * попытка через секунду, дальше пауза удваивается до BG_MAX_MS, пока узел не ответит), и запрос
 * потока, пришедший при упавшем соединении, тоже поднимает его и ждёт (в пределах срока запроса).
 * После неудачного подъёма запрос не повторяет попытку раньше чем через секунду — иначе серия SYN
 * клиентов стучалась бы в мёртвый узел с частотой SYN.
 *
 * ЧТО ДЕЛАЕТ СЕРВЕР С ПОТОКОМ. TCP: клиент пишет TCPRequest (адрес назначения), сервер отвечает
 * TCPResponse (статус, сообщение) и дальше поток — прозрачный байтовый канал. UDP: датаграммы QUIC
 * с UDPMessage (идентификатор сессии, адрес, данные), сессия на сервере рождается с первой; ответа на
 * «открытие» нет, поэтому запрос UDP-потока завершается сразу. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/random.h>
#include <sys/socket.h>

#include "hy2conn.h"
#include "quic.h"

#define LOG_W2 "steer[warn]: "
#define LOG_I2 "steer[info]: "

#if HY2_HOP_RANGES != QC_HOP_RANGES
#error "диапазонов прыжков в узле и в обёртке QUIC должно быть поровну"
#endif

/* Потоков клиента одновременно — не константа: массив потоков растёт (E.fl), а пределом служит
 * сам QUIC — сколько двунаправленных потоков разрешил сервер (qc_stream_open отвечает отказом,
 * запрос получает HY2E_BUSY) — и память. Раньше стояло 1024 «по умолчанию эталона», и клиент
 * отказывал раньше сервера, у которого лимит выше. */
#define CHUNK      16000       /* сообщение клиентской стороне: меньше буфера стека (TUNNEL_BUF) */
#define RXB         65536

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
 * Мбит/с), так что менять эти два числа вместе с замером на длинном пути. */
#define RX_CONN_WIN    (16u << 20)
#define RX_STREAM_WIN  (8u << 20)
/* Очередь одного потока не больше окна потока; запас — на округление окна, а не на нарушителя:
 * нарушителя закрывает ngtcp2, и если очередь всё же вышла за окно, это ошибка счёта кредита —
 * такой поток закрывается с числами в журнале, а не растит память. */
#define PEND_MAX       (RX_STREAM_WIN + (1u << 20))
#define RSLOT       1400        /* место под фрагмент UDP при сборке */
/* Фрагментов одной датаграммы UDP от сервера — не больше 64: датаграмма UDP не длиннее 65535
 * байт, а фрагмент несёт до RSLOT байт, так что 64 покрывают протокол целиком; заявленное
 * сервером большее число — испорченный кадр, он отбрасывается (on_datagram). Свойство протокола. */
#define RFRAG_MAX   64
#define AUTH_S      10          /* срок ответа на авторизацию */
#define REQ_S       15          /* срок ответа на запрос TCP */
#define RETRY_MS    1000
#define BG_MAX_MS   30000       /* потолок паузы между попытками поднять упавшее соединение */

/* ---- запрос потока (поток установщика → мультиплексор) ------------------------------------------ */

struct req {
    struct req *next;
    int udp;
    char host[128];
    uint16_t port;
    int efd;                    /* конец пары у мультиплексора: после постановки в очередь его */
    uint64_t deadline_ms;
    int done, cancel, rc;
    char msg[128];
    int refs;
    pthread_cond_t cv;
};

/* ---- поток клиента ---------------------------------------------------------------------------- */

enum { FL_RESP, FL_OPEN };

/* Блок очереди к клиенту: ровно одно сообщение клиентской стороне (CHUNK). off — сколько с головы
 * уже отдано, len — сколько лежит. */
struct pblk {
    struct pblk *next;
    uint32_t off, len;
    uint8_t d[CHUNK];
};

struct flow {
    int fd;                     /* конец пары у мультиплексора */
    int udp;
    int state;
    int64_t sid;                /* поток QUIC (TCP) */
    uint32_t usid;              /* идентификатор сессии UDP */
    uint16_t pkt;               /* счётчик пакетов UDP */
    struct req *req;            /* пока запрос не завершён */
    uint32_t events;            /* что сейчас в epoll */
    int inep;                   /* дескриптор уже добавлен */
    uint64_t t0_ms;
    char addr[280];             /* «хост:порт» назначения */
    /* Ответ сервера на запрос TCP копится здесь, пока не разобран целиком. */
    uint8_t *hbuf;
    size_t hn;
    /* Вниз, к клиенту: то, что не влезло в сокет, — цепочка блоков (pblk), голова — самое
     * старое. pend_n — сколько байт в цепочке всего. */
    struct pblk *ph, *pt;
    size_t pend_n;
    /* Вверх, к серверу: остаток, который qc_stream_send не принял. */
    uint8_t *up;
    size_t up_n;
    unsigned rx_fin : 1, up_eof : 1, fin_sent : 1, shut : 1, closing : 1;
    /* Сборка фрагментированной датаграммы UDP от сервера. */
    uint16_t rpkt;
    uint8_t rgot, rn;
    uint16_t rlen[RFRAG_MAX];
    uint8_t rseen[RFRAG_MAX];
    uint8_t *rbuf;
    /* Цепочки корзин индексов по номеру потока и по идентификатору сессии UDP (E.by_sid,
     * E.by_usid): коллизия корзины — не отказ, а следующий в цепочке. */
    struct flow *hn_sid, *hn_usid;
};

enum { S_IDLE, S_HS, S_AUTH, S_UP };

static struct {
    const struct hy2_node *node;
    int started;
    pthread_t th;
    int epfd, wake;
    uint32_t mark;
    int mark_req;

    pthread_mutex_t mu;
    struct req *qh, *qt;            /* очередь запросов */
    char err[160];                  /* причина последнего отказа соединения */
    struct hy2c_status st;
    /* Кэш разрешённого адреса сервера: getaddrinfo зовёт поток установщика, не мультиплексор. */
    char ip[64];
    uint64_t ip_at_ms;

    /* Всё ниже — только поток мультиплексора. */
    struct qc *qc;
    int state;
    int want_up;                    /* поднять соединение при старте, не дожидаясь запроса */
    unsigned gen;                   /* растёт при каждом закрытии потока клиента */
    int dead;                       /* on_closed сработал: разобрать после возврата из qc_* */
    int dead_reason;
    char dead_why[160];
    uint64_t state_at_ms, next_try_ms, up_at_ms;
    uint64_t bg_try_ms;             /* когда поднимать упавшее соединение без запроса (want_up) */
    unsigned bg_ms;                 /* текущая пауза этих попыток: растёт при отказах, 0 — после подъёма */
    uint64_t rx_at_ms;              /* последний пакет от узла (hy2c_alive); пишет мультиплексор */
    struct obfs_state *ob;          /* обфускация текущего соединения (make_cfg) */
    int64_t auth_sid;
    uint8_t abuf[4096];
    size_t an;
    uint64_t hs_start_ms;
    struct flow **fl;               /* растущий массив потоков (flow_new), nfl — занято, flcap — место */
    unsigned nfl, flcap;
    struct flow *by_sid[4096];      /* корзины цепочек по номеру потока (sid / 4) */
    struct flow *by_usid[1024];     /* по идентификатору сессии UDP */
    char ip_used[64];
} E = { .mu = PTHREAD_MUTEX_INITIALIZER };

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

void hy2c_set_mark(uint32_t mark, int required) {
    E.mark = mark;
    E.mark_req = required;
}

/* Срок простоя QUIC (ключ `silence` выхода): узел, от которого ничего нет дольше срока, — соединение
 * закрыто, потоки клиентов кончаются, следующий поток поднимает соединение заново. PING QUIC шлёт
 * чаще срока втрое, но не реже прежних 10 с. Умолчание — прежнее: 30 с и 10 с. */
static unsigned g_idle_ms = 30000;
void hy2c_set_idle(int silence_s) {
    if (silence_s > 0) g_idle_ms = (unsigned)silence_s * 1000u;
}

static void set_err(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void set_err(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    pthread_mutex_lock(&E.mu);
    vsnprintf(E.err, sizeof E.err, fmt, ap);
    pthread_mutex_unlock(&E.mu);
    va_end(ap);
}

const char *hy2c_strerror(int rc) {
    static __thread char buf[200];
    char e[160];
    pthread_mutex_lock(&E.mu);
    snprintf(e, sizeof e, "%s", E.err);
    pthread_mutex_unlock(&E.mu);
    switch (rc) {
    case HY2E_TIMEOUT: return "узел не ответил вовремя";
    case HY2E_DOWN: snprintf(buf, sizeof buf, "нет соединения с узлом: %s", e); return buf;
    case HY2E_DENIED: snprintf(buf, sizeof buf, "сервер отказал: %s", e); return buf;
    case HY2E_NOUDP: return "сервер не принимает UDP";
    case HY2E_BUSY: return "нет свободных потоков";
    case HY2E_SYS: return "ошибка сокета или памяти";
    }
    return "ошибка";
}

/* ---- адрес сервера ----------------------------------------------------------------------------- */

/* Числовой адрес узла. Имя разрешается тут, в потоке установщика или зонда, а не в мультиплексоре:
 * getaddrinfo блокирует, а в мультиплексоре ждут все потоки клиентов разом. IPv4 предпочтителен:
 * путь до узла чаще есть по нему, а QUIC не пробует адреса по очереди. */
static int resolve_ip(const struct hy2_node *n, char *ip, size_t cap) {
    struct in_addr a4;
    struct in6_addr a6;
    if (inet_pton(AF_INET, n->host, &a4) == 1 || inet_pton(AF_INET6, n->host, &a6) == 1) {
        snprintf(ip, cap, "%s", n->host);
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

static int cached_ip(char *ip, size_t cap) {
    pthread_mutex_lock(&E.mu);
    if (E.ip[0] && now_ms() - E.ip_at_ms < 120000) {
        snprintf(ip, cap, "%s", E.ip);
        pthread_mutex_unlock(&E.mu);
        return 0;
    }
    pthread_mutex_unlock(&E.mu);
    if (resolve_ip(E.node, ip, cap) != 0) return -1;
    pthread_mutex_lock(&E.mu);
    snprintf(E.ip, sizeof E.ip, "%s", ip);
    E.ip_at_ms = now_ms();
    pthread_mutex_unlock(&E.mu);
    return 0;
}

/* ---- настройка QUIC по узлу -------------------------------------------------------------------- */

/* Состояние обфускации соединения: живёт, пока живёт qc (фильтр держит указатель на него). */
struct obfs_state {
    struct hy2_salamander sm;
    struct hy2_gecko gk;
    struct qc_filter flt;
};

static void make_cfg(const struct hy2_node *n, const char *ip, struct qc_cfg *c,
                     struct obfs_state *ob, uint32_t mark, int mark_req) {
    memset(c, 0, sizeof *c);
    c->host = ip;
    c->port = n->port;
    /* Без sni имя сертификата сверяется с хостом узла — и с адресом тоже: у адреса SNI не уходит, а
     * проверка идёт по SAN IP (qcssl_new), как у эталона (Go кладёт хост в ServerName). Прежде при
     * адресе без sni имени не сверял никто, и годился сертификат любого имени от признанного корня. */
    c->sni = n->sni[0] ? n->sni : n->host[0] ? n->host : NULL;
    c->alpn = "h3";
    c->insecure = n->insecure;
    if (n->has_pin) c->pin_sha256 = n->pin;
    /* Скорость: заданный up включает Brutal сразу, без него — BBR. Ответ сервера на авторизацию
     * может это изменить (apply_cc). */
    c->brutal_bps = n->up_bps;
    c->bbr = n->up_bps == 0;
    c->datagram_max = 1500;
    c->idle_ms = g_idle_ms;
    c->keepalive_ms = g_idle_ms / 3 < 10000 ? g_idle_ms / 3 : 10000;
    c->flow_manual = 1;
    c->max_data = RX_CONN_WIN;
    c->max_stream_data = RX_STREAM_WIN;
    c->sock_mark = mark;
    c->mark_required = mark_req;
    memset(ob, 0, sizeof *ob);
    if (n->obfs == 2 && hy2_gecko_init(&ob->gk, n->obfs_pass, n->gecko_min, n->gecko_max) == 0) {
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
}

/* ---- авторизация (общая у мультиплексора и разовой проверки) ------------------------------------ */

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
    make_cfg(n, ip, &c, &ob, E.mark, E.mark_req);
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
    uint64_t t0 = now_ms(), lim = t0 + (uint64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    int ret = -1;
    while (!pr->closed && pr->stage >= 0 && pr->stage != 2) {
        uint64_t t = now_ms();
        if (t >= lim) { snprintf(pr->why, sizeof pr->why, "узел не ответил за %d с", timeout_s); break; }
        if (qc_run(pr->q, (int)(lim - t > 200 ? 200 : lim - t)) == QC_ECLOSED) break;
    }
    if (pr->stage == 2) {
        ret = 0;
        if (hs_ms) *hs_ms = (int)(now_ms() - t0);
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

/* ---- потоки клиента: таблицы ------------------------------------------------------------------- */

static uint32_t flow_ev(const struct flow *f) {
    /* EPOLLRDHUP срабатывает по уровню, пока клиент не закрыл запись: после этого события ждать
     * незачем, и оставить его значило бы крутить цикл. HUP и ERR приходят и без запроса. */
    uint32_t e = 0;
    if (f->state == FL_OPEN && !f->up_eof && !f->up_n) e |= EPOLLIN | EPOLLRDHUP;
    if (f->pend_n) e |= EPOLLOUT;
    return e;
}

static void ep_sync(struct flow *f) {
    uint32_t e = flow_ev(f);
    if (e == f->events && f->inep) return;
    struct epoll_event ev = { .events = e, .data.ptr = f };
    if (epoll_ctl(E.epfd, f->inep ? EPOLL_CTL_MOD : EPOLL_CTL_ADD, f->fd, &ev) == 0) {
        f->events = e;
        f->inep = 1;
    }
}

static void req_finish(struct req *r, int rc, const char *msg) {
    pthread_mutex_lock(&E.mu);
    r->rc = rc;
    if (msg) snprintf(r->msg, sizeof r->msg, "%s", msg);
    r->done = 1;
    pthread_cond_signal(&r->cv);
    if (--r->refs == 0) { pthread_cond_destroy(&r->cv); free(r); }
    pthread_mutex_unlock(&E.mu);
}

/* Индексы потоков — корзины с цепочками: число одновременных потоков от размера таблицы не
 * зависит. Вставка — в голову цепочки, снятие — по указателю (снять нестоящего безвредно). */
static struct flow **sid_bucket(int64_t sid) { return &E.by_sid[(uint64_t)(sid / 4) & 4095]; }
static struct flow **usid_bucket(uint32_t u) { return &E.by_usid[u & 1023]; }
static void sid_add(struct flow *f) { struct flow **b = sid_bucket(f->sid); f->hn_sid = *b; *b = f; }
static void usid_add(struct flow *f) { struct flow **b = usid_bucket(f->usid); f->hn_usid = *b; *b = f; }
static void sid_del(struct flow *f) {
    for (struct flow **p = sid_bucket(f->sid); *p; p = &(*p)->hn_sid)
        if (*p == f) { *p = f->hn_sid; break; }
    f->hn_sid = NULL;
}
static void usid_del(struct flow *f) {
    for (struct flow **p = usid_bucket(f->usid); *p; p = &(*p)->hn_usid)
        if (*p == f) { *p = f->hn_usid; break; }
    f->hn_usid = NULL;
}
static struct flow *usid_find(uint32_t u) {
    for (struct flow *f = *usid_bucket(u); f; f = f->hn_usid)
        if (f->usid == u) return f;
    return NULL;
}

/* ---- очередь к клиенту ------------------------------------------------------------------------ */

/* Очередь к медленному клиенту — цепочка блоков по CHUNK байт, а не один растущий буфер.
 *
 * Прежде это был один буфер со смещением «уже отдано», и отданное место возвращалось, только когда
 * очередь пустела ЦЕЛИКОМ. Под непрерывной загрузкой клиент отстаёт от узла постоянно (сеть быстрее
 * его приёма — а здесь это обычное дело: узким местом бывает сама сторона клиента), и очередь не
 * пустела никогда: дописывалось всё дальше, буфер удваивался (до 256 МиБ на поток), а живых байт в
 * нём лежали мегабайты — их держало в узде окно потока, а отданный хвост не держал никто. Восемь
 * потоков за двадцать секунд раздували процесс с 14 до 700 МБ (замер 2026-10-04). Блоки отдают
 * память по мере отдачи клиенту и не копируются при росте: занято ровно то, что лежит, плюс
 * неполный хвостовой блок. Предел самой очереди — RX_STREAM_WIN. */

/* Дописать n байт в хвост. -1 — нет памяти: что успело лечь, осталось (pend_n честный). */
static int pend_add(struct flow *f, const uint8_t *d, size_t n) {
    while (n) {
        struct pblk *b = f->pt;
        if (!b || b->len == CHUNK) {
            b = malloc(sizeof *b);
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

/* Что отдать клиенту следующим: не длиннее CHUNK, из головного блока. NULL — очередь пуста. */
static const uint8_t *pend_front(const struct flow *f, size_t *n) {
    const struct pblk *b = f->ph;
    if (!b) return NULL;
    *n = b->len - b->off;
    return b->d + b->off;
}

/* Из головы отдано k байт (не больше того, что вернул pend_front). Опустевший блок освобождается —
 * в том числе неполный хвостовой: память следует за нагрузкой, а не за её наибольшим всплеском. */
static void pend_take(struct flow *f, size_t k) {
    struct pblk *b = f->ph;
    b->off += (uint32_t)k;
    f->pend_n -= k;
    if (b->off == b->len) {
        f->ph = b->next;
        if (!f->ph) f->pt = NULL;
        free(b);
    }
}

static void pend_free(struct flow *f) {
    while (f->ph) {
        struct pblk *b = f->ph;
        f->ph = b->next;
        free(b);
    }
    f->pt = NULL;
    f->pend_n = 0;
}

static void flow_free(struct flow *f, int rc, const char *msg) {
    if (f->req) {
        req_finish(f->req, rc ? rc : HY2E_DOWN, msg ? msg : "поток закрыт");
        f->req = NULL;
    }
    /* Окно соединения возвращаем и за то, что так и не отдали клиенту. */
    if (f->pend_n && E.qc) qc_stream_consumed(E.qc, f->udp ? 0 : f->sid, f->pend_n);
    if (f->fd >= 0) close(f->fd);
    if (!f->udp) sid_del(f);
    else usid_del(f);
    for (unsigned i = 0; i < E.nfl; i++)
        if (E.fl[i] == f) { E.fl[i] = E.fl[--E.nfl]; break; }
    free(f->hbuf);
    pend_free(f);
    free(f->up);
    free(f->rbuf);
    free(f);
    E.gen++;
}

static void status_up(int up) {
    pthread_mutex_lock(&E.mu);
    E.st.up = up;
    E.st.flows = E.nfl;
    pthread_mutex_unlock(&E.mu);
}

/* Соединение кончилось: все потоки клиента — в ошибку. Их дескрипторы закрываются, стек видит
 * EOF/ошибку и рвёт клиентские соединения (как при обрыве связи с узлом у VLESS). */
static void teardown(const char *why) {
    if (E.qc) { qc_free(E.qc); E.qc = NULL; }
    if (E.ob) { hy2_gecko_free(&E.ob->gk); free(E.ob); E.ob = NULL; }
    E.state = S_IDLE;
    E.dead = 0;
    set_err("%s", why);
    while (E.nfl) flow_free(E.fl[0], HY2E_DOWN, why);
    memset(E.by_sid, 0, sizeof E.by_sid);
    memset(E.by_usid, 0, sizeof E.by_usid);
    status_up(0);
}

/* ---- сторона клиента: запись и чтение --------------------------------------------------------- */

/* Отдать клиенту сообщение целиком; -1 — сокет закрыт, 0 — нет места, 1 — отдано. */
static int local_put(struct flow *f, const uint8_t *d, size_t n) {
    ssize_t w = send(f->fd, d, n, MSG_DONTWAIT | MSG_NOSIGNAL);
    if (w == (ssize_t)n) return 1;
    if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == ENOBUFS)) return 0;
    return -1;
}

static void flow_local_gone(struct flow *f) {
    if (!f->udp && E.qc) qc_stream_reset(E.qc, f->sid, 0);
    flow_free(f, HY2E_DOWN, "клиент закрыл поток");
}

/* Байты от сервера — клиенту: сколько можно сразу, остальное в очередь. */
static void flow_down(struct flow *f, const uint8_t *d, size_t n) {
    size_t off = 0;
    while (off < n && !f->pend_n) {
        size_t k = n - off < CHUNK ? n - off : CHUNK;
        int r = local_put(f, d + off, k);
        if (r < 0) { qc_stream_consumed(E.qc, f->sid, n - off); flow_local_gone(f); return; }
        if (r == 0) break;
        off += k;
        qc_stream_consumed(E.qc, f->sid, k);
    }
    if (off < n) {
        size_t rest = n - off;
        if (f->pend_n + rest > PEND_MAX) {
            /* Окно не бывает больше очереди: сюда доходят только при ошибке счёта кредита. Рвём
             * поток, а не растим память, и называем числа. */
            fprintf(stderr, LOG_W2 "hysteria2: очередь к клиенту %zu КиБ вышла за окно потока %u КиБ — "
                            "поток закрыт\n", (f->pend_n + rest) >> 10, (unsigned)(PEND_MAX >> 10));
            qc_stream_consumed(E.qc, f->sid, rest);
            flow_local_gone(f);
            return;
        }
        size_t before = f->pend_n;
        if (pend_add(f, d + off, rest) != 0) {
            /* Что успело лечь в очередь, вернёт flow_free: кредит возвращаем только за остальное. */
            qc_stream_consumed(E.qc, f->sid, rest - (f->pend_n - before));
            flow_local_gone(f);
            return;
        }
    }
    ep_sync(f);
}

static void flow_maybe_shut(struct flow *f) {
    if (f->rx_fin && !f->pend_n && !f->shut) {
        f->shut = 1;
        shutdown(f->fd, SHUT_WR);
    }
}

static void flow_drain(struct flow *f) {
    size_t k;
    const uint8_t *p;
    while ((p = pend_front(f, &k)) != NULL) {
        int r = local_put(f, p, k);
        if (r < 0) { flow_local_gone(f); return; }
        if (r == 0) break;
        pend_take(f, k);
        qc_stream_consumed(E.qc, f->sid, k);
    }
    flow_maybe_shut(f);
    if (f->closing && !f->pend_n) { flow_free(f, 0, NULL); return; }
    ep_sync(f);
}

/* Дослать серверу остаток, который не принял буфер потока; закрыть передачу, если клиент закончил. */
static void flow_up_flush(struct flow *f) {
    if (f->up_n) {
        ssize_t k = qc_stream_send(E.qc, f->sid, f->up, f->up_n, 0);
        if (k < 0) { flow_local_gone(f); return; }
        if ((size_t)k < f->up_n) {
            memmove(f->up, f->up + k, f->up_n - (size_t)k);
            f->up_n -= (size_t)k;
            return;
        }
        f->up_n = 0;
        free(f->up);
        f->up = NULL;
    }
    if (f->up_eof && !f->fin_sent && !f->up_n) {
        if (qc_stream_send(E.qc, f->sid, (const uint8_t *)"", 0, 1) >= 0) f->fin_sent = 1;
    }
    ep_sync(f);
}

static uint8_t g_rx[RXB];

static void flow_readable(struct flow *f) {
    for (int i = 0; i < 16 && f->state == FL_OPEN && !f->up_eof && !f->up_n; i++) {
        ssize_t n = recv(f->fd, g_rx, sizeof g_rx, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) break;
            flow_local_gone(f);
            return;
        }
        if (n == 0) {                       /* клиент закончил запись */
            f->up_eof = 1;
            flow_up_flush(f);
            break;
        }
        ssize_t k = qc_stream_send(E.qc, f->sid, g_rx, (size_t)n, 0);
        if (k < 0) { flow_local_gone(f); return; }
        if (k < n) {
            f->up = malloc((size_t)(n - k));
            if (!f->up) { flow_local_gone(f); return; }
            memcpy(f->up, g_rx + k, (size_t)(n - k));
            f->up_n = (size_t)(n - k);
        }
    }
    ep_sync(f);
}

static void udp_readable(struct flow *f) {
    for (int i = 0; i < 32; i++) {
        ssize_t n = recv(f->fd, g_rx, sizeof g_rx, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR) break;
            flow_local_gone(f);
            return;
        }
        if (n == 0) { flow_local_gone(f); return; }
        uint8_t msg[1600];
        size_t dmax = qc_datagram_max(E.qc);
        uint8_t hdr[320];
        size_t hl = hy2_udp_header(hdr, sizeof hdr, f->usid, 0, 0, 1, f->addr);
        if (!hl || dmax <= hl) continue;                    /* сервер датаграмм не принимает */
        size_t room = dmax - hl;
        if (room > sizeof msg - hl) room = sizeof msg - hl;
        size_t nfrag = ((size_t)n + room - 1) / room;
        if (nfrag > 255) continue;
        /* Целая датаграмма идёт с packet id 0, как у эталона; у фрагментированной id ненулевой и
         * свой на каждую: приёмник эталона склеивает фрагменты одного id, а нулевой у него
         * значит «состояния нет». */
        uint16_t pid = 0;
        if (nfrag > 1 && ++f->pkt == 0) f->pkt = 1;
        if (nfrag > 1) pid = f->pkt;
        for (size_t fi = 0; fi < nfrag; fi++) {
            size_t off = fi * room, len = (size_t)n - off < room ? (size_t)n - off : room;
            hl = hy2_udp_header(msg, sizeof msg, f->usid, pid, (uint8_t)fi, (uint8_t)nfrag, f->addr);
            memcpy(msg + hl, g_rx + off, len);
            (void)qc_datagram_send(E.qc, msg, hl + len);    /* очередь полна — датаграмма пропала, как в сети */
        }
    }
}

/* ---- события потоков клиента ------------------------------------------------------------------ */

static void flow_event(struct flow *f, uint32_t ev) {
    if (ev & (EPOLLHUP | EPOLLERR)) { flow_local_gone(f); return; }
    if (ev & EPOLLOUT) { flow_drain(f); if (!E.qc) return; }
    if (ev & (EPOLLIN | EPOLLRDHUP)) {
        if (f->udp) udp_readable(f);
        else flow_readable(f);
    }
}

/* ---- начало потока по запросу ----------------------------------------------------------------- */

static struct flow *flow_new(struct req *r) {
    if (E.nfl == E.flcap) {
        unsigned nc = E.flcap ? E.flcap * 2 : 64;
        struct flow **nf = realloc(E.fl, nc * sizeof *nf);
        if (!nf) return NULL;
        E.fl = nf;
        E.flcap = nc;
    }
    struct flow *f = calloc(1, sizeof *f);
    if (!f) return NULL;
    f->fd = r->efd;
    f->udp = r->udp;
    f->req = r;
    f->t0_ms = now_ms();
    if (strchr(r->host, ':')) snprintf(f->addr, sizeof f->addr, "[%s]:%u", r->host, r->port);
    else snprintf(f->addr, sizeof f->addr, "%s:%u", r->host, r->port);
    E.fl[E.nfl++] = f;
    return f;
}

static void flow_ready(struct flow *f) {
    f->state = FL_OPEN;
    struct req *r = f->req;
    f->req = NULL;
    /* Уже отменён (установщик не дождался): поток не нужен. */
    pthread_mutex_lock(&E.mu);
    int cancelled = r->cancel;
    pthread_mutex_unlock(&E.mu);
    req_finish(r, cancelled ? HY2E_TIMEOUT : 0, NULL);
    if (cancelled) {
        if (!f->udp) qc_stream_reset(E.qc, f->sid, 0);
        flow_free(f, 0, NULL);
        return;
    }
    ep_sync(f);
}

static void start_flow(struct req *r) {
    pthread_mutex_lock(&E.mu);
    int cancelled = r->cancel;
    pthread_mutex_unlock(&E.mu);
    if (cancelled) { close(r->efd); req_finish(r, HY2E_TIMEOUT, NULL); return; }

    if (r->udp && !E.st.udp_ok) {
        close(r->efd);
        req_finish(r, HY2E_NOUDP, NULL);
        return;
    }
    struct flow *f = flow_new(r);
    if (!f) { close(r->efd); req_finish(r, HY2E_BUSY, NULL); return; }
    if (r->udp) {
        /* Идентификатор сессии — случайный, свободный в таблице. */
        for (int tries = 0; tries < 16; tries++) {
            uint32_t u;
            if (getrandom(&u, sizeof u, 0) != sizeof u) u = (uint32_t)now_ms() * 2654435761u;
            if (!u || usid_find(u)) continue;
            f->usid = u;
            usid_add(f);
            break;
        }
        if (!f->usid) { f->fd = -1; close(r->efd); f->req = NULL; flow_free(f, 0, NULL); req_finish(r, HY2E_BUSY, NULL); return; }
        flow_ready(f);
        return;
    }
    int64_t sid;
    int rc = qc_stream_open(E.qc, &sid);
    if (rc != 0) {                      /* потоков больше нет: лимит сервера (MAX_STREAMS) */
        struct req *rq = f->req;
        f->req = NULL;
        flow_free(f, 0, NULL);          /* закроет efd */
        req_finish(rq, HY2E_BUSY, NULL);
        return;
    }
    f->sid = sid;
    sid_add(f);
    uint8_t pad;
    if (getrandom(&pad, 1, 0) != 1) pad = 16;
    uint8_t b[600];
    size_t l = hy2_tcp_request(b, sizeof b, r->host, r->port, pad % 64);
    if (!l || qc_stream_send(E.qc, sid, b, l, 0) != (ssize_t)l) {
        struct req *rq = f->req;
        f->req = NULL;
        qc_stream_reset(E.qc, sid, 0);
        flow_free(f, 0, NULL);
        req_finish(rq, HY2E_BUSY, "запрос не ушёл");
        return;
    }
    f->state = FL_RESP;
}

/* ---- колбэки QUIC ----------------------------------------------------------------------------- */

static void on_handshake(void *u) {
    (void)u;
    E.hs_start_ms = E.hs_start_ms ? E.hs_start_ms : now_ms();
    const char *w = auth_begin(E.qc, E.node, &E.auth_sid);
    if (w) {
        E.dead = 1;
        E.dead_reason = QC_CLOSE_ERROR;
        snprintf(E.dead_why, sizeof E.dead_why, "%s", w);
        qc_close(E.qc, 0x101);
        return;
    }
    E.state = S_AUTH;
    E.state_at_ms = now_ms();
    E.an = 0;
}

static struct flow *flow_by_sid(int64_t sid) {
    if (sid < 0 || (sid & 3) != 0) return NULL;
    for (struct flow *f = *sid_bucket(sid); f; f = f->hn_sid)
        if (f->sid == sid) return f;
    return NULL;
}

static void auth_data(const uint8_t *d, size_t n) {
    if (E.an + n > sizeof E.abuf) n = sizeof E.abuf - E.an;
    memcpy(E.abuf + E.an, d, n);
    E.an += n;
    struct hy2_auth_resp r;
    char why[160];
    int rc = auth_check(E.abuf, E.an, &r, why, sizeof why);
    if (rc == 0) return;
    if (rc < 0) {
        E.dead = 1;
        E.dead_reason = QC_CLOSE_ERROR;
        snprintf(E.dead_why, sizeof E.dead_why, "%s", why);
        qc_close(E.qc, 0x101);
        return;
    }
    E.state = S_UP;
    E.up_at_ms = now_ms();
    E.bg_ms = 0;
    uint64_t eff = apply_cc(E.qc, E.node, &r);
    pthread_mutex_lock(&E.mu);
    E.st.up = 1;
    E.st.udp_ok = r.udp;
    E.st.brutal = eff != 0;
    E.st.brutal_bps = eff;
    E.st.hs_ms = (uint32_t)(now_ms() - E.hs_start_ms);
    E.err[0] = '\0';
    pthread_mutex_unlock(&E.mu);
    fprintf(stderr, LOG_I2 "hysteria2: узел %s принял авторизацию за %u мс (%s%s%s%s)\n",
            E.node->name, (unsigned)E.st.hs_ms, eff ? "Brutal" : "BBR",
            r.udp ? ", UDP" : ", без UDP", E.node->obfs == 2 ? ", Gecko" : E.node->obfs ? ", Salamander" : "",
            E.node->hop_n ? ", прыжки по портам" : "");
}

static void on_stream_data(void *u, int64_t sid, const uint8_t *d, size_t n, int fin) {
    (void)u;
    if (E.state == S_AUTH && sid == E.auth_sid) {
        qc_stream_consumed(E.qc, sid, n);
        auth_data(d, n);
        return;
    }
    struct flow *f = flow_by_sid(sid);
    if (!f) { qc_stream_consumed(E.qc, sid, n); return; }
    if (f->state == FL_RESP) {
        if (!f->hbuf) f->hbuf = malloc(4300);
        if (!f->hbuf) { qc_stream_consumed(E.qc, sid, n); flow_local_gone(f); return; }
        /* Ответ короче hbuf (сообщение и набивка ограничены при разборе), поэтому не влезшее — уже
         * негодный ответ. Копится вся порция: разбор скажет, где ответ кончился. */
        size_t before = f->hn;
        int bad = n > 4300 - f->hn;
        struct hy2_tcp_resp resp;
        int used = -1;
        if (!bad) {
            memcpy(f->hbuf + f->hn, d, n);
            f->hn += n;
            used = hy2_tcp_response(f->hbuf, f->hn, &resp);
        }
        if (used == 0) { qc_stream_consumed(E.qc, sid, n); return; }    /* ответ пришёл не весь */
        struct req *rq = f->req;
        if (used < 0 || !resp.ok) {
            qc_stream_consumed(E.qc, sid, n);
            const char *m = used < 0 ? "негодный ответ на запрос потока" : resp.msg;
            set_err("%s", m);
            f->req = NULL;
            qc_stream_reset(E.qc, sid, 0);
            flow_free(f, 0, NULL);
            if (rq) req_finish(rq, HY2E_DENIED, m);
            return;
        }
        /* Окно возвращаем за сам ответ; данные потока, пришедшие с ним, вернёт flow_down по мере
         * записи клиенту. */
        size_t resp_here = (size_t)used - before;
        qc_stream_consumed(E.qc, sid, resp_here);
        free(f->hbuf);
        f->hbuf = NULL;
        f->hn = 0;
        flow_ready(f);
        f = flow_by_sid(sid);           /* flow_ready мог закрыть отменённый поток */
        if (!f) { qc_stream_consumed(E.qc, sid, n - resp_here); return; }
        if (n > resp_here) flow_down(f, d + resp_here, n - resp_here);
        f = flow_by_sid(sid);
        if (f && fin) { f->rx_fin = 1; flow_maybe_shut(f); }
        return;
    }
    if (n) flow_down(f, d, n);
    f = flow_by_sid(sid);
    if (f && fin) { f->rx_fin = 1; flow_maybe_shut(f); }
}

static void on_stream_close(void *u, int64_t sid, uint64_t err) {
    (void)u; (void)err;
    struct flow *f = flow_by_sid(sid);
    if (!f) return;
    if (f->state == FL_RESP) {
        struct req *rq = f->req;
        f->req = NULL;
        flow_free(f, 0, NULL);
        if (rq) req_finish(rq, HY2E_DENIED, "сервер закрыл поток, не ответив");
        return;
    }
    if (f->pend_n) { f->closing = 1; f->rx_fin = 1; return; }   /* сперва дошлём клиенту */
    f->rx_fin = 1;
    flow_maybe_shut(f);
    /* Поток закрыт с обеих сторон: клиенту остался EOF, который он уже получил. */
    flow_free(f, 0, NULL);
}

static void on_datagram(void *u, const uint8_t *d, size_t n) {
    (void)u;
    struct hy2_udp_msg m;
    if (hy2_udp_parse(d, n, &m) != 0) return;
    struct flow *f = usid_find(m.sid);
    if (!f || f->state != FL_OPEN) return;
    if (m.nfrag == 1) { (void)local_put(f, m.data, m.n); return; }
    if (m.nfrag > RFRAG_MAX || m.n > RSLOT) return;
    if (f->rn != m.nfrag || f->rpkt != m.pkt || !f->rbuf) {
        if (!f->rbuf) f->rbuf = malloc((size_t)RFRAG_MAX * RSLOT);
        if (!f->rbuf) return;
        f->rn = m.nfrag;
        f->rpkt = m.pkt;
        f->rgot = 0;
        memset(f->rseen, 0, sizeof f->rseen);
    }
    if (f->rseen[m.frag]) return;
    memcpy(f->rbuf + (size_t)m.frag * RSLOT, m.data, m.n);
    f->rlen[m.frag] = (uint16_t)m.n;
    f->rseen[m.frag] = 1;
    if (++f->rgot < f->rn) return;
    /* Собрано: кусочки подряд в один буфер (слоты фиксированные, длины разные). */
    size_t tot = 0;
    for (unsigned i = 0; i < f->rn; i++) {
        memmove(f->rbuf + tot, f->rbuf + (size_t)i * RSLOT, f->rlen[i]);
        tot += f->rlen[i];
    }
    f->rn = 0;
    if (tot <= RSLOT * 3) (void)local_put(f, f->rbuf, tot);
    else if (tot <= 65000) (void)local_put(f, f->rbuf, tot);
}

static void on_closed(void *u, int reason, const char *why) {
    (void)u;
    E.dead = 1;
    if (!E.dead_why[0]) {
        E.dead_reason = reason;
        snprintf(E.dead_why, sizeof E.dead_why, "%s", why && *why ? why : "соединение закрыто");
    }
}

static const struct qc_ops G_OPS = {
    .on_handshake = on_handshake,
    .on_stream_data = on_stream_data,
    .on_stream_close = on_stream_close,
    .on_datagram = on_datagram,
    .on_closed = on_closed,
};

/* ---- жизнь соединения ------------------------------------------------------------------------- */

/* Следующая попытка поднять соединение без запроса: сразу после обрыва — через секунду, после
 * отказа подъёма — с удвоенной паузой, до BG_MAX_MS. */
static void bg_schedule(int failed) {
    if (!failed) E.bg_ms = RETRY_MS;
    else E.bg_ms = E.bg_ms ? (E.bg_ms * 2 > BG_MAX_MS ? BG_MAX_MS : E.bg_ms * 2) : RETRY_MS;
    E.bg_try_ms = now_ms() + E.bg_ms;
    E.want_up = 1;
}

static int connect_now(void) {
    char ip[64];
    if (cached_ip(ip, sizeof ip) != 0) {
        set_err("адрес узла %s не разрешился", E.node->host);
        E.next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(1);
        return -1;
    }
    struct qc_cfg c;
    E.ob = calloc(1, sizeof *E.ob);
    if (!E.ob) { set_err("нет памяти"); E.next_try_ms = now_ms() + RETRY_MS; bg_schedule(1); return -1; }
    make_cfg(E.node, ip, &c, E.ob, E.mark, E.mark_req);
    E.dead = 0;
    E.dead_why[0] = '\0';
    E.hs_start_ms = now_ms();
    int rc = qc_open(&c, &G_OPS, NULL, &E.qc);
    if (rc != 0) {
        set_err("QUIC не открылся (%d)", rc);
        E.next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(1);
        E.qc = NULL;
        hy2_gecko_free(&E.ob->gk);
        free(E.ob);
        E.ob = NULL;
        return -1;
    }
    /* Сокет QUIC — в общий epoll. Регистрируется при каждом подъёме: закрытие дескриптора убрало
     * прежнюю запись, а номер нового мог совпасть со старым. */
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &E.epfd };
    if (epoll_ctl(E.epfd, EPOLL_CTL_ADD, qc_fd(E.qc), &ev) != 0) {
        qc_free(E.qc);
        E.qc = NULL;
        hy2_gecko_free(&E.ob->gk);
        free(E.ob);
        E.ob = NULL;
        set_err("сокет QUIC не встал в epoll");
        E.next_try_ms = now_ms() + RETRY_MS;
        bg_schedule(1);
        return -1;
    }
    E.state = S_HS;
    E.state_at_ms = now_ms();
    return 0;
}

static void queue_fail_all(int rc, const char *msg) {
    pthread_mutex_lock(&E.mu);
    struct req *r = E.qh;
    E.qh = E.qt = NULL;
    pthread_mutex_unlock(&E.mu);
    while (r) {
        struct req *nx = r->next;
        close(r->efd);
        req_finish(r, rc, msg);
        r = nx;
    }
}

static void process_queue(uint64_t now) {
    /* Соединение закрыто в этом же проходе (срок авторизации в expire, отказ в колбэке), а разбор —
     * в следующем: открыть на нём поток значило бы получить отказ QUIC и ответить запросу «нет
     * свободных потоков» (HY2E_BUSY), хотя потоки ни при чём. Запросы ждут разбора. */
    if (E.dead) return;
    for (;;) {
        pthread_mutex_lock(&E.mu);
        struct req *r = E.qh;
        int have = r != NULL;
        pthread_mutex_unlock(&E.mu);
        if (!have) return;
        if (E.state == S_UP) {
            pthread_mutex_lock(&E.mu);
            E.qh = r->next;
            if (!E.qh) E.qt = NULL;
            pthread_mutex_unlock(&E.mu);
            start_flow(r);
            continue;
        }
        if (E.state == S_IDLE) {
            if (now < E.next_try_ms) {
                char e[160];
                pthread_mutex_lock(&E.mu);
                snprintf(e, sizeof e, "%s", E.err);
                pthread_mutex_unlock(&E.mu);
                queue_fail_all(HY2E_DOWN, e[0] ? e : "узел недоступен");
                return;
            }
            if (connect_now() != 0) {
                char e[160];
                pthread_mutex_lock(&E.mu);
                snprintf(e, sizeof e, "%s", E.err);
                pthread_mutex_unlock(&E.mu);
                queue_fail_all(HY2E_DOWN, e);
                return;
            }
        }
        return;         /* HS/AUTH: запросы ждут в очереди */
    }
}

static void expire(uint64_t now) {
    /* Запросы в очереди с истёкшим сроком. */
    pthread_mutex_lock(&E.mu);
    struct req **pp = &E.qh, *last = NULL;
    struct req *dead = NULL;
    while (*pp) {
        struct req *r = *pp;
        if (r->deadline_ms <= now || r->cancel) {
            *pp = r->next;
            r->next = dead;
            dead = r;
        } else {
            last = r;
            pp = &r->next;
        }
    }
    E.qt = last;
    pthread_mutex_unlock(&E.mu);
    while (dead) {
        struct req *nx = dead->next;
        close(dead->efd);
        req_finish(dead, HY2E_TIMEOUT, NULL);
        dead = nx;
    }
    for (unsigned i = 0; i < E.nfl; ) {
        struct flow *f = E.fl[i];
        if (f->state == FL_RESP && now - f->t0_ms > REQ_S * 1000u) {
            struct req *rq = f->req;
            f->req = NULL;
            if (E.qc) qc_stream_reset(E.qc, f->sid, 0);
            flow_free(f, 0, NULL);
            if (rq) req_finish(rq, HY2E_TIMEOUT, NULL);
            continue;
        }
        i++;
    }
    if (E.state == S_AUTH && now - E.state_at_ms > AUTH_S * 1000u && E.qc && !E.dead) {
        E.dead = 1;
        E.dead_reason = QC_CLOSE_HANDSHAKE;
        snprintf(E.dead_why, sizeof E.dead_why, "узел не ответил на авторизацию за %d с", AUTH_S);
        qc_close(E.qc, 0x101);
    }
}

static void eng_flush_blocked(void) {
    for (unsigned i = 0; i < E.nfl; i++) {
        struct flow *f = E.fl[i];
        if (!f->udp && f->state == FL_OPEN && (f->up_n || (f->up_eof && !f->fin_sent))) {
            flow_up_flush(f);
            if (!E.qc) return;
            /* flow_up_flush мог освободить поток: таблица сдвинулась. */
            if (i < E.nfl && E.fl[i] != f) i--;
        }
    }
}

static void *engine(void *arg) {
    (void)arg;
    struct epoll_event evs[64];
    for (;;) {
        int tmo = -1;
        if (E.qc) {
            int t = qc_timeout_ms(E.qc);
            tmo = t < 0 ? 1000 : (t > 1000 ? 1000 : t);
        } else if (E.want_up) {
            uint64_t t = now_ms();
            tmo = E.bg_try_ms <= t ? 0 : (E.bg_try_ms - t > 1000 ? 1000 : (int)(E.bg_try_ms - t));
        }
        pthread_mutex_lock(&E.mu);
        int queued = E.qh != NULL;
        pthread_mutex_unlock(&E.mu);
        if (queued && (tmo < 0 || tmo > 200)) tmo = 200;
        int n = epoll_wait(E.epfd, evs, 64, tmo);
        unsigned gen0 = E.gen;
        if (E.want_up && E.state == S_IDLE && !E.dead && now_ms() >= E.bg_try_ms) {
            E.want_up = 0;
            (void)connect_now();
        }
        for (int i = 0; i < n; i++) {
            void *p = evs[i].data.ptr;
            if (p == &E.epfd) {                         /* сокет QUIC */
                if (E.qc) __atomic_store_n(&E.rx_at_ms, now_ms(), __ATOMIC_RELAXED);
                if (E.qc && qc_on_readable(E.qc) == QC_ECLOSED) E.dead = E.dead ? E.dead : 1;
            } else if (p == &E.wake) {
                uint64_t v;
                ssize_t rd = read(E.wake, &v, sizeof v);
                (void)rd;
            } else {
                struct flow *f = p;
                /* Поток мог закрыться событием выше в этой же пачке: указатель тогда чужой. Сверка
                 * со списком нужна, только если что-то закрывалось (счётчик). */
                int live = 1;
                if (E.gen != gen0) {
                    live = 0;
                    for (unsigned k = 0; k < E.nfl; k++) if (E.fl[k] == f) { live = 1; break; }
                }
                if (live && E.qc) flow_event(f, evs[i].events);
            }
        }
        /* Окна, которые продлили события потоков выше (qc_stream_consumed из flow_drain и flow_down):
         * сервер, остановленный окном, о них иначе не узнает до следующего события QUIC. */
        if (E.qc && !E.dead) qc_flush_credit(E.qc);
        if (E.qc && qc_timeout_ms(E.qc) == 0 && qc_on_timer(E.qc) == QC_ECLOSED) E.dead = E.dead ? E.dead : 1;
        if (E.qc && !E.dead) eng_flush_blocked();
        if (E.dead) {
            char why[160];
            snprintf(why, sizeof why, "%s", E.dead_why[0] ? E.dead_why : "соединение закрыто");
            int wasup = E.state == S_UP;
            int reason = E.dead_reason;
            if (E.state == S_UP && reason != QC_CLOSE_LOCAL)
                fprintf(stderr, LOG_W2 "hysteria2: соединение с узлом оборвалось: %s\n", why);
            else if (E.state != S_UP && E.state != S_IDLE)
                fprintf(stderr, LOG_W2 "hysteria2: узел %s не принял соединение: %s\n", E.node->name, why);
            teardown(why);
            /* Пауза перед повтором — только после провала подъёма или обрыва; своё закрытие
             * поднятого соединения повтора не ждёт. Без запроса соединение поднимается снова само
             * (bg_schedule): туннель держит связь с узлом всё время, а не по первому потоку. */
            E.next_try_ms = (wasup && reason == QC_CLOSE_LOCAL) ? 0 : now_ms() + RETRY_MS;
            bg_schedule(!wasup);
            queue_fail_all(HY2E_DOWN, why);
            E.dead_why[0] = '\0';
            E.dead_reason = 0;
        }
        expire(now_ms());
        process_queue(now_ms());
        /* И закрытые потоки возвращают окно (flow_free): без этого окно соединения, занятое
         * очередью ушедшего клиента, оставалось бы закрытым до следующего события QUIC. */
        if (E.qc && !E.dead) qc_flush_credit(E.qc);
        pthread_mutex_lock(&E.mu);
        E.st.flows = E.nfl;
        if (E.qc && E.state == S_UP) {
            struct qc_stats qs;
            qc_stats_get(E.qc, &qs);
            E.st.rtt_us = qs.rtt_us;
            /* Датаграмма, не влезшая в пакет, выбрасывается (как потеря в сети) — но не молча:
             * строка в журнал не чаще раза в десять секунд, с числом выброшенных. */
            static uint64_t dg_seen, dg_log_ms;
            if (qs.dg_dropped > dg_seen && now_ms() - dg_log_ms >= 10000) {
                fprintf(stderr, LOG_W2 "hysteria2: выброшено датаграмм UDP, не влезших в пакет: %llu\n",
                        (unsigned long long)qs.dg_dropped);
                dg_seen = qs.dg_dropped;
                dg_log_ms = now_ms();
            }
        }
        pthread_mutex_unlock(&E.mu);
    }
    return NULL;
}

int hy2c_start(const struct hy2_node *node) {
    if (E.started) return 0;
    E.node = node;
    E.epfd = epoll_create1(EPOLL_CLOEXEC);
    E.wake = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (E.epfd < 0 || E.wake < 0) return -1;
    struct epoll_event ev = { .events = EPOLLIN, .data.ptr = &E.wake };
    if (epoll_ctl(E.epfd, EPOLL_CTL_ADD, E.wake, &ev) != 0) return -1;
    pthread_attr_t a;
    pthread_attr_init(&a);
    /* Не меньше минимума потока: в него входит статическая TLS всех загруженных библиотек, а у
     * libsteer она немалая (thread-local буферы стека туннеля) — 256 КБ давали EINVAL. Стек
     * потока — виртуальная память, занятой становится по мере использования. */
    pthread_attr_setstacksize(&a, 1024 * 1024);
    int err = pthread_create(&E.th, &a, engine, NULL);
    pthread_attr_destroy(&a);
    if (err) {
        fprintf(stderr, LOG_W2 "hysteria2: поток соединения не создался (%s)\n", strerror(err));
        return -1;
    }
    pthread_detach(E.th);
    E.started = 1;
    /* Соединение — сразу: первый поток клиента не платит за рукопожатие. */
    E.want_up = 1;
    uint64_t one = 1;
    ssize_t w = write(E.wake, &one, sizeof one);
    (void)w;
    return 0;
}

int hy2c_open(int udp, const char *host, uint16_t port, int timeout_s) {
    if (!E.started) return HY2E_SYS;
    char ip[64];
    if (cached_ip(ip, sizeof ip) != 0) {
        set_err("адрес узла %s не разрешился", E.node->host);
        return HY2E_DOWN;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, sv) != 0) return HY2E_SYS;
    /* Очередь пары — в каждую сторону свой SO_SNDBUF отправителя (приёмник у сокета unix ничего не
     * считает). 256 КиБ ядро удваивает под учёт служебного: очередь считает «веса» сообщений (данные
     * плюс служебное — у сообщения в 1460 байт вес около 2,3 КиБ). Измерено на 6.8: полной очередь
     * бывает при 525 КиБ весов (228 сообщений по 1460 байт — около 333 КБ полезной нагрузки), а
     * готовность записи пропадает на четверти буфера, при 131 КиБ (57 сообщений, 83 КБ).
     *
     * ВНИЗ (мультиплексор → стек) очередь — всё, что мы готовы держать у стека помимо самих
     * окон клиента; остальное ждёт в очереди потока (pblk) под окном QUIC.
     *
     * ВВЕРХ (стек → мультиплексор) выше нижней отметки должно оставаться места на окно клиента: стек
     * не подтверждает данные, пока запись не готова (DC_ACK_PACED, dialer.h), и клиент не успевает
     * прислать больше окна, а окно стек объявляет не больше HY2_CLIENT_WND (hy2_dialer.rcv_wnd_max):
     * потолок самого стека — мегабайты (rcv_window_init), и очередь пары их не вместит. 128 КиБ
     * полезной нагрузки — около 200 КиБ весов поверх 131 КиБ нижней отметки, при полной очереди в
     * 525 КиБ; связь чисел проверяет сборка (hy2conn.h). Меньший буфер вернул бы переполнение, а с
     * ним — потерю окна и вставшую выгрузку. Размер не должен зависеть от net.core.wmem_max:
     * SNDBUFFORCE (root, а мультиплексор им и работает — SO_MARK у QUIC тоже требует CAP_NET_ADMIN)
     * обходит этот предел; без права остаётся обычный SO_SNDBUF под потолком системы. */
    int sz = HY2_PAIR_SNDBUF;
    for (int i = 0; i < 2; i++) {
        if (setsockopt(sv[i], SOL_SOCKET, SO_SNDBUFFORCE, &sz, sizeof sz) != 0)
            setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &sz, sizeof sz);
        setsockopt(sv[i], SOL_SOCKET, SO_RCVBUF, &sz, sizeof sz);
    }
    struct req *r = calloc(1, sizeof *r);
    if (!r) { close(sv[0]); close(sv[1]); return HY2E_SYS; }
    pthread_condattr_t ca;
    pthread_condattr_init(&ca);
    pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
    pthread_cond_init(&r->cv, &ca);
    pthread_condattr_destroy(&ca);
    r->udp = udp;
    snprintf(r->host, sizeof r->host, "%s", host);
    r->port = port;
    r->efd = sv[1];
    r->refs = 2;
    uint64_t now = now_ms();
    r->deadline_ms = now + (uint64_t)(timeout_s > 0 ? timeout_s : 10) * 1000;

    pthread_mutex_lock(&E.mu);
    if (E.qt) E.qt->next = r; else E.qh = r;
    E.qt = r;
    pthread_mutex_unlock(&E.mu);
    uint64_t one = 1;
    ssize_t w = write(E.wake, &one, sizeof one);
    (void)w;

    struct timespec ts = { .tv_sec = (time_t)(r->deadline_ms / 1000), .tv_nsec = (long)(r->deadline_ms % 1000) * 1000000L };
    pthread_mutex_lock(&E.mu);
    while (!r->done) {
        if (pthread_cond_timedwait(&r->cv, &E.mu, &ts) != 0) break;
    }
    int rc;
    if (!r->done) { r->cancel = 1; rc = HY2E_TIMEOUT; }
    else rc = r->rc;
    char msg[128];
    snprintf(msg, sizeof msg, "%s", r->msg);
    int last = --r->refs == 0;
    if (last) { pthread_cond_destroy(&r->cv); free(r); }
    pthread_mutex_unlock(&E.mu);
    if (rc != 0) {
        if (msg[0]) set_err("%s", msg);
        close(sv[0]);
        return rc;
    }
    return sv[0];
}

int hy2c_alive(void) {
    if (!E.started) return 0;
    /* Окно — два PING с запасом: на каждый узел отвечает ACK, так что живое соединение без
     * трафика получает пакет не реже срока PING (make_cfg; после рукопожатия он бывает и короче). */
    unsigned ka = g_idle_ms / 3 < 10000 ? g_idle_ms / 3 : 10000;
    uint64_t within_ms = 2ull * ka + 1000;
    pthread_mutex_lock(&E.mu);
    int up = E.st.up;
    pthread_mutex_unlock(&E.mu);
    uint64_t rx = __atomic_load_n(&E.rx_at_ms, __ATOMIC_RELAXED);
    return up && rx && now_ms() - rx <= within_ms;
}

void hy2c_status(struct hy2c_status *st) {
    pthread_mutex_lock(&E.mu);
    *st = E.st;
    snprintf(st->err, sizeof st->err, "%s", E.err);
    pthread_mutex_unlock(&E.mu);
}
