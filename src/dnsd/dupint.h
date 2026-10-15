#ifndef STEER_DNSD_DUPINT_H
#define STEER_DNSD_DUPINT_H

/* Общее у dup.c (цикл событий, очередь, транспорты) и dupdial.c (поток установки соединения).
 * Снаружи резолвера не видно: proxy.c знает только dup.h. */

#include <sys/socket.h>
#include "dup.h"

/* Метка объекта, чей адрес лежит в epoll (data.ptr). Первое поле — число: proxy.c держит в тех же
 * data.ptr указатели на int и на свои структуры, и dup_event узнаёт своё по числу, не разыменовывая
 * ничего сверх четырёх байт. */
#define DTAG_MAGIC 0x44555031u
enum { DT_UDP = 1, DT_CONN, DT_DIAL };
struct dtag { uint32_t magic; int kind; void *obj; };

#define DIAL_MAXADDR 6

/* Одно соединение с сервером, которое поток устанавливает целиком: имя (bootstrap) -> адрес ->
 * connect -> рукопожатие TLS. Хозяин структуры — цикл резолвера; поток берёт её, пока не запишет в
 * wfd байт «готово», и после этого её не касается. */
struct dial {
    struct dtag tag;                    /* DT_DIAL, для epoll на rfd */
    int rfd, wfd;                       /* концы socketpair: цикл читает rfd, поток пишет wfd */
    void *up;                           /* владелец (struct dup *) и его поколение — для отмены */
    unsigned up_gen;
    int conn;                           /* номер соединения владельца */
    volatile int cancel;                /* владелец ушёл: результат выбросить */

    /* Вход. */
    struct spec_dns_up u;
    char (*ips_own)[46];                /* личные копии u.ips и u.boot (dial_free отдаёт) */
    char (*boot_own)[46];
    unsigned mark;
    int doh;                            /* DoH: сервер обязан выбрать h2 или http/1.1 */
    int quic;                           /* DoQ: поток только находит адреса сервера (список — в
                                         * addr), connect и рукопожатие ведёт цикл через dupq_open */
    struct sockaddr_storage cached[DIAL_MAXADDR];
    int cached_n, cached_fresh;         /* прежде найденные адреса и не истёк ли их срок */
    char ca[256];                       /* файл корней вместо системного ("" — системный) */
    int timeout_ms;                     /* на всё: bootstrap, connect, рукопожатие */

    /* Выход. */
    int h2;                             /* DoH: сервер выбрал h2 */
    int rc;                             /* 0 — соединение готово */
    char err[192];
    int fd;                             /* сокет, уже неблокирующий */
    void *tls;                          /* struct tls13 *, владение переходит циклу */
    struct sockaddr_storage res[DIAL_MAXADDR];  /* заново найденные адреса (bootstrap) */
    int res_n;
    long res_ttl;                       /* секунд */
    int peer_i;                         /* к какому адресу подключились: индекс в res/cached */
    int peer_from_res;
    struct sockaddr_storage addr[DIAL_MAXADDR];  /* DoQ: все адреса сервера по порядку выдачи */
    int addr_n;
};

/* ClientHello в две записи TLS (`fragment: true`, DoT и DoH). Hello — уже готовая запись (5 байт
 * заголовка и сообщение рукопожатия, как её строит reality_build_hello_carry); хеш рукопожатия
 * считается по сообщению, а не по записям, поэтому разрез сервер не замечает (RFC 8446, 5.1: сообщение
 * рукопожатия вправе занимать несколько записей).
 *
 * dup_hello_split — смещение разреза в байтах записи (с заголовком): случайная точка внутри имени SNI
 * (rnd выбирает её), а у Hello без SNI — на 30-80 байтах сообщения; 0 — разрезать нечем (запись
 * короткая или не Hello). dup_hello_send — запись одной отправкой, при frag — двумя с паузой около
 * 2 мс между ними (сокет с TCP_NODELAY): DPI, ищущий SNI в одной записи или одном сегменте, его не
 * находит. Только первая запись соединения; дальше сокетом владеет рукопожатие. 0 — ушло. */
size_t dup_hello_split(const unsigned char *h, size_t n, unsigned rnd);
int dup_hello_send(int fd, const unsigned char *h, size_t n, int frag);

/* Запустить поток. 0 — запущен и вернёт байт в wfd; -1 — не удалось (rc и err заполнены). */
int dial_launch(struct dial *d);

/* Разрешить имя серверами bootstrap (UDP, метка mark). Адреса — в out, срок в *ttl. Число адресов
 * или -1. Отдельно и без TLS: его проверяет стенд без сети. */
int dup_bootstrap(const char *host, const char (*boot)[46], size_t boot_n, unsigned mark,
                  int timeout_ms, struct sockaddr_storage *out, size_t max, long *ttl);

/* ---- объекты цикла (dup.c) ------------------------------------------------------------------
 * Здесь, а не в dup.c, ради стенда tests/dupconnmatch.c: он линкуется с dup.c и собирает
 * соединение в таблице апстрима сам (подменив слой TLS), чтобы проверить разбор и сроки без сети. */

#define DUP_QMAX 1024
#define DUP_DIAL_MS 6000

enum { CS_FREE = 0, CS_DIAL, CS_TCPCONN, CS_READY, CS_QHS };   /* CS_QHS — DoQ, рукопожатие идёт */

struct dup;
struct dconn {
    struct dtag tag;
    struct dup *up;
    /* DoQ. qc — соединение QUIC (fd тогда -1: сокетом владеет обёртка, а в epoll он лежит под qfd).
     * Обратные вызовы обёртки НЕ делают ничего, кроме отметок ниже: ответить клиенту, поставить в
     * поток следующий вопрос или закрыть соединение изнутри вызова из ngtcp2 нельзя (ngtcp2 не
     * терпит повторного входа), поэтому все последствия разбирает quic_after после возврата из
     * qc_on_readable / qc_on_timer. */
    struct dupq *qc;
    int qfd;
    long qrx_ms;                /* когда от сервера в последний раз пришёл хоть один пакет */
    int qhs;                    /* on_handshake сработал */
    int qerej;                  /* on_early_rejected сработал: вопросы, ушедшие до рукопожатия, потеряны */
    int qclosed;                /* on_closed сработал: qc больше не пригоден, только qc_free */
    int qreason;                /* QC_CLOSE_* */
    char qwhy[64];
    uint64_t qerr;              /* код приложения при нашем закрытии (DOQ_*) */
    int fd, st;
    struct tls13 *tls;
    struct dial *dial;
    uint8_t *rb;
    size_t rn, rcap;
    uint8_t *wb;
    size_t wn, woff;
    /* DoH по HTTP/2 (h2 — сервер выбрал h2 в ALPN). Вопрос — поток, номер потока в dreq.sid, число
     * открытых потоков — busy. Окна отправки ведутся только по данным: заголовки в окно не входят
     * (RFC 9113, 6.9), а тело вопроса — до килобайта. */
    int h2;
    int h2_go;                  /* GOAWAY получен (или номера потоков кончились): новых вопросов нет,
                                 * соединение закрывается, когда откроется последний поток */
    uint32_t h2_next;           /* номер следующего потока (нечётный) */
    uint32_t h2_maxs;           /* SETTINGS_MAX_CONCURRENT_STREAMS сервера */
    int64_t h2_win;             /* окно отправки соединения (может уйти в минус по SETTINGS) */
    int64_t h2_iwin;            /* начальное окно потока, объявленное сервером */
    uint8_t *hb;                /* блок заголовков, пришедший кусками (HEADERS без END_HEADERS) */
    size_t hbn;
    uint32_t hb_sid;
    int hb_fin;                 /* у HEADERS был END_STREAM */
    long last_ms;
    int idx;                    /* номер в up->c: адрес соединения не переезжает (метка epoll) */
    int busy;                   /* DoH: номер вопроса плюс один; DoT/TCP: число вопросов на нём */
    int close_after;
    /* Разбор ответа HTTP. */
    int hdr_done, chunked;
    long clen;
    size_t body_off;
};

struct dup {
    struct dtag utag;
    int live;
    unsigned gen;
    struct dup_cfg cfg;
    int ufd;
    struct sockaddr_storage srv;
    int srv_ok;
    /* Соединения — каждое отдельным блоком: адрес dconn — метка epoll, и он не должен переезжать,
     * когда пул растёт. Блоки живут, пока живёт сам dup (они, как и он, не освобождаются). */
    struct dconn **c;
    int c_n, c_cap;
    char (*ips_own)[46];        /* личные копии адресов cfg.u.ips и cfg.u.boot */
    char (*boot_own)[46];
    struct sockaddr_storage ad[DIAL_MAXADDR];
    int ad_n;
    long ad_exp_ms;
    unsigned qpos;              /* DoQ: с какого адреса из ad начинать; неудача рукопожатия сдвигает */
    int dialing;
    long retry_at_ms;
    long backoff_ms;
    char err[192];
    long err_ms, ok_ms;
    unsigned long q_sent, q_ok, q_fail;
    unsigned long q_early, q_early_rej;   /* DoQ: вопросов ушло в 0-RTT; соединений, где сервер его отверг */
    uint16_t next_id;
    int hproto;                 /* DoH: что выбрал сервер при последнем соединении — 0 не знаем, 1
                                 * http/1.1, 2 h2 (от этого зависит, сколько соединений заводить) */
    /* Группа серверов (cfg.grp): личная копия номеров членов (cfg.gm указывает сюда) и пауза
     * каждого члена — по cfg.gm_n (dupgrp.c). */
    unsigned *gm_own;
    struct dpause *gp;
};

struct dreq {
    int used;
    int slot;                   /* номер места (RQ): busy у DoH — это slot плюс один */
    struct dup *up;
    unsigned up_gen;
    int ci;                     /* соединение или -1 — ждёт */
    int tcp;                    /* усечённый ответ по UDP: идти по TCP */
    uint8_t tries;
    uint16_t wid, oid;
    long t0, deadline;
    dup_done_fn cb;
    void *ctx;
    /* DoQ: поток вопроса (-1 — ещё не открыт) и накопленный ответ (rxn байт из rxcap, куча). rxfin —
     * поток закончен (FIN или закрыт), rxbad — закрыт с кодом ошибки. Всё это обнуляется вместе с
     * полями выше при приёме вопроса (memset до q), поэтому rx освобождает req_finish и никто иной. */
    int64_t sid;
    uint8_t *rx;
    size_t rxn, rxcap;
    int rxfin, rxbad;
    int hgot;                   /* DoH/h2: заголовки ответа с кодом 200 пришли */
    uint8_t q[DUP_QMAX];
    uint16_t qn;
};

/* ---- группы серверов (dupgrp.c) ------------------------------------------------------------- */
int grp_ask(struct dup *g, const uint8_t *q, size_t n, dup_done_fn cb, void *ctx);
void grp_tick(long now);
long grp_deadline(void);                /* ближайший срок группы (мс монотонных часов) или -1 */
int grp_busy(void);
void grp_render(FILE *f, const struct dup *g);
const char *dup_state(const struct dup *up);     /* состояние апстрима для dns-log (dup.c) */

extern struct dup **g_dups;             /* текущие апстримы, по номеру настройки */
extern size_t g_dups_n;
extern int g_req_cap;                   /* мест в таблице вопросов */
struct dreq *req_ref(int k);            /* место k, 0 <= k < g_req_cap */

#endif
