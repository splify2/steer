/* Соединение hysteria2: QUIC к узлу в цикле рабочего потока стека, потоки клиента — поверх него.
 * Устройство и доводы — hy2conn.c и docs/hysteria2.md. */
#ifndef STEER_HY2CONN_H
#define STEER_HY2CONN_H
#include <stddef.h>
#include <stdint.h>

#include "hy2.h"

/* Исходы открытия потока (hy2c_connect; отрицательные). */
#define HY2E_TIMEOUT (-1)       /* не уложились в срок */
#define HY2E_DOWN    (-2)       /* соединение с узлом не поднялось или оборвалось (причина — hy2c_strerror) */
#define HY2E_DENIED  (-3)       /* сервер отказал в этом потоке (адрес недоступен для него) */
#define HY2E_NOUDP   (-4)       /* сервер не принимает UDP */
#define HY2E_BUSY    (-5)       /* нет свободных потоков или слотов */
#define HY2E_SYS     (-6)       /* память, соединения нет вовсе */

struct hq;                      /* соединение рабочего потока (hy2conn.c) */
struct hy2_udpx;                /* то, что нужно только потоку UDP */
struct pblk;
struct udg;

/* Сессия дайлера — один поток клиента: TCP-поток QUIC или поток датаграмм. Лежит в таблице потока стека
 * (dialer_ops.sess_size), по одной на соединение клиента, и никакого дескриптора у неё нет: нагрузка
 * ложится в очереди ниже прямо из колбэков QUIC, а стек забирает её вызовом read.
 *
 * q — первым полем: clear стека трогает только начало сессии, и «нет связи» — это q == NULL. */
struct hy2_flow {
    struct hq *q;
    uint8_t state;              /* FL_* (hy2conn.c) */
    uint8_t udp;
    uint8_t opening;            /* открытие не закончено: считается в hq.nopen и ждёт срока */
    uint8_t rx_fin;             /* сервер закончил передачу: после очереди — конец потока */
    uint8_t sclosed;            /* поток QUIC закрыт целиком: ему не слать и не сбрасывать */
    uint8_t gone;               /* соединение QUIC кончилось: связь оборвана, потока больше нет */
    uint8_t aborted;            /* конец — обрыв, а не закрытие (клиенту RST, а не FIN) */
    uint8_t act;                /* в списке «отправка идёт» (hq.act): ждёт подтверждений узла */
    uint16_t dport;
    uint32_t dst;               /* IPv4 назначения, сетевой порядок */
    int64_t sid;                /* поток QUIC (TCP) */
    uint32_t usid;              /* идентификатор сессии UDP */
    uint64_t deadline_ms;       /* срок открытия */
    struct hy2_flow *nx, *pv;   /* все потоки рабочего */
    struct hy2_flow *hn;        /* цепочка корзины по sid (TCP) или по usid (UDP) */
    struct hy2_flow *anx, *apv; /* список «отправка идёт» */
    /* Ответ сервера на запрос TCP копится здесь, пока не разобран целиком. */
    uint8_t *hbuf;
    uint16_t hn_;
    /* Вверх, к серверу: остаток, который qc_stream_send не принял. Он уже принят у клиента (подтверждён
     * окном, которое мы же ему объявили), так что копится не больше окна. */
    uint8_t *up;
    size_t up_n;
    /* Вниз, к клиенту: очередь блоков TCP или датаграмм UDP, голова — самое старое. pend_n — сколько байт
     * TCP в очереди. spent* — последний отданный стеку блок: стек держит указатель на его данные до
     * следующего read, поэтому освобождается он там же. */
    struct pblk *ph, *pt, *spent_b;
    size_t pend_n;
    struct udg *uh, *ut, *spent_u;
    struct hy2_udpx *ux;
};

/* Метка сокета к узлу: до hy2c_init. mark == 0 — без метки. */
void hy2c_set_mark(uint32_t mark, int required);
/* Срок простоя QUIC — ключ `silence` выхода, секунды; 0 — прежний (30 с). До hy2c_init. */
void hy2c_set_idle(int silence_s);

/* Запомнить узел (указатель живёт до конца процесса) и разрешить его адрес. Само соединение с узлом
 * поднимает каждый рабочий поток стека, когда встаёт (hy2c_loop_start), и держит, с потоками и без. 0 или -1. */
int hy2c_init(const struct hy2_node *node);
/* Обновить адрес узла-имени, если разрешённый устарел. Зовёт поток состояния модуля: getaddrinfo блокирует, а
 * в цикле рабочего блокировать нечем. Адрес-литерал не трогает. */
void hy2c_refresh_addr(void);

/* Цикл рабочего (hy2dial.c ставит их в dialer_ops): состояние встаёт со старта потока и уходит с ним. */
void hy2c_loop_start(int worker, int nworkers);
void hy2c_loop_poll(int ready);
int  hy2c_loop_wait(void);
void hy2c_loop_stop(void);

/* Сессия: открыть поток к назначению (dst, dport, udp — в f, их ставит flow_open). Не блокирует; исход —
 * stack_sess_ready, из этого же вызова или позже. Возвращает 0. */
int  hy2c_connect(struct hy2_flow *f, int timeout_s);
/* Закрыть: сбросить поток, вернуть окно за непрочитанное, освободить очереди. Пустую сессию не трогает. */
void hy2c_close(struct hy2_flow *f);
/* Байты клиента узлу (SEND_*), у UDP — одна датаграмма. */
int  hy2c_send(struct hy2_flow *f, const unsigned char *d, size_t n);
/* Следующий кусок очереди без копии: не больше cap байт TCP или одна датаграмма; got == 0 — пока пусто. */
int  hy2c_read(struct hy2_flow *f, size_t cap, const unsigned char **data, size_t *got);
int  hy2c_has_data(const struct hy2_flow *f);
/* Сколько байт клиента примет send сейчас (место в буфере потока QUIC); -1 — предела нет. */
long hy2c_room(const struct hy2_flow *f);
int  hy2c_fd(const struct hy2_flow *f);
int  hy2c_aborted(const struct hy2_flow *f);
/* Текст последнего отказа для кода rc (копия в локальном буфере потока). */
const char *hy2c_strerror(int rc);

struct hy2c_status {
    int up;                     /* QUIC поднят и авторизован */
    int udp_ok;                 /* сервер принимает UDP */
    int brutal;                 /* работает Brutal (иначе BBR) */
    uint64_t brutal_bps;
    uint32_t hs_ms;             /* рукопожатие + авторизация последнего подъёма, мс */
    uint64_t rtt_us;
    unsigned flows;
    char err[160];              /* причина последнего отказа соединения, пока оно не поднято */
};
/* Сводка по рабочим: поднят — если поднято соединение хотя бы одного (у каждого свой, и потоки клиента
 * разложены по ним хэшем), остальное — у первого поднятого, потоков — сумма. */
void hy2c_status(struct hy2c_status *st);
/* Соединение поднято, и от узла недавно (за два срока PING) был пакет: узел жив без отдельной
 * проверки (слежка за узлом, hy2main.c). 1 или 0. */
int hy2c_alive(void);

/* Разовая проверка узла: рукопожатие QUIC и авторизация, без потоков. 0 — узел принял; иначе
 * причина в why (для журнала и статуса). *hs_ms — сколько ушло на рукопожатие и авторизацию. */
int hy2_probe(const struct hy2_node *n, int timeout_s, char *why, size_t why_n, int *hs_ms);

/* Сообщение слежке за узлом об исходе открытия потока (hy2main.c). */
void hy2_watch_seen(int rc);

#endif
