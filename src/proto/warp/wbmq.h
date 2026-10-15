/* Туннель MASQUE к Cloudflare WARP (подробности — в wbmq.c). */
#ifndef STEER_WBMQ_H
#define STEER_WBMQ_H

#include <stddef.h>
#include <stdint.h>

#include "wbx509.h"

#define WB_MQ_MTU 1280

struct wb_mq_cfg {
    char dev[32];                       /* устройство TUN — имя члена; пусто у пробы */
    char ep[64];                        /* адрес точки (IPv4 или IPv6 литералом) */
    unsigned port;
    uint32_t mark;                      /* метка сокета: подложка, мимо самого туннеля */
    unsigned char priv[32];             /* ключ клиента P-256 */
    unsigned char spki[WB_SPKI_P256];   /* ключ сервера, выданный при включении MASQUE */
    char v4[48], v6[64];                /* адреса туннеля из регистрации */
};

struct wb_mq;

/* Поток туннеля члена: TUN cfg.dev и соединение к точке cfg.ep:port, с переподключением. 0 — запущен. */
int  wb_mq_start(const struct wb_mq_cfg *c, struct wb_mq **out, char *why, size_t wn);
/* Новая точка: поток переподключается к ней сразу. */
void wb_mq_retarget(struct wb_mq *m, const char *ep, unsigned port);
/* 1 — запрос CONNECT принят и датаграммы ходят; 0 — нет (why — последняя причина). */
int  wb_mq_up(struct wb_mq *m, char *why, size_t wn);
void wb_mq_stop(struct wb_mq *m);

/* Проба точки без TUN: рукопожатие, CONNECT и эхо-запрос к 1.1.1.1 прямо в датаграмме.
 * 0 — ответ пришёл, rtt в *rtt_ms; 1 — CONNECT принят, но эхо не вернулось; -1 — отказ (why). */
int  wb_mq_probe(const struct wb_mq_cfg *c, int timeout_ms, int *rtt_ms, char *why, size_t wn);

#endif
