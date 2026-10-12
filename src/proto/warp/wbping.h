/* Очередь эхо-запросов через туннель (подробности — в wbping.c). */
#ifndef STEER_WBPING_H
#define STEER_WBPING_H

struct wb_ping {
    int sent, got;
    int loss;       /* % */
    int rtt;        /* средняя, мс; -1 — ответов нет */
    int torn;       /* ответы шли и оборвались — так DPI рвёт туннель */
};

/* count запросов на dst (IPv4 строкой) с шагом step_ms, ответы ждутся wait_ms после последнего.
 * Сокет создаётся в текущем пространстве сети. 0 — замер сделан. */
int wb_ping_burst(const char *dst, int count, int step_ms, int wait_ms, struct wb_ping *r);
/* То же через устройство dev (SO_BINDTODEVICE) — проверка туннеля, который несёт трафик. */
int wb_ping_dev(const char *dev, const char *dst, int count, int step_ms, int wait_ms, struct wb_ping *r);

#endif
