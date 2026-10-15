/* Подбор точек WARP (подробности — в wbscan.c). */
#ifndef STEER_WBSCAN_H
#define STEER_WBSCAN_H

#include <stddef.h>
#include "wbreg.h"

struct spec;

/* Класс точки: чем меньше, тем лучше. Негодные (нет рукопожатия, туннель молчит или рвётся) в
 * итог не попадают вовсе. */
enum wb_cls {
    WB_GOOD = 0,        /* всё проходит, страна подходит, колония не занята соседом */
    WB_SAME = 1,        /* то же, но колония уже у другого туннеля группы */
    WB_NOTLS = 2,       /* пинг идёт, HTTPS через туннель — нет */
};

struct wb_pt {
    char ip[16];
    unsigned port;
    int cls;
    int loss, rtt;
    int warp;           /* trace сказал warp=on/plus */
    char colo[4];       /* IATA колонии Cloudflare */
    char cc[3];         /* страна колонии */
    char seen[3];       /* страна, которую видят сайты */
    char city[40];
};

struct wb_scan {
    const struct spec *sp;
    int ns;                         /* пространство подбора (wb_ns_new) */
    const char *over;               /* туннель через этот выход (over группы) или NULL */
    const struct wb_reg *reg;       /* ключ, которым пробуются точки */
    const char *i1;                 /* маска (NULL — без) */
    int obfs;                       /* параметры AmneziaWG */
    const char *dir;                /* каталог временных файлов (состояние, не флеш) */
    const char (*cc)[3];            /* разрешённые страны; cc_n == 0 — любые */
    size_t cc_n;
    const char (*xcc)[3];           /* исключённые страны */
    size_t xcc_n;
    const char (*busy_colo)[4];     /* колонии других туннелей группы */
    size_t busy_colo_n;
    const char (*busy_ip)[16];      /* их адреса */
    size_t busy_ip_n;
    unsigned rot;                   /* сдвиг портов: у каждого туннеля свой первый порт */
    int quick;                      /* короткий проход (смена маски) */
    size_t want;                    /* сколько хороших точек искать, прежде чем остановиться */
    const char *also_ip;            /* точка, стоящая в туннеле: мерить и её (NULL — нет) */
    unsigned also_port;
    /* итог */
    struct wb_pt *out;              /* найденные, по порядку пригодности */
    size_t out_n, out_cap;
    int torn;                       /* сколько точек оборвали трафик (DPI) */
    int rufilt;                     /* сколько отсеяно фильтром стран */
    struct wb_pt also;              /* also_ip той же мерой (also_ok — HTTPS идёт) */
    int also_ok;
    char why[256];
};

/* Подбор. 0 — найдена хотя бы одна точка (s->out[0] — лучшая); -1 — нет, причина в s->why.
 * Ход — строками в stderr (журнал демона). */
int wb_scan_run(struct wb_scan *s);
void wb_scan_free(struct wb_scan *s);

/* Проверка точки, уже стоящей в туннеле: trace через устройство dev основного пространства. 0 —
 * HTTPS идёт; colo/seen/warp — что сказал trace. */
int wb_trace_dev(const char *dev, struct wb_pt *p);

/* Колония — российская (список апстрима ZM) или страна колонии/сайтов RU. */
int wb_colo_is_ru(const char *colo);

#endif
