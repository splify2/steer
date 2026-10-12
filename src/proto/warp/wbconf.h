/* Файл туннеля WARP и маски первого пакета (подробности — в wbconf.c). */
#ifndef STEER_WBCONF_H
#define STEER_WBCONF_H

#include <stddef.h>
#include "wbreg.h"

/* Маски I1 по порядку перебора; 0 — основная. */
#define WB_MASKS 6
/* Маска номер k: текст в buf (собранные заново — DNS, STUN, SIP — каждый раз свои), имя — в *name. */
const char *wb_mask(int k, char *buf, size_t n, const char **name);

struct wb_conf {
    const struct wb_reg *reg;
    const char *endpoint;       /* «адрес:порт» */
    const char *i1;             /* маска или NULL */
    int obfs;                   /* параметры AmneziaWG (Jc…H4, I1); 0 — обычный WireGuard */
    int addr;                   /* Address из регистрации (у устройства подбора он свой) */
    int keepalive;
};

/* Записать файл (0600, заменой). 0 — записан. */
int wb_conf_write(const char *path, const struct wb_conf *c);
/* Endpoint из файла туннеля в ep (пусто — нет). 0 — прочитан. */
int wb_conf_endpoint(const char *path, char *ep, size_t n);

#endif
