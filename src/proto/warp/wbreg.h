/* Регистрация устройства WARP (подробности — в wbreg.c). */
#ifndef STEER_WBREG_H
#define STEER_WBREG_H

#include <stddef.h>

struct wb_reg {
    char id[64];
    char token[128];
    char priv[48];          /* закрытый ключ X25519, base64 */
    char pub[48];
    char peer_pub[48];      /* ключ пира Cloudflare */
    char v4[48];            /* адрес туннеля */
    char v6[64];
    char client_id[16];
    char api[96];           /* кто зарегистрировал: «хост/путь» или santa-atmo.ru */
};

/* Новая регистрация с включением устройства. 0 — r заполнен; -1 — нет, почему — в why. */
int wb_register(struct wb_reg *r, char *why, size_t wn);
/* Кэш регистрации (0600, запись заменой). 0 — прочитан/записан. */
int wb_reg_save(const char *path, const struct wb_reg *r);
int wb_reg_load(const char *path, struct wb_reg *r);
void wb_reg_wipe(struct wb_reg *r);

#endif
