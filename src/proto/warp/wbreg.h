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
    /* MASQUE (этап 2): ключ P-256 клиента (скаляр, base64), ключ сервера (SubjectPublicKeyInfo DER,
     * base64) и точка по API — адреса без порта. Пусто — MASQUE не включался. */
    char mq_priv[48];
    char mq_peer[160];
    char mq_ep4[48];
    char mq_ep6[64];
};

/* Новая регистрация с включением устройства. 0 — r заполнен; -1 — нет, почему — в why. */
int wb_register(struct wb_reg *r, char *why, size_t wn);
/* Кэш регистрации (0600, запись заменой). 0 — прочитан/записан. */
int wb_reg_save(const char *path, const struct wb_reg *r);
int wb_reg_load(const char *path, struct wb_reg *r);
void wb_reg_wipe(struct wb_reg *r);
/* Включить MASQUE у регистрации r (нужны id и token — регистрация через API, не готовая чужая):
 * ключ P-256 создаётся здесь, открытая половина уходит в API. 0 — поля mq_* заполнены. */
int wb_enroll_masque(struct wb_reg *r, char *why, size_t wn);
/* Вернуть устройству ключ WireGuard после MASQUE (transport сменили на awg). 0 — вернул, mq_* очищены. */
int wb_enroll_wireguard(struct wb_reg *r, char *why, size_t wn);
/* Есть ли у регистрации всё для MASQUE. */
int wb_reg_has_masque(const struct wb_reg *r);
/* base64 (обычный и url) в байты: длина или -1. */
int wb_b64_decode(const char *in, unsigned char *out, size_t cap);

#endif
