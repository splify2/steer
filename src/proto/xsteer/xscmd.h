/* Подкоманды программы плагина xsteer (src/modules/main_xsteer.c). */
#ifndef STEER_XSCMD_H
#define STEER_XSCMD_H

struct pk_out;

/* Клиент звезды: выход по {conf} (po) или готовое устройство (po NULL, нужны conf_path и device).
 * stream: 1 — --stream, -1 — --no-stream, 0 — как в ключах выхода. */
int cmd_xsteer(const struct pk_out *po, const char *conf_path, const char *device, int stream,
               int stream_port);
int cmd_xsteer_peers(const struct pk_out *po, const char *conf_path);
int cmd_xsteer_key(void);
int cmd_xsteer_check(const char *conf_path);
int cmd_xsteer_link(const char *what, const char *name);

#endif
