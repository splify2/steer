/* Подкоманды программы плагина vless (src/modules/main_vless.c зовёт их по таблице pk_cmd). */
#ifndef STEER_VLCMD_H
#define STEER_VLCMD_H

struct pk_out;

/* Помощник выхода: туннель по {conf}. */
int cmd_vless(const struct pk_out *o);
/* Узлы подписки выхода (o — его {conf}) или файла (arg — путь с «/», o NULL). */
int cmd_vless_nodes(const struct pk_out *o, const char *arg, int insecure);
int cmd_vless_probe(const struct pk_out *o, const char *arg, int node, int timeout_s, int insecure);
int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path);
int cmd_sub_quota(const char *url, const char *info_path);
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port, int quiet);

#endif
