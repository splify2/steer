/* Подкоманды программы плагина proxy (src/modules/main_proxy.c). */
#ifndef STEER_PXCMD_H
#define STEER_PXCMD_H

struct pk_out;

int cmd_proxy(const struct pk_out *o);
int cmd_proxy_nodes(const struct pk_out *o, const char *arg, int insecure);
int cmd_proxy_probe(const struct pk_out *o, const char *arg, int node, int timeout_s, int insecure);

#endif
