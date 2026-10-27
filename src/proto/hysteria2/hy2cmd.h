/* Подкоманды программы плагина hysteria2 (src/modules/main_hysteria2.c). */
#ifndef STEER_HY2CMD_H
#define STEER_HY2CMD_H

struct pk_out;

int cmd_hysteria2(const struct pk_out *o);
int cmd_hysteria2_nodes(const struct pk_out *o, const char *arg, int insecure);
int cmd_hysteria2_probe(const struct pk_out *o, const char *arg, int node, int timeout_s, int insecure);

#endif
