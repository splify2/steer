/* Дайлер hysteria2 и подъём туннеля: устройство — hy2dial.c. */
#ifndef STEER_HY2DIAL_H
#define STEER_HY2DIAL_H
#include "dialer.h"
#include "hy2.h"

struct tun_out;
extern const struct dialer_ops hy2_dialer;

/* Запустить соединение с узлом и стек TUN с дайлером hysteria2 (stack_run). ready — как у
 * stack_run: устройство поднято, модуль говорит об этом демону. Возвращает код выхода процесса,
 * всегда ненулевой. */
int hy2_tunnel_run(const struct tun_out *o, const struct hy2_node *node,
                   void (*ready)(void *arg, const char *dev), void *arg);

#endif
