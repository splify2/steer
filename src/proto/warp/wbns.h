/* Пространство сети подбора модуля steer-warpbox (подробности — в wbns.c). */
#ifndef STEER_WBNS_H
#define STEER_WBNS_H

/* Своё пространство сети модуля: дескриптор или -1 (причина — в errno). Поток остаётся в своём. */
int wb_ns_new(void);
/* Войти в ns; вернуть — wb_ns_leave(old). 0 — вошли. */
int wb_ns_enter(int ns, int *old);
void wb_ns_leave(int old);

#endif
