/* Хук check вида xsteer (steer-api.md, 3.2): то, чего схема ключей вида не выражает. */
#ifndef STEER_XSHOOK_H
#define STEER_XSHOOK_H

/* stdin — вход хука; 0 — годится, 2 — отказ с причиной в stderr. */
int xs_check_hook(void);

#endif
