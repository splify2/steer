/* Хук check вида tgws (plugins/tgws/plugin.json): чистый разбор входа, без моста и сети — его зовут и
 * программа плагина (src/modules/main_tgws.c), и стенды ядра (tests/pkhooks.c). */
#ifndef STEER_TGHOOK_H
#define STEER_TGHOOK_H

/* Вход — JSON хука check в stdin (steer-api.md, 3.2). 0 — годится; 2 — отказ, причина в stderr. */
int tg_check_hook(void);

#endif
