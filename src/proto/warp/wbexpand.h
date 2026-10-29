/* Разворот выхода `kind: warp` — хук expand вида warp плагина warpbox (steer-api.md, 3.3).
 *
 * Отдельным файлом: чистая функция «JSON входа → JSON фрагмента», без сети и без ядра, — её проверяет
 * стенд tests/warpmatch.c, а программа плагина зовёт cmd_warp_expand (stdin → stdout). */
#ifndef STEER_WBEXPAND_H
#define STEER_WBEXPAND_H

#include <stdio.h>

struct pkj;

/* Вход хука (output.name, keys, common; spec.etc) → фрагмент в f. 0 — готово; 2 — отказ, строка в stderr. */
int warp_expand(const struct pkj *in, FILE *f);
/* То же со stdin и stdout — подкоманда warp-expand программы плагина. */
int cmd_warp_expand(void);

#endif
