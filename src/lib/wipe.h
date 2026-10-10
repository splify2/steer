#ifndef STEER_WIPE_H
#define STEER_WIPE_H

#include <stddef.h>

/* Затереть секрет (ключ, состояние шифра, пароль) так, чтобы компилятор не выбросил запись.
 *
 * Обычный memset по памяти, которая дальше не читается, — «мёртвая запись», и при -O2 компилятор
 * вправе убрать её целиком (PVS-Studio V597): ключ остаётся в стеке или в освобождённой куче до
 * следующей перезаписи. explicit_bzero есть не во всякой musl, memset_s — не в C99, поэтому —
 * побайтно через volatile-указатель, как уже делает xs_conf_wipe (xsconf.h): запись по volatile
 * компилятор обязан выполнить. Секреты короткие (десятки-сотни байт), скорость побайтной записи
 * значения не имеет.
 *
 * Функция в заголовке (static inline), а не в libsteer: зовут её и ядро, и модули, и список
 * экспорта libsteer (build/libsteer.map) от неё не зависит. */
static inline void steer_wipe(void *p, size_t n) {
    volatile unsigned char *v = (volatile unsigned char *)p;
    while (n--) *v++ = 0;
}

#endif
