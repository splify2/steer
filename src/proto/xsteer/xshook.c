/* Хук check вида xsteer (xshook.h). Отдельным файлом: чистый разбор входа, без звезды и без сети —
 * его зовут и программа плагина, и стенды ядра (tests/pkhooks.c). */
#include <stdio.h>

#include "pkjson.h"
#include "plugkit.h"
#include "xshook.h"

int xs_check_hook(void) {
    char err[300];
    struct pkj *d = pkj_load("-", err, sizeof err);
    if (!d) { fprintf(stderr, "check: %s\n", err); return 2; }
    const struct pkj *k = pkj_path(d, "output.keys");
    int st = 0;
    long sp = 0;
    pkj_bool(pkj_get(k, "stream"), &st);
    pkj_long(pkj_get(k, "stream_port"), &sp);
    pkj_free(d);
    /* Порт без режима потока — настройка, которая ничего не делает: сказать «настроено», не настроив,
     * хуже, чем отказать. */
    if (sp && !st) {
        fprintf(stderr, "stream_port без stream: транспорт остался бы поддельным TCP\n");
        return 2;
    }
    return 0;
}
