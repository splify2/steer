/* Хук check вида tgws (tghook.h): то, что схема ключей выразить не может, — общие ключи выхода. */
#include <stdio.h>
#include <string.h>

#include "pkjson.h"
#include "tghook.h"

int tg_check_hook(void) {
    char err[300];
    struct pkj *d = pkj_load("-", err, sizeof err);
    if (!d) { fprintf(stderr, "check: %s\n", err); return 2; }
    const struct pkj *c = pkj_path(d, "output.common");
    const char *ofs = pkj_str(pkj_get(c, "on_fail"));
    int dev = pkj_get(c, "device") != NULL;
    int drop = !ofs || !strcmp(ofs, "drop");
    pkj_free(d);
    /* Устройства нет по той же причине, что у обхода DPI: маршрут не меняется, меняется то, куда уводится
     * перехваченное соединение. Названное устройство — почти наверняка описка, и принять её молча значило
     * бы обещать маршрутизацию, которой не будет. */
    if (dev) {
        fprintf(stderr, "у kind tgws нет устройства — соединение перехватывается\n");
        return 2;
    }
    /* on_fail не выражается вовсе: перехват — правило nat, оно стоит всегда; когда моста нет, ядро
     * Linux отвечает отказом на соединение, то есть ведёт себя как drop, и никаким полем это не
     * переключить. Обещать direct и не сделать его хуже, чем отказать сразу. */
    if (!drop) {
        fprintf(stderr, "у kind tgws on_fail только drop: перехват стоит всегда, и без моста соединение "
                "отвергается — обойти это правилом нечем\n");
        return 2;
    }
    return 0;
}
