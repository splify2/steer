/* Программа плагина xsteer (plugins/xsteer/plugin.json): помощник выхода `xsteer` (клиент звезды),
 * хук check его вида и подкоманды `steer xsteer-peers`, `xsteer-key`, `xsteer-check`, `xsteer-link`.
 * С ядром — только через API (src/plugkit). Без {conf} `xsteer --config --device` поднимает клиент
 * на готовом устройстве (режим netifd), спеки не касаясь. */
#include <stdio.h>
#include <string.h>

#include "plugkit.h"
#include "xscmd.h"
#include "xshook.h"


static int r_run(const struct pk_args *a) {
    int st = pk_has(a, "stream"), nst = pk_has(a, "no-stream");
    const char *sp = pk_opt(a, "stream-port");
    if (nst && (st || sp))
        pk_fail("флаги --no-stream и %s противоречат друг другу — оставьте один", st ? "--stream" : "--stream-port");
    int port = (int)pk_opt_long(a, "stream-port", 0, 1, 65535);
    return cmd_xsteer(a->out, pk_opt(a, "config"), pk_opt(a, "device"), st || sp ? 1 : nst ? -1 : 0, port);
}
static int r_peers(const struct pk_args *a) {
    if (!a->out) pk_fail("xsteer-peers: нужен --conf — файл настройки выхода (команду зовёт ядро: steer xsteer-peers <выход>)");
    return cmd_xsteer_peers(a->out, pk_opt(a, "config"));
}
static int r_key(const struct pk_args *a) { (void)a; return cmd_xsteer_key(); }
static int r_check(const struct pk_args *a) { return cmd_xsteer_check(pk_opt(a, "config")); }
static int r_link(const struct pk_args *a) {
    return cmd_xsteer_link(a->npos ? a->pos[0] : pk_opt(a, "config"), pk_opt(a, "name"));
}

static int r_hook(const struct pk_args *a) { (void)a; return xs_check_hook(); }

static const struct pk_cmd CMDS[] = {
    { "xsteer", "[<выход>]", 0, 1, "config: device: stream no-stream stream-port:",
      "поднять клиент xsteer: для выхода по его {conf} или для готового устройства (--config, --device)", 0, r_run },
    { "xsteer-peers", "<выход>", 1, 1, "config:", "узлы звезды выхода и его живое состояние", 0, r_peers },
    { "xsteer-key", "", 0, 0, "", "новый ключ клиента", 0, r_key },
    { "xsteer-check", "", 0, 0, "config:", "проверить файл настройки", 0, r_check },
    { "xsteer-link", "[<файл|ссылка|->]", 0, 1, "config: name:", "ссылка на настройку", 0, r_link },
    { "check", "", 0, 0, "", "хук check вида xsteer", 0, r_hook },
};

PK_PROGRAM("xsteer", CMDS);
