/* Программа плагина proxy (plugins/proxy/plugin.json): помощник выходов `tunnel:trojan`,
 * `tunnel:shadowsocks`, `tunnel:socks`, `tunnel:http`, `tunnel:vmess`, хук check их видов и подкоманды
 * `steer proxy-nodes`, `proxy-probe`. С ядром — только через API (src/plugkit), как у vless. */
#include <stdio.h>

#include "plugkit.h"
#include "pktun.h"
#include "pxcmd.h"


static int r_run(const struct pk_args *a) { return cmd_proxy(a->out); }
static int insecure_ok(const struct pk_args *a) {
    if (pk_has(a, "insecure") && a->pos[0][0] != '/') {
        fprintf(stderr, "steer: %s: --insecure — только с файлом подписки (путь с «/»); у выхода узлы с "
                "allowInsecure решает его ключ insecure\n", a->cmd);
        return 0;
    }
    return 1;
}
static int r_nodes(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_proxy_nodes(a->out, a->pos[0], pk_has(a, "insecure"));
}
static int r_probe(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_proxy_probe(a->out, a->pos[0], (int)pk_opt_long(a, "node", -1, -1, 65535),
                           (int)pk_opt_long(a, "timeout", 5, 1, 3600), pk_has(a, "insecure"));
}
static int r_check(const struct pk_args *a) { (void)a; return pk_tun_check_hook(NULL); }

static const struct pk_cmd CMDS[] = {
    { "proxy", "<выход>", 0, 1, "", "поднять TUN и клиент выхода протокола прокси по его {conf}", 1, r_run },
    { "proxy-nodes", "<выход|/файл>", 1, 1, "insecure", "узлы подписки выхода или файла", 0, r_nodes },
    { "proxy-probe", "<выход|/файл>", 1, 1, "node: timeout: insecure",
      "проверить узел протокола прокси и измерить задержку", 0, r_probe },
    { "check", "", 0, 0, "", "хук check видов протоколов прокси", 0, r_check },
};

PK_PROGRAM("proxy", CMDS);
