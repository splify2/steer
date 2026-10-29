/* Программа плагина hysteria2 (plugins/hysteria2/plugin.json): помощник выхода `tunnel:hysteria2`, хук
 * check его вида и подкоманды `steer hysteria2-nodes`, `hysteria2-probe`. С ядром — только через API
 * (src/plugkit), как у vless (main_vless.c). */
#include <stdio.h>

#include "plugkit.h"
#include "pktun.h"
#include "hy2cmd.h"


static int r_run(const struct pk_args *a) { return cmd_hysteria2(a->out); }
static int insecure_ok(const struct pk_args *a) {
    if (pk_has(a, "insecure") && a->pos[0][0] != '/') {
        fprintf(stderr, "steer: %s: --insecure — только с файлом подписки (путь с «/»)\n", a->cmd);
        return 0;
    }
    return 1;
}
static int r_nodes(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_hysteria2_nodes(a->out, a->pos[0], pk_has(a, "insecure"));
}
static int r_probe(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_hysteria2_probe(a->out, a->pos[0], (int)pk_opt_long(a, "node", -1, -1, 65535),
                               (int)pk_opt_long(a, "timeout", 5, 1, 3600), pk_has(a, "insecure"));
}
static int r_check(const struct pk_args *a) { (void)a; return pk_tun_check_hook(NULL); }

static const struct pk_cmd CMDS[] = {
    { "hysteria2", "<выход>", 0, 1, "", "поднять TUN и клиент выхода tunnel:hysteria2 по его {conf}", 1, r_run },
    { "hysteria2-nodes", "<выход|/файл>", 1, 1, "insecure", "узлы подписки выхода или файла", 0, r_nodes },
    { "hysteria2-probe", "<выход|/файл>", 1, 1, "node: timeout: insecure",
      "проверить узел hysteria2: рукопожатие QUIC и авторизация, задержка", 0, r_probe },
    { "check", "", 0, 0, "", "хук check вида tunnel:hysteria2", 0, r_check },
};

PK_PROGRAM("hysteria2", CMDS);
