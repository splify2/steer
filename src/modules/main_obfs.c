/* Программа плагина obfs (plugins/obfs/plugin.json): помощник обфускатора выхода interface с obfs и
 * сервер обфускации `steer obfs-server`. С ядром — только через API (src/plugkit). */
#include "plugkit.h"

int cmd_obfs(const struct pk_out *o);
int cmd_obfs_server(int listen_port, const char *forward);

static int r_obfs(const struct pk_args *a) { return cmd_obfs(a->out); }
static int r_server(const struct pk_args *a) {
    return cmd_obfs_server((int)pk_opt_long(a, "listen", 0, 1, 65535), pk_opt(a, "forward"));
}

static const struct pk_cmd CMDS[] = {
    { "obfs", "<выход>", 0, 1, "", "клиент обфускатора выхода interface с obfs, по его {conf}", 1, r_obfs },
    { "obfs-server", "", 0, 0, "listen: forward:", "сервер обфускации (VPS): поддельный TCP → WireGuard", 0, r_server },
};

PK_PROGRAM("obfs", CMDS);
