/* Программа плагина warpbox (plugins/warpbox/plugin.json): вид warp — хук expand и помощник
 * развёрнутой группы, — и подкоманды `steer warp-reg`, `warp-scan`. С ядром — только через API
 * (src/plugkit). */
#include "plugkit.h"
#include "wbexpand.h"

int cmd_warp(const struct pk_out *po);
int cmd_warp_reg(const char *path);
int cmd_warp_scan(const struct pk_out *po);

static int r_warp(const struct pk_args *a) { return cmd_warp(a->out); }
static int r_expand(const struct pk_args *a) { (void)a; return cmd_warp_expand(); }
static int r_reg(const struct pk_args *a) { return cmd_warp_reg(a->pos[0]); }
static int r_scan(const struct pk_args *a) {
    if (!a->out) pk_fail("warp-scan: нужен --conf — файл настройки выхода (команду зовёт ядро: steer warp-scan <выход>)");
    return cmd_warp_scan(a->out);
}

static const struct pk_cmd CMDS[] = {
    { "warp", "<выход>", 0, 1, "", "вести выход kind: warp: регистрация, подбор точек, замена", 1, r_warp },
    { "warp-expand", "", 0, 0, "", "хук expand вида warp: вход — JSON выхода в stdin", 0, r_expand },
    { "warp-reg", "<файл>", 1, 1, "", "зарегистрировать устройство WARP", 0, r_reg },
    { "warp-scan", "<выход>", 1, 1, "", "подобрать точки входа WARP для выхода", 0, r_scan },
};

PK_PROGRAM("warpbox", CMDS);
