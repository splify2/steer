/* main бинарника steer-warpbox — модуль WARP (src/proto/warp/wbmain.c): регистрация, подбор точек и
 * замена для группы `kind: warp`. Всё дело — в steer_module_main (src/cli/modcmd.c), как у остальных
 * модулей; версия — этого бинарника (см. main_hysteria2.c).
 *
 * Модуль есть только в раскладке с libsteer.so (build/sources.mk, PROFILE_mod_warpbox). */
#include "modcmd.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    return steer_module_main(argc, argv, "warpbox", STEER_VERSION);
}
