/* main бинарника steer-obfs — модуль обфускатора (шаг 4 выпуска 1.10). Клиент и сервер
 * обфускации (obfs.c) остаются в libsteer, потому что их зовёт и xsteer в режиме потока;
 * модуль — это только точка входа помощника (src/proto/obfs/obfsmain.c). Устройство то же, что
 * у steer-vless (src/modules/main_vless.c). */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "obfs", STEER_VERSION);
}
