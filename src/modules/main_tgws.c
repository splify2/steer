/* main бинарника steer-tgws — модуль моста Telegram (шаг 4 выпуска 1.10). Правила перехвата
 * (kinds/tgws.c) по-прежнему пишет ядро: мост — только процесс, который принимает
 * перехваченные соединения. Устройство то же, что у steer-vless (src/modules/main_vless.c).
 * Команды модуля: tgws (мост) и tgws-probe (проверка путей до дата-центров). */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "tgws", STEER_VERSION);
}
