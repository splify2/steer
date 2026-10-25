/* main бинарника steer-xsteer — модуль клиента звезды xsteer (шаг 4 выпуска 1.10). Устройство
 * то же, что у steer-vless (src/modules/main_vless.c): вся работа в steer_module_main, здесь
 * только имя модуля и версия ЭТОГО бинарника. Команды модуля: xsteer, xsteer-peers (клиент,
 * xsclient.c) и служебные xsteer-key, xsteer-check, xsteer-link (xsadmin.c). Хаб (xsteer-hub)
 * не здесь: он живёт на VPS отдельным архивом. */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "xsteer", STEER_VERSION);
}
