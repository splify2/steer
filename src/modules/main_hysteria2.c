/* main бинарника steer-hysteria2 — модуль hysteria2 (выпуск 1.10, docs/architecture.md, «Процессы»).
 * Всё дело — в steer_module_main (src/cli/modcmd.c): платформа, hello с версией этого бинарника в
 * линию событий, разбор аргументов по общей таблице команд и вызов cmd_hysteria2 и остальных команд
 * модуля (src/proto/hysteria2/hy2main.c). Версия берётся ЗДЕСЬ, в единице компиляции самого
 * модуля, а не из libsteer: hello должно называть версию бинарника, который запустил демон.
 *
 * Модуль есть только в раскладке с libsteer.so (build/sources.mk, PROFILE_mod_hysteria2): ни в
 * статических сборках, ни в профиле телефона его нет. */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "hysteria2", STEER_VERSION);
}
