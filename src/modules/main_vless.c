/* main бинарника steer-vless — модуль VLESS (шаг 4 выпуска 1.10, docs/architecture.md,
 * «Процессы»). Всё дело — в steer_module_main (src/cli/modcmd.c): платформа, hello с версией
 * этого бинарника в линию событий, разбор аргументов по общей таблице команд и вызов cmd_vless
 * и остальных команд модуля (vlmain.c, subfetch.c, tlsprobe.c). Версия берётся ЗДЕСЬ, в единице
 * компиляции самого модуля, а не из libsteer: hello должно называть версию бинарника, который
 * запустил демон, а не библиотеки, которую он загрузил.
 *
 * Файлы main_*.c лежат в src/modules, а не рядом с кодом модуля: каталог кода модуля (src/proto/
 * vless и так далее) сверяется с профилями статических сборок, а точка входа существует только у
 * разделяемой раскладки (build/sources.mk, PROFILE_mod_*). */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "vless", STEER_VERSION);
}
