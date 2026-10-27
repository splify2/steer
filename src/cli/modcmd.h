/* Разбор, общий для точек входа steerd (src/daemon/main.c): флаг --platform.
 *
 * Прежде здесь жили команды модулей ядра и точка входа бинарника модуля (steer-tgws, steer-vless…). С 2.1
 * модулей у ядра нет: протоколы и мост Telegram — плагины, их подкоманды ядро берёт из манифестов
 * (src/kinds/plugin.c), а точку входа их программ даёт src/plugkit. */
#ifndef STEER_MODCMD_H
#define STEER_MODCMD_H

/* Вынуть из argv пару «--platform ИМЯ» и выбрать платформу. 0 — выбрана или не названа; 2 —
 * отказ (уже напечатан). Платформа — до всего остального. */
int modcmd_platform_args(int *argc, char **argv);

#endif
