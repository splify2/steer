/* Модули ЯДРА — отдельные бинарники рядом со steerd. Сейчас такой один: мост Telegram steer-tgws
 * (вид tgws ещё в ядре). Протоколы модулями ядра больше не являются: это плагины, их программы,
 * подкоманды и помощники ядро берёт только из манифестов (kinds/plugin.c), а их имён не знает.
 *
 * ГДЕ ИСКАТЬ МОДУЛЬ. Рядом с исполняемым файлом текущего процесса (/proc/self/exe): steerd и
 * модуль лежат в одном каталоге (/usr/sbin). STEER_MODULE_DIR подменяет каталог — так стенды кладут
 * заглушку вместо настоящего модуля, не копируя движок. */
#ifndef STEER_MODULE_H
#define STEER_MODULE_H

#include <stddef.h>

/* Какой модуль ядра ведёт подкоманду: "tgws-probe" → "steer-tgws"; NULL — команда не модульная.
 * Таблица одна, в module.c. */
const char *steer_cmd_module(const char *cmd);

/* Каталог модулей (STEER_MODULE_DIR, иначе каталог исполняемого файла процесса) в buf. */
const char *steer_module_dir(char *buf, size_t n);

/* Полный путь модуля в buf, если он установлен (есть и исполняем): 0; иначе -1. */
int steer_module_path(const char *mod, char *buf, size_t n);

/* Установлен ли модуль. */
int steer_module_present(const char *mod);

/* Версия движка этой сборки (STEER_VERSION, файл VERSION) — с ней демон сверяет версию из
 * hello модуля (evline.h). */
const char *steer_engine_version(void);

/* Имя файла (без каталога) — бинарник модуля ядра? "steer-tgws" → 1, "steer-nfqws" → 0. */
int steer_module_is(const char *base);

#endif
