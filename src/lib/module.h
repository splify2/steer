/* Модули движка — отдельные бинарники рядом с steerd (выпуск 1.10, шаг 4; docs/architecture.md,
 * «Сборки» и «Процессы»).
 *
 * Клиент VLESS, клиент xsteer, обфускатор и мост Telegram — не часть steerd, а программы
 * steer-vless, steer-xsteer, steer-obfs и steer-tgws: у каждой свой пакет, и есть ли она на
 * роутере, решает файл в каталоге движка. Этот файл — единственное место, где движок отвечает на
 * два вопроса о модулях: «какой модуль ведёт эту команду» и «установлен ли он». Вид выхода
 * (kinds/kind.c), справка (cli/cli.c), помощники демона (daemon/helpers.c) и заглушки команд
 * (cli/modcmd.c) спрашивают здесь, а не гадают каждый по-своему.
 *
 * ГДЕ ИСКАТЬ МОДУЛЬ. Рядом с исполняемым файлом текущего процесса (/proc/self/exe): steerd и
 * модули лежат в одном каталоге (/usr/sbin), как обработчик очереди steer-nfqws. STEER_MODULE_DIR
 * подменяет каталог — так стенды кладут заглушки вместо настоящих модулей, не копируя движок.
 *
 * ПЛАГИНЫ (раскладка 2.1). Модуль steer-<id> может быть плагином протокола: программа
 * <каталог плагинов>/<id>/bin/<id> (STEER_PLUGIN_DIR или STEER_PLUGINS_ROOT, иначе /usr/lib/steer/plugins).
 * steer_module_path ищет сначала её, затем прежний модуль рядом (кроме стендов с STEER_MODULE_DIR). */
#ifndef STEER_MODULE_H
#define STEER_MODULE_H

#include <stddef.h>

/* Какой модуль ведёт подкоманду: "vless" → "steer-vless", "sub-fetch" → "steer-vless",
 * "tgws-probe" → "steer-tgws"; NULL — команда не модульная. Таблица одна, в module.c. */
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

/* Имя файла (без каталога) — бинарник модуля? "steer-vless" → 1, "steer-nfqws" → 0. */
int steer_module_is(const char *base);

#endif
