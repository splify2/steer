/* Версия ядра этой сборки. Прежде здесь была и таблица модулей ядра — отдельных бинарников рядом со
 * steerd (последним был мост Telegram steer-tgws). С 2.1 модулей у ядра нет: протоколы и мост — плагины,
 * их программы, подкоманды и помощники ядро берёт только из манифестов (kinds/plugin.c) и их имён не
 * знает. */
#ifndef STEER_MODULE_H
#define STEER_MODULE_H

/* Версия ядра этой сборки (STEER_VERSION, файл VERSION): её печатают version, spec-schema и
 * окружение программ плагинов (STEER_CORE_VERSION). */
const char *steer_engine_version(void);

#endif
