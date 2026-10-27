/* Модули движка: какая команда чья и установлен ли модуль (module.h). */
#include "module.h"

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Версию подставляет сборка (-DSTEER_VERSION) из файла VERSION; умолчание — для стендов. */
#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

const char *steer_engine_version(void) { return STEER_VERSION; }

/* Команда → модуль ЯДРА. Модуль здесь один — мост Telegram steer-tgws: вид tgws пока в ядре, и его
 * бинарник лежит рядом со steerd. Протоколов в таблице нет и быть не должно: их подкоманды
 * (`vless-nodes`, `xsteer-peers`…) и помощники приходят только из манифестов плагинов
 * (kinds/plugin.c, steer.commands и kinds[].helper), и ядро их имён не знает. Когда tgws станет
 * плагином, таблица уйдёт целиком. */
static const struct { const char *cmd, *mod; } CMD_MOD[] = {
    { "tgws",        "steer-tgws"   },
    { "tgws-probe",  "steer-tgws"   },
};

const char *steer_cmd_module(const char *cmd) {
    for (size_t i = 0; i < sizeof(CMD_MOD) / sizeof(CMD_MOD[0]); i++)
        if (!strcmp(CMD_MOD[i].cmd, cmd)) return CMD_MOD[i].mod;
    return NULL;
}

int steer_module_is(const char *base) {
    for (size_t i = 0; i < sizeof(CMD_MOD) / sizeof(CMD_MOD[0]); i++)
        if (!strcmp(CMD_MOD[i].mod, base)) return 1;
    return 0;
}

const char *steer_module_dir(char *buf, size_t n) {
    const char *e = getenv("STEER_MODULE_DIR");
    if (e && *e) {
        snprintf(buf, n, "%s", e);
        return buf;
    }
    char self[PATH_MAX];
    ssize_t l = readlink("/proc/self/exe", self, sizeof(self) - 1);
    if (l <= 0) {
        snprintf(buf, n, ".");
        return buf;
    }
    self[l] = '\0';
    char *sl = strrchr(self, '/');
    if (sl == self) snprintf(buf, n, "/");
    else if (sl) snprintf(buf, n, "%.*s", (int)(sl - self), self);
    else snprintf(buf, n, ".");
    return buf;
}

int steer_module_path(const char *mod, char *buf, size_t n) {
    /* Модуль ядра — рядом с исполняемым файлом (STEER_MODULE_DIR — каталог, заданный стендом). */
    char dir[PATH_MAX];
    steer_module_dir(dir, sizeof(dir));
    snprintf(buf, n, "%s/%s", dir, mod);
    return access(buf, X_OK) == 0 ? 0 : -1;
}

int steer_module_present(const char *mod) {
    char p[PATH_MAX + 64];
    return steer_module_path(mod, p, sizeof(p)) == 0;
}
