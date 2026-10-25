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

/* Команда → модуль. Вся подкомандная поверхность модулей в одном месте: заглушки steerd
 * (cli/modcmd.c), справка и помощники демона читают эту таблицу, а не хранят каждый свой список,
 * который разошёлся бы с первым же новым инструментом. Что здесь НЕ названо, остаётся в steerd:
 * sub-hwid и dev-id (идентификатор роутера нужен и там, где модулей нет), xsteer-hub (хаб живёт
 * на VPS, отдельным архивом), apply-plan и прочее служебное.
 *
 * tls-probe и sub-fetch — у steer-vless, а не у ядра: их зовёт только тот, кто работает с
 * подпиской и узлами VLESS (splify2), а зонд нужен ровно затем, чтобы выбрать узел. Лишний
 * килобайт кода разбора подписки ядру ни к чему. */
static const struct { const char *cmd, *mod; } CMD_MOD[] = {
    { "vless",       "steer-vless"  },
    { "vless-nodes", "steer-vless"  },
    { "vless-probe", "steer-vless"  },
    { "sub-fetch",   "steer-vless"  },
    { "sub-quota",   "steer-vless"  },
    { "tls-probe",   "steer-vless"  },
    { "hysteria2",       "steer-hysteria2" },
    { "hysteria2-nodes", "steer-hysteria2" },
    { "hysteria2-probe", "steer-hysteria2" },
    { "proxy",       "steer-proxy" },
    { "proxy-nodes", "steer-proxy" },
    { "proxy-probe", "steer-proxy" },
    { "warp",        "steer-warpbox" },
    { "warp-reg",    "steer-warpbox" },
    { "warp-scan",   "steer-warpbox" },
    { "xsteer",       "steer-xsteer" },
    { "xsteer-peers", "steer-xsteer" },
    { "xsteer-key",   "steer-xsteer" },
    { "xsteer-check", "steer-xsteer" },
    { "xsteer-link",  "steer-xsteer" },
    { "obfs",        "steer-obfs"   },
    { "obfs-server", "steer-obfs"   },
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

/* Каталог плагинов (plugin-sdk/docs/s2p.md, «Раскладка на роутере»). Имя переменной у менеджера
 * (ветка plugin-mgr) — STEER_PLUGIN_DIR, у реестра видов (plugin-kind) — STEER_PLUGINS_ROOT; до их
 * сведения годятся обе. */
static const char *plugin_root(void) {
    const char *e = getenv("STEER_PLUGIN_DIR");
    if (e && *e) return e;
    e = getenv("STEER_PLUGINS_ROOT");
    if (e && *e) return e;
    return "/usr/lib/steer/plugins";
}

/* Плагин протокола вместо модуля (раскладка 2.1, build/sources.mk): команды модуля steer-<id> ведёт
 * программа <каталог плагинов>/<id>/bin/<id> — та же таблица команд, тот же разбор (cli/modcmd.c).
 * Шов до реестра плагинов (ветка plugin-kind): там помощник и подкоманды берутся из манифеста. */
static int plugin_path(const char *mod, char *buf, size_t n) {
    if (strncmp(mod, "steer-", 6) != 0 || !mod[6]) return -1;
    const char *id = mod + 6;
    snprintf(buf, n, "%s/%s/bin/%s", plugin_root(), id, id);
    return access(buf, X_OK) == 0 ? 0 : -1;
}

int steer_module_path(const char *mod, char *buf, size_t n) {
    /* Каталог модулей, заданный стендом (STEER_MODULE_DIR), — первым: стенд подменяет модуль
     * заглушкой и не должен получить настоящий плагин, если тот стоит на машине. Затем плагин, затем
     * прежний модуль рядом с исполняемым файлом (раскладка 2.0 и ссылки steer-<id> сборки 2.1). */
    const char *e = getenv("STEER_MODULE_DIR");
    if (!(e && *e) && plugin_path(mod, buf, n) == 0) return 0;
    char dir[PATH_MAX];
    steer_module_dir(dir, sizeof(dir));
    snprintf(buf, n, "%s/%s", dir, mod);
    return access(buf, X_OK) == 0 ? 0 : -1;
}

int steer_module_present(const char *mod) {
    char p[PATH_MAX + 64];
    return steer_module_path(mod, p, sizeof(p)) == 0;
}
