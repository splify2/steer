/* Программа плагина tgws (plugins/tgws/plugin.json): мост Telegram — помощник выхода `kind: tgws`, хук
 * check его вида и подкоманда `steer tgws-probe`.
 *
 * С ядром программа говорит только через API (plugin-sdk/docs/steer-api.md, src/plugkit): ядро запускает
 * её по манифесту, о выходе она знает из {conf} (ключ domain, порт моста — ресурс выхода), правила
 * перехвата ставит ядро по шаблону nft плагина (plugins/tgws/nft/tgws.nft). Настройки плагина — пул
 * доменов, пути ДЦ, адреса ДЦ, туннели WARP — лежат в своём каталоге настроек ({conf}: paths.conf,
 * у подкоманды — STEER_PLUGIN_CONF), файл settings.json по схеме plugins/tgws/settings.schema.json;
 * пишет его панель (splify2-api, plugin_settings_set). Мост читает его один раз при старте: файл входит в подпись
 * перезапуска помощника (манифест: steer.settings = "restart", steer-api 1.4), и хост, записав его, зовёт
 * reload — ядро поднимает мост заново сразу, без паузы перезапуска. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "plugkit.h"
#include "tghook.h"
#include "tgws.h"

/* Настройки плагина: документ живёт, пока жив процесс, списки — указатели на его строки. */
struct tg_settings {
    struct pkj *doc;
    const char **alt, **route, **dc, **warp;
    size_t alt_n, route_n, dc_n, warp_n;
    int verbose;
};

/* Список строк ключа key; не список строк — отказ с именем ключа (схему проверяет панель, но файл
 * мог написать и человек). */
static int strs(const struct pkj *doc, const char *key, const char ***out, size_t *n, const char *path) {
    const struct pkj *j = pkj_get(doc, key);
    *out = NULL;
    *n = 0;
    if (!j) return 0;
    if (j->t != PKJ_ARR) {
        fprintf(stderr, "steer[warn] tgws: %s: %s — не список, пропущен\n", path, key);
        return -1;
    }
    const char **a = calloc(j->n ? j->n : 1, sizeof(*a));
    if (!a) return -1;
    size_t k = 0;
    for (size_t i = 0; i < j->n; i++) {
        const char *s = pkj_str(j->v[i]);
        if (s) a[k++] = s;
        else fprintf(stderr, "steer[warn] tgws: %s: %s[%zu] — не строка, пропущено\n", path, key, i);
    }
    *out = a;
    *n = k;
    return 0;
}

/* Прочитать settings.json каталога настроек dir. Файла нет — умолчания схемы (пусто). Негодный файл
 * не роняет мост: Telegram без пула лучше, чем без моста, — причина уходит в журнал. */
static void settings_load(const char *dir, struct tg_settings *s, char *path, size_t pn) {
    memset(s, 0, sizeof(*s));
    path[0] = '\0';
    if (!dir || !*dir) return;
    snprintf(path, pn, "%s/settings.json", dir);
    if (access(path, F_OK) != 0) return;
    char err[300];
    s->doc = pkj_load(path, err, sizeof err);
    if (!s->doc || s->doc->t != PKJ_OBJ) {
        fprintf(stderr, "steer[warn] tgws: настройки %s не читаются (%s) — без них\n", path, s->doc ? "не объект" : err);
        pkj_free(s->doc);
        s->doc = NULL;
        return;
    }
    strs(s->doc, "domains", &s->alt, &s->alt_n, path);
    strs(s->doc, "routes", &s->route, &s->route_n, path);
    strs(s->doc, "dc_addresses", &s->dc, &s->dc_n, path);
    strs(s->doc, "warp", &s->warp, &s->warp_n, path);
    int b;
    if (pkj_bool(pkj_get(s->doc, "verbose"), &b) == 0) s->verbose = b;
}

static void settings_opts(const struct tg_settings *s, struct tgws_opts *o) {
    o->alt = s->alt;     o->alt_n = s->alt_n;
    o->route = s->route; o->route_n = s->route_n;
    o->dc = s->dc;       o->dc_n = s->dc_n;
    o->warp = s->warp;   o->warp_n = s->warp_n;
    o->verbose = s->verbose;
}

/* ---- подкоманды -------------------------------------------------------------------------------- */

static int r_tgws(const struct pk_args *a) {
    const struct pk_out *o = a->out;
    struct tgws_opts opt;
    memset(&opt, 0, sizeof opt);
    opt.name = o->tun.name;
    opt.domain = pk_key_str(o, "domain");
    long port = 0;
    pkj_long(pkj_at(pkj_get(o->output, "ports"), 0), &port);
    opt.port = (int)port;
    static struct tg_settings s;
    char path[4200];
    settings_load(o->plugin_conf, &s, path, sizeof path);
    settings_opts(&s, &opt);
    return tgws_serve(&opt);
}

static int r_probe(const struct pk_args *a) {
    if (a->npos && strcmp(a->pos[0], "media") != 0)
        pk_fail("команда tgws-probe понимает аргументом только «media», а получила «%s»", a->pos[0]);
    struct tgws_opts opt;
    memset(&opt, 0, sizeof opt);
    opt.domain = pk_opt(a, "domain");
    static struct tg_settings s;
    char path[4200];
    settings_load(getenv("STEER_PLUGIN_CONF"), &s, path, sizeof path);
    settings_opts(&s, &opt);
    long dc = pk_opt_long(a, "node", 2, 1, 203);
    return tgws_probe(&opt, (int)dc, a->npos == 1, pk_has(a, "direct"), (int)pk_opt_long(a, "timeout", 5, 1, 3600));
}

static int r_check(const struct pk_args *a) { (void)a; return tg_check_hook(); }

static const struct pk_cmd CMDS[] = {
    { "tgws", "<выход>", 0, 1, "", "поднять мост Telegram выхода kind: tgws по его {conf}", 1, r_tgws },
    { "tgws-probe", "[media]", 0, 1, "node: direct timeout: domain:",
      "проверить путь до дата-центра Telegram (--node 1..5 или 203, по умолчанию 2) через домен --domain "
      "или напрямую (--direct); срок --timeout, по умолчанию 5 секунд", 0, r_probe },
    { "check", "", 0, 0, "", "хук check вида tgws: вход — JSON выхода в stdin", 0, r_check },
};

PK_PROGRAM("tgws", CMDS);
