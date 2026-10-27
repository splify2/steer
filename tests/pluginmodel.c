/* Стенд плагинной модели ядра: реестр манифестов, совместимость steer-api, помощник вида, {conf}.
 *
 * Что проверяется (то, чего не видно через `steer`, tests/pluginkindmatch.sh):
 *   - диапазоны compat.steer-api (^, ~, >=, <, ||): плагин с несовместимым тегом выключен, причина
 *     называет числа;
 *   - запись вида: имя, свойства caps, помощник из манифеста; kind_ops.helper плагина отдаёт
 *     программу плагина (полный путь), argv с раскрытыми {out} и {conf}, id плагина и путь {conf};
 *   - подпись помощника — от версии плагина и содержимого {conf}: те же ключи — та же подпись, другие
 *     ключи — другая;
 *   - {conf}: api, плагин, ключи по схеме, устройство, метка, таблица, подложка; пишется атомарно с
 *     правами 0600;
 *   - реестр видит свежий манифест после plugin_refresh (менеджер подменил каталог плагина).
 *
 * Модель линкуется отдельными объектами (MODEL_KINDS + awg.c), как у modelmatch. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "spec.h"
#include "plugin.h"
#include "unit.h"

static char g_root[256], g_etc[256], g_st[256], g_dir[256];

static void put(const char *rel, const char *text) {
    char p[600], d[600];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    snprintf(d, sizeof(d), "%s", p);
    for (char *s = d + strlen(g_root) + 1; *s; s++)
        if (*s == '/') { *s = '\0'; mkdir(d, 0755); *s = '/'; }
    FILE *f = fopen(p, "w");
    if (!f) { perror(p); exit(2); }
    fputs(text, f);
    fclose(f);
}

static void compat_plugin(const char *id, const char *range) {
    char rel[128], text[512];
    snprintf(rel, sizeof(rel), "%s/plugin.json", id);
    snprintf(text, sizeof(text),
             "{\"schema\":1,\"id\":\"%s\",\"version\":\"1.0.0\",\"compat\":{\"steer-api\":\"%s\"},"
             "\"steer\":{\"kinds\":[{\"name\":\"k-%s\",\"caps\":[\"mark\"]}]}}", id, range, id);
    put(rel, text);
}

static const char *why_of(const char *id) {
    const struct plugin *p = plugin_find(id);
    return p ? (p->why ? p->why : "") : "(нет плагина)";
}

static int load(const char *name, const char *text, struct spec *sp, char *msg, size_t n) {
    char path[600];
    snprintf(path, sizeof(path), "%s/%s", g_dir, name);        /* вне каталога плагинов: время его не меняется */
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
    struct err e = {0};
    int rc = load_spec(path, sp, &e);
    snprintf(msg, n, "%s", e.msg);
    return rc;
}

int main(void) {
    char tmpl[] = "/tmp/pluginmodel.XXXXXX";
    if (!mkdtemp(tmpl)) { perror("mkdtemp"); return 2; }
    snprintf(g_dir, sizeof(g_dir), "%s", tmpl);
    snprintf(g_root, sizeof(g_root), "%s/plugins", tmpl);
    snprintf(g_etc, sizeof(g_etc), "%s/etc", tmpl);
    snprintf(g_st, sizeof(g_st), "%s/st", tmpl);
    mkdir(g_root, 0755);
    mkdir(g_etc, 0755);
    mkdir(g_st, 0755);
    setenv("STEER_PLUGINS_ROOT", g_root, 1);
    setenv("STEER_PLUGINS_ETC", g_etc, 1);
    steer_set_state_dir(g_st);

    /* ---- совместимость ---- */
    compat_plugin("c-caret", "^1.0");
    compat_plugin("c-tilde", "~1.2");
    compat_plugin("c-ge", ">=1.0 <2");
    compat_plugin("c-or", "^2.0 || ^1.0");
    compat_plugin("c-exact", "1.2");
    compat_plugin("c-newer", "^1.3");
    compat_plugin("c-major", "^2.0");
    compat_plugin("c-lt", "<1.0");
    compat_plugin("c-zero", "^0.9");
    compat_plugin("c-junk", "abc");
    plugin_reload(NULL);
    check("^1.0 — совместим с steer-api 1.2", 1, plugin_find("c-caret")->enabled);
    check("~1.1 — совместим", 1, plugin_find("c-tilde")->enabled);
    check(">=1.0 <2 — совместим", 1, plugin_find("c-ge")->enabled);
    check("^2.0 || ^1.0 — совместим", 1, plugin_find("c-or")->enabled);
    check("1.2 — совместим", 1, plugin_find("c-exact")->enabled);
    check("^1.3 — не совместим (ядро 1.2)", 0, plugin_find("c-newer")->enabled);
    check_str("  причина называет числа", "c-newer 1.0.0 требует steer-api ^1.3, у ядра 1.2", why_of("c-newer"));
    check("^2.0 — не совместим", 0, plugin_find("c-major")->enabled);
    check("<1.0 — не совместим", 0, plugin_find("c-lt")->enabled);
    check("^0.9 — не совместим", 0, plugin_find("c-zero")->enabled);
    check("диапазон не разобран — плагин выключен", 0, plugin_find("c-junk")->enabled);
    check_str("  причина — «диапазон не разобран»", "compat.steer-api: «abc» — диапазон не разобран", why_of("c-junk"));
    check("вид выключенного плагина не регистрируется", 1, plugin_kind_find("k-c-newer") == NULL);
    check("вид включённого — регистрируется", 1, plugin_kind_find("k-c-caret") != NULL);
    char buf[256];
    const char *id = NULL;
    check("отказ про вид выключенного плагина называет его", 1,
          plugin_kind_why("k-c-newer", buf, sizeof(buf), &id) != NULL && id && !strcmp(id, "c-newer"));
    check("вид, которого нет ни у кого, — без причины (неизвестный kind)", 1,
          plugin_kind_why("nosuchkind", buf, sizeof(buf), &id) == NULL);
    /* Своего списка «вид → плагин» у ядра нет: имя плагина — из индекса семени (provides.kinds). Семени
     * нет — причины нет (неизвестный протокол). */
    check("нет семени — причины нет", 1, plugin_kind_why("tunnel:vless", buf, sizeof(buf), &id) == NULL);
    put("../seed/index.json", "{\"plugins\":{\"vless\":{\"versions\":[{\"version\":\"2.1.0\","
        "\"provides\":{\"kinds\":[\"tunnel:vless\"]}}]}}}");
    char seed[300];
    snprintf(seed, sizeof(seed), "%s/../seed", g_root);
    setenv("STEER_PLUGIN_SEED", seed, 1);
    const char *nw = plugin_kind_why("tunnel:vless", buf, sizeof(buf), &id);
    check_str("нужен плагин — по семени", "нужен плагин vless — поставить", nw ? nw : "(нет)");
    check_str("  и плагин назван", "vless", id ? id : "(нет)");
    unsetenv("STEER_PLUGIN_SEED");

    /* ---- вид с помощником ---- */
    put("hp/plugin.json",
        "{\"schema\":1,\"id\":\"hp\",\"version\":\"3.1.4\",\"compat\":{\"steer-api\":\"^1.0\"},"
        "\"steer\":{\"kinds\":[{\"name\":\"hpkind\",\"keys\":\"kinds/hp.schema.json\","
        "\"caps\":[\"device\",\"mark\",\"ctmark\",\"over\"],"
        "\"helper\":{\"prog\":\"bin/h\",\"cmd\":\"hphelper\",\"argv\":[\"run\",\"{out}\",\"--conf\",\"{conf}\",\"--x\",\"{{lit}}\"],"
        "\"env\":{\"HP_MODE\":\"fast\"}}}]}}");
    put("hp/kinds/hp.schema.json",
        "{\"type\":\"object\",\"properties\":{\"token\":{\"type\":\"string\"}},\"required\":[\"token\"],"
        "\"additionalProperties\":false}");
    plugin_reload(NULL);
    const struct plugin_kind *pk = plugin_kind_find("hpkind");
    check("вид hpkind зарегистрирован", 1, pk != NULL);
    check("  caps из манифеста", KC_DEVICE | KC_MARK | KC_CTMARK | KC_OVER, pk ? (long)pk->caps : -1);
    check("  у записи вида плагин назван", 1, pk && pk->ops.plugin == pk);
    check_str("  запись kind_ops называется как вид", "hpkind", pk ? pk->ops.name : "");

    struct spec sp;
    memset(&sp, 0, sizeof(sp));
    char msg[1024];
    check("спека с видом плагина принята", 0,
          load("s1.yaml", "version: 2\noutputs:\n  base: { kind: interface, device: wg9 }\n  h1: { kind: hpkind, token: aaa, over: base }\n", &sp, msg, sizeof(msg)));
    if (unit_fail) printf("%s\n", msg);
    struct output *o = out_by_name(&sp, "h1");
    check("выход разобран и знает свой вид", 1, o && out_plugin_kind(o) == pk);
    check_str("  ключи вида — по схеме", "{\"token\":\"aaa\"}", o && out_plugin_keys(o) ? out_plugin_keys(o) : "");
    check("  владельца нет (выход человека)", 0, o && out_owned_by(o, NULL, NULL));
    check("  вид доступен", 1, o && out_unavail(o) == NULL);
    struct kind_helper h = { .sig = KIND_SIG_INIT };
    check("помощник выхода есть", 0, o ? kind_of(o)->helper(&sp, o, &h) : -1);
    char want[600];
    snprintf(want, sizeof(want), "%s/hp/bin/h", g_root);
    check_str("  программа — полный путь в каталоге плагина", want, h.prog ? h.prog : "");
    check_str("  имя помощника из манифеста", "hphelper", h.cmd ? h.cmd : "");
    check_str("  плагин назван", "hp", h.plugin ? h.plugin : "");
    check("  argv: шесть слов", 6, (long)h.arg_n);
    check_str("  argv[0]", "run", h.arg_n > 0 ? h.arg[0] : "");
    check_str("  {out} раскрыт", "h1", h.arg_n > 1 ? h.arg[1] : "");
    snprintf(want, sizeof(want), "%s/plugin/hp/h1.json", g_st);
    check_str("  {conf} — файл выхода в каталоге состояния", want, h.arg_n > 3 ? h.arg[3] : "");
    check_str("  conf_path совпадает", want, h.conf_path ? h.conf_path : "");
    check_str("  {{lit}} — буквальные скобки", "{lit}", h.arg_n > 5 ? h.arg[5] : "");
    check("  окружение из манифеста", 1, h.env_n == 1 && !strcmp(h.env[0], "HP_MODE=fast"));
    unsigned long long sig1 = h.sig;
    kind_helper_free(&h);
    h = (struct kind_helper){ .sig = KIND_SIG_INIT };
    kind_of(o)->helper(&sp, o, &h);
    check("подпись помощника: те же ключи — та же подпись", 1, h.sig == sig1);
    kind_helper_free(&h);

    /* {conf} */
    char *cj = plugin_conf_json(&sp, o, pk);
    check("{conf} собран", 1, cj != NULL);
    if (cj) {
        check("  api ядра", 1, strstr(cj, "\"api\":\"" STEER_API_VERSION "\"") != NULL);
        check("  плагин и версия", 1, strstr(cj, "\"plugin\":{\"id\":\"hp\",\"version\":\"3.1.4\"}") != NULL);
        check("  вид и ключи", 1, strstr(cj, "\"kind\":\"hpkind\",\"keys\":{\"token\":\"aaa\"}") != NULL);
        check("  устройство выведено из имени", 1, strstr(cj, "\"device\":\"h1\"") != NULL);
        check("  подложка — выход base с его меткой", 1, strstr(cj, "\"over\":{\"name\":\"base\"") != NULL);
        check("  метка сокетов обязательна при over", 1, strstr(cj, "\"sock_mark_required\":true") != NULL);
        check("  каталоги", 1, strstr(cj, "\"paths\":{\"etc\":") != NULL);
        free(cj);
    }
    check("plugin_conf_write пишет файл", 0, plugin_conf_write(&sp, o));
    snprintf(want, sizeof(want), "%s/plugin/hp/h1.json", g_st);
    struct stat st;
    check("  файл на месте, права 0600", 1, stat(want, &st) == 0 && (st.st_mode & 0777) == 0600);

    /* другие ключи — другая подпись */
    struct spec sp2;
    memset(&sp2, 0, sizeof(sp2));
    check("вторая спека принята", 0,
          load("s2.yaml", "version: 2\noutputs:\n  base: { kind: interface, device: wg9 }\n  h1: { kind: hpkind, token: bbb, over: base }\n", &sp2, msg, sizeof(msg)));
    struct output *o2 = out_by_name(&sp2, "h1");
    struct kind_helper h2 = { .sig = KIND_SIG_INIT };
    if (o2) kind_of(o2)->helper(&sp2, o2, &h2);
    check("подпись помощника: другой token — другая подпись", 1, h2.sig != sig1);
    kind_helper_free(&h2);

    /* ---- смена плагина на диске подхватывается plugin_refresh ---- */
    check("реестр не менялся — plugin_refresh ничего не делает", 0, plugin_refresh());
    sleep(1);                                       /* время каталога — в секундах файловой системы */
    compat_plugin("c-late", "^1.0");
    check("появился новый каталог — реестр перечитан", 1, plugin_refresh());
    check("  и новый плагин в нём", 1, plugin_find("c-late") != NULL);
    check("  а прежний вид по-прежнему на месте", 1, plugin_kind_find("hpkind") != NULL);

    spec_release(&sp);
    spec_release(&sp2);
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpl);
    if (system(cmd) != 0) {}
    return unit_done("pluginmodel");
}
