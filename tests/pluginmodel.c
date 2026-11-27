/* Стенд плагинной модели ядра: реестр манифестов, совместимость steer-api, помощник вида, {conf}.
 *
 * Что проверяется (то, чего не видно через `steer`, tests/pluginkindmatch.sh):
 *   - диапазоны compat.steer-api (^, ~, >=, <, ||): плагин с несовместимым тегом выключен, причина
 *     называет числа;
 *   - запись вида: имя, свойства caps, помощник из манифеста; kind_ops.helper плагина отдаёт
 *     программу плагина (полный путь), argv с раскрытыми {out} и {conf}, id плагина и путь {conf};
 *   - подпись помощника — от версии плагина и содержимого {conf}: те же ключи — та же подпись, другие
 *     ключи — другая; при steer.settings: "restart" — и от settings.json плагина (steer-api 1.5);
 *   - {conf}: api, плагин, ключи по схеме, устройство, метка, таблица, подложка; пишется атомарно с
 *     правами 0600;
 *   - реестр видит свежий манифест после plugin_refresh (менеджер подменил каталог плагина).
 *
 * Модель линкуется отдельными объектами (MODEL_KINDS + awg.c), как у modelmatch. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "spec.h"
#include "plugin.h"
#include "unit.h"

static char g_root[256], g_etc[256], g_st[256], g_dir[256];

/* Только модель: один обычный отказ роста массива пакетов с одного до двух.
 * Другие выделения работают; отказ не требует исчерпания памяти. */
static int fail_growth, hits;
void *__real_realloc(void *p, size_t n);
void *__wrap_realloc(void *p, size_t n) {
    if (fail_growth && p && n == 2 * sizeof(struct plugin)) {
        fail_growth = 0; hits++;
        errno = ENOMEM;
        return NULL;
    }
    return __real_realloc(p, n);
}

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

/* Direct-directory fixtures: installer rejection alone does not protect runtime. */
static void schema_plugin(const char *id, const char *schema, const char *extra_compat) {
    char rel[128], text[1024];
    snprintf(rel, sizeof(rel), "%s/plugin.json", id);
    snprintf(text, sizeof(text),
             "{%s\"id\":\"%s\",\"version\":\"1.0.0\","
             "\"compat\":{\"steer-api\":\"^1.0\"%s},"
             "\"steer\":{\"kinds\":[{\"name\":\"k-%s\",\"caps\":[\"mark\"]}]}}",
             schema, id, extra_compat, id);
    put(rel, text);
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
    compat_plugin("c-tilde", "~1.5");
    compat_plugin("c-ge", ">=1.0 <2");
    compat_plugin("c-or", "^2.0 || ^1.0");
    compat_plugin("c-exact", "1.5");
    compat_plugin("c-newer", "^1.6");
    compat_plugin("c-major", "^2.0");
    compat_plugin("c-lt", "<1.0");
    compat_plugin("c-zero", "^0.9");
    compat_plugin("c-junk", "abc");
    schema_plugin("s-future", "\"schema\":2,", "");
    schema_plugin("s-missing", "", "");
    schema_plugin("s-string", "\"schema\":\"1\",", "");
    schema_plugin("s-provider", "\"schema\":1,", ",\"steer-provider-api\":\"^1.0\"");
    plugin_reload(NULL);
    const char *schema_rejected[] = { "s-future", "s-missing", "s-string" };
    for (size_t i = 0; i < sizeof(schema_rejected) / sizeof(schema_rejected[0]); i++) {
        const struct plugin *p = plugin_find(schema_rejected[i]);
        check("unsupported/missing schema is disabled", 1, p && !p->enabled);
        check_str("schema rejection reason", "plugin.json: поддерживается только schema 1",
                  why_of(schema_rejected[i]));
    }
    const struct plugin *provider = plugin_find("s-provider");
    check("provider axis cannot fall back to legacy", 1, provider && !provider->enabled);
    check_str("provider axis rejection reason", "steer-provider-api не поддерживается legacy runtime",
              why_of("s-provider"));
    check("future schema kind is not registered", 1, plugin_kind_find("k-s-future") == NULL);
    check("provider kind is not registered", 1, plugin_kind_find("k-s-provider") == NULL);
    check("^1.0 — совместим с steer-api 1.5", 1, plugin_find("c-caret")->enabled);
    check("~1.5 — совместим", 1, plugin_find("c-tilde")->enabled);
    check(">=1.0 <2 — совместим", 1, plugin_find("c-ge")->enabled);
    check("^2.0 || ^1.0 — совместим", 1, plugin_find("c-or")->enabled);
    check("1.5 — совместим", 1, plugin_find("c-exact")->enabled);
    check("^1.6 — не совместим (ядро 1.5)", 0, plugin_find("c-newer")->enabled);
    check_str("  причина называет числа", "c-newer 1.0.0 требует steer-api ^1.6, у ядра 1.5", why_of("c-newer"));
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
    /* Имя плагина для вида — из индекса семени (provides.kinds), а без семени — из таблицы видов официальных
     * плагинов, собранной вместе с ядром (src/kinds/offkinds.h): на роутере без семени или с плагином из другого
     * репозитория (tgws) отказ всё равно называет, что поставить, а не «неизвестный kind». */
    id = NULL;
    check("нет семени — плагин назван по таблице официальных видов", 1,
          plugin_kind_why("tunnel:vless", buf, sizeof(buf), &id) != NULL && id && !strcmp(id, "vless"));
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
        "{\"schema\":1,\"id\":\"hp\",\"version\":\"3.1.4\",\"compat\":{\"steer-api\":\"^1.5\"},"
        "\"steer\":{\"settings\":\"restart\",\"commands\":[{\"name\":\"hp-cmd\",\"prog\":\"bin/c\"}],"
        "\"services\":[{\"name\":\"hp-svc\",\"prog\":\"bin/s\"}],"
        "\"kinds\":[{\"name\":\"hpkind\",\"keys\":\"kinds/hp.schema.json\",\"paths\":true,"
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
    check("  paths из манифеста — у помощника", 1, h.paths == 1);
    kind_helper_free(&h);
    /* steer.settings: "restart" (steer-api 1.4) — settings.json плагина в подписи: появился, переписан,
     * убран — подпись другая; тот же текст — та же. */
    {
        char sd[400], sf[500];
        snprintf(sd, sizeof(sd), "%s/conf", g_etc);
        mkdir(sd, 0755);
        snprintf(sd, sizeof(sd), "%s/conf/hp", g_etc);
        mkdir(sd, 0755);
        snprintf(sf, sizeof(sf), "%s/settings.json", sd);
        unsigned long long s[3];
        const char *txt[2] = { "{\"a\":1}\n", "{\"a\":2}\n" };
        for (int i = 0; i < 2; i++) {
            FILE *f = fopen(sf, "w");
            fputs(txt[i], f);
            fclose(f);
            h = (struct kind_helper){ .sig = KIND_SIG_INIT };
            kind_of(o)->helper(&sp, o, &h);
            s[i] = h.sig;
            kind_helper_free(&h);
        }
        unlink(sf);
        h = (struct kind_helper){ .sig = KIND_SIG_INIT };
        kind_of(o)->helper(&sp, o, &h);
        s[2] = h.sig;
        kind_helper_free(&h);
        check("настройки плагина появились — подпись другая", 1, s[0] != sig1);
        check("  переписаны — другая", 1, s[1] != s[0]);
        check("  убраны — снова прежняя", 1, s[2] == sig1);
    }

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

    /* Текущие запросы и более старая спека sp уже относятся к разным поколениям. */
    const struct plugin *hp = plugin_find("hp");
    const struct plugin_cmd *cmd0 = plugin_cmd_find("hp-cmd");
    const struct plugin_svc *svc0 = plugin_svc_at(0);
    size_t packages = plugin_n(), kinds = plugin_kinds_n();
    const struct plugin *old_pl[packages];
    const struct kind_ops *old_kind[kinds];
    for (size_t i = 0; i < packages; i++) old_pl[i] = plugin_at(i);
    for (size_t i = 0; i < kinds; i++) old_kind[i] = plugin_kind_ops_at(i);
    put("../etc/state.json", "{\"plugins\":{\"c-ge\":{\"enabled\":true},\"c-late\":{\"enabled\":true},"
                            "\"hp\":{\"enabled\":false,\"why\":\"paused\"}}}");
    fail_growth = 1;
    int rc = plugin_refresh();
    printf("refresh fault: rc=%d hits=%d packages=%zu/%zu kinds=%zu/%zu\n",
           rc, hits, plugin_n(), packages, plugin_kinds_n(), kinds);
    check("отказ перестроения не объявлен перечитыванием", -1, rc);
    check("инъекция сработала", 1, hits);
    check("карта пакетов не заменилась префиксом кандидата", packages, plugin_n());
    check("все виды на месте", kinds, plugin_kinds_n());
    int same = 1;
    for (size_t i = 0; i < packages; i++)
        if (plugin_at(i) != old_pl[i] || plugin_find(old_pl[i]->id) != old_pl[i]) same = 0;
    for (size_t i = 0; i < kinds; i++)
        if (plugin_kind_ops_at(i) != old_kind[i] || plugin_kind_find(old_kind[i]->name) != old_kind[i]->plugin) same = 0;
    check("перечисление и поиск сохранили каждый пакет и вид", 1, same);
    check("поиск по-прежнему возвращает старые адреса", 1,
          hp && plugin_find("hp") == hp && cmd0 && plugin_cmd_find("hp-cmd") == cmd0 &&
          svc0 && plugin_svc_at(0) == svc0 && plugin_kind_find("hpkind") == hp->kind[0]);
    rc = plugin_refresh();  /* ни одного изменения на диске после отказа */
    printf("refresh retry: rc=%d packages=%zu kinds=%zu\n", rc, plugin_n(), plugin_kinds_n());
    check("повтор на той же отметке публикует кандидата", 1, rc);
    check("опубликованы все записи пакетов", packages, plugin_n());
    check("индекс содержит ровно два разрешённых вида по порядку", 1, plugin_kinds_n() == 2 &&
          !strcmp(plugin_kind_ops_at(0)->name, "k-c-ge") && !strcmp(plugin_kind_ops_at(1)->name, "k-c-late"));
    check_str("отключение пакета — нормальный результат", "paused", why_of("hp"));
    check("выключенные команды и службы не видны", 1, !plugin_cmd_find("hp-cmd") && !plugin_svc_n());
    check("повтор после публикации ничего не меняет", 0, plugin_refresh());
    check("старые команда и служба сохраняют владельца", 1,
          cmd0 && svc0 && cmd0->owner == hp && svc0->owner == hp && hp->enabled &&
          !strcmp(cmd0->name, "hp-cmd") && !strcmp(svc0->name, "hp-svc"));
    check("ранее разобранная спека сохраняет kind_ops и данные своего поколения", 1,
          o && pk && out_plugin_kind(o) == pk && kind_of(o) == &pk->ops && pk->ops.plugin == pk &&
          pk->owner->enabled && !strcmp(pk->owner->version, "3.1.4") && pk->schema);
    /* Принудительный reload может быть нужен даже при прежней отметке. */
    fail_growth = 1;
    check("явный reload сообщает ошибку", -1, plugin_reload(NULL));
    check("повтор после явного отказа", 1, plugin_refresh());
    check("после исправного повтора отметка принята", 0, plugin_refresh());

    /* Удаление пакета (менеджер уносит каталог целиком) — исправное перечитывание. */
    char late[400], removed[400];
    snprintf(late, sizeof(late), "%s/c-late", g_root);
    snprintf(removed, sizeof(removed), "%s/removed", g_dir);
    check("каталог убран из реестра", 0, rename(late, removed));
    check("удалённый пакет не мешает перечитать реестр", 1, plugin_refresh());
    check("исчезли только удалённый пакет и его вид", 1,
          plugin_n() == packages - 1 && !plugin_find("c-late") && !plugin_kind_find("k-c-late") &&
          plugin_kinds_n() == 1 && plugin_kind_find("k-c-ge"));

    spec_release(&sp);
    spec_release(&sp2);
    char cmd[400];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", tmpl);
    if (system(cmd) != 0) {}
    return unit_done("pluginmodel");
}
