/* Сторона плагина в API ядра (src/plugkit) без сети и без ядра.
 *
 *   - JSON (pkjson.c): разбор, отказы с местом, \u и суррогатные пары, пути;
 *   - {conf} (plugkit.c): поля выхода и каталоги, метка сокетов без {conf}, файл состояния и его имя;
 *   - ключи туннеля (pktun.c): разбор, сочетания (то, чего схема вида не выражает), порядок перебора узлов
 *     и «назван ли узел» — прежде это жило в видах ядра (kinds/vless.c), теперь — у программы плагина;
 *   - точка входа (pk_main): подкоманды, флаги, --conf. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pktun.h"
#include "plugkit.h"
#include "pkjson.h"
#include "platform.h"

static int fails, passes;

static void check(const char *what, long want, long got) {
    if (want == got) { passes++; return; }
    fails++;
    printf("FAIL %s\n  expected: %ld\n  actual:   %ld\n", what, want, got);
}

static void check_s(const char *what, const char *want, const char *got) {
    if (got && !strcmp(want, got)) { passes++; return; }
    fails++;
    printf("FAIL %s\n  expected: %s\n  actual:   %s\n", what, want, got ? got : "(null)");
}

static struct pkj *J(const char *s) {
    char err[200];
    return pkj_parse(s, strlen(s), err, sizeof err);
}

static void t_json(void) {
    struct pkj *j = J("{\"a\":[1,2,{\"b\":\"x\\u00e9\\ud83d\\ude00\"}],\"t\":true,\"n\":null,\"f\":-1.5}");
    check("json: разобран", 1, j != NULL);
    if (!j) return;
    check("json: длина массива", 3, (long)pkj_len(pkj_get(j, "a")));
    check_s("json: \\u и суррогатная пара — UTF-8", "x\xc3\xa9\xf0\x9f\x98\x80", pkj_str(pkj_get(pkj_at(pkj_get(j, "a"), 2), "b")));
    int b = 0;
    check("json: булево", 0, pkj_bool(pkj_get(j, "t"), &b));
    check("  true", 1, b);
    long v;
    check("json: дробное — не целое", -1, pkj_long(pkj_get(j, "f"), &v));
    check("json: целое", 0, pkj_long(pkj_at(pkj_get(j, "a"), 1), &v));
    check("  2", 2, v);
    check("json: путь", 1, pkj_path(j, "a") != NULL);
    pkj_free(j);
    char err[200];
    check("json: висящая запятая — отказ", 1, pkj_parse("[1,]", 4, err, sizeof err) == NULL);
    check("  с местом", 1, strstr(err, "байт") != NULL);
    check("json: мусор после документа — отказ", 1, pkj_parse("{} x", 4, err, sizeof err) == NULL);
    check("json: управляющий байт в строке — отказ", 1, pkj_parse("\"a\nb\"", 5, err, sizeof err) == NULL);
    check("json: строка не закрыта — отказ", 1, pkj_parse("\"abc", 4, err, sizeof err) == NULL);
    check("json: пустой документ — отказ", 1, pkj_parse("", 0, err, sizeof err) == NULL);
}

static const char *CONF =
    "{\"api\":\"1.1\",\"plugin\":{\"id\":\"vless\",\"version\":\"2.1.0\"},"
    "\"output\":{\"name\":\"nl\",\"kind\":\"tunnel:vless\",\"keys\":{\"subscription\":\"/etc/steer/sub/nl\","
    "\"nodes\":[3,1],\"transport\":\"ws\",\"exclude\":[\"RU\"],\"exclude_name\":\"lte\",\"active\":2,\"by\":\"site\","
    "\"silence\":0,\"pick\":\"latency\",\"tolerance\":0},\"device\":\"nl\",\"mark\":\"0x00300000\","
    "\"mark_mask\":\"0x0ff00000\",\"table\":302,\"ipv6\":false,\"on_fail\":\"drop\",\"over\":{\"name\":\"wg0\","
    "\"mark\":\"0x00100000\"},\"sock_mark\":\"0x00100000\",\"sock_mark_required\":true,\"tcp_port\":9482,"
    "\"ports\":[],\"queues\":[]},\"paths\":{\"etc\":\"/etc/steer\",\"state\":\"/var/lib/steer\","
    "\"plugin_state\":\"%s\",\"fakeip\":\"/var/lib/steer/fakeip.state\"},\"platform\":\"openwrt\"}";

static void t_conf(const char *dir) {
    char path[512], txt[2048], err[300];
    snprintf(path, sizeof path, "%s/nl.json", dir);
    snprintf(txt, sizeof txt, CONF, dir);
    FILE *f = fopen(path, "w");
    if (!f) { check("conf: файл", 0, -1); return; }
    fputs(txt, f);
    fclose(f);
    struct pk_out o;
    check("conf: прочитан", 0, pk_conf_load(path, &o, err, sizeof err));
    check_s("conf: имя", "nl", o.tun.name);
    check_s("conf: вид", "tunnel:vless", o.kind);
    check_s("conf: устройство", "nl", o.tun.device);
    check("conf: метка", 0x00300000, (long)o.tun.mark);
    check("conf: таблица", 302, o.tun.table);
    check("conf: порт слушателя", 9482, o.tun.tcp_port);
    check("conf: метка сокетов", 0x00100000, (long)o.sock_mark);
    check("conf: метка обязательна", 1, o.sock_mark_required);
    check("conf: IPv6 снят", 0, o.ipv6);
    check_s("conf: подложка", "wg0", o.over);
    check_s("conf: fake-IP", "/var/lib/steer/fakeip.state", o.fakeip);
    char sp[600];
    snprintf(sp, sizeof sp, "%s/nl.status.json", dir);
    check_s("conf: файл состояния — <plugin_state>/<выход>.status.json", sp, o.status_path);
    check("conf: метка сокетов из {conf}", 0x00100000, (long)pk_sock_mark(&o));
    check("без {conf}: «мимо каналов» платформы", (long)plat()->self_mark, (long)pk_sock_mark(NULL));

    struct pk_tun t;
    check("tun: ключи прочитаны", 0, pk_tun_load(&o, &t, err, sizeof err));
    check_s("tun: подписка", "/etc/steer/sub/nl", t.sub_file);
    check("tun: узлов два", 2, (long)t.nodes_n);
    check("tun: транспорт ws одним словом", (long)TT_WS, (long)t.transports);
    check("tun: страна исключена", 1, (long)t.excl.cc_n);
    check("tun: кусок имени", 1, (long)t.excl.names_n);
    check("tun: active", 2, t.pool.active);
    check("tun: by site", 1, t.pool.by);
    check("tun: silence: 0 — порог выключен явно", -1, t.pool.silence_s);
    check("tun: pick latency", 1, t.pool.pick);
    check("tun: tolerance 0 — задан", 1, t.pool.tol_set);
    check("tun: сочетания годятся", 0, pk_tun_check(&t, err, sizeof err));
    /* Порядок перебора — выбор человека, в его порядке; номер вне подписки пропускается. */
    int dst[8];
    check("перебор: выбранные в пределах подписки", 2, (long)pk_node_list(&t, 4, dst, 8));
    check("  порядок как написан", 1, dst[0] == 3 && dst[1] == 1);
    check("перебор: подписка укоротилась — устаревший номер пропущен", 1, (long)pk_node_list(&t, 2, dst, 8));
    check("перебор: целиком вне подписки — кандидатов нет", 0, (long)pk_node_list(&t, 1, dst, 8));
    check("узел назван: двое — нет", 0, pk_node_named(&t));
    struct pk_tun e = { 0 };
    check("перебор без выбора — вся подписка", 3, (long)pk_node_list(&e, 3, dst, 8));
    int one[1] = { 4 };
    e.nodes = one;
    e.nodes_n = 1;
    check("узел назван: номер написан", 1, pk_node_named(&e));
    /* Сочетания, которых схема вида не выражает. */
    struct pk_tun c = t;
    c.pool.active = 1;
    check("by без active больше 1 — отказ", -1, pk_tun_check(&c, err, sizeof err));
    c = t;
    c.pool.active = 5;
    check("active больше выбранных — отказ", -1, pk_tun_check(&c, err, sizeof err));
    c = t;
    c.pool.pick = 0;
    check("tolerance без pick: latency — отказ", -1, pk_tun_check(&c, err, sizeof err));
    c = t;
    c.pool.silence_s = 3;
    check("silence 3 с — отказ", -1, pk_tun_check(&c, err, sizeof err));
    char only[1][3] = { "RU" };
    c = t;
    c.excl.only = only;
    c.excl.only_n = 1;
    check("страна и в only, и в exclude — отказ", -1, pk_tun_check(&c, err, sizeof err));
    check("  причина названа", 1, strstr(err, "RU") != NULL);

    /* Файл состояния: атомарно, в своё место. */
    check("состояние записано", 0, pk_status_write(&o, "{\"up\":true}"));
    FILE *s = fopen(o.status_path, "r");
    char line[64] = "";
    if (s) { if (!fgets(line, sizeof line, s)) line[0] = '\0'; fclose(s); }
    check_s("  содержимое", "{\"up\":true}\n", line);
    unlink(o.status_path);
    unlink(path);
}

/* Точка входа: флаги команды, позиционные, --conf. */
static const char *g_seen;
static int r_probe(const struct pk_args *a) {
    static char b[256];
    snprintf(b, sizeof b, "%s|%s|%s|%s|%s", a->cmd, a->npos ? a->pos[0] : "-", pk_opt(a, "node") ? pk_opt(a, "node") : "-",
             pk_has(a, "insecure") ? "i" : "-", a->out ? a->out->tun.name : "-");
    g_seen = b;
    return 7;
}
static const struct pk_cmd CMDS[] = {
    { "x-probe", "<выход|/файл>", 1, 1, "node: insecure", "проба", 0, r_probe },
};

static void t_main(const char *dir) {
    char conf[512], txt[2048];
    snprintf(conf, sizeof conf, "%s/nl.json", dir);
    snprintf(txt, sizeof txt, CONF, dir);
    FILE *f = fopen(conf, "w");
    fputs(txt, f);
    fclose(f);
    char *a1[] = { "x", "x-probe", "/tmp/sub", "--node", "-1", "--insecure", NULL };
    check("main: код подкоманды", 7, pk_main(6, a1, "x", "1.0", CMDS, 1));
    check_s("main: позиционное, флаг со значением -1, флаг без значения", "x-probe|/tmp/sub|-1|i|-", g_seen);
    char *a2[] = { "x", "x-probe", "nl", "--conf", conf, NULL };
    check("main: с --conf", 7, pk_main(5, a2, "x", "1.0", CMDS, 1));
    check_s("main: выход из {conf}", "x-probe|nl|-|-|nl", g_seen);
    check("main: {conf} процесса", 1, pk_out() != NULL);
    unlink(conf);
}

int main(void) {
    char dir[] = "/tmp/pkmatch-XXXXXX";
    if (!mkdtemp(dir)) { perror("mkdtemp"); return 1; }
    t_json();
    t_conf(dir);
    t_main(dir);
    rmdir(dir);
    printf("pkmatch: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
