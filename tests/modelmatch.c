/* Стенд модели v2 и перевода спеки v1 (src/model/v1.c, src/kinds/group.c; docs/architecture.md,
 * «4в»).
 *
 * Что проверяется: спека v1 из текста превращается ровно в те правила, списки, клиенты, выходы и
 * группы, какие обещает перевод:
 *   - канал → правило с безымянными клиентом и списком; без своего `from` — без клиента, «кто» по
 *     умолчанию (sp->lan, прежний from_default);
 *   - `any` без списков — список «весь трафик», со списками ничего не значит;
 *   - `scope: device`, `mode: realip`, `enabled: false`, proto/ports — на своих местах;
 *   - выход с `devices` — группа pick: order (latency при `prefer: latency`) из безымянных
 *     членов-интерфейсов по одному на устройство; имя, метка, таблица, on_fail — у группы, и
 *     снаружи она видна прежним видом (interface); у безымянных членов меток нет;
 *   - один `devices` — прежний выход, не группа; `via` — `over`;
 *   - то, что перевод отвергает (пул с obfs, `kind: group` в v1, пулов больше MAX_ANON), и
 *     решения выбора группы (замер с допуском, гистерезис).
 * Что НЕ проверяется здесь: что v1 через модель даёт тот же ruleset — это снимок генератора
 * (tests/snapshot.sh), 118 вызовов apply --dry-run байт в байт.
 *
 * Модель линкуется отдельными объектами (MODEL_KINDS + awg.c, как у specmatch), без #include
 * чужого .c. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#include "unit.h"

static char g_tmp[256];
static struct spec g_spec;
static char g_msg[sizeof(((struct err *)0)->msg)];

/* Спека из текста: «TMP» заменяется каталогом стенда. 0 — разобрана (и метки розданы), -1 —
 * отказ, текст в g_msg. */
static int load(const char *tmpl) {
    char buf[16384], *o = buf;
    for (const char *s = tmpl; *s && o < buf + sizeof(buf) - 256; ) {
        if (!strncmp(s, "TMP", 3)) { o += sprintf(o, "%s", g_tmp); s += 3; }
        else *o++ = *s++;
    }
    *o = '\0';
    char p[512];
    snprintf(p, sizeof(p), "%s/spec.json", g_tmp);
    FILE *f = fopen(p, "w");
    if (!f) { perror(p); exit(2); }
    fputs(buf, f);
    fclose(f);
    struct err e = {0};
    g_msg[0] = '\0';
    if (load_spec(p, &g_spec, &e) < 0 || registry_assign(&g_spec, &e) < 0) {
        snprintf(g_msg, sizeof(g_msg), "%s", e.msg);
        return -1;
    }
    return 0;
}

static int has(const char *needle) { return strstr(g_msg, needle) != NULL; }

/* ---- каналы → правила, списки, клиенты ------------------------------------------------ */

static void t_rules(void) {
    check("каналы v1 разобраны", 0, load(
        "{\"schema\":2,\"from_default\":[\"192.168.1.0/24\"],"
        "\"outputs\":{\"direct\":{\"kind\":\"direct\"},\"vpn\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
        "\"channels\":["
        " {\"name\":\"yt\",\"match\":{\"domains_file\":\"TMP/yt.lst\"},\"out\":\"vpn\"},"
        " {\"name\":\"tv\",\"from\":[\"192.168.1.50\"],\"match\":{\"prefixes_files\":[\"TMP/a.lst\",\"TMP/b.lst\"],"
        "  \"mode\":\"realip\"},\"out\":\"direct\"},"
        " {\"name\":\"phone\",\"scope\":\"device\",\"from\":[\"aa:bb:cc:dd:ee:01\"],\"match\":{\"any\":true},\"out\":\"vpn\"},"
        " {\"name\":\"all\",\"match\":{\"any\":true,\"allow_all\":true,\"proto\":\"udp\",\"ports\":[\"50000-65535\"]},\"out\":\"vpn\"},"
        " {\"name\":\"off\",\"enabled\":false,\"match\":{\"any\":true,\"srs_file\":\"TMP/x.srs\"},\"out\":\"vpn\"}"
        "]}"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    check("правил — по каналу", 5, (long)g_spec.rule_n);
    check("списков — по каналу", 5, (long)g_spec.list_n);
    check("клиентов — только у каналов со своим from", 2, (long)g_spec.client_n);

    const struct spec_rule *r = &g_spec.rule[0];
    check_str("правило 0: имя канала", "yt", r->name);
    check_str("правило 0: выход по номеру", "vpn", rule_out(&g_spec, r)->name);
    check("правило 0: своего клиента нет", 0, (long)r->clients_n);
    check("правило 0: «кто» — клиенты по умолчанию", 1, rule_who(&g_spec, r) == &g_spec.lan);
    check_str("клиенты по умолчанию — from_default", "192.168.1.0/24",
              g_spec.lan.from_n ? g_spec.lan.from[0] : "");
    check("правило 0: один безымянный список", 1, r->lists_n == 1 && !rule_list(&g_spec, r)->name[0]);
    check("правило 0: доменный файл в списке", 1, rule_list(&g_spec, r)->domains_n == 1 &&
          strstr(rule_list(&g_spec, r)->domains_files[0], "yt.lst") != NULL);
    check("правило 0: не весь трафик", 0, rule_list(&g_spec, r)->all);

    r = &g_spec.rule[1];
    check("правило 1: свой безымянный клиент", 1, r->clients_n == 1 && rule_client(&g_spec, r) &&
          !rule_client(&g_spec, r)->name[0]);
    check_str("правило 1: адрес клиента", "192.168.1.50", rule_who(&g_spec, r)->from[0]);
    check("правило 1: два адресных файла", 2, (long)rule_list(&g_spec, r)->prefixes_n);
    check("правило 1: realip", 1, r->realip);
    check_str("правило 1: выход direct", "direct", rule_out(&g_spec, r)->name);

    r = &g_spec.rule[2];
    check("правило 2: на устройство", 1, r->dev_scope);
    check("правило 2: any без списков — весь трафик", 1, rule_list(&g_spec, r)->all);

    r = &g_spec.rule[3];
    check("правило 3: весь трафик с сужением", 1, rule_list(&g_spec, r)->all);
    check("правило 3: сужение udp", CH_PROTO_UDP, rule_list(&g_spec, r)->l4.proto);
    check("правило 3: порты 50000-65535", 1, rule_list(&g_spec, r)->l4.ports_n == 1 &&
          rule_list(&g_spec, r)->l4.ports[0].lo == 50000 &&
          rule_list(&g_spec, r)->l4.ports[0].hi == 65535);

    r = &g_spec.rule[4];
    check("правило 4: выключено", 1, r->disabled);
    check("правило 4: any рядом с набором — не весь трафик", 0, rule_list(&g_spec, r)->all);
    check("правило 4: набор .srs в списке", 1, (long)rule_list(&g_spec, r)->srs_n);

    /* Имена наборов считаются по правилам: клиенты по умолчанию — без суффикса, свой клиент —
     * номер различного списка клиентов в порядке правил (у tv — второй, c1). */
    char n0[64], n1[64];
    group_set_name(&g_spec, n0, sizeof(n0), "vpn", "dom", g_spec.lan.from, g_spec.lan.from_n, 0, NULL);
    check_str("имя набора правила без своих клиентов", "vpn_dom", n0);
    const struct spec_client *tv = rule_who(&g_spec, &g_spec.rule[1]);
    group_set_name(&g_spec, n1, sizeof(n1), "direct", "ip", tv->from, tv->from_n, 0, NULL);
    check_str("имя набора правила со своим клиентом", "direct_ip_c1", n1);

    check("allow_all спеки v1 по-прежнему нужен", -1, load(
        "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
        "\"outputs\":{\"vpn\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
        "\"channels\":[{\"name\":\"all\",\"match\":{\"any\":true},\"out\":\"vpn\"}]}"));
    check("… с прежним текстом", 1, has("allow_all"));
}

/* ---- выходы: пул → группа, via → over --------------------------------------------------- */

static void t_groups(void) {
    check("пул устройств разобран", 0, load(
        "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
        "\"outputs\":{\"direct\":{\"kind\":\"direct\"},"
        " \"pool\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"wg1\"],\"on_fail\":\"direct\"},"
        " \"one\":{\"kind\":\"interface\",\"devices\":[\"wg2\"]},"
        " \"fast\":{\"kind\":\"interface\",\"devices\":[\"wg3\",\"wg4\",\"wg5\"],\"prefer\":\"latency\","
        "  \"latency_tolerance_ms\":20,\"latency_interval_s\":60},"
        " \"odd\":{\"kind\":\"interface\",\"device\":\"wg6\",\"devices\":[\"wg7\"]}},"
        "\"channels\":[{\"name\":\"c\",\"match\":{\"prefixes_file\":\"TMP/a.lst\"},\"out\":\"pool\"}]}"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    check("именованных выходов — как в спеке", 5, (long)g_spec.out_n);
    check("безымянных членов — по устройству в пулах", 6, (long)g_spec.anon_n);

    struct output *p = &g_spec.out[1];
    const struct group_cfg *g = out_group(p);
    check_str("имя группы — прежнее имя выхода", "pool", p->name);
    check("пул стал группой", 1, g != NULL);
    check_str("снаружи — прежний вид", "interface", out_kind_name(p));
    check("pick: order", PICK_ORDER, g ? (long)g->pick : -1);
    check("членов два", 2, g ? (long)g->members_n : -1);
    size_t mn = out_members_n(&g_spec, p);
    const struct output *m[2] = { mn > 0 ? out_member(&g_spec, p, 0) : NULL,
                                  mn > 1 ? out_member(&g_spec, p, 1) : NULL };
    check("кандидаты группы — её члены", 2, (long)mn);
    check_str("член 0 — устройство wg0", "wg0", mn > 0 ? m[0]->device : "");
    check_str("член 1 — устройство wg1", "wg1", mn > 1 ? m[1]->device : "");
    check("члены безымянные", 1, mn == 2 && !m[0]->name[0] && !m[1]->name[0]);
    check_str("члены — интерфейсы", "interface", mn ? out_kind_name(m[0]) : "");
    check("члены лежат отдельно от именованных (sp->anon)", 1,
          mn == 2 && m[0] >= g_spec.anon && m[0] < g_spec.anon + g_spec.anon_n);
    check_str("активное до сторожа — первое устройство", "wg0", p->device);
    check("on_fail — у группы", FAIL_DIRECT, p->on_fail);
    check("у группы есть устройство (свойство членов)", 1, out_has_device(p));
    check("у группы метка", 1, out_needs_mark(p) && p->mark != 0);
    check("у группы таблица", 1, p->table != 0);
    check("у безымянных членов меток нет", 1, mn == 2 && !m[0]->mark && !m[1]->mark);
    check("своего сокета наверх у группы нет", 0, out_over_capable(p));
    check("процесса у группы нет", 0, out_engine_managed(p));
    check("выход по имени — группа", 1, out_by_name(&g_spec, "pool") == p);

    struct output *one = &g_spec.out[2];
    check("один devices — не группа", 1, out_group(one) == NULL);
    check_str("… устройство из devices", "wg2", one->device);
    mn = out_members_n(&g_spec, one);
    check("… кандидат — он сам", 1, mn == 1 && out_member(&g_spec, one, 0) == one);

    const struct group_cfg *f = out_group(&g_spec.out[3]);
    check("prefer: latency — pick: latency", PICK_LATENCY, f ? (long)f->pick : -1);
    check("… допуск", 20, f ? f->lat_tolerance_ms : -1);
    check("… интервал", 60, f ? f->lat_interval_s : -1);
    check("… членов три", 3, f ? (long)f->members_n : -1);
    check("допуск не задан — «не задан» (-1), умолчание 50 даёт group_tolerance_ms", 1,
          g && g->lat_tolerance_ms == -1 && group_tolerance_ms(g) == GROUP_TOL_DEFAULT_MS &&
          f && group_tolerance_ms(f) == 20);
    check("интервал не задан — умолчание 180", GROUP_INT_DEFAULT_S, g ? group_interval_s(g) : -1);

    struct output *odd = &g_spec.out[4];
    check("device и другое devices — группа", 1, out_group(odd) != NULL);
    check_str("… активное — названное device", "wg6", odd->device);
    mn = out_members_n(&g_spec, odd);
    check_str("… член — из devices", "wg7", mn ? out_member(&g_spec, odd, 0)->device : "");

    check("прямому выходу выбирать не из чего", 0, (long)out_members_n(&g_spec, &g_spec.out[0]));

    /* Ноль допуска законен («переключаться на любое улучшение», model/v1.c) и остаётся нулём: прежде
     * он читался как «не задан» и подменялся умолчанием 50 — group_tolerance_ms. */
    check("v1: latency_tolerance_ms 0 разобран", 0, load(
        "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
        "\"outputs\":{\"fast\":{\"kind\":\"interface\",\"devices\":[\"wg3\",\"wg4\"],"
        "\"prefer\":\"latency\",\"latency_tolerance_ms\":0}},\"channels\":[]}"));
    const struct group_cfg *z = g_spec.out_n ? out_group(&g_spec.out[0]) : NULL;
    check("… нулевой допуск остаётся нулём", 0, z ? group_tolerance_ms(z) : -1);

    check("via → over", 0, load(
        "{\"schema\":1,\"from_default\":[\"192.168.1.0/24\"],"
        "\"outputs\":{\"wg\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"wg1\"]},"
        " \"ob\":{\"kind\":\"interface\",\"device\":\"wg2\",\"via\":\"wg\","
        "  \"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
        "\"channels\":[]}"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    check_str("… подложка названа", "wg", g_spec.out[1].over);
    check("… и найдена: группа", 1, out_over(&g_spec, &g_spec.out[1]) == &g_spec.out[0]);
    check("… глубина 1", 1, out_over_depth(&g_spec, &g_spec.out[1]));
    check("… метка подложки — метка группы", 1,
          out_underlay_mark(&g_spec, &g_spec.out[1]) == (g_spec.out[0].mark | STEER_TUNNEL_BIT));

    check("дубликат устройства в пуле — отказ", -1, load(
        "{\"schema\":1,\"outputs\":{\"p\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"wg0\"]}},"
        "\"channels\":[]}"));
    check("… прежним текстом", 1, has("указано дважды"));

    check("пул с obfs — отказ", -1, load(
        "{\"schema\":1,\"outputs\":{\"p\":{\"kind\":\"interface\",\"devices\":[\"wg0\",\"wg1\"],"
        "\"obfs\":{\"server\":\"203.0.113.10:4567\",\"listen\":\"127.0.0.1:51820\"}}},"
        "\"channels\":[]}"));
    check("… сказано про obfs", 1, has("obfs"));

    check("kind group в спеке v1 — неизвестный вид", -1, load(
        "{\"schema\":1,\"outputs\":{\"g\":{\"kind\":\"group\"}},\"channels\":[]}"));
    check("… прежним текстом", 1, has("неизвестный kind"));

    check("awg с пулом — прежний отказ", -1, load(
        "{\"schema\":1,\"outputs\":{\"a\":{\"kind\":\"awg\",\"devices\":[\"x0\",\"x1\"]}},"
        "\"channels\":[]}"));
    check("… прежним текстом", 1, has("у kind awg одно устройство"));

    /* Пул из ста устройств и пять пулов по шестнадцать: безымянных членов сколько написано (раньше
     * «не больше 16 в пуле и 64 на спеку»). */
    {
        char *big = malloc(65536), *o = big;
        o += sprintf(o, "{\"schema\":1,\"outputs\":{");
        for (int i = 0; i < 5; i++) {
            o += sprintf(o, "%s\"p%d\":{\"kind\":\"interface\",\"devices\":[", i ? "," : "", i);
            for (int k = 0; k < 16; k++) o += sprintf(o, "%s\"d%d_%d\"", k ? "," : "", i, k);
            o += sprintf(o, "]}");
        }
        o += sprintf(o, ",\"big\":{\"kind\":\"interface\",\"devices\":[");
        for (int k = 0; k < 100; k++) o += sprintf(o, "%s\"e%d\"", k ? "," : "", k);
        sprintf(o, "]}},\"channels\":[]}");
        check("пулы на 80 + 100 устройств — принимаются", 0, load(big));
        check("безымянных членов 180", 180, (long)g_spec.anon_n);
        const struct output *bg = out_by_name(&g_spec, "big");
        check("в пуле из ста устройств сто кандидатов", 100, bg ? (long)out_members_n(&g_spec, bg) : -1);
        check_str("последний кандидат сотого пула — e99", "e99",
                  bg ? out_member(&g_spec, bg, 99)->device : "");
        free(big);
    }
}

/* ---- спека v2 → та же модель (src/model/v2.c) --------------------------------------------- */

static void t_v2(void) {
    check("v2: разобрана", 0, load(
        "version: 2\n"
        "lan: { devices: [br-lan, tailscale0] }\n"
        "clients:\n"
        "  kids: { mac: [aa:bb:cc:dd:ee:01] }\n"
        "  tv:   { mac: [aa:bb:cc:dd:ee:02] }\n"
        "lists:\n"
        "  a: { prefixes_file: TMP/a.lst }\n"
        "  b: { prefixes_file: [TMP/b.lst], domains_file: TMP/yt.lst }\n"
        "  v: { prefixes_file: TMP/a.lst, proto: udp, ports: [\"50000-65535\", 3478] }\n"
        "outputs:\n"
        "  wg0: { kind: interface, device: wg0 }\n"
        "  wg1: { kind: interface, device: wg1, on_fail: direct }\n"
        "  res: { kind: group, pick: latency, members: [wg1, wg0], tolerance: 70, interval: 60 }\n"
        "dns: { mode: realip }\n"
        "rules:\n"
        "  - { name: two, for: [kids, tv], to: [a, b], out: res }\n"
        "  - { to: v, out: wg0, resolve: fakeip, enabled: false }\n"
        "  - { name: all, for: lan, to: all, out: wg1 }\n"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    check("v2: выходы — именованные, без безымянных", 3, (long)g_spec.out_n);
    check("v2: безымянных нет", 0, (long)g_spec.anon_n);
    const struct output *g = out_by_name(&g_spec, "res");
    const struct group_cfg *gc = g ? out_group(g) : NULL;
    check("v2: res — группа", 1, gc != NULL);
    if (gc) {
        check("v2: pick latency", PICK_LATENCY, gc->pick);
        check("v2: члены — именованные выходы по номеру", 1,
              gc->members_n == 2 && gc->members[0] == 1 && gc->members[1] == 0);
        check("v2: допуск и интервал", 1, gc->lat_tolerance_ms == 70 && gc->lat_interval_s == 60);
        check_str("v2: видна как group", "group", out_kind_name(g));
        check_str("v2: активное — первый член", "wg1", g->device);
        check("v2: метка у группы", 1, g->mark != 0);
    }
    check("v2: lan — два устройства", 2, (long)g_spec.lan_dev_n);
    const struct spec_rule *r = &g_spec.rule[0];
    check("v2: два клиента одного вида сведены в один безымянный", 1,
          r->clients_n == 1 && !rule_client(&g_spec, r)->name[0] && rule_client(&g_spec, r)->from_n == 2);
    check("v2: два списка без сужения сведены в один", 1, r->lists_n == 1 && !rule_list(&g_spec, r)->name[0]);
    check("v2: … файлы обоих", 1, rule_list(&g_spec, r)->prefixes_n == 2 && rule_list(&g_spec, r)->domains_n == 1);
    check("v2: dns.mode realip — умолчание правила", 1, r->realip);
    r = &g_spec.rule[1];
    check_str("v2: имя по умолчанию — номер", "rule-2", r->name);
    check("v2: resolve fakeip перекрывает dns.mode", 0, r->realip);
    check("v2: enabled: false", 1, r->disabled);
    check("v2: сужение списка", 1, rule_list(&g_spec, r)->l4.proto == CH_PROTO_UDP &&
          rule_list(&g_spec, r)->l4.ports_n == 2 && rule_list(&g_spec, r)->l4.ports[1].lo == 3478);
    r = &g_spec.rule[2];
    check("v2: to: all — весь трафик, без списка", 1, r->lists_n == 0 && rule_list(&g_spec, r)->all);
    check("v2: for: lan — клиенты по умолчанию", 1, r->clients_n == 0 && rule_who(&g_spec, r) == &g_spec.lan);

    /* Апстримы и кэш (с 1.11) читаются и хранятся в модели. */
    check("v2: dns.upstreams — принято", 0, load(
        "version: 2\n"
        "outputs: { vpn: { kind: interface, device: wg0 } }\n"
        "dns: { cache: 512, upstreams: { doh: { url: \"https://1.1.1.1/dns-query\", out: vpn } } }\n"
        "rules: [ { to: all, out: vpn, dns: doh } ]\n"));
    check("… протокол DoH, порт 443", 1, g_spec.dns.up[0].proto == DNSP_DOH && g_spec.dns.up[0].port == 443);
    check("… апстрим в модели", 1, g_spec.dns.up_n == 1 && g_spec.dns.up[0].out == 0 &&
          !strcmp(g_spec.dns.up[0].name, "doh"));
    check("… кэш в модели", 512, g_spec.dns.cache);
    check("… апстрим правила", 1, g_spec.rule_n == 1 && g_spec.rule[0].dns == 1);
}

/* ---- шаг 3: manual, balance, вложенность, urltest ----------------------------------------- */

static void t_groups_v2(void) {
    check("группы шага 3 разобраны", 0, load(
        "version: 2\n"
        "outputs:\n"
        "  a:   { kind: interface, device: wg0 }\n"
        "  b:   { kind: interface, device: wg1 }\n"
        "  res: { kind: group, members: [a, b] }\n"
        "  top: { kind: group, pick: order, members: [res, b] }\n"
        "  man: { kind: group, pick: manual, members: [a, top], default: top }\n"
        "  bal: { kind: group, pick: balance, members: [res, b], weights: [3, 1] }\n"
        "  lat: { kind: group, pick: latency, members: [a, b], url: \"http://example.net:8080/x\", idle_timeout: 90 }\n"
        "  strict: { kind: group, pick: latency, members: [a, b], tolerance: 0 }\n"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    const struct output *top = out_by_name(&g_spec, "top"), *man = out_by_name(&g_spec, "man");
    const struct output *bal = out_by_name(&g_spec, "bal"), *lat = out_by_name(&g_spec, "lat");
    check("вложенная группа — член внешней, у внешней устройство (свойство членов)", 1,
          top && out_has_device(top) && out_needs_mark(top));
    check_str("активное устройство внешней — лист первого члена (вложенной)", "wg0", top ? top->device : "");
    check("manual: default — номер члена", 1, man && out_group(man)->def == 1 && group_named(out_group(man)));
    check("balance: веса по членам", 31, bal ? out_group(bal)->weight[0] * 10 + out_group(bal)->weight[1] : 0);
    check_str("latency: url", "http://example.net:8080/x", lat ? out_group(lat)->url : "");
    check("latency: idle_timeout", 90, lat ? out_group(lat)->idle_timeout_s : -1);
    const struct output *strict = out_by_name(&g_spec, "strict");
    check("latency: допуск не задан — умолчание", GROUP_TOL_DEFAULT_MS, lat ? group_tolerance_ms(out_group(lat)) : -1);
    check("latency: tolerance: 0 — настоящий ноль, а не умолчание", 0,
          strict ? group_tolerance_ms(out_group(strict)) : -1);
    check("без idle_timeout — умолчание платформы (-1)", -1, top ? out_group(top)->idle_timeout_s : 0);
    check("состояние сторожа до прохода — «нет»", 1,
          man && out_group(man)->cur == -1 && out_group(man)->sel == -1 && out_group(man)->lat_ms[0] == -1);

    check("balance без by — случайно (connection)", BY_CONNECTION, bal ? out_group(bal)->by : -1);

    /* by: как balance раздаёт новые соединения — случайно, по сайту, по сайту и устройству. */
    check("balance: by: site и site_client — приняты", 0, load(
        "version: 2\n"
        "outputs:\n"
        "  a:  { kind: interface, device: wg0 }\n"
        "  b:  { kind: interface, device: wg1 }\n"
        "  s:  { kind: group, pick: balance, by: site, members: [a, b] }\n"
        "  sc: { kind: group, pick: balance, by: site_client, members: [a, b] }\n"
        "  c:  { kind: group, pick: balance, by: connection, members: [a, b] }\n"));
    if (g_msg[0]) printf("     %s\n", g_msg);
    check("  by: site — BY_SITE", BY_SITE, out_by_name(&g_spec, "s") ? out_group(out_by_name(&g_spec, "s"))->by : -1);
    check("  by: site_client — BY_SITE_CLIENT", BY_SITE_CLIENT,
          out_by_name(&g_spec, "sc") ? out_group(out_by_name(&g_spec, "sc"))->by : -1);
    check("  by: connection — BY_CONNECTION", BY_CONNECTION,
          out_by_name(&g_spec, "c") ? out_group(out_by_name(&g_spec, "c"))->by : -1);
    check("by не у balance — отказ", -1, load(
        "version: 2\n"
        "outputs:\n"
        "  a: { kind: interface, device: wg0 }\n"
        "  b: { kind: interface, device: wg1 }\n"
        "  o: { kind: group, pick: order, by: site, members: [a, b] }\n"));
    check("… с объяснением", 1, has("by — как раздавать соединения, он есть только у pick: balance"));
    check("by неверный — отказ", -1, load(
        "version: 2\n"
        "outputs:\n"
        "  a: { kind: interface, device: wg0 }\n"
        "  b: { kind: interface, device: wg1 }\n"
        "  x: { kind: group, pick: balance, by: random, members: [a, b] }\n"));
    check("… со списком значений", 1, has("«random» — нужен connection, site или site_client"));
    check("by у выхода не-группы — отказ", -1, load(
        "version: 2\n"
        "outputs:\n"
        "  a: { kind: interface, device: wg0, by: site }\n"));
    check("… ключ группы", 1, has("by есть только у kind: group"));

    check("balance членом order — отказ", -1, load(
        "version: 2\n"
        "outputs:\n"
        "  a: { kind: interface, device: wg0 }\n"
        "  b: { kind: interface, device: wg1 }\n"
        "  x: { kind: group, pick: balance, members: [a, b] }\n"
        "  y: { kind: group, pick: order, members: [x, a] }\n"));
    check("… с объяснением", 1, has("членом группы pick: order она быть не может"));

    /* Слоты карты balance: по весам живых методом наибольшего остатка. */
    static struct spec gs;
    struct group_cfg g;
    group_cfg_init(&g);
    group_members_alloc(&gs, &g, 7);
    g.members_n = 3;
    g.weight[0] = 2;
    unsigned char own[GROUP_BAL_SLOTS];
    int cnt[4];
    const unsigned char alive3[3] = { 1, 1, 1 }, alive_no1[3] = { 0, 1, 1 };
    group_balance_slots(&g, alive3, own);
    memset(cnt, 0, sizeof(cnt));
    for (int s = 0; s < GROUP_BAL_SLOTS; s++) cnt[own[s] == 0xff ? 3 : own[s]]++;
    check("слоты: веса 2:1:1 — 60/30/30", 603030, cnt[0] * 10000L + cnt[1] * 100L + cnt[2]);
    group_balance_slots(&g, alive_no1, own);
    memset(cnt, 0, sizeof(cnt));
    for (int s = 0; s < GROUP_BAL_SLOTS; s++) cnt[own[s] == 0xff ? 3 : own[s]]++;
    check("слоты: первый упал — 0/60/60", 6060, cnt[0] * 10000L + cnt[1] * 100L + cnt[2]);
    g.members_n = 7;
    memset(g.weight, 0, 7);
    group_balance_slots(&g, NULL, own);                 /* NULL — все живы */
    memset(cnt, 0, sizeof(cnt));
    int mx = 0, mn = GROUP_BAL_SLOTS, per[7] = {0};
    for (int s = 0; s < GROUP_BAL_SLOTS; s++) per[own[s]]++;
    for (int k = 0; k < 7; k++) { if (per[k] > mx) mx = per[k]; if (per[k] < mn) mn = per[k]; }
    check("слоты: семь равных — 17 или 18 у каждого", 1718, mn * 100L + mx);
    /* Слоты живых при уходе члена не двигаются (by: site — слот это сайты): уходит b из трёх
     * равных — у a и c остаются ВСЕ их прежние слоты, и добирают они только слоты b; вернулся b —
     * карта снова та же, что при всех живых. */
    {
        unsigned char all[GROUP_BAL_SLOTS], nob[GROUP_BAL_SLOTS], back[GROUP_BAL_SLOTS];
        const unsigned char alive_b0[3] = { 1, 0, 1 }, alive3b[3] = { 1, 1, 1 };
        g.members_n = 3;
        memset(g.weight, 0, 7);
        group_balance_slots(&g, NULL, all);
        group_balance_slots(&g, alive_b0, nob);
        group_balance_slots(&g, alive3b, back);
        int moved = 0, got_b = 0, ca = 0, cc = 0;
        for (int s = 0; s < GROUP_BAL_SLOTS; s++) {
            if (all[s] != 1 && nob[s] != all[s]) moved++;
            if (all[s] == 1 && (nob[s] == 0 || nob[s] == 2)) got_b++;
            ca += nob[s] == 0;
            cc += nob[s] == 2;
        }
        check("слоты: b ушёл — слоты a и c на месте", 0, moved);
        check("  слоты b розданы живым поровну — 60/60", 6060, ca * 100L + cc);
        check("  все 40 слотов b — живым", 40, got_b);
        check("  b вернулся — карта как при всех живых", 0, memcmp(all, back, sizeof(all)));
        /* Веса 1:2:3, уходит a — c и b сохраняют свои слоты, доли живых — 40/80. */
        g.weight[0] = 1; g.weight[1] = 2; g.weight[2] = 3;
        const unsigned char alive_a0[3] = { 0, 1, 1 };
        group_balance_slots(&g, NULL, all);
        group_balance_slots(&g, alive_a0, nob);
        int cb = 0, kept = 0;
        moved = 0;
        for (int s = 0; s < GROUP_BAL_SLOTS; s++) {
            cb += nob[s] == 1;
            kept += all[s] != 0 && nob[s] == all[s];
            if (all[s] != 0 && nob[s] != all[s]) moved++;
        }
        check("слоты: веса 1:2:3, a ушёл — b 48 из 120, слоты b и c на месте", 4800, cb * 100L + moved);
        check("  у живых по-прежнему все 100 их слотов", 100, kept);
        memset(g.weight, 0, 7);
    }
    g.members_n = 7;
    const unsigned char none7[7] = { 0 };
    group_balance_slots(&g, none7, own);
    check("слоты: живых нет — карта пуста", 0xff, own[0] == 0xff && own[GROUP_BAL_SLOTS - 1] == 0xff ? 0xff : 0);
    /* Много членов: карта делится между шестьюдесятью — у каждого хотя бы слот; больше слотов, чем
     * их есть, balance не принимает (group_seal, предел — свойство карты). */
    group_cfg_init(&g);
    group_members_alloc(&gs, &g, 60);
    g.members_n = 60;
    group_balance_slots(&g, NULL, own);
    int empty = 0, over60 = 0;
    int per60[60] = {0};
    for (int s = 0; s < GROUP_BAL_SLOTS; s++) { if (own[s] >= 60) over60++; else per60[own[s]]++; }
    for (int k = 0; k < 60; k++) empty += per60[k] == 0;
    check("слоты: 60 членов — у каждого не меньше слота", 0, empty + over60);
    spec_release(&gs);
}

/* ---- решения выбора группы --------------------------------------------------------------- */

static void t_pick(void) {
    int best = 0;
    int ms1[] = { 200, 20 };
    check("замер: заметно быстрее — запас", 1, group_latency_pick(ms1, 2, 50, &best));
    check("… лучший 20", 20, best);
    int ms2[] = { 40, 20 };
    check("замер: внутри допуска — порядок", 0, group_latency_pick(ms2, 2, 50, &best));
    check("замер: свой допуск делает разницу значимой", 1, group_latency_pick(ms2, 2, 10, &best));
    int ms3[] = { -1, -1 };
    check("замер: никто не измерен", -1, group_latency_pick(ms3, 2, 50, &best));
    check("… лучшего нет", -1, best);
    int ms4[] = { -1, 30, 25 };
    check("замер: неизмеренный пропускается", 1, group_latency_pick(ms4, 3, 50, &best));
    check("с живого текущего — только за выигрыш больше допуска", 1, group_latency_keep(ms2, 1, 0, 50));
    check("… а за больший — уходим", 0, group_latency_keep(ms1, 0, 1, 50));

    /* По обоим семействам (group_latency_score): худший из двух, не ответивший по IPv6 выбывает;
     * по IPv6 не ответил никто — выбор по IPv4. */
    int a4[] = { 20, 60 }, a6[] = { 300, 70 }, sc[2];
    group_latency_score(a4, a6, 2, sc);
    check("IPv4+IPv6: у члена худший из двух", 1, sc[0] == 300 && sc[1] == 70);
    check("… и выбор — ровный по обоим, хоть он медленнее по IPv4", 1,
          group_latency_pick(sc, 2, 50, &best));
    int b4[] = { 20, 60 }, b6[] = { -1, 70 };
    group_latency_score(b4, b6, 2, sc);
    check("IPv6 у члена не ответил — член выбыл", 1, sc[0] == -1 && sc[1] == 70);
    int c4[] = { 20, 60 }, c6[] = { -1, -1 };
    group_latency_score(c4, c6, 2, sc);
    check("по IPv6 не ответил никто — по IPv4", 1, sc[0] == 20 && sc[1] == 60);
    int d4[] = { -1, 60 }, d6[] = { 30, 70 };
    group_latency_score(d4, d6, 2, sc);
    check("IPv4 у члена не ответил — член выбыл и по обоим", 1, sc[0] == -1 && sc[1] == 70);

    /* ПОЧЕМУ ГРУППА НА ЭТОМ ЧЛЕНЕ (status, group.why): «первый живой», о котором говорят
     * «самый быстрый не работает», — это либо допуск (in_tolerance), либо замера нет (no_measure). */
    int fa = -2;
    unsigned char al2[] = { 1, 1 }, al3[] = { 1, 0, 1 };
    int w1[] = { 200, 20 };
    check("why: выбран самый быстрый", GW_FASTEST, group_latency_why(w1, al2, 2, 1, 50, &fa));
    check("… он и назван", 1, fa);
    check("why: выбран не самый быстрый, но внутри допуска", GW_TOLERANCE,
          group_latency_why(ms2, al2, 2, 0, 50, &fa));
    check("… самый быстрый назван, хоть выбран не он", 1, fa);
    check("why: хуже самого быстрого больше допуска — ждёт прохода", GW_PENDING,
          group_latency_why(w1, al2, 2, 0, 50, &fa));
    check("why: допуск 0 — любая разница значима", GW_PENDING, group_latency_why(ms2, al2, 2, 0, 0, &fa));
    check("why: у равных по замеру — самый быстрый", GW_FASTEST,
          group_latency_why(ms2, al2, 2, 1, 0, &fa));
    check("why: замера нет ни у кого — по порядку", GW_NOMEASURE, group_latency_why(ms3, al2, 2, 0, 50, &fa));
    check("… самого быстрого нет", -1, fa);
    int w4[] = { 30, -1 };
    check("why: выбранный жив, но не измерен, другие измерены", GW_UNMEASURED,
          group_latency_why(w4, al2, 2, 1, 50, &fa));
    int w5[] = { 200, 5, 20 };
    check("why: упавший самый быстрый в счёт не идёт", GW_FASTEST, group_latency_why(w5, al3, 3, 2, 50, &fa));
    check("… самый быстрый — из живых", 2, fa);
    check("why: группа никого не выбрала", GW_NONE, group_latency_why(w1, al2, 2, -1, 50, &fa));
    check_str("имя: fastest", "fastest", group_why_name(GW_FASTEST));
    check_str("имя: in_tolerance", "in_tolerance", group_why_name(GW_TOLERANCE));
    check_str("имя: no_measure", "no_measure", group_why_name(GW_NOMEASURE));
    check_str("имя: pending", "pending", group_why_name(GW_PENDING));
    check_str("имя: unmeasured", "unmeasured", group_why_name(GW_UNMEASURED));
    check("имени у GW_NONE нет", 1, group_why_name(GW_NONE) == NULL);

    int ns = -1;
    check("гистерезис: держим живое текущее", 1, group_hysteresis(1, 0, 1, 0, 3, &ns));
    check("… серия растёт", 1, ns);
    check("… третий тик — возврат наверх", 0, group_hysteresis(1, 0, 1, 2, 3, &ns));
    check("… серия сброшена", 0, ns);
    check("гистерезис: мёртвое текущее — сразу вниз", 0, group_hysteresis(1, 0, 0, 1, 3, &ns));
    check("гистерезис: без порога — сразу", 0, group_hysteresis(1, 0, 1, 0, 0, &ns));
    check("гистерезис: несём лучшее — его и берём", 0, group_hysteresis(0, 0, 1, 5, 3, &ns));
}

int main(void) {
    snprintf(g_tmp, sizeof(g_tmp), "/tmp/modelmatch-XXXXXX");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 2; }
    steer_set_state_dir(g_tmp);
    t_rules();
    t_groups();
    t_v2();
    t_groups_v2();
    t_pick();
    char cmd[320];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmp);
    if (system(cmd) != 0) fprintf(stderr, "modelmatch: не убран %s\n", g_tmp);
    return unit_done("modelmatch");
}
