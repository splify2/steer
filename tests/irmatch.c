/* Стенд дерева набора правил (src/lib/ir.h): генератор строит дерево по спеке, стенд
 * проверяет его СТРУКТУРУ запросами к дереву — какие таблицы, цепочки с каким хуком и
 * приоритетом, правило с каким комментарием смотрит в какой набор, какие у набора флаги и
 * откуда его элементы, — а не сравнением текста.
 *
 * Зачем, если есть снимок (tests/snapshot.sh). Снимок отвечает «текст не изменился» и молчит о
 * том, ЧТО в нём стоит: переделанное дерево, которое печатается тем же текстом, он пропустит, а
 * верное изменение текста потребует перезаписи снимка, после которой уже не видно, что именно
 * должно было остаться. Здесь записаны сами свойства — «у доменного набора в старой раскладке
 * две половины и по правилу на каждую», «nat уходит из inet в ip», — и они переживают любую
 * перезапись снимка.
 *
 * Модули линкуются (Makefile: MODEL_SRC и COMPILE_SRC), не подключаются #include.
 * Собирается дважды: роутер и телефон (-DSTEER_DEFAULT_PLATFORM=android — платформа телефона,
 * цепочки на output; выходов zapret и tgws у телефона нет, поэтому случаи с ними — только на
 * роутере). Какие случаи гонять, решает выбранная платформа, а не ключ сборки. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#include "groups.h"
#include "generate.h"
#include "unit.h"

static char g_tmp[256];
static struct spec g_spec;
static struct groups g_gr;

static void put(const char *name, const char *text) {
    char p[512];
    snprintf(p, sizeof(p), "%s/%s", g_tmp, name);
    FILE *f = fopen(p, "w");
    if (!f) { perror(p); exit(2); }
    fputs(text, f);
    fclose(f);
}

/* Спека из текста: «TMP» заменяется каталогом стенда. Разбор, метки выходов, группы и
 * проверка списков — ровно те шаги, что делает cmd_apply перед генерацией. */
static int load(const char *tmpl) {
    char buf[4096], *o = buf;
    for (const char *s = tmpl; *s && o < buf + sizeof(buf) - 256; ) {
        if (!strncmp(s, "TMP", 3)) { o += sprintf(o, "%s", g_tmp); s += 3; }
        else *o++ = *s++;
    }
    *o = '\0';
    put("spec.json", buf);
    spec_release(&g_spec);              /* load_spec ставит умолчания (br-lan) сам */
    char p[512];
    snprintf(p, sizeof(p), "%s/spec.json", g_tmp);
    struct err e = {0};
    if (load_spec(p, &g_spec, &e) < 0 || registry_assign(&g_spec, &e) < 0 ||
        build_groups(&g_spec, &g_gr, &e) < 0 || check_address_lists(&g_gr, &e) < 0) {
        printf("спека не разобрана: %s\n", e.msg);
        return -1;
    }
    return 0;
}

static int build(struct nft_rs *rs) {
    struct err e = {0};
    nft_rs_init(rs);
    if (nft_build(rs, &g_spec, &g_gr, &e) < 0) {
        printf("дерево не построено: %s\n", e.msg);
        return -1;
    }
    return 0;
}

static const struct group *group_of(const char *out, int domains) {
    for (size_t i = 0; i < g_gr.n; i++)
        if (!strcmp(g_gr.g[i].out, out) && g_gr.g[i].domains == domains) return &g_gr.g[i];
    return NULL;
}

static const char *cm(const char *pfx, const char *name) {
    static char b[4][96];
    static int k;
    k = (k + 1) % 4;
    snprintf(b[k], sizeof(b[k]), "%s%s", pfx, name);
    return b[k];
}

static const char *setref(const struct nft_rule *r) {
    const struct nft_expr *x = ir_expr_find(r, NFT_X_SETREF);
    return x ? x->arg : "";
}

static int nobjs(const struct nft_table *t, enum nft_objk k) {
    int n = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next) n += o->k == k;
    return n;
}


/* Правило с этим комментарием для семейства fam (4 и 6 — nft_rule.fam; у правил, семейство
 * которых задано выражением «ip …», fam 0 считается четвёркой). */
static struct nft_rule *rule_fam(const struct nft_chain *c, const char *comment, int fam) {
    for (struct nft_rule *r = c ? c->rules : NULL; r; r = r->next) {
        if (!r->comment || strcmp(r->comment, comment) != 0) continue;
        int f = r->fam ? r->fam : 4;
        if (f == fam) return r;
    }
    return NULL;
}

static const char *ctype(const struct nft_chain *c) { return c && c->type ? c->type : "-"; }
static const char *chook(const struct nft_chain *c) { return c && c->hook ? c->hook : "-"; }
static int cprio(const struct nft_chain *c) { return c ? ir_prio_value(c) : 9999; }

/* ---- 1. адресные каналы на роутере ---------------------------------------------------- */
static void t_router_basic(void) {
    printf("\n-- адресные каналы, современная раскладка --\n");
    put("a.lst", "203.0.113.0/24\n198.51.100.5\n");
    put("b.lst", "198.51.100.5\n");
    if (load("{ \"schema\": 1, \"from_default\": [\"192.168.1.0/24\"],"
             "  \"outputs\": { \"direct\": { \"kind\": \"direct\" },"
             "               \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" } },"
             "  \"channels\": ["
             "    { \"name\": \"keep\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"direct\" },"
             "    { \"name\": \"blocked\", \"match\": { \"prefixes_file\": \"TMP/a.lst\" }, \"out\": \"vpn\" } ] }")) {
        check("спека разобрана", 0, 1);
        return;
    }
    struct nft_rs rs;
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    check("есть таблица inet", 1, t != NULL);
    check_str("имя таблицы — nft_table()", nft_table(), t ? t->name : "");
    check("таблиц ip/ip6 нет", 0, ir_table_find(&rs, NFT_FAM_IP, NULL) ||
                                  ir_table_find(&rs, NFT_FAM_IP6, NULL));

    struct nft_set *s = ir_set_find(t, "vpn_ip");
    check("набор vpn_ip есть", 1, s != NULL);
    check("у адресного набора flags interval без timeout", NFT_SET_INTERVAL, s ? (long)s->flags : -1);
    check("и auto-merge", 1, s ? s->auto_merge : 0);
    check("элементы — ссылкой на файл списка, не загружены", NFT_EL_ADDR_FILE,
          s && s->els ? (long)s->els->k : -1);
    char want[512];
    snprintf(want, sizeof(want), "%s/a.lst", g_tmp);
    check_str("это тот самый список", want, s && s->els ? s->els->s : "");

    struct nft_chain *pm = ir_chain_find(t, "prerouting_mark");
    check_str("prerouting_mark — filter", "filter", ctype(pm));
    check_str("на хуке prerouting", "prerouting", chook(pm));
    check("приоритет mangle + 1 = -149", -149, cprio(pm));
    struct nft_rule *r = ir_rule_find(pm, "steer:vpn_ip");
    check("правило steer:vpn_ip есть", 1, r != NULL);
    check_str("и смотрит в @vpn_ip", "vpn_ip", setref(r));
    check("ставит метку пакета", 1, ir_expr_find(r, NFT_X_MARKSET) != NULL);
    check("и считает", 1, ir_expr_find(r, NFT_X_COUNTER) != NULL);
    check("правило direct метку не ставит", 0,
          ir_expr_find(ir_rule_find(pm, "steer:direct_ip"), NFT_X_MARKSET) != NULL);
    check("правило на группу одно", 1, (long)ir_rule_count(pm, "steer:vpn_ip"));

    struct nft_chain *pd = ir_chain_find(t, "postrouting_down");
    check("postrouting_down — prio srcnat + 10 = 110", 110, cprio(pd));
    r = ir_rule_find(pd, "steer-down:vpn_ip");
    check("правило steer-down:vpn_ip есть", 1, r != NULL);
    check_str("встречный путь смотрит в ip saddr", "ip saddr",
              ir_expr_find(r, NFT_X_SETREF) ? ir_expr_find(r, NFT_X_SETREF)->text : "");

    struct nft_chain *dns = ir_chain_find(t, "prerouting_dns");
    check_str("заворот DNS — nat", "nat", ctype(dns));
    check("четыре правила: udp/tcp по подсети и по устройству", 4, (long)ir_rule_count(dns, NULL));
    check("карта fakeip без доменов не строится", 0, ir_set_find(t, "fakeip") != NULL);
    check("цепочек zapret без выходов zapret нет", 0, ir_chain_find(t, "zapret_queue") != NULL);
    nft_rs_free(&rs);
}

/* ---- 2. домены, zapret, tgws: обе раскладки -------------------------------------------- */
static int nat_chains(const struct nft_table *t) {
    int n = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next) {
        struct nft_chain *c = ir_obj_chain(o);
        n += c && c->type && !strcmp(c->type, "nat");
    }
    return n;
}

static const char *mixed =
    "{ \"schema\": 2, \"from_default\": [\"192.168.1.0/24\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" },"
    "               \"yt\": { \"kind\": \"zapret\" },"
    "               \"tg\": { \"kind\": \"tgws\", \"domain\": \"ex.co.uk\" } },"
    "  \"channels\": ["
    "    { \"name\": \"dom\", \"match\": { \"domains_files\": [\"TMP/d.lst\"], \"prefixes_files\": [\"TMP/a.lst\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"z\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"yt\" },"
    "    { \"name\": \"t\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"tg\" } ] }";

static void t_mixed_modern(void) {
    printf("\n-- домены, zapret и tgws, современная раскладка --\n");
    if (load(mixed)) { check("спека разобрана", 0, 1); return; }
    const struct group *dg = group_of("vpn", 1);
    check("доменная группа есть", 1, dg != NULL);
    if (!dg) return;
    struct nft_rs rs;
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_set *s = ir_set_find(t, dg->name);
    check("доменный набор — interval,timeout", NFT_SET_INTERVAL | NFT_SET_TIMEOUT,
          s ? (long)s->flags : -1);
    check("адресные строки списка — элементами из файла", NFT_EL_ADDR_FILE,
          s && s->els ? (long)s->els->k : -1);
    struct nft_set *m = ir_set_find(t, "fakeip");
    check("карта fakeip есть", 1, m != NULL);
    check_str("и это карта ipv4_addr : ipv4_addr", "ipv4_addr", m && m->data ? m->data : "");
    check("её элементы — из файла состояния резолвера", NFT_EL_FAKEIP_STATE,
          m && m->els ? (long)m->els->k : -1);
    struct nft_chain *dn = ir_chain_find(t, "prerouting_dnat");
    struct nft_rule *r = ir_rule_find(dn, NULL);
    check("правило fakeip — dnat по карте", 1, ir_expr_find(r, NFT_X_DNAT) != NULL);
    check("и помечено IPv4", 4, r ? r->fam : 0);

    struct nft_chain *zq = ir_chain_find(t, "zapret_queue");
    check_str("zapret_queue на postrouting", "postrouting", chook(zq));
    check("приоритет srcnat + 2 = 102", 102, cprio(zq));
    check("своё правило первым", 1, ir_rule_find(zq, NULL) == ir_rule_find(zq, "steer:zapret-own"));
    check("правило очереди выхода yt", 1, ir_rule_find(zq, "steer:zapret:yt") != NULL);
    check("ответы — в zapret_queue_in", 1,
          ir_rule_find(ir_chain_find(t, "zapret_queue_in"), "steer:zapret-reply:yt") != NULL);
    struct nft_chain *nq = ir_chain_find(t, "zapret_predefrag_nfqws");
    check("predefrag_nfqws — обычная цепочка без хука", 1, nq && !nq->type);
    check("три правила notrack", 3, (long)ir_rule_count(nq, NULL));
    check("predefrag прыгает в неё", 1,
          ir_expr_find(ir_rule_find(ir_chain_find(t, "zapret_predefrag"), NULL), NFT_X_JUMP) != NULL);
    check("фрагмент IPv6 — exthdr frag exists", 1,
          ir_rule_has(ir_rule_find(nq, NULL)->next, "exthdr frag exists"));

    struct nft_chain *tg = ir_chain_find(t, "tgws_redirect");
    check_str("перехват Telegram — nat", "nat", ctype(tg));
    check("после трансляции адресов: dstnat + 1 = -99", -99, cprio(tg));
    r = ir_rule_find(tg, "steer:tgws:tg");
    check("правило моста есть", 1, r != NULL);
    check("и помечено IPv4", 4, r ? r->fam : 0);
    check("nat-цепочек в inet четыре (tgws, dns, dnat, подмена IPv4 ядра у interface)", 4, nat_chains(t));
    struct nft_chain *n4 = ir_chain_find(t, "postrouting_nat4");
    check("postrouting_nat4: masquerade на устройстве выхода interface", 1,
          n4 && ir_rule_find(n4, "steer-nat4:vpn") && ir_rule_has(ir_rule_find(n4, "steer-nat4:vpn"), "masquerade"));
    nft_rs_free(&rs);
}

/* ---- 2б. emit вида подключён, и порядок в тексте не зависит от порядка выходов в спеке --- */
static const char *mixed_rev =
    "{ \"schema\": 2, \"from_default\": [\"192.168.1.0/24\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" },"
    "               \"tg\": { \"kind\": \"tgws\", \"domain\": \"ex.co.uk\" },"
    "               \"yt\": { \"kind\": \"zapret\" } },"
    "  \"channels\": ["
    "    { \"name\": \"dom\", \"match\": { \"domains_files\": [\"TMP/d.lst\"], \"prefixes_files\": [\"TMP/a.lst\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"t\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"tg\" },"
    "    { \"name\": \"z\", \"match\": { \"prefixes_file\": \"TMP/b.lst\" }, \"out\": \"yt\" } ] }";

static void t_mixed_order(void) {
    printf("\n-- emit вида подключён; порядок выходов в спеке текст не меняет --\n");
    check("kind zapret даёт emit", 1, kind_by_name("zapret") && kind_by_name("zapret")->emit != NULL);
    check("kind tgws даёт emit", 1, kind_by_name("tgws") && kind_by_name("tgws")->emit != NULL);

    /* Та же спека, что у mixed, но tg (tgws) объявлен ПЕРЕД yt (zapret) — и в outputs, и в
     * channels. kind_emit_all зовёт виды в порядке реестра (zapret раньше tgws), а не в
     * порядке их появления в спеке, поэтому в дереве цепочки zapret обязаны стоять раньше
     * цепочки моста так же, как в t_mixed_modern. */
    if (load(mixed_rev)) { check("спека разобрана", 0, 1); return; }
    struct nft_rs rs;
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    int zi = -1, ti = -1, i = 0;
    for (struct nft_obj *o = t ? t->objs : NULL; o; o = o->next, i++) {
        if (!strcmp(o->name, "zapret_queue")) zi = i;
        if (!strcmp(o->name, "tgws_redirect")) ti = i;
    }
    check("цепочка zapret_queue построена", 1, zi >= 0);
    check("цепочка tgws_redirect построена", 1, ti >= 0);
    check("правило очереди выхода yt на месте", 1,
          ir_rule_find(ir_chain_find(t, "zapret_queue"), "steer:zapret:yt") != NULL);
    check("правило моста выхода tg на месте", 1,
          ir_rule_find(ir_chain_find(t, "tgws_redirect"), "steer:tgws:tg") != NULL);
    check("zapret в тексте раньше моста, хоть в спеке он объявлен вторым", 1,
          zi >= 0 && ti >= 0 && zi < ti);
    nft_rs_free(&rs);
}

/* ---- 3. каналы на сам телефон ------------------------------------------------------------ */
static const char *phone =
    "{ \"schema\": 2, \"lan_devices\": [\"rndis0\"],"
    "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" } },"
    "  \"channels\": ["
    "    { \"name\": \"s\", \"from\": [\"self\"], \"match\": { \"any\": true, \"allow_all\": true, \"proto\": \"udp\", \"ports\": [\"50000-65535\"] }, \"out\": \"vpn\" },"
    "    { \"name\": \"d\", \"from\": [\"uid:10124\"], \"match\": { \"domains_files\": [\"TMP/d.lst\"] }, \"out\": \"vpn\" } ] }";

static void t_phone(void) {
    printf("\n-- каналы на сам телефон --\n");
    if (load(phone)) { check("спека разобрана", 0, 1); return; }
    /* Поддельные IPv6 (fake-IP v6) — всегда: nat в inet один на оба семейства. */
    const int f6 = 1;
    const struct group *all = NULL, *dom = group_of("vpn", 1);
    for (size_t i = 0; i < g_gr.n; i++) if (g_gr.g[i].all) all = &g_gr.g[i];
    if (!all || !dom) { check("группы телефона есть", 0, 1); return; }
    struct nft_rs rs;
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    struct nft_table *in = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_chain *om = ir_chain_find(in, "output_mark");
    check_str("output_mark на хуке output", "output", chook(om));
    check_str("в современной — route", "route", ctype(om));
    /* Выход interface несёт IPv6 (KC_IPV6, 1.9): IPv6 «весь трафик» не отвергается, а метится
     * v6-двойником правила — под тем же именем, со своей сетью мимо. */
    check("отказа IPv6 у выхода с IPv6 нет", 0,
          ir_rule_find(om, cm("steer-v6:", all->name)) != NULL);
    check("у «весь трафик» два правила: IPv4 и IPv6", 2,
          (long)ir_rule_count(om, cm("steer:", all->name)));
    struct nft_rule *r = ir_rule_find(om, cm("steer:", all->name));
    struct nft_rule *r6 = rule_fam(om, cm("steer:", all->name), 6);
    struct nft_expr *fx = ir_expr_find(r6, NFT_X_FAMILY);
    check("двойник — про IPv6", 6, fx ? fx->fam : 0);
    check("двойник метит меткой выхода", 1, r6 && ir_expr_find(r6, NFT_X_MARKSET) != NULL);
    check("своя сеть IPv6 — мимо", 1, ir_rule_has(r6, "fe80::/10"));
    check("правило разметки группы есть", 1, r != NULL);
    check("бита перемаршрутизации нет", 0, ir_rule_has(r, "mark or 0x00200000"));
    check("и у двойника", 0, ir_rule_has(r6, "mark or 0x00200000"));
    check("скачанное — в input_down", 1,
          ir_rule_find(ir_chain_find(in, "input_down"), cm("steer-down:", all->name)) != NULL);
    struct nft_table *t4 = ir_table_find(&rs, NFT_FAM_IP, NULL);
    {
        struct nft_chain *od = ir_chain_find(in, "output_dns");
        check_str("заворот DNS приложений — nat output", "output", chook(od));
        /* И по правилу «без подмены — drop» на семейство (steer-fakeip-local-nomap, generate.c). */
        check("udp, tcp, fakeip и fakeip6 (с правилами без подмены)", 6,
              (long)ir_rule_count(od, NULL));
        check("  правил без подмены — два", 2, (long)ir_rule_count(od, "steer-fakeip-local-nomap"));
        check("таблицы ip нет", 0, t4 != NULL);
    }
    /* Доменная группа приложения: парный набор IPv6 и v6-двойник — там же, где fake-IP v6. */
    char d6[80];
    group_set6_name(dom, d6, sizeof(d6));
    check("доменный набор IPv6 приложения — только при fake-IP v6", f6, ir_set_find(in, d6) != NULL);
    check("и его v6-двойник в output_mark", f6,
          rule_fam(om, cm("steer:", dom->name), 6) != NULL);
    nft_rs_free(&rs);
}

/* ---- 3б. IPv6 правил (docs/architecture.md, «4б») --------------------------------------------
 *
 * Строки IPv6 списков — в парный набор «<имя>6» (ipv6_addr), у правила — v6-двойник с тем же
 * именем; клиенты по умолчанию из подсетей IPv4 — для IPv6 по устройству; клиент с адресом IPv6 —
 * `ip6 saddr`; direct — двойник без метки; выход без IPv6 (tgws) — двойник метит, а forward_v6
 * отвергает IPv6 с его меткой (fail-closed); список без строк IPv6 — ни набора, ни двойника. */
static void t_router_v6(void) {
    printf("\n-- IPv6 правил на роутере --\n");
    put("v6a.lst", "203.0.113.0/24\n2001:db8:1::/48\n2001:db8:2::1-2001:db8:2::9\n");
    put("v6b.lst", "198.51.100.0/24\n");
    put("v6c.lst", "2001:db8:3::/48\n");
    if (load("{ \"schema\": 2, \"from_default\": [\"192.168.1.0/24\"],"
             "  \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" },"
             "               \"tg\": { \"kind\": \"tgws\", \"domain\": \"example.com\" },"
             "               \"dir\": { \"kind\": \"direct\" } },"
             "  \"channels\": ["
             "    { \"name\": \"d\", \"match\": { \"prefixes_file\": \"TMP/v6c.lst\" }, \"out\": \"dir\" },"
             "    { \"name\": \"a\", \"match\": { \"prefixes_file\": \"TMP/v6a.lst\" }, \"out\": \"vpn\" },"
             "    { \"name\": \"b\", \"match\": { \"prefixes_file\": \"TMP/v6b.lst\" }, \"out\": \"vpn\","
             "      \"from\": [\"192.168.1.7\"] },"
             "    { \"name\": \"t\", \"match\": { \"prefixes_file\": \"TMP/v6c.lst\" }, \"out\": \"tg\","
             "      \"from\": [\"192.168.1.9\", \"fd00::9\"] },"
             "    { \"name\": \"all\", \"match\": { \"any\": true, \"allow_all\": true }, \"out\": \"vpn\" } ] }")) {
        check("спека разобрана", 0, 1);
        return;
    }
    struct nft_rs rs;
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    struct nft_set *s6 = ir_set_find(t, "vpn_ip6");
    check("парный набор vpn_ip6 есть", 1, s6 != NULL);
    check_str("  тип ipv6_addr", "ipv6_addr", s6 ? s6->key : "");
    check("  flags interval (без timeout и в 4.9)", NFT_SET_INTERVAL, s6 ? (long)s6->flags : -1);
    check("  элементы — тот же файл списка", NFT_EL_ADDR_FILE, s6 && s6->els ? (long)s6->els->k : -1);
    struct nft_chain *pm = ir_chain_find(t, "prerouting_mark");
    check("у группы vpn_ip два правила", 2, (long)ir_rule_count(pm, "steer:vpn_ip"));
    struct nft_rule *r4 = rule_fam(pm, "steer:vpn_ip", 4), *r6 = rule_fam(pm, "steer:vpn_ip", 6);
    check_str("  IPv4 — прежний набор", "vpn_ip", setref(r4));
    check_str("  IPv6 — парный", "vpn_ip6", setref(r6));
    check("  двойник: ip6 daddr", 1, ir_rule_has(r6, "ip6 daddr"));
    check("  двойник: «кто» по устройству (from_default — подсети IPv4)", 1,
          ir_rule_has(r6, "iifname \"br-lan\""));
    check("  двойник метит той же меткой", 1, ir_rule_has(r6, "or 0x"));
    const struct group *gb = NULL, *gt = NULL, *ga = NULL, *gd = NULL;
    for (size_t i = 0; i < g_gr.n; i++) {
        const struct group *g = &g_gr.g[i];
        if (!strcmp(g->out, "vpn") && g->all) ga = g;
        else if (!strcmp(g->out, "vpn") && g->from_n == 1) gb = g;
        else if (!strcmp(g->out, "tg")) gt = g;
        else if (!strcmp(g->out, "dir")) gd = g;
    }
    if (!ga || !gb || !gt || !gd) { check("группы найдены", 0, 1); nft_rs_free(&rs); return; }
    char n6[80];
    group_set6_name(gb, n6, sizeof(n6));
    check("клиент из одного IPv4, список без IPv6 — одно правило", 1,
          (long)ir_rule_count(pm, cm("steer:", gb->name)));
    check("  и набора IPv6 нет", 0, ir_set_find(t, n6) != NULL);
    struct nft_rule *ra6 = rule_fam(pm, cm("steer:", ga->name), 6);
    check("«весь трафик» с from_default: двойник IPv6", 1, ra6 != NULL);
    struct nft_expr *fx = ir_expr_find(ra6, NFT_X_FAMILY);
    check("  двойник сужен до IPv6 (meta nfproto ipv6)", 6, fx ? fx->fam : 0);
    check("  «кто» — по устройству", 1, ir_rule_has(ra6, "iifname \"br-lan\""));
    struct nft_rule *rt6 = rule_fam(pm, cm("steer:", gt->name), 6);
    check("клиент с адресом IPv6: ip6 saddr", 1, ir_rule_has(rt6, "ip6 saddr { fd00::9 }"));
    check("  и в правиле IPv4 его нет", 0,
          ir_rule_has(rule_fam(pm, cm("steer:", gt->name), 4), "fd00::9"));
    struct nft_rule *rd6 = rule_fam(pm, cm("steer:", gd->name), 6);
    check("direct: двойник есть (первое совпадение и для IPv6)", 1, rd6 != NULL);
    check("  без метки", 0, rd6 && ir_expr_find(rd6, NFT_X_MARKSET) != NULL);
    check("  и с return", 1, ir_rule_has(rd6, "return"));
    struct nft_chain *pd = ir_chain_find(t, "postrouting_down");
    check("скачанное по IPv6 — тем же именем", 2, (long)ir_rule_count(pd, "steer-down:vpn_ip"));
    /* Выход без IPv6 (tgws): IPv6 его правила отвергается в forward, а не уходит напрямую. */
    struct nft_chain *fw = ir_chain_find(t, "forward_v6");
    check_str("forward_v6 — filter", "filter", ctype(fw));
    check_str("  на хуке forward", "forward", chook(fw));
    check("  одно правило — на выход tg", 1, (long)ir_rule_count(fw, NULL));
    struct nft_rule *rj = ir_rule_find(fw, "steer-v6drop:tg");
    check("  отказ, а не прямой путь", 1, ir_rule_has(rj, "reject"));
    char mk[64];
    snprintf(mk, sizeof(mk), "== 0x%08x", out_by_name(&g_spec, "tg")->mark);
    check("  по метке выхода tg", 1, ir_rule_has(rj, mk));
    struct nft_expr *jx = ir_expr_find(rj, NFT_X_FAMILY);
    check("  только IPv6", 6, jx ? jx->fam : 0);
    check("выходу с IPv6 отказа нет", 0, ir_rule_find(fw, "steer-v6drop:vpn") != NULL);
    nft_rs_free(&rs);

    /* Спека без IPv6 и без выходов без IPv6 — ни одного объекта IPv6. */
    if (load("{ \"schema\": 1, \"outputs\": { \"vpn\": { \"kind\": \"interface\", \"device\": \"wg0\" } },"
             "  \"channels\": [ { \"name\": \"b\", \"match\": { \"prefixes_file\": \"TMP/v6b.lst\" }, \"out\": \"vpn\" } ] }")) {
        check("спека без IPv6 разобрана", 0, 1);
        return;
    }
    if (build(&rs)) { check("дерево построено", 0, 1); return; }
    t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    check("без IPv6: одно правило разметки", 1,
          (long)ir_rule_count(ir_chain_find(t, "prerouting_mark"), NULL));
    check("  ни набора IPv6, ни forward_v6", 0,
          ir_set_find(t, "vpn_ip6") != NULL || ir_chain_find(t, "forward_v6") != NULL);
    nft_rs_free(&rs);
}

/* ---- 4. само дерево: поиск, клон, арена ------------------------------------------------- */
/* ---- группы balance (шаг 3 из 1.9): переход в цепочку группы, карта numgen, метка соединения ---- */
static const struct output *oname(const char *n) {
    for (size_t i = 0; i < g_spec.out_n; i++)
        if (!strcmp(g_spec.out[i].name, n)) return &g_spec.out[i];
    return NULL;
}
static size_t nels(const struct nft_set *s) {
    size_t n = 0;
    for (const struct nft_elsrc *e = s ? s->els : NULL; e; e = e->next) n++;
    return n;
}
static int els_with(const struct nft_set *s, const char *needle) {
    int n = 0;
    for (const struct nft_elsrc *e = s ? s->els : NULL; e; e = e->next)
        n += e->k == NFT_EL_VALUE && strstr(e->s, needle) != NULL;
    return n;
}

static void t_balance(void) {
    printf("\n-- balance: карта numgen, метка соединения, вложенность --\n");
    put("bal.lst", "203.0.113.0/24\n");
    if (load("version: 2\n"
             "lists:\n  l: { prefixes_file: TMP/bal.lst }\n"
             "outputs:\n"
             "  a:   { kind: interface, device: wg0 }\n"
             "  b:   { kind: interface, device: wg1 }\n"
             "  c:   { kind: interface, device: wg2 }\n"
             "  res: { kind: group, pick: order, members: [a, b] }\n"
             "  in:  { kind: group, pick: balance, members: [b, c] }\n"
             "  top: { kind: group, pick: balance, members: [res, in, a], weights: [2, 1, 1] }\n"
             "rules:\n  - { name: t, to: [l], out: top }\n") < 0) return;
    struct nft_rs rs;
    if (build(&rs) < 0) return;
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    const struct output *top = oname("top"), *in = oname("in"), *res = oname("res"),
                        *a = oname("a"), *b = oname("b"), *c = oname("c");
    char bc[32], bm[32], ic[32], rc[32], mres[32], ma[32], mb[32], mc[32], mtop[32];
    group_bal_chain(res, rc, sizeof(rc));
    group_bal_chain(top, bc, sizeof(bc));
    group_bal_map(top, bm, sizeof(bm));
    group_bal_chain(in, ic, sizeof(ic));
    group_mark_chain(res, mres, sizeof(mres));
    group_mark_chain(a, ma, sizeof(ma));
    group_mark_chain(b, mb, sizeof(mb));
    group_mark_chain(c, mc, sizeof(mc));
    group_mark_chain(top, mtop, sizeof(mtop));

    const struct group *g = group_of("top", 0);
    const struct nft_rule *r = g ? ir_rule_find(ir_chain_find(t, "prerouting_mark"), cm("steer:", g->name)) : NULL;
    check("правило канала — goto в цепочку группы, без метки", 1,
          r && ir_rule_has(r, cm("goto ", bc)) && !ir_expr_find(r, NFT_X_MARKSET) &&
          ir_expr_find(r, NFT_X_COUNTER) != NULL);
    const struct nft_set *m = ir_set_find(t, bm);
    check_str("карта: type mark : verdict", "mark verdict",
              m ? ir_printf(&rs, "%s %s", m->key, m->data ? m->data : "-") : "-");
    check("  слотов 120 — все члены живы", GROUP_BAL_SLOTS, (long)nels(m));
    /* res — order с именованными членами, то есть закрепляющая (group_carded): её слоты ведут в её
     * цепочку, как у вложенной balance, и там соединение получает метку её текущего члена. */
    check("  по весам 2:1:1 — res 60 (в её цепочку), вложенная in 30, a 30", 603030,
          els_with(m, cm("goto ", rc)) * 10000L + els_with(m, cm("goto ", ic)) * 100L +
          els_with(m, cm("goto ", ma)));
    const struct nft_chain *ch = ir_chain_find(t, bc);
    check("цепочка группы: восстановление по метке соединения — по листу на правило", 3,
          (long)(ch ? ir_rule_count(ch, NULL) : 0) - 2);
    int rest = 0, numgen = 0, fall = 0;
    for (const struct nft_rule *q = ch ? ch->rules : NULL; q; q = q->next) {
        if (ir_rule_has(q, "ct mark and ")) rest++;
        if (ir_rule_has(q, ir_printf(&rs, "numgen random mod %d vmap @%s", GROUP_BAL_SLOTS, bm))) numgen++;
        if (ir_rule_has(q, cm("goto ", mtop)) && !q->next) fall++;
    }
    check("  листья: a, b, c (листья res и in вглубь, каждый один раз)", 3, rest);
    check("  затем numgen по карте и запасной goto в метку группы", 11, numgen * 10 + fall);
    const struct nft_rule *lr = ch ? ch->rules : NULL;
    int leaf_b = 0;
    for (; lr; lr = lr->next)
        if (ir_rule_has(lr, ir_printf(&rs, "== 0x%08x", b->mark)) && ir_rule_has(lr, cm("goto ", mb)))
            leaf_b = 1;
    check("  соединение на члене вложенной balance — сразу в его метку", 1, leaf_b);
    const struct nft_chain *mk = ir_chain_find(t, mres);
    const struct nft_rule *mr = mk ? mk->rules : NULL;
    check("цепочка метки: метка члена и ct mark set mark", 1,
          mr && ir_expr_find(mr, NFT_X_MARKSET) &&
          ir_rule_has(mr, ir_printf(&rs, "0x%08x", res->mark | ZAPRET_SKIP_MARK)) &&
          ir_rule_has(mr, "ct mark set mark"));
    /* res (order: a, b) — свой член карты top: её доля уходит в её цепочку, а не раскрывается в
     * карту top. Слоты a — только его собственные 30 (как члена top); b в карте top не бывает. */
    check("вложенная order — один член: её листья в карту не раскрываются", 1,
          els_with(m, cm("goto ", ma)) == 30 && els_with(m, cm("goto ", mb)) == 0);
    const struct nft_set *rm = ir_set_find(t, ir_printf(&rs, "balmap_%d", res->table));
    check("вложенная order — своя карта из одного слота: её первый член", 1,
          rm && nels(rm) == 1 && els_with(rm, cm("goto ", ma)) == 1);
    const struct nft_set *im = ir_set_find(t, ir_printf(&rs, "balmap_%d", in->table));
    check("вложенная balance — своя карта со своими членами", 1,
          im && els_with(im, cm("goto ", mb)) == 60 && els_with(im, cm("goto ", mc)) == 60);
    check("отказа памяти не было", 0, rs.oom);
    nft_rs_free(&rs);
}

/* by: site, site_client — слот по хешу адресов вместо numgen: по правилу на семейство, семя —
 * номер таблицы группы (своё у каждой группы, постоянное между apply), карта и восстановление по
 * метке соединения — те же. */
static void t_balance_by(void) {
    printf("\n-- balance by: site и site_client — jhash по адресам --\n");
    put("bal.lst", "203.0.113.0/24\n");
    if (load("version: 2\n"
             "lists:\n  l: { prefixes_file: TMP/bal.lst }\n  m: { prefixes_file: TMP/bal.lst }\n"
             "outputs:\n"
             "  a:   { kind: interface, device: wg0 }\n"
             "  b:   { kind: interface, device: wg1 }\n"
             "  c:   { kind: interface, device: wg2 }\n"
             "  in:  { kind: group, pick: balance, by: site, members: [b, c] }\n"
             "  st:  { kind: group, pick: balance, by: site, members: [a, in] }\n"
             "  sc:  { kind: group, pick: balance, by: site_client, members: [a, b], weights: [1, 3] }\n"
             "rules:\n  - { name: t, to: [l], out: st }\n  - { name: u, to: [m], out: sc }\n") < 0) return;
    struct nft_rs rs;
    if (build(&rs) < 0) return;
    struct nft_table *t = ir_table_find(&rs, NFT_FAM_INET, NULL);
    const struct output *st = oname("st"), *in = oname("in"), *sc = oname("sc");
    char c_st[32], m_st[32], c_in[32], m_in[32], c_sc[32], m_sc[32];
    group_bal_chain(st, c_st, sizeof(c_st));
    group_bal_map(st, m_st, sizeof(m_st));
    group_bal_chain(in, c_in, sizeof(c_in));
    group_bal_map(in, m_in, sizeof(m_in));
    group_bal_chain(sc, c_sc, sizeof(c_sc));
    group_bal_map(sc, m_sc, sizeof(m_sc));
    const struct nft_chain *ch = ir_chain_find(t, c_st);
    int v4 = 0, v6 = 0, numgen = 0;
    for (const struct nft_rule *q = ch ? ch->rules : NULL; q; q = q->next) {
        if (q->fam == 4 && ir_rule_has(q, ir_printf(&rs, "jhash ip daddr mod %d seed 0x%x vmap @%s",
                                                   GROUP_BAL_SLOTS, (unsigned)st->table, m_st))) v4++;
        if (q->fam == 6 && ir_rule_has(q, ir_printf(&rs, "jhash ip6 daddr mod %d seed 0x%x vmap @%s",
                                                   GROUP_BAL_SLOTS, (unsigned)st->table, m_st))) v6++;
        if (ir_rule_has(q, "numgen")) numgen++;
    }
    check("by: site — jhash адреса назначения, IPv4 и IPv6 своим правилом, без numgen", 110,
          v4 * 100 + v6 * 10 + numgen);
    const struct nft_rule *last = ch ? ch->rules : NULL;
    while (last && last->next) last = last->next;
    check("  восстановление по метке соединения — до хеша, запасной goto — последним", 1,
          ch && ir_rule_has(ch->rules, "ct mark and ") && last && ir_rule_has(last, "goto mark_"));
    const struct nft_chain *ci = ir_chain_find(t, c_in);
    int in4 = 0;
    for (const struct nft_rule *q = ci ? ci->rules : NULL; q; q = q->next)
        if (ir_rule_has(q, ir_printf(&rs, "jhash ip daddr mod %d seed 0x%x vmap @%s", GROUP_BAL_SLOTS,
                                     (unsigned)in->table, m_in))) in4++;
    check("вложенная by: site — своё семя (номер своей таблицы), а не внешней", 1,
          in4 == 1 && in->table != st->table);
    const struct nft_chain *cs = ir_chain_find(t, c_sc);
    int sc4 = 0, sc6 = 0;
    for (const struct nft_rule *q = cs ? cs->rules : NULL; q; q = q->next) {
        if (q->fam == 4 && ir_rule_has(q, ir_printf(&rs, "jhash ip saddr . ip daddr mod %d seed 0x%x vmap @%s",
                                                   GROUP_BAL_SLOTS, (unsigned)sc->table, m_sc))) sc4++;
        if (q->fam == 6 && ir_rule_has(q, ir_printf(&rs, "jhash ip6 saddr . ip6 daddr mod %d seed 0x%x vmap @%s",
                                                   GROUP_BAL_SLOTS, (unsigned)sc->table, m_sc))) sc6++;
    }
    check("by: site_client — хеш пары «клиент, назначение» по обоим семействам", 11, sc4 * 10 + sc6);
    const struct nft_set *msc = ir_set_find(t, m_sc);
    check("  карта та же: 120 слотов по весам 1:3 — 30/90", 3090,
          els_with(msc, cm("goto ", "mark_")) == GROUP_BAL_SLOTS
              ? els_with(msc, ir_printf(&rs, "goto mark_%d", oname("a")->table)) * 100L +
                    els_with(msc, ir_printf(&rs, "goto mark_%d", oname("b")->table))
              : -1);
    check("отказа памяти не было", 0, rs.oom);
    nft_rs_free(&rs);
}

static void t_tree(void) {
    printf("\n-- дерево: поиск и переделка --\n");
    struct nft_rs rs;
    nft_rs_init(&rs);
    struct nft_table *t = ir_table_add(&rs, NFT_FAM_INET, "x");
    struct nft_chain *c = ir_base_chain_add(t, "c", "filter", "input", "filter", -5);
    struct nft_rule *r = ir_rule(c);
    ir_x(r, "tcp dport %d", 22);
    ir_counter(r, 7, 700);
    ir_comment(r, "k");
    struct nft_rule *n = ir_rule_clone(NULL, r);
    check("клон встал сразу за оригиналом", 1, r->next == n && n->next == NULL);
    check("и у него свои выражения", 1, n->x != r->x && !strcmp(n->x->text, r->x->text));
    check("счётчик копируется", 700, n ? (long)n->bytes : 0);
    ir_rule(c);
    check("хвост цепочки после клона верен", 3, (long)ir_rule_count(c, NULL));
    check("по комментарию — два", 2, (long)ir_rule_count(c, "k"));
    char p[32];
    ir_prio_str(c, p, sizeof(p));
    check_str("приоритет словами", "filter - 5", p);
    struct nft_set *s1 = ir_set_add(t, "s1", "ipv4_addr");
    struct nft_set *s2 = ir_set_add(t, "s2", "ipv4_addr");
    ir_obj_unlink(&s2->o);
    ir_obj_insert_after(&c->o, &s2->o);
    check("вставка после объекта", 1, c->o.next == &s2->o && s2->o.next == &s1->o);
    check("наборов два, цепочка одна", 21, nobjs(t, NFT_OBJ_SET) * 10 + nobjs(t, NFT_OBJ_CHAIN));
    /* Строка длиннее куска арены — свой кусок, а не отказ. */
    char big[10000];
    memset(big, 'a', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';
    check("длинная строка в арене", (long)sizeof(big) - 1, (long)strlen(ir_strdup(&rs, big)));
    check("отказа памяти не было", 0, rs.oom);
    nft_rs_free(&rs);
    check("после освобождения таблиц нет", 1, rs.tables == NULL && rs.arena == NULL);
}

int main(void) {
    const char *td = getenv("TMPDIR");
    snprintf(g_tmp, sizeof(g_tmp), "%s/irmatch.XXXXXX", td ? td : "/tmp");
    if (!mkdtemp(g_tmp)) { perror("mkdtemp"); return 2; }
    steer_set_state_dir(g_tmp);
    put("d.lst", "example.com\n");
    t_tree();
    t_router_basic();
    if (!plat()->local_channels) {
        t_mixed_modern();
        t_mixed_order();
        t_balance();
        t_balance_by();
        t_router_v6();
    } else {
        t_phone();
    }
    groups_free(&g_gr);
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_tmp);
    if (system(cmd) != 0) printf("не удалось убрать %s\n", g_tmp);
    return unit_done(plat()->local_channels ? "irmatch-android" : "irmatch");
}
