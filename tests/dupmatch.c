/* Апстримы резолвера без сети: разбор адреса, спека v2 с dns, таблица «демон -> dnsd» (построение и
 * разбор, старый формат до байта), кэш ответов (срок, зажим, возраст, отрицательные, вытеснение).
 * Кадры DoQ (RFC 9250) — по байтам, без QUIC. Сеть, TLS, QUIC и путь через выход проверяют
 * tests/dnsup.sh и tests/doqup.sh. Устройство проверяемого — src/dnsd/dup.h, src/dnsd/doq.h. */
#include "dnsd_int.h"
#include "doq.h"
#include "doh2.h"
#include "tabfmt.h"
#include <sys/stat.h>

static int fails;
static void check(const char *what, int want, int got) {
    int ok = want == got;
    if (!ok) fails++;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) printf("   ожидалось %d, получено %d\n", want, got);
}
static void check_str(const char *what, const char *want, const char *got) {
    int ok = !strcmp(want, got);
    if (!ok) fails++;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) printf("   ожидалось «%s», получено «%s»\n", want, got);
}

static int parse(const char *u, struct spec_dns_up *o) {
    char why[128];
    memset(o, 0, sizeof(*o));
    return dnsurl_parse(u, o, why, sizeof(why));
}

/* Ответ A: имя a.b, TTL ttl, адрес 1.2.3.4. */
static size_t mk_answer(uint8_t *b, const char *name_lbl, uint32_t ttl, int rcode, int with_rr) {
    size_t o = 0;
    memset(b, 0, 12);
    b[2] = 0x81; b[3] = (uint8_t)(0x80 | rcode); b[5] = 1; b[7] = with_rr ? 1 : 0;
    o = 12;
    for (const char *p = name_lbl; *p;) {
        const char *d = strchr(p, '.');
        size_t l = d ? (size_t)(d - p) : strlen(p);
        b[o++] = (uint8_t)l; memcpy(b + o, p, l); o += l;
        p += l + (d ? 1 : 0);
    }
    b[o++] = 0; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;
    if (with_rr) {
        b[o++] = 0xC0; b[o++] = 12; b[o++] = 0; b[o++] = 1; b[o++] = 0; b[o++] = 1;
        b[o++] = (uint8_t)(ttl >> 24); b[o++] = (uint8_t)(ttl >> 16); b[o++] = (uint8_t)(ttl >> 8); b[o++] = (uint8_t)ttl;
        b[o++] = 0; b[o++] = 4; b[o++] = 1; b[o++] = 2; b[o++] = 3; b[o++] = 4;
    }
    return o;
}
static size_t mk_query(uint8_t *b, const char *name) {
    size_t n = mk_answer(b, name, 0, 0, 0);
    b[2] = 0x01; b[3] = 0;
    return n;
}
static uint32_t rr_ttl(const uint8_t *a, size_t n, size_t qlen) {
    (void)n;
    return ((uint32_t)a[qlen + 6] << 24) | ((uint32_t)a[qlen + 7] << 16) | ((uint32_t)a[qlen + 8] << 8) | a[qlen + 9];
}

int main(void) {
    struct spec_dns_up u;
    /* ---- адрес апстрима ---- */
    check("https://dns.google/dns-query — DoH", 0, parse("https://dns.google/dns-query", &u));
    check("  протокол", DNSP_DOH, u.proto);
    check("  порт 443", 443, u.port);
    check_str("  путь", "/dns-query", u.path);
    check("https://h:8443/x — порт и путь", 0, parse("https://h.test:8443/x", &u));
    check("  порт", 8443, u.port);
    check_str("  путь", "/x", u.path);
    check("https://h без пути — путь по умолчанию", 0, parse("https://h.test", &u));
    check_str("  путь", "/dns-query", u.path);
    check("tls://one.one.one.one — DoT 853", 0, parse("tls://one.one.one.one", &u));
    check("  порт", 853, u.port);
    check("tls://[2606:4700::1111]:853 — IPv6 в скобках", 0, parse("tls://[2606:4700::1111]", &u));
    check_str("  адрес", "2606:4700::1111", u.host);
    check("udp://1.1.1.1 — порт 53", 0, parse("udp://1.1.1.1", &u));
    check("  порт", 53, u.port);
    check("udp://имя — отказ (обычному DNS нечем разрешить имя)", -1, parse("udp://dns.test", &u));
    check("quic://dns.test — DoQ 853", 0, parse("quic://dns.test", &u));
    check("  протокол", DNSP_QUIC, u.proto);
    check("  порт 853", 853, u.port);
    check_str("  имя", "dns.test", u.host);
    check("quic://[2001:db8::1]:8853 — IPv6 и порт", 0, parse("quic://[2001:db8::1]:8853", &u));
    check("  порт", 8853, u.port);
    check_str("  адрес", "2001:db8::1", u.host);
    check("путь у quic:// — отказ", -1, parse("quic://dns.test/x", &u));
    check("doq:// — не схема (ни AdGuard, ни sing-box, ни Xray её не пишут)", -1, parse("doq://dns.test", &u));
    check("http:// — отказ", -1, parse("http://dns.test", &u));
    check("путь у tls:// — отказ", -1, parse("tls://dns.test/x", &u));
    check("порт 99999 — отказ", -1, parse("tls://dns.test:99999", &u));

    /* ---- спека v2 ---- */
    char dir[] = "/tmp/dupmatchXXXXXX";
    if (!mkdtemp(dir)) return 2;
    char lst[200], sp[200];
    snprintf(lst, sizeof(lst), "%s/a.lst", dir);
    snprintf(sp, sizeof(sp), "%s/s.yaml", dir);
    FILE *f = fopen(lst, "w"); fputs("a.test\n", f); fclose(f);
    char lst2[200]; snprintf(lst2, sizeof(lst2), "%s/b.lst", dir);
    f = fopen(lst2, "w"); fputs("b.test\n", f); fclose(f);
    f = fopen(sp, "w");
    fprintf(f, "version: 2\nlan: { devices: [br-lan] }\nlists:\n  la: { domains_file: %s }\n  lb: { domains_file: %s }\n"
               "outputs:\n  direct: { kind: direct }\n  vpn: { kind: interface, device: wg0 }\n"
               "dns:\n  cache: 128\n  cache_ttl: { min: 20, max: 900, negative: 45 }\n  bootstrap: [1.1.1.1, 8.8.8.8]\n"
               "  upstream: g\n  upstreams:\n    g: { url: 'https://dns.google/dns-query', out: vpn }\n"
               "    t: { url: 'tls://dns.test', ips: [192.0.2.1] }\n"
               "rules:\n  - { name: ra, to: [la], out: vpn, dns: t }\n  - { name: rb, to: [lb], out: vpn }\n", lst, lst2);
    fclose(f);
    static struct spec cfg;
    struct err e = {0};
    check("спека с dns.upstreams/bootstrap/cache читается", 0, load_spec(sp, &cfg, &e) < 0);
    check("  кэш", 128, (int)cfg.dns.cache);
    check("  ttl min/max/neg", 20 * 1000000 + 900 * 1000 + 45, (int)(cfg.dns.ttl_min * 1000000 + cfg.dns.ttl_max * 1000 + cfg.dns.ttl_neg));
    check("  общий апстрим — первый", 1, cfg.dns.general);
    check("  bootstrap из двух", 2, cfg.dns.boot_n);
    check("  апстрим t: адреса записаны", 1, cfg.dns.up[1].ips_n);

    /* ---- таблица: построение и разбор ---- */
    cfg.out[1].mark = 0x00100000;     /* метку выдал бы реестр демона */
    char *txt = NULL; size_t tn = 0;
    FILE *m = open_memstream(&txt, &tn);
    tabfmt_build(&cfg, m); fclose(m);
    check("таблица: расширенный заголовок «2 2 128 20 900 45»", 0, strncmp(txt, "2 2 128 20 900 45\n", 18));
    check("  канал ra несёт dns:1, rb — dns:2 (порядок использования)", 1,
          strstr(txt, "|dns:1\n") != NULL && strstr(txt, "|dns:2\n") != NULL);
    check("  метка выхода в строке апстрима g", 1, strstr(txt, "https://dns.google/dns-query|vpn|1048576|-|1.1.1.1,8.8.8.8") != NULL);
    check("  для t (без выхода): метка 0, адреса", 1, strstr(txt, "tls://dns.test|-|0|192.0.2.1|1.1.1.1,8.8.8.8") != NULL);
    size_t before_n = g_dup_cfg_n;
    /* g_dch держит строки спеки взаймы (сборка), а tabfmt_parse освобождает прежнее как своё —
     * в настоящем процессе они не встречаются вместе; здесь встречаются ради сравнения, поэтому
     * таблица обнуляется руками (те же слова — в tests/dnsmatch.c). */
    for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);
    memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
    g_dch_n = 0;
    check("  разбор своей же таблицы", 0, tabfmt_parse(txt, tn));
    check("  апстримов", (int)before_n, (int)g_dup_cfg_n);
    check("  протокол t — DoT", DNSP_DOT, g_dup_cfg[0].u.proto == DNSP_DOT ? DNSP_DOT : g_dup_cfg[1].u.proto);
    check("  кэш из заголовка", 128, (int)g_dcache_cfg.entries);
    check("  у канала апстрим", 1, g_dch[0].up > 0 && g_dch[1].up > 0);
    free(txt);

    /* Без dns — старый формат до байта. */
    f = fopen(sp, "w");
    fprintf(f, "version: 2\nlan: { devices: [br-lan] }\nlists:\n  la: { domains_file: %s }\n"
               "outputs:\n  vpn: { kind: interface, device: wg0 }\nrules:\n  - { name: ra, to: [la], out: vpn }\n", lst);
    fclose(f);
    static struct spec cfg2;
    check("спека без dns читается", 0, load_spec(sp, &cfg2, &e) < 0);
    txt = NULL; m = open_memstream(&txt, &tn);
    tabfmt_build(&cfg2, m); fclose(m);
    check("таблица без dns: заголовок «1»", 0, strncmp(txt, "1\n", 2));
    check("  ни одного dns: и строки апстрима", 1, strstr(txt, "dns:") == NULL && g_dup_cfg_n == 0);
    for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);
    memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
    g_dch_n = 0;
    check("  разбор старой", 0, tabfmt_parse(txt, tn));
    check("  кэша нет", 0, (int)g_dcache_cfg.entries);
    free(txt);

    /* ---- группы серверов и сервер для имён вне правил (dns.other) ---- */
    f = fopen(sp, "w");
    fprintf(f, "version: 2\nlan: { devices: [br-lan] }\nlists:\n  la: { domains_file: %s }\n  lb: { domains_file: %s }\n"
               "outputs:\n  vpn: { kind: interface, device: wg0 }\n"
               "dns:\n  upstream: both\n  other: oth\n  upstreams:\n"
               "    both: { servers: [b, a], mode: race }\n"
               "    a: { url: 'udp://192.0.2.1' }\n    b: { url: 'udp://192.0.2.2', out: vpn }\n"
               "    c: { url: 'udp://192.0.2.3' }\n    unused: { url: 'udp://192.0.2.4', out: vpn }\n"
               "    oth: { servers: [c, a] }\n"
               "rules:\n  - { name: ra, to: [la], out: vpn }\n"
               "  - { name: rb, to: [lb], out: vpn, dns: { servers: [c], mode: failover } }\n", lst, lst2);
    fclose(f);
    static struct spec cfgg;
    check("спека с группами и dns.other читается", 0, load_spec(sp, &cfgg, &e) < 0);
    check("  группа both: race, члены b и a по порядку", 1, cfgg.dns.up[0].grp == DNSG_RACE &&
          cfgg.dns.up[0].mem_n == 2 && cfgg.dns.up[0].mem[0] == 2 && cfgg.dns.up[0].mem[1] == 1);
    check("  группа без mode — failover", DNSG_FAILOVER, cfgg.dns.up[5].grp);
    check("  dns.other — группа oth", 6, (int)cfgg.dns.other);
    check("  своя группа правила rb", 1, cfgg.rule[1].dns && cfgg.dns.up[cfgg.rule[1].dns - 1].grp == DNSG_FAILOVER &&
          cfgg.dns.up[cfgg.rule[1].dns - 1].inl);
    check("  член группы через выход используется (страж выхода)", 1, spec_dns_up_used(&cfgg, 2));
    check("  сервер вне групп и назначений не используется", 0, spec_dns_up_used(&cfgg, 4));
    check("  член группы dns.other используется", 1, spec_dns_up_used(&cfgg, 3));
    cfgg.out[0].mark = 0x00100000;
    txt = NULL; m = open_memstream(&txt, &tn);
    tabfmt_build(&cfgg, m); fclose(m);
    check("таблица: седьмое число заголовка — dns.other", 1, !strncmp(txt, "2 6 0 10 3600 30 ", 17));
    check("  строка группы race: члены номерами строк", 1, strstr(txt, "\nboth|group:race|-|0|1,2|-\n") != NULL);
    {
        const char *pb = strstr(txt, "\nb|udp://192.0.2.2|vpn|1048576|-|-\n"), *pg = strstr(txt, "\nboth|");
        check("  члены — раньше группы, b с меткой выхода", 1, pb && pg && pb < pg);
    }
    check("  неиспользуемый сервер в таблицу не идёт", 1, strstr(txt, "unused|") == NULL);
    check("  группа dns.other и своя группа правила", 1, strstr(txt, "\noth|group:failover|-|0|") != NULL &&
          strstr(txt, "\nrb|group:failover|-|0|") != NULL);
    for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);
    memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
    g_dch_n = 0;
    check("  разбор своей таблицы", 0, tabfmt_parse(txt, tn));
    check("  апстримов шесть", 6, (int)g_dup_cfg_n);
    {
        int gi = -1, oi = -1;
        for (size_t i = 0; i < g_dup_cfg_n; i++) {
            if (!strcmp(g_dup_cfg[i].u.name, "both")) gi = (int)i;
            if (!strcmp(g_dup_cfg[i].u.name, "oth")) oi = (int)i;
        }
        check("  группа both разобрана: race, два члена-сервера", 1, gi >= 0 && g_dup_cfg[gi].grp == DNSG_RACE &&
              g_dup_cfg[gi].gm_n == 2 && !strcmp(g_dup_cfg[g_dup_cfg[gi].gm[0]].u.name, "b") &&
              !strcmp(g_dup_cfg[g_dup_cfg[gi].gm[1]].u.name, "a"));
        check("  g_dup_other — строка группы oth", oi + 1, (int)g_dup_other);
    }
    free(txt);
    /* Испорченная строка группы: член — группа и номер вне таблицы — выпадают. */
    {
        const char *t = "0 3 0 10 3600 30 3\nx|udp://192.0.2.1|-|0|-|-\ng|group:race|-|0|1,3,9|-\nh|group:failover|-|0|2,1|-\n";
        check("таблица с группой в группе разбирается", 0, tabfmt_parse(t, strlen(t)));
        check("  у h остался только сервер x", 1, g_dup_cfg[2].gm_n == 1 && g_dup_cfg[2].gm[0] == 0);
        check("  у g — только x", 1, g_dup_cfg[1].gm_n == 1 && g_dup_cfg[1].gm[0] == 0);
        check("  dns.other — h", 3, (int)g_dup_other);
        const char *t2 = "0 1 0 10 3600 30 2\nx|udp://192.0.2.1|-|0|-|-\n";
        check("  dns.other вне таблицы — отказ разбора", -1, tabfmt_parse(t2, strlen(t2)));
    }
    /* Годный ответ и пауза после отказа. */
    {
        uint8_t aa[64];
        size_t al = mk_answer(aa, "g.test", 60, 0, 1);
        check("годный ответ: NOERROR", 1, dup_ans_good(aa, al));
        al = mk_answer(aa, "g.test", 60, 3, 0);
        check("  NXDOMAIN — годный", 1, dup_ans_good(aa, al));
        al = mk_answer(aa, "g.test", 60, 2, 0);
        check("  SERVFAIL — нет", 0, dup_ans_good(aa, al));
        al = mk_answer(aa, "g.test", 60, 5, 0);
        check("  REFUSED — нет", 0, dup_ans_good(aa, al));
        check("  нет ответа — нет", 0, dup_ans_good(NULL, 0));
        struct dpause pz = {0};
        dpause_fail(&pz, 1000);
        check("пауза: первая 5 с", 6000, (int)pz.until_ms);
        check("  на паузе", 1, dpause_on(&pz, 5999));
        check("  кончилась", 0, dpause_on(&pz, 6000));
        dpause_fail(&pz, 7000);
        check("  вторая — вдвое длиннее", 17000, (int)pz.until_ms);
        for (int i = 0; i < 20; i++) dpause_fail(&pz, 20000);
        check("  потолок 300 с", 320000, (int)pz.until_ms);
        dpause_ok(&pz);
        check("  годный ответ снимает паузу", 0, dpause_on(&pz, 20000));
        dpause_fail(&pz, 30000);
        check("  и снова первая 5 с", 35000, (int)pz.until_ms);
        /* Победа не переживает более позднего отказа: ответ на вопрос, ушедший ДО последнего отказа
         * (медленный годный ответ, пришедший после SERVFAIL на более новый вопрос), паузу не снимает. */
        struct dpause pl = {0};
        dpause_fail(&pl, 1000);
        dpause_ok_at(&pl, 900);
        check("поздняя победа (вопрос старше отказа) паузу не снимает", 1, dpause_on(&pl, 2000));
        check("  но в счёт годных идёт", 1, (int)pl.ok);
        dpause_ok_at(&pl, 1500);
        check("победа на вопрос новее отказа — снимает", 0, dpause_on(&pl, 2000));
        dpause_fail(&pl, 3000);
        check("  и после неё отказ снова первая пауза", 8000, (int)pl.until_ms);
    }

    /* Отказы спеки. */
    const char *bad[] = {
        "dns: { upstreams: { a: { url: 'tls://dns.test' } } }",                    /* нечем разрешить имя */
        "dns: { upstreams: { a: { url: 'quic://dns.test' } } }",                    /* DoQ: нечем разрешить имя */
        "dns: { upstream: nope }",                                                  /* нет такого */
        "dns: { upstreams: { a: { url: 'tls://1.1.1.1', out: nope } } }",          /* нет выхода */
        "dns: { cache_ttl: { min: 100, max: 10 } }",                                /* min > max */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a] }, h: { servers: [g, a] } } }", /* группа в группе */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a, nope] } } }", /* нет члена */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a, a] } } }",    /* член дважды */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [] } } }",        /* пустая группа */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a], mode: fast } } }", /* режим */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a], url: 'udp://1.1.1.1' } } }", /* и то и то */
        "dns: { upstreams: { g: { servers: [g] } } }",                              /* сама в себе */
        "dns: { other: nope }",                                                     /* нет такого */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        f = fopen(sp, "w");
        fprintf(f, "version: 2\nlan: { devices: [br-lan] }\noutputs:\n  vpn: { kind: interface, device: wg0 }\n%s\n", bad[i]);
        fclose(f);
        static struct spec cfg3;
        spec_release(&cfg3);
        struct err e3 = {0};
        char nm[80]; snprintf(nm, sizeof(nm), "отказ спеки №%zu", i + 1);
        check(nm, 1, load_spec(sp, &cfg3, &e3) < 0);
    }

    /* ---- кэш ---- */
    struct dcache_cfg cc = { 8, 10, 100, 30 };
    dcache_config(&cc);
    uint8_t a[512], q[512], out[512];
    size_t an = mk_answer(a, "x.test", 300, 0, 1), qn = mk_query(q, "x.test");
    size_t qlen = an - 16;
    check("кэш включён", 1, dcache_on());
    check("положен ответ", 1, dcache_put(1, a, an, 1000));
    size_t on = dcache_get(1, q, qn, out, sizeof(out), 1010);
    check("выдан из кэша", (int)an, (int)on);
    check("  номер — как у вопроса", (q[0] << 8) | q[1], (out[0] << 8) | out[1]);
    check("  TTL зажат сверху (300 -> 100) и уменьшен на возраст 10", 90, (int)rr_ttl(out, on, qlen));
    check("  другой апстрим — промах", 0, (int)dcache_get(2, q, qn, out, sizeof(out), 1010));
    check("  после срока — промах", 0, (int)dcache_get(1, q, qn, out, sizeof(out), 1100));
    an = mk_answer(a, "y.test", 2, 0, 1);
    dcache_put(1, a, an, 2000);
    qn = mk_query(q, "y.test");
    on = dcache_get(1, q, qn, out, sizeof(out), 2000);
    check("TTL 2 поднят до min 10", 10, (int)rr_ttl(out, on, an - 16));
    an = mk_answer(a, "n.test", 0, 3, 0);
    check("NXDOMAIN кладётся", 1, dcache_put(1, a, an, 3000));
    qn = mk_query(q, "n.test");
    check("  живёт negative (30 с)", 1, dcache_get(1, q, qn, out, sizeof(out), 3029) > 0);
    check("  и не дольше", 0, (int)dcache_get(1, q, qn, out, sizeof(out), 3030));
    an = mk_answer(a, "s.test", 0, 2, 0);
    check("SERVFAIL не кладётся", 0, dcache_put(1, a, an, 3000));
    an = mk_answer(a, "Z.Test", 60, 0, 1);
    dcache_put(1, a, an, 4000);
    qn = mk_query(q, "z.TEST");
    check("имя без учёта регистра", 1, dcache_get(1, q, qn, out, sizeof(out), 4001) > 0);
    for (int i = 0; i < 40; i++) {
        char nm[32]; snprintf(nm, sizeof(nm), "e%d.test", i);
        an = mk_answer(a, nm, 60, 0, 1);
        dcache_put(1, a, an, 5000);
    }
    struct dcache_cfg c0 = { 0, 0, 0, 0 };
    dcache_config(&c0);
    check("кэш 0 — выключен", 0, dcache_on());

    /* ---- DoQ: кадры RFC 9250 ---- */
    {
        uint8_t qq[64], fr[128], rs[300];
        size_t qlen = mk_query(qq, "doq.test");
        qq[0] = 0xAB; qq[1] = 0xCD;                    /* номер клиента */
        size_t fl = doq_frame_query(fr, sizeof(fr), qq, qlen);
        check("DoQ: кадр запроса = 2 + длина сообщения", (int)(2 + qlen), (int)fl);
        check("  длина в сетевом порядке", (int)qlen, (fr[0] << 8) | fr[1]);
        check("  номер сообщения в кадре — 0 (RFC 9250, 4.2.1)", 0, (fr[2] << 8) | fr[3]);
        check("  остальное сообщение — как есть", 0, memcmp(fr + 4, qq + 2, qlen - 2));
        check("  вход не изменён", 0xABCD, (qq[0] << 8) | qq[1]);
        check("  мало места — 0", 0, (int)doq_frame_query(fr, qlen + 1, qq, qlen));
        check("  короче заголовка DNS — 0", 0, (int)doq_frame_query(fr, sizeof(fr), qq, 11));

        /* Ответ на потоке. */
        size_t al = mk_answer(rs + 2, "doq.test", 60, 0, 1);
        rs[0] = (uint8_t)(al >> 8); rs[1] = (uint8_t)al;
        rs[2] = 0; rs[3] = 0;                          /* сервер отвечает с номером 0 */
        const uint8_t *m = NULL; size_t ml = 0;
        check("DoQ: пусто — ждём", 0, doq_take_answer(rs, 0, &m, &ml));
        check("  один байт длины — ждём", 0, doq_take_answer(rs, 1, &m, &ml));
        check("  длина есть, тела нет — ждём", 0, doq_take_answer(rs, 2, &m, &ml));
        check("  без последнего байта — ждём", 0, doq_take_answer(rs, 2 + al - 1, &m, &ml));
        check("  целый ответ", 1, doq_take_answer(rs, 2 + al, &m, &ml));
        check("  длина сообщения", (int)al, (int)ml);
        check("  указатель — за длиной", 1, m == rs + 2);
        check("  лишний байт после сообщения — нарушение формата", -1, doq_take_answer(rs, 2 + al + 1, &m, &ml));
        rs[0] = 0; rs[1] = 5;
        check("  длина короче заголовка DNS — нарушение", -1, doq_take_answer(rs, 2 + 5, &m, &ml));
        rs[0] = 0xFF; rs[1] = 0xFF;
        check("  длина 65535 — ждём (предел формата)", 0, doq_take_answer(rs, 100, &m, &ml));

        /* Коды RFC 9250, раздел 8.4. */
        check("DOQ_NO_ERROR", 0, (int)DOQ_NO_ERROR);
        check("DOQ_INTERNAL_ERROR", 1, (int)DOQ_INTERNAL_ERROR);
        check("DOQ_PROTOCOL_ERROR", 2, (int)DOQ_PROTOCOL_ERROR);
        check("DOQ_REQUEST_CANCELLED", 3, (int)DOQ_REQUEST_CANCELLED);
        check("DOQ_EXCESSIVE_LOAD", 4, (int)DOQ_EXCESSIVE_LOAD);
        check("DOQ_UNSPECIFIED_ERROR", 5, (int)DOQ_UNSPECIFIED_ERROR);
        check_str("  имя кода", "DOQ_PROTOCOL_ERROR", doq_err_name(DOQ_PROTOCOL_ERROR));
        check_str("  неизвестный код", "DOQ_?", doq_err_name(0x1234));
    }

    /* ---- DoH по HTTP/2: кадры и HPACK (RFC 9113, RFC 7541) ---- */
    {
        uint8_t hb[256], rq[2048];
        struct h2d_frame f;
        size_t hl = h2d_hello(hb, sizeof(hb));
        check("h2: преамбула + SETTINGS = 24 + 9 + 12 байт", 45, (int)hl);
        check("  начинается с PRI * HTTP/2.0", 0, memcmp(hb, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24));
        check("  дальше кадр SETTINGS", 1, h2d_next(hb + 24, hl - 24, &f));
        check("  тип SETTINGS, поток 0", (H2D_SETTINGS << 8) | 0, (f.type << 8) | (int)f.sid);
        check("  HEADER_TABLE_SIZE = 0", 0, (f.body[0] << 8 | f.body[1]) != 1 || f.body[2] || f.body[3] || f.body[4] || f.body[5]);
        check("  ENABLE_PUSH = 0", 0, (f.body[6] << 8 | f.body[7]) != 2 || f.body[8] || f.body[9] || f.body[10] || f.body[11]);
        check("  мало места — 0", 0, (int)h2d_hello(hb, 44));

        uint8_t qq[64];
        size_t qlen = mk_query(qq, "h2.test");
        qq[0] = 0xAB; qq[1] = 0xCD;
        size_t rl = h2d_request(rq, sizeof(rq), 7, "dns.test:8443", "/dns-query", qq, qlen);
        check("h2: запрос собран", 1, rl > 0);
        check("  первый кадр — HEADERS с END_HEADERS на потоке 7", 1, h2d_next(rq, rl, &f) == 1 && f.type == H2D_HEADERS &&
              f.flags == H2D_F_END_HEADERS && f.sid == 7);
        check("  заголовки: :method POST и :scheme https — по индексам 3 и 7", 1, f.body[0] == 0x83 && f.body[1] == 0x87);
        check("  путь и authority — литералами с именами 4 и 1", 1, f.body[2] == 0x04 && f.body[3] == 10 &&
              memcmp(f.body + 4, "/dns-query", 10) == 0 && f.body[14] == 0x01 && f.body[15] == 13 &&
              memcmp(f.body + 16, "dns.test:8443", 13) == 0);
        check("  в блоке есть application/dns-message", 1, memmem(f.body, f.len, "application/dns-message", 23) != NULL);
        size_t first = f.total;
        check("  второй кадр — DATA с END_STREAM на том же потоке", 1, h2d_next(rq + first, rl - first, &f) == 1 &&
              f.type == H2D_DATA && f.flags == H2D_F_END_STREAM && f.sid == 7 && f.len == qlen);
        check("  номер сообщения в теле — 0", 0, f.body[0] | f.body[1]);
        check("  остальное сообщение — как есть", 0, memcmp(f.body + 2, qq + 2, qlen - 2));
        check("  вход не изменён", 0xABCD, (qq[0] << 8) | qq[1]);
        check("  короче заголовка DNS — 0", 0, (int)h2d_request(rq, sizeof(rq), 1, "a", "/", qq, 11));
        check("  мало места — 0", 0, (int)h2d_request(rq, 20, 1, "a", "/", qq, qlen));

        check("h2: половина заголовка кадра — ждём", 0, h2d_next(rq, 5, &f));
        check("  кадр без последнего байта — ждём", 0, h2d_next(rq, first - 1, &f));
        uint8_t big[9] = { 0, 0x40, 1, 0, 0, 0, 0, 0, 1 };      /* длина 16385 */
        check("  кадр длиннее 16384 — нарушение", -1, h2d_next(big, sizeof(big), &f));
        uint8_t hi[9 + 4] = { 0, 0, 4, H2D_WINDOW_UPDATE, 0, 0x80, 0, 0, 3, 0, 0, 1, 0 };
        check("  старший бит номера потока отбрасывается", 3, h2d_next(hi, sizeof(hi), &f) == 1 ? (int)f.sid : -1);

        /* Статус ответа. */
        static const uint8_t s200[] = { 0x88 }, s404[] = { 0x8d }, s500[] = { 0x8e };
        static const uint8_t s505p[] = { 0x08, 3, '5', '0', '5' };                 /* литерал, цифры */
        static const uint8_t s505h[] = { 0x08, 0x83, 0x6c, 0x0d, 0xff };          /* тот же, кодом Хаффмана */
        static const uint8_t s502h[] = { 0x08, 0x82, 0x6c, 0x02 };                /* «502» ровно в 16 бит */
        static const uint8_t s200x[] = { 0x20, 0x88, 0x0f, 0x0d, 0x02, '4', '2' }; /* размер таблицы, статус, content-length */
        static const uint8_t sinc[] = { 0x48, 3, '4', '0', '3' };                  /* с индексацией: имя 8 — 6 бит */
        static const uint8_t s103[] = { 0x08, 3, '1', '0', '3' };
        static const uint8_t strl[] = { 0x0f, 0x0d, 0x02, '4', '2' };              /* только content-length */
        static const uint8_t dyn[] = { 0xbe };                                     /* индекс 62: таблицы нет */
        static const uint8_t cut[] = { 0x08, 5, '5', '0' };
        static const uint8_t junk[] = { 0x08, 3, 'x', '0', '5' };
        static const uint8_t name[] = { 0x00, 7, ':', 's', 't', 'a', 't', 'u', 's', 3, '4', '1', '8' };
        /* «1=0» кодом Хаффмана: '1' 00001, '=' 100000, '0' 00000 — ровно 16 бит. Шестибитный код '='
         * (0x20) лежит выше цифр (0x19…0x1F) и прежде читался как «цифра 10»: 1·100 + 10·10 + 0 = 200. */
        static const uint8_t s1eq0[] = { 0x08, 0x82, 0x0c, 0x00 };
        check("h2: статус 200 (индекс 8)", 200, h2d_status(s200, sizeof(s200)));
        check("  404 (индекс 13)", 404, h2d_status(s404, sizeof(s404)));
        check("  500 (индекс 14)", 500, h2d_status(s500, sizeof(s500)));
        check("  505 литералом с цифрами", 505, h2d_status(s505p, sizeof(s505p)));
        check("  505 кодом Хаффмана (как пишет сервер Quad9)", 505, h2d_status(s505h, sizeof(s505h)));
        check("  502 кодом Хаффмана без набивки", 502, h2d_status(s502h, sizeof(s502h)));
        check("  обновление размера таблицы, статус и прочие поля", 200, h2d_status(s200x, sizeof(s200x)));
        check("  литерал с индексацией", 403, h2d_status(sinc, sizeof(sinc)));
        check("  статус, заданный именем строкой", 418, h2d_status(name, sizeof(name)));
        check("  103 — информационный, код возвращается как есть", 103, h2d_status(s103, sizeof(s103)));
        check("  без :status (трейлеры) — 0", 0, h2d_status(strl, sizeof(strl)));
        check("  ссылка на динамическую таблицу — ошибка", -1, h2d_status(dyn, sizeof(dyn)));
        check("  оборванная строка — ошибка", -1, h2d_status(cut, sizeof(cut)));
        check("  нецифровое значение — ошибка", -1, h2d_status(junk, sizeof(junk)));
        check("  нецифровой знак кодом Хаффмана («1=0») — ошибка, а не 200", -1, h2d_status(s1eq0, sizeof(s1eq0)));
        char nb[24];
        check_str("h2: имя кода 7", "REFUSED_STREAM", h2d_errname(H2D_E_REFUSED_STREAM, nb, sizeof(nb)));
        check_str("  неизвестный код", "код 99", h2d_errname(99, nb, sizeof(nb)));
    }

    unlink(lst); unlink(lst2); unlink(sp); rmdir(dir);
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
