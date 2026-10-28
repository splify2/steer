/* Дерево YAML (src/lib/ynode.c поверх libyaml, src/third_party/libyaml): стенд модуля — модуль и
 * библиотека линкуются отдельными объектами (tests/unit.h, правило юнит-стендов).
 *
 * Что сторожит:
 *   - пример спеки v2 из docs/architecture.md, раздел 3, разбирается и даёт те значения, которые
 *     в нём написаны (копия ниже — для проверок по значениям; сам блок из документа читается тоже,
 *     но только на «разобрался и это version 2»: документ правят, и стенд не должен падать от
 *     правки примера);
 *   - JSON спек v1 (тексты из tests/gen.sh) читается той же функцией, и дерево совпадает по смыслу
 *     с той же спекой, записанной блочным YAML: строки — строками, числа — числами;
 *   - сообщения об ошибках называют файл, строку и столбец;
 *   - отказы: алиасы и якоря, глубина, размер, число узлов, повторный ключ, составной ключ,
 *     второй документ, пустой документ, нулевой байт, не-UTF-8.
 *
 *   build/yamlmatch               стенд (так зовёт make test)
 *   build/yamlmatch --dump ФАЙЛ   печать дерева одной строкой: {"k":v,...}, [..], s"строка" для
 *                                 скаляров в кавычках, pТЕКСТ без кавычек — для сверки с другим
 *                                 разборщиком JSON руками. */
#include <stdlib.h>
#include <unistd.h>

#include "unit.h"
#include "ynode.h"

/* Значение скаляра, иначе NULL. */
static const char *ynode_str(const struct ynode *n) {
    return n && n->kind == YN_SCALAR ? n->str : NULL;
}

/* Файл для --dump: целиком в память и ydoc_parse_buf. */
static struct ydoc *parse_file(const char *path, struct err *e) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        snprintf(e->msg, sizeof(e->msg), "%s: не открывается", path);
        return NULL;
    }
    size_t len = 0, cap = 0;
    char *buf = NULL;
    for (;;) {
        if (len == cap) {
            char *nb = realloc(buf, cap = cap ? cap * 2 : 16384);
            if (!nb) { free(buf); fclose(f); snprintf(e->msg, sizeof(e->msg), "нет памяти"); return NULL; }
            buf = nb;
        }
        size_t got = fread(buf + len, 1, cap - len, f);
        if (!got) break;
        len += got;
    }
    fclose(f);
    struct ydoc *d = ydoc_parse_buf(buf, len, path, e);
    free(buf);
    return d;
}

/* ---- печать дерева (--dump и сообщения стенда) ------------------------------------------ */
static void dump_str(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        if (c == '"') fputs("\\\"", f);
        else if (c == '\\') fputs("\\\\", f);
        else if (c < 0x20) fprintf(f, "\\u%04x", c);
        else fputc(c, f);
    }
    fputc('"', f);
}

static void dump(FILE *f, const struct ynode *n) {
    if (n->kind == YN_MAP) {
        fputc('{', f);
        for (size_t i = 0; i < ynode_len(n); i++) {
            if (i) fputc(',', f);
            dump_str(f, ynode_str(ynode_key_at(n, i)));
            fputc(':', f);
            dump(f, ynode_val_at(n, i));
        }
        fputc('}', f);
    } else if (n->kind == YN_SEQ) {
        fputc('[', f);
        for (size_t i = 0; i < ynode_len(n); i++) {
            if (i) fputc(',', f);
            dump(f, ynode_at(n, i));
        }
        fputc(']', f);
    } else if (n->style == YS_PLAIN) {
        fprintf(f, "p%s", n->str);
    } else {
        fputc('s', f);
        dump_str(f, n->str);
    }
}

/* ---- сравнение «по смыслу» -------------------------------------------------------------- */
/* Скаляр без кавычек, который читается как null, логическое или целое, — значение этого типа;
 * всё остальное — строка, в каком бы стиле ни было записано (`wg0` и `"wg0"` — одно и то же). */
static int sclass(const struct ynode *n) {
    long l;
    int b;
    if (ynode_is_null(n)) return 1;
    if (ynode_bool(n, &b) == 0) return 2;
    if (ynode_long(n, &l) == 0) return 3;
    return 0;
}

static int same(const struct ynode *a, const struct ynode *b) {
    if (a->kind != b->kind) return 0;
    if (a->kind == YN_SCALAR)
        return sclass(a) == sclass(b) && (sclass(a) == 1 || strcmp(a->str, b->str) == 0);
    if (ynode_len(a) != ynode_len(b)) return 0;
    for (size_t i = 0; i < ynode_len(a); i++) {
        if (a->kind == YN_SEQ) {
            if (!same(ynode_at(a, i), ynode_at(b, i))) return 0;
        } else {
            /* Порядок ключей в отображении смысла не несёт — ищется по имени. */
            const char *k = ynode_str(ynode_key_at(a, i));
            const struct ynode *bv = ynode_get(b, k);
            if (!bv || !same(ynode_val_at(a, i), bv)) return 0;
        }
    }
    return 1;
}

/* ---- помощники стенда ------------------------------------------------------------------ */
static struct ydoc *parse(const char *text, struct err *e) {
    memset(e, 0, sizeof(*e));
    return ydoc_parse_buf(text, strlen(text), "t.yaml", e);
}

/* Отказ с точным текстом: документа нет, сообщение — ровно want. */
static void refuse_eq(const char *what, const char *text, const char *want) {
    struct err e;
    struct ydoc *d = parse(text, &e);
    check(what, 1, d == NULL);
    check_str(what, want, e.msg);
    ydoc_free(d);
}

/* Отказ с началом сообщения (место) и подстрокой (суть) — там, где хвост текста — от libyaml. */
static void refuse_has(const char *what, const char *text, const char *prefix, const char *needle) {
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(text, strlen(text), "t.yaml", &e);
    check(what, 1, d == NULL);
    int ok = strncmp(e.msg, prefix, strlen(prefix)) == 0 && strstr(e.msg, needle) != NULL;
    check(what, 1, ok);
    if (!ok) printf("     сообщение: \"%s\"\n", e.msg);
    ydoc_free(d);
}

static const char *sget(const struct ynode *root, const char *a, const char *b, const char *c) {
    const struct ynode *n = ynode_get(root, a);
    if (b) n = ynode_get(n, b);
    if (c) n = ynode_get(n, c);
    const char *s = ynode_str(n);
    return s ? s : "(нет)";
}

/* ---- пример спеки v2 (docs/architecture.md, раздел 3), байт в байт на момент переноса ------ */
static const char spec_v2[] =
"version: 2\n"
"\n"
"lan: { devices: [br-lan] }            # кто наши клиенты по умолчанию\n"
"\n"
"clients:                              # именованные группы клиентов\n"
"  kids: { mac: [aa:bb:cc:dd:ee:01] }\n"
"  tv:   { addr: [192.168.1.50] }\n"
"  tg:   { app: [org.telegram.messenger] }      # только на телефоне\n"
"\n"
"lists:                                # что: назначения\n"
"  youtube: { srs: lists/youtube.srs }\n"
"  work:    { domains: [corp.example], prefixes: [10.20.0.0/16] }\n"
"  voice:   { prefixes_file: lists/dc.lst, proto: udp, ports: [50000-65535] }\n"
"\n"
"outputs:                              # куда\n"
"  wg0:  { kind: interface, device: wg0 }\n"
"  wg1:  { kind: interface, device: wg1 }\n"
"  nl:   { kind: tunnel, protocol: vless, subscription: sub/nl, nodes: [3, 5],\n"
"          transport: ws, over: wg0 }\n"
"  dpi:  { kind: block }\n"
"  res:  { kind: group, pick: order,   members: [wg0, wg1], on_fail: drop }\n"
"  eu:   { kind: group, pick: manual,  members: [nl, res], default: nl }\n"
"  bal:  { kind: group, pick: balance, members: [nl, wg1] }\n"
"\n"
"dns:\n"
"  mode: fakeip                        # умолчание; realip остаётся насовсем\n"
"  cache: 2048\n"
"  upstreams:\n"
"    nl-doh: { url: https://1.1.1.1/dns-query, out: nl }\n"
"\n"
"rules:                                # сверху вниз, выше — сильнее\n"
"  - { name: yt,   for: [kids, tv], to: [youtube], out: dpi, resolve: realip }\n"
"  - { name: work, to: [work, voice], out: eu, dns: nl-doh }\n";

static void test_spec_v2(void) {
    struct err e;
    struct ydoc *d = parse(spec_v2, &e);
    check("v2: пример из раздела 3 разбирается", 1, d != NULL);
    if (!d) { printf("     %s\n", e.msg); return; }
    const struct ynode *r = ydoc_root(d);
    check("v2: корень — отображение из 7 разделов", 7, (long)ynode_len(r));
    static const char *order[] = { "version", "lan", "clients", "lists", "outputs", "dns", "rules" };
    int in_order = 1;
    for (size_t i = 0; i < 7; i++)
        if (strcmp(ynode_str(ynode_key_at(r, i)) ? ynode_str(ynode_key_at(r, i)) : "", order[i]))
            in_order = 0;
    check("v2: разделы — в порядке текста", 1, in_order);
    long v = 0;
    check("v2: version — число 2", 0, ynode_long(ynode_get(r, "version"), &v));
    check("v2: version = 2", 2, v);
    check_str("v2: lan.devices[0]", "br-lan", ynode_str(ynode_at(ynode_get(ynode_get(r, "lan"), "devices"), 0)));
    check_str("v2: MAC с двоеточиями в потоковом списке — одна строка", "aa:bb:cc:dd:ee:01",
              ynode_str(ynode_at(ynode_get(ynode_get(ynode_get(r, "clients"), "kids"), "mac"), 0)));
    check_str("v2: clients.tg.app[0]", "org.telegram.messenger",
              ynode_str(ynode_at(ynode_get(ynode_get(ynode_get(r, "clients"), "tg"), "app"), 0)));
    check_str("v2: lists.voice.ports[0] — строка диапазона", "50000-65535",
              ynode_str(ynode_at(ynode_get(ynode_get(ynode_get(r, "lists"), "voice"), "ports"), 0)));
    check_str("v2: lists.work.prefixes[0]", "10.20.0.0/16",
              ynode_str(ynode_at(ynode_get(ynode_get(ynode_get(r, "lists"), "work"), "prefixes"), 0)));
    const struct ynode *nl = ynode_get(ynode_get(r, "outputs"), "nl");
    check("v2: outputs.nl — 6 ключей через перенос строки", 6, (long)ynode_len(nl));
    long n0 = 0, n1 = 0;
    ynode_long(ynode_at(ynode_get(nl, "nodes"), 0), &n0);
    ynode_long(ynode_at(ynode_get(nl, "nodes"), 1), &n1);
    check("v2: outputs.nl.nodes = [3, 5]", 35, n0 * 10 + n1);
    check_str("v2: outputs.nl.over", "wg0", sget(nl, "over", NULL, NULL));
    check("v2: outputs.nl.over — со строки 19", 19, (long)ynode_get(nl, "over")->line);
    check_str("v2: outputs.res.on_fail", "drop", sget(r, "outputs", "res", "on_fail"));
    check("v2: outputs.bal.members — два", 2, (long)ynode_len(ynode_get(ynode_get(ynode_get(r, "outputs"), "bal"), "members")));
    check_str("v2: комментарий после значения не входит в него", "fakeip", sget(r, "dns", "mode", NULL));
    long cache = 0;
    check("v2: dns.cache — число", 0, ynode_long(ynode_get(ynode_get(r, "dns"), "cache"), &cache));
    check("v2: dns.cache = 2048", 2048, cache);
    check_str("v2: URL с двоеточием в потоковом отображении", "https://1.1.1.1/dns-query",
              ynode_str(ynode_get(ynode_get(ynode_get(ynode_get(r, "dns"), "upstreams"), "nl-doh"), "url")));
    const struct ynode *rules = ynode_get(r, "rules");
    check("v2: rules — последовательность из двух", 2, (long)ynode_len(rules));
    check("v2: rules — вид YN_SEQ", YN_SEQ, rules->kind);
    check_str("v2: rules[0].for[1]", "tv", ynode_str(ynode_at(ynode_get(ynode_at(rules, 0), "for"), 1)));
    check_str("v2: rules[1].dns", "nl-doh", sget(ynode_at(rules, 1), "dns", NULL, NULL));
    check("v2: rules[1] — строка 33", 33, (long)ynode_at(rules, 1)->line);
    check("v2: rules[1] — столбец 5 (после «- »)", 5, (long)ynode_at(rules, 1)->col);
    check_str("v2: ydoc_name — имя из вызова", "t.yaml", ydoc_name(d));
    ydoc_free(d);
}

/* Блок ```yaml из раздела 3 самого документа: разобрался, version = 2. Стенды идут из корня
 * репозитория (make test); нет документа — громкий провал, а не пропуск. */
static void test_doc_block(void) {
    FILE *f = fopen("docs/architecture.md", "r");
    check("документ: docs/architecture.md читается", 1, f != NULL);
    if (!f) return;
    static char buf[1 << 16];
    char line[1024];
    size_t len = 0;
    int state = 0;                /* 0 — ищем раздел, 1 — ищем начало блока, 2 — в блоке */
    while (fgets(line, sizeof(line), f)) {
        if (state == 0 && strncmp(line, "## 3. ", 6) == 0) state = 1;
        else if (state == 1 && strncmp(line, "```yaml", 7) == 0) state = 2;
        else if (state == 2 && strncmp(line, "```", 3) == 0) { state = 3; break; }
        else if (state == 2 && len + strlen(line) < sizeof(buf)) {
            memcpy(buf + len, line, strlen(line));
            len += strlen(line);
        }
    }
    fclose(f);
    check("документ: блок yaml в разделе 3 найден", 3, state);
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(buf, len, "docs/architecture.md", &e);
    check("документ: блок разбирается", 1, d != NULL);
    if (!d) printf("     %s\n", e.msg);
    long v = 0;
    check("документ: version = 2", 2, ynode_long(ynode_get(ydoc_root(d), "version"), &v) == 0 ? v : -1);
    ydoc_free(d);
}

/* ---- JSON спек v1 ---------------------------------------------------------------------- */
/* Тексты из tests/gen.sh ($tmp заменён путём). Первый — как есть, второй — сжатый без пробелов
 * (так пишет JSON splify2: `"a":1`, без пробела после двоеточия — у YAML 1.1 это место спорное,
 * libyaml 0.2.5 принимает его после ключа в кавычках). */
static const char v1_dspec[] =
"{ \"schema\": 1, \"from_default\": [\"192.168.1.0/24\"], \"lan_device\": \"br-lan\",\n"
"  \"outputs\": { \"geo\": { \"kind\": \"interface\", \"device\": \"tun0\" } },\n"
"  \"channels\": [ { \"name\": \"dom\", \"match\": { \"domains_file\": \"/tmp/x/d.lst\" }, \"out\": \"geo\" } ] }\n";
static const char v1_dspec_yaml[] =
"schema: 1\n"
"from_default:\n"
"  - 192.168.1.0/24\n"
"lan_device: br-lan\n"
"outputs:\n"
"  geo:\n"
"    kind: interface\n"
"    device: tun0\n"
"channels:\n"
"  - name: dom\n"
"    match:\n"
"      domains_file: /tmp/x/d.lst\n"
"    out: geo\n";
static const char v1_mix_compact[] =
"{\"schema\":1,\"outputs\":{\"vpn\":{\"kind\":\"interface\",\"device\":\"wg0\"}},"
"\"channels\":[{\"name\":\"mix\",\"from\":[\"192.168.1.5\",\"a4:83:e7:2c:11:0f\"],"
"\"match\":{\"prefixes_file\":\"/tmp/x/a.lst\"},\"out\":\"vpn\"}]}";
static const char v1_mix_yaml[] =
"schema: 1\n"
"outputs: { vpn: { kind: interface, device: wg0 } }\n"
"channels:\n"
"  - name: mix\n"
"    from: [192.168.1.5, a4:83:e7:2c:11:0f]\n"
"    match: { prefixes_file: /tmp/x/a.lst }\n"
"    out: vpn\n";

static void same_as(const char *what, const char *json, const char *yaml) {
    struct err e1, e2;
    struct ydoc *a = parse(json, &e1), *b = parse(yaml, &e2);
    check(what, 1, a != NULL && b != NULL);
    if (!a) printf("     json: %s\n", e1.msg);
    if (!b) printf("     yaml: %s\n", e2.msg);
    if (a && b) {
        int eq = same(ydoc_root(a), ydoc_root(b));
        check(what, 1, eq);
        if (!eq) {
            printf("     json: "); dump(stdout, ydoc_root(a));
            printf("\n     yaml: "); dump(stdout, ydoc_root(b)); printf("\n");
        }
    }
    ydoc_free(a);
    ydoc_free(b);
}

static void test_json(void) {
    same_as("v1: dspec из gen.sh — JSON и блочный YAML совпадают по смыслу", v1_dspec, v1_dspec_yaml);
    same_as("v1: mix без пробелов («\"a\":1») — совпадает с YAML", v1_mix_compact, v1_mix_yaml);

    struct err e;
    struct ydoc *d = parse(v1_dspec, &e);
    const struct ynode *r = ydoc_root(d);
    long s = 0;
    check("v1: schema — число без кавычек", 0, ynode_long(ynode_get(r, "schema"), &s));
    check("v1: у строки JSON стиль «двойные кавычки»", YS_DOUBLE, ynode_get(r, "lan_device")->style);
    check("v1: channels[0].match — со строки 3", 3, (long)ynode_get(ynode_at(ynode_get(r, "channels"), 0), "match")->line);
    ydoc_free(d);

    /* Всё, что JSON умеет, а YAML-автору не придёт в голову: экранирования (в том числе \/ и
     * \u), вложенные пустые, отрицательное и дробное число, true/false/null. */
    d = parse("{\"s\":\"a\\\"b\\\\c\\/d\\u00e9\\n\",\"e\":{},\"l\":[],\"n\":-7,\"f\":1.5,"
              "\"t\":true,\"z\":null,\"q\":\"5\"}", &e);
    check("json: экранирования и пустые коллекции разбираются", 1, d != NULL);
    if (!d) printf("     %s\n", e.msg);
    r = ydoc_root(d);
    check_str("json: \\\" \\\\ \\/ \\u00e9 \\n раскрыты", "a\"b\\c/d\xc3\xa9\n", ynode_str(ynode_get(r, "s")));
    check("json: {} — пустое отображение", 1, ynode_get(r, "e")->kind == YN_MAP && ynode_len(ynode_get(r, "e")) == 0);
    check("json: [] — пустая последовательность", 1, ynode_get(r, "l")->kind == YN_SEQ && ynode_len(ynode_get(r, "l")) == 0);
    long n = 0;
    check("json: -7 — целое", 0, ynode_long(ynode_get(r, "n"), &n));
    check("json: -7", -7, n);
    check("json: 1.5 — не целое", -1, ynode_long(ynode_get(r, "f"), &n));
    int b = 0;
    check("json: true — логическое", 0, ynode_bool(ynode_get(r, "t"), &b));
    check("json: true = 1", 1, b);
    check("json: null", 1, ynode_is_null(ynode_get(r, "z")));
    check("json: \"5\" в кавычках — строка, не число", -1, ynode_long(ynode_get(r, "q"), &n));
    ydoc_free(d);
}

/* ---- толкование скаляров (YAML 1.2, базовая схема) ------------------------------------- */
static void test_scalars(void) {
    struct err e;
    struct ydoc *d = parse("a: yes\nb: True\nc: ~\nd: ''\ne:\nf: 0x10\ng: 99999999999999999999999\n"
                           "h: +12\ni: 007\nj: 'null'\nk: |\n  две\n  строки\n", &e);
    check("скаляры: документ разбирается", 1, d != NULL);
    const struct ynode *r = ydoc_root(d);
    int b = -1;
    long n = 0;
    check("скаляры: yes — не логическое (это 1.1)", -1, ynode_bool(ynode_get(r, "a"), &b));
    check("скаляры: True — логическое", 0, ynode_bool(ynode_get(r, "b"), &b));
    check("скаляры: ~ — null", 1, ynode_is_null(ynode_get(r, "c")));
    check("скаляры: '' — пустая строка, не null", 0, ynode_is_null(ynode_get(r, "d")));
    check("скаляры: ключ без значения — null", 1, ynode_is_null(ynode_get(r, "e")));
    check("скаляры: 0x10 — не десятичное целое", -1, ynode_long(ynode_get(r, "f"), &n));
    check("скаляры: переполнение long — отказ", -1, ynode_long(ynode_get(r, "g"), &n));
    check("скаляры: +12 — целое", 0, ynode_long(ynode_get(r, "h"), &n));
    check("скаляры: 007 — десятичное 7 (1.2, не восьмеричное)", 7, ynode_long(ynode_get(r, "i"), &n) == 0 ? n : -1);
    check("скаляры: 'null' в кавычках — строка", 0, ynode_is_null(ynode_get(r, "j")));
    check_str("скаляры: блочный | — строки с переводами", "две\nстроки\n", ynode_str(ynode_get(r, "k")));
    check("скаляры: стиль блочного |", YS_LITERAL, ynode_get(r, "k")->style);
    ydoc_free(d);

    /* Доступ к не тому виду и к NULL — NULL/0, без падения. */
    d = parse("[a, b]\n", &e);
    r = ydoc_root(d);
    check("доступ: get у последовательности — NULL", 1, ynode_get(r, "a") == NULL);
    check("доступ: at за концом — NULL", 1, ynode_at(r, 2) == NULL);
    check("доступ: str у последовательности — NULL", 1, ynode_str(r) == NULL);
    check("доступ: цепочка через NULL — NULL", 1, ynode_str(ynode_get(ynode_get(NULL, "x"), "y")) == NULL);
    check("доступ: len у скаляра — 0", 0, (long)ynode_len(ynode_at(r, 0)));
    struct err ee;
    memset(&ee, 0, sizeof(ee));
    check("ynode_err: возвращает -1", -1, ynode_err(&ee, d, ynode_at(r, 1), "не то значение: %s", "b"));
    check_str("ynode_err: имя:строка:столбец и текст", "t.yaml:1:5: не то значение: b", ee.msg);
    ydoc_free(d);
}

/* ---- отказы ---------------------------------------------------------------------------- */
static void test_errors(void) {
    refuse_has("синтаксис: лишний отступ — строка 3", "a: 1\nb: 2\n  c: 3\n",
               "t.yaml:3:", "ошибка YAML: mapping values are not allowed");
    refuse_has("синтаксис: незакрытый список — место и контекст", "a: [1, 2\nb: 3\n",
               "t.yaml:", "начало в строке 1");
    refuse_has("синтаксис: место — начало конструкции, а не где заметили", "x: 1\na:\n  b: 1\n c: 2\n",
               "t.yaml:1:1:", "замечено в строке 4");
    refuse_has("табуляция в отступе названа", "a:\n\tb: 1\n", "t.yaml:2:", "табуляция");
    refuse_eq("повторный ключ: второе вхождение, строка первого",
              "a: 1\nb: 2\na: 3\n", "t.yaml:3:1: ключ \"a\" повторяется (первый раз — строка 1)");
    refuse_eq("повторный ключ в JSON",
              "{\"a\": 1, \"a\": 2}", "t.yaml:1:10: ключ \"a\" повторяется (первый раз — строка 1)");
    refuse_eq("повторный ключ во вложенном отображении",
              "x:\n  k: 1\n  j: 2\n  k: 3\n", "t.yaml:4:3: ключ \"k\" повторяется (первый раз — строка 2)");
    refuse_has("составной ключ", "? [a, b]\n: 1\n", "t.yaml:1:3:", "ключ отображения — не строка");
    refuse_has("якорь — отказ на строке якоря", "a: &x 1\nb: *x\n", "t.yaml:1:4:", "якорь &x");
    refuse_has("алиас без якоря — отказ", "a: *x\n", "t.yaml:1:4:", "алиас *x");
    /* Ямл-бомба: дальше первой строки разбор не идёт. */
    static const char lol[] =
        "a: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n"
        "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
        "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
        "d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n";
    refuse_has("ямл-бомба остановлена на первом якоре", lol, "t.yaml:1:4:", "якорь &a");
    refuse_has("второй документ", "a: 1\n---\nb: 2\n", "t.yaml:2:1:", "второй документ");
    refuse_eq("пустой поток", "", "t.yaml: документ пуст");
    refuse_eq("только комментарий", "# ничего\n", "t.yaml: документ пуст");
    refuse_has("нулевой байт в строке", "a: \"x\\0y\"\n", "t.yaml:1:4:", "нулевой байт");
    refuse_has("не UTF-8 — строка и столбец", "a: 1\nb: \xff\n", "t.yaml:2:4:", "UTF-8");

    /* Глубина: 64 уровня — можно, 65 — нет. */
    char deep[200];
    for (int lvl = 64; lvl <= 65; lvl++) {
        memset(deep, '[', lvl);
        memset(deep + lvl, ']', lvl);
        struct err e;
        memset(&e, 0, sizeof(e));
        struct ydoc *d = ydoc_parse_buf(deep, 2 * lvl, "t.yaml", &e);
        if (lvl == 64) check("глубина 64 — разбирается", 1, d != NULL);
        else {
            check("глубина 65 — отказ", 1, d == NULL);
            check_str("глубина 65 — место и предел", "t.yaml:1:65: вложенность глубже 64 уровней", e.msg);
        }
        ydoc_free(d);
    }

    /* Узлы: последовательность из YDOC_MAX_NODES - 1 чисел — ровно предел узлов (с самой
     * последовательностью), одним больше — отказ. */
    size_t cnt = YDOC_MAX_NODES - 1, cap = 2 * cnt + 8;
    char *big = malloc(cap);
    for (int extra = 0; extra <= 1; extra++) {
        size_t k = cnt + extra, len = 0;
        big[len++] = '[';
        for (size_t i = 0; i < k; i++) { big[len++] = '1'; big[len++] = ','; }
        big[len - 1] = ']';
        struct err e;
        memset(&e, 0, sizeof(e));
        struct ydoc *d = ydoc_parse_buf(big, len, "t.yaml", &e);
        if (!extra) check("узлов ровно предел — разбирается", 1, d != NULL);
        else {
            check("узлов больше предела — отказ", 1, d == NULL);
            check("узлов больше предела — текст", 1, strstr(e.msg, "в документе больше 262144 узлов") != NULL);
        }
        ydoc_free(d);
    }
    free(big);

    /* Размер: ровно предел (комментарий до конца) — можно, байтом больше — отказ до разбора. */
    char *huge = malloc(YDOC_MAX_BYTES + 1);
    memset(huge, ' ', YDOC_MAX_BYTES + 1);
    memcpy(huge, "a: 1\n#", 6);
    huge[YDOC_MAX_BYTES - 1] = '\n';
    struct err e;
    memset(&e, 0, sizeof(e));
    struct ydoc *d = ydoc_parse_buf(huge, YDOC_MAX_BYTES, "t.yaml", &e);
    check("размер ровно предел — разбирается", 1, d != NULL);
    ydoc_free(d);
    memset(&e, 0, sizeof(e));
    d = ydoc_parse_buf(huge, YDOC_MAX_BYTES + 1, "t.yaml", &e);
    check("размер больше предела — отказ", 1, d == NULL);
    check_str("размер больше предела — текст", "t.yaml: документ больше 4194304 байт", e.msg);
    free(huge);
}

int main(int argc, char **argv) {
    if (argc == 3 && strcmp(argv[1], "--dump") == 0) {
        struct err e;
        memset(&e, 0, sizeof(e));
        struct ydoc *d = parse_file(argv[2], &e);
        if (!d) { fprintf(stderr, "%s\n", e.msg); return 2; }
        dump(stdout, ydoc_root(d));
        fputc('\n', stdout);
        ydoc_free(d);
        return 0;
    }
    test_spec_v2();
    test_doc_block();
    test_json();
    test_scalars();
    test_errors();
    return unit_done("yamlmatch");
}
