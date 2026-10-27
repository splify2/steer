/* СХЕМА СПЕКИ v2 — `steer spec-schema [--json]` (формат — docs/spec-schema.md).
 *
 * Схема строится из таблиц ключей (v2keys.c), которыми пользуется разбор (v2.c), из реестра видов
 * (kind_ops.caps и .keys — кому какой общий ключ и ключ вида принадлежит) и из реестра плагинов
 * (виды установленных плагинов, схемы их ключей из манифестов). Отдельного списка ключей здесь нет.
 *
 * Формат — подмножество JSON Schema того же вида, что у ключей вида плагина
 * (plugin-sdk/schema/kind-keys.schema.json, разбор — kinds/plugin.c): type, enum, default, pattern,
 * minimum/maximum, minItems/maxItems, items, properties, required, additionalProperties, x-secret,
 * x-path. Сверх него — расширения ядра, которых схема плагина не знает: x-ref, x-when, x-when-set,
 * x-example, x-one-or-list, x-name, x-variants с x-discriminator, x-unsupported, x-platform, x-absent,
 * x-plugin. Все расширения — с префиксом x-, и читатель, не знающий их, видит обычную схему.
 *
 * Дерево строится в памяти (struct jn), потому что то же дерево печатается и JSON, и таблицей для
 * человека. Нехватка памяти копится флагом (g_oom) и проверяется один раз в конце: все помощники
 * принимают NULL и ничего с ним не делают. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spec.h"
#include "v2keys.h"
#include "v2.h"
#include "ynode.h"
#include "kind.h"
#include "plugin.h"
#include "module.h"
#include "platform.h"
#include "err.h"

/* Строка JSON с кавычками: собственная, чтобы схема не тянула lib/jsonw.c в каждый стенд, что
 * компонует модель (кавычка, обратная косая и управляющие байты — экранами, остальное как есть). */
static void j_quote(FILE *f, const char *s) {
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        if (*p == '"' || *p == '\\') fprintf(f, "\\%c", *p);
        else if (*p == '\n') fputs("\\n", f);
        else if (*p == '\t') fputs("\\t", f);
        else if (*p < 0x20) fprintf(f, "\\u%04x", *p);
        else fputc(*p, f);
    }
    fputc('"', f);
}

/* ---- дерево ------------------------------------------------------------------------------ */

enum jt { J_OBJ, J_ARR, J_STR, J_RAW };

struct jn {
    enum jt t;
    char *key;                  /* имя у члена объекта */
    char *s;                    /* J_STR: строка; J_RAW: литерал JSON как есть */
    struct jn **c;
    size_t n, cap;
};

static int g_oom;

static struct jn *jnew(enum jt t) {
    struct jn *j = calloc(1, sizeof(*j));
    if (!j) { g_oom = 1; return NULL; }
    j->t = t;
    return j;
}

static struct jn *jobj(void) { return jnew(J_OBJ); }
static struct jn *jarr(void) { return jnew(J_ARR); }

static struct jn *jstr(const char *s) {
    struct jn *j = jnew(J_STR);
    if (!j) return NULL;
    j->s = strdup(s ? s : "");
    if (!j->s) { g_oom = 1; free(j); return NULL; }
    return j;
}

static struct jn *jraw(const char *s) {
    struct jn *j = jnew(J_RAW);
    if (!j) return NULL;
    j->s = strdup(s);
    if (!j->s) { g_oom = 1; free(j); return NULL; }
    return j;
}

static void jfree(struct jn *j) {
    if (!j) return;
    for (size_t i = 0; i < j->n; i++) jfree(j->c[i]);
    free(j->c);
    free(j->key);
    free(j->s);
    free(j);
}

static void jpush(struct jn *p, struct jn *v) {
    if (!p || !v) { jfree(v); return; }
    if (p->n == p->cap) {
        size_t nc = p->cap ? p->cap * 2 : 4;
        struct jn **nn = realloc(p->c, nc * sizeof(*nn));
        if (!nn) { g_oom = 1; jfree(v); return; }
        p->c = nn;
        p->cap = nc;
    }
    p->c[p->n++] = v;
}

/* Член объекта; одноимённый член заменяется (схема вида плагина не должна дублировать ключ). */
static void jset(struct jn *o, const char *key, struct jn *v) {
    if (!o || !v) { jfree(v); return; }
    for (size_t i = 0; i < o->n; i++)
        if (!strcmp(o->c[i]->key, key)) {
            char *k = o->c[i]->key;
            o->c[i]->key = NULL;
            jfree(o->c[i]);
            v->key = k;
            o->c[i] = v;
            return;
        }
    free(v->key);
    v->key = strdup(key);
    if (!v->key) { g_oom = 1; jfree(v); return; }
    jpush(o, v);
}

/* Вынуть член объекта по имени (владение переходит вызывающему). */
static struct jn *jtake(struct jn *o, const char *key) {
    for (size_t i = 0; o && i < o->n; i++)
        if (!strcmp(o->c[i]->key, key)) {
            struct jn *v = o->c[i];
            memmove(o->c + i, o->c + i + 1, (o->n - i - 1) * sizeof(*o->c));
            o->n--;
            return v;
        }
    return NULL;
}

/* Член key — на место idx (описание сразу после типа читается лучше, чем в хвосте узла). */
static void jplace(struct jn *o, const char *key, size_t idx) {
    struct jn *v = jtake(o, key);
    if (!v) return;
    if (idx > o->n) idx = o->n;
    if (o->n == o->cap) {
        struct jn **nn = realloc(o->c, (o->cap ? o->cap * 2 : 4) * sizeof(*nn));
        if (!nn) { g_oom = 1; o->c[o->n++] = v; return; }
        o->c = nn;
        o->cap = o->cap ? o->cap * 2 : 4;
    }
    memmove(o->c + idx + 1, o->c + idx, (o->n - idx) * sizeof(*o->c));
    o->c[idx] = v;
    o->n++;
}

static struct jn *jget(const struct jn *o, const char *key) {
    for (size_t i = 0; o && i < o->n; i++)
        if (o->c[i]->key && !strcmp(o->c[i]->key, key)) return o->c[i];
    return NULL;
}

static void jset_str(struct jn *o, const char *key, const char *s) { jset(o, key, jstr(s)); }
static void jset_raw(struct jn *o, const char *key, const char *s) { jset(o, key, jraw(s)); }
static void jset_int(struct jn *o, const char *key, long v) {
    char b[32];
    snprintf(b, sizeof(b), "%ld", v);
    jset_raw(o, key, b);
}
static void jset_true(struct jn *o, const char *key) { jset_raw(o, key, "true"); }
static void jpush_str(struct jn *a, const char *s) { jpush(a, jstr(s)); }

/* Значения через «|» — в массив: числа числами, true и false логическими, прочее строками. */
static struct jn *jlist(const char *vals, int as_num) {
    struct jn *a = jarr();
    for (const char *p = vals; p && *p; ) {
        const char *e = strchr(p, '|');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        char tok[96];
        snprintf(tok, sizeof(tok), "%.*s", (int)l, p);
        if (as_num || !strcmp(tok, "true") || !strcmp(tok, "false")) jpush(a, jraw(tok));
        else jpush(a, jstr(tok));
        if (!e) break;
        p = e + 1;
    }
    return a;
}

/* ---- ключ таблицы -> узел схемы -------------------------------------------------------------- */

static void put_ref(struct jn *n, const struct v2key *k) {
    if (!k->ref) return;
    struct jn *r = jobj();
    jset_str(r, "section", k->ref);
    if (k->also) jset(r, "also", jlist(k->also, 0));
    jset(n, "x-ref", r);
}

static void put_when(struct jn *n, const char *when) {
    if (!when) return;
    /* «ключ=знач|знач»: условие на соседний ключ той же записи. */
    const char *eq = strchr(when, '=');
    if (!eq) return;
    char key[64];
    snprintf(key, sizeof(key), "%.*s", (int)(eq - when), when);
    struct jn *w = jobj();
    jset(w, key, jlist(eq + 1, 0));
    jset(n, "x-when", w);
}

/* x-needs: {"значение": ["сосед", …]} — при этом значении ключа без соседей разбор отказывает. */
static void put_needs(struct jn *n, const char *needs) {
    const char *colon = needs ? strchr(needs, ':') : NULL;
    if (!colon) return;
    char val[64];
    snprintf(val, sizeof(val), "%.*s", (int)(colon - needs), needs);
    struct jn *o = jobj();
    jset(o, val, jlist(colon + 1, 0));
    jset(n, "x-needs", o);
    /* jlist делит по «|», соседи в таблице — через «,»: переведём. */
    struct jn *l = jget(o, val);
    if (l && l->n == 1 && strchr(l->c[0]->s, ',')) {
        char *src = strdup(l->c[0]->s), *sp = NULL, *tok;
        struct jn *a = jarr();
        for (tok = strtok_r(src, ",", &sp); tok; tok = strtok_r(NULL, ",", &sp)) jpush_str(a, tok);
        free(src);
        jset(o, val, a);
    }
}

static void put_path(struct jn *n, const struct v2key *k) {
    if (k->flags & VF_PATH) jset_str(n, "x-path", "etc");
}

static const char *const NOT_YET = "ещё не поддерживается в этой версии ядра steer";

static struct jn *scope_node(enum v2_scope sc, int *emitted_required);
static struct jn *dns_entity_node(void);

/* Значения enum ключа с поправкой на платформу (zapret — не на телефоне). */
static struct jn *key_enum(const struct v2key *k, int as_num) {
    if (!k->en) return NULL;
    if (!strcmp(k->key, "on_fail") && !plat()->zapret) {
        char buf[64] = "";
        for (const char *p = k->en; *p; ) {
            const char *e = strchr(p, '|');
            size_t l = e ? (size_t)(e - p) : strlen(p);
            if (!(l == 6 && !strncmp(p, "zapret", 6)))
                snprintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "%s%.*s", buf[0] ? "|" : "", (int)l, p);
            if (!e) break;
            p = e + 1;
        }
        return jlist(buf, as_num);
    }
    return jlist(k->en, as_num);
}

/* Общие слова записи: описание, умолчание, пример, условия и пометки платформы. */
static void put_common(struct jn *n, const struct v2key *k) {
    if (k->hint) { jset_str(n, "description", k->hint); jplace(n, "description", 1); }
    if (k->def) jset_raw(n, "default", k->def);
    if (k->flags & VF_SECRET) jset_true(n, "x-secret");
    put_when(n, k->when);
    put_needs(n, k->needs);
    if (k->ex) jset_raw(n, "x-example", k->ex);
    if (k->flags & VF_NOT_YET) jset_str(n, "x-unsupported", NOT_YET);
    if (k->flags & VF_PHONE) jset_str(n, "x-platform", "phone");
}

static struct jn *key_node(const struct v2key *k) {
    struct jn *n = jobj();
    switch (k->type) {
    case VT_STR:
        jset_str(n, "type", "string");
        if (k->en) jset(n, "enum", key_enum(k, 0));
        if (k->pat) jset_str(n, "pattern", k->pat);
        put_path(n, k);
        put_ref(n, k);
        break;
    case VT_INT:
        jset_str(n, "type", "integer");
        if (k->en) jset(n, "enum", key_enum(k, 1));
        if (k->range) { jset_int(n, "minimum", k->lo); jset_int(n, "maximum", k->hi); }
        break;
    case VT_BOOL:
        jset_str(n, "type", "boolean");
        break;
    case VT_STRS: {
        jset_str(n, "type", "array");
        struct jn *it = jobj();
        if (k->flags & VF_ITEM_NUM) {
            struct jn *t = jarr();
            jpush_str(t, "integer");
            jpush_str(t, "string");
            jset(it, "type", t);
        } else jset_str(it, "type", "string");
        if (k->en) jset(it, "enum", key_enum(k, 0));
        if (k->pat) jset_str(it, "pattern", k->pat);
        put_path(it, k);
        put_ref(it, k);
        jset(n, "items", it);
        if (k->min_items) jset_int(n, "minItems", k->min_items);
        if (k->max_items) jset_int(n, "maxItems", k->max_items);
        jset_true(n, "x-one-or-list");
        break;
    }
    case VT_INTS: {
        jset_str(n, "type", "array");
        struct jn *it = jobj();
        jset_str(it, "type", "integer");
        if (k->range) { jset_int(it, "minimum", k->lo); jset_int(it, "maximum", k->hi); }
        jset(n, "items", it);
        if (k->min_items) jset_int(n, "minItems", k->min_items);
        if (k->max_items) jset_int(n, "maxItems", k->max_items);
        jset_true(n, "x-one-or-list");
        break;
    }
    case VT_OBJ: {
        struct jn *o = scope_node(k->sub, NULL);
        jfree(n);
        n = o;
        break;
    }
    case VT_MAP: {
        jset_str(n, "type", "object");
        struct jn *ent = k->sub == V2S_DNS_UP ? dns_entity_node() : scope_node(k->sub, NULL);
        if (ent && !jget(ent, "description")) jset_str(ent, "description", k->hint);
        jset(n, "additionalProperties", ent);
        struct jn *nm = jobj();
        jset_str(nm, "pattern", "^[A-Za-z0-9_.-]+$");
        jset_int(nm, "maxLength", 31);
        if (k->reserved) jset(nm, "reserved", jlist(k->reserved, 0));
        jset(n, "x-name", nm);
        break;
    }
    case VT_SEQ: {
        jset_str(n, "type", "array");
        jset(n, "items", scope_node(k->sub, NULL));
        break;
    }
    case VT_STR_OBJ: {
        struct jn *t = jarr();
        jpush_str(t, "string");
        jpush_str(t, "object");
        jset(n, "type", t);
        put_ref(n, k);
        /* Запись правила — те же варианты, что у dns.upstreams. */
        struct jn *ent = dns_entity_node();
        jset(n, "x-variants", jtake(ent, "x-variants"));
        jset(n, "x-discriminator", jtake(ent, "x-discriminator"));
        jfree(ent);
        break;
    }
    }
    put_common(n, k);
    return n;
}

/* Запись раздела sc: объект со всеми ключами таблицы (кроме внутренних). */
static struct jn *scope_node(enum v2_scope sc, int *emitted_required) {
    (void)emitted_required;
    size_t cnt;
    const struct v2key *t = v2keys_all(&cnt);
    struct jn *o = jobj(), *props = jobj(), *req = jarr();
    jset_str(o, "type", "object");
    for (size_t i = 0; i < cnt; i++) {
        if (t[i].scope != sc || (t[i].flags & VF_INTERNAL)) continue;
        jset(props, t[i].key, key_node(&t[i]));
        if (t[i].flags & VF_REQUIRED) jpush_str(req, t[i].key);
    }
    jset(o, "properties", props);
    /* Записи, где обязательного ключа нет, а годная запись без источника пуста (клиент, список,
     * сервер DNS): пример — минимальная годная запись. */
    static const struct { enum v2_scope sc; const char *ex; } ENT[] = {
        { V2S_CLIENT, "{\"addr\": [\"192.168.1.50\"]}" },
        { V2S_LIST, "{\"domains_file\": [\"lists/work.dom\"]}" },
        { V2S_DNS_UP, "{\"url\": \"tls://dns.example\", \"ips\": [\"1.1.1.1\"]}" },
    };
    for (size_t i = 0; i < sizeof(ENT) / sizeof(ENT[0]); i++)
        if (ENT[i].sc == sc) jset_raw(o, "x-example", ENT[i].ex);
    if (req && req->n) jset(o, "required", req);
    else jfree(req);
    jset_raw(o, "additionalProperties", "false");
    return o;
}

/* dns.upstreams.<имя> и dns правила: либо сервер (url), либо группа серверов (servers). */
static struct jn *dns_entity_node(void) {
    struct jn *o = jobj(), *vars = jobj(), *d = jobj();
    jset_str(o, "type", "object");
    struct jn *srv = scope_node(V2S_DNS_UP, NULL), *grp = scope_node(V2S_DNS_GRP, NULL);
    jset_str(srv, "description", "Сервер DNS.");
    jset_str(grp, "description", "Группа серверов DNS: по очереди или все сразу.");
    jset(vars, "server", srv);
    jset(vars, "group", grp);
    jset(o, "x-variants", vars);
    jset_str(d, "has", "servers");
    jset_str(d, "yes", "group");
    jset_str(d, "no", "server");
    jset(o, "x-discriminator", d);
    return o;
}

/* ---- выходы: варианты по виду -------------------------------------------------------------- */

static const struct { const char *name, *hint; } KIND_HINT[] = {
    { "direct", "Не маршрутизировать: трафик идёт обычным путём." },
    { "block", "Блок: трафик правила не пропускается." },
    { "interface", "Устройство системы: WireGuard, PPPoE и другие." },
    { "awg", "AmneziaWG: устройство заводит ядро." },
    { "tgws", "Мост Telegram." },
    { "group", "Группа выходов: выбор члена по порядку, задержке, вручную или балансом." },
};

static const char *kind_hint(const char *variant) {
    for (size_t i = 0; i < sizeof(KIND_HINT) / sizeof(KIND_HINT[0]); i++)
        if (!strcmp(KIND_HINT[i].name, variant)) return KIND_HINT[i].hint;
    return NULL;
}

/* Видимый в спеке вид и протокол: «tunnel:vless» — это kind: tunnel, protocol: vless. */
static void spec_names(const char *kname, const char **kind, const char **proto) {
    if (!strncmp(kname, "tunnel:", 7)) { *kind = "tunnel"; *proto = kname + 7; }
    else { *kind = kname; *proto = NULL; }
}

/* Что вид проверяет сам (kinds/<вид>.c, kind_ops.parse и .check), а в таблицах ключей выразить нечем:
 * обязательный ключ и сужение значений. Сверяет стенд tests/specschemamatch.sh — разойдись запись с
 * видом, он скажет, какой ключ принят вопреки схеме или отвергнут вопреки ей. */
static const struct { const char *variant, *key, *en; int required; } KIND_RULE[] = {
    { "interface", "device", NULL, 1 },         /* kind interface needs a device */
    { "tgws", "on_fail", "drop", 0 },           /* у tgws on_fail только drop */
};

/* Пример записи вида: обязательные ключи с их примерами — годная запись, с которой начинает форма
 * «добавить выход» и стенд. */
static void jprint(FILE *f, const struct jn *j, int d);

static struct jn *entity_example(const struct jn *props, const struct jn *req) {
    char *buf = NULL;
    size_t bn = 0;
    FILE *m = open_memstream(&buf, &bn);
    if (!m) { g_oom = 1; return NULL; }
    fputc('{', m);
    int first = 1;
    for (size_t i = 0; req && i < req->n; i++) {
        const struct jn *p = jget(props, req->c[i]->s), *ex = p ? jget(p, "x-example") : NULL,
                        *cs = p ? jget(p, "const") : NULL;
        if (!cs && !ex) continue;
        fputs(first ? "" : ", ", m);
        first = 0;
        j_quote(m, req->c[i]->s);
        fputs(": ", m);
        if (cs) j_quote(m, cs->s);
        else jprint(m, ex, 0);
    }
    fputc('}', m);
    fclose(m);
    struct jn *r = jraw(buf);
    free(buf);
    return r;
}

/* Узел вида: общие ключи и ключи вида по свойствам kd. */
static struct jn *variant_node(const struct kind_ops *kd, int group, const char *kind, const char *proto) {
    size_t cnt;
    const struct v2key *t = v2keys_all(&cnt);
    struct jn *o = jobj(), *props = jobj(), *req = jarr();
    char variant[64];
    snprintf(variant, sizeof(variant), proto ? "tunnel:%s" : "%s", proto ? proto : kind);
    jset_str(o, "type", "object");
    const char *h = kind_hint(variant);
    if (h) jset_str(o, "description", h);
    struct jn *sp = jobj();
    jset_str(sp, "kind", kind);
    if (proto) jset_str(sp, "protocol", proto);
    jset(o, "x-spec", sp);
    for (size_t i = 0; i < cnt; i++) {
        const struct v2key *k = &t[i];
        if (k->scope != V2S_OUT || k->who == W_INTERNAL) continue;
        if (k->who == W_PROTOCOL) {
            if (!proto) continue;
        } else if (k->who != W_ALL && !v2key_applies(k, kd, group)) continue;
        if (!v2key_proto_ok(k, proto)) continue;
        struct jn *n = key_node(k);
        /* routed и nat — только виду с устройством без завершения TCP (тому же, у кого бывает prefix). */
        if (k->who == W_IPV6 && !v2key_applies(v2key_out_find("prefix", W_PREFIX), kd, group))
            jset(n, "enum", jlist("off", 0));
        for (size_t r = 0; r < sizeof(KIND_RULE) / sizeof(KIND_RULE[0]); r++)
            if (!strcmp(KIND_RULE[r].variant, variant) && !strcmp(KIND_RULE[r].key, k->key) && KIND_RULE[r].en)
                jset(n, "enum", jlist(KIND_RULE[r].en, 0));
        if (k->who == W_ALL) {
            jset_str(n, "const", kind);
            jset_str(n, "description", "Вид выхода.");
        } else if (k->who == W_PROTOCOL) {
            jset_str(n, "const", proto);
            jset_str(n, "description", "Протокол туннеля.");
        }
        /* interface носит подложку только с obfs: ключ имеет смысл, когда obfs записан. */
        if (k->who == W_OVER && !(kd->caps & KC_OVER)) {
            struct jn *a = jarr();
            jpush_str(a, "obfs");
            jset(n, "x-when-set", a);
        }
        jset(props, k->key, n);
        int need = (k->flags & VF_REQUIRED) != 0;
        for (size_t r = 0; r < sizeof(KIND_RULE) / sizeof(KIND_RULE[0]); r++)
            if (!strcmp(KIND_RULE[r].variant, variant) && !strcmp(KIND_RULE[r].key, k->key) && KIND_RULE[r].required)
                need = 1;
        if (need) jpush_str(req, k->key);
    }
    jset(o, "properties", props);
    jset(o, "x-example", entity_example(props, req));
    if (req && req->n) jset(o, "required", req);
    else jfree(req);
    jset_raw(o, "additionalProperties", "false");
    return o;
}

/* Скаляр схемы плагина по записи, как читает YAML 1.2. */
static struct jn *yn_scalar(const struct ynode *n) {
    int b;
    long l;
    char *end;
    if (n->style != YS_PLAIN) return jstr(n->str);
    if (ynode_is_null(n)) return jraw("null");
    if (ynode_bool(n, &b) == 0) return jraw(b ? "true" : "false");
    if (ynode_long(n, &l) == 0) return jraw(n->str);
    if (*n->str) {
        strtod(n->str, &end);
        if (!*end) return jraw(n->str);
    }
    return jstr(n->str);
}

/* Дерево схемы плагина — в узел, значения как есть. plugin — id для пометки x-plugin. */
static struct jn *yn_to_jn(const struct ynode *n) {
    if (n->kind == YN_SCALAR) return yn_scalar(n);
    if (n->kind == YN_SEQ) {
        struct jn *a = jarr();
        for (size_t i = 0; i < ynode_len(n); i++) jpush(a, yn_to_jn(ynode_at(n, i)));
        return a;
    }
    struct jn *o = jobj();
    for (size_t i = 0; i < ynode_len(n); i++) jset(o, ynode_key_at(n, i)->str, yn_to_jn(ynode_val_at(n, i)));
    return o;
}

/* Пример значения по узлу схемы плагина (x-example у него нет): умолчание, первое значение enum,
 * иначе по типу и границам. Литерал JSON; NULL — типа нет. */
static struct jn *guess_example(const struct ynode *p) {
    char b[256];
    const struct ynode *df = ynode_get(p, "default"), *en = ynode_get(p, "enum"), *ty = ynode_get(p, "type");
    if (df) return yn_to_jn(df);
    if (en && ynode_len(en)) return yn_to_jn(ynode_at(en, 0));
    const char *t = ty ? (ty->kind == YN_SCALAR ? ty->str : ynode_at(ty, 0)->str) : "string";
    if (!strcmp(t, "boolean")) return jraw("true");
    if (!strcmp(t, "integer") || !strcmp(t, "number")) {
        const struct ynode *mn = ynode_get(p, "minimum");
        return jraw(mn ? mn->str : "1");
    }
    if (!strcmp(t, "array")) {
        const struct ynode *it = ynode_get(p, "items");
        struct jn *a = jarr();
        if (it) jpush(a, guess_example(it));
        return a;
    }
    if (!strcmp(t, "object")) return jraw("{}");
    const struct ynode *ml = ynode_get(p, "minLength");
    long n = 2;
    if (ml) ynode_long(ml, &n);
    if (n < 2) n = 2;
    if (n > (long)sizeof(b) - 1) n = (long)sizeof(b) - 1;
    memset(b, 'x', (size_t)n);
    b[n] = '\0';
    return jstr(b);
}

/* Вид плагина: общие ключи по его свойствам, поверх них ключи из схемы манифеста. */
static struct jn *plugin_variant(const struct plugin_kind *pk) {
    const char *kind, *proto;
    spec_names(pk->name, &kind, &proto);
    struct jn *v = variant_node(&pk->ops, 0, kind, proto);
    struct jn *props = jget(v, "properties"), *req = jget(v, "required");
    /* Описание вида — из манифеста (kinds[].description, иначе описание плагина). */
    if (!jget(v, "description") && pk->desc) jset_str(v, "description", pk->desc);
    struct jn *pl = jobj();
    jset_str(pl, "id", pk->owner->id);
    jset_str(pl, "version", pk->owner->version ? pk->owner->version : "");
    jset(v, "x-plugin", pl);
    if (!req) { req = jarr(); jset(v, "required", req); req = jget(v, "required"); }
    const struct ynode *sch = pk->schema;
    const struct ynode *sp = sch ? ynode_get(sch, "properties") : NULL;
    for (size_t i = 0; sp && i < ynode_len(sp); i++) {
        const char *key = ynode_key_at(sp, i)->str;
        /* Общие ключи разбор читает раньше схемы плагина (v2.c): одноимённый ключ плагина не действует. */
        if (jget(props, key)) continue;
        struct jn *kn = yn_to_jn(ynode_val_at(sp, i));
        jset_str(kn, "x-plugin", pk->owner->id);
        if (!jget(kn, "x-example")) {
            struct jn *g = guess_example(ynode_val_at(sp, i));
            /* Пример — литерал JSON: строка печатается как есть. */
            jset(kn, "x-example", g);
        }
        jset(props, key, kn);
    }
    const struct ynode *rq = sch ? ynode_get(sch, "required") : NULL;
    for (size_t i = 0; rq && i < ynode_len(rq); i++) jpush_str(req, ynode_at(rq, i)->str);
    /* Пример записи — с обязательными ключами плагина тоже. */
    jset(v, "x-example", entity_example(props, req));
    if (req && !req->n) { /* пустой required не печатаем */
        for (size_t i = 0; i < v->n; i++) if (v->c[i] == req) { jfree(req); v->c[i] = v->c[--v->n]; break; }
    }
    return v;
}

static void variant_add(struct jn *vars, const char *name, struct jn *v) {
    jset(vars, name, v);
}

static struct jn *outputs_entity(void) {
    struct jn *ent = jobj(), *vars = jobj(), *kinds = jarr(), *protos = jarr();
    size_t reg = kind_count() - plugin_kinds_n();
    jset_str(ent, "type", "object");

    /* Виды ядра в порядке реестра, затем группа; виды протоколов — только у установленных плагинов. */
    for (size_t i = 0; i < reg; i++) {
        const struct kind_ops *kd = kind_at(i);
        if (!kd) continue;
        const char *kind, *proto;
        spec_names(kd->name, &kind, &proto);
        char vname[64];
        snprintf(vname, sizeof(vname), proto ? "tunnel:%s" : "%s", proto ? proto : kind);
        struct jn *v;
        if (kd->absent) {
            v = jobj();
            struct jn *sp = jobj(), *props = jobj();
            jset_str(v, "type", "object");
            jset_str(sp, "kind", kind);
            if (proto) jset_str(sp, "protocol", proto);
            jset(v, "x-spec", sp);
            jset(v, "properties", props);
            const char *h = kind_hint(vname);
            if (h) jset_str(v, "description", h);
            jset_str(v, "x-absent", kd->absent);
        } else v = variant_node(kd, 0, kind, proto);
        variant_add(vars, vname, v);
    }
    variant_add(vars, "group", variant_node(kind_by_name_v2("group"), 1, "group", NULL));
    /* Виды установленных плагинов: заменяют одноимённый вид ядра на его месте. */
    for (size_t pi = 0; pi < plugin_n(); pi++) {
        const struct plugin *pl = plugin_at(pi);
        if (!pl->enabled) continue;
        for (size_t ki = 0; ki < pl->kind_n; ki++) {
            const struct plugin_kind *pk = pl->kind[ki];
            variant_add(vars, pk->name, plugin_variant(pk));
        }
    }

    /* Перечни вида и протокола — по собранным вариантам, порядок тот же. */
    for (size_t i = 0; vars && i < vars->n; i++) {
        struct jn *sp = jget(vars->c[i], "x-spec");
        struct jn *k = jget(sp, "kind"), *p = jget(sp, "protocol");
        int seen = 0;
        for (size_t j = 0; k && j < kinds->n; j++) if (!strcmp(kinds->c[j]->s, k->s)) seen = 1;
        if (k && !seen) jpush_str(kinds, k->s);
        if (p) jpush_str(protos, p->s);
    }
    /* Свойства самой записи: вид (по нему выбирается вариант), остальное — у вариантов. */
    struct jn *props = jobj();
    const struct v2key *kk = v2key_out_find("kind", W_ALL);
    struct jn *kn = key_node(kk);
    jset(kn, "enum", kinds);
    jset(props, "kind", kn);
    jset(ent, "properties", props);
    struct jn *req = jarr();
    jpush_str(req, "kind");
    jset(ent, "required", req);
    jset(ent, "x-protocols", protos);
    struct jn *d = jobj(), *then = jobj();
    jset_str(d, "key", "kind");
    jset_str(then, "tunnel", "protocol");
    jset(d, "then", then);
    jset(ent, "x-discriminator", d);
    jset(ent, "x-variants", vars);
    return ent;
}

/* ---- корень -------------------------------------------------------------------------------- */

static struct jn *build_root(void) {
    struct jn *r = jobj();
    jset_str(r, "$schema", "https://json-schema.org/draft/2020-12/schema");
    jset_str(r, "title", "Спека steer v2");
    jset_str(r, "description", "Схема спеки v2: разделы, ключи, виды выходов и виды установленных плагинов.");
    jset_int(r, "x-schema-version", 1);
    jset_str(r, "x-steer-version", steer_engine_version());
    jset_str(r, "x-platform", plat()->local_channels ? "phone" : "router");
    /* Плагины реестра: и выключенные — с причиной, чтобы каркас мог про них сказать. */
    struct jn *pls = jarr();
    for (size_t pi = 0; pi < plugin_n(); pi++) {
        const struct plugin *pl = plugin_at(pi);
        struct jn *p = jobj(), *ks = jarr();
        jset_str(p, "id", pl->id);
        jset_str(p, "version", pl->version ? pl->version : "");
        jset_raw(p, "enabled", pl->enabled ? "true" : "false");
        if (pl->why) jset_str(p, "why", pl->why);
        for (size_t ki = 0; ki < pl->kind_names_n; ki++) jpush_str(ks, pl->kind_names[ki]);
        jset(p, "kinds", ks);
        jpush(pls, p);
    }
    jset(r, "x-plugins", pls);
    /* Корень: свойства из таблицы, а записи выходов — с вариантами по виду. */
    struct jn *root = scope_node(V2S_TOP, NULL);
    struct jn *outs = jget(jget(root, "properties"), "outputs");
    if (outs) jset(outs, "additionalProperties", outputs_entity());
    while (root && root->n) {
        struct jn *c = root->c[0];
        char *k = c->key;
        memmove(root->c, root->c + 1, (root->n - 1) * sizeof(*root->c));
        root->n--;
        c->key = NULL;
        jset(r, k, c);
        free(k);
    }
    jfree(root);
    return r;
}

/* ---- печать -------------------------------------------------------------------------------- */

static void indent(FILE *f, int d) { for (int i = 0; i < d; i++) fputs("  ", f); }

static void jprint(FILE *f, const struct jn *j, int d) {
    switch (j->t) {
    case J_STR: j_quote(f, j->s); return;
    case J_RAW: fputs(j->s, f); return;
    case J_ARR: {
        int flat = 1;
        for (size_t i = 0; i < j->n; i++) if (j->c[i]->t == J_OBJ || j->c[i]->t == J_ARR) flat = 0;
        if (!j->n) { fputs("[]", f); return; }
        fputc('[', f);
        for (size_t i = 0; i < j->n; i++) {
            if (flat) fputs(i ? ", " : "", f);
            else { fputs(i ? ",\n" : "\n", f); indent(f, d + 1); }
            jprint(f, j->c[i], d + 1);
        }
        if (!flat) { fputc('\n', f); indent(f, d); }
        fputc(']', f);
        return;
    }
    case J_OBJ:
        if (!j->n) { fputs("{}", f); return; }
        fputc('{', f);
        for (size_t i = 0; i < j->n; i++) {
            fputs(i ? ",\n" : "\n", f);
            indent(f, d + 1);
            j_quote(f, j->c[i]->key);
            fputs(": ", f);
            jprint(f, j->c[i], d + 1);
        }
        fputc('\n', f);
        indent(f, d);
        fputc('}', f);
        return;
    }
}

/* Тип узла одной строкой: string, integer, array of string, object… */
static void type_text(const struct jn *n, char *buf, size_t bn) {
    const struct jn *t = jget(n, "type");
    buf[0] = '\0';
    if (!t) return;
    if (t->t == J_STR) snprintf(buf, bn, "%s", t->s);
    else for (size_t i = 0; i < t->n; i++)
        snprintf(buf + strlen(buf), bn - strlen(buf), "%s%s", i ? "|" : "", t->c[i]->s);
    const struct jn *it = jget(n, "items");
    const struct jn *itt = it ? jget(it, "type") : NULL;
    if (itt && itt->t == J_STR && !strcmp(buf, "array"))
        snprintf(buf + strlen(buf), bn - strlen(buf), " of %s", itt->s);
}

static void raw_text(const struct jn *v, char *buf, size_t bn) {
    buf[0] = '\0';
    if (!v) return;
    if (v->t == J_STR || v->t == J_RAW) { snprintf(buf, bn, "%s", v->s); return; }
    for (size_t i = 0; i < v->n; i++) {
        char one[96];
        raw_text(v->c[i], one, sizeof(one));
        snprintf(buf + strlen(buf), bn - strlen(buf), "%s%s", i ? "|" : "", one);
    }
}

/* Таблица для человека: путь, тип, умолчание, подсказка; у видов — их ключи отдельным блоком. */
static void text_node(FILE *f, const struct jn *n, const char *path, int d);

static void text_props(FILE *f, const struct jn *props, const struct jn *req, const char *path, int d,
                       int in_variant) {
    for (size_t i = 0; props && i < props->n; i++) {
        const struct jn *p = props->c[i];
        /* Вид и протокол названы в заголовке варианта. */
        if (in_variant && (!strcmp(p->key, "kind") || !strcmp(p->key, "protocol"))) continue;
        char type[96], def[96], en[160], where[256];
        type_text(p, type, sizeof(type));
        raw_text(jget(p, "default"), def, sizeof(def));
        raw_text(jget(p, "enum"), en, sizeof(en));
        int required = 0;
        for (size_t r = 0; req && r < req->n; r++) if (!strcmp(req->c[r]->s, p->key)) required = 1;
        snprintf(where, sizeof(where), "%s%s%s", path, *path ? "." : "", p->key);
        indent(f, d);
        fprintf(f, "%s  %s%s", where, type, required ? "  обязателен" : "");
        if (en[0]) fprintf(f, "  [%s]", en);
        if (def[0]) fprintf(f, "  умолчание %s", def);
        const struct jn *w = jget(p, "x-when");
        if (w && w->n) {
            char wt[96];
            raw_text(w->c[0], wt, sizeof(wt));
            fprintf(f, "  при %s=%s", w->c[0]->key, wt);
        }
        if (jget(p, "x-unsupported")) fputs("  (ещё не поддерживается)", f);
        if (jget(p, "x-platform")) fputs("  (только на телефоне)", f);
        fputc('\n', f);
        const struct jn *desc = jget(p, "description");
        if (desc) { indent(f, d + 1); fprintf(f, "%s\n", desc->s); }
        text_node(f, p, where, d);
    }
}

static void text_node(FILE *f, const struct jn *n, const char *path, int d) {
    const struct jn *props = jget(n, "properties");
    /* Внутри отображения-«имя → запись» путь называет запись: <имя>. */
    const struct jn *ap = jget(n, "additionalProperties");
    char sub[256];
    if (props) text_props(f, props, jget(n, "required"), path, d, 0);
    const struct jn *items = jget(n, "items");
    if (items && jget(items, "properties")) {
        snprintf(sub, sizeof(sub), "%s[]", path);
        text_node(f, items, sub, d);
    }
    if (ap && ap->t == J_OBJ) {
        snprintf(sub, sizeof(sub), "%s.<имя>", path);
        text_node(f, ap, sub, d);
    }
    const struct jn *vars = jget(n, "x-variants");
    for (size_t i = 0; vars && i < vars->n; i++) {
        const struct jn *v = vars->c[i];
        const struct jn *pl = jget(v, "x-plugin"), *ab = jget(v, "x-absent");
        indent(f, d);
        fprintf(f, "— %s%s%s", vars->c[i]->key, pl ? " (плагин " : "", pl ? jget(pl, "id")->s : "");
        if (pl) fputc(')', f);
        if (ab) fprintf(f, "  недоступен: %s", ab->s);
        fputc('\n', f);
        const struct jn *desc = jget(v, "description");
        if (desc) { indent(f, d + 1); fprintf(f, "%s\n", desc->s); }
        text_props(f, jget(v, "properties"), jget(v, "required"), path, d + 1, 1);
    }
}

int v2_schema_print(FILE *f, int json, struct err *e) {
    g_oom = 0;
    struct jn *r = build_root();
    if (g_oom || !r) {
        jfree(r);
        return err_set(e, "%s", "недостаточно памяти для схемы спеки");
    }
    if (json) {
        jprint(f, r, 0);
        fputc('\n', f);
    } else {
        fprintf(f, "Схема спеки v2 (steer %s, платформа %s). Ключи — путь внутри спеки; JSON — `steer spec-schema --json`.\n\n",
                steer_engine_version(), plat()->local_channels ? "телефон" : "роутер");
        const struct jn *props = jget(r, "properties");
        text_props(f, props, jget(r, "required"), "", 0, 0);
        const struct jn *pls = jget(r, "x-plugins");
        if (pls && pls->n) {
            fputs("\nПлагины:\n", f);
            for (size_t i = 0; i < pls->n; i++) {
                const struct jn *p = pls->c[i];
                fprintf(f, "  %s %s%s\n", jget(p, "id")->s, jget(p, "version")->s,
                        !strcmp(jget(p, "enabled")->s, "true") ? "" : "  (выключен)");
            }
        }
    }
    jfree(r);
    return ferror(f) ? err_set(e, "%s", "не удалось записать схему") : 0;
}
