#!/usr/bin/env python3
"""Покрытие схемы спеки v2 (src/model/v2keys.c, v2schema.c; docs/spec-schema.md).

Схему отдаёт `steerd spec-schema --json`; стенд проверяет её против настоящего разбора спеки
(`steerd spec convert`), без своего списка ключей:

  1. СХЕМА ЧИСТАЯ: только слова подмножества и расширения ядра (docs/spec-schema.md).
  2. КАЖДЫЙ КЛЮЧ СХЕМЫ РАЗБОР ПРИНИМАЕТ: на каждый ключ каждой записи (разделы, виды выходов,
     варианты dns) строится спека с примером значения (x-example), условием применимости (x-when)
     и пробуется разбором. Ключи «ещё не поддерживается» принимаются по этому отказу, ключи телефона
     на роутере — отказываются «только на телефоне».
  3. ЗНАЧЕНИЯ: каждое значение enum принято, чужое — нет; границы чисел (minimum, maximum) приняты,
     за ними — отказ; один скаляр вместо списка принят; ссылка на несуществующее имя — отказ; слова
     x-ref.also приняты; пустой список при minItems — отказ; maxItems принят и превышен.
  4. НЕОБЯЗАТЕЛЬНОСТЬ: без обязательного ключа (required) разбор отказывает.
  5. НЕИЗВЕСТНЫЙ КЛЮЧ: в каждой записи разбор отказывает «неизвестный ключ»; ключ чужого вида
     (из объединения ключей всех видов, но не из этого) — тоже.
  6. ОБРАТНОЕ: слова из справочника docs/spec-v2.md и все ключи схемы пробуются в каждой записи, и
     всё, что разбор НЕ назвал «неизвестным ключом», обязано быть в схеме этой записи (кроме owner:
     его пишет только плагин). Перечень разбора «(есть: …)» совпадает со схемой записи.

Запуск: specschemamatch.py <steerd> <платформа router|android> [документ spec-v2.md]
"""
import copy
import json
import os
import re
import subprocess
import sys
import tempfile

BIN, PLAT = sys.argv[1], sys.argv[2]
DOC = sys.argv[3] if len(sys.argv) > 3 else None
LABEL = os.environ.get("SPECSCHEMA_LABEL", PLAT)

STD_WORDS = {
    "$schema", "$id", "title", "description", "type", "enum", "const", "default", "pattern", "minLength",
    "maxLength", "minimum", "maximum", "minItems", "maxItems", "uniqueItems", "items", "properties",
    "required", "additionalProperties",
}
EXT_WORDS = {
    "x-secret", "x-path", "x-ref", "x-when", "x-when-set", "x-example", "x-one-or-list", "x-name",
    "x-variants", "x-discriminator", "x-needs", "x-unsupported", "x-platform", "x-absent", "x-plugin", "x-spec",
    "x-protocols", "x-schema-version", "x-steer-version", "x-plugins",
}
# Ключи, которые разбор принимает, а схема не показывает: их пишет только плагин (подготовленная спека).
INTERNAL = {"owner"}

passes = 0
fails = []
notes = []
tmp = tempfile.mkdtemp(prefix="specschema.")


def ok():
    global passes
    passes += 1


def bad(msg, detail=""):
    fails.append(msg + (("\n    " + detail) if detail else ""))


env = dict(os.environ)
if PLAT == "android":
    env["STEER_PLATFORM"] = "android"
else:
    env.pop("STEER_PLATFORM", None)
SPEC = os.path.join(tmp, "case.json")


def run_spec(spec):
    with open(SPEC, "w") as f:
        json.dump(spec, f, ensure_ascii=False)
    p = subprocess.run([BIN, "spec", "convert", "--spec", SPEC], capture_output=True, text=True, env=env)
    return p.returncode == 0, p.stderr.strip()


NOT_YET = "ещё не поддерживается"

# Граница числа законна, но на ней срабатывает ДРУГАЯ проверка разбора — стенд называет её явно.
#   min кэша DNS не больше max (и наоборот): границы одного ключа берутся вместе с подходящим соседом;
#   count у warp до 255 по таблице, а выходов с меткой всего 211 (поле метки, check_slots) — граница
#   проходит проверку ключа и спотыкается о размер поля метки.
COMPANION = {
    (("dns.cache_ttl.min"), "maximum"): [{"max": 604800}],
    (("dns.cache_ttl.max"), "minimum"): [{"min": 0}],
}
RANGE_OK_IF = {
    ("outputs.<имя>[warp].count", "maximum"): "поле метки даёт мест",
}

# ---- схема ----------------------------------------------------------------------------------


def schema_of(binary=BIN):
    p = subprocess.run([binary, "spec-schema", "--json"], capture_output=True, text=True, env=env)
    if p.returncode != 0:
        print("specschemamatch: spec-schema не отработал:", p.stderr)
        sys.exit(1)
    return json.loads(p.stdout)


S = schema_of()

# Основа: записи, на которые ссылаются примеры (выходы wg0 и wg1, список work, клиент kids, апстрим dns1).
FIX = {
    "version": 2,
    "clients": {"kids": {"addr": ["192.168.1.50"]}},
    "lists": {"work": {"domains_file": ["lists/work.dom"]}},
    "outputs": {"wg0": {"kind": "interface", "device": "fx0"}, "wg1": {"kind": "interface", "device": "fx1"}},
    "dns": {"upstreams": {"dns1": {"url": "tls://dns.example", "ips": ["1.1.1.1"]}}},
}


def check_words(node, path):
    if isinstance(node, list):
        for i, n in enumerate(node):
            check_words(n, f"{path}[{i}]")
        return
    if not isinstance(node, dict):
        return
    for k, v in node.items():
        if path.endswith(".properties") or path.endswith(".x-variants"):
            check_words(v, f"{path}.{k}")
            continue
        if k not in STD_WORDS and k not in EXT_WORDS:
            bad(f"схема: слово «{k}» вне списка ({path})")
            continue
        if k in ("properties", "x-variants"):
            check_words(v, f"{path}.{k}")
        elif k in ("items", "additionalProperties") and isinstance(v, dict):
            check_words(v, f"{path}.{k}")
        elif k == "x-plugins":
            pass


def place(path, obj):
    """Основа со вставленной записью obj по пути path (список ключей; число — номер в списке)."""
    spec = copy.deepcopy(FIX)
    if path == ["rules"]:
        spec["rules"] = [obj]
        return spec
    cur = spec
    for k in path[:-1]:
        if k == 0:
            cur = cur[0]
        else:
            cur = cur.setdefault(k, {})
    cur[path[-1]] = obj
    return spec


def guess(p):
    """Пример по схеме плагина (у ключей плагина x-example нет): умолчание, enum, иначе по типу и границам."""
    if "default" in p:
        return p["default"]
    if "enum" in p:
        return p["enum"][0]
    t = scalars(p)[0]
    if t == "string":
        return "x" * max(2, p.get("minLength", 0))
    if t == "integer":
        return p.get("minimum", 1)
    if t == "number":
        return p.get("minimum", 1)
    if t == "boolean":
        return True
    if t == "array":
        return [guess(p["items"])] if p.get("minItems", 0) or p.get("items") else []
    return {}


def ex_of(p):
    if "const" in p:
        return p["const"]
    if "x-example" in p:
        return p["x-example"]
    return guess(p) if "x-plugin" in p else None


def ex_has(p):
    return "const" in p or "x-example" in p or "x-plugin" in p


ok_, why_ = run_spec(FIX)
if not ok_:
    print("specschemamatch: основа не разбирается:", why_)
    sys.exit(1)

check_words(S, "$")
if not [f for f in fails if f.startswith("схема:")]:
    ok()


# ---- проверки ключей записи -----------------------------------------------------------------

class Ctx:
    """Где стоит проверяемая запись: функция вставки и подпись."""

    def __init__(self, mk, label):
        self.mk = mk
        self.label = label


def try_obj(ctx, obj):
    return run_spec(ctx.mk(obj))


def unknown(why):
    """Разбор не принял САМ КЛЮЧ: неизвестный или чужого вида (а не значение у известного)."""
    return "неизвестный ключ" in why or "есть только у kind" in why or "url и servers вместе" in why


def accept(ctx, obj, what):
    a, why = try_obj(ctx, obj)
    if a:
        ok()
    else:
        bad(f"{ctx.label}: {what} — отказ разбора", why)
    return a


def reject(ctx, obj, what, needle=None):
    a, why = try_obj(ctx, obj)
    if a:
        bad(f"{ctx.label}: {what} — разбор принял, а должен отказать")
    elif needle and needle not in why:
        bad(f"{ctx.label}: {what} — отказ не тот (ждали «{needle}»)", why)
    else:
        ok()


def base_of(node):
    if "x-example" in node and isinstance(node["x-example"], dict):
        return copy.deepcopy(node["x-example"])
    props = node.get("properties", {})
    return {r: copy.deepcopy(ex_of(props[r])) for r in node.get("required", []) if r in props and ex_has(props[r])}


def when_fix(obj, p, props, key=None):
    """Условия применимости ключа: соседние ключи (x-when) и ключи, при которых он имеет смысл (x-when-set)."""
    for k, vals in p.get("x-when", {}).items():
        obj[k] = vals[0]
    needs = p.get("x-needs", {})
    need = (needs.get(str(obj.get(key))) or needs.get("*")) if key else None
    for k in p.get("x-when-set", []) + (need or []):
        if k in props and ex_has(props[k]):
            obj[k] = copy.deepcopy(ex_of(props[k]))


def attempt(ctx, node, base, key, value):
    """Годная запись с key=value: сначала на основе, потом на одних обязательных ключах."""
    props = node.get("properties", {})
    p = props[key]
    c1 = copy.deepcopy(base)
    c1[key] = value
    when_fix(c1, p, props, key)
    c2 = {r: copy.deepcopy(ex_of(props[r])) for r in node.get("required", []) if r in props and ex_has(props[r])}
    c2[key] = value
    when_fix(c2, p, props, key)
    last = ""
    for c in (c1, c2):
        a, why = try_obj(ctx, c)
        if a:
            return c, ""
        last = why
        if NOT_YET in why:
            return c, why
    return None, last


def scalars(p):
    """Тип узла как список имён."""
    t = p.get("type")
    return t if isinstance(t, list) else [t]


def walk_object(ctx, node, label_prefix=""):
    props = node.get("properties", {})
    req = node.get("required", [])
    base = base_of(node)
    accept(ctx, base, "основа записи")
    reject(ctx, {**base, "zz_unknown": 1}, "неизвестный ключ", "неизвестный ключ")
    for r in req:
        if r in base:
            nb = {k: v for k, v in base.items() if k != r}
            a, _ = try_obj(ctx, nb)
            if a:
                bad(f"{ctx.label}: без обязательного {r} разбор принял")
            else:
                ok()
    for key, p in props.items():
        walk_key(ctx, node, base, key, p)


def walk_key(ctx, node, base, key, p):
    props = node.get("properties", {})
    label = f"{ctx.label}.{key}"
    kctx = Ctx(ctx.mk, label)
    if "const" in p:
        return                      # kind и protocol вида — проверены самим вариантом
    if not ex_has(p) and "properties" not in p:
        bad(f"{label}: у ключа нет x-example")
        return
    types = scalars(p)
    # Вложенная запись: свои ключи, основа родителя.
    if types == ["object"] and "properties" in p:
        sub = Ctx(lambda o, mk=ctx.mk, b=base, k=key: mk({**b, k: o}), label)
        walk_object(sub, p)
        return
    if types == ["object"] and isinstance(p.get("additionalProperties"), dict):
        return                      # записи «имя → запись» обходят walk_top и walk_object_with_maps
    if types == ["array"] and isinstance(p.get("items"), dict) and "properties" in p["items"]:
        return                      # rules[] — обходит walk_rules
    ex = copy.deepcopy(ex_of(p))
    phone = p.get("x-platform") == "phone"
    c, why = attempt(kctx, node, base, key, ex)
    if phone and PLAT != "android":
        if c is None and "телефон" in why:
            ok()
        elif c is None:
            bad(f"{label}: на роутере ждали отказ «только на телефоне»", why)
        else:
            bad(f"{label}: на роутере ключ телефона принят")
        return
    if c is None:
        bad(f"{label}: пример {json.dumps(ex, ensure_ascii=False)} разбор не принял", why)
        return
    if "x-unsupported" in p:
        if NOT_YET in why:
            ok()
        else:
            bad(f"{label}: ждали отказ «{NOT_YET}»", why)
        return
    ok()
    win = c

    def with_value(v):
        n = copy.deepcopy(win)
        n[key] = v
        return n

    def accept_value(v, what, key_path=None, bound=None):
        cc, w2 = attempt(kctx, node, base, key, v)
        # Соседи, с которыми граница законна (min не больше max у кэша), — по таблице исключений.
        for comp in COMPANION.get((key_path, bound), []):
            if cc is None:
                cc, w2 = attempt(kctx, node, {**base, **comp}, key, v)
        if cc is None and (key_path, bound) in RANGE_OK_IF and RANGE_OK_IF[(key_path, bound)] in w2:
            cc = {}
        if cc is None:
            bad(f"{label}: {what} — отказ разбора", w2)
        else:
            ok()
        return cc

    def reject_value(v, what):
        n = with_value(v)
        a, w2 = try_obj(kctx, n)
        if a:
            bad(f"{label}: {what} — разбор принял")
        elif unknown(w2):
            bad(f"{label}: {what} — ключ назван неизвестным", w2)
        else:
            ok()

    is_arr = types == ["array"]
    item = p.get("items", {}) if is_arr else p
    # enum
    for e in item.get("enum", []):
        accept_value([e] if is_arr else e, f"значение {json.dumps(e, ensure_ascii=False)}")
    if "enum" in item:
        bad_v = "zz-bad" if "string" in scalars(item) else 999999
        reject_value([bad_v] if is_arr else bad_v, "значение вне enum")
    # границы чисел (у перечня — столько элементов, сколько в примере: веса по числу членов)
    if "minimum" in item or "maximum" in item:
        n_el = len(ex) if is_arr and isinstance(ex, list) and ex else 1
        for lim, d in (("minimum", -1), ("maximum", 1)):
            if lim in item:
                v = item[lim]
                # элементы разные (узлы подписки не повторяются), крайний — на границе или за ней
                run = [v + i for i in range(n_el)] if lim == "minimum" else [v - n_el + 1 + i for i in range(n_el)]
                over = ([v + d] + run[:-1]) if lim == "minimum" else (run[1:] + [v + d])
                accept_value(run if is_arr else v, f"граница {lim}={v}", key_path=label, bound=lim)
                reject_value(over if is_arr else v + d, f"за границей {lim}={v}")
    # один скаляр вместо списка
    # (веса — по одному на члена: скаляр годится при одном члене, а в примере их два)
    if is_arr and p.get("x-one-or-list") and isinstance(ex, list) and ex and key != "weights":
        accept_value(ex[0], "один скаляр вместо списка")
    # минимальная длина перечня
    if is_arr and p.get("minItems"):
        reject_value([], "пустой список при minItems")
    if is_arr and "maxItems" in p:
        n = p["maxItems"]
        accept_value([str(i) for i in range(1, n + 1)], f"{n} элементов (maxItems)")
        reject_value([str(i) for i in range(1, n + 2)], f"{n + 1} элементов (больше maxItems)")
    # булево
    if types == ["boolean"]:
        reject_value("maybe", "не логическое значение")
    # ссылки по именам
    ref = item.get("x-ref")
    if ref:
        reject_value(["zz-nope"] if is_arr else "zz-nope", "ссылка на несуществующее имя")
        for w in ref.get("also", []):
            accept_value([w] if is_arr else w, f"слово {w} из x-ref.also")
    # путь: x-path etc — строка
    if item.get("x-path") and "string" not in scalars(item):
        bad(f"{label}: x-path у не строки")


# ---- обход разделов -------------------------------------------------------------------------

def top_mk(section):
    return lambda o: place([section, "t1"], o)


def walk_entity(label, mk, ent):
    ctx = Ctx(mk, label)
    if "x-variants" in ent:
        walk_variants(ctx, ent)
    else:
        walk_object(ctx, ent)


def names_checks(label, section, ent, nm, mkname):
    """Имена записей: негодный состав, слишком длинное, занятые."""
    good = ent_base(ent)
    pat = re.compile(nm.get("pattern", ".*"))
    ctx = Ctx(None, label)
    for badn in ("a b", "x" * (nm.get("maxLength", 31) + 1)):
        a, why = run_spec(mkname(badn, good))
        if a:
            bad(f"{label}: имя «{badn}» принято")
        else:
            ok()
    for r in nm.get("reserved", []):
        a, why = run_spec(mkname(r, good))
        if a:
            bad(f"{label}: занятое имя {r} принято")
        else:
            ok()
    a, why = run_spec(mkname("x" * nm.get("maxLength", 31), good))
    if a:
        ok()
    else:
        bad(f"{label}: имя в {nm.get('maxLength', 31)} байт — отказ", why)


def ent_base(ent):
    if "x-variants" in ent:
        # запись по первому доступному варианту
        for v in ent["x-variants"].values():
            if "x-absent" not in v:
                return base_of(v)
    return base_of(ent)


def walk_variants(ctx, ent):
    vars_ = ent["x-variants"]
    union = {}
    for name, v in vars_.items():
        for k, p in v.get("properties", {}).items():
            if k not in union and ex_has(p) and "const" not in p:
                union[k] = p
    for name, v in vars_.items():
        label = f"{ctx.label}[{name}]"
        if "x-absent" in v:
            notes.append(name)
            # вид без ключей: отказ называет пакет
            # Без плагинной раскладки разбор отказывает словами x-absent; с ней (стенд плагинов) вид
            # недоступный: выход принят и живёт как unavail (steer-api.md, 3.5).
            spec = v.get("x-spec", {})
            o = {k: val for k, val in spec.items()}
            a, why = run_spec(ctx.mk(o))
            if not a and v["x-absent"] not in why:
                bad(f"{label}: отказ не называет x-absent", why)
            else:
                ok()
            continue
        sub = Ctx(ctx.mk, label)
        walk_object(sub, v)
        # ключи чужих видов
        own = set(v.get("properties", {}))
        base = base_of(v)
        for k, p in union.items():
            if k in own:
                continue
            a, why = run_spec(ctx.mk({**base, k: copy.deepcopy(ex_of(p))}))
            if a:
                bad(f"{label}: чужой ключ {k} принят")
            else:
                ok()


def walk_dns_entity(ctx, ent):
    walk_variants(ctx, ent)


def walk_top():
    props = S["properties"]
    # version
    v = props["version"]
    a, why = run_spec({k: val for k, val in FIX.items() if k != "version"})
    if a:
        bad("version: без ключа разбор принял")
    else:
        ok()
    for e in v.get("enum", []):
        accept(Ctx(lambda o: {**FIX, "version": o}, "version"), e, "значение")
    reject(Ctx(lambda o: {**FIX, "version": o}, "version"), 999, "чужая версия")
    reject(Ctx(lambda o: {**FIX, "zz_unknown": o}, "корень"), 1, "неизвестный раздел", "неизвестный ключ")

    # lan, dns — вложенные объекты
    for sec in ("lan", "dns"):
        node = props[sec]
        mk = (lambda o, s=sec: {**FIX, s: {**FIX.get(s, {}), **o}})
        ctx = Ctx(mk, sec)
        walk_object_with_maps(ctx, node, sec)
    # clients, lists, outputs
    for sec in ("clients", "lists", "outputs"):
        p = props[sec]
        ent = p["additionalProperties"]
        walk_entity(sec + ".<имя>", top_mk(sec), ent)
        nm = p.get("x-name", {})
        names_checks(sec, sec, ent, nm, lambda name, good, s=sec: place([s, name], good))
    # rules
    r = props["rules"]
    ent = r["items"]
    walk_rules(ent)


def walk_object_with_maps(ctx, node, sec):
    """lan и dns: ключи узла и вложенные записи (dns.upstreams, dns.cache_ttl)."""
    pr = node.get("properties", {})
    base = base_of(node)
    accept(ctx, base, "основа записи")
    reject(ctx, {**base, "zz_unknown": 1}, "неизвестный ключ", "неизвестный ключ")
    for key, p in pr.items():
        if scalars(p) == ["object"] and isinstance(p.get("additionalProperties"), dict):
            ent = p["additionalProperties"]
            mk = lambda o, k=key, s=sec: {**FIX, s: {**FIX.get(s, {}), k: {**FIX.get(s, {}).get(k, {}), "t1": o}}}
            walk_dns_entity(Ctx(mk, f"{sec}.{key}.<имя>"), ent)
            nm = p.get("x-name", {})
            names_checks(f"{sec}.{key}", key, ent, nm,
                         lambda name, good, k=key, s=sec: {**FIX, s: {**FIX.get(s, {}), k: {name: good}}})
            continue
        walk_key(ctx, node, base, key, p)


def walk_rules(ent):
    base_node = ent
    mk = lambda o: place(["rules"], o)
    ctx = Ctx(mk, "rules[]")
    props = ent["properties"]
    base = base_of(ent)
    accept(ctx, base, "основа записи")
    reject(ctx, {**base, "zz_unknown": 1}, "неизвестный ключ", "неизвестный ключ")
    for r in ent.get("required", []):
        a, _ = run_spec(mk({k: v for k, v in base.items() if k != r}))
        if a:
            bad(f"rules[]: без обязательного {r} разбор принял")
        else:
            ok()
    for key, p in props.items():
        if key == "dns":
            # имя апстрима и запись прямо в правиле — варианты те же, что у dns.upstreams
            c, why = attempt(Ctx(mk, "rules[].dns"), ent, base, key, "dns1")
            if c is None:
                bad("rules[].dns: имя апстрима отвергнуто", why)
            else:
                ok()
            reject(Ctx(mk, "rules[].dns"), {**base, "dns": "zz-nope"}, "ссылка на несуществующее имя")
            walk_variants(Ctx(lambda o, m=mk, b=base: m({**b, "dns": o}), "rules[].dns"),
                          {"x-variants": p["x-variants"]})
            continue
        walk_key(ctx, ent, base, key, p)


# ---- обратная проверка: что разбор принимает, то есть в схеме ----------------------------------

def doc_words():
    if not DOC or not os.path.exists(DOC):
        return set()
    words = set()
    for line in open(DOC, encoding="utf-8"):
        if line.startswith("|") or line.startswith("###"):
            for w in re.findall(r"`([a-z_][a-z_0-9]*)`", line):
                words.add(w)
    return words


def recognized(mk, key, base):
    """Принимает ли разбор ключ key в записи (по тому, что он не назвал его неизвестным)."""
    a, why = run_spec(mk({**base, key: 1}))
    return not unknown(why)


def listed(why):
    m = re.search(r"\(есть: ([^)]*)\)", why)
    return set(x.strip() for x in m.group(1).split(",")) if m else None


def reverse_check(label, mk, node, base, extra_words, known=frozenset()):
    keys = set(node.get("properties", {}))
    # 1. перечень, который разбор сам печатает в отказе «неизвестный ключ … (есть: …)»
    a, why = run_spec(mk({**base, "zz_unknown": 1}))
    lst = listed(why)
    if lst is not None:
        # У вида плагина перечень печатает проверка схемы манифеста: в нём только ключи плагина.
        if (not lst <= keys) if "x-plugin" in node else (lst - INTERNAL != keys):
            bad(f"{label}: перечень разбора {sorted(lst)} расходится со схемой {sorted(keys)}")
        else:
            ok()
    # 2. пробы слов: ключи схемы и слова справочника
    for w in sorted((keys | extra_words) - {"zz_unknown"}):
        if "x-spec" in node and w in ("kind", "protocol"):
            continue
        # Ключ другой записи: что разбор с ним делает здесь, проверяют «чужие ключи» (walk_variants).
        if w in known and w not in keys:
            continue
        if recognized(mk, w, base):
            if w not in keys and w not in INTERNAL:
                bad(f"{label}: разбор принимает ключ «{w}», а в схеме его нет")
            else:
                ok()
        elif w in keys:
            bad(f"{label}: ключ схемы «{w}» разбор не принял", "")


def variant_keys(variants):
    out = set()
    for v in variants.values():
        out |= set(v.get("properties", {}))
    return out


def walk_reverse():
    words = doc_words()
    props = S["properties"]
    targets = []
    targets.append(("корень", lambda o: o, {"version": 2}, props.keys()))
    # корень: ключи самой спеки
    keys = set(props)
    a, why = run_spec({**FIX, "zz_unknown": 1})
    lst = listed(why)
    if lst is not None and lst != keys:
        bad(f"корень: перечень разбора {sorted(lst)} расходится со схемой {sorted(keys)}")
    else:
        ok()
    for w in sorted(words | keys):
        a, why = run_spec({**FIX, w: 1})
        if w in keys:
            if unknown(why):
                bad(f"корень: раздел «{w}» из схемы разбор назвал неизвестным")
        elif not unknown(why):
            bad(f"корень: разбор принимает «{w}», а в схеме его нет")
    for sec in ("lan", "dns"):
        node = props[sec]
        mk = lambda o, s=sec: {**FIX, s: {**FIX.get(s, {}), **o}}
        reverse_check(sec, mk, node, {}, words)
        for key, p in node["properties"].items():
            if scalars(p) == ["object"] and "properties" in p:
                reverse_check(f"{sec}.{key}", lambda o, s=sec, k=key: {**FIX, s: {**FIX.get(s, {}), k: o}}, p, {}, words)
            if scalars(p) == ["object"] and isinstance(p.get("additionalProperties"), dict):
                ent = p["additionalProperties"]
                known = variant_keys(ent["x-variants"])
                for vn, v in ent["x-variants"].items():
                    reverse_check(f"{sec}.{key}[{vn}]",
                                  lambda o, s=sec, k=key: {**FIX, s: {**FIX.get(s, {}), k: {"t1": o}}}, v, base_of(v), words,
                                  known)
    for sec in ("clients", "lists"):
        ent = props[sec]["additionalProperties"]
        reverse_check(sec, top_mk(sec), ent, base_of(ent), words)
    ent = props["outputs"]["additionalProperties"]
    known = variant_keys(ent["x-variants"])
    for vn, v in ent["x-variants"].items():
        if "x-absent" in v:
            continue
        reverse_check(f"outputs[{vn}]", top_mk("outputs"), v, base_of(v), words, known)
    ent = props["rules"]["items"]
    reverse_check("rules[]", lambda o: place(["rules"], o), ent, base_of(ent), words)
    # вложенные записи выходов (obfs)
    for vn, v in ent_vars(props["outputs"]).items():
        for key, p in v.get("properties", {}).items():
            if scalars(p) == ["object"] and "properties" in p and "x-absent" not in v:
                b = base_of(v)
                reverse_check(f"outputs[{vn}].{key}", lambda o, bb=b, k=key: place(["outputs", "t1"], {**bb, k: o}), p, {}, set())


def ent_vars(outs):
    return outs["additionalProperties"]["x-variants"]


# ---- плагины: виды из реестра вливаются в схему с пометкой плагина ------------------------------

def check_plugins():
    want = [x for x in os.environ.get("SPECSCHEMA_PLUGINS", "").split(",") if x]
    if not want:
        return
    vars_ = S["properties"]["outputs"]["additionalProperties"]["x-variants"]
    listed_ids = {p["id"]: p for p in S.get("x-plugins", [])}
    for w in want:
        pid, variant = w.split("|", 1)
        v = vars_.get(variant)
        if v is None:
            bad(f"плагин {pid}: вида {variant} нет в схеме")
            continue
        if v.get("x-plugin", {}).get("id") != pid:
            bad(f"плагин {pid}: у вида {variant} нет пометки x-plugin")
        elif pid not in listed_ids:
            bad(f"плагин {pid}: нет в x-plugins")
        else:
            ok()
        if not any(p.get("x-plugin") == pid for p in v.get("properties", {}).values()):
            bad(f"плагин {pid}: у вида {variant} нет ключей из схемы манифеста")
        else:
            ok()
    for gone in [x for x in os.environ.get("SPECSCHEMA_PLUGINS_OFF", "").split(",") if x]:
        pid, variant = gone.split("|", 1)
        if variant in vars_:
            bad(f"плагин {pid} выключен, а вид {variant} в схеме")
        elif not (pid in listed_ids and listed_ids[pid]["enabled"] is False and listed_ids[pid].get("why")):
            bad(f"плагин {pid}: выключенный не назван в x-plugins с причиной")
        else:
            ok()


# ---- прогон ---------------------------------------------------------------------------------

check_plugins()

walk_top()
walk_reverse()

# Отчёт о расхождениях со справочником docs/spec-v2.md.
words = doc_words()
schema_keys = set()


def collect(node):
    if isinstance(node, dict):
        for k, v in node.get("properties", {}).items():
            schema_keys.add(k)
            collect(v)
        for k in ("items", "additionalProperties"):
            if isinstance(node.get(k), dict):
                collect(node[k])
        for v in node.get("x-variants", {}).values():
            collect(v)


collect(S)
if words:
    undocumented = sorted(k for k in schema_keys if k not in words)
    notaccepted = sorted(w for w in words if w not in schema_keys)
    if os.environ.get("SPECSCHEMA_REPORT"):
        print(f"specschemamatch[{LABEL}]: ключи схемы, не названные в таблицах docs/spec-v2.md: {undocumented}")
        print(f"specschemamatch[{LABEL}]: слова таблиц docs/spec-v2.md, которых нет среди ключей схемы: {notaccepted}")

if notes:
    print(f"specschemamatch[{LABEL}]: видов нет в сборке (схема называет их недоступными): " + ", ".join(notes))
print(f"specschemamatch[{LABEL}]: схема спеки — {passes} проверок прошли")
if fails:
    for f in fails:
        print(f"FAIL specschemamatch[{LABEL}]: {f}")
    print(f"specschemamatch[{LABEL}]: ПРОВАЛЕНО {len(fails)}")
    sys.exit(1)
sys.exit(0)
