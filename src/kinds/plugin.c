/* Плагины в ядре (plugin.h): вид unavail — выход, чей вид сейчас недоступен. */
#include <stdio.h>
#include <string.h>

#include "spec.h"
#include "awg.h"
#include "plugin.h"

/* ---- вид unavail ---------------------------------------------------------------------------
 *
 * Выход, вид которого не работает здесь и сейчас: плагин не поставлен или отключён, спека ещё не
 * подготовлена (steer-api.md, 3.5). Решение владельца: при старте и reload такой выход не рушит
 * спеку — он получает свою метку и таблицу, устройства у него нет, он `failed` и живёт по своему
 * on_fail, а остальные выходы работают; при apply из интерфейса спека с таким выходом — отказ с
 * причиной (LOAD_STRICT, spec.h).
 *
 * caps — устройство и метка: ровно столько нужно реестру меток и правилам on_fail, чтобы выход
 * ушёл в drop или direct, как у выхода, чьё устройство пропало. Своих ключей, правил и помощника у
 * вида нет; ключи неизвестного вида разбор пропускает молча — проверить их нечем. */
static int unavail_parse(struct output *o, const struct out_keys *k, struct err *e) {
    (void)k; (void)e;
    if (!o->device[0]) awg_default_ifname(o->name, o->device, sizeof(o->device));
    return 0;
}

static void unavail_keys_of(const struct output *o, struct out_keys *k) {
    (void)o; (void)k;
}

const struct kind_ops kind_unavail = {
    .name = "unavail",
    .caps = KC_DEVICE | KC_MARK,
    .parse = unavail_parse,
    .keys_of = unavail_keys_of,
};

int out_make_unavail(struct spec *sp, struct output *o, const char *why, const char *plugin,
                     const char *shown) {
    const char *w = spec_strdup(sp, why);
    const char *p = plugin ? spec_strdup(sp, plugin) : NULL;
    const char *sh = shown ? spec_strdup(sp, shown) : NULL;
    if (!w || (plugin && !p) || (shown && !sh)) return -1;
    memset(&o->plg, 0, sizeof(o->plg));
    o->kind = &kind_unavail;
    o->unavail = w;
    o->unavail_plugin = p;
    o->plg.shown = sh;
    o->failed = 1;
    if (!o->device[0]) awg_default_ifname(o->name, o->device, sizeof(o->device));
    return 0;
}
