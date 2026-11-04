/* Виды ядра, которые дополняет плагин (impl: core), и плагины, которых требует спека (`steer plugin migrate`).
 *
 * Один перечень на две проверки: менеджер принимает impl: core только для вида из него (manifest.md,
 * «Проверки при установке»), а migrate по нему же решает, нужен ли такой плагин выходу. Вид ядра работает
 * и без плагина, поэтому плагин ему ставится не по provides.kinds индекса (там его вид записан всегда), а
 * по правилу перечня: awg — всякому выходу awg, obfs — только выходу interface с ключом obfs (helper.when
 * манифеста obfs, kinds/plugin.c: plugin_core_ext).
 *
 * Модуль без менеджера вокруг (только ynode): его проверяет tests/pmkindmatch.c в `make test`. */
#ifndef STEER_PMKIND_H
#define STEER_PMKIND_H

#include <stddef.h>
#include "ynode.h"

/* 1 — плагину можно объявить вид name с impl: core (вид ядра из перечня), 0 — нельзя. */
int pm_core_ext_kind(const char *name);

/* Плагины, которых требуют выходы спеки (текст YAML или JSON, buf длиной n; name — для сообщений):
 * add(arg, id) на каждый, повторы возможны. plugins — раздел plugins индекса семени (provides.kinds);
 * NULL — только правила перечня. Возврат: 0; -1 — спека не разобралась (ничего не добавлено). */
int pm_spec_plugins(const char *buf, size_t n, const char *name, const struct ynode *plugins,
                    void (*add)(void *arg, const char *id), void *arg);

#endif
