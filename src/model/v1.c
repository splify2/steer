/* СПЕКА v1 → МОДЕЛЬ v2 (docs/architecture.md, «3. Спека v2» и «4в»).
 *
 * Спека v1 — JSON со `schema: 1` или `schema: 2` — читается до 2.0.0, и читается ЭТИМ файлом:
 * разбор, все прежние проверки (с прежними текстами отказов — их сверяют стенды и снимок) и
 * перевод в модель v2, в которой работает весь остальной движок. В 2.0.0 файл удаляется целиком.
 *
 * ПЕРЕВОД:
 *   - канал → правило (struct spec_rule) с безымянными клиентом и списком. Клиент — только если
 *     у канала свой `from`: без него «кто» правила — клиенты по умолчанию (sp->lan, прежний
 *     `from_default` и `lan_devices`). Список несёт файлы, наборы .srs и сужение proto/ports;
 *     `any` без списков — список «весь трафик» (all), с сужением, если оно написано. `scope:
 *     device` — dev_scope правила, `mode: realip` — realip, `enabled: false` — disabled.
 *     `allow_all` — согласие спеки v1, в модели его нет: проверяется здесь и дальше не нужен;
 *   - выход с `devices` (пул) → группа pick: order (или latency, если `prefer: latency`) из
 *     безымянных выходов-членов, по одному на устройство (group_of_devices, src/kinds/group.c).
 *     Имя группы — прежнее имя выхода, поэтому status, реестр меток и таблиц, имена наборов nft,
 *     comment правил и файл active остаются прежними. Выход с одним устройством остаётся
 *     выходом;
 *   - `via` → `over`.
 * Проверка перевода — снимок генератора (tests/snapshot.sh): v1 через модель v2 обязана давать
 * тот же ruleset до байта, — и стенд tests/modelmatch.c. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "spec.h"
#include "obfs.h"
#include "check.h"
#include "v1.h"

/* Канал спеки v1 — ровно то, что в нём написано, до перевода в правило. Живёт только на время
 * разбора одного канала (на стеке): модель хранит правило, список и клиента. */
struct v1_chan {
    char name[32];
    char out[32];
    /* Массивы — куски арены спеки ровно по числу записей (js_count): число файлов, адресов и
     * портов в канале константой не ограничено. */
    const char **prefixes_files;
    size_t prefixes_n;
    const char **domains_files;
    size_t domains_n;
    const char **srs_files;
    size_t srs_n;
    int realip;
    char (*from)[64];
    size_t from_n;
    int dev_scope;
    int any;
    /* Явное согласие на канал, который забирает весь трафик. Без него `any` без
     * списков отвергается: это почти всегда описка, а последствие — клиенты
     * теряют и роутер, и DNS, то есть чинить придётся с провода. */
    int allow_all;
    struct l4match l4;
    /* Стояли ли в `match` ключи схемы 2. Отдельно от самого сужения, и это не дублирование:
     * `"proto": "both"` — записанное умолчание, сужения из него не выходит, а ключ схемы 2 в
     * спеке `schema: 1` обязан быть отказом. Выводи признак из непустоты сужения — и `both`
     * проходил бы там, где `udp` отвергается, то есть человек читал бы это как «порты в
     * первой схеме работают», и однажды написал бы рядом настоящий порт. */
    int l4_written;
    int disabled;
};

/* Что из канала v1 нужно проверкам после разбора всего документа и чего в модели нет: имя
 * выхода (выход может стоять в спеке ниже канала), согласие allow_all и ключи схемы 2 (у JSON
 * нет порядка ключей, и `schema` законно стоит после `channels`). По номеру правила. */
struct v1_ctx {
    char (*out)[32];
    unsigned char *allow_all;
    unsigned char *l4_written;
    size_t cap;                     /* сколько правил вмещают три массива (ctx_at) */
};

/* Место под сведения о правиле i: три массива растут вместе с числом каналов, а не лежат на
 * предельное число. Вызывается до записи по номеру. -1 — нехватка памяти. */
static int ctx_at(struct v1_ctx *x, size_t i) {
    if (i < x->cap) return 0;
    size_t nc = x->cap ? x->cap * 2 : 16;
    while (nc <= i) nc *= 2;
    char (*o)[32] = realloc(x->out, nc * sizeof(*x->out));
    if (!o) return -1;
    x->out = o;
    unsigned char *a = realloc(x->allow_all, nc), *l = realloc(x->l4_written, nc);
    if (a) x->allow_all = a;
    if (l) x->l4_written = l;
    if (!a || !l) return -1;
    memset(x->allow_all + x->cap, 0, nc - x->cap);
    memset(x->l4_written + x->cap, 0, nc - x->cap);
    memset(x->out + x->cap, 0, (nc - x->cap) * sizeof(*x->out));
    x->cap = nc;
    return 0;
}
static void ctx_free(struct v1_ctx *x) {
    free(x->out);
    free(x->allow_all);
    free(x->l4_written);
    memset(x, 0, sizeof(*x));
}

static int v1_nomem(struct err *e) {
    return err_set(e, "%s", "недостаточно памяти для спеки");
}

/* Массив путей под j — в арену спеки ровно по числу записей. Строки str_list берёт в куче
 * (keep), здесь они переезжают в арену и отдаются обратно: спека владеет всем, что держит.
 * *n — число прочитанных (мягкая остановка на нестроке — не отказ), (size_t)-1 — отказ. */
static const char **v1_paths(struct spec *s, struct js *j, size_t *n, struct err *e) {
    size_t cnt = js_count(j);
    const char **tmp = cnt ? (const char **)calloc(cnt, sizeof(*tmp)) : NULL;
    if (cnt && !tmp) { v1_nomem(e); *n = (size_t)-1; return NULL; }
    size_t got = str_list(j, tmp, cnt, e);
    const char **out = NULL;
    if (got != (size_t)-1 && got) {
        out = (const char **)spec_alloc(s, got * sizeof(*out));
        if (!out) { v1_nomem(e); got = (size_t)-1; }
    }
    for (size_t i = 0; i < cnt; i++) {
        if (out && i < got) out[i] = spec_strdup(s, tmp[i]);
        free((char *)tmp[i]);
        if (out && i < got && !out[i]) { v1_nomem(e); got = (size_t)-1; out = NULL; }
    }
    free(tmp);
    *n = got;
    return got == (size_t)-1 ? NULL : out;
}

/* Один путь как массив из одного элемента (`prefixes_file` и родня). */
static const char **v1_path1(struct spec *s, const char *str, struct err *e) {
    const char **a = (const char **)spec_alloc(s, sizeof(*a));
    if (a) a[0] = spec_strdup(s, str);
    if (!a || !a[0]) { v1_nomem(e); return NULL; }
    return a;
}

/* Массив строк по 64 байта (адреса и устройства) — в арену ровно по числу записей. Возврат как у
 * str_array: 0 — разобрано (*n записей), -1 — не разобрано, e->msg заполнен или пуст (мягкий
 * отказ, решает вызывающий). */
static int v1_strs64(struct spec *s, struct js *j, char (**dst)[64], size_t *n, struct err *e) {
    size_t cnt = js_count(j);
    char (*a)[64] = cnt ? (char (*)[64])spec_alloc(s, cnt * sizeof(*a)) : NULL;
    if (cnt && !a) { v1_nomem(e); return -1; }
    int rc = str_array(j, a, cnt, n, e);
    if (*n) *dst = a;               /* пустой массив прежнее значение не трогает (br-lan у lan_dev) */
    return rc;
}

/* «443» или «50000-65535» → диапазон портов — port_range_parse (check.c, общий с v2). Отказ
 * громкий делает вызывающий: только он знает имя канала, а без имени сообщение не говорит, что
 * чинить. */

/* Перечень диапазонов портов канала.
 *
 * Отдельно от str_list, хотя читает такой же массив строк, потому что каждая строка здесь
 * ПРОВЕРЯЕТСЯ на месте: отложить проверку до генерации значило бы отдать негодный элемент
 * в `nft -f`, а тот отвергает НАБОР ПРАВИЛ ЦЕЛИКОМ. На роутере это выглядит как «мой выбор
 * не подействовал» — прежние правила остались, отказа человек не видел. Тот же довод, что у
 * check_address_lists в compile/groups.c, и та же беда, которую он лечит.
 *
 * Пересечения тоже отвергаются здесь: множество nftables с накладывающимися интервалами
 * (`{ 1-100, 50-60 }`) ядро не принимает, а повтор (`{ 443, 443 }`) — тем более. Отказать
 * при загрузке дешевле, чем при применении: при загрузке ничего ещё не изменено.
 *
 * 0 — разобрано, *out_n заполнен; -1 — отказ, текст уже в e->msg (см. правило 5). */
static int port_list(struct js *j, const char *chan, struct port_range *dst, size_t max,
                     size_t *out_n, struct err *e) {
    /* Буфер с запасом: строки русские, в UTF-8 это два байта на букву, и обрезка по границе
     * буфера разрубила бы букву посередине — на этом ломался вывод при первом прогоне
     * стенда однажды уже (см. I-029). */
    char msg[512];
    if (js_lit(j, '[') != 0) {
        snprintf(msg, sizeof(msg), "channels.%.24s: ports — массив строк вида "
                 "[\"443\", \"50000-65535\"]", chan);
        return err_set(e, "%s", msg);
    }
    size_t n = 0;
    js_ws(j);
    if (*j->p == ']') { j->p++; *out_n = 0; return 0; }
    for (;;) {
        char t[32];
        int r = js_str(j, t, sizeof(t), e);
        if (r != 0) {
            if (e->msg[0]) return -1;
            snprintf(msg, sizeof(msg), "channels.%.24s: ports: диапазон пишется СТРОКОЙ "
                     "(\"443\", а не 443)", chan);
            return err_set(e, "%s", msg);
        }
        if (n >= max) {
            snprintf(msg, sizeof(msg), "channels.%.24s: диапазонов портов больше %zu — каждый "
                     "диапазон размножает все адреса списка в составном наборе nftables "
                     "(адрес . протокол . порт), и память роутера кончилась бы раньше", chan, max);
            return err_set(e, "%s", msg);
        }
        if (port_range_parse(t, &dst[n]) != 0) {
            snprintf(msg, sizeof(msg), "channels.%.24s: ports: негодная запись «%.20s» — "
                     "нужно «443» или «50000-65535», числа от 1 до 65535, начало не больше "
                     "конца", chan, t);
            return err_set(e, "%s", msg);
        }
        /* Пересечение с уже прочитанным. Квадрат по шестнадцати записям — это дешевле, чем
         * сортировка, и сообщение остаётся про ту пару, которую человек написал. */
        for (size_t k = 0; k < n; k++)
            if (dst[k].lo <= dst[n].hi && dst[n].lo <= dst[k].hi) {
                snprintf(msg, sizeof(msg), "channels.%.24s: ports: диапазоны %u-%u и %u-%u "
                         "пересекаются — сложите их в один", chan,
                         dst[k].lo, dst[k].hi, dst[n].lo, dst[n].hi);
                return err_set(e, "%s", msg);
            }
        n++;
        js_ws(j);
        if (*j->p == ',') {
            /* См. str_list: висящая запятая — громкий отказ, а не продвижение к ']' и риск
             * зависания вызывающего цикла на несъеденной скобке. */
            j->p++;
            js_ws(j);
            if (*j->p == ']') {
                snprintf(msg, sizeof(msg), "channels.%.24s: ports: висящая запятая "
                         "(ожидалась строка)", chan);
                return err_set(e, "%s", msg);
            }
            continue;
        }
        break;
    }
    js_lit(j, ']');
    *out_n = n;
    return 0;
}

/* Обфускация транспорта выхода. Форма:
 *
 *   "obfs": { "mode": "wg-over-tcp", "server": "203.0.113.10:4567",
 *             "listen": "127.0.0.1:51820" }
 *
 * `listen` обязателен и должен совпадать с `Endpoint` пира в /etc/config/network: это
 * единственное место, где две настройки обязаны знать друг о друге, и вывести одну из
 * другой движок не может — ключи и пиры не его. Несовпадение молчаливо: WireGuard шлёт
 * в никуда, туннель не поднимается, и причина не видна ниоткуда, кроме tcpdump. */
static int parse_obfs(struct js *j, const char *name, struct out_obfs *ob, struct err *e) {
    if (js_lit(j, '{') != 0) return err_set(e, "outputs.%s: obfs должен быть объектом", name);
    char mode[32] = "", server[80] = "", listen[80] = "";
    js_ws(j);
    while (*j->p != '}') {
        char key[32];
        if (js_str(j, key, sizeof(key), e) != 0)
            return err_prop(e, "outputs.%s: плохой ключ в obfs", name);
        if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: в obfs после ключа нет двоеточия", name);
        if (!strcmp(key, "mode")) { if (js_str(j, mode, sizeof(mode), e) != 0 && e->msg[0]) return -1; }
        else if (!strcmp(key, "server")) { if (js_str(j, server, sizeof(server), e) != 0 && e->msg[0]) return -1; }
        else if (!strcmp(key, "listen")) { if (js_str(j, listen, sizeof(listen), e) != 0 && e->msg[0]) return -1; }
        else { if (js_skip(j, e) != 0) return -1; }
        js_ws(j);
        if (*j->p == ',') { j->p++; js_ws(j); }
    }
    j->p++;
    /* Что значения значат и что в них отказ — obfs_set (check.c, общий с v2). */
    return obfs_set(name, mode, server, listen, ob, e);
}

static int parse_outputs(struct js *j, struct spec *s, struct err *e) {
    if (js_lit(j, '{') != 0) return err_set(e, "outputs: expected an object", NULL);
    js_ws(j);
    if (*j->p == '}') { j->p++; return 0; }
    for (;;) {
        struct output o = {0};
        /* Ключи видов — сюда, до того как известен вид: `kind` может стоять в объекте последним.
         * Разбираются они здесь для всех видов, в том числе не вошедших в сборку: ошибка в
         * значении ключа и отказ «ключ чужого вида» обязаны звучать одинаково в любой сборке.
         * Что значения значат, решает вид (kind_ops.parse). */
        struct out_keys k = {0};
        /* Второй оси сторожа в модели у выхода нет — она у группы (pick: latency): здесь только
         * запоминаем написанное, а в группу оно ляжет, если выход окажется пулом. */
        int prefer_latency = 0, lat_tolerance_ms = -1, lat_interval_s = 0;   /* -1 — допуск не задан */
        if (js_str(j, o.name, sizeof(o.name), e) != 0)
            return err_prop(e, "outputs: expected a name", NULL);
        /* Состав имени — см. name_ok(). Оно уходит в командную строку через diag и в имя
         * набора, поэтому проверяется здесь, один раз, а не у каждого вызова. */
        if (!name_ok(o.name))
            return err_set(e, "outputs.%s: в имени выхода можно только буквы, цифры, _ - и точку", o.name);
        if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: expected ':'", o.name);
        if (js_lit(j, '{') != 0) return err_set(e, "outputs.%s: expected an object", o.name);
        char kind[32] = "";
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key), e) != 0) return err_prop(e, "outputs.%s: bad key", o.name);
            if (js_lit(j, ':') != 0) return err_set(e, "outputs.%s: после ключа нет двоеточия", o.name);
            if (!strcmp(key, "kind")) { if (js_str(j, kind, sizeof(kind), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "device")) {
                if (js_str(j, o.device, sizeof(o.device), e) != 0 && e->msg[0]) return -1;
                if (!name_ok(o.device))
                    return err_set(e, "outputs.%s: имя устройства негодного состава", o.name);
            }
            else if (!strcmp(key, "devices")) {
                /* Кандидаты в порядке предпочтения. Единственное число остаётся
                 * сокращением для одного — прежние спеки не ломаются. */
                if (js_lit(j, '[') == 0) {
                    js_ws(j);
                    if (*j->p == ']') j->p++;
                    else for (;;) {
                        char t[32];
                        int r = js_str(j, t, sizeof(t), e);
                        if (r != 0) { if (e->msg[0]) return -1; break; }
                        if (!name_ok(t)) return err_set(e, "outputs.%s: имя устройства негодного состава", o.name);
                        char (*slot)[32] = spec_push(s, (void **)&k.devices, k.devices_n, &k.devices_cap,
                                                     sizeof(*k.devices));
                        if (!slot) return v1_nomem(e);
                        snprintf(*slot, 32, "%s", t);
                        k.devices_n++;
                        js_ws(j);
                        if (*j->p == ',') {
                            /* См. str_list: trailing comma → отказ, не продвижение к ']' и
                             * риск зависания parse_outputs на несъеденной скобке. */
                            j->p++;
                            js_ws(j);
                            if (*j->p == ']') return err_set(e, "outputs.%s: trailing comma in devices", o.name);
                            continue;
                        }
                        js_lit(j, ']');
                        break;
                    }
                }
            }
            else if (!strcmp(key, "obfs")) { if (parse_obfs(j, o.name, &k.obfs, e) != 0) return -1; }
            else if (!strcmp(key, "sub_file")) { if (js_str(j, k.sub_file, sizeof(k.sub_file), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "conf")) { if (js_str(j, k.conf, sizeof(k.conf), e) != 0 && e->msg[0]) return -1; }
            /* Файл ключей nfqws у kind=zapret. Отдельным ключом, а не переиспользованным
             * `conf`: у xsteer там конфигурация в стиле wg с приватным ключом, здесь —
             * список ключей командной строки, и одно имя для двух разных вещей однажды
             * привело бы к попытке поднять туннель по стратегии обхода. */
            else if (!strcmp(key, "opts_file")) { if (js_str(j, k.opts_file, sizeof(k.opts_file), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "domain")) { if (js_str(j, k.domain, sizeof(k.domain), e) != 0 && e->msg[0]) return -1; }
            /* Через какой выход идёт трафик самого туннеля (подложка `over` модели — см. блок
             * «подложка» в spec.h). Состав имени проверяется тем же name_ok, что имя выхода:
             * строка уходит в status и в подпись помощника, а годное имя выхода по-другому и не
             * выглядит. Всё остальное (есть ли такой выход, годится ли он, нет ли круга)
             * проверяет over_check после разбора — цель может стоять в спеке ниже. */
            else if (!strcmp(key, "via")) {
                /* Пустая строка — «напрямую», как отсутствие ключа: так поле очищает
                 * интерфейс, который держит его в форме, и отказ на ней был бы придиркой. */
                if (js_str(j, o.over, sizeof(o.over), e) != 0 && e->msg[0]) return -1;
                if (o.over[0] && !name_ok(o.over))
                    return err_set(e, "outputs.%s: via — имя другого выхода (буквы, цифры, _ - и точка)",
                        o.name);
            }
            /* Транспорт выхода xsteer. Полем спеки, а не только ключом командной строки,
             * потому что процесс поднимает procd: ключи ему передать негде, а настройка
             * обязана переживать перезагрузку. */
            /* Проверяем на 't', как соседнее `enabled` проверяется на 'f': значение здесь
             * либо true, либо false, и разбирать его полноценным разбором JSON незачем. */
            else if (!strcmp(key, "stream")) { js_ws(j); k.stream = (*j->p == 't'); if (js_skip(j, e) != 0) return -1; }
            else if (!strcmp(key, "stream_port")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                k.stream_port = (int)v;
            }
            /* `node` — сокращение для списка из одного узла, `nodes` — сам список. Дальше по
             * коду путь один, ровно как у `device`/`devices`. Прежнее `-1` («первый рабочий»)
             * записывается пустым списком: это то же самое умолчание, только выраженное
             * отсутствием кандидатов, а не отрицательным номером. */
            else if (!strcmp(key, "node")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                k.node_one = 1;
                if (v >= 0) {
                    k.nodes = (int *)spec_alloc(s, sizeof(int));
                    if (!k.nodes) return v1_nomem(e);
                    k.nodes[0] = (int)v;
                    k.nodes_n = 1;
                }
                else k.nodes_n = 0;
            }
            else if (!strcmp(key, "nodes")) {
                size_t nc = js_count(j);
                k.nodes = nc ? (int *)spec_alloc(s, nc * sizeof(int)) : NULL;
                if (nc && !k.nodes) return v1_nomem(e);
                if (num_array(j, k.nodes, nc, &k.nodes_n, e) != 0)
                    return err_prop(e, "outputs.%s: nodes — массив номеров узлов подписки", o.name);
                k.node_many = 1;
            }
            else if (!strcmp(key, "on_fail")) {
                char m[16];
                if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(m, "drop")) o.on_fail = FAIL_DROP;
                else if (!strcmp(m, "direct")) o.on_fail = FAIL_DIRECT;
                /* zapret на телефоне нет — см. out_skips_zapret в spec.h. */
                else if (!strcmp(m, "zapret") && !plat()->zapret)
                    return err_set(e, "outputs.%s: on_fail zapret — на телефоне zapret нет "
                        "(want drop or direct)", o.name);
                else if (!strcmp(m, "zapret")) o.on_fail = FAIL_ZAPRET;
                else if (!plat()->zapret)
                    return err_set(e, "outputs.%s: unknown on_fail (want drop or direct)", o.name);
                else return err_set(e, "outputs.%s: unknown on_fail (want drop, direct or zapret)", o.name);
            }
            /* ВТОРАЯ ОСЬ СТОРОЖА: выбирать не только «живо», но и «насколько быстро».
             *
             * До запуска 65 порядок в `devices` был единственным мерилом: сторож брал ПЕРВОЕ
             * здоровое и на этом останавливался. `prefer: latency` включает второй вопрос — в
             * модели это группа pick: latency. НЕ ПО УМОЛЧАНИЮ, и это про совместимость:
             * старый движок неизвестный ключ пропускает (js_skip), то есть ведёт себя «по
             * порядку»; ключ, включённый по умолчанию, у него бы молча не действовал.
             *
             * Цена названа там, где она возникает (failover.c): замер требует опросить ВСЕХ
             * кандидатов, поэтому идёт он на своём, длинном интервале. У выхода без пула ключ
             * ничего не меняет — выбирать не из чего. */
            else if (!strcmp(key, "prefer")) {
                char m[16];
                if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(m, "latency")) prefer_latency = 1;
                else if (strcmp(m, "order") != 0)
                    return err_set(e, "outputs.%s: unknown prefer (want order or latency)", o.name);
            }
            else if (!strcmp(key, "latency_tolerance_ms")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                /* Ноль законен и означает «переключаться на любое улучшение». Отрицательное
                 * — нет: оно означало бы «переключаться на ухудшение», и это не настройка, а
                 * опечатка, которую надо назвать. */
                if (v < 0 || v > 60000)
                    return err_set(e, "outputs.%s: latency_tolerance_ms — от 0 до 60000", o.name);
                lat_tolerance_ms = (int)v;
            }
            else if (!strcmp(key, "latency_interval_s")) {
                long v = 0;
                if (js_num(j, &v, e) != 0) return -1;
                /* Нижний предел не косметика: замер опрашивает ВСЕХ кандидатов, и интервал
                 * короче тика сторожа означал бы замер на каждом тике — то есть таймаут за
                 * каждого мёртвого кандидата каждую минуту. */
                if (v < 30 || v > 86400)
                    return err_set(e, "outputs.%s: latency_interval_s — от 30 до 86400", o.name);
                lat_interval_s = (int)v;
            }
            else { if (js_skip(j, e) != 0) return -1; }
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        /* Вид — по имени из реестра (src/kinds/kind.c). Вид, не вошедший в сборку, отвечает своей
         * строкой отказа СРАЗУ, а не при подъёме: иначе спека применяется, правила встают, и выход
         * молча никуда не ведёт. */
        /* Группы (kind: group) в реестре нет — спека v1 её не знает, и `"kind": "group"` здесь
         * остаётся неизвестным видом, как было (см. kind.h). */
        const struct kind_ops *kd = kind_by_name(kind);
        if (!kd) return err_set(e, "outputs.%s: неизвестный kind "
                   "(нужен direct, interface, vless, xsteer, zapret, tgws или awg)", o.name);
        if (kd->absent) {
            static char msg[256];
            snprintf(msg, sizeof(msg), "outputs.%s: %s", o.name, kd->absent);
            return err_set(e, "%s", msg);
        }
        o.kind = kd;
        if (kd->parse && kd->parse(&o, &k, e) != 0) return -1;
        /* КЛЮЧ ЧУЖОГО ВИДА — отказ. Поле, принятое молча у чужого вида выхода, — это
         * «настроено», сказанное о том, что не настроено. Проверки стоят ПОСЛЕ разбора вида,
         * и порядок их прежний: сообщение называет первый чужой ключ.
         *
         * Обфускация осмысленна только там, где транспорт — чужой UDP, до которого
         * движку не дотянуться иначе. У vless свой транспорт внутри движка (и свои
         * средства маскировки — Reality), у xsteer он свой и поддельный TCP уже внутри
         * него, у direct транспорта нет вовсе. Режим потока — свойство транспорта xsteer. */
        if (k.obfs.on && !(kd->keys & KK_OBFS))
            return err_set(e, "outputs.%s: obfs есть только у kind=interface", o.name);
        if ((k.stream || k.stream_port) && !(kd->keys & KK_STREAM))
            return err_set(e, "outputs.%s: stream есть только у kind=xsteer", o.name);
        if (k.opts_file[0] && !(kd->keys & KK_OPTS))
            return err_set(e, "outputs.%s: opts_file есть только у kind=zapret", o.name);
        if (k.domain[0] && !(kd->keys & KK_DOMAIN))
            return err_set(e, "outputs.%s: domain есть только у kind=tgws", o.name);
        /* Своя проверка вида после общих — то, что зависит от общих полей (on_fail у zapret и
         * tgws). */
        if (kd->check && kd->check(s, &o, e) != 0) return -1;
        /* Какой из двух форм записан выбор узлов. Нужно, чтобы отличить «поля нет» от «поле
         * задано» и поймать выход, где заданы обе: молча взять одну значило бы, что половина
         * написанного человеком не действует, и понять это было бы нечем (тот же приём, что
         * у lan_device/lan_devices в load_spec). */
        if (k.node_one && k.node_many)
            return err_set(e, "outputs.%s: задано и node, и nodes — оставьте одно", o.name);
        /* Выбор узлов есть только у подписки. Отвергается ТОЛЬКО новая форма: `nodes` не
         * может стоять в спеке, написанной до этой версии, а `node` там стоять мог — и у
         * чужого вида выхода он и раньше ничего не делал. Отказать на нём сейчас значило бы
         * сломать применение спеки, которая работала, ради поля, которое ничего не меняет. */
        if (k.node_many && !(kd->keys & KK_NODES))
            return err_set(e, "outputs.%s: nodes есть только у kind=vless — это номера узлов подписки",
                o.name);
        /* Дубликат номера делает перебор бессмысленным ровно так же, как дубликат устройства
         * в devices: второй кандидат ничем не отличается от первого. */
        for (size_t a = 0; a < k.nodes_n; a++)
            for (size_t b = a + 1; b < k.nodes_n; b++)
                if (k.nodes[a] == k.nodes[b])
                    return err_set(e, "outputs.%s: узел подписки указан в nodes дважды", o.name);
        /* Два выхода с одним именем: реестр раздаст две метки, init поднимет два процесса
         * на одно имя, а out_by_name всегда возьмёт первый — как у devices и nodes, это
         * отказ, не молчаливая победа одного из двух. */
        for (size_t a = 0; a < s->out_n; a++)
            if (!strcmp(s->out[a].name, o.name))
                return err_set(e, "outputs.%s: имя выхода повторяется", o.name);
        /* ПУЛ УСТРОЙСТВ → ГРУППА. Выход interface с `devices` из нескольких устройств (или с
         * одним, но не тем, что в `device`) — это выбор среди кандидатов, то есть группа: члены —
         * безымянные интерфейсы по одному на устройство, pick — order или latency, имя, метка,
         * таблица, on_fail и via — прежние, у группы. Выход с единственным устройством остаётся
         * выходом: выбирать ему не из чего, и сторож ведёт его так же, как вёл.
         *
         * Пул с obfs — отказ. Обфускатор обслуживает одно устройство — то, чей Endpoint смотрит на
         * его listen, — и у группы его нет: он остался бы без выхода, а какому члену он
         * принадлежит, из спеки не узнать. */
        if (k.devices_n && (kd->keys & KK_DEVICES) &&
            (k.devices_n > 1 || strcmp(k.devices[0], o.device) != 0)) {
            if (iface_obfs(&o))
                return err_set(e, "outputs.%s: obfs у выхода с несколькими устройствами — "
                    "обфускатор обслуживает одно устройство; оставьте в devices одно или вынесите "
                    "обфускацию в отдельный выход", o.name);
            if (group_of_devices(s, &o, k.devices, k.devices_n, e) != 0) return -1;
            o.grp.pick = prefer_latency ? PICK_LATENCY : PICK_ORDER;
            o.grp.lat_tolerance_ms = lat_tolerance_ms;
            o.grp.lat_interval_s = lat_interval_s;
        }
        if (spec_reserve_out(s, s->out_n + 1) != 0) return v1_nomem(e);
        s->out[s->out_n++] = o;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    /* Закрывающая скобка обязательна: без неё это оборванный файл (питание пропало посреди
     * записи), и половина спеки применялась бы без единой жалобы. */
    if (js_lit(j, '}') != 0) return err_set(e, "outputs: нет закрывающей скобки — спека оборвана?", NULL);
    return 0;
}

/* Канал → правило с безымянными клиентом и списком (перевод — в шапке файла). */
static int chan_store(struct spec *s, struct v1_ctx *x, const struct v1_chan *c, struct err *e) {
    if (spec_reserve_rule(s, s->rule_n + 1) != 0 || spec_reserve_list(s, s->list_n + 1) != 0 ||
        spec_reserve_client(s, s->client_n + 1) != 0 || ctx_at(x, s->rule_n) != 0)
        return v1_nomem(e);
    size_t i = s->rule_n++;
    struct spec_rule *r = &s->rule[i];
    memset(r, 0, sizeof(*r));
    snprintf(r->name, sizeof(r->name), "%s", c->name);
    r->out = -1;                    /* номер выхода — после разбора всего документа */
    r->realip = c->realip;
    r->dev_scope = c->dev_scope;
    r->disabled = c->disabled;
    struct spec_list *l = &s->list[s->list_n];
    memset(l, 0, sizeof(*l));
    /* Канал v1 — ровно один список и не больше одного клиента (шапка файла). */
    r->lists = (unsigned *)spec_alloc(s, sizeof(unsigned));
    r->clients = c->from_n ? (unsigned *)spec_alloc(s, sizeof(unsigned)) : NULL;
    if (!r->lists || (c->from_n && !r->clients)) return v1_nomem(e);
    r->lists[r->lists_n++] = (unsigned)s->list_n++;
    /* Массивы канала уже лежат в арене спеки: список забирает их по указателю. */
    l->prefixes_files = c->prefixes_files;
    l->prefixes_n = c->prefixes_n;
    l->domains_files = c->domains_files;
    l->domains_n = c->domains_n;
    l->srs_files = c->srs_files;
    l->srs_n = c->srs_n;
    l->l4 = c->l4;
    /* `any` рядом со списками ничего не значит (так было всегда: группа «весь трафик» — только
     * у канала без списков), поэтому в модель он приходит признаком списка, а не канала. */
    l->all = c->any && !c->prefixes_n && !c->domains_n && !c->srs_n;
    if (c->from_n) {
        struct spec_client *cl = &s->client[s->client_n];
        memset(cl, 0, sizeof(*cl));
        cl->from = c->from;
        cl->from_n = c->from_n;
        r->clients[r->clients_n++] = (unsigned)s->client_n++;
    }
    snprintf(x->out[i], sizeof(x->out[i]), "%s", c->out);
    x->allow_all[i] = (unsigned char)c->allow_all;
    x->l4_written[i] = (unsigned char)c->l4_written;
    return 0;
}

static int parse_channels(struct js *j, struct spec *s, struct v1_ctx *x, struct err *e) {
    if (js_lit(j, '[') != 0) return err_set(e, "channels: expected an array", NULL);
    js_ws(j);
    if (*j->p == ']') { j->p++; return 0; }
    for (;;) {
        struct v1_chan c = {0};
        /* Какой из двух форм записаны списки совпадения — как у device/devices: заданы обе
         * значит половина написанного человеком молча не действует. */
        int pf_one = 0, pf_many = 0, df_one = 0, df_many = 0, sf_one = 0, sf_many = 0;
        if (js_lit(j, '{') != 0) return err_set(e, "channels: expected an object", NULL);
        js_ws(j);
        while (*j->p != '}') {
            char key[32];
            if (js_str(j, key, sizeof(key), e) != 0) return err_prop(e, "channels: bad key", NULL);
            if (js_lit(j, ':') != 0) return err_set(e, "channels: после ключа «%s» нет двоеточия", key);
            if (!strcmp(key, "name")) { if (js_str(j, c.name, sizeof(c.name), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "out")) { if (js_str(j, c.out, sizeof(c.out), e) != 0 && e->msg[0]) return -1; }
            else if (!strcmp(key, "from")) { if (v1_strs64(s, j, &c.from, &c.from_n, e) != 0 && e->msg[0]) return -1; }
            /* СХЕМА 2: правило на одно устройство, старше глобальных по построению.
             * Разрешено только при `schema: 2` — проверяется ниже, вместе с proto/ports, и
             * по той же причине: движок постарше ключ пропустит и положит правило в порядке
             * спеки, то есть исключение для телефона проиграет глобальному правилу молча. */
            else if (!strcmp(key, "scope")) {
                char sc[16];
                if (js_str(j, sc, sizeof(sc), e) != 0 && e->msg[0]) return -1;
                if (!strcmp(sc, "device")) { c.dev_scope = 1; c.l4_written = 1; }
                else if (strcmp(sc, "global") != 0)
                    return err_set(e, "channels.%s: unknown scope (want device or global)", c.name);
            }
            /* Отсутствие поля и `true` значат одно: правило работает, — спека без этого
             * поля обязана вести себя как прежде. «Нет» — и `false`, и `0`: jshn пишет
             * логическое значение то словом, то единицей (см. any ниже), а проверка по
             * первой букве 'f' включала канал, выключенный человеком, на `"enabled":0`
             * (I-315). Непонятное значение канал по-прежнему не выключает, но называется. */
            else if (!strcmp(key, "enabled")) {
                js_ws(j);
                const char *v = j->p;
                if (js_skip(j, e) != 0) return -1;
                size_t vl = (size_t)(j->p - v);
                while (vl && (v[vl - 1] == ' ' || v[vl - 1] == '\t' ||
                              v[vl - 1] == '\n' || v[vl - 1] == '\r')) vl--;
                if ((vl == 5 && !strncmp(v, "false", 5)) || (vl == 1 && *v == '0'))
                    c.disabled = 1;
                else if (!(vl == 4 && !strncmp(v, "true", 4)) && !(vl == 1 && *v == '1'))
                    fprintf(stderr, "steer[warn] channels.%s: enabled=%.*s не понят — канал "
                            "остаётся включённым; запишите true или false\n",
                            c.name[0] ? c.name : "?", (int)(vl > 16 ? 16 : vl), v);
            }
            else if (!strcmp(key, "match")) {
                if (js_lit(j, '{') != 0) return err_set(e, "channels.%s: match must be an object", c.name);
                js_ws(j);
                while (*j->p != '}') {
                    char mk[32];
                    /* Возврат js_str проверяется, как во всех соседних циклах, и это не
                     * педантизм. На недописанной спеке (питание пропало посреди записи
                     * файла) js_str отказывал молча, js_lit тоже, а js_skip на '\0' не
                     * продвигает указатель ни на байт — условие цикла оставалось истинным
                     * вечно. `steer status` на таком файле уходил в бесконечный цикл со
                     * 100% CPU, а его опрашивает rpcd каждые пять секунд: каждый опрос
                     * плодил ещё один вечный процесс на единственном ядре роутера.
                     * Контракт обещает громкий отказ на битой спеке — вот он. */
                    if (js_str(j, mk, sizeof(mk), e) != 0)
                        return err_prop(e, "channels.%s: match: expected a key", c.name);
                    if (js_lit(j, ':') != 0)
                        return err_set(e, "channels.%s: match: expected ':'", c.name);
                    /* Singular is shorthand for a one-element list, so a spec written
                     * before this stayed valid. */
                    if (!strcmp(mk, "prefixes_file")) {
                        if (pf_many) return err_set(e, "channels.%s: prefixes_file рядом с prefixes_files", c.name);
                        pf_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            c.prefixes_files = v1_path1(s, one, e);
                            if (!c.prefixes_files) return -1;
                            c.prefixes_n = 1;
                        }
                    } else if (!strcmp(mk, "domains_file")) {
                        if (df_many) return err_set(e, "channels.%s: domains_file рядом с domains_files", c.name);
                        df_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            c.domains_files = v1_path1(s, one, e);
                            if (!c.domains_files) return -1;
                            c.domains_n = 1;
                        }
                    } else if (!strcmp(mk, "prefixes_files")) {
                        if (pf_one) return err_set(e, "channels.%s: prefixes_files рядом с prefixes_file", c.name);
                        pf_many = 1;
                        size_t sl;
                        c.prefixes_files = v1_paths(s, j, &sl, e);
                        if (sl == (size_t)-1) return -1;
                        c.prefixes_n = sl;
                    } else if (!strcmp(mk, "domains_files")) {
                        if (df_one) return err_set(e, "channels.%s: domains_files рядом с domains_file", c.name);
                        df_many = 1;
                        size_t sl;
                        c.domains_files = v1_paths(s, j, &sl, e);
                        if (sl == (size_t)-1) return -1;
                        c.domains_n = sl;
                    }
                    /* Наборы sing-box (`.srs`) — полноценный источник списка: имена из них
                     * берёт резолвер, подсети — компилятор, сужение по протоколу и портам
                     * применяется к каналу само (src/model/srs.c, src/compile/groups.c). Форма —
                     * та же пара, что у prefixes_file/prefixes_files. Содержимое здесь не
                     * читается: разбор спеки не открывает списков, их открывает тот, кому они
                     * нужны. */
                    else if (!strcmp(mk, "srs_file")) {
                        if (sf_many) return err_set(e, "channels.%s: srs_file рядом с srs_files", c.name);
                        sf_one = 1;
                        char one[256];
                        int r = js_str(j, one, sizeof(one), e);
                        if (r != 0 && e->msg[0]) return -1;
                        if (r == 0) {
                            c.srs_files = v1_path1(s, one, e);
                            if (!c.srs_files) return -1;
                            c.srs_n = 1;
                        }
                    } else if (!strcmp(mk, "srs_files")) {
                        if (sf_one) return err_set(e, "channels.%s: srs_files рядом с srs_file", c.name);
                        sf_many = 1;
                        size_t sl;
                        c.srs_files = v1_paths(s, j, &sl, e);
                        if (sl == (size_t)-1) return -1;
                        c.srs_n = sl;
                    }
                    else if (!strcmp(mk, "mode")) {
                        char m[16];
                        if (js_str(j, m, sizeof(m), e) != 0 && e->msg[0]) return -1;
                        if (!strcmp(m, "realip")) {
                            c.realip = 1;
                            /* РЕЖИМ УХОДИТ (решение владельца, запуск 65), но принимается
                             * по-прежнему: спеки с ним уже лежат на роутерах, и отказ
                             * означал бы, что обновление движка снимает маршрутизацию.
                             * Поэтому предупреждение, а не die, — и с уровнем, потому что
                             * спека разобрана и работа продолжается.
                             *
                             * Что теряется при переходе на fakeip: читаемость traceroute.
                             * В real-IP ответ идёт клиенту нетронутым, DNAT нет, ICMP не
                             * переписывается и трассировка показывает настоящие узлы (см.
                             * ветку real-IP в upstream_answer, src/dnsd/proxy.c). Взамен
                             * fakeip даёт точность на домен: в real-IP два домена за
                             * одним адресом склеиваются, и если они в разных
                             * каналах, первый разрешённый решает за оба. Пул поддельных
                             * адресов исчерпать нечем — 198.18.0.0/15 это 131072 адреса
                             * против полутора тысяч имён в самом большом списке. */
                            fprintf(stderr, "steer[warn] channel %s: mode=realip уходит из "
                                    "ядра — переведите канал на fakeip; сейчас режим ещё "
                                    "работает\n", c.name);
                        }
                        else if (strcmp(m, "fakeip") != 0) return err_set(e, "channels: unknown mode %s (want fakeip or realip)", m);
                    }
                    /* ---- СХЕМА 2: протокол и порты назначения ----------------------
                     *
                     * Разрешены только при `schema: 2`, и проверяется это НЕ ЗДЕСЬ, а в
                     * load_spec: у JSON нет порядка ключей, и `schema` законно стоит после
                     * `channels`. Здесь запоминаем сам факт (l4_written), а судим потом,
                     * когда прочитан весь документ. */
                    else if (!strcmp(mk, "proto")) {
                        char pr[16] = "";
                        if (js_str(j, pr, sizeof(pr), e) != 0)
                            return err_prop(e, "channels.%s: proto — строка: tcp, udp или both", c.name);
                        c.l4_written = 1;
                        if (!strcmp(pr, "tcp")) c.l4.proto = CH_PROTO_TCP;
                        else if (!strcmp(pr, "udp")) c.l4.proto = CH_PROTO_UDP;
                        /* `both` — записанное умолчание: сужения по протоколу из него не
                         * выходит. Принимается затем, чтобы у интерфейса с тремя пунктами в
                         * списке не было особого случая «третий пункт — не писать ключ». */
                        else if (!strcmp(pr, "both")) c.l4.proto = CH_PROTO_ANY;
                        else {
                            char msg[160];
                            snprintf(msg, sizeof(msg), "channels.%.24s: неизвестный proto "
                                     "«%.12s» (нужен tcp, udp или both)", c.name, pr);
                            return err_set(e, "%s", msg);
                        }
                    }
                    else if (!strcmp(mk, "ports")) {
                        c.l4_written = 1;
                        if (port_list(j, c.name, c.l4.ports, L4_PORTS_MAX, &c.l4.ports_n, e) != 0) return -1;
                    }
                    /* «Да» — и `true`, и `1`. Спеку пишет не только человек: jshn у OpenWrt
                     * в разных сборках выдаёт логическое значение то словом, то единицей, а
                     * канал, чьё `any` не понято, объявляется «не подходящим ни к чему» и
                     * роняет всю спеку. Ошибка при этом выглядит как «сплошной канал не
                     * работает», хотя написан он верно. */
                    else if (!strcmp(mk, "any")) { js_ws(j); c.any = (*j->p == 't' || *j->p == '1'); if (js_skip(j, e) != 0) return -1; }
                    else if (!strcmp(mk, "allow_all")) { js_ws(j); c.allow_all = (*j->p == 't' || *j->p == '1'); if (js_skip(j, e) != 0) return -1; }
                    else { if (js_skip(j, e) != 0) return -1; }
                    js_ws(j);
                    if (*j->p == ',') { j->p++; js_ws(j); }
                }
                j->p++;
            }
            else { if (js_skip(j, e) != 0) return -1; }
            js_ws(j);
            if (*j->p == ',') { j->p++; js_ws(j); }
        }
        j->p++;
        if (!c.name[0]) return err_set(e, "a channel has no name", NULL);
        /* Подпись, а не идентификатор: по-русски — можно, кавычкой — нельзя (см. label_ok). */
        if (!label_ok(c.name))
            return err_set(e, "channel %s: в имени нельзя кавычку, обратную косую и управляющие символы", c.name);
        if (!c.out[0]) return err_set(e, "channel %s has no out", c.name);
        /* ПОРТЫ ИСТОЧНИКОМ СОВПАДЕНИЯ НЕ ЯВЛЯЮТСЯ, и в это условие они не входят
         * намеренно. «Канал ловит по портам» выразить нечем: правило без `ip daddr @набор`
         * безусловно, то есть udp 50000-65535 ко ВСЕМУ интернету уехало бы в туннель. Порты
         * без списка адресов — это недописанная настройка, и отказ на ней прежний. */
        if (!c.prefixes_n && !c.domains_n && !c.srs_n && !c.any)
            return err_set(e, "channel %s matches nothing (want prefixes_files, domains_files or any)", c.name);
        /* Адреса и домены в одном правиле — МОЖНО.
         *
         * Раньше запрещалось: набор один, а заполняются они по-разному — адреса читаются из
         * файла при компиляции, домены кладёт резолвер по мере запросов. Из этого следовало,
         * что человек выбирает не сервис, а ВИД СПИСКА: «YouTube (адреса)» и «YouTube
         * (домены)» приходилось заводить двумя правилами, хотя это один сервис.
         *
         * Ограничение оказалось нашим, а не ядра: набор с `flags interval,timeout` держит и
         * постоянные элементы из файла, и временные от резолвера — проверено опытом на живом
         * nft. Поэтому запрет снят, а набор такой группы объявляется с timeout. */
        if (chan_store(s, x, &c, e) != 0) return -1;
        js_ws(j);
        if (*j->p == ',') { j->p++; continue; }
        break;
    }
    if (js_lit(j, ']') != 0) return err_set(e, "channels: нет закрывающей скобки — спека оборвана?", NULL);
    return 0;
}

/* Проверка `via` (over модели) — spec_check_outputs в check.c, общая с v2: смысл и отказы там. */

/* Что из каналов понадобится проверкам после разбора всего документа (см. struct v1_ctx). Растёт
 * с числом каналов и отдаётся после разбора (spec_parse_v1); файловый static, а не локальный —
 * чтобы обёртка освободила его на любом из десятков выходов с отказом. */
static struct v1_ctx x;
static int v1_parse(const char *text, struct spec *s, struct err *e);

int spec_parse_v1(const char *text, struct spec *s, struct err *e) {
    ctx_free(&x);
    int rc = v1_parse(text, s, e);
    ctx_free(&x);
    if (rc == 0) rc = check_mark_slots(s, e);
    return rc;
}

static int v1_parse(const char *text, struct spec *s, struct err *e) {
    /* Имена правил v1 — только IPv4: на AAAA имени под доменным каналом резолвер отвечает пустым
     * ответом, как до 1.9, и в выход с IPv6 тоже (доводы — у поля, spec.h). Ставится до разбора,
     * а не после: у функции десятки выходов с отказом, а отказ v1 и так обнуляет спеку
     * (load_spec зовёт spec_defaults, прежде чем пробовать v2). */
    s->dns.names_v4 = 1;
    struct js j = { text };
    long schema = -1;
    /* Какой из двух форм записано локальное устройство. Нужно, чтобы отличить «поля нет» от
     * «поле задано» и поймать спеку, где заданы обе: молча взять одну значило бы, что
     * половина написанного человеком не действует, и понять это было бы нечем. */
    int lan_one = 0, lan_many = 0;
    if (js_lit(&j, '{') != 0) return err_set(e, "spec: expected an object", NULL);
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char key[64];
        if (js_str(&j, key, sizeof(key), e) != 0) return err_prop(e, "spec: bad key", NULL);
        /* Возврат проверяется, как в цикле match: без этого {"kind" "direct"} читался как
         * {"kind":"direct"} — не JSON, который интерфейс не разберёт, а движок молча принимал
         * (I-315). То же в циклах выходов, каналов и obfs. */
        if (js_lit(&j, ':') != 0) return err_set(e, "spec: после ключа «%s» нет двоеточия", key);
        if (!strcmp(key, "schema")) {
            long v = 0;
            if (js_num(&j, &v, e) != 0) return -1;
            schema = v;
        }
        else if (!strcmp(key, "outputs")) { if (parse_outputs(&j, s, e) != 0) return -1; }
        else if (!strcmp(key, "channels")) { if (parse_channels(&j, s, &x, e) != 0) return -1; }
        /* Клиенты по умолчанию — адресами (`lan` модели). */
        else if (!strcmp(key, "from_default")) {
            if (v1_strs64(s, &j, &s->lan.from, &s->lan.from_n, e) != 0 && e->msg[0]) return -1;
        }
        else if (!strcmp(key, "lan_device")) {
            /* Одиночная форма — сокращение для списка из одного элемента, ровно как
             * `device` у выхода. Дальше по коду путь один. */
            if (js_str(&j, s->lan_dev[0], sizeof(s->lan_dev[0]), e) != 0 && e->msg[0]) return -1;
            s->lan_dev_n = 1;
            lan_one = 1;
        }
        else if (!strcmp(key, "lan_devices")) {
            if (v1_strs64(s, &j, &s->lan_dev, &s->lan_dev_n, e) != 0)
                return err_prop(e, "lan_devices: ожидался массив строк", NULL);
            lan_many = 1;
        }
        else if (!strcmp(key, "traceroute_hops")) { js_ws(&j); s->traceroute_hops = (*j.p == 't'); if (js_skip(&j, e) != 0) return -1; }
        else { if (js_skip(&j, e) != 0) return -1; }
        js_ws(&j);
        if (*j.p == ',') { j.p++; js_ws(&j); }
    }
    /* Закрывающая скобка обязательна: без неё это файл, оборванный посреди записи (питание
     * пропало), и половина спеки применялась без единой жалобы. Комментарий выше обещает
     * громкий отказ на битой спеке; до этой правки он был только при обрыве внутри строки.
     * Текст ПОСЛЕ скобки по-прежнему не читается и не мешает: так было всегда, и на это
     * опираются стенды. */
    if (js_lit(&j, '}') != 0) return err_set(e, "spec: нет закрывающей скобки — файл оборван?", NULL);
    if (lan_one && lan_many)
        return err_set(e, "задано и lan_device, и lan_devices — оставьте одно", NULL);
    /* Пустой список — это «клиентов нет», а правило без условия «кто» забирает ВЕСЬ транзит
     * роутера, включая путь из интернета внутрь. Отказ дешевле такой находки на живом
     * роутере. */
    if (!s->lan_dev_n)
        return err_set(e, "lan_devices: пустой список — некому адресовать правила", NULL);
    for (size_t i = 0; i < s->lan_dev_n; i++) {
        /* Самая дорогая из проверок этого набора: имя уходит и в текст правил nftables, и
         * в командные строки popen у любой команды, читающей спеку. */
        if (!name_ok(s->lan_dev[i]))
            return err_set(e, "lan_devices: негодный состав имени (%s)", s->lan_dev[i]);
        for (size_t k = i + 1; k < s->lan_dev_n; k++)
            if (!strcmp(s->lan_dev[i], s->lan_dev[k]))
                return err_set(e, "lan_devices: устройство %s указано дважды", s->lan_dev[i]);
    }
    /* Клиентов по умолчанию описывают ЛИБО подсети, либо устройства. Оба сразу — не
     * обогащение, а противоречие, и молчаливого разрешения у него нет ни в одну сторону.
     *
     * Взять только подсети значило бы, что человек добавил tailscale0 и ничего не
     * изменилось: перечень интерфейсов стал бы дорогим украшением, а понять это было бы
     * нечем — отказа нет, правила есть, трафик идёт мимо. Взять и то, и другое (вторым
     * правилом по `iifname`) — хуже: `from_default` пишут, чтобы клиентов ОГРАНИЧИТЬ,
     * гостевая подсеть на том же мосту нарочно остаётся вне списка, и второе правило молча
     * забрало бы её тоже. То есть добавление интерфейса меняло бы смысл строки, написанной
     * когда-то совсем про другое.
     *
     * Отказ узкий намеренно: одно устройство рядом с `from_default` — это спека, написанная
     * до появления перечня, и она обязана значить ровно то, что значила. Отвергается только
     * НОВАЯ возможность, применённая вместе со старой. */
    if (s->lan.from_n && s->lan_dev_n > 1)
        return err_set(e, "клиенты описаны дважды: и from_default, и несколько lan_devices. "
            "Уберите from_default — устройства опишут клиентов точнее", NULL);
    /* Refusing an unknown major is the whole point of having the field: guessing
     * would mean compiling a config we do not understand into firewall rules. */
    /* ЧЕМ ОТЛИЧАЮТСЯ 1 И 2 — и почему второй версии нельзя было обойтись ключом.
     *
     * Отличие ровно одно: в схеме 2 у `match` канала есть измерение «протокол и порты»
     * (`proto`, `ports`). Всё остальное совпадает буква в букву, и спека `schema: 1`
     * применяется этой сборкой без единого изменения в поведении — включая текст
     * генерируемых правил и имена наборов nftables, от которых зависит перенос счётчиков.
     *
     * ПОЧЕМУ НЕ ХВАТИЛО НОВОГО КЛЮЧА. Неизвестный КЛЮЧ движок пропускает (js_skip выше), и
     * для всего, что совпадение РАСШИРЯЕТ, этого достаточно: старая сборка не поняла новое
     * поле — она просто не получила новой возможности, а то, что было, работает как было.
     * Порты совпадение СУЖАЮТ. Пропущенный ключ здесь означает «сузить забыли»: канал
     * Discord — это 104.16.0.0/12 (Cloudflare) плюс udp 50000-65535, и без портов он
     * забирает весь TCP к Cloudflare, то есть половину интернета, в туннель. Молча. Разница
     * между «не получил новую возможность» и «сделал не то, что написано» — это и есть
     * граница major, и она здесь пройдена.
     *
     * ПОЧЕМУ ЭТО НЕ ЛОМАЕТ РОУТЕР со старым движком. Управляющий слой (splify2, метод
     * spec_set) проверяет спеку компилятором — `apply --dry-run` — ДО записи на диск.
     * Старая сборка ответит на `schema: 2` тем же отказом кодом 2 (раньше — прямым exit
     * отсюда, теперь — через err_die у точки входа: сообщение то же), метод скажет
     * человеку «обновите движок», а на роутере останутся прежние правила. Отказ громкий и
     * заранее — ровно то, ради чего поле существует; понятая наполовину спека такого шанса
     * не даёт. */
    if (schema != 1 && schema != 2) {
        char msg[96];
        snprintf(msg, sizeof(msg), "spec schema %ld is not supported (this build speaks 1 and 2)", schema);
        return err_set(e, "%s", msg);
    }
    /* Поля схемы 2 в спеке схемы 1 — ОТКАЗ, а не молчаливое игнорирование.
     *
     * Игнорирование здесь и есть та беда, от которой заведена версия, только с другой
     * стороны: человек написал порты, увидел, что спека применилась, и считает, что сузил
     * канал. Не сузил. Отказ называет и канал, и что поднять.
     *
     * Проверяются ВСЕ каналы, включая выключенные, в отличие от проверок ниже. Исключение
     * для выключенных сделано затем, чтобы сломанное правило можно было выключить, а не
     * только удалить; здесь же чинить надо не правило, а число схемы у всей спеки, и
     * выключенный канал этому ничуть не мешает. */
    if (schema == 1)
        for (size_t i = 0; i < s->rule_n; i++)
            if (x.l4_written[i]) {
                /* Буфер с запасом: строка русская, в UTF-8 это два байта на букву, и
                 * обрезка по границе буфера разрубила бы букву посередине. */
                char msg[400];
                snprintf(msg, sizeof(msg),
                         "канал %.24s: proto и ports появились в schema 2, а в спеке "
                         "schema 1. Поднимите \"schema\": 2 — иначе ядро постарше поймёт "
                         "спеку наполовину и канал заберёт больше, чем вы написали",
                         s->rule[i].name);
                return err_set(e, "%s", msg);
            }
    /* ЗДЕСЬ БЫЛО АВТООПРЕДЕЛЕНИЕ ПОДСЕТИ. Движок читал адрес lan_device через popen и
     * выводил из него `from_default`, когда тот не задан. Нужно это было ради одной вещи:
     * без `from_default` не появлялось правило DNS-перенаправления, клиенты уходили к
     * dnsmasq напрямую, и fake-IP молча не работал — «с роутера работает, с устройств нет»
     * при синтаксически целой цепочке.
     *
     * Теперь на тот же вопрос отвечает имя устройства, и отвечает точнее. Выведенная
     * подсеть была ДОГАДКОЙ: у tailscale0 адрес на роутере /32, и догадка давала «клиент
     * один, и это сам роутер»; у клиентов за вторым роутером в LAN адреса чужой подсети, и
     * догадка их теряла. `iifname` не гадает вовсе. Заодно из загрузки спеки ушёл запуск
     * оболочки — тот самый, через который имя устройства однажды уезжало в popen.
     *
     * Явный `from_default` при этом остался и значит ровно то же, что значил: он и выбирает
     * клиентов, а устройства тогда не участвуют (см. x_from в compile/generate.c). */
    /* Пустая спека законна, и отказ на ней запирал настройку наглухо: чтобы завести
     * канал, нужен выход, а сохранить выход без каналов движок не давал — тупик, из
     * которого нельзя выйти изнутри интерфейса.
     *
     * "Выходы есть, каналов нет" — это осмысленное состояние: steer настроен, но
     * ничего не направляет. Оно же и правильное начальное: угадывать, какие списки
     * человеку нужны, хуже, чем не направлять ничего. */
    for (size_t i = 0; i < s->rule_n; i++) {
        size_t k = 0;
        for (; k < s->out_n; k++) if (!strcmp(x.out[i], s->out[k].name)) break;
        if (k == s->out_n) return err_set(e, "channel %s points at an output that does not exist", s->rule[i].name);
        s->rule[i].out = (int)k;
    }

    /* ---- защита от конфигураций, которые отрежут доступ к роутеру -----------
     *
     * Всё ниже — про ошибки, которые компилируются и применяются без единой
     * жалобы, а замечаются как «роутер пропал». Отказать на них дешевле, чем
     * потом объяснять, как чинить коробку, до которой уже не достучаться.
     * Каждая проверка отвечает на «что человек сделает случайно», а не на
     * «что запрещено стандартом». Петля в локальную сеть, устройство дважды в пуле и `via` —
     * spec_check_outputs (check.c, общая с v2). */
    if (spec_check_outputs(s, "via", NULL, e) != 0) return -1;

    /* from_default — это клиенты раздачи; сам телефон называет канал, а не умолчание для всех
     * каналов. Проверка вне цикла по каналам: from_default уходит в правило заворота DNS и
     * тогда, когда у каждого канала свой from, — и «ip saddr self» nft отверг бы синтаксической
     * ошибкой вместо слова о спеке. */
    for (size_t k = 0; k < s->lan.from_n; k++)
        if (from_is_local(s->lan.from[k]))
            return err_set(e, "from_default: «%s» — сам телефон, а не клиенты; укажите его в from канала",
                s->lan.from[k]);
    for (size_t i = 0; i < s->rule_n; i++) {
        struct spec_rule *c = &s->rule[i];
        /* Свой клиент правила (его `from` у канала v1) — изменяемый: пустые строки из него
         * выбрасываются ниже. Нет своего — «кто» по умолчанию; тогда и пустого `from` нет. */
        struct spec_client *cl = c->clients_n ? &s->client[c->clients[0]] : NULL;
        static struct spec_client none;
        struct spec_client *cf = cl ? cl : &none;
        const struct spec_list *l = rule_list(s, c);
        /* Выключенное правило не проверяем: оно не действует, а отказ применить спеку из-за
         * него означал бы, что выключить сломанное правило нельзя — только удалить. */
        if (c->disabled) continue;

        /* Пустая строка в «кому» уходила в правило как «ip saddr {  }», и nft отвергал ВСЁ
         * применение синтаксической ошибкой вместо слова о спеке (I-315).
         *
         * У своего from канала это не отказ, а предупреждение: такой from пишет сам
         * интерфейс splify2 — выбор «только эти устройства» без единого устройства хранится
         * как [""]. Пустые строки выбрасываются; если не осталось ничего, канал не
         * применяется. Отдать его «всем» (пустой from значит from_default) нельзя: человек
         * выбрал «только эти», а получил бы правило на всю сеть.
         *
         * У from_default пустая строка — отказ: её не пишет ни один наш источник, а
         * выбросить её значило бы сузить или расширить «кому» у всех каналов сразу. */
        if (cf->from_n) {
            size_t w = 0;
            for (size_t k = 0; k < cf->from_n; k++)
                if (cf->from[k][0]) memmove(cf->from[w++], cf->from[k], sizeof(cf->from[0]));
            if (w != cf->from_n) {
                cf->from_n = w;
                if (!w) {
                    fprintf(stderr, "steer[warn] канал %s: в «кому» не выбрано ни одного "
                            "устройства — канал не применяется; выберите устройства или "
                            "«все»\n", c->name);
                    c->disabled = 1;
                    continue;
                }
                fprintf(stderr, "steer[warn] канал %s: в «кому» пустая строка — пропущена\n",
                        c->name);
            }
        } else {
            for (size_t k = 0; k < s->lan.from_n; k++)
                if (!s->lan.from[k][0])
                    return err_set(e, "канал %s берёт «кому» из from_default, а в нём пустая строка — "
                        "уберите её", c->name);
        }

        /* Адреса и MAC-и в одном «кому» — нельзя. nft не умеет «или» внутри правила, и
         * смешанный список пришлось бы либо разбивать на два правила (тогда порядок и
         * приоритет расходятся с тем, что человек написал), либо взять половину молча — а
         * тогда часть устройств правило не касается, и понять это нечем. Отказываем громко. */
        /* Правило на устройство: `from` обязателен и только одиночные хозяева.
         *
         * Подсеть здесь означала бы, что приоритет получил не телефон, а половина сети, —
         * и получила бы тихо: снаружи такое правило выглядит точно так же. Пустой `from`
         * означал бы правило «на устройство», действующее на всех, то есть глобальное с
         * приоритетом глобальных — самое опасное из возможных недоразумений. */
        /* «Кто» на самом устройстве — см. from_is_local в spec.h. */
        size_t local = 0;
        for (size_t k = 0; k < cf->from_n; k++) if (from_is_local(cf->from[k])) local++;
        if (local) {
            if (!plat()->local_channels)
                return err_set(e, "канал %s: «self» и «uid:» в from — только на телефоне", c->name);
            if (local != cf->from_n)
                return err_set(e, "канал %s: в «кому» смешаны сам телефон и клиенты раздачи — это разные "
                    "пути пакета, разделите на два канала", c->name);
            for (size_t k = 0; k < cf->from_n; k++) {
                unsigned lo, hi;
                if (!strcmp(cf->from[k], "self")) {
                    if (cf->from_n > 1)
                        return err_set(e, "канал %s: «self» уже включает все приложения — уберите из "
                            "«кому» остальное", c->name);
                    continue;
                }
                static char msg[300];
                if (from_uid_range(cf->from[k], &lo, &hi) != 0) {
                    snprintf(msg, sizeof(msg), "канал %.40s: «%.40s» — не UID приложения "
                             "(want uid:N or uid:N-M)", c->name, cf->from[k]);
                    return err_set(e, "%s", msg);
                }
                if (lo == 0)
                    return err_set(e, "канал %s: uid:0 — это root, то есть само ядро steer и системные демоны; "
                        "их трафик каналом не маршрутизируется", c->name);
                /* Правило на устройство — на ОДНО приложение, диапазон тут был бы тем же
                 * «приоритет получила половина сети», что и подсеть у адресов. */
                if (c->dev_scope && lo != hi) {
                    snprintf(msg, sizeof(msg), "канал %.40s: правило на устройство принимает "
                             "одно приложение, а «%.40s» — диапазон", c->name, cf->from[k]);
                    return err_set(e, "%s", msg);
                }
            }
        }

        if (c->dev_scope && !local) {
            if (!cf->from_n)
                return err_set(e, "канал %s объявлен правилом на устройство, но в нём нет ни одного "
                    "хозяина: добавьте адрес или MAC в \"from\"", c->name);
            for (size_t k = 0; k < cf->from_n; k++)
                if (!spec_one_host(cf->from[k])) {
                    static char msg[400];
                    snprintf(msg, sizeof(msg),
                             "канал %.24s: правило на устройство принимает только одиночных "
                             "хозяев, а «%.40s» — подсеть. Приоритет достался бы не одному "
                             "устройству, а всем в ней",
                             c->name, cf->from[k]);
                    return err_set(e, "%s", msg);
                }
        }

        if (cf->from_n > 1 && !local) {
            int macs = 0;
            /* MAC — по форме MAC, а не по двоеточию: с 1.9 в «кому» бывают адреса IPv6, и
             * смесь IPv4 с IPv6 законна (правило на каждое семейство своё). */
            for (size_t k = 0; k < cf->from_n; k++) if (spec_is_mac(cf->from[k])) macs++;
            if (macs && macs != (int)cf->from_n)
                return err_set(e, "канал %s: в «кому» смешаны адреса и MAC-адреса. nft не умеет «или» внутри "
                    "правила — разделите на два канала", c->name);
        }
        /* КАНАЛ `any` БЕЗ СПИСКОВ ЗАБИРАЕТ ВЕСЬ ТРАФИК КЛИЕНТОВ — и проверять это надо
         * ДО всего, что касается выхода.
         *
         * Проверка стояла ниже, за `continue` по «у выхода нет устройства», и из-за этого не
         * срабатывала там, где последствие самое тяжёлое. У выхода kind=zapret устройства нет
         * по определению (движок его прямо запрещает), значит канал `any` на обход DPI
         * проезжал молча — и весь трафик локальной сети уходил в nfqws, а при on_fail=drop
         * умирал целиком. То же с kind=tgws и kind=direct.
         *
         * Воспроизведено на стенде в QEMU: спека с `{"any": true}` и выходом kind=zapret
         * принимается, правило выходит без `ip daddr @набор`, и счётчик растёт на ЛЮБОМ
         * трафике клиента (59 -> 97 пакетов, пока клиент ходил на два несвязанных сайта).
         *
         * Условие от выхода не зависит вовсе: «весь трафик вместо списка» — это свойство
         * КАНАЛА, и место ему здесь, до поиска выхода. У правила на устройство согласия
         * по-прежнему не требуется: запрет заведён против «все клиенты без интернета и
         * починка с провода», а у правила на одно устройство цена ошибки — один хозяин, и он
         * же её заметит. Ровно эта пара («весь трафик телефона в туннель» и «этот ноутбук не
         * маршрутизируем») и просилась. */
        if (l->all && !x.allow_all[i] && !c->dev_scope)
            return err_set(e, "канал %s забирает ВЕСЬ трафик в туннель. Если это правда нужно, "
                "добавьте \"allow_all\": true — иначе выберите список", c->name);

        struct output *o = &s->out[c->out];
        /* Выход, который работает только для клиентов раздачи (мост Telegram перехватывает
         * соединения только в prerouting): канал «приложение → такой выход» стоял бы
         * применённым, не делая ничего. Почему — говорит вид (kind_ops.lan_only). */
        if (local && o && kind_of(o)->lan_only) {
            static char msg[300];
            snprintf(msg, sizeof(msg), "канал %s: выход kind=%s работает только для клиентов раздачи — %s",
                     c->name, out_kind_name(o), kind_of(o)->lan_only);
            return err_set(e, "%s", msg);
        }
    }
    return 0;
}

