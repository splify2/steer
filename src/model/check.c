/* Сквозные проверки спеки, общие для v1 и v2 (check.h).
 *
 * Всё здесь переехало из model/v1.c без изменения смысла и текстов: разбор v2 (model/v2.c)
 * обязан отказывать на тех же конфигурациях, что и v1, и держать две копии проверки подложки —
 * самой хитрой из них — значило бы однажды получить две разные. Слово для подложки («via» в v1,
 * «over» в v2) приходит параметром; с «via» тексты совпадают с прежними байт в байт (снимок
 * генератора tests/snapshot.sh). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "spec.h"
#include "obfs.h"
#include "check.h"

/* ---- порты ---------------------------------------------------------------------------------
 *
 * ТИРЕ, А НЕ ДВОЕТОЧИЕ, хотя в `.srs` у sing-box записано `port_range 50000:65535`. Тире — это
 * форма, которой у нас уже пишется диапазон АДРЕСОВ в списках (`10.0.9.0-10.0.9.5`), и два
 * синтаксиса диапазона в одной настройке — это вопрос «а тут как?» на каждом поле. Чужую форму
 * переводит тот, кто читает чужой файл, а не спека.
 *
 * Разбор свой, а не strtol по месту: strtol на не-числе НЕ ПРОДВИГАЕТ указатель и возвращает
 * нуль, то есть «abc» без явной проверки прошло бы как порт 0. Проверяется поэтому КАЖДЫЙ
 * символ, и хвост тоже: «1-2-3» это описка, а не «1-2 и ещё что-то». */
static int port_num(const char **pp, long *out) {
    const char *p = *pp;
    if (*p < '0' || *p > '9') return -1;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
        v = v * 10 + (*p++ - '0');
        if (v > 65535) return -1;           /* обрываем до переполнения, а не после */
    }
    if (v < 1) return -1;                   /* порт 0 не адресуем ничем */
    *pp = p;
    *out = v;
    return 0;
}

int port_range_parse(const char *s, struct port_range *r) {
    long lo = 0, hi = 0;
    const char *p = s;
    if (port_num(&p, &lo) != 0) return -1;
    hi = lo;                                /* одиночный порт — диапазон из одного */
    if (*p == '-') {
        p++;
        if (port_num(&p, &hi) != 0) return -1;
    }
    if (*p) return -1;                      /* хвост: «1-2-3», «443 », «443/tcp» */
    if (lo > hi) return -1;                 /* «9-1» — почти наверняка перепутанные концы */
    r->lo = (unsigned short)lo;
    r->hi = (unsigned short)hi;
    return 0;
}

/* ---- обфускация ----------------------------------------------------------------------------
 *
 * `listen` обязателен и должен совпадать с `Endpoint` пира в /etc/config/network: это
 * единственное место, где две настройки обязаны знать друг о друге, и вывести одну из другой
 * движок не может — ключи и пиры не его. Несовпадение молчаливо: WireGuard шлёт в никуда, туннель
 * не поднимается, и причина не видна ниоткуда, кроме tcpdump. */
int obfs_set(const char *name, const char *mode, const char *server, const char *listen,
             struct out_obfs *ob, struct err *e) {
    /* Отсутствующий mode — это сегодняшний единственный режим: спека, написанная до появления
     * второго, обязана значить то же, что значила. Неизвестный — отказ, а не молчаливое
     * «наверное, тот самый»: обфускация, которой нет, выглядит как рабочий выход, из которого
     * не выходит ни один пакет. */
    if (mode[0] && strcmp(mode, "wg-over-tcp") != 0)
        return err_set(e, "outputs.%s: неизвестный obfs.mode (сейчас есть только wg-over-tcp)", name);
    if (!server[0]) return err_set(e, "outputs.%s: obfs нужен server вида адрес:порт", name);
    if (obfs_split_hostport(server, ob->server, sizeof(ob->server), &ob->server_port) != 0)
        return err_set(e, "outputs.%s: obfs.server должен быть вида адрес:порт", name);
    /* Имя, а не адрес — отказ. Имя пришлось бы разрешать, и разрешать его через тот самый DNS,
     * который может идти в туннель, который поднимается через этот самый сервер. Управляющий
     * слой резолвит один раз и кладёт сюда адрес — то же правило, что со списками: движок
     * читает то, что ему положили. */
    struct in_addr tmp;
    if (inet_pton(AF_INET, ob->server, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.server должен быть адресом, а не именем", name);

    if (!listen[0]) return err_set(e, "outputs.%s: obfs нужен listen — тот же адрес и порт, что в "
                        "Endpoint пира WireGuard", name);
    if (obfs_split_hostport(listen, ob->listen, sizeof(ob->listen), &ob->listen_port) != 0)
        return err_set(e, "outputs.%s: obfs.listen должен быть вида адрес:порт", name);
    if (inet_pton(AF_INET, ob->listen, &tmp) != 1)
        return err_set(e, "outputs.%s: obfs.listen должен быть адресом, а не именем", name);
    ob->on = 1;
    return 0;
}

/* ---- подложка: `over` (v1: `via`) ---------------------------------------------------------
 *
 * Смысл поля — в блоке «подложка» в spec.h. Здесь — то, что обязано быть отказом, а не
 * применённой спекой, и у каждого отказа своя причина:
 *
 *   - подложка у выхода без своего соединения с сервером (direct, zapret, tgws, обычный
 *     interface, группа) ничего бы не сделала: метку ставит тот, кто открывает сокет (или, у
 *     awg, настраивает устройство), а у этих видов его открывает не движок. Принять поле молча —
 *     сказать «настроено», не настроив;
 *   - цели нет в спеке или она без устройства — метке некуда вести, и туннель тихо ушёл бы
 *     напрямую (правила на метку нет — пакет идёт по main);
 *   - круг (a → b → a, в том числе a → a) — пакет туннеля вечно заворачивался бы сам в себя:
 *     соединение a идёт в устройство b, соединение b — в устройство a, и не встаёт ни одно;
 *   - круг ЧЕРЕЗ ПУЛ: цель — группа, среди устройств членов которой устройство самого выхода или
 *     выхода, который сам зависит от него. Снаружи в спеке круга не видно — он проходит через имя
 *     устройства, — а по сути это тот же круг, только проявится он лишь в тот момент, когда
 *     сторож переключит группу на это устройство;
 *   - цепочка длиннее MAX_OVER_DEPTH переходов — скорее описка, чем замысел (см. spec.h).
 *
 * Проверяется ПОСЛЕ разбора всех выходов: цель может стоять ниже того, кто на неё ссылается. */
static int via_idx(const struct spec *sp, const struct output *o) { return (int)(o - sp->out); }

/* Устройства, в которые может уйти трафик выхода: у группы — устройства её членов, у выхода с
 * устройством — его собственное (out_members). */
/* Устройства выхода: у группы — листья всех членов, вниз по вложенным группам (любое из них может
 * оказаться выбранным); список растёт по числу устройств (раньше — 64 записи, а сверх них листья
 * просто не проверялись, то есть проверка молча слепла на большом пуле). Вложенность ограничена
 * числом выходов: группы без кругов вкладываются не глубже, чем их всего. leaves = 0 — только
 * члены без групп: так смотрит проверка дубликатов, где вложенная группа с общими листьями
 * законна (bal из res и wg1, а рядом запасной wg0). */
struct devlist { const char **v; size_t n, cap; };
static int devs_of(const struct spec *sp, const struct output *o, struct devlist *d, int leaves,
                   size_t depth) {
    size_t mn = out_members_n(sp, o);
    for (size_t i = 0; i < mn; i++) {
        const struct output *m = out_member(sp, o, i);
        if (m != o && out_group(m)) {
            if (leaves && depth < sp->out_n && devs_of(sp, m, d, leaves, depth + 1) != 0) return -1;
            continue;
        }
        if (d->n == d->cap) {
            size_t nc = d->cap ? d->cap * 2 : 16;
            const char **nv = realloc(d->v, nc * sizeof(*nv));
            if (!nv) return -1;
            d->v = nv;
            d->cap = nc;
        }
        d->v[d->n++] = m->device;
    }
    return 0;
}
static int via_devs(const struct spec *sp, const struct output *o, struct devlist *d) {
    d->n = 0;
    return devs_of(sp, o, d, 1, 0);
}

/* Выход, которому принадлежит устройство пула, — тот же ответ, что device_owner в failover.c
 * (владелец — выход, чей процесс устройство создаёт). Своя копия, а не вызов: specmatch
 * собирает модель без failover.c. Отвечает она на узкий вопрос этой проверки и расходиться с той
 * функцией ей негде — обе смотрят на out_engine_managed и имя устройства. */
static const struct output *via_dev_owner(const struct spec *sp, const char *dev,
                                          const struct output *not) {
    for (size_t i = 0; i < sp->out_n; i++)
        if (&sp->out[i] != not && out_engine_managed(&sp->out[i]) && !strcmp(sp->out[i].device, dev))
            return &sp->out[i];
    return NULL;
}

/* Рабочие массивы обхода подложек: по числу выходов спеки, а не на предельное число. */
struct over_ws { int *on_path, *seen, *stack; struct devlist td, od; };

static int over_check_run(const struct spec *sp, const char *w, int *bad, struct err *e,
                          struct over_ws *ws) {
    static char msg[512];
    int *on_path = ws->on_path, *seen = ws->seen, *stack = ws->stack;
#define td (ws->td)                 /* списки устройств живут в ws: realloc виден обёртке */
#define od (ws->od)
    int rc = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!o->over[0]) continue;
        if (bad) *bad = (int)i;
        if (!out_over_capable(o)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: %s есть только у выходов со своим соединением с сервером — "
                     "vless, xsteer, awg и interface с obfs; у kind=%s соединение открывает не ядро steer, "
                     "и пустить его через другой выход нечем", o->name, w,
                     out_kind_shown(o)->novia ? out_kind_shown(o)->novia : out_kind_name(o));
            return err_set(e, "%s", msg);
        }
        if (!strcmp(o->over, o->name)) {
            snprintf(msg, sizeof(msg), "выход %s: %s указывает на него самого — туннель не может "
                     "идти внутри себя", o->name, w);
            return err_set(e, "%s", msg);
        }
        const struct output *v = out_over(sp, o);
        if (!v) {
            snprintf(msg, sizeof(msg), "выход %.31s: %s «%.31s» — такого выхода в спеке нет",
                     o->name, w, o->over);
            return err_set(e, "%s", msg);
        }
        if (!out_over_target_ok(v)) {
            snprintf(msg, sizeof(msg),
                     "выход %.31s: %s «%.31s» — это kind=%s, у него нет устройства, в которое "
                     "можно пустить туннель (нужен выход с устройством: interface, vless, xsteer, awg)",
                     o->name, w, v->name, out_kind_name(v));
            return err_set(e, "%s", msg);
        }

        /* Цепочка по одним подложкам: круг и глубина. Путь печатается целиком — по одному имени
         * человек круга не найдёт, если в спеке шестнадцать выходов. */
        char path[256];
        memset(on_path, 0, sp->out_n * sizeof(int));
        size_t pl = (size_t)snprintf(path, sizeof(path), "%s", o->name);
        on_path[via_idx(sp, o)] = 1;
        int hops = 0;
        for (const struct output *t = o, *n; (n = out_over(sp, t)); t = n) {
            hops++;
            if (pl < sizeof(path))
                pl += (size_t)snprintf(path + pl, sizeof(path) - pl, " → %s", n->name);
            if (on_path[via_idx(sp, n)]) {
                snprintf(msg, sizeof(msg), "выход %.31s: %s замыкается в круг (%s) — туннели "
                         "заворачивались бы друг в друга, и не встал бы ни один", o->name, w, path);
                return err_set(e, "%s", msg);
            }
            on_path[via_idx(sp, n)] = 1;
            if (hops > MAX_OVER_DEPTH) {
                snprintf(msg, sizeof(msg), "выход %.31s: цепочка %s длиннее %d переходов (%s)",
                         o->name, w, MAX_OVER_DEPTH, path);
                return err_set(e, "%s", msg);
            }
        }

        /* Круг через пул: обход всего, во что может уйти трафик туннеля o, — целей подложки и
         * владельцев устройств в пулах целей. Встретить устройство самого o или сам o — круг. */
        /* seen ставится при постановке в стек, а не при выемке: каждый выход попадает в стек не
         * больше раза, и стек длиной в число выходов не переполняется никаким пулом. */
        memset(seen, 0, sp->out_n * sizeof(int));
        int top = 0;
        stack[top++] = via_idx(sp, v);
        seen[via_idx(sp, v)] = 1;
        while (top) {
            const struct output *t = &sp->out[stack[--top]];
            if (t == o) {
                snprintf(msg, sizeof(msg), "выход %.31s: %s замыкается в круг через устройства "
                         "пула — туннель однажды пошёл бы внутрь себя", o->name, w);
                rc = err_set(e, "%s", msg);
                goto out;
            }
            if (via_devs(sp, t, &td) != 0 || via_devs(sp, o, &od) != 0) {
                rc = err_set(e, "%s", "недостаточно памяти для проверки спеки");
                goto out;
            }
            for (size_t d = 0; d < td.n; d++) {
                for (size_t k = 0; k < od.n; k++)
                    if (!strcmp(td.v[d], od.v[k])) {
                        snprintf(msg, sizeof(msg), "выход %.31s: %s ведёт в %.31s, а среди его "
                                 "устройств %.31s — устройство самого выхода, туннель пошёл бы "
                                 "внутрь себя", o->name, w, t->name, td.v[d]);
                        rc = err_set(e, "%s", msg);
                        goto out;
                    }
                const struct output *wo = via_dev_owner(sp, td.v[d], t);
                if (wo && !seen[via_idx(sp, wo)]) { seen[via_idx(sp, wo)] = 1; stack[top++] = via_idx(sp, wo); }
            }
            const struct output *n = out_over(sp, t);
            if (n && !seen[via_idx(sp, n)]) { seen[via_idx(sp, n)] = 1; stack[top++] = via_idx(sp, n); }
        }
    }
out:
    return rc;
#undef td
#undef od
}

static int over_check(const struct spec *sp, const char *w, int *bad, struct err *e) {
    /* У спеки без `over` (почти всех) ничего не выделяется. */
    size_t any = 0;
    for (size_t i = 0; i < sp->out_n; i++) any += sp->out[i].over[0] != 0;
    if (!any) return 0;
    struct over_ws ws = { calloc(sp->out_n, sizeof(int)), calloc(sp->out_n, sizeof(int)),
                          malloc(sp->out_n * sizeof(int)), {0}, {0} };
    int rc;
    if (!ws.on_path || !ws.seen || !ws.stack)
        rc = err_set(e, "%s", "недостаточно памяти для проверки спеки");
    else
        rc = over_check_run(sp, w, bad, e, &ws);
    free(ws.on_path);
    free(ws.seen);
    free(ws.stack);
    free(ws.td.v);
    free(ws.od.v);
    return rc;
}

/* ---- защита от конфигураций, которые отрежут доступ к роутеру ------------------------------
 *
 * Всё ниже — про ошибки, которые компилируются и применяются без единой жалобы, а замечаются
 * как «роутер пропал». Отказать на них дешевле, чем потом объяснять, как чинить коробку, до
 * которой уже не достучаться. */
int spec_check_outputs(const struct spec *sp, const char *over_word, int *bad, struct err *e) {
    struct devlist dv = {0};
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if (!out_has_device(o)) continue;
        if (bad) *bad = (int)i;

        /* Выход в локальное устройство — это петля: помеченный пакет получает маршрут обратно в
         * ту же сеть, откуда пришёл. Проверяется ВЕСЬ список: выход в tailscale0, с которого мы
         * забираем клиентов, закольцуется ровно так же, как выход в br-lan. */
        for (size_t d = 0; d < sp->lan_dev_n; d++)
            if (!strcmp(o->device, sp->lan_dev[d])) {
                /* 256, не 160: через указатель на struct spec gcc считает границы имени и
                 * устройства не так точно, и -Wformat-truncation видит в этом риск. */
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "выход %s ведёт в %s — это локальная сеть, трафик закольцуется",
                         o->name, sp->lan_dev[d]);
                free(dv.v);
                return err_set(e, "%s", msg);
            }

        /* Дубликат устройства внутри одного пула делает failover бессмысленным: второй
         * кандидат ничем не отличается от первого. */
        dv.n = 0;
        if (devs_of(sp, o, &dv, 0, 0) != 0) {
            free(dv.v);
            return err_set(e, "%s", "недостаточно памяти для проверки спеки");
        }
        for (size_t a = 0; a < dv.n; a++)
            for (size_t b = a + 1; b < dv.n; b++)
                if (!strcmp(dv.v[a], dv.v[b])) {
                    char msg[160];
                    snprintf(msg, sizeof(msg), "выход %s: устройство %s указано дважды",
                             o->name, dv.v[a]);
                    free(dv.v);
                    return err_set(e, "%s", msg);
                }
    }
    free(dv.v);
    return over_check(sp, over_word, bad, e);
}

int check_mark_slots(const struct spec *sp, struct err *e) {
    size_t n = 0;
    for (size_t i = 0; i < sp->out_n; i++)
        if (out_needs_mark(&sp->out[i])) n++;
    unsigned slots = steer_mark_slots();
    if (n <= slots) return 0;
    /* Цифры раскладки, а не имя константы: столько мест даёт поле метки, вот какие это биты, и
     * вот почему больше нельзя (marks.h, «СКОЛЬКО ВЫХОДОВ ВЛЕЗАЕТ В ПОЛЕ МЕТКИ»). */
    char msg[600];
    snprintf(msg, sizeof(msg), "выходов с меткой %zu, а поле метки даёт мест не больше %u: у метки "
             "%d бит (биты %d-%d), значения, которые чужая перезапись соседних битов 16-23 могла бы "
             "превратить в метку другого выхода, не раздаются. Выходы без метки (direct) в счёт не "
             "идут", n, slots, (int)STEER_MARK_BITS,
             STEER_MARK_LOBIT, STEER_MARK_HIBIT);
    return err_set(e, "%s", msg);
}
