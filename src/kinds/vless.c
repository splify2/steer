/* kind=vless — туннель VLESS по подписке, устройство которого создаёт наш процесс
 * (`steer vless <выход>`, src/proto/vless/vlmain.c; стек — src/tunnel/stack.c).
 *
 * vless — это тоже устройство: клиент поднимает TUN, и дальше всё остальное (метки,
 * таблицы, failover, каналы) работает с ним ровно как с wireguard. Отдельный вид нужен
 * только потому, что устройство надо СОЗДАТЬ и обслуживать процессом, тогда как
 * wireguard уже есть в системе к моменту apply.
 *
 * Вид только расширенной сборки: файла нет в профиле base (build/sources.mk), и там реестр
 * отвечает на него отказом «требует пакет steer-extended» (kind.c). Отказываем СРАЗУ, а не при
 * подъёме: иначе спека применяется, правила встают, и выход молча никуда не ведёт — то есть
 * человек видит рабочую конфигурацию, в которой трафик пропадает. */
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include "spec.h"
#include "tunpool.h"

const struct vless_cfg *out_vless(const struct output *o) {
    return kind_of(o) == &kind_vless ? &o->vless : NULL;
}

static int vless_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->vless.sub_file, sizeof(o->vless.sub_file), "%s", k->sub_file);
    /* Массив номеров узлов лежит в арене спеки (его завёл читатель формата ровно на nodes_n): выход
     * берёт его по указателю, копировать нечего. Число узлов в выборе константой не ограничено. */
    o->vless.nodes = k->nodes;
    o->vless.nodes_n = k->nodes_n;
    o->vless.transports = k->transports;
    o->vless.insecure = k->insecure;
    o->vless.excl = k->excl;            /* массивы — в арене спеки, как nodes */
    o->vless.pool = k->pool;
    if (tun_pool_check(o, k, e) != 0) return -1;
    if (!o->vless.sub_file[0]) {
        char msg[160];
        snprintf(msg, sizeof(msg), "outputs.%s: kind vless нужен %s с подпиской", o->name,
                 out_key(k, "sub_file", "subscription"));
        return err_set(e, "%s", msg);
    }
    /* Имя устройства выводится из имени выхода: держать его отдельным полем
     * значило бы дать двум именам расходиться, а никакой пользы от их различия
     * нет. Ограничение в 15 символов — предел IFNAMSIZ. */
    if (!o->device[0]) snprintf(o->device, sizeof(o->device), "%.15s", o->name);
    /* Устройство у выхода ОДНО — его создаёт клиент этого выхода, как у awg. Пул из нескольких
     * туннелей — это группа (`devices` у kind=interface); список здесь означал бы устройства,
     * которые никто не создаст. */
    if (k->devices_n > 1 || (k->devices_n == 1 && strcmp(o->device, k->devices[0]) != 0))
        return err_set(e, "outputs.%s: у kind vless одно устройство — его заводит ядро steer; пул "
            "собирается выходом kind=interface", o->name);
    return 0;
}

/* Обратное vless_parse (`steer spec convert`): подписка и узлы; устройство — если не выведено
 * из имени. */
static void vless_keys_of(const struct output *o, struct out_keys *k) {
    snprintf(k->sub_file, sizeof(k->sub_file), "%s", o->vless.sub_file);
    k->nodes = o->vless.nodes;
    k->nodes_n = o->vless.nodes_n;
    k->transports = o->vless.transports;
    k->insecure = o->vless.insecure;
    k->excl = o->vless.excl;
    k->pool = o->vless.pool;
    char dev[32];
    snprintf(dev, sizeof(dev), "%.15s", o->name);
    k->device_derived = !strcmp(dev, o->device);
}

/* Выбранные узлы подписки — то же, что пул устройств: список кандидатов выхода, только у vless
 * кандидаты называются номерами узлов.
 * Печатается ВСЕГДА, в том числе пустым, и это главное здесь: незнакомый ключ
 * спеки движок пропускает молча (js_skip), поэтому интерфейс, записавший `nodes`
 * в старый движок, получил бы применённую спеку и трафик через узел, которого не
 * выбирал. Наличие поля в status — единственный способ узнать движок, который
 * `nodes` понимает, до того как их писать. Тем же приёмом узнаётся движок с
 * lan_devices. */
static void vless_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    fprintf(out, ",\"nodes\":[");
    for (size_t d = 0; d < o->vless.nodes_n; d++)
        fprintf(out, "%s%d", d ? "," : "", o->vless.nodes[d]);
    fprintf(out, "]");
    /* Проверка сертификата выключена явно — видно в status, пока ключ включён. Печатается только
     * тогда: вывод выходов без ключа остаётся прежним. */
    if (o->vless.insecure) fprintf(out, ",\"insecure\":true");
    /* Активные узлы пула (src/tunnel/pool.c) — пока клиент жив: номера, имена, сколько просили. */
    char *st = tun_state_load("vless", o->name);
    if (st) fprintf(out, ",\"vless\":%s", st);
    free(st);
}

/* `insecure` выхода: проверка сертификата узлов TLS выключена по решению человека. warn, а не fail:
 * туннель работает, но подмену сервера на пути никто не заметит — об этом надо напоминать, пока
 * ключ включён. */
static void vless_diag(kind_diag_fn *put, const struct spec *sp, const struct output *o) {
    (void)sp;
    tun_pool_diag(put, "vless", o, &o->vless.pool);
    if (!o->vless.insecure) return;
    char what[160];
    snprintf(what, sizeof(what), "выход %.40s: сертификат узла не проверяется", o->name);
    put("insecure", "warn", what,
        "у выхода стоит insecure: цепочку, имя и срок сертификата узла (security=tls) никто не "
        "сверяет — уберите ключ или закрепите сертификат (pcs в ссылке узла)");
}

/* Помощник — клиент туннеля. В подпись — файл подписки, его СОДЕРЖИМОЕ и выбор узлов (helper_sig,
 * daemon/helpers.c). Содержимое — потому что клиент читает узлы один раз, при старте: обновлённая
 * подписка без перезапуска не заработала бы. До демона это делал управляющий слой сигналом
 * экземпляру procd (vless_<выход>); у демона такого экземпляра нет, и сверка по подписи — apply,
 * reload, SIGHUP — перезапускает клиент ровно того выхода, чья подписка изменилась. */
static int vless_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    snprintf(h->cmd, sizeof(h->cmd), "vless");
    /* Счётчики туннеля — по файлу-выключателю, как у init.d/steer (procd_set_param env). */
    char st[256];
    if (access(plat_etc_path(st, sizeof(st), "stats"), F_OK) == 0)
        snprintf(h->env, sizeof(h->env), "STEER_TUN_STATS=1");
    kind_sig_mix(&h->sig, o->vless.sub_file, strlen(o->vless.sub_file));
    FILE *f = fopen(o->vless.sub_file, "r");
    if (f) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(&h->sig, buf, n);
        fclose(f);
    }
    for (size_t i = 0; i < o->vless.nodes_n; i++)
        kind_sig_mix(&h->sig, &o->vless.nodes[i], sizeof(o->vless.nodes[i]));
    /* И выбор транспортов — по той же причине, что номера узлов: клиент читает его при старте. */
    if (o->vless.transports)
        kind_sig_mix(&h->sig, &o->vless.transports, sizeof(o->vless.transports));
    /* И insecure: клиент читает его при старте, смена без перезапуска не вступила бы в силу. */
    if (o->vless.insecure) kind_sig_mix(&h->sig, "insecure", 8);
    /* И исключение узлов: клиент отбирает кандидатов при старте. */
    kind_sig_excl(&h->sig, &o->vless.excl);
    /* И пул узлов: active, by, interval, silence клиент тоже читает при старте. */
    if (o->vless.pool.active || o->vless.pool.by || o->vless.pool.interval_s || o->vless.pool.silence_s ||
        o->vless.pool.pick || o->vless.pool.tol_set)
        kind_sig_mix(&h->sig, &o->vless.pool, sizeof(o->vless.pool));
    return 0;
}

/* Порядок перебора узлов подписки. Объяснение — у объявления в kind.h. */
size_t out_node_list(const struct output *o, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!o->vless.nodes_n) {
        /* Кандидатов не выбирали — кандидаты все, в порядке подписки. Это прежнее
         * поведение `node: -1` и умолчание, которое рекомендует интерфейс: номер узла
         * меняется при обновлении подписки, а проверка находит живой сама. */
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < o->vless.nodes_n && n < max; i++)
        if (o->vless.nodes[i] >= 0 && (size_t)o->vless.nodes[i] < usable) dst[n++] = o->vless.nodes[i];
    return n;
}

/* Назван ли узел человеком. Объяснение — у объявления в kind.h. */
int out_node_named(const struct output *o) {
    return o->vless.nodes_n == 1;
}

const struct kind_ops kind_vless = {
    .name = "vless",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_SELF_NAT | KC_OVER |
            KC_SKIP_ZAPRET | KC_TCP_PROBE | KC_FLOW_UDP | KC_TCP_REDIR | KC_IPV6,
    .keys = KK_NODES | KK_SUB,
    /* Сюда попадает выход без masquerade, которому он и не нужен, — для него это норма
     * (см. out_self_natting и проверку «output» в diag.c). */
    .selfnat_why = "masquerade не нужен: туннель завершает TCP сам, адреса клиентов "
                   "наружу не уходят",
    .parse = vless_parse,
    .keys_of = vless_keys_of,
    .status = vless_status,
    .diag = vless_diag,
    .helper = vless_helper,
};
