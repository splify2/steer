/* kind=tunnel, protocol=hysteria2 — туннель hysteria2 по подписке, устройство которого создаёт наш
 * процесс (`steer hysteria2 <выход>`, src/proto/hysteria2; стек — src/tunnel/stack.c).
 *
 * По устройству это тот же вид, что vless: клиент поднимает TUN, и всё остальное (метки, таблицы,
 * failover, каналы) работает с ним как с любым туннелем. Спека v2 пишет его `kind: tunnel,
 * protocol: hysteria2`; внутри движка вид называется hysteria2, как vless.
 *
 * Вид ТОЛЬКО ОТДЕЛЬНОГО ПАКЕТА steer-hysteria2 (kind.c: модуль ведёт реестр): meta-пакета
 * steer-extended в нём нет. Нет модуля — отказ при разборе спеки, а не молчаливый выход, который
 * ни к чему не ведёт (тот же довод, что у vless.c).
 *
 * Что здесь своё, по сравнению с vless: нет `transport` (hysteria2 — QUIC целиком, выбирать между
 * tcp и ws нечем), а в status лежит состояние соединения, которое пишет сам клиент в файл
 * состояния: узел, рукопожатие, перегрузка, обфускация. */
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"

const struct hy2_cfg *out_hysteria2(const struct output *o) {
    return kind_of(o) == &kind_hysteria2 ? &o->hy2 : NULL;
}

static int hy2_parse(struct output *o, const struct out_keys *k, struct err *e) {
    snprintf(o->hy2.sub_file, sizeof(o->hy2.sub_file), "%s", k->sub_file);
    /* Массив номеров узлов лежит в арене спеки (его завёл читатель формата ровно на nodes_n) —
     * тот же порядок владения, что у kind vless. */
    o->hy2.nodes = k->nodes;
    o->hy2.nodes_n = k->nodes_n;
    o->hy2.excl = k->excl;
    o->hy2.pool = k->pool;
    /* Несколько узлов сразу — нет: соединение с узлом у hysteria2 одно QUIC на все потоки
     * (hy2conn.c), и узел соединения выбрать нечем. interval и silence — есть. */
    if (k->pool.pick) {
        char msg[320];
        snprintf(msg, sizeof(msg), "outputs.%s: у kind hysteria2 пока нет pick: latency — узел у него "
                 "один, замер кандидатов и смена узла на ходу есть у vless и протоколов прокси", o->name);
        return err_set(e, "%s", msg);
    }
    if (k->pool.active > 1 || k->by_set) {
        char msg[320];
        snprintf(msg, sizeof(msg), "outputs.%s: у kind hysteria2 нет %s — соединение с узлом одно на "
                 "все потоки (QUIC), несколько узлов сразу есть у vless и протоколов прокси", o->name,
                 k->by_set ? "by" : "active больше 1");
        return err_set(e, "%s", msg);
    }
    if (!o->hy2.sub_file[0]) {
        char msg[160];
        snprintf(msg, sizeof(msg), "outputs.%s: kind hysteria2 нужен %s с подпиской", o->name,
                 out_key(k, "sub_file", "subscription"));
        return err_set(e, "%s", msg);
    }
    /* transport — выбор транспорта узла VLESS; у hysteria2 транспорта нет. Промолчать значило бы
     * принять слово, которое ничего не делает, и оставить человека с уверенностью, что фильтр
     * работает. */
    if (k->transports)
        return err_set(e, "outputs.%s: у kind hysteria2 нет transport — это QUIC целиком", o->name);
    /* insecure у hysteria2 — параметр ссылки узла (`insecure=1`), а не ключ выхода: промолчать
     * значило бы принять ключ, который ничего не делает. */
    if (k->insecure)
        return err_set(e, "outputs.%s: у kind hysteria2 нет insecure — он задаётся в ссылке узла", o->name);
    /* Имя устройства выводится из имени выхода, как у vless, и по тому же доводу: два имени
     * расходились бы, а пользы от различия нет. */
    if (!o->device[0]) snprintf(o->device, sizeof(o->device), "%.15s", o->name);
    if (k->devices_n > 1 || (k->devices_n == 1 && strcmp(o->device, k->devices[0]) != 0))
        return err_set(e, "outputs.%s: у kind hysteria2 одно устройство — его заводит ядро steer; пул "
            "собирается выходом kind=interface", o->name);
    return 0;
}

static void hy2_keys_of(const struct output *o, struct out_keys *k) {
    snprintf(k->sub_file, sizeof(k->sub_file), "%s", o->hy2.sub_file);
    k->nodes = o->hy2.nodes;
    k->nodes_n = o->hy2.nodes_n;
    k->excl = o->hy2.excl;
    k->pool = o->hy2.pool;
    char dev[32];
    snprintf(dev, sizeof(dev), "%.15s", o->name);
    k->device_derived = !strcmp(dev, o->device);
}

/* Файл состояния клиента: JSON-объект одной строкой, пишет процесс модуля (hy2main.c). Читает
 * status и diag. Файл верен, пока жив процесс из поля pid: kill -9 не оставляет времени убрать за
 * собой, а «соединение поднято» от мёртвого процесса хуже, чем никакого ответа. */
static int state_read(const char *out_name, char *buf, size_t n) {
    char path[256];
    snprintf(path, sizeof(path), "%s/hy2-%.32s", steer_state_dir(), out_name);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    size_t r = fread(buf, 1, n - 1, f);
    fclose(f);
    buf[r] = '\0';
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
    if (buf[0] != '{') return -1;
    const char *p = strstr(buf, "\"pid\":");
    if (!p) return -1;
    long pid = 0;
    if (sscanf(p + 6, "%ld", &pid) != 1 || pid <= 0 || kill((pid_t)pid, 0) != 0) return -1;
    return 0;
}

/* Печатается ВСЕГДА `nodes`, в том числе пустым — по той же причине, что у vless (движок, который
 * ключ понимает, узнаётся по наличию поля). Состояние клиента — когда он жив. */
static void hy2_status(FILE *out, const struct spec *sp, const struct output *o) {
    (void)sp;
    fprintf(out, ",\"nodes\":[");
    for (size_t d = 0; d < o->hy2.nodes_n; d++)
        fprintf(out, "%s%d", d ? "," : "", o->hy2.nodes[d]);
    fprintf(out, "]");
    char buf[1024];
    if (state_read(o->name, buf, sizeof(buf)) == 0) fprintf(out, ",\"hysteria2\":%s", buf);
}

static void hy2_diag(kind_diag_fn *put, const struct spec *sp, const struct output *o) {
    (void)sp;
    char buf[1024], what[200];
    if (state_read(o->name, buf, sizeof(buf)) != 0) {
        snprintf(what, sizeof(what), "выход %.40s: клиент hysteria2 не запущен", o->name);
        put("hysteria2", "fail", what, "перезапустите ядро steer: /etc/init.d/steer restart");
        return;
    }
    int up = strstr(buf, "\"up\":true") != NULL;
    snprintf(what, sizeof(what), "выход %.40s: соединение с узлом hysteria2 %s", o->name,
             up ? "поднято" : "не поднято");
    put("hysteria2", up ? "ok" : "fail", what,
        up ? "" : "узел не принял соединение или авторизацию: `steer hysteria2-probe` называет причину");
}

/* Помощник — клиент туннеля. В подпись — файл подписки, его СОДЕРЖИМОЕ и выбор узлов: клиент
 * читает узлы при старте, и обновлённая подписка без перезапуска не заработала бы (см. vless.c). */
static int hy2_helper(const struct spec *sp, const struct output *o, struct kind_helper *h) {
    (void)sp;
    if (kind_helper_cmd(h, "hysteria2") != 0) return -1;
    kind_sig_mix(&h->sig, o->hy2.sub_file, strlen(o->hy2.sub_file));
    FILE *f = fopen(o->hy2.sub_file, "r");
    if (f) {
        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), f)) > 0) kind_sig_mix(&h->sig, buf, n);
        fclose(f);
    }
    for (size_t i = 0; i < o->hy2.nodes_n; i++)
        kind_sig_mix(&h->sig, &o->hy2.nodes[i], sizeof(o->hy2.nodes[i]));
    kind_sig_excl(&h->sig, &o->hy2.excl);
    /* interval и silence клиент читает при старте. */
    if (o->hy2.pool.interval_s || o->hy2.pool.silence_s)
        kind_sig_mix(&h->sig, &o->hy2.pool, sizeof(o->hy2.pool));
    return 0;
}

/* Порядок перебора узлов: то же правило, что out_node_list у vless (пустой выбор — вся подписка,
 * номер вне подписки пропускается). Отдельная функция, а не общая: выбор лежит в разных
 * структурах видов, и общая заставила бы вид знать чужую. */
size_t out_hy2_node_list(const struct output *o, size_t usable, int *dst, size_t max) {
    size_t n = 0;
    if (!o->hy2.nodes_n) {
        for (size_t i = 0; i < usable && n < max; i++) dst[n++] = (int)i;
        return n;
    }
    for (size_t i = 0; i < o->hy2.nodes_n && n < max; i++)
        if (o->hy2.nodes[i] >= 0 && (size_t)o->hy2.nodes[i] < usable) dst[n++] = o->hy2.nodes[i];
    return n;
}

int out_hy2_node_named(const struct output *o) {
    return o->hy2.nodes_n == 1;
}

const struct kind_ops kind_hysteria2 = {
    .name = "hysteria2",
    .caps = KC_DEVICE | KC_MARK | KC_CTMARK | KC_ENGINE_OWNED | KC_SELF_NAT | KC_OVER |
            KC_SKIP_ZAPRET | KC_TCP_PROBE | KC_FLOW_UDP | KC_TCP_REDIR | KC_IPV6,
    .keys = KK_NODES | KK_SUB,
    .selfnat_why = "masquerade не нужен: туннель завершает TCP сам, адреса клиентов "
                   "наружу не уходят",
    .parse = hy2_parse,
    .keys_of = hy2_keys_of,
    .status = hy2_status,
    .diag = hy2_diag,
    .helper = hy2_helper,
};
