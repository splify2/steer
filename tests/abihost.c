/* Хост для стенда tests/abimatch.sh: настоящий загрузчик src/daemon/plugso.c, цикл, подписчики и модель спеки,
 * без демона. Сценарий выбирает argv[3]; вывод — строки, которые проверяет стенд.
 *
 *   abihost <файл.so> <id> load      загрузить, напечатать состояние, причину и status (код 0 — загружен)
 *   abihost <файл.so> <id> enable    plugso_enable отключённому по падениям плагину и повторная загрузка
 *   abihost <файл.so> <id> calls     все вызовы вида под сторожем на спеке из двух выходов
 *   abihost <файл.so> <id> async     таймеры, дескрипторы, имена, HTTPS и события на цикле 1,5 с
 *   abihost <файл.so> <id> health    вызов health (падение или зависание — как у плагина)
 *   abihost <файл.so> <id> timer     цикл, пока не упадёт таймер плагина
 *   abihost <файл.so> <id> event     событие boom подписчикам (on_event плагина)
 *
 * Состояние — STEER_STATE_DIR из окружения (steer_set_state_dir). */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "kind.h"
#include "loop.h"
#include "plugso.h"
#include "spec.h"
#include "state.h"
#include "platform.h"
#include "groups.h"

/* Заглушки того, что принадлежит демону целиком. */
void watchd_preempt(struct watchd *w) { (void)w; printf("WAKE\n"); }
void supd_member_set(struct supd *s, const char *grp, const char *out, int v) {
    (void)s;
    printf("MEMBER %s %s %d\n", grp, out, v);
}
/* state.c читает спеку и строит группы; хосту стенда спека задана руками, читать нечего. */
int build_groups(const struct spec *sp, struct groups *gr, struct err *e) { (void)sp; (void)gr; (void)e; return 0; }
void groups_release(struct groups *gr) { (void)gr; }
void tcp_redir_learn(const struct spec *sp) { (void)sp; }
/* HTTPS-клиент ядра подменён: настоящий — в libsteer, а здесь проверяется только путь через рабочий поток. */
int plugso_http_get(const char *method, const char *url, const char *headers, const void *body, size_t body_n,
                    uint32_t mark, uint32_t timeout_ms, int (*sink)(void *, const void *, size_t), void *arg,
                    int *status, char *why, size_t wn) {
    (void)method; (void)url; (void)headers; (void)body; (void)body_n; (void)mark; (void)timeout_ms; (void)why; (void)wn;
    sink(arg, "pong", 4);
    *status = 200;
    return 0;
}

static struct steerd D;
static struct spec SP;
static struct loop *L;
static void sub_push(struct steerd_sub *s, const char *line, size_t n) {
    (void)s;
    printf("SUB %.*s", (int)n, line);
}
static struct steerd_sub SUB = { .push = sub_push };

static const char *keys_of(const struct output *o) { (void)o; return "{\"k\":1}"; }
static const char *conf_of(const struct output *o) { (void)o; return "{\"c\":2}"; }
static const char *owner_of(const struct output *o) { static char b[64]; snprintf(b, sizeof b, "abitest/%s", o->name); return b; }
static int res_of(const char *pl, const char *kind, unsigned i, uint32_t *out) {
    if (!strcmp(kind, "mark")) { *out = 1u << (28 + i); return 0; }
    (void)pl;
    return -1;
}
static const struct plugso_model_ops MODEL = { keys_of, conf_of, owner_of, res_of };

static int sink(void *arg, const char *id, const char *slot, const char *rule) {
    printf("NFT %s %s: %s (%s)\n", id, slot, rule, (const char *)arg);
    return 0;
}

static void stop_cb(struct loop *l, struct loop_timer *t, void *arg) {
    (void)t; (void)arg;
    loop_stop(l, 0);
}

int main(int argc, char **argv) {
    if (argc < 4) return 2;
    setvbuf(stdout, NULL, _IOLBF, 0);
    const char *so = argv[1], *id = argv[2], *sc = argv[3];
    const char *sd = getenv("STEER_STATE_DIR");
    if (sd) steer_set_state_dir(sd);
    L = loop_new();
    D.loop = L;
    D.sp = &SP;
    D.have = 1;
    steerd_sub_add(&D, &SUB);
    plugso_attach(&D);
    plugso_set_model(&MODEL);
    SP.out = calloc(2, sizeof *SP.out);
    SP.out_n = SP.out_cap = 2;
    snprintf(SP.out[0].name, sizeof SP.out[0].name, "wan");
    snprintf(SP.out[0].device, sizeof SP.out[0].device, "wg0");
    SP.out[0].mark = 0x100;
    SP.out[0].table = 100;
    snprintf(SP.out[1].name, sizeof SP.out[1].name, "bad");
    snprintf(SP.out[1].device, sizeof SP.out[1].device, "wg1");

    char dir[512], rel[256], why[512] = "";
    snprintf(dir, sizeof dir, "%s", so);
    char *sl = strrchr(dir, '/');
    if (sl) { snprintf(rel, sizeof rel, "%s", sl + 1); *sl = 0; }
    else { snprintf(rel, sizeof rel, "%s", so); snprintf(dir, sizeof dir, "."); }
    struct plugso *p = NULL;
    if (!strcmp(sc, "enable")) {
        /* Отключённый по падениям плагин: сначала запись (отказ), затем включение человеком и повтор. */
        int r0 = plugso_load(id, NULL, dir, rel, &p, why, sizeof why);
        printf("BEFORE rc=%d state=%d\n", r0, p ? (int)plugso_state(p) : 0);
        plugso_enable(id);
        printf("AFTER state=%d crashes=%d why=%s\n", p ? (int)plugso_state(p) : 0, p ? plugso_crashes(p) : -1,
               p && plugso_why(p) ? plugso_why(p) : "");
        return p && plugso_state(p) == PLUGSO_LOADED ? 0 : 1;
    }
    int rc = plugso_load(id, getenv("ABI_VERSION") && *getenv("ABI_VERSION") ? getenv("ABI_VERSION") : NULL, dir, rel, &p, why, sizeof why);
    printf("LOAD rc=%d state=%d why=%s\n", rc, p ? (int)plugso_state(p) : 0, p && plugso_why(p) ? plugso_why(p) : why);
    if (!strcmp(sc, "load")) {
        printf("STATUS ");
        plugso_status_print(stdout);
        printf("\n");
        return rc == 0 ? 0 : 1;
    }
    if (rc != 0) return 1;
    const struct steer_kind_v1 *k = plugso_kind_find(p, "abikind");
    if (!strcmp(sc, "calls")) {
        char w[256] = "";
        printf("KIND found=%d absent=%d\n", k != NULL, plugso_kind_find(p, "nope") == NULL);
        printf("CHECK0 %d\n", plugso_call_check(p, k, &SP, &SP.out[0], w, sizeof w));
        printf("CHECK1 %d why=%s\n", plugso_call_check(p, k, &SP, &SP.out[1], w, sizeof w), w);
        plugso_call_emit(p, k, &SP, &SP.out[0], sink, "ctx");
        printf("HEALTH %d %d\n", plugso_call_health(p, k, &SP, &SP.out[0], "wg0"), plugso_call_health(p, k, &SP, &SP.out[0], "x"));
        printf("REVIVE %d\n", plugso_call_revive(p, k, &SP, &SP.out[0], "wg0"));
        printf("APPLY_ALL %d\n", plugso_call_apply_all(p, k, &SP, w, sizeof w));
        printf("DOWN_ALL %d\n", plugso_call_down_all(p, k, &SP));
        char *st = plugso_call_status(p, k, &SP, &SP.out[0]);
        printf("STATUS_CALL %s\n", st ? st : "(null)");
        free(st);
        char *fr = NULL;
        printf("EXPAND %d ", plugso_call_expand(p, k, "{\"a\":1}", &fr, w, sizeof w));
        printf("%s\n", fr ? fr : "(null)");
        free(fr);
        char *po = NULL;
        int pr = plugso_call_pre_apply(p, "{\"spec\":1}", &po, w, sizeof w);
        printf("PRE_APPLY %d %s\n", pr, po ? po : "(null)");
        free(po);
        char *rs = NULL;
        printf("CTL-UNKNOWN %d\n", plugso_call_ctl(p, "nope", NULL, 0, NULL, 0, &rs));
        printf("CTL-OUTSIDE %d\n", plugso_call_ctl(p, "nft-outside", NULL, 0, NULL, 0, &rs));
        plugso_call_ctl(p, "emit", NULL, 0, NULL, 0, &rs);
        printf("STATUS_OUT ");
        plugso_status_out(stdout, "wan");
        printf("\n");
        uint32_t res = 0;
        (void)res;
        plugso_fini_all();
        return 0;
    }
    if (!strcmp(sc, "async")) {
        char *rs = NULL;
        plugso_call_ctl(p, "async", NULL, 0, NULL, 0, &rs);
        free(rs);
        struct loop_timer *t = loop_timer_new(L, stop_cb, NULL);
        loop_timer_set(t, 1500);
        loop_run(L);
        return 0;
    }
    if (!strcmp(sc, "health")) {
        printf("HEALTH %d\n", plugso_call_health(p, k, &SP, &SP.out[0], "wg0"));
        return 0;
    }
    if (!strcmp(sc, "timer")) {
        struct loop_timer *t = loop_timer_new(L, stop_cb, NULL);
        loop_timer_set(t, 20000);
        loop_run(L);
        return 0;
    }
    if (!strcmp(sc, "event")) {
        steerd_emit(&D, "boom", NULL);
        return 0;
    }
    return 2;
}
