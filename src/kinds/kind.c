/* Реестр видов выхода (kind.h).
 *
 * ВИДЫ ЯДРА — ЭТО ТО, ЧТО ВОШЛО В СБОРКУ: direct, interface, tgws, awg, block (и группа — она часть
 * модели, см. kind.h). Виды протоколов в ядре не живут вовсе: tunnel:vless, xsteer, warp и соседи
 * приходят только из манифестов плагинов (kinds/plugin.c) и идут в реестре после видов ядра, по id
 * плагина и порядку манифеста. Вида без плагина ядро не знает: выход с ним недоступен (unavail) при
 * старте и reload, а apply и check отказывают с причиной «нужен плагин X» (steer-api.md, 3.5).
 *
 * Реестр ссылается на записи видов ядра СЛАБО: стенды компонуют модель с частью видов, и вид, файла
 * которого нет, отвечает записью отказа (absent) — честнее падения. В настоящей сборке эти строки
 * недостижимы: файлы видов ядра входят в каждый профиль (tests/buildmatch.sh).
 *
 * direct — единственный вид со СИЛЬНОЙ ссылкой: обнулённый выход читается как direct (kind_of
 * в spec.h), то есть без этой записи движок не значит ничего. */
#include <stdlib.h>
#include <string.h>

#include "spec.h"
#include "plugin.h"

extern const struct kind_ops kind_interface __attribute__((weak));
extern const struct kind_ops kind_awg __attribute__((weak));

static const struct kind_ops no_interface = { .name = "interface", .absent = "kind interface в этой сборке нет" };
static const struct kind_ops no_awg       = { .name = "awg",    .absent = "kind awg в этой сборке нет" };

/* Порядок — прежний порядок видов (им же печатается справка о видах и идут проверки diag по
 * видам, см. cmd_diag). */
static const struct { const struct kind_ops *have, *none; } REG[] = {
    { &kind_direct,    NULL },
    { &kind_interface, &no_interface },
    { &kind_awg,       &no_awg },
    /* Блок — без правил вида до себя: в конце, порядок прежних не меняется. */
    { &kind_block,     NULL },
};
#define REG_N (sizeof(REG) / sizeof(REG[0]))

/* Виды плагинов идут после видов ядра, по id плагина и порядку манифеста (plugin.c): порядок
 * kind_emit_all и проверок diag не зависит от порядка установки. */
size_t kind_count(void) { return REG_N + plugin_kinds_n(); }

const struct kind_ops *kind_at(size_t i) {
    if (i >= REG_N) return plugin_kind_ops_at(i - REG_N);
    return REG[i].have ? REG[i].have : REG[i].none;
}

/* Только виды ядра: спека v1 плагинных видов не знает (spec-fields.md, раздел 7). Вид плагина
 * спека v2 ищет сама — по имени манифеста (plugin_kind_find). */
const struct kind_ops *kind_by_name(const char *name) {
    for (size_t i = 0; i < REG_N; i++) {
        const struct kind_ops *k = kind_at(i);
        if (!strcmp(k->name, name)) return k;
    }
    return NULL;
}

/* Правила видов в дерево ruleset (generate.c: nft_build). По ВИДАМ, в порядке реестра, а
 * внутри вида — по выходам в порядке спеки: тот же приём, что у diag.c (шаг 8, kind_ops.diag)
 * — «Обход по видам в порядке реестра, а внутри вида — по выходам в порядке спеки», и тот же
 * довод: правила одного вида ложатся в дерево подряд, одним блоком, и текст ruleset не
 * зависит от того, в каком порядке человек перечислил выходы разных видов в спеке. До
 * переноса на emit это обеспечивали два ЖЁСТКО заказанных прохода в generate.c (сначала все
 * одного вида, потом другого); порядок реестра даёт то же самое без знания имён видов. */
int kind_emit_all(struct nft_rs *rs, const struct spec *sp, struct err *e) {
    for (size_t ki = 0; ki < REG_N; ki++) {
        const struct kind_ops *k = kind_at(ki);
        if (!k->emit) continue;
        for (size_t i = 0; i < sp->out_n; i++)
            if (kind_of(&sp->out[i]) == k) k->emit(rs, sp, &sp->out[i]);
    }
    /* Файлы и шаблоны nft плагинов — после видов ядра (plugin.c). */
    return plugin_emit_all(rs, sp, e);
}

void kind_sig_mix(unsigned long long *h, const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) { *h ^= b[i]; *h *= 1099511628211ULL; }
    *h ^= 0xff; *h *= 1099511628211ULL;   /* граница поля: «ab»+«c» не равно «a»+«bc» */
}

/* ---- поля помощника (kind_helper) --------------------------------------------------------- */

static int kh_str(char **dst, const char *v) {
    char *c = strdup(v);
    if (!c) return -1;
    free(*dst);
    *dst = c;
    return 0;
}

static int kh_add(char ***vec, size_t *n, const char *v) {
    char *c = strdup(v);
    if (!c) return -1;
    char **nv = realloc(*vec, (*n + 1) * sizeof(*nv));
    if (!nv) { free(c); return -1; }
    nv[(*n)++] = c;
    *vec = nv;
    return 0;
}

int kind_helper_cmd(struct kind_helper *h, const char *cmd) { return kh_str(&h->cmd, cmd); }
int kind_helper_prog(struct kind_helper *h, const char *prog) { return kh_str(&h->prog, prog); }
int kind_helper_arg(struct kind_helper *h, const char *arg) { return kh_add(&h->arg, &h->arg_n, arg); }
int kind_helper_env(struct kind_helper *h, const char *var) { return kh_add(&h->env, &h->env_n, var); }
int kind_helper_conf(struct kind_helper *h, const char *path) { return kh_str(&h->conf_path, path); }

void kind_helper_free(struct kind_helper *h) {
    free(h->cmd);
    free(h->prog);
    for (size_t i = 0; i < h->arg_n; i++) free(h->arg[i]);
    free(h->arg);
    for (size_t i = 0; i < h->env_n; i++) free(h->env[i]);
    free(h->env);
    free(h->conf_path);
    h->conf_path = NULL;
    h->cmd = h->prog = NULL;
    h->arg = h->env = NULL;
    h->arg_n = h->env_n = 0;
}
