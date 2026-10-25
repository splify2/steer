/* Реестр видов выхода (kind.h).
 *
 * РЕЕСТР — ЭТО ТО, ЧТО ВОШЛО В СБОРКУ. Какие виды есть в бинарнике, решает профиль в
 * build/sources.mk: файл src/kinds/<вид>.c в профиле есть — вид есть. Реестр ссылается на
 * записи видов СЛАБО, поэтому файл вида, не вошедший в профиль, не ломает компоновку: его адрес
 * оказывается нулевым, и на его месте встаёт запись отказа — имя и одна строка `absent`. Так
 * отказ «kind vless требует пакет steer-extended» живёт в одном месте, и #ifdef для него не
 * нужен ни здесь, ни в разборе.
 *
 * Почему слабые ссылки, а не таблица, которую собирает сборка. Сгенерированный файл пришлось
 * бы порождать в трёх системах сборки (Makefile, сценарии образа, Soong в Android.bp), а у Soong
 * для этого нужен свой genrule — три копии одного знания, которые расходятся молча, то есть
 * ровно то, от чего избавлял единый манифест. Слабая ссылка — одно место и та же компоновка
 * объектов, которой собираются все пути (архивов .a здесь нет: при них слабая ссылка не
 * вытянула бы файл вида из архива, и вид пропал бы молча). Чтобы вид не выпал из профиля по
 * недосмотру, tests/buildmatch.sh сверяет: все файлы src/kinds, кроме видов расширенной части,
 * — в профиле base, а виды расширенной части — в extended и android.
 *
 * direct — единственный вид со СИЛЬНОЙ ссылкой: обнулённый выход читается как direct (kind_of
 * в spec.h), то есть без этой записи движок не значит ничего.
 *
 * Строки отказа базовых видов (interface, tgws, awg) в настоящей сборке недостижимы —
 * эти файлы входят в каждый профиль. Они нужны стендам, которые компонуют модель с частью видов,
 * и там отказ честнее падения. */
#include <stdlib.h>
#include <string.h>

#include "spec.h"

extern const struct kind_ops kind_interface __attribute__((weak));
extern const struct kind_ops kind_vless __attribute__((weak));
extern const struct kind_ops kind_xsteer __attribute__((weak));
extern const struct kind_ops kind_tgws __attribute__((weak));
extern const struct kind_ops kind_awg __attribute__((weak));
extern const struct kind_ops kind_hysteria2 __attribute__((weak));
extern const struct kind_ops kind_trojan __attribute__((weak));
extern const struct kind_ops kind_shadowsocks __attribute__((weak));
extern const struct kind_ops kind_socks __attribute__((weak));
extern const struct kind_ops kind_http __attribute__((weak));
extern const struct kind_ops kind_vmess __attribute__((weak));

/* ТЕКСТ ОТКАЗА «НУЖЕН ПАКЕТ» — из одного места: здесь. С выпуска 1.10 у каждого модуля свой пакет
 * (steer-vless, steer-xsteer), а прежнее имя steer-extended осталось пакетом, который ставит их
 * все. Подстроку «steer-extended» читает splify2 — по ней он предлагает поставить полный пакет
 * (tests/climatch.sh, splify2 FirstRun.tsx), и пока он не научится читать имена модулей, она
 * обязана остаться в тексте рядом с новым именем. Прежней фразы «требует пакет steer-extended»
 * снимок генератора не хранит (в tests/golden её нет), так что дописать имя модуля можно. */
static const struct kind_ops no_interface = { .name = "interface", .absent = "kind interface в этой сборке нет" };
static const struct kind_ops no_vless     = { .name = "vless",  .absent = "kind vless требует пакет steer-vless (входит в steer-extended)" };
static const struct kind_ops no_xsteer    = { .name = "xsteer", .absent = "kind xsteer требует пакет steer-xsteer (входит в steer-extended)" };
static const struct kind_ops no_tgws      = { .name = "tgws",   .absent = "kind tgws в этой сборке нет" };
static const struct kind_ops no_awg       = { .name = "awg",    .absent = "kind awg в этой сборке нет" };
/* hysteria2 — единственный вид, которого нет в steer-extended: у него свой пакет, и текст не
 * отсылает к мета-пакету. */
static const struct kind_ops no_hysteria2 = { .name = "hysteria2", .absent = "kind hysteria2 требует пакет steer-hysteria2" };
/* Протоколы прокси — пакет steer-proxy (коннектор sing-box для podkop/forkop); как hysteria2, не в
 * steer-extended. Текст — один на пять, имя вида подставляет kind_absent. */
static const struct kind_ops no_trojan      = { .name = "trojan",      .absent = "kind trojan требует пакет steer-proxy" };
static const struct kind_ops no_shadowsocks = { .name = "shadowsocks", .absent = "kind shadowsocks требует пакет steer-proxy" };
static const struct kind_ops no_socks       = { .name = "socks",       .absent = "kind socks требует пакет steer-proxy" };
static const struct kind_ops no_http        = { .name = "http",        .absent = "kind http требует пакет steer-proxy" };
static const struct kind_ops no_vmess       = { .name = "vmess",       .absent = "kind vmess требует пакет steer-proxy" };

/* Порядок — прежний порядок видов (им же печатается справка о видах и идут проверки diag по
 * видам, см. cmd_diag). */
static const struct { const struct kind_ops *have, *none; const char *module; } REG[] = {
    { &kind_direct,    NULL,          NULL },
    { &kind_interface, &no_interface, NULL },
    { &kind_vless,     &no_vless,     "steer-vless" },
    { &kind_xsteer,    &no_xsteer,    "steer-xsteer" },
    { &kind_tgws,      &no_tgws,      NULL },
    { &kind_awg,       &no_awg,       NULL },
    /* Последними: порядок реестра — порядок правил видов и проверок diag, а у hysteria2 и
     * протоколов прокси правил нет. */
    { &kind_hysteria2, &no_hysteria2, "steer-hysteria2" },
    { &kind_trojan,      &no_trojan,      "steer-proxy" },
    { &kind_shadowsocks, &no_shadowsocks, "steer-proxy" },
    { &kind_socks,       &no_socks,       "steer-proxy" },
    { &kind_http,        &no_http,        "steer-proxy" },
    { &kind_vmess,       &no_vmess,       "steer-proxy" },
    /* Блок — без модуля и без правил вида до себя: в конце, порядок прежних не меняется. */
    { &kind_block,       NULL,            NULL },
};
#define REG_N (sizeof(REG) / sizeof(REG[0]))

size_t kind_count(void) { return REG_N; }

#ifdef STEER_LIBSTEER
#include <time.h>
#include "module.h"

/* В libsteer (ею пользуются steerd и модули) записи видов vless и xsteer есть всегда — сами
 * kinds/vless.c и xsteer.c разбирают ключи и пишут состояние, — а вот доступен ли ВИД, решает
 * модуль: установлен steer-vless — вид есть, нет — запись отказа, как у базовой сборки прежних
 * выпусков. Отказываем СРАЗУ, при разборе спеки (kinds/vless.c, шапка): иначе спека применялась
 * бы, правила вставали, и выход молча никуда не вёл.
 *
 * Установлен ли модуль — файл рядом с движком (lib/module.c). Ответ помнится секунду: реестр
 * спрашивают на каждый выход и каждый проход, а установка пакета не происходит чаще. Секунда, а
 * не навсегда: пакет ставят при работающем демоне, и его следующий проход обязан увидеть модуль. */
static int module_ok(size_t i) {
    static int val[REG_N];
    static time_t at[REG_N];
    time_t now = time(NULL);
    if (!at[i] || at[i] != now) {
        val[i] = steer_module_present(REG[i].module);
        at[i] = now;
    }
    return val[i];
}
#else
/* Статические сборки (телефон, стенды, микропакеты) несут модули в себе, и вид есть, если есть
 * его файл: профиль в build/sources.mk и решает. */
static int module_ok(size_t i) { (void)i; return 1; }
#endif

const struct kind_ops *kind_at(size_t i) {
    if (i >= REG_N) return NULL;
    if (REG[i].have && (!REG[i].module || module_ok(i))) return REG[i].have;
    return REG[i].none;
}

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
void kind_emit_all(struct nft_rs *rs, const struct spec *sp) {
    for (size_t ki = 0; ki < REG_N; ki++) {
        const struct kind_ops *k = kind_at(ki);
        if (!k->emit) continue;
        for (size_t i = 0; i < sp->out_n; i++)
            if (kind_of(&sp->out[i]) == k) k->emit(rs, sp, &sp->out[i]);
    }
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

void kind_helper_free(struct kind_helper *h) {
    free(h->cmd);
    free(h->prog);
    for (size_t i = 0; i < h->arg_n; i++) free(h->arg[i]);
    free(h->arg);
    for (size_t i = 0; i < h->env_n; i++) free(h->env[i]);
    free(h->env);
    h->cmd = h->prog = NULL;
    h->arg = h->env = NULL;
    h->arg_n = h->env_n = 0;
}
