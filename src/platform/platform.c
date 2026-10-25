/* Выбор платформы при запуске и пути, которые зависят от неё (см. platform.h).
 *
 * ПОРЯДОК ВЫБОРА. Явное (--platform, STEER_PLATFORM) — всегда первым: стенду нужно собрать
 * ruleset телефона на своей машине тем же бинарником. Затем умолчание сборки
 * (-DSTEER_DEFAULT_PLATFORM=android): прошивка и цель build/steer-android обязаны вести себя
 * как телефон, где бы их ни запустили, — стенды гоняют Android-сборку на обычном Linux и в
 * виртуальной машине, где признаков Android нет, а /etc/openwrt_release может и быть. Затем
 * признаки среды, и последним — роутер: с него движок начинался, и сборка без умолчания на
 * машине разработчика собирает ruleset роутера, как собирала всегда. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "platform.h"
#include "profile.h"

static const struct platform_ops *const PLATFORMS[] = { &plat_openwrt, &plat_android };
#define PLATFORMS_N (sizeof PLATFORMS / sizeof PLATFORMS[0])

#define PLAT_STR_(x) #x
#define PLAT_STR(x) PLAT_STR_(x)

static const struct platform_ops *g_plat;

const struct platform_ops *plat_by_name(const char *name) {
    for (size_t i = 0; name && i < PLATFORMS_N; i++)
        if (!strcmp(PLATFORMS[i]->name, name)) return PLATFORMS[i];
    return NULL;
}

const char *plat_names(void) {
    static char buf[64];
    if (!buf[0])
        for (size_t i = 0; i < PLATFORMS_N; i++)
            snprintf(buf + strlen(buf), sizeof buf - strlen(buf), "%s%s", i ? ", " : "",
                     PLATFORMS[i]->name);
    return buf;
}

static const struct platform_ops *plat_choose(void) {
    const char *e = getenv("STEER_PLATFORM");
    if (e && *e) {
        const struct platform_ops *p = plat_by_name(e);
        if (p) return p;
        fprintf(stderr, "steer[warn] STEER_PLATFORM=%s: такой платформы нет (есть %s), "
                        "выбираю по среде\n", e, plat_names());
    }
#ifdef STEER_DEFAULT_PLATFORM
    {
        const struct platform_ops *p = plat_by_name(PLAT_STR(STEER_DEFAULT_PLATFORM));
        if (p) return p;
    }
#endif
    /* Признаки: сначала Android — его признаки однозначны, а роутер и так умолчание. */
    for (size_t i = PLATFORMS_N; i-- > 0;)
        if (PLATFORMS[i]->detect && PLATFORMS[i]->detect()) return PLATFORMS[i];
    return &plat_openwrt;
}

/* Поле метки, заданное профилем сборки (src/profile/profile.h): мини-сборка tgws живёт на роутере
 * в своём бите. Таблица платформы — константа, поэтому поправка кладётся в копию, одну на
 * процесс; у платформы, которой профиль не касается, остаётся её собственная таблица. */
/* ПОЛЕ МЕТКИ ИЗ ОКРУЖЕНИЯ: STEER_MARK_FIELD=<маска> (например 0x000000ff). Нужно экземпляру
 * движка, которого запускает steer-box-connector (sing-box для podkop и forkop): их правила nft
 * ставят метки в битах нашего поля по умолчанию — podkop 0x00100000 и 0x00200000, forkop
 * 0x01000000..0x08000000, — и ставят их ЦЕЛИКОМ (`meta mark set 0x00100000`) в prerouting
 * раньше нашей prerouting_mark. Метка podkop 0x00100000 совпала бы с меткой нашего первого
 * выхода, и пакет, который podkop пометил для своего tproxy, уехал бы в наш туннель. Сдвинуть
 * контракт для всех нельзя (marks.h), поэтому поле задаёт тот, кто знает соседей, — запускающий.
 * Маска — биты подряд, не больше шестнадцати; другое — предупреждение и поле платформы. Поле
 * профиля (мини-сборка tgws) сильнее: у неё один бит, и сдвигать его незачем. */
static int mark_field_env(uint32_t *base, unsigned *bits) {
    const char *e = getenv("STEER_MARK_FIELD");
    if (!e || !*e) return 0;
    char *end;
    unsigned long m = strtoul(e, &end, 0);
    if (*end || !m || m > 0xffffffffUL) goto bad;
    uint32_t mask = (uint32_t)m, low = mask & -mask;
    unsigned n = 0;
    for (uint32_t v = mask / low; v & 1u; v >>= 1) n++;
    if ((uint32_t)(((1ull << n) - 1u) * low) != mask || n > 16) goto bad;
    *base = low;
    *bits = n;
    return 1;
bad:
    fprintf(stderr, "steer[warn] STEER_MARK_FIELD=%s: нужна маска из битов подряд (до 16), "
                    "беру поле платформы\n", e);
    return 0;
}

/* ПРИОРИТЕТ ПРАВИЛ ВЫХОДОВ ИЗ ОКРУЖЕНИЯ: STEER_RULE_PREF=<1..32765>. На роутере приоритет не
 * передаётся (rule_pref 0), и ядро ставит правило сразу перед самым ранним ненулевым — то есть
 * место зависит от того, чьи правила уже стоят (Tailscale — 5210 и дальше, mwan3 — тысячи). Тому
 * же экземпляру steer-box-connector нужен порядок наверняка: правила steer, за ними его правило
 * «метка tproxy podkop/forkop — в main», за ними их правило 105 в `local default dev lo`. */
static int rule_pref_env(unsigned *pref) {
    const char *e = getenv("STEER_RULE_PREF");
    if (!e || !*e) return 0;
    char *end;
    unsigned long v = strtoul(e, &end, 10);
    if (*end || v < 1 || v > 32765) {
        fprintf(stderr, "steer[warn] STEER_RULE_PREF=%s: нужен приоритет 1..32765, беру умолчание\n", e);
        return 0;
    }
    *pref = (unsigned)v;
    return 1;
}

/* КАНАЛЫ НА САМ РОУТЕР: STEER_ROUTER_SELF=1. Нужны экземпляру steer-box-connector: у sing-box,
 * которого он заменяет, трафик самого роутера к адресам из списков (podkop и forkop помечают его
 * в mangle_output) возвращается через lo в tproxy и идёт по тем же правилам, что трафик LAN, — на
 * этом стоят проверки podkop (`curl https://fakeip.podkop.fyi/check` с роутера) и всё, что роутер
 * сам качает с имён из списков. Включается механизм телефона — каналы `self` на хуке output
 * (local_channels) — с двумя отличиями роутера:
 *   - «сам движок» (self_mark) — всё поле метки: так метятся сокеты самого движка (туннели,
 *     апстримы dnsd, замеры групп), и правило `self` их не берёт (`meta mark and поле == 0`);
 *   - свой DNS роутера в резолвер не заворачивается (local_dns = 0, см. platform.h).
 * У платформы телефона переменная ничего не меняет. */
static int router_self_env(void) {
    const char *e = getenv("STEER_ROUTER_SELF");
    return e && !strcmp(e, "1");
}

static const struct platform_ops *plat_profiled(const struct platform_ops *p) {
    static struct platform_ops copy;
    const struct profile *pr = prof();
    uint32_t base = 0;
    unsigned bits = 0, pref = 0;
    int field = 0;
    if (pr->mark_bits && pr->mark_platform && !strcmp(pr->mark_platform, p->name)) {
        base = pr->mark_base;
        bits = pr->mark_bits;
        field = 1;
    } else field = mark_field_env(&base, &bits);
    int prefd = rule_pref_env(&pref);
    int self = !p->local_channels && router_self_env();
    if (!field && !prefd && !self) return p;
    copy = *p;
    if (field) {
        copy.mark_base = base;
        copy.mark_bits = bits;
        copy.mark_mask = PLAT_MARK_MASK(base, bits);
    }
    if (prefd) copy.rule_pref = pref;
    if (self) {
        copy.local_channels = 1;
        copy.local_dns = 0;
        copy.self_mark = copy.mark_mask;
        copy.app_uid_min = 0;
    }
    return &copy;
}

const struct platform_ops *plat(void) {
    if (!g_plat) g_plat = plat_profiled(plat_choose());
    return g_plat;
}

int plat_select(const char *name) {
    const struct platform_ops *p = plat_by_name(name);
    if (!p) return -1;
    g_plat = plat_profiled(p);
    setenv("STEER_PLATFORM", p->name, 1);
    return 0;
}

/* ---- пути с переопределением ------------------------------------------------------------
 *
 * Каталог состояния и каталог имён таблиц — пути платформы, но у обоих есть шов: у первого
 * --state-dir (движок, dnsd, ctl-serve передают его своим детям), у второго — стенды, которым
 * нужно писать в свой каталог, а не в системный. Переопределение хранится отдельно от
 * таблицы: таблица платформы — константа, одна на процесс. */
static const char *g_state_override, *g_rt_override;

const char *steer_state_dir(void) {
    return g_state_override ? g_state_override : plat()->state_dir;
}

void steer_set_state_dir(const char *dir) { g_state_override = dir; }

const char *steer_rt_tables_dir(void) {
    return g_rt_override ? g_rt_override : plat()->rt_tables_d;
}

void steer_set_rt_tables_dir(const char *dir) { g_rt_override = dir; }

const char *plat_etc_path(char *buf, size_t n, const char *name) {
    snprintf(buf, n, "%s/%s", plat()->etc_dir, name);
    return buf;
}

/* Каталог спеки — копией, а не указателем в argv: путь приходит и из разобранных флагов, и из
 * plat_spec_default (его буфер статический, но общий с другими вопросами). */
static char g_keep_dir[256];

const char *steer_keep_dir(void) {
    return g_keep_dir[0] ? g_keep_dir : plat()->etc_dir;
}

void steer_set_keep_dir_of(const char *spec_path) {
    g_keep_dir[0] = '\0';
    if (!spec_path || !*spec_path) return;
    const char *sl = strrchr(spec_path, '/');
    if (!sl) { snprintf(g_keep_dir, sizeof(g_keep_dir), "."); return; }
    size_t n = sl == spec_path ? 1 : (size_t)(sl - spec_path);
    if (n >= sizeof(g_keep_dir)) return;     /* не влез — умолчание платформы, а не обрубок */
    memcpy(g_keep_dir, spec_path, n);
    g_keep_dir[n] = '\0';
}

/* spec.yaml рядом с spec.json: тот же путь с другим окончанием. Выводится из spec_path, а не
 * пишется второй строкой в таблицу платформы — две строки разошлись бы. */
const char *plat_spec_yaml(void) {
    static char buf[256];
    const char *js = plat()->spec_path;
    size_t n = strlen(js);
    if (n > 5 && !strcmp(js + n - 5, ".json") && n < sizeof(buf))
        snprintf(buf, sizeof(buf), "%.*s.yaml", (int)(n - 5), js);
    else
        snprintf(buf, sizeof(buf), "%s.yaml", js);
    return buf;
}

const char *plat_spec_default(void) {
    const char *js = plat()->spec_path, *ym = plat_spec_yaml();
    return access(js, F_OK) != 0 && access(ym, F_OK) == 0 ? ym : js;
}

const char *plat_spec_resolve(const char *path) {
    if (!path || !strcmp(path, plat()->spec_path) || !strcmp(path, plat_spec_yaml()))
        return plat_spec_default();
    return path;
}
