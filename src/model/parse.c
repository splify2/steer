/* Модель спеки — то, что общее у всех её читателей и не зависит от формата файла (see spec.h
 * for why this is shared): состав имён, имена наборов nftables, что такое строка списка и «кто»
 * на самом телефоне, поиск выхода по имени и точка входа load_spec.
 *
 * Разбор ФОРМАТА — не здесь. Спека v1 (JSON со `schema: 1` или `2`, до 2.0.0) разбирается и
 * переводится в модель v2 в model/v1.c; спека v2 (YAML или JSON с `version: 2`) — в model/v2.c
 * (docs/spec-v2.md). load_spec читает файл, узнаёт формат по содержимому и отдаёт текст нужному
 * разборщику, а всё остальное в движке видит только модель: правила, списки, клиенты, выходы и
 * группы. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "spec.h"
#include "srsplan.h"
#include "obfs.h"
#include "ynode.h"
#include "v1.h"
#include "v2.h"

/* Список правила без списков — весь трафик (rule_list в spec.h). Один на процесс: правило
 * ссылается на него, а не держит свой, и сужения у него нет. */
const struct spec_list spec_list_all = { .all = 1 };


/* Состав идентификатора, пришедшего из спеки: имя выхода, имя устройства, имя канала,
 * записи lan_devices.
 *
 * Заслон стоит В ПАРСЕРЕ, а не у каждого вызова оболочки, и это принципиально. Имена
 * отсюда подставляются в командные строки в нескольких разных местах — `pgrep -f 'steer
 * obfs %s'` и `nft list chain … o_%s` в diag, имя набора в set_count, — и проверять их по
 * месту значит проверять по разу в каждом и забыть в следующем. Забыли: спека с lan_device
 * вида «x;id>/tmp/pwned;#» уезжала в `ip -4 -o addr show %s` через popen и выполняла это от
 * root, причём у ЛЮБОЙ команды, читающей спеку, потому что автоопределение подсети
 * включалось штатно. Того вызова больше нет (клиенты выбираются по имени устройства, а не
 * по выведенной подсети), но проверка от этого не менее нужна: имя устройства теперь уходит
 * в текст правил nftables. Имя выхода с кавычкой давало то же самое через diag, а diag
 * дёргает rpcd интерфейса.
 *
 * Проверенное однажды при загрузке имя безопасно везде и навсегда, включая места,
 * которых ещё нет. Это то же решение, что с адресом в explain: там проверка формы стоит
 * до подстановки, и по той же причине — подстановка непроверенной строки уже была дырой.
 *
 * Состав нарочно уже, чем позволяет ядро: буквы, цифры, `_`, `-`, `.`. Имена интерфейсов
 * Linux этим и ограничены на практике, а имя выхода придумывает человек в интерфейсе —
 * ему хватает. Пустое имя отвергается тоже: оно ломает и набор, и pgrep. */
int name_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (!((*q >= 'a' && *q <= 'z') || (*q >= 'A' && *q <= 'Z') ||
              (*q >= '0' && *q <= '9') || *q == '_' || *q == '-' || *q == '.'))
            return 0;
    return 1;
}

/* Имя КАНАЛА — не идентификатор, а подпись, которую человек читает в интерфейсе, и
 * требовать от неё латиницу нельзя: каналы в этом проекте называют по-русски, и стенд
 * с «адресами»/«доменами» — ровно тот случай. В оболочку это имя не попадает никогда:
 * комментарий в ruleset собирается из имени ГРУППЫ, а то выводится из имени выхода.
 * Дойти оно может до JSON у status и до текста ruleset, поэтому запрещено ровно то, что
 * ломает их разбор: кавычка, обратная косая и управляющие символы. Всё остальное, включая
 * любой UTF-8, разрешено. */
int label_ok(const char *s) {
    if (!s || !*s) return 0;
    for (const unsigned char *q = (const unsigned char *)s; *q; q++)
        if (*q == '"' || *q == '\\' || *q < 0x20 || *q == 0x7F) return 0;
    return 1;
}

/* ---- имя набора группы -----------------------------------------------------
 *
 * Живёт ЗДЕСЬ, а не в компиляторе, потому что имя вычисляют двое: компилятор
 * (compile/groups.c), когда заводит набор, и резолвер (dnsd/table.c), когда решает, в какой
 * набор класть адрес разрешённого домена. Разойдись они — резолвер наполнял бы набор, которого нет, и доменная
 * маршрутизация молча переставала бы работать. Одна функция, два вызывающих.
 *
 * Почему у имени появился различитель. Раньше имя собиралось только из выхода и вида
 * (`vpn_ip`, `vpn_dom`), а группы компилятор разделяет ещё и по списку клиентов (`from`)
 * и по режиму резолвера. Две группы получали ОДНО имя, ядро сливало их наборы в один, и
 * список, заведённый «только для телевизора», уезжал в туннель для всей сети. Никакого
 * отказа при этом не было: nft принимает два объявления одного набора.
 *
 * Различитель — порядковый номер списка клиентов в спеке, а не хэш: номер точен, а хэш
 * мог бы совпасть у двух разных списков и вернуть ту же беду тихо. Номер считается по
 * правилам в порядке спеки, поэтому оба вызывающих получают одно и то же число, не
 * сговариваясь.
 *
 * Умолчания суффикса не получают: `vpn_ip` у обычной конфигурации остаётся `vpn_ip`, и
 * на уже установленных роутерах имена наборов (а с ними и перенос счётчиков) не меняются.
 */
static int from_same(const char (*a)[64], size_t an, const char (*b)[64], size_t bn) {
    if (an != bn) return 0;
    for (size_t i = 0; i < an; i++) if (strcmp(a[i], b[i]) != 0) return 0;
    return 1;
}

/* Действующий список клиентов правила — rule_who в spec.h: свой, а если его нет — клиенты по
 * умолчанию. Правило то же, что у компилятора при сборке групп. */
static const char (*rule_from(const struct spec *sp, const struct spec_rule *r, size_t *n))[64] {
    const struct spec_client *c = rule_who(sp, r);
    *n = c->from_n;
    return c->from;
}

/* Номер списка клиентов среди РАЗЛИЧНЫХ списков, встреченных в спеке, в порядке первого
 * появления. Список по умолчанию участвует в нумерации наравне с прочими: он всё равно
 * попадает в ветку без суффикса, кроме случая realip. */
static int from_disc(const struct spec *sp, const char (*from)[64], size_t from_n) {
    int idx = 0;
    for (size_t i = 0; i < sp->rule_n; i++) {
        size_t cn;
        const char (*cf)[64] = rule_from(sp, &sp->rule[i], &cn);
        if (from_same(cf, cn, from, from_n)) return idx;
        /* Считаем только первое появление каждого списка. */
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++) {
            size_t kn;
            const char (*kf)[64] = rule_from(sp, &sp->rule[k], &kn);
            seen = from_same(kf, kn, cf, cn);
        }
        if (!seen) idx++;
    }
    return idx;
}

int l4match_same(const struct l4match *a, const struct l4match *b) {
    int ae = l4match_empty(a), be = l4match_empty(b);
    if (ae || be) return ae && be;
    if (a->proto != b->proto || a->ports_n != b->ports_n || a->override_port != b->override_port)
        return 0;
    /* ПОРЯДОК ЗНАЧИМ, и это сознательно. Два канала с одними диапазонами, записанными в
     * разном порядке, дадут разные группы и разные наборы — то есть лишнее правило вместо
     * слияния. Цена ошибки в эту сторону — одно правило; в другую (счесть разное одним) —
     * молча поделённый набор адресов. Сортировать перед сравнением значило бы завести
     * второй порядок помимо написанного человеком, а он виден в тексте правил. */
    for (size_t i = 0; i < a->ports_n; i++)
        if (a->ports[i].lo != b->ports[i].lo || a->ports[i].hi != b->ports[i].hi) return 0;
    return 1;
}

/* Номер СУЖЕНИЯ среди различных сужений, встреченных в спеке, в порядке первого появления.
 * Нуль — сужения нет.
 *
 * Тот же приём и та же причина, что у from_disc: ядро сливает одноимённые наборы МОЛЧА, и
 * два канала одного выхода с разными портами поделили бы один набор адресов. Тогда
 * ограничение по портам либо распространилось бы на чужие адреса (сузили то, чего не
 * просили), либо пропало бы вовсе (весь TCP к Cloudflare в туннель) — в зависимости от
 * того, чьё правило встанет первым. Номер, а не хэш: номер точен, а хэш мог бы совпасть у
 * двух разных сужений и вернуть ту же беду тихо.
 *
 * Считается по спискам правил в порядке спеки (у перевода v1 — по списку на канал), поэтому
 * компилятор и резолвер получают одно и то же число, не сговариваясь. */
/* Сужение i-го правила: сужение его списка (у правила без списков — пустое). */
static const struct l4match *rule_l4(const struct spec *sp, size_t i) {
    return &rule_list(sp, &sp->rule[i])->l4;
}

/* Различные сужения клауз наборов, которых нет среди сужений правил, — в порядке появления. */
struct l4seen { const struct spec *sp; struct l4match *v; size_t n; };
static void l4seen_add(void *ctx, const struct l4match *m) {
    struct l4seen *c = ctx;
    for (size_t i = 0; i < c->sp->rule_n; i++)
        if (!l4match_empty(rule_l4(c->sp, i)) && l4match_same(rule_l4(c->sp, i), m)) return;
    for (size_t k = 0; k < c->n; k++) if (l4match_same(&c->v[k], m)) return;
    if (c->n < 256) c->v[c->n++] = *m;
}

static int l4_disc(const struct spec *sp, const struct l4match *m) {
    if (l4match_empty(m)) return 0;
    int idx = 0;
    for (size_t i = 0; i < sp->rule_n; i++) {
        const struct l4match *c = rule_l4(sp, i);
        if (l4match_empty(c)) continue;
        int seen = 0;
        for (size_t k = 0; k < i && !seen; k++)
            seen = l4match_same(rule_l4(sp, k), c);
        if (seen) continue;                 /* посчитан при первом появлении */
        idx++;
        if (l4match_same(c, m)) return idx;
    }
    /* Сужение не из канала — значит из набора .srs (у клаузы набора своё сужение, см.
     * src/model/srsplan.c). Такие нумеруются ПОСЛЕ сужений каналов, в порядке каналов, файлов и
     * клауз: номера каналов тогда не сдвигаются от того, что в спеке появился набор, и имена
     * наборов у прежних каналов — а от них зависит перенос счётчиков — остаются прежними. */
    static struct l4match seen[256];
    struct l4seen c = { sp, seen, 0 };
    for (size_t i = 0; i < sp->rule_n; i++) {
        const struct spec_list *l = rule_list(sp, &sp->rule[i]);
        if (l->srs_n) srs_list_l4_each(l, l4seen_add, &c);
    }
    for (size_t k = 0; k < c.n; k++)
        if (l4match_same(&seen[k], m)) return idx + 1 + (int)k;
    /* Недостижимо: сужение приходит из спеки или её наборов. Возвращать здесь нуль значило бы
     * отдать имя без суффикса, то есть ровно то слияние наборов, от которого функция и
     * заведена, — поэтому число, которого ни у кого нет. */
    return idx + 1 + (int)c.n;
}

void group_set_name(const struct spec *sp, char *dst, size_t n, const char *out, const char *kind,
                    const char (*from)[64], size_t from_n, int realip,
                    const struct l4match *l4) {
    /* realip различает только доменные группы: у адресных резолвер не участвует. */
    int rip = realip && !strcmp(kind, "dom");
    int pd = l4_disc(sp, l4);
    /* Ветки без сужения оставлены КАК БЫЛИ, до последнего символа формата. От имени набора
     * зависит перенос счётчиков между применениями (см. counter_find в compile/generate.c), и
     * переименование стоило бы обнулённых объёмов у каждого канала на каждом установленном
     * роутере — при обновлении движка, которое для человека выглядит как «ничего не менял». */
    if (!pd) {
        if (!rip && from_same(from, from_n, sp->lan.from, sp->lan.from_n)) {
            snprintf(dst, n, "%.24s_%s", out, kind);
            return;
        }
        /* Выход обрезается сильнее, чтобы имя с суффиксом осталось коротким: у наборов
         * nftables на старых ядрах предел длины 32 символа. */
        snprintf(dst, n, "%.18s_%s_c%d%s", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
        return;
    }
    /* Выход обрезается ещё сильнее: суффиксов теперь два, а предел в 32 символа тот же. */
    snprintf(dst, n, "%.14s_%s_c%d%s_p%d", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", pd);
}

/* Имя СОСТАВНОГО набора канала со смешанным сужением (src/model/srsplan.c): у элементов свои
 * протокол и порты, поэтому сужения в имени нет — только выход, вид, клиенты и режим, как у
 * группы без сужения, и свой хвост «_m», чтобы с ней не совпасть. Выход обрезается до 16:
 * имя обязано уложиться в 31 символ (старые ядра). */
void group_set_name_mixed(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.16s_%s_c%d%s_m", out, kind, from_disc(sp, from, from_n), rip ? "r" : "");
}

/* Имя доп. группы канала — клауз набора с условиями, которых у канала нет (клиент, приложение,
 * исключения-подсети): номер id задаёт раскладка (номер канала * 100 + порядковый), и рядом с
 * ним остаётся место на «_x» набора исключений. */
void group_set_name_extra(const struct spec *sp, char *dst, size_t n, const char *out,
                          const char *kind, const char (*from)[64], size_t from_n, int realip,
                          unsigned id) {
    int rip = realip && !strcmp(kind, "dom");
    snprintf(dst, n, "%.12s_%s_c%d%s_e%u", out, kind, from_disc(sp, from, from_n),
             rip ? "r" : "", id);
}

/* Доменный набор с половиной IPv6 — объяснение у объявления в spec.h. Условия — те же, по
 * которым компилятор даёт группе v6-двойника (generate.c: out_v6_ok, who6_ok): выход несёт IPv6
 * или метки не ставит вовсе (direct), а «кто» выражается для IPv6 — устройством, MAC, адресом
 * IPv6, клиентами по умолчанию или владельцем сокета на телефоне («uid:N» — тоже с двоеточием,
 * как адрес IPv6, и у generate.c считается так же). Режим fake-IP ещё требует nat в семействе
 * IPv6: на старом ядре без NFTC_IP6NAT карты fakeip6 и её dnat поставить негде. */
int dom6_ok(const struct spec *sp, const struct output *o, const char (*from)[64], size_t from_n,
            int realip, int nftc) {
    if (out_needs_mark(o) && !out_has_cap(o, KC_IPV6)) return 0;
    /* IPv6 выхода снят (spec_v6_resolve): `ipv6: off` или выход рядом с донором. Отдельной
     * строкой ради direct — у него метки нет, и строка выше его не касается, а рядом с донором
     * IPv6 из префикса хоста напрямую не пускается (forward_v6), и адрес ему отвечать незачем. */
    if (o->v6_denied) return 0;
    int who = !from_n || spec_is_mac(from[0]) || from_same(from, from_n, sp->lan.from, sp->lan.from_n);
    for (size_t i = 0; i < from_n && !who; i++) who = strchr(from[i], ':') != NULL;
    if (!who) return 0;
    if (!realip && (nftc & NFTC_LEGACY) && !(nftc & NFTC_IP6NAT)) return 0;
    return 1;
}

/* ---- IPv6 от хоста (spec.h, enum out_ipv6) ------------------------------------------------- */

int v6pfx_parse(const char *s, struct v6pfx *p, char *why, size_t n) {
    memset(p, 0, sizeof(*p));
    char buf[64];
    const char *sl = strchr(s, '/');
    if (!sl || (size_t)(sl - s) >= sizeof(buf)) {
        snprintf(why, n, "«%s» — нужен префикс IPv6 с длиной, например 2001:db8:1::/56", s);
        return -1;
    }
    memcpy(buf, s, (size_t)(sl - s));
    buf[sl - s] = '\0';
    char *end = NULL;
    long len = strtol(sl + 1, &end, 10);
    struct in6_addr a;
    if (!sl[1] || *end || inet_pton(AF_INET6, buf, &a) != 1) {
        snprintf(why, n, "«%s» — не префикс IPv6 (нужно вида 2001:db8:1::/56)", s);
        return -1;
    }
    /* Не длиннее /64: из префикса хоста netifd выдаёт LAN куски по /64 (ip6assign), и SLAAC
     * клиентов работает только в /64 — префикс длиннее раздать нечем. */
    if (len < 1 || len > 64) {
        snprintf(why, n, "«%s» — длина префикса от 1 до 64 (сеть клиентов — /64, раздавать её "
                 "нужно из префикса не длиннее)", s);
        return -1;
    }
    memcpy(p->a, &a, 16);
    p->len = (unsigned char)len;
    struct v6pfx m = *p;
    uint8_t lo[16], hi[16];
    v6pfx_range(&m, lo, hi);
    if (memcmp(lo, p->a, 16) != 0) {
        char net[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, lo, net, sizeof(net));
        snprintf(why, n, "«%s» — у префикса ненулевые биты хоста: сеть этой длины — %s/%ld", s, net,
                 len);
        memset(p, 0, sizeof(*p));
        return -1;
    }
    /* Служебные диапазоны префиксом хоста не бывают: link-local, multicast, петля и пул fake-IP
     * v6 движка (fdfe:dcba:9876::/96 — его адреса клиенты видят как настоящие назначения). */
    static const uint8_t fake6[12] = { FAKEIP6_PREFIX_BYTES };
    if (IN6_IS_ADDR_LINKLOCAL(&a) || IN6_IS_ADDR_MULTICAST(&a) || IN6_IS_ADDR_UNSPECIFIED(&a) ||
        IN6_IS_ADDR_LOOPBACK(&a) || !memcmp(p->a, fake6, sizeof(fake6))) {
        snprintf(why, n, "«%s» — служебный диапазон, префиксом хоста он быть не может", s);
        memset(p, 0, sizeof(*p));
        return -1;
    }
    return 0;
}

/* КОМУ СНЯТЬ IPv6. `ipv6: off` — самому выходу. Рядом с донором (`ipv6: routed`) — всем, кроме
 * донора и выходов с `ipv6: nat`: у клиентов LAN адреса из префикса хоста, и такой адрес в любом
 * другом выходе ответа не получит (другой сервер WireGuard отбросит его по AllowedIPs, провайдер —
 * по BCP38). Поэтому IPv6 правил в другие выходы отвергается сразу (forward_v6 по метке, а у
 * direct — правило «источник из префикса не мимо донора»), имена под ними получают пустой AAAA
 * (dom6_ok), и клиент идёт по IPv4 в нужный выход. Выход с `ipv6: nat` рядом с донором IPv6 несёт
 * (masquerade), но адрес из префикса и туда не уходит — это держит правило в forward_v6; с ULA
 * клиенты туда ходят. Группа — такой же выход: она не донор, и IPv6 её правил снят (адрес из
 * префикса нельзя отдать члену, который не донор, а выбор члена меняется без замены набора правил).
 *
 * Спека без ключа ipv6 (и спека v1) — ни одному выходу ничего не снимается: поведение 1.9. */
void spec_v6_resolve(struct spec *sp) {
    const struct output *donor = spec_v6_donor(sp);
    for (size_t i = 0; i < sp->out_n; i++) {
        struct output *o = &sp->out[i];
        enum out_ipv6 m = out_ipv6_mode(o);
        o->v6_denied = m == OUT_V6_OFF || (donor && o != donor && m != OUT_V6_NAT);
    }
}

/* Поддельный адрес IPv6 из поддельного IPv4: префикс пула и адрес IPv4 в младших 32 битах. */
void fakeip6_of(uint32_t fake4_host, uint8_t out[16]) {
    static const uint8_t pfx[12] = { FAKEIP6_PREFIX_BYTES };
    memcpy(out, pfx, 12);
    out[12] = (uint8_t)(fake4_host >> 24);
    out[13] = (uint8_t)(fake4_host >> 16);
    out[14] = (uint8_t)(fake4_host >> 8);
    out[15] = (uint8_t)fake4_host;
}

/* Обратное: адрес IPv6 из пула — его поддельный IPv4 (0 — не из пула). */
uint32_t fakeip6_to4(const uint8_t a[16]) {
    static const uint8_t pfx[12] = { FAKEIP6_PREFIX_BYTES };
    if (memcmp(a, pfx, 12) != 0) return 0;
    uint32_t v = ((uint32_t)a[12] << 24) | ((uint32_t)a[13] << 16) | ((uint32_t)a[14] << 8) | a[15];
    return (v & 0xfffe0000u) == 0xc6120000u ? v : 0;
}

/* «адрес:порт» → адрес и порт. Живёт здесь, а не в obfs.c, потому что нужен обоим:
 * парсеру спеки при чтении и обфускатору при разборе своих аргументов, а линкуются
 * они всегда вместе. Порт по последнему двоеточию — чтобы форма не мешала будущему
 * IPv6-литералу. */
int obfs_split_hostport(const char *s, char *host, size_t hn, int *port) {
    const char *colon = strrchr(s, ':');
    if (!colon || colon == s) return -1;
    size_t hl = (size_t)(colon - s);
    if (hl + 1 > hn) return -1;
    memcpy(host, s, hl);
    host[hl] = '\0';
    char *end = NULL;
    long p = strtol(colon + 1, &end, 10);
    if (!end || *end || p < 1 || p > 65535) return -1;
    *port = (int)p;
    return 0;
}

/* Есть ли на верхнем уровне JSON-объекта ключ key. Читается только верхний уровень (значения
 * пропускаются js_skip), до первой неувязки: на битом тексте ответ — «что успели увидеть». Нужна
 * выбору формата, и дешевле разбора в дерево: v1 читают на каждый status. */
static int json_top_key(const char *text, const char *key) {
    struct err scratch = {0};
    struct js j = { text };
    if (js_lit(&j, '{') != 0) return 0;
    js_ws(&j);
    while (*j.p && *j.p != '}') {
        char k[64];
        if (js_str(&j, k, sizeof(k), &scratch) != 0 || js_lit(&j, ':') != 0) return 0;
        if (!strcmp(k, key)) return 1;
        if (js_skip(&j, &scratch) != 0) return 0;
        js_ws(&j);
        if (*j.p != ',') return 0;
        j.p++;
        js_ws(&j);
    }
    return 0;
}

static int spec_defaults(struct spec *s) {
    /* Прежняя загрузка в этот же экземпляр (цикл демона) отдаётся здесь, а не оставляется на
     * вызывающего: спека владеет своими массивами (spec.h, «память спеки»). */
    spec_release(s);
    s->lan_dev = (char (*)[64])spec_alloc(s, sizeof(*s->lan_dev));
    if (!s->lan_dev) return -1;
    snprintf(s->lan_dev[0], sizeof(s->lan_dev[0]), "br-lan");
    s->lan_dev_n = 1;
    return 0;
}

/* Спека v2 из текста: дерево YAML (JSON читается им же) и разбор v2. */
static int load_v2(const char *buf, size_t n, const char *name, struct spec *s, struct err *e) {
    struct ydoc *d = ydoc_parse_buf(buf, n, name, e);
    if (!d) return -1;
    const struct ynode *root = ydoc_root(d);
    int rc;
    if (root && root->kind == YN_MAP && !ynode_get(root, "version") && ynode_get(root, "schema"))
        rc = ynode_err(e, d, ynode_get(root, "schema"), "%s", "спека v1 пишется JSON-объектом "
                       "({\"schema\": 1, …}); спека YAML — это v2, и начинается она с version: 2");
    else if (root && root->kind == YN_MAP && !ynode_get(root, "version"))
        rc = ynode_err(e, d, root, "%s", "нет version: 2 — спека YAML — это спека v2 "
                       "(docs/spec-v2.md); спека v1 — JSON-объект со schema");
    else
        rc = spec_parse_v2(d, s, e);
    ydoc_free(d);
    return rc;
}

/* ФАЙЛ СПЕКИ ПО УМОЛЧАНИЮ: spec.json или spec.yaml рядом (plat_spec_default). Обе сразу — отказ,
 * а не правило старшинства: какая из двух настоящая, знает только тот, кто их положил, и
 * молча читать одну значило бы, что правки во второй не действуют, а понять это нечем. Так же
 * устроены device/devices и lan_device/lan_devices в v1. Путь, названный явно (--spec), кроме
 * этих двух, читается как есть. */
static int spec_pick_default(const char **path, struct err *e) {
    const char *js = plat()->spec_path, *ym = plat_spec_yaml();
    if (strcmp(*path, js) != 0 && strcmp(*path, ym) != 0) return 0;
    int hj = access(js, F_OK) == 0, hy = access(ym, F_OK) == 0;
    if (hj && hy) {
        char msg[640];
        snprintf(msg, sizeof(msg), "две спеки: %.255s и %.255s — ядро не выбирает между ними, "
                 "оставьте одну", js, ym);
        return err_set(e, "%s", msg);
    }
    if (!strcmp(*path, js) && !hj && hy) *path = ym;
    return 0;
}

#define SPEC_TEXT_MAX (16 << 20)
static int load_text(char *buf, size_t n, const char *path, struct spec *s, struct err *e);

int load_spec(const char *path, struct spec *s, struct err *e) {
    /* Спека — значение (правило 6): экземпляр обнуляется здесь, а не оставляется на
     * совести вызывающего, и получает те же умолчания, что раньше стояли инициализаторами
     * глобалов — один br-lan клиентским устройством, всё остальное пусто/нуль. */
    if (spec_defaults(s) != 0) return err_set(e, "%s", "недостаточно памяти для спеки");
    if (spec_pick_default(&path, e) != 0) return -1;
    FILE *f = strcmp(path, "-") ? fopen(path, "r") : stdin;
    if (!f) return err_set(e, "%s: cannot open", path);
    /* Текст читается в кучу по мере надобности (раньше — статический буфер в 256 КиБ, то есть
     * 256 КиБ bss ради спеки, которая занимает полкилобайта). Потолок — 16 МиБ: столько же,
     * сколько принимает ctl (CTL_FILE_MAX), — защита от файла-невпопад (лог вместо спеки), а не
     * размер спеки: спека на тысячи правил — сотни килобайт. */
    size_t cap = 16384, n = 0;
    char *buf = malloc(cap);
    if (!buf) { if (f != stdin) fclose(f); return err_set(e, "%s", "недостаточно памяти для спеки"); }
    for (;;) {
        if (n + 1 >= cap) {
            if (cap >= SPEC_TEXT_MAX) {
                free(buf);
                if (f != stdin) fclose(f);
                return err_set(e, "%s", "spec too large (max 16 MiB)");
            }
            char *nb = realloc(buf, cap * 2);
            if (!nb) { free(buf); if (f != stdin) fclose(f); return err_set(e, "%s", "недостаточно памяти для спеки"); }
            buf = nb;
            cap *= 2;
        }
        size_t got = fread(buf + n, 1, cap - 1 - n, f);
        if (!got) break;
        n += got;
    }
    buf[n] = '\0';
    if (f != stdin) fclose(f);
    int rc = load_text(buf, n, path, s, e);
    free(buf);
    return rc;
}

static int load_text(char *buf, size_t n, const char *path, struct spec *s, struct err *e) {
    /* ФОРМАТ — ПО СОДЕРЖИМОМУ, а не по имени файла: ctl apply кладёт тело в тот файл, который
     * сейчас спека, каким бы форматом тело ни было записано.
     *
     *   - текст начинается с `{` (JSON-объект) или пуст: ключ `version` наверху — спека v2
     *     (JSON тоже YAML); иначе — спека v1, с прежними отказами разбора v1 слово в слово
     *     (их сверяет снимок генератора). И `version`, и `schema` — отказ: это два формата;
     *   - всё остальное — YAML, то есть спека v2.
     * Одна поблажка: потоковый YAML `{version: 2, …}` (ключи без кавычек) начинается со скобки,
     * а JSON-разбор его не прочтёт. Если v1 отказал, `schema` наверху нет, а слово version в
     * тексте есть, — ответ даёт разбор v2. */
    const char *p = buf;
    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') p++;
    const char *name = strcmp(path, "-") ? path : "stdin";
    if (*p == '{' || !*p) {
        int ver = json_top_key(p, "version"), sch = json_top_key(p, "schema");
        if (ver && sch)
            return err_set(e, "в спеке и version, и schema — это два формата (version: 2 — спека v2, "
                           "schema — v1); оставьте одно", NULL);
        if (!ver) {
            int rc = spec_parse_v1(buf, s, e);
            if (rc == 0 || sch || !strstr(buf, "version")) return rc;
            if (spec_defaults(s) != 0) return err_set(e, "%s", "недостаточно памяти для спеки");
            e->msg[0] = '\0';
        }
    }
    return load_v2(buf, n, name, s, e);
}

struct output *out_by_name(const struct spec *sp, const char *n) {
    /* Возврат — НЕ const: правило 6 просит sp константным параметром (эта функция только
     * ищет), а вызывающие с изменяемой спекой (load_spec, registry_assign) правят найденный
     * выход дальше — тем же способом, каким это делал g_out[i] до перехода на struct spec.
     * Приведение снимает константность указателя, а не массива за ним: массив мутабелен
     * ровно тогда, когда мутабелен *sp у вызывающего. */
    for (size_t i = 0; i < sp->out_n; i++)
        if (!strcmp(sp->out[i].name, n)) return (struct output *)&sp->out[i];
    return NULL;
}


/* ---- что такое строка списка -------------------------------------------------------
 *
 * ЖИВЁТ ЗДЕСЬ, А НЕ В КОМПИЛЯТОРЕ, потому что читателей стало двое. Компилятор набора правил
 * берёт из файла адресные строки (emit_elements в compile/print.c), резолвер — доменные
 * (ruleset_add в dnsd/rules.c), и с гибридными списками они читают ОДИН И ТОТ ЖЕ файл. Две копии этого правила означали бы
 * строку, которую не взял никто, или строку, которую взяли оба, — и ни то ни другое не
 * заметно снаружи: набор соберётся, резолвер запустится, а часть списка просто не будет
 * действовать.
 *
 * Проверяется ФОРМА, а не значения октетов: `1.1.1.1` и `8.8.8.0/24` адреса, `youtube.com`
 * нет. Строка вроде `123.456.789.0` формой проходит, а адресом не является — её отвергнет
 * nft, и это правильное место для такого отказа: там она названа по имени, а угадывать
 * здесь значило бы завести второй разборщик адресов рядом с ядерным. */
static int addr_half_ok(const char *s, const char *end) {
    int digits = 0, dots = 0, slash = 0;
    for (const char *p = s; p < end; p++) {
        if (*p >= '0' && *p <= '9') { digits++; continue; }
        if (*p == '.') { dots++; continue; }
        if (*p == '/') { slash++; continue; }
        return 0;                       /* буква, двоеточие — это не IPv4 */
    }
    return digits > 0 && dots == 3 && slash <= 1;
}

/* Половина IPv6: адрес с необязательной длиной префикса «/0-128» (with_len), без длины — у
 * половин диапазона «a-b». Здесь, в отличие от IPv4, проверка НЕ по форме, а разбором
 * (inet_pton): запись IPv6 со сжатием «::» и хвостом в точечной записи форме «цифры и
 * двоеточия» не опишешь без второго разборщика, а строк IPv6 в списках на порядки меньше, чем
 * IPv4, — цена разбора не заметна. Двоеточие обязательно: MAC («aa:bb:cc:dd:ee:ff») адресом
 * IPv6 не разбирается (шесть групп без «::»), и спутать их нельзя. */
static int addr6_half_ok(const char *s, const char *end, int with_len) {
    char buf[64];
    size_t n = (size_t)(end - s);
    if (n == 0 || n >= sizeof(buf)) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    if (!strchr(buf, ':')) return 0;
    char *sl = strchr(buf, '/');
    if (sl) {
        if (!with_len) return 0;
        *sl = '\0';
        char *e = NULL;
        long len = strtol(sl + 1, &e, 10);
        if (e == sl + 1 || *e || len < 0 || len > 128) return 0;
    }
    struct in6_addr a;
    return inet_pton(AF_INET6, buf, &a) == 1;
}

/* Диапазон здесь обязателен, и это не расширение ради полноты: `steer fit` сам ВЫДАЁТ
 * диапазоны — два соседних адреса, не складывающихся в выровненный префикс, объединяются
 * именно так (emit_range в aggregate.c). Раньше дефис отвергался, поэтому подогнанный
 * список, поданный каналу, терял такие строки целиком. */
/* Одиночный хозяин: адрес без маски, адрес с /32 или MAC. Всё остальное — подсеть или не
 * адрес вовсе.
 *
 * Нужно правилу на устройство: приоритет там даётся ОДНОМУ хозяину, и подсеть в этом месте
 * означала бы приоритет для всех в ней. Проверяется форма, а не значения октетов, — по той
 * же причине, что у spec_line_is_addr ниже. */
int spec_one_host(const char *s) {
    if (!s || !*s) return 0;
    /* MAC: шесть пар шестнадцатеричных через двоеточие. */
    if (spec_is_mac(s)) return 1;
    /* IPv6 (с 1.9): адрес без длины или /128. Раньше любое двоеточие считалось MAC-ом, и
     * подсеть IPv6 проходила бы здесь как одиночный хозяин. */
    if (strchr(s, ':')) {
        if (spec_line_family(s) != 6 || strchr(s, '-')) return 0;
        const char *l = strchr(s, '/');
        return !l || !strcmp(l, "/128");
    }
    const char *sl = strchr(s, '/');
    if (sl && strcmp(sl, "/32") != 0) return 0;
    char buf[64];
    size_t n = sl ? (size_t)(sl - s) : strlen(s);
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, s, n);
    buf[n] = '\0';
    return spec_line_is_addr(buf) && !strchr(buf, '-');
}

int from_is_local(const char *s) {
    return s && (!strcmp(s, "self") || !strncmp(s, "uid:", 4));
}

int from_uid_range(const char *s, unsigned *lo, unsigned *hi) {
    if (!s || strncmp(s, "uid:", 4)) return -1;
    const char *p = s + 4;
    unsigned long a, b;
    char *end;
    if (*p < '0' || *p > '9') return -1;
    a = strtoul(p, &end, 10);
    if (*end == '-') {
        p = end + 1;
        if (*p < '0' || *p > '9') return -1;
        b = strtoul(p, &end, 10);
    } else {
        b = a;
    }
    /* UID ядра — 32 бита, но (uid_t)-1 означает «нет» и в правило попадать не должен. */
    if (*end || a > 0x7fffffffUL || b > 0x7fffffffUL || a > b) return -1;
    *lo = (unsigned)a;
    *hi = (unsigned)b;
    return 0;
}

/* Семейство адресной строки (docs/architecture.md, «4б»): 4 — IPv4 (адрес, подсеть, диапазон),
 * 6 — IPv6 (то же), 0 — не адрес (доменное правило, мусор). До 1.9 строки IPv6 адресами не
 * считались вовсе: компилятор их пропускал, а резолвер брал доменным правилом, которое не
 * совпадало ни с чем. Теперь они идут в парный набор ipv6_addr, а резолвер их не трогает. */
int spec_line_family(const char *s) {
    const char *dash = strchr(s, '-');
    const char *end = s + strlen(s);
    if (!dash) return addr_half_ok(s, end) ? 4 : addr6_half_ok(s, end, 1) ? 6 : 0;
    /* Ровно один дефис, и обе половины — адреса одного семейства. */
    if (strchr(dash + 1, '-')) return 0;
    if (addr_half_ok(s, dash) && addr_half_ok(dash + 1, end)) return 4;
    if (addr6_half_ok(s, dash, 0) && addr6_half_ok(dash + 1, end, 0)) return 6;
    return 0;
}

int spec_line_is_addr(const char *s) {
    return spec_line_family(s) != 0;
}

/* MAC-адрес: шесть групп по одной-две шестнадцатеричные цифры через двоеточие. Группы
 * проверяются на длину — иначе «a::b:c:d:e» (пять двоеточий, законный IPv6) сошёл бы за MAC. */
int spec_is_mac(const char *s) {
    int groups = 0, len = 0;
    for (const char *p = s; ; p++) {
        if (*p == ':' || *p == '\0') {
            if (len < 1 || len > 2) return 0;
            groups++;
            len = 0;
            if (!*p) break;
            continue;
        }
        if (!((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') || (*p >= 'A' && *p <= 'F')))
            return 0;
        len++;
    }
    return groups == 6;
}

/* ---- пользуется ли резолвер апстримом (spec.h) --------------------------------------------- */

/* Назначение (номер плюс один) ведёт к апстриму u: это он сам или группа, где он член. */
static int dns_ref_hits(const struct spec *sp, unsigned ref, size_t u) {
    if (!ref || ref > sp->dns.up_n) return 0;
    if (ref == u + 1) return 1;
    const struct spec_dns_up *g = &sp->dns.up[ref - 1];
    for (size_t k = 0; g->grp && k < g->mem_n; k++)
        if (g->mem[k] == u) return 1;
    return 0;
}

int spec_dns_up_used(const struct spec *sp, size_t u) {
    if (dns_ref_hits(sp, sp->dns.general, u) || dns_ref_hits(sp, sp->dns.other, u)) return 1;
    for (size_t r = 0; r < sp->rule_n; r++)
        if (!sp->rule[r].disabled && dns_ref_hits(sp, sp->rule[r].dns, u)) return 1;
    return 0;
}

/* ---- адрес апстрима DNS (dns.upstreams, docs/spec-v2.md) ---------------------------------------
 *
 * Схема выбирает транспорт, и только она: `https://` — DoH (RFC 8484), `tls://` — DoT (RFC 7858),
 * `udp://` и `tcp://` — обычный DNS, `quic://` — DoQ (RFC 9250, порт 853 по UDP, ALPN `doq`), `h3://` — DoH по HTTP/3 (RFC 9114, порт 443 по UDP, ALPN `h3`). Так же
 * пишут DoQ AdGuard (dnsproxy, AdGuard Home) и sing-box (`quic://dns.adguard-dns.com`); Xray для
 * него пишет `quic+local://`, а `doq://` — не схема ни у одного из этих клиентов, поэтому её нет и
 * здесь. Имя в quic:// и tls:// — одного рода: SNI и проверка сертификата идут по нему, а адрес
 * находят `ips` или bootstrap.
 *
 * Имя или адрес сервера — до первого `:` или `/`; адрес IPv6 пишется в скобках, как в любом URL.
 * Для udp:// и tcp:// нужен адрес, а не имя: обычный DNS на имя потребовал бы разрешить его тем же
 * обычным DNS, то есть тем самым системным резолвером, от которого bootstrap и отвязывает
 * апстрим. Путь есть только у DoH и DoH3 (умолчание /dns-query, как у dns.google и cloudflare-dns.com).
 * Порт по умолчанию — у протокола: 53, 853, 443. Разбор один и тот же у спеки (demon) и у
 * резолвера: последнему демон передаёт адрес строкой, и разойтись им нечем. */
int dnsurl_parse(const char *url, struct spec_dns_up *u, char *why, size_t why_n) {
    static const struct { const char *scheme; int proto; unsigned short port; } S[] = {
        { "udp://", DNSP_UDP, 53 }, { "tcp://", DNSP_TCP, 53 }, { "tls://", DNSP_DOT, 853 },
        { "https://", DNSP_DOH, 443 }, { "quic://", DNSP_QUIC, 853 },
        { "h3://", DNSP_DOH3, 443 },
    };
    u->proto = DNSP_NONE;
    size_t k = 0;
    for (; k < sizeof(S) / sizeof(S[0]); k++)
        if (!strncmp(url, S[k].scheme, strlen(S[k].scheme))) break;
    if (k == sizeof(S) / sizeof(S[0])) {
        snprintf(why, why_n, "нужен адрес вида https://… (DoH), tls://… (DoT), quic://… (DoQ), h3://… (DoH по HTTP/3), udp://… или tcp://…");
        return -1;
    }
    const char *p = url + strlen(S[k].scheme);
    char host[128];
    size_t hn = 0;
    if (*p == '[') {
        const char *e = strchr(p, ']');
        if (!e || e == p + 1 || (size_t)(e - p) > sizeof(host)) {
            snprintf(why, why_n, "адрес IPv6 в скобках не разобрался");
            return -1;
        }
        hn = (size_t)(e - p - 1);
        memcpy(host, p + 1, hn);
        p = e + 1;
    } else {
        while (p[hn] && p[hn] != ':' && p[hn] != '/') hn++;
        if (!hn || hn >= sizeof(host)) {
            snprintf(why, why_n, "нет имени сервера");
            return -1;
        }
        memcpy(host, p, hn);
        p += hn;
    }
    host[hn] = '\0';
    long port = S[k].port;
    if (*p == ':') {
        char *end;
        port = strtol(p + 1, &end, 10);
        if (end == p + 1 || port < 1 || port > 65535 || (*end && *end != '/')) {
            snprintf(why, why_n, "порт — число от 1 до 65535");
            return -1;
        }
        p = end;
    }
    const char *path = "/dns-query";
    if (*p == '/') {
        if (S[k].proto != DNSP_DOH && S[k].proto != DNSP_DOH3) {
            snprintf(why, why_n, "путь есть только у https:// и h3://");
            return -1;
        }
        path = p;
    } else if (*p) {
        snprintf(why, why_n, "лишнее после адреса: «%s»", p);
        return -1;
    }
    if (strlen(path) >= sizeof(u->path)) {
        snprintf(why, why_n, "путь длиннее %zu байт", sizeof(u->path) - 1);
        return -1;
    }
    for (const char *c = host; *c; c++)
        if ((unsigned char)*c <= ' ' || *c == '|' || *c == ',' || *c == '"') {
            snprintf(why, why_n, "недопустимый символ в имени сервера");
            return -1;
        }
    struct in6_addr a;
    int lit = inet_pton(AF_INET, host, &a) == 1 || inet_pton(AF_INET6, host, &a) == 1;
    if ((S[k].proto == DNSP_UDP || S[k].proto == DNSP_TCP) && !lit) {
        snprintf(why, why_n, "для %s нужен адрес, а не имя: обычный DNS не может сам разрешить имя своего "
                 "сервера", S[k].scheme);
        return -1;
    }
    u->proto = (unsigned char)S[k].proto;
    u->port = (unsigned short)port;
    snprintf(u->host, sizeof(u->host), "%s", host);
    snprintf(u->path, sizeof(u->path), "%s", S[k].proto == DNSP_DOH || S[k].proto == DNSP_DOH3 ? path : "");
    return 0;
}
