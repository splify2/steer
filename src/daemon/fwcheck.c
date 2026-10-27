#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <ifaddrs.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "daemon.h"
#include "kind.h"
#include "nftdump.h"

/* ---- what an interface output depends on, and does not own ----------------- */
/* steer does not touch the firewall. It has no business rewriting someone's zones
 * or adding masquerade rules — that is the operator's configuration, and a routing
 * engine silently editing it is how two tools start fighting over one ruleset.
 *
 * But an interface output cannot work without it: packets leaving a tunnel with LAN
 * source addresses never come back, so the route looks applied, the channel counter
 * even rises, and every site behind it simply hangs. That failure is invisible from
 * inside steer's own state — which is exactly why it must be REPORTED.
 *
 * ОДНО ЯВНОЕ ИСКЛЮЧЕНИЕ (шаг 8 выпуска 1.10, решение владельца): у выхода с `ipv6: nat`
 * masquerade IPv6 на его устройство ставит сам движок — в СВОЕЙ таблице (цепочка
 * postrouting_nat6, compile/generate.c: build_nat6) и только по этому ключу спеки. Зоны fw4 он
 * по-прежнему не трогает, и проверки ниже свою таблицу не читают: подмену IPv6 такого выхода
 * diag засчитывает по ключу, а не по дампу (docs/contract-v1.md, §7).
 *
 * Both checks are textual and deliberately conservative: a false "looks fine" is
 * worse than a false warning, so anything unrecognised reads as missing. */


/* Is DEVICE named here as a whole token? Substring matching is not good enough in
 * either direction: looking for it quoted missed fw4 entirely (see below), while a
 * bare substring would let "warp" answer for "warp0". */
static int names_device(const char *hay, const char *device) {
    size_t n = strlen(device);
    for (const char *p = strstr(hay, device); p; p = strstr(p + 1, device)) {
        char before = p == hay ? ' ' : p[-1];
        char after = p[n];
        int lb = (before >= 'a' && before <= 'z') || (before >= 'A' && before <= 'Z')
                 || (before >= '0' && before <= '9');
        int la = (after >= 'a' && after <= 'z') || (after >= 'A' && after <= 'Z')
                 || (after >= '0' && after <= '9');
        if (!lb && !la) return 1;
    }
    return 0;
}

/* Имя цепочки — первое слово: и в заголовке (`chain srcnat_vpn {`), и в переходе
 * (`jump srcnat_vpn comment ...`) оно стоит первым и кончается пробелом или скобкой. */
static void chain_token(const char *s, char *out, size_t cap) {
    size_t i = 0;
    while (*s == ' ' || *s == '\t') s++;
    while (i + 1 < cap && s[i] && s[i] != ' ' && s[i] != '\t' && s[i] != '\n'
           && s[i] != '{' && s[i] != ';')
        out[i] = s[i], i++;
    out[i] = 0;
}

/* Зона fw4 по имени её цепочки подмены: fw4 зовёт её srcnat_<зона> (шаблон zone-masq.uc). Не
 * такое имя — цепочка не зоны fw4 (своя таблица человека), и зону не назвать: out пуст. */
static void zone_of_chain(const char *tok, char *out, size_t n) {
    if (!strncmp(tok, "srcnat_", 7) && tok[7]) snprintf(out, n, "%s", tok + 7);
}

/* Имена цепочек, растущий список без повторов: у fw4 на роутере с десятками зон их больше
 * шестнадцати (раньше — таблица на 16, и цепочка сверх неё теряла masquerade выхода). */
struct fwc_chains { char **v; size_t n, cap; };

static void remember_chain(struct fwc_chains *t, const char *name) {
    if (!*name) return;
    for (size_t i = 0; i < t->n; i++)
        if (!strcmp(t->v[i], name)) return;
    if (t->n == t->cap) {
        size_t cap = t->cap ? t->cap * 2 : 16;
        char **g = realloc(t->v, cap * sizeof(*g));
        if (!g) return;
        t->v = g;
        t->cap = cap;
    }
    char *d = strdup(name);
    if (d) t->v[t->n++] = d;
}

static void chains_free(struct fwc_chains *t) {
    for (size_t i = 0; i < t->n; i++) free(t->v[i]);
    free(t->v);
}

/* Два дампа набора правил, у каждого свой кэш на процесс.
 *
 * ТЕКСТ ОТ ЯДРА ПО NETLINK (nl_dump) — для fw_check, то есть для status и diag. status интерфейс
 * опрашивает раз в несколько секунд, и `sh -c nft -t list ruleset` на каждый вызов — два
 * процесса ради одного вопроса (docs/architecture.md, «4а», «Сокет и протокол»). Текст
 * собирает src/lib/nftdump.c в форме `nft -t list ruleset` — ровно в объёме того, что читает
 * fw_check ниже, — и разбор остаётся одним: тем, что закрыт стендом fwmatch на дампах с живого
 * fw4. Стенд же сверяет, что оба текста дают fw_check один ответ на наборе правил в ядре.
 *
 * ТЕКСТ ОТ `nft` (nft_dump) — для предупреждений apply (traceroute_hops, соседи на битах 16-23):
 * им нужны числа масок и `ct state untracked` в той форме, как их печатает nft, а apply и без
 * того работает детьми с `nft -f`. Переводить их на netlink значило бы повторить печать nft
 * целиком ради того, что читается раз на применение.
 *
 * Кэш корректен потому, что все читатели работают ПОСЛЕ любых изменений набора правил в этом же
 * процессе: в apply отчёты идут после `nft -f`, а status/diag ruleset не трогают; демон
 * сбрасывает кэш перед каждым ответом (fwcheck_reset_cache).
 *
 * Кэш всегда либо NULL, либо получен malloc'ом: tests/fwmatch.c сбрасывает его между
 * пробами через fwcheck_reset_cache(), изображая свежий процесс на каждую пробу. */
static char *g_nft_dump, *g_nl_dump;

/* Сброс кэша дампа — единственное, что стенду нужно от него самого, а не через fw_check().
 * Кэши — static (правило юнит-стендов, docs/architecture.md, раздел 4: только то, что
 * пересекает границу файла, выходит из static, и то функцией, а не голым указателем). */
void fwcheck_reset_cache(void) {
    free(g_nft_dump);
    g_nft_dump = NULL;
    free(g_nl_dump);
    g_nl_dump = NULL;
}

static const char *nl_dump(void) {
    if (g_nl_dump) return g_nl_dump;
    g_nl_dump = nfd_ruleset_text();
    /* Ядро не ответило (нет прав, нет nf_tables) — пустой текст, как у nft, которому нечего
     * напечатать: обе проверки тогда честно говорят «не видно». Пустой — тоже в кэш. */
    if (!g_nl_dump) g_nl_dump = calloc(1, 1);
    return g_nl_dump ? g_nl_dump : "";
}

static const char *nft_dump(void) {
    if (g_nft_dump) return g_nft_dump;
    size_t cap = 65536, n = 0;
    char *buf = malloc(cap);
    if (!buf) return ""; /* не кэшируем — следующий вызов попробует снова */
    FILE *f = popen("nft -t list ruleset 2>/dev/null || "
                    "nft list ruleset 2>/dev/null", "r");
    if (!f) { buf[0] = '\0'; return g_nft_dump = buf; }
    for (;;) {
        if (n + 4096 + 1 > cap) {
            char *nb = realloc(buf, cap *= 2);
            if (!nb) break; /* сколько влезло — с тем и работаем */
            buf = nb;
        }
        size_t r = fread(buf + n, 1, 4096, f);
        if (!r) break;
        n += r;
    }
    pclose(f);
    buf[n] = '\0';
    return g_nft_dump = buf;
}

/* Следующая «строка» кэша с семантикой fgets: длинная строка выдаётся кусками
 * по cap-1 — читатели ниже написаны в этих терминах. Возвращает позицию
 * продолжения или NULL в конце. */
static const char *dump_line(const char *p, char *line, size_t cap) {
    if (!p || !*p) return NULL;
    size_t len = 0;
    while (len < cap - 1 && p[len] && p[len] != '\n') len++;
    if (len < cap - 1 && p[len] == '\n') len++;
    memcpy(line, p, len);
    line[len] = '\0';
    return p + len;
}

struct fwcheck fw_check(const char *device) {
    return fw_check_dump(nl_dump(), device);
}

/* Семейства правила подмены — битами: 1 — IPv4, 2 — IPv6.
 *
 * ПО СЕМЕЙСТВАМ (с 1.10, шаг 8). fw4 пишет masquerade зоны правилом на семейство: `meta nfproto
 * ipv4 masquerade` — это masq зоны, `meta nfproto ipv6 masquerade` — masq6 (шаблон
 * zone-masq.uc). Прежде проверка засчитывала любое такое правило за оба семейства, и выход с одним
 * masq6 получал «NAT есть» для IPv4 (а с одним masq — для IPv6, которого нет). Выход, несущий
 * IPv6, без подмены IPv6 отправляет в туннель адреса клиентов как есть — и ответ не вернётся,
 * если хост их не маршрутизует; ровно это diag и должен называть отдельно.
 *
 * Откуда семейство: слово `nfproto ipv4|ipv6` в правиле (его печатает и nft, и текст от ядра —
 * nftdump.c), иначе адреса в правиле (`ip saddr`, `ip6 daddr` — у nft зависимость от семейства не
 * печатается), иначе семейство таблицы: ip — IPv4, ip6 — IPv6, inet — оба. Правило без семейства в
 * inet (`oifname "wg0" masquerade`, как пишут руками) подменяет оба — так его и считаем. */
static unsigned rule_fams(const char *line, unsigned table_fams) {
    if (strstr(line, "nfproto ipv4")) return 1;
    if (strstr(line, "nfproto ipv6")) return 2;
    if (strstr(line, "ip6 saddr") || strstr(line, "ip6 daddr") || strstr(line, "snat ip6 to"))
        return 2;
    if (strstr(line, "ip saddr") || strstr(line, "ip daddr") || strstr(line, "snat ip to"))
        return 1;
    return table_fams;
}

static unsigned table_fams_of(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (!strncmp(p, "table ip6 ", 10)) return 2;
    if (!strncmp(p, "table ip ", 9)) return 1;
    return 3;
}

struct fwcheck fw_check_dump(const char *dump, const char *device) {
    struct fwcheck r;
    memset(&r, 0, sizeof(r));
    /* Зона может называться не так, как устройство, и тогда оба признака ниже молчат:
     * fw4 пишет имя ЗОНЫ и в имя цепочки (`srcnat_vpn`), и в комментарий правила
     * ("Masquerade IPv4 vpn traffic"), а устройство называет ТОЛЬКО на переходе в эту
     * цепочку: `oifname "warp0" jump srcnat_vpn`. Снято с fw4 25.12: при зоне с именем,
     * отличным от имени устройства, во всём наборе нет ни одной строки, где устройство
     * стояло бы рядом со словом masquerade, — и выход получал «нет masquerade» при
     * включённом masq (splicicd#8). Поэтому цепочка, в которую устройство уходит по oif,
     * засчитывается вместе со своим содержимым. Порядок строк не предполагается: дамп
     * может назвать цепочку и до перехода, и после, поэтому оба множества собираются за
     * один проход и пересекаются в конце. */
    /* Цепочки с подменой — по семейству отдельно (masq_chain[0] — IPv4, [1] — IPv6): у зоны fw4 в
     * одной цепочке srcnat_<зона> бывает одно правило, другое или оба. */
    struct fwc_chains dev_chain = {0}, masq_chain[2] = {{0}, {0}};
    unsigned tfams = 3;
    /* Без содержимого именованных наборов (как у `nft -t`): проверка смотрит на имена
     * устройств в правилах и цепочках, а элементы наборов ей не нужны — при этом их бывают
     * десятки тысяч, и полный дамп на слабом роутере стоил секунды НА КАЖДЫЙ ВЫЗОВ. */
    const char *pos = dump;
    char line[2048];
    char chain[128] = "";
    int in_steer = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
        /* Our own table mentions the device too; it proves nothing about NAT. */
        {
            char want[80];
            snprintf(want, sizeof(want), "table inet %s", nft_table());
            if (strstr(line, want)) in_steer = 1;
            else if (!strncmp(line, "table ", 6)) in_steer = 0;
        }
        if (!strncmp(line, "table ", 6)) tfams = table_fams_of(line);
        if (in_steer) continue;

        const char *c = strstr(line, "chain ");
        if (c) snprintf(chain, sizeof(chain), "%s", c + 6);

        if (names_device(line, device)) r.in_firewall = 1;
        /* fw4 does NOT name the device on the masquerade rule: it emits
         * `chain srcnat_warp0 { meta nfproto ipv4 masquerade comment "...warp0..." }`
         * and matches the device on the jump into that chain. Checking only the rule
         * line reported "no NAT" on a router whose NAT was working fine — a false
         * alarm that sent me diagnosing the wrong thing. So the enclosing chain name
         * counts as evidence too. */
        /* Переход, на котором названо устройство: `oifname "warp0" jump srcnat_vpn`.
         * Требование oif намеренное — masquerade живёт на выходе, и переход по входящему
         * устройству (dstnat) про NAT наружу не говорит ничего. */
        const char *j = strstr(line, "jump ");
        if (j && strstr(line, "oif") && names_device(line, device)) {
            char t[64];
            chain_token(j + 5, t, sizeof t);
            remember_chain(&dev_chain, t);
        }
        if (strstr(line, "masquerade") || strstr(line, "snat")) {
            unsigned f = rule_fams(line, tfams);
            if (names_device(line, device) || names_device(chain, device)) {
                if (f & 1) r.masqueraded = 1;
                if (f & 2) {
                    r.masq6 = 1;
                    /* Устройство названо именем цепочки (зона зовётся как устройство:
                     * srcnat_wg0) — это и есть зона; названо в самом правиле — зоны нет. */
                    if (!r.zone6[0] && !names_device(line, device)) {
                        char t[64];
                        chain_token(chain, t, sizeof t);
                        zone_of_chain(t, r.zone6, sizeof(r.zone6));
                    }
                }
            } else {
                char t[64];
                chain_token(chain, t, sizeof t);
                for (int k = 0; k < 2; k++)
                    if (f & (1u << k)) remember_chain(&masq_chain[k], t);
            }
        }
    }
    for (int fam = 0; fam < 2; fam++) {
        int *got = fam ? &r.masq6 : &r.masqueraded;
        for (size_t i = 0; i < dev_chain.n && !*got; i++)
            for (size_t k = 0; k < masq_chain[fam].n; k++)
                if (!strcmp(dev_chain.v[i], masq_chain[fam].v[k])) {
                    *got = 1;
                    if (fam) zone_of_chain(dev_chain.v[i], r.zone6, sizeof(r.zone6));
                    break;
                }
    }
    chains_free(&dev_chain);
    chains_free(&masq_chain[0]);
    chains_free(&masq_chain[1]);
    return r;
}

/* Только на платформе с fw4 (plat()->fw4) — см. конец cmd_apply. */
void report_traceroute_dep(const struct spec *sp) {
    if (!sp->traceroute_hops) return;
    /* Say the useless case out loud rather than leaving the operator to discover it
     * as a column of asterisks. */
    for (size_t i = 0; i < sp->out_n; i++) {
        if (!out_has_device(&sp->out[i])) continue;
        if (fw_check(sp->out[i].device).masqueraded) {
            fprintf(stderr, LOG_W "traceroute_hops не сработает для выхода %s: %s "
                            "подменяет адрес, поэтому ошибки ICMP приходят на адрес роутера "
                            "и вернуть их клиенту может только conntrack — "
                            "если их не отслеживать, узлы пропадут совсем\n",
                    sp->out[i].name, sp->out[i].device);
            return;
        }
    }
    /* Дамп nft: ищется `ct state untracked … accept` в той форме, как его печатает nft. */
    const char *pos = nft_dump();
    int ok = 0;
    char line[2048];
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL)
        if (strstr(line, "untracked") && strstr(line, "accept")) ok = 1;
    if (!ok)
        fprintf(stderr, LOG_W "traceroute_hops включён, но правила, принимающего неотслеживаемые "
                        "пакеты, нет — фаервол отбросит ICMP time-exceeded, и узлы в traceroute "
                        "будут звёздочками. Нужно один раз, в фаерволе (не здесь): "
                        "accept ct state untracked icmp type time-exceeded в сторону %s\n", sp->lan_dev[0]);
}

/* ЧУЖИЕ ПРАВИЛА НА БИТАХ 16-23 — предупреждение, а не отказ.
 *
 * Поле метки движка — биты 20-27 (STEER_MARK_MASK, контракт). Tailscale и pbr держат свою
 * метку маской 0x00ff0000, то есть битами 16-23, и на битах 20-23 два поля ПЕРЕСЕКАЮТСЯ —
 * подробно у STEER_MARK_MASK в spec.h. Раскладку не меняем: это контракт, и сдвиг поля
 * означал бы новые метки у всех выходов на всех роутерах. Зато говорим, когда соседство
 * действительно есть, — иначе его последствия выглядят как «канал иногда идёт мимо выхода»
 * без единой строки в журнале.
 *
 * Признак — число в выражении с меткой в ЧУЖОЙ таблице: 0x00ff0000 (маска поля 16-23) или
 * 0xff00ffff (она же, дополнением: «стереть биты 16-23»). Так их печатает nft и для
 * Tailscale (снято с роутера: `meta mark set mark and 0xff00ffff xor 0x40000`), и для
 * всякого, кто метит по той же схеме. Разбираются числа, а не строка: ведущие нули nft то
 * печатает, то нет.
 *
 * Не отказ, потому что соседство законно и чаще всего безвредно: Tailscale переписывает
 * метку в хуке forward, то есть ПОСЛЕ решения о маршруте, и ip rule выхода его не замечает;
 * единственный наш читатель метки после forward — очередь модуля DPI — узнаёт выход по
 * метке соединения. Отказ применить спеку на роутере с Tailscale снял бы маршрутизацию у
 * людей, у которых всё работает. Вредные случаи — чужое правило, которое метит ТОТ ЖЕ пакет
 * в prerouting после нас (стирает наши биты — пакет уходит по main, мимо выхода и мимо
 * запрета on_fail=drop), или до нас (мы стираем его биты 20-23 — его политика на этом
 * пакете перестаёт совпадать), — по дампу не отличить, поэтому о них говорится словами.
 *
 * Возвращает, о скольких таблицах сказано: стенд fwmatch проверяет признак на дампах. */
int report_mark_overlap(void) {
    /* Поле целиком выше бита 23 (мини-сборка моста живёт в бите 28) — с масками 16-23 оно не
     * пересекается, и говорить не о чем. */
    if (STEER_MARK_LOBIT > 23) return 0;
    const char *pos = nft_dump();
    char line[2048], table[96] = "", said[8][96];
    int n_said = 0;
    while ((pos = dump_line(pos, line, sizeof(line))) != NULL) {
        const char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!strncmp(p, "table ", 6)) {
            snprintf(table, sizeof(table), "%s", p + 6);
            char *b = strchr(table, '{');
            if (b) *b = '\0';
            for (size_t k = strlen(table); k && table[k - 1] == ' '; k--) table[k - 1] = '\0';
            continue;
        }
        if (!*table || !strstr(p, "mark")) continue;
        /* Своя таблица — «семейство имя», имя вторым словом. */
        const char *tn = strchr(table, ' ');
        if (tn && !strcmp(tn + 1, nft_table())) continue;
        int hit = 0;
        for (const char *q = p; (q = strstr(q, "0x")) != NULL; q += 2) {
            unsigned long v = strtoul(q, NULL, 16);
            if (v == 0x00ff0000ul || v == 0xff00fffful) { hit = 1; break; }
        }
        if (!hit) continue;
        int dup = 0;
        for (int k = 0; k < n_said; k++) if (!strcmp(said[k], table)) dup = 1;
        if (dup || n_said >= 8) continue;
        snprintf(said[n_said++], sizeof(said[0]), "%s", table);
        /* Биты — из базы и ширины поля (STEER_MARK_LOBIT/HIBIT), а не строкой: у сборки под
         * Android поле 22-27, и пересекается оно с 16-23 на двух битах, а не на четырёх. */
        fprintf(stderr, LOG_W "таблица %s метит пакеты маской 0x00ff0000 (биты 16-23, так "
                        "работают Tailscale и pbr), а поле ядра steer — биты %d-%d: на битах "
                        "%d-23 метки пересекаются. Если её правило метит тот же пакет в "
                        "prerouting после нас, трафик канала уйдёт мимо выхода; если до нас — "
                        "перестанет действовать её политика на этом пакете\n", table,
                STEER_MARK_LOBIT, STEER_MARK_HIBIT, STEER_MARK_LOBIT);
    }
    return n_said;
}

/* Есть ли у клиентов IPv6 наружу: глобальный адрес IPv6 (не fe80::/10) на одном из устройств
 * раздачи. Роутер раздаёт клиентам префиксы своих адресов (odhcpd), и без такого адреса на
 * устройстве раздачи у клиентов нет IPv6 дальше своей сети — спрашивать про его подмену незачем,
 * и строка «нет masquerade IPv6» была бы постоянной ложной тревогой. Адреса — getifaddrs
 * (netlink внутри libc), без процесса: зовут diag в процессе демона и apply. */
int lan_has_global_v6(const struct spec *sp) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return 0;
    int yes = 0;
    for (struct ifaddrs *p = ifa; p && !yes; p = p->ifa_next) {
        if (!p->ifa_addr || p->ifa_addr->sa_family != AF_INET6 || !p->ifa_name) continue;
        const struct in6_addr *a = &((const struct sockaddr_in6 *)p->ifa_addr)->sin6_addr;
        if (IN6_IS_ADDR_LINKLOCAL(a) || IN6_IS_ADDR_LOOPBACK(a)) continue;
        for (size_t i = 0; i < sp->lan_dev_n && !yes; i++)
            if (!strcmp(p->ifa_name, sp->lan_dev[i])) yes = 1;
    }
    freeifaddrs(ifa);
    return yes;
}

/* Ключ ipv6, которым судить устройство (daemon.h). Проверка на QEMU-роутере 4192267: группа man
 * (члены wg0 и wg1, сейчас wg1, у wg1 `ipv6: nat`) получала «у wg1 нет masquerade IPv6» и в apply,
 * и в diag output_nat6, хотя всё, что уходит в wg1, маскирует наш postrouting_nat6: проверка брала
 * ключ группы (не записан — KIND, «подмену ставит зона»), а не владельца устройства, — та же
 * ошибка, от которой out_self_natting уже спрашивает out_for_device. Ключ, записанный у самой
 * группы, важнее: build_nat6 ставит тогда правило на её устройство.
 *
 * Владелец здесь — не только device_owner (он знает лишь устройства, которые заводит движок:
 * vless, xsteer, awg), но и член группы, чьё устройство dev: у interface-члена устройство заводит
 * netifd, и device_owner его не назовёт. Член ищется вглубь вложенных групп. */
static const struct output *member_for_device(const struct spec *sp, const struct output *o,
                                              const char *dev, int depth) {
    const struct group_cfg *g = out_group(o);
    if (!g || depth > 8) return o;
    for (size_t k = 0; k < g->members_n; k++) {
        /* spec_out: член бывает безымянным (устройство из `devices`), и его номер — не место в out[]. */
        const struct output *m = spec_out(sp, g->members[k]);
        if (m != o && !strcmp(m->device, dev)) return member_for_device(sp, m, dev, depth + 1);
    }
    return o;
}

int out_ipv6_mode_dev(const struct spec *sp, const struct output *o, const char *dev) {
    enum out_ipv6 m = out_ipv6_mode(o);
    if (m != OUT_V6_KIND) return m;
    const struct output *leaf = member_for_device(sp, o, dev, 0);
    m = out_ipv6_mode(leaf);
    if (m != OUT_V6_KIND) return m;
    return out_ipv6_mode(out_for_device(sp, leaf, dev));
}

/* Только на платформе с fw4 (plat()->fw4) — см. конец cmd_apply. */
void report_output_deps(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) {
        if (!out_has_device(&sp->out[i])) continue;
        struct fwcheck c = fw_check(sp->out[i].device);
        if (!c.in_firewall)
            fprintf(stderr, LOG_W "выход %s: фаервол не знает устройства %s — "
                            "трафик, ушедший туда, не вернётся, пока оно не окажется в зоне\n",
                    sp->out[i].name, sp->out[i].device);
        /* Выходу vless NAT не нужен, и предупреждать о нём — значит посылать человека
         * настраивать то, чему нечего транслировать: клиент завершает TCP у себя и
         * соединяется с сервером обычным сокетом, поэтому адрес клиента наружу не уезжает
         * вовсе. Предупреждение «нет masquerade» здесь было ложной тревогой, а ложная
         * тревога дороже отсутствующей: по ней настраивают лишнее и перестают верить
         * настоящим. Про зону предупреждать всё равно надо — без неё fw4 не пропускает
         * транзит, и это проверено с настоящего клиента.
         *
         * У xsteer тот же итог по другой причине: адреса клиентов границу переходят, но
         * переходят к хабу внутри туннеля, где транслировать их нечем. Там NAT не просто
         * не нужен, а вреден — он скрывает, от какой пира пришёл пакет, и ломает
         * обратный поиск по AllowedIPs. Условие поэтому одно (out_self_natting), а
         * объяснения в diag разные: см. ветку про masquerade в cmd_diag.
         *
         * Спрашивается ВЛАДЕЛЕЦ устройства, а не выход, который его назвал (out_for_device):
         * в пуле kind=interface активным может быть устройство VLESS-туннеля, и вопрос «нужен
         * ли ему masquerade» решает то, чем устройство является, а не то, кто его перечислил.
         * Иначе — постоянная жалоба на исправной настройке. */
        else if (out_self_natting(out_for_device(sp, &sp->out[i], sp->out[i].device))) {
            /* нечего проверять */
        }
        else if (out_nat4_by_steer(out_for_device(sp, &sp->out[i], sp->out[i].device))) {
            /* подмену IPv4 ставит само ядро (generate.c, build_nat4); IPv6 — ниже, своим вопросом */
            if (!c.masq6 && out_route6(&sp->out[i]) &&
                out_ipv6_mode_dev(sp, &sp->out[i], sp->out[i].device) == OUT_V6_KIND &&
                lan_has_global_v6(sp))
                fprintf(stderr, LOG_W "output %s: у %s нет masquerade IPv6 — IPv6 клиентов уйдёт "
                                "в туннель с их адресами, и ответ не вернётся; поставьте выходу "
                                "ipv6: nat\n", sp->out[i].name, sp->out[i].device);
        }
        else {
            if (!c.masqueraded)
                fprintf(stderr, LOG_W "выход %s: для %s нет правила masquerade/snat — "
                                "если этому пути нужна подмена адреса, пакеты уйдут с адресами LAN, "
                                "и канал замолчит, хотя его счётчик растёт\n",
                        sp->out[i].name, sp->out[i].device);
            /* IPv6 — своим вопросом (fw_check по семействам, шаг 8 выпуска 1.10): masq6 зоны. */
            /* У `ipv6: nat` подмену ставит сам движок, у `ipv6: routed` её не нужно вовсе. */
            /* Ключ — устройства, а не выхода (out_ipv6_mode_dev): у группы с членом `ipv6: nat`. */
            if (!c.masq6 && out_route6(&sp->out[i]) &&
                out_ipv6_mode_dev(sp, &sp->out[i], sp->out[i].device) == OUT_V6_KIND &&
                lan_has_global_v6(sp))
                fprintf(stderr, LOG_W "output %s: у %s нет masquerade IPv6 — IPv6 клиентов уйдёт "
                                "в туннель с их адресами, и ответ не вернётся; включите masq6 у "
                                "зоны выхода\n", sp->out[i].name, sp->out[i].device);
        }
    }
}

