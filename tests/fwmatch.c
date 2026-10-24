/* Проверка зависимости выхода от firewall: что движок засчитывает как «здесь есть
 * masquerade», а что нет.
 *
 * Зачем отдельным стендом. fw_check() — единственное место, где движок судит о чужой
 * конфигурации, и судит её ТЕКСТОМ: он читает дамп `nft list ruleset` и ищет в нём
 * признаки. Признак — эвристика, а эвристика проверяется только примерами; ошибка же
 * здесь не видна как сбой: движок работает, трафик идёт, а человек читает в диагностике
 * «у warp0 нет masquerade» при включённом masq и идёт чинить то, что не сломано. Ложная
 * тревога дороже отсутствующей — по ней настраивают лишнее и перестают верить настоящим.
 *
 * Дамп берётся из живого fw4 (OpenWrt 25.12, стенд): формы строк здесь не придуманы, а
 * скопированы, включая то, что имя ЗОНЫ и имя УСТРОЙСТВА — разные вещи, совпадающие лишь
 * по привычке называть зону как интерфейс.
 *
 * Текст fw_check берёт у ядра по netlink (src/lib/nftdump.c печатает его в форме `nft -t list
 * ruleset`), поэтому стенд проверяет две вещи порознь:
 *
 *   1. разбор — fw_check_dump на дословных дампах fw4 (ниже, RS_*): эвристика проверяется только
 *      примерами;
 *   2. печать — в своём сетевом пространстве (нужен root): те же дампы и набор правил,
 *      похожий на полный fw4 (безымянные наборы устройств, карта вердиктов, flowtable), грузятся
 *      настоящим `nft -f`, и fw_check по тексту от ядра обязан ответить то же, что разбор по
 *      тексту самого `nft -t list ruleset`, — и то, что ожидается.
 *
 * Предупреждения apply (соседи на битах 16-23) по-прежнему читают текст `nft`: popen подменён
 * функцией с именем и подписью из <stdio.h> — сильный символ в объекте стенда перекрывает слабый
 * из libc при компоновке, и вызовы из fwcheck.o приходят сюда. Проверяется настоящая функция, а
 * не её копия, и ради теста в движок не добавляется ни строки. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sched.h>

#include "spec.h"
#include "daemon.h"

static const char *g_ruleset;    /* что «вернёт» nft этому вызову */

FILE *popen(const char *cmd, const char *mode) {
    (void)cmd; (void)mode;
    return fmemopen((void *)g_ruleset, strlen(g_ruleset), "r");
}
int pclose(FILE *f) { return fclose(f); }

static int g_fail;
static int g_kernel_n;    /* сколько проб печати от ядра прошло */

static void check(const char *what, int got, int want) {
    if (got == want) return;
    fprintf(stderr, "fwmatch: %s: получено %d, ожидалось %d\n", what, got, want);
    g_fail++;
}

static void probe(const char *what, const char *ruleset, const char *device,
                  int want_in_firewall, int want_masq) {
    char label[256];
    struct fwcheck r = fw_check_dump(ruleset, device);
    snprintf(label, sizeof(label), "%s — устройство в firewall", what);
    check(label, r.in_firewall, want_in_firewall);
    snprintf(label, sizeof(label), "%s — masquerade", what);
    check(label, r.masqueraded, want_masq);
}

/* Зона названа так же, как устройство (warp0). Так выглядит роутер, где зону завёл
 * splify2 или человек, повторивший имя интерфейса, — этот случай работал и до правки. */
static const char RS_ZONE_EQ_DEVICE[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"br-lan\" jump srcnat_lan comment \"!fw4: Handle lan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"warp0\" jump srcnat_warp0 comment \"!fw4: Handle warp0 IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_lan {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"	chain srcnat_warp0 {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 warp0 traffic\"\n"
"	}\n"
"}\n";

/* То же самое, но зона названа vpn, а устройство осталось warp0 — обычный случай для
 * того, кто заводил зону руками по любому руководству. Устройство не стоит рядом со
 * словом masquerade НИ В ОДНОЙ строке набора: fw4 пишет в цепочку и в комментарий имя
 * зоны, а устройство называет только на переходе. Ровно этот дамп снят со стенда. */
static const char RS_ZONE_RENAMED[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"br-lan\" jump srcnat_lan comment \"!fw4: Handle lan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"warp0\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_lan {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 vpn traffic\"\n"
"	}\n"
"}\n";

/* Цепочка зоны есть, masquerade в ней нет (так выглядит lan). Устройство упомянуто
 * firewall'ом, но NAT ему не делают — предупреждение обязано остаться. */
static const char RS_ZONE_NO_MASQ[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"tun0\" jump srcnat_guest comment \"!fw4: Handle guest IPv4/IPv6 srcnat traffic\"\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_guest {\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"}\n";

/* Явный snat вместо masquerade, зона снова названа иначе. */
static const char RS_SNAT_RENAMED[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		oifname \"proton_nl\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 snat to 10.2.0.2 comment \"!fw4: SNAT vpn traffic\"\n"
"	}\n"
"}\n";

/* Устройство называет только наша собственная таблица. Про NAT это не говорит ничего,
 * и про зону тоже: steer сам себе не firewall. */
static const char RS_ONLY_STEER[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		oifname \"wan\" jump srcnat_wan comment \"!fw4: Handle wan IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 wan traffic\"\n"
"	}\n"
"}\n"
"table inet steer {\n"
"	chain forward {\n"
"		oifname \"warp0\" counter accept\n"
"		meta l4proto tcp oifname \"warp0\" masquerade\n"
"	}\n"
"}\n";

/* ---- подмена по семействам (с 1.10, шаг 8): masq и masq6 зоны fw4 — разные правила ----------
 *
 * Зона vpn с одним masq6 (`option masq6 '1'` без masq): у fw4 это правило `meta nfproto ipv6
 * masquerade`. Прежде оно засчитывалось и за IPv4 — выход получал «NAT есть» при IPv4, уходящем в
 * туннель с адресами локальной сети. */
static const char RS_MASQ6_ONLY[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"wg0\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv6 masquerade comment \"!fw4: Masquerade IPv6 vpn traffic\"\n"
"	}\n"
"}\n";

/* Зона с masq и masq6 — оба правила в одной цепочке. */
static const char RS_MASQ_BOTH[] =
"table inet fw4 {\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"wg0\" jump srcnat_vpn comment \"!fw4: Handle vpn IPv4/IPv6 srcnat traffic\"\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 masquerade comment \"!fw4: Masquerade IPv4 vpn traffic\"\n"
"		meta nfproto ipv6 masquerade comment \"!fw4: Masquerade IPv6 vpn traffic\"\n"
"	}\n"
"}\n";

/* Руками: правило без семейства в inet — подменяет оба; в таблице ip6 — только IPv6; в ip —
 * только IPv4. */
static const char RS_HAND_FAMS[] =
"table inet hand {\n"
"	chain post {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"wga\" masquerade\n"
"	}\n"
"}\n"
"table ip6 hand6 {\n"
"	chain post {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"wgb\" masquerade\n"
"	}\n"
"}\n"
"table ip hand4 {\n"
"	chain post {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname \"wgc\" masquerade\n"
"	}\n"
"}\n";

static void probe6(const char *what, const char *ruleset, const char *device, int want4,
                   int want6) {
    char label[256];
    struct fwcheck r = fw_check_dump(ruleset, device);
    snprintf(label, sizeof(label), "%s — masquerade IPv4", what);
    check(label, r.masqueraded, want4);
    snprintf(label, sizeof(label), "%s — masquerade IPv6", what);
    check(label, r.masq6, want6);
}

/* Похоже на полный fw4 25.12: безымянные наборы устройств зоны, карта вердиктов ct state, flowtable
 * на устройстве, карта вердиктов по устройству (так пишут руками), маска имени, oif по номеру,
 * fib и префикс log. Нужно только для второй части стенда — печати набора правил от ядра. */
static const char RS_FW4_FULL[] =
"table inet fw4 {\n"
"	flowtable ft {\n"
"		hook ingress priority filter\n"
"		devices = { fwm0 }\n"
"	}\n"
"	set lan_devs {\n"
"		type ifname\n"
"		elements = { \"br-lan\" }\n"
"	}\n"
"	chain input {\n"
"		type filter hook input priority filter; policy drop;\n"
"		iifname \"lo\" accept comment \"!fw4: Accept traffic from loopback\"\n"
"		ct state vmap { established : accept, related : accept, invalid : drop } comment \"!fw4: Handle inbound flows\"\n"
"		iifname \"br-lan\" jump input_lan comment \"!fw4: Handle lan IPv4/IPv6 input traffic\"\n"
"		iifname { \"eth1\", \"pppoe-wan\" } jump input_wan comment \"!fw4: Handle wan IPv4/IPv6 input traffic\"\n"
"		iifname @lan_devs counter drop\n"
"		fib saddr . iif oif missing drop\n"
"	}\n"
"	chain input_lan {\n"
"		accept\n"
"	}\n"
"	chain input_wan {\n"
"		log prefix \"drop wanlog0 in: \" drop\n"
"	}\n"
"	chain forward {\n"
"		type filter hook forward priority filter; policy drop;\n"
"		meta l4proto { tcp, udp } flow add @ft\n"
"		iifname \"br-lan\" jump forward_lan\n"
"		oifname \"eth*\" accept\n"
"		oif \"lo\" accept\n"
"	}\n"
"	chain forward_lan {\n"
"		jump accept_to_tun\n"
"	}\n"
"	chain accept_to_tun {\n"
"		meta nfproto ipv4 oifname \"tun0\" counter accept\n"
"	}\n"
"	chain srcnat {\n"
"		type nat hook postrouting priority srcnat; policy accept;\n"
"		oifname { \"eth1\", \"pppoe-wan\" } jump srcnat_wan\n"
"		oifname vmap { \"wg0\" : jump srcnat_vpn, \"wg1\" : goto srcnat_vpn }\n"
"	}\n"
"	chain srcnat_wan {\n"
"		meta nfproto ipv4 masquerade\n"
"	}\n"
"	chain srcnat_vpn {\n"
"		meta nfproto ipv4 masquerade\n"
"	}\n"
"	chain dstnat {\n"
"		type nat hook prerouting priority dstnat; policy accept;\n"
"		iifname \"br-lan\" ct status dnat accept\n"
"		ip daddr 10.0.0.1 tcp dport 80 dnat ip to 192.168.1.2\n"
"	}\n"
"}\n"
"table inet steer {\n"
"	chain forward {\n"
"		oifname \"warp0\" counter accept\n"
"		meta l4proto tcp oifname \"warp0\" masquerade\n"
"	}\n"
"}\n";

/* ---- печать набора правил от ядра ------------------------------------------------------------
 *
 * Набор загружается настоящим nft в своё сетевое пространство; fw_check (текст от ядра по
 * netlink) сверяется с разбором текста самого `nft -t list ruleset` и, где задано, с ожиданием. */
static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 65536, n = 0;
    char *b = malloc(cap);
    size_t r;
    while (b && (r = fread(b + n, 1, cap - n - 1, f)) > 0) {
        n += r;
        if (n + 1 >= cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); b = NULL; break; } b = nb; }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

static int kernel_load(const char *rs, const char *dir) {
    char path[256], cmd[600];
    snprintf(path, sizeof(path), "%s/rs.nft", dir);
    FILE *f = fopen(path, "w");
    if (!f) return -1;
    fputs(rs, f);
    fclose(f);
    snprintf(cmd, sizeof(cmd), "nft flush ruleset && nft -f %s", path);
    return system(cmd) == 0 ? 0 : -1;
}

static void kernel_probe(const char *what, const char *rs, const char *dir,
                         const char *device, int want_in_firewall, int want_masq) {
    char label[256], cmd[400], path[256];
    snprintf(path, sizeof(path), "%s/list.txt", dir);
    snprintf(cmd, sizeof(cmd), "nft -t list ruleset > %s", path);
    if (system(cmd) != 0) { fprintf(stderr, "fwmatch: %s: nft list не прошёл\n", what); g_fail++; return; }
    char *text = slurp(path);
    if (!text) { g_fail++; return; }
    fwcheck_reset_cache();
    struct fwcheck k = fw_check(device);
    struct fwcheck t = fw_check_dump(text, device);
    free(text);
    (void)rs;
    snprintf(label, sizeof(label), "%s — %s в firewall: ядро и nft", what, device);
    check(label, k.in_firewall, t.in_firewall);
    snprintf(label, sizeof(label), "%s — %s masquerade: ядро и nft", what, device);
    check(label, k.masqueraded, t.masqueraded);
    snprintf(label, sizeof(label), "%s — %s masquerade IPv6: ядро и nft", what, device);
    check(label, k.masq6, t.masq6);
    if (want_in_firewall >= 0) {
        snprintf(label, sizeof(label), "%s — %s в firewall (ядро)", what, device);
        check(label, k.in_firewall, want_in_firewall);
        snprintf(label, sizeof(label), "%s — %s masquerade (ядро)", what, device);
        check(label, k.masqueraded, want_masq);
    }
    g_kernel_n++;
}

static void kernel_part(void) {
    if (geteuid() != 0 || unshare(CLONE_NEWNET) != 0 || system("nft list ruleset >/dev/null 2>&1") != 0) {
        printf("fwmatch: нет root, своего сетевого пространства или nft — печать от ядра не проверена\n");
        return;
    }
    char dir[] = "/tmp/fwmatch-XXXXXX";
    if (!mkdtemp(dir)) { g_fail++; return; }
    /* Устройство под flowtable: ядро не примет flowtable на несуществующем. */
    if (system("ip link add fwm0 type dummy 2>/dev/null") != 0)
        fprintf(stderr, "fwmatch: dummy-устройства нет — flowtable не проверен\n");
    static const char *const devs[] = {
        "warp0", "warp", "br-lan", "wan", "tun0", "proton_nl", "eth1", "pppoe-wan", "eth0",
        "wg0", "wg1", "fwm0", "lo", "wanlog0", "wga", "wgb", "wgc",
    };
    const struct { const char *what, *rs; } sets[] = {
        { "зона = устройство", RS_ZONE_EQ_DEVICE }, { "зона переименована", RS_ZONE_RENAMED },
        { "зона без masquerade", RS_ZONE_NO_MASQ }, { "snat", RS_SNAT_RENAMED },
        { "только steer", RS_ONLY_STEER }, { "полный fw4", RS_FW4_FULL },
        { "только masq6", RS_MASQ6_ONLY }, { "masq и masq6", RS_MASQ_BOTH },
        { "руками по семействам", RS_HAND_FAMS },
    };
    for (size_t i = 0; i < sizeof(sets) / sizeof(sets[0]); i++) {
        const char *rs = sets[i].rs;
        if (rs == RS_FW4_FULL && system("ip link show fwm0 >/dev/null 2>&1") != 0) continue;
        if (kernel_load(rs, dir) != 0) {
            fprintf(stderr, "fwmatch: %s: nft -f не принял набор\n", sets[i].what);
            g_fail++;
            continue;
        }
        for (size_t d = 0; d < sizeof(devs) / sizeof(devs[0]); d++)
            kernel_probe(sets[i].what, rs, dir, devs[d], -1, -1);
    }
    /* Ожидания на полном fw4 — то, ради чего печать и нужна: устройство в безымянном наборе
     * уходит в цепочку с masquerade; устройство одной flowtable в зоне (так судит и разбор
     * текста nft); префикс log называет устройство целиком. Карта вердиктов по устройству
     * masquerade НЕ даёт: первый переход в её строке печатается с запятой («jump srcnat_vpn,»),
     * и разбор имени цепочки его не узнаёт — так судит и разбор текста самого nft, и печать от
     * ядра обязана повторить даже это (порядок элементов — как у nft). */
    if (system("ip link show fwm0 >/dev/null 2>&1") == 0 && kernel_load(RS_FW4_FULL, dir) == 0) {
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "eth1", 1, 1);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "pppoe-wan", 1, 1);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "wg0", 1, 0);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "tun0", 1, 0);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "fwm0", 1, 0);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "warp0", 0, 0);
        kernel_probe("полный fw4", RS_FW4_FULL, dir, "wanlog0", 1, 0);
    }
    /* Семейство подмены — и в тексте от ядра (слово `meta nfproto`, nftdump.c): masq6 зоны не
     * засчитывается за IPv4 и там. */
    if (kernel_load(RS_MASQ6_ONLY, dir) == 0) {
        fwcheck_reset_cache();
        struct fwcheck k = fw_check("wg0");
        check("ядро: зона только с masq6 — IPv4", k.masqueraded, 0);
        check("ядро: зона только с masq6 — IPv6", k.masq6, 1);
    } else g_fail++;
    if (kernel_load(RS_HAND_FAMS, dir) == 0) {
        fwcheck_reset_cache();
        struct fwcheck a = fw_check("wga"), b = fw_check("wgb"), c = fw_check("wgc");
        check("ядро: без семейства в inet — IPv4", a.masqueraded, 1);
        check("ядро: без семейства в inet — IPv6", a.masq6, 1);
        check("ядро: таблица ip6 — IPv4", b.masqueraded, 0);
        check("ядро: таблица ip6 — IPv6", b.masq6, 1);
        check("ядро: таблица ip — IPv4", c.masqueraded, 1);
        check("ядро: таблица ip — IPv6", c.masq6, 0);
    } else g_fail++;
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", dir);
    if (system(cmd) != 0) { /* временный каталог остался — не повод проваливать стенд */ }
}

int main(void) {
    /* 1. Зона = имя устройства: и раньше засчитывалось, и обязано засчитываться дальше. */
    probe("зона названа как устройство", RS_ZONE_EQ_DEVICE, "warp0", 1, 1);

    /* 2. Тот же роутер, зона названа vpn. До правки здесь было «нет masquerade»
     *    при работающем NAT — жалоба из splicicd#8. */
    probe("зона названа иначе, чем устройство", RS_ZONE_RENAMED, "warp0", 1, 1);

    /* 3. Соседнее устройство той же таблицы не должно получить чужой вердикт. */
    probe("устройство соседней зоны без masquerade", RS_ZONE_RENAMED, "br-lan", 1, 0);

    /* 4. Зона есть, masquerade в ней нет — предупреждение остаётся. Это направление
     *    ошибки, ради которого проверка вообще написана: ложное «всё в порядке» хуже
     *    ложной тревоги. */
    probe("зона без masquerade", RS_ZONE_NO_MASQ, "tun0", 1, 0);

    /* 5. Устройства нет в наборе вовсе. */
    probe("устройство не упомянуто", RS_ZONE_NO_MASQ, "warp0", 0, 0);

    /* 6. Явный snat засчитывается наравне с masquerade. */
    probe("snat в переименованной зоне", RS_SNAT_RENAMED, "proton_nl", 1, 1);

    /* 7. Подстрока не отвечает за целое имя: warp ≠ warp0, иначе выход на несуществующем
     *    устройстве отчитался бы чужим NAT. */
    probe("warp не отвечает за warp0", RS_ZONE_RENAMED, "warp", 0, 0);

    /* 8. Собственная таблица движка не доказывает ни зоны, ни NAT. */
    probe("только table inet steer", RS_ONLY_STEER, "warp0", 0, 0);

    /* 9. Подмена по семействам: masq и masq6 зоны — разные вопросы. */
    probe6("зона только с masq6", RS_MASQ6_ONLY, "wg0", 0, 1);
    probe6("зона с masq и masq6", RS_MASQ_BOTH, "wg0", 1, 1);
    probe6("зона только с masq", RS_ZONE_RENAMED, "warp0", 1, 0);
    probe6("правило без семейства в inet", RS_HAND_FAMS, "wga", 1, 1);
    probe6("правило в таблице ip6", RS_HAND_FAMS, "wgb", 0, 1);
    probe6("правило в таблице ip", RS_HAND_FAMS, "wgc", 1, 0);
    probe6("snat IPv4 в зоне", RS_SNAT_RENAMED, "proton_nl", 1, 0);

    /* 10. Зона fw4, чей masq6 подменяет IPv6 устройства (fwcheck.zone6): по имени цепочки
     * srcnat_<зона>, а не по устройству — wg0 в зоне vpn называет vpn; правило на самом устройстве
     * (своя таблица) зоны не называет; без masq6 зоны нет. */
    {
        struct fwcheck z = fw_check_dump(RS_MASQ6_ONLY, "wg0");
        check("зона masq6 — vpn, а не wg0", strcmp(z.zone6, "vpn") == 0, 1);
        z = fw_check_dump(RS_HAND_FAMS, "wga");
        check("masquerade на самом устройстве — зоны нет", z.zone6[0] == 0, 1);
        z = fw_check_dump(RS_ZONE_RENAMED, "warp0");
        check("без masq6 — зоны нет", z.zone6[0] == 0, 1);
    }

    /* 11. Зон больше прежних 16 цепочек: устройство в тридцатой, masquerade в цепочке той же зоны. */
    {
        static char rs[16384];
        size_t o = (size_t)snprintf(rs, sizeof(rs), "table inet fw4 {\n\tchain srcnat {\n");
        for (int i = 0; i < 40; i++)
            o += (size_t)snprintf(rs + o, sizeof(rs) - o, "\t\toifname \"dev%d\" jump srcnat_z%d\n", i, i);
        o += (size_t)snprintf(rs + o, sizeof(rs) - o, "\t}\n");
        for (int i = 0; i < 40; i++)
            o += (size_t)snprintf(rs + o, sizeof(rs) - o,
                "\tchain srcnat_z%d {\n\t\tmeta nfproto ipv4 masquerade\n\t}\n", i);
        snprintf(rs + o, sizeof(rs) - o, "}\n");
        probe("30-я из 40 зон (прежний предел 16 цепочек)", rs, "dev29", 1, 1);
        probe("40-я из 40 зон", rs, "dev39", 1, 1);
    }

    /* ---- чем объясняется совпадение в explain -----------------------------------
     *
     * Фраза выводилась из ИМЕНИ набора, и у группы с доменами она всегда была «domain set».
     * Но группа, у которой есть и адресный список, и доменный, держит оба в ОДНОМ наборе —
     * так его находит резолвер, — и адрес из АДРЕСНОГО списка объяснялся как совпадение по
     * домену. Человек, выясняющий, почему 142.250.1.1 идёт в туннель, получал ответ про DNS,
     * которого там не было. Снято с живого роутера.
     *
     * Проверяется здесь, а не в gen.sh, по простой причине: настоящий explain спрашивает
     * ЯДРО (`nft get element`), и без живого набора до этой строки дело не доходит. Выбор
     * фразы от ядра не зависит, поэтому вынесен в отдельную функцию — её и проверяем. */
    {
        struct { const char *what; const char *addr; int files; int domains; const char *want; } t[] = {
            /* Один вид списка — ответ прежний. */
            { "только адресный список", "142.250.1.1", 1, 0, "address set" },
            { "только доменный список", "198.18.0.7",  0, 1, "domain set" },
            /* fake-IP выдал резолвер: имя нашлось в доменном списке, что бы ещё ни было в
             * наборе. Это единственный случай, где происхождение известно точно. */
            { "fake-IP при обоих списках", "198.18.0.1", 1, 1, "domain set" },
            { "fake-IP из 198.19", "198.19.255.255", 1, 1, "domain set" },
            /* Настоящий адрес при обоих списках различить нельзя: в режиме realip резолвер
             * кладёт в набор настоящие адреса. Честнее назвать оба, чем угадать один. */
            { "настоящий адрес при обоих списках", "142.250.1.1", 1, 1, "address+domain set" },
            /* Похожий, но не тот префикс: 198.180 — чужая сеть, и её нельзя читать как
             * fake-IP (иначе объяснение соврёт на чужом адресе). */
            { "198.180 не fake-IP", "198.180.0.1", 1, 1, "address+domain set" },
            { "198.1 не fake-IP", "198.1.0.1", 0, 1, "domain set" },
            /* fake-IP v6 (1.9): пара поддельного IPv4 в пуле fdfe:dcba:9876::/96. */
            { "fake-IP v6 при обоих списках", "fdfe:dcba:9876::c612:1", 1, 1, "domain set" },
            { "тот же префикс вне пары — не fake-IP", "fdfe:dcba:9876::1", 1, 1, "address+domain set" },
            { "настоящий IPv6 при обоих списках", "2001:db8::1", 1, 1, "address+domain set" },
        };
        for (size_t i = 0; i < sizeof(t) / sizeof(*t); i++) {
            const char *got = explain_set_phrase(t[i].addr, t[i].files, t[i].domains);
            if (strcmp(got, t[i].want) != 0) {
                fprintf(stderr, "fwmatch: %s: получено «%s», ожидалось «%s»\n",
                        t[i].what, got, t[i].want);
                g_fail++;
            }
        }
    }

    /* Соседи на битах 16-23 (Tailscale, pbr) пересекаются с полем движка на битах 20-23 —
     * apply об этом говорит, но только когда сосед действительно есть. Строка Tailscale —
     * та, что снята с роутера (I-265); ведущих нулей nft в ней не печатает. Своя таблица и
     * чужие правила с другими масками (mwan3 0x3f00, zapret 0x40000000) не в счёт. */
    {
        static const char *const ts =
            "table inet steer {\n"
            "\tchain prerouting_mark {\n"
            "\t\tmeta mark set meta mark & 0xf00fffff | 0x40100000 return\n"
            "\t}\n"
            "}\n"
            "table ip mangle {\n"
            "\tchain ts-forward {\n"
            "\t\tiifname \"tailscale0\" meta mark set meta mark & 0xff00ffff ^ 0x40000\n"
            "\t}\n"
            "}\n";
        static const char *const cmp =
            "table inet fw4 {\n"
            "\tchain policy {\n"
            "\t\tmeta mark & 0x00ff0000 == 0x00010000 return\n"
            "\t}\n"
            "}\n";
        static const char *const quiet =
            "table inet steer {\n"
            "\tchain prerouting_mark {\n"
            "\t\tmeta mark set meta mark & 0xf00fffff | 0x40100000 return\n"
            "\t}\n"
            "}\n"
            "table inet mwan3 {\n"
            "\tchain m { meta mark & 0x00003f00 == 0x00000100 }\n"
            "}\n"
            "table inet zapret {\n"
            "\tchain postnat_hook { meta mark & 0x40000000 == 0x00000000 jump postnat }\n"
            "}\n";
        const struct { const char *what, *rs; int want; } t[] = {
            { "Tailscale рядом — сказано", ts, 1 },
            { "сравнение маской 0x00ff0000 в чужой таблице — сказано", cmp, 1 },
            { "своя таблица и чужие маски — тишина", quiet, 0 },
        };
        for (size_t i = 0; i < sizeof(t) / sizeof(*t); i++) {
            g_ruleset = t[i].rs;
            fwcheck_reset_cache();
            check(t[i].what, report_mark_overlap(), t[i].want);
        }
    }

    kernel_part();

    if (g_fail) {
        fprintf(stderr, "fwmatch: провалено проверок: %d\n", g_fail);
        return 1;
    }
    printf("fwmatch: 16/16 проверок пройдено плюс 7 про объяснение совпадения, 3 про соседей на битах "
           "16-23 и %d проб печати набора правил от ядра\n", g_kernel_n);
    return 0;
}
