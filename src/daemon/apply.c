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

#include "spec.h"
#include "awg.h"
#include "plugin.h"
#include "hwid.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "daemon.h"
#include "groups.h"
#include "generate.h"
#include "run.h"
#include "helpers.h"
#include "failover_int.h"
#include "fogroup.h"
#include "fpseed.h"
#include "recon.h"
#include "nftdump.h"
#include "rtnl.h"

static void iptables_masq_drop_all(void);   /* ниже, у apply_routing */
static int table_has_default(int table);    /* ниже, у apply-commit */
/* ---- apply ---------------------------------------------------------------- */


/* ---- снятие мёртвых правил маршрутизации ------------------------------------
 *
 * rename/remove выхода оставляли в ядре ip rule fwmark и его таблицу навсегда:
 * apply ставит правила только для ТЕКУЩИХ выходов по их НОВЫМ меткам, метка
 * назначается по имени из реестра, и правило переименованного выхода не снимал
 * никто (I-019). Мёртвые правила не матчатся — метку с них уже никто не ставит, —
 * но копятся с каждым переименованием и засоряют `ip rule show` ровно тогда,
 * когда по нему пытаются понять, куда ушёл трафик.
 *
 * Снимок прежнего реестра берётся ДО registry_assign — тот перезаписывает файл
 * текущими выходами, и после него сравнивать уже не с чем. Живой считается метка,
 * которую несёт ЛЮБОЙ текущий недирект-выход: устройство здесь не проверяется
 * нарочно, у vless его создаёт сам процесс туннеля, и снять правило выхода за то,
 * что его устройство ещё не поднялось, значило бы обрубить туннель на ровном
 * месте. */
struct oldreg { unsigned mark; int table; };

/* Половина IPv6 выхода, которого больше нет (или всего движка при down): правило и таблица IPv6.
 * Снимается всегда, а не только у выходов с KC_IPV6: вид удалённого выхода по реестру не узнать, а
 * отказ `ip -6 rule del` по отсутствующему правилу ничего не значит. */
static void routing6_drop(unsigned mark, int table) {
    rule_drop6(mark, table);
    route6_flush(table);
}
/* Выход целиком: правило метки, таблица IPv4, затем половина IPv6. Порядок один для уборки
 * прежнего реестра, down и снятия по списку drop. */
static void routing_drop(unsigned mark, int table) {
    char t[16];
    snprintf(t, sizeof(t), "%d", table);
    rule_drop(mark, table);
    const char *flush[] = { "ip", "route", "flush", "table", t, NULL };
    run(flush);
    routing6_drop(mark, table);
}
/* Прежний реестр — по записи на выход, сколько их было; растёт (раньше — 16 записей, и хвост
 * реестра не убирался: правила выходов за шестнадцатым переживали удаление выхода). */
static struct oldreg *g_oldreg;
static size_t g_oldreg_n, g_oldreg_cap;

static void registry_snapshot(void) {
    char path[512];
    snprintf(path, sizeof(path), "%s/registry", steer_state_dir());
    FILE *f = fopen(path, "r");
    if (!f) return;
    char name[32];
    unsigned mark;
    int table;
    while (fscanf(f, "%31s %x %d\n", name, &mark, &table) == 3) {
        /* Чужой диапазон — чужие правила и чужая таблица (см. registry_assign): снимать их
         * по такой записи значило бы опустошить таблицу другого экземпляра движка. */
        if (!mark || (mark & ~STEER_MARK_MASK)) continue;
        if (g_oldreg_n == g_oldreg_cap) {
            size_t nc = g_oldreg_cap ? g_oldreg_cap * 2 : 32;
            struct oldreg *nr = realloc(g_oldreg, nc * sizeof(*nr));
            if (!nr) break;
            g_oldreg = nr;
            g_oldreg_cap = nc;
        }
        g_oldreg[g_oldreg_n].mark = mark;
        g_oldreg[g_oldreg_n].table = table;
        g_oldreg_n++;
    }
    fclose(f);
}

static void cleanup_stale_routing(const struct spec *sp) {
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        /* Живое — та же ПАРА «метка, таблица» у выхода с устройством. Одной метки мало: освободившуюся
         * метку реестр отдаёт другому выходу, и правило прежнего владельца (`fwmark M lookup
         * <его таблица>`) пережило бы его, уводя трафик нового в мёртвую таблицу. Так было на
         * стенде QEMU 2026-10-13: WARP с двух туннелей сократили до одного, метку cf.2 получил
         * kind: block, и его трафик пропадал в таблице steer_cf.2, не доходя до отказа. rule_drop
         * снимает именно эту пару — правило нового владельца с другой таблицей не задевается. */
        for (size_t k = 0; k < sp->out_n; k++)
            if (out_needs_mark(&sp->out[k]) && sp->out[k].mark == g_oldreg[i].mark &&
                (!out_has_device(&sp->out[k]) ? 0 : sp->out[k].table == g_oldreg[i].table)) {
                live = 1;
                break;
            }
        if (live) continue;
        char table[16];
        snprintf(table, sizeof(table), "%d", g_oldreg[i].table);
        rule_drop(g_oldreg[i].mark, g_oldreg[i].table);
        rule_drop6(g_oldreg[i].mark, g_oldreg[i].table);
        /* Таблицу — только ничью: её номер реестр тоже мог отдать другому выходу. */
        int tlive = 0;
        for (size_t k = 0; k < sp->out_n && !tlive; k++)
            tlive = out_has_device(&sp->out[k]) && sp->out[k].table == g_oldreg[i].table;
        if (tlive) continue;
        const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
        run(flush);
        route6_flush(g_oldreg[i].table);
    }
}

/* ---- down: снять всё, что поставил движок ------------------------------------
 *
 * То же, что stop_service в files/etc/init.d/steer, но командой движка. На роутере снятие —
 * это десяток строк shell; у init Android shell нет (сервис — один исполняемый файл), а
 * выдать домену steerd /system/bin/sh значило бы разрешить ему любую команду. Командой
 * движка оно и точнее: маска метки здесь STEER_MARK_MASK той платформы, что правила ставила
 * (у телефона она другая, 0x0fc00000), а в shell её пришлось бы повторять литералом.
 *
 * Зачем снимать при выключении, если перезапуск нарочно правил не трогает. Перезапуск — это
 * мгновение, после которого демоны встают снова, и открыть трафик на это мгновение хуже, чем
 * подержать правила. Выключение — другое: резолвер погашен навсегда, а правило заворота DNS
 * на его порт осталось бы в ядре, и у всех, чей DNS заворачивался, имена перестали бы
 * разрешаться вовсе. То же с on_fail=drop: blackhole в таблице выхода пережил бы выключение
 * и держал трафик закрытым без всякой видимой причины.
 *
 * Все таблицы: inet, ip и ip6 (остатки прежней раскладки для ядра 4.9) и steer_obfs (правила
 * обфускаторов). Какой таблицы нет — отказ nft молча
 * значит «нечего снимать». Спека не читается: снимать надо и то, что поставила прежняя
 * спека, а реестр в состоянии — это и есть список того, что стоит в ядре. */
int cmd_down(void) {
    static const char *const tabs[][2] = {
        { "inet", NULL }, { "ip", NULL }, { "ip6", NULL }, { "inet", "steer_obfs" },
    };
    /* Все таблицы — одним запуском nft и одной транзакцией: «table X» + «delete table X» (тот же
     * приём, что у замены таблицы в apply) не отвергается и тогда, когда таблицы нет. Раньше —
     * четыре запуска nft подряд, а на роутере каждый — десятки миллисекунд при каждой остановке
     * и перезапуске. Файл не записался или nft его не принял — по таблице, как прежде. */
    int one = -1;
    {
        char tmp[256];
        steer_tmp_template(tmp, sizeof(tmp), "steer-down");
        int fd = mkstemp(tmp);
        FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
        if (f) {
            for (size_t i = 0; i < sizeof tabs / sizeof tabs[0]; i++) {
                const char *t = tabs[i][1] ? tabs[i][1] : nft_table();
                fprintf(f, "table %s %s\ndelete table %s %s\n", tabs[i][0], t, tabs[i][0], t);
            }
            if (fclose(f) == 0) {
                const char *load[] = { "nft", "-f", tmp, NULL };
                one = run(load);
            }
            unlink(tmp);
        } else if (fd >= 0) {
            close(fd);
            unlink(tmp);
        }
    }
    for (size_t i = 0; one != 0 && i < sizeof tabs / sizeof tabs[0]; i++) {
        const char *del[] = { "nft", "delete", "table", tabs[i][0],
                              tabs[i][1] ? tabs[i][1] : nft_table(), NULL };
        run(del);
    }
    registry_snapshot();
    for (size_t i = 0; i < g_oldreg_n; i++) {
        routing_drop(g_oldreg[i].mark, g_oldreg[i].table);
    }
    /* Правило и таблица пробы сторожа. Сторож снимает их сам при выходе, но init Android гасит
     * сервис SIGKILL (без gentle_kill — сразу, с ним — через 200 мс), и уборка при выходе может
     * не успеть. */
    probe_rule_cleanup();
    if (plat()->iptables_masq) iptables_masq_drop_all();
    /* Туннели kind=awg заводил движок — ему их и снимать; без этого интерфейс с ключами пира
     * пережил бы выключение и продолжал бы отвечать на рукопожатия. */
    awg_down_all();
    /* Резолвер, переживший демона (src/dnsd/adopt.c). Штатно его гасит сам демон на SIGTERM, но
     * в окне после падения демона — kill -9 и stop, пока procd не поднял его снова, — экземпляра
     * procd нет, init.d pid не узнаёт, и резолвер жил бы ещё до 60 с (--orphan-timeout) на своём
     * порту, ожидая демона, которого не будет. Последним, после таблиц: заворот DNS к нему уже
     * снят, и клиенты к этому мигу ходят к dnsmasq. Резолвер живого демона просьбу отклоняет —
     * `steer down` руками при работающей службе его не гасит. */
    supd_orphan_down();
    return 0;
}

/* Policy routing for interface outputs. Дубликаты правил не копятся: rule_ensure считает копии
 * в ядре и лишние снимает — но только ПОСЛЕ того, как верная стоит, а не «снять всё и
 * поставить заново» (см. table_bind в failover.c: в том промежутке трафик уходил напрямую). */
/* ---- masquerade у выходов-интерфейсов: правилом iptables, а не nft ----------------------
 *
 * Только на платформе с plat()->iptables_masq (телефон, src/platform/android.c).
 *
 * ЗАЧЕМ. На роутере адрес источника у пакетов в туннель подменяет firewall (зона выхода с
 * masq). На телефоне такого firewall нет: netd делает NAT только для раздачи на её восходящий
 * интерфейс. Пакет раздачи или приложения, уведённый меткой в туннель, уходил бы с адресом
 * Wi-Fi или сотовой сети — сервер туннеля такой пакет не примет.
 *
 * ПОЧЕМУ iptables. На ядре 4.9 каждая регистрация nat (цепочка nat nft, таблица nat iptables)
 * решает судьбу нового соединения сама: первая сработавшая, не найдя правила, ставит «пустую»
 * привязку, и следующие для этого соединения уже не вычисляются (nf_nat_ipv4_fn в
 * nf_nat_l3proto_ipv4.c). netd держит nat в iptables на srcnat (100). Цепочка nft после неё
 * не срабатывает никогда, а до неё — отнимает у netd раздачу целиком. Правило в той же таблице
 * nat iptables, первым в POSTROUTING, живёт с правилами netd в одном проходе.
 *
 * Только наш помеченный трафик и только на устройствах выхода. Правила узнаются по маске
 * поля метки в тексте `iptables -S` — чужих с нашей маской не бывает. Выходы vless и xsteer
 * здесь не нужны: их устройство обслуживает наш процесс, адреса он переводит сам. Выход
 * kind=awg — нужен, как interface: туннель в ядре несёт пакет с тем адресом источника, что
 * был, а сервер WireGuard примет только адрес из своих AllowedIPs, то есть адрес туннеля. */
/* IPv6 (docs/architecture.md, «4б»): у выхода с маршрутом IPv6 (out_route6) — такое же правило в
 * nat ip6tables. Смысл тот же, что у IPv4: пакет приложения или раздачи, уведённый в туннель,
 * несёт адрес IPv6 сети Wi-Fi или сотовой, а сервер WireGuard примет только адрес туннеля. На ядре
 * без nat в ip6tables (CONFIG_IP6_NF_NAT есть не у всех сборок) правила не встанут — тогда IPv6
 * через туннель не пойдёт (сервер отбросит чужой адрес), но и напрямую не уйдёт; apply об этом
 * говорит. Есть ли nat в ip6tables — спрашивается один раз на процесс. */
static int ip6tables_nat_ok(void) {
    static int ok = -1;
    if (ok < 0) {
        const char *probe[] = { "ip6tables", "-w", "-t", "nat", "-S", "POSTROUTING", NULL };
        ok = run_quiet(probe) == 0;
    }
    return ok;
}

static void masq_drop_all_tool(const char *tool) {
    char mask[24], cmd[96];
    snprintf(mask, sizeof(mask), "/0x%x ", STEER_MARK_MASK);
    snprintf(cmd, sizeof(cmd), "%s -w -t nat -S POSTROUTING 2>/dev/null", tool);
    FILE *p = popen(cmd, "r");
    if (!p) return;
    char line[512], lines[64][512];
    int n = 0;
    while (n < 64 && fgets(line, sizeof(line), p)) {
        if (strncmp(line, "-A POSTROUTING ", 15) || !strstr(line, mask) ||
            !strstr(line, "-j MASQUERADE")) continue;
        snprintf(lines[n++], sizeof(lines[0]), "%s", line + 15);
    }
    pclose(p);
    for (int i = 0; i < n; i++) {
        const char *argv[32] = { tool, "-w", "-t", "nat", "-D", "POSTROUTING" };
        int k = 6;
        for (char *t = strtok(lines[i], " \n"); t && k < 31; t = strtok(NULL, " \n"))
            argv[k++] = t;
        argv[k] = NULL;
        run(argv);
    }
}

static void iptables_masq_drop_all(void) {
    masq_drop_all_tool("iptables");
    if (ip6tables_nat_ok()) masq_drop_all_tool("ip6tables");
}

/* Каким инструментам нужен masquerade выхода: iptables — всем с устройством, кроме тех, кто наружу
 * ходит от своего имени (out_self_natting: у interface и awg он нужен, у vless и xsteer — нет);
 * ip6tables — тем из них, у кого маршрут IPv6. */
static int masq_tools(const struct output *o, const char *tools[2]) {
    if (!out_has_device(o) || out_self_natting(o)) return 0;
    int n = 0;
    tools[n++] = "iptables";
    if (out_route6(o) && ip6tables_nat_ok()) tools[n++] = "ip6tables";
    return n;
}

/* Вернуть недостающие правила masquerade, не трогая стоящие. Зовёт сторож после каждого
 * прохода: netd при (пере)запуске перестраивает iptables и наши правила пропадают, а apply
 * после этого случится, только если его позовёт init (см. steerd.rc). */
void iptables_masq_ensure(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        const char *tools[2];
        int tn = masq_tools(o, tools);
        if (!tn) continue;
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        /* На каждое устройство, в которое выход может увести трафик: у группы — устройства
         * членов, у выхода с устройством — его собственное (out_members). */
        size_t mn = out_members_n(sp, o);
        for (int ti = 0; ti < tn; ti++)
        for (size_t k = 0; k < mn; k++) {
            const struct output *mk_o = out_member(sp, o, k);
            const char *chk[] = { tools[ti], "-w", "-t", "nat", "-C", "POSTROUTING",
                                  "-o", mk_o->device, "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(chk) == 0) continue;
            const char *add[] = { tools[ti], "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", mk_o->device, "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) == 0)
                fprintf(stderr, "steer[info] failover: masquerade%s на %s возвращён\n",
                        ti ? " IPv6" : "", mk_o->device);
        }
    }
}

static void iptables_masq_sync(const struct spec *sp) {
    iptables_masq_drop_all();
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        const char *tools[2];
        int tn = masq_tools(o, tools);
        if (!tn) continue;
        if (out_route6(o) && tn < 2)
            fprintf(stderr, LOG_W "output %s: в ядре нет nat для ip6tables — IPv6 через туннель "
                            "не пойдёт (сервер не примет чужой адрес), но и напрямую не "
                            "уйдёт\n", o->name);
        char mk[32];
        snprintf(mk, sizeof(mk), "0x%x/0x%x", o->mark, STEER_MARK_MASK);
        size_t mn = out_members_n(sp, o);
        for (int ti = 0; ti < tn; ti++)
        for (size_t k = 0; k < mn; k++) {
            const struct output *mo = out_member(sp, o, k);
            const char *add[] = { tools[ti], "-w", "-t", "nat", "-I", "POSTROUTING", "1",
                                  "-o", mo->device, "-m", "mark", "--mark", mk,
                                  "-j", "MASQUERADE", NULL };
            if (run(add) != 0)
                fprintf(stderr, LOG_W "output %s: masquerade на %s не встал (%s)\n",
                        o->name, mo->device, tools[ti]);
        }
    }
}

/* Привязка одного выхода — тело прежнего цикла apply_routing. Одна функция на два пути: apply
 * подкомандой проходит все выходы, apply-commit демона — только те, чья часть маршрутизации
 * изменилась (apply-сверка, src/daemon/recon.c). */
static void apply_routing_one(const struct output *o) {
    if (!out_has_device(o)) return;
    /* IPv6 выхода снят спекой (ipv6: off или выход рядом с донором — spec_v6_resolve): правило и
     * таблица IPv6, поставленные прежней спекой, снимаются. Вреда от них не было бы — IPv6 такого
     * выхода отвергает forward_v6 по метке, — но `ip -6 rule` с правилом выхода, который IPv6 не
     * несёт, путал бы того, кто по нему выясняет, куда уходит IPv6. */
    if (o->v6_denied) routing6_drop(o->mark, o->table);
    /* Группа спеки v2, у которой по известным приговорам членов взять некого (у manual — не
     * работает выбранный член): подхват outputs_adopt_active_st принял то же решение, что примет
     * проход, и это решение — on_fail. Ставится сразу и тем же кодом, что у прохода, а не
     * устройство, которое проход через секунды сменит на запрет: иначе после старта (или
     * restart) трафик группы до первого прохода шёл бы через член, которого человек не
     * выбирал. У выхода с одним устройством и у пула v1 `failed` — прошлый приговор пробы, и
     * apply по-прежнему привязывает устройство: судить его может только новая проба. */
    if (o->failed && group_named(out_group(o))) {
        fo_fail_apply(o);
        return;
    }
    char table[16];
    snprintf(table, sizeof(table), "%d", o->table);
    /* Маршрут — заменой, правило — не снимая стоящего (table_bind и rule_ensure в
     * failover.c). Прежде здесь были `rule_drop` + `rule_add` и `flush` + `add`, и на
     * каждом apply помеченный трафик выхода на миг оставался без правила и без маршрута,
     * то есть уходил напрямую, мимо туннеля, — подробно у table_bind. Маршрут первым: если
     * правила не было, появившееся должно найти в таблице устройство, а не пустоту. */
    int rc = table_bind(o, o->device);
    rule_ensure(o->mark, o->table);
    /* Половина IPv6 (docs/architecture.md, «4б») — у выхода с KC_IPV6. Не встала при живом IPv4 —
     * у устройства выключен IPv6: в таблице IPv6 запрет, и IPv6 правил выхода стоит. */
    if (rc == 0 && route6_bind(o, o->device) != 0)
        fprintf(stderr, LOG_W "output %s: маршрут IPv6 в %s не встал (IPv6 на устройстве "
                        "выключен?) — IPv6 правил выхода остановлен\n", o->name, o->device);
    if (rc != 0) {
        fprintf(stderr, LOG_W "выход %s: не проложить маршрут через %s — устройство поднято?\n",
                o->name, o->device);
        /* Пустая таблица — это не «нет маршрута», а «ищи дальше»: помеченный
         * пакет провалится в следующую таблицу и уйдёт напрямую, то есть ровно
         * туда, куда его не пускали. При on_fail=drop окно между apply и первым
         * тиком failover обязано быть закрыто, иначе защита работает не всегда,
         * а это хуже, чем не работает вовсе. */
        if (o->on_fail == FAIL_DROP) {
            table_bind(o, NULL);
            route6_bind(o, NULL);
            fprintf(stderr, LOG_W "output %s: трафик остановлен до появления "
                            "рабочего устройства (on_fail=drop)\n", o->name);
        } else {
            /* direct/zapret: таблица пуста, пакет уйдёт напрямую — значит и через общий
             * обход, как обычный (см. out_failopen_capable в spec.h). Отметка ложится в
             * набор, который стоит сейчас: у apply с новым набором правил привязка идёт до его
             * загрузки, и отметку для нового набора ставит failopen_after_load по этой же
             * пустой таблице. Сброс — потому что замена не прошла и в таблице могло остаться
             * прежнее устройство. */
            const char *flush[] = { "ip", "route", "flush", "table", table, NULL };
            run(flush);
            tcp_redir_sync(o, NULL);
            if (out_route6(o)) {
                /* IPv6 — тем же путём напрямую: правило на месте, таблица пуста. */
                rule_ensure6(o->mark, o->table);
                route6_flush(o->table);
            }
            failopen_mark(o, 1);
        }
    }
}

static void apply_routing(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) apply_routing_one(&sp->out[i]);
}

/* Стоит ли в ядре таблица «<семейство> <наша таблица>» — вопрос ядру по netlink (nfd_table_exists),
 * а не разбор текста `nft list tables` в буфере: перечень таблиц на коробке с чужими firewall
 * длиннее любого буфера, и обрезанный перечень выдавал бы стоящую таблицу за отсутствующую.
 * Не смогли спросить — «нет»: лишний `delete` отверг бы весь набор правил, а пропущенный
 * оставляет только чужую теперь таблицу, о которой скажет diag. */
static int nft_table_exists(const char *fam) {
    return nfd_table_exists(!strcmp(fam, "ip6") ? NFD_IP6 : NFD_IP, nft_table());
}

/* IPv6 ОТ ХОСТА — что не так, вслух при apply (подробно и с приговором — diag, `ipv6_host`).
 * Ключ routed/nat там, где он не действует (телефон), и донор, префикс которого не узнать: без
 * префикса правила в донора ведут IPv6 по меткам, но «всё несовпавшее из префикса — в донора» и
 * запрет источника мимо донора стоят пустыми. */
static void report_v6_host(const struct spec *sp) {
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        if ((o->ipv6 == OUT_V6_ROUTED || o->ipv6 == OUT_V6_NAT) && out_ipv6_mode(o) != o->ipv6)
            fprintf(stderr, LOG_W "output %s: ipv6: %s на этой платформе не действует — раздачей "
                            "IPv6 владеет Android, IPv6 выхода идёт как без ключа\n", o->name,
                    o->ipv6 == OUT_V6_ROUTED ? "routed" : "nat");
    }
    const struct output *d = spec_v6_donor(sp);
    if (!d || d->v6pfx_given || d->v6pfx.len) return;
    struct v6pfx p;
    if (v6donor_derive(sp, d, &p) < 0)
        fprintf(stderr, LOG_W "output %s: ipv6: routed — префиксов, из которых у LAN адреса, "
                        "несколько, и который из них от хоста, не узнать: задайте prefix: у выхода\n",
                d->name);
    else
        fprintf(stderr, LOG_W "output %s: ipv6: routed — у LAN нет адреса из префикса хоста: задайте "
                        "ip6prefix у интерфейса %s и ip6assign у LAN (или prefix: у выхода)\n",
                d->name, d->device);
}

/* ---- apply: общее начало, одна транзакция, конец ---------------------------------------
 *
 * cmd_apply (подкоманда `steer apply` — init.d, rpcd, init телефона) и служебные apply-plan и
 * apply-commit демона (apply-сверка, src/daemon/recon.c) — одни и те же шаги, нарезанные так,
 * чтобы демон мог сделать их по отдельности: план (разбор, проверки, компиляция в отпечаток) и
 * применение только изменившихся частей. Подкоманда проходит их все подряд, как раньше, байт в
 * байт тем же выводом. */

/* Общее начало: разбор, реестр, группы, проверки, раскладка. full=0 — только разбор, реестр и
 * выбор устройств (apply-commit без новых правил: ему нужны метки и таблицы выходов, а групп и
 * списков он не касается). nftc < 0 — раскладку (хук ingress) спросить у ядра; иначе взять
 * готовую — её демон запомнил с первого плана и пробы ядра не повторяет. report — сказать вслух о
 * том, что спека просит сверх возможного. */
static void apply_prepare(const char *spec, struct spec *cfg, struct groups *gr, int full,
                          int nftc, int report, int strict) {
    /* Разбор спеки и компиляция возвращают отказ, а не завершают процесс сами (правило 5,
     * docs/architecture.md, раздел 2) — err_die здесь, в точке входа, довершает то же самое:
     * код 2, тот же текст, что раньше печатал die() изнутри load_spec/build_groups/generate. */
    struct err e = {0};
    /* ШАГ ПОДГОТОВКИ (kinds/plugprep.c): хуки плагинов check, expand, pre_apply — над спекой человека,
     * до разбора. strict — apply и check из интерфейса: отказ хука — отказ всей спеки, и выход вида
     * без плагина тоже отказ (LOAD_STRICT). Без strict — запуск и перезагрузка: сбой подготовки не
     * роняет остальное, выходы, которые не подготовлены, уходят в on_fail как недоступные. Подготовка
     * нужна и разбору без хуков — ничего не делает, пока хуков нет ни у одного плагина. */
    if (full && spec_prepare(spec, &e) < 0) {
        if (strict) err_die(&e);
        fprintf(stderr, "steer[warn] подготовка спеки: %s\n", e.msg);
        e.msg[0] = '\0';
    }
    if (load_spec_mode(spec, cfg, &e, strict ? LOAD_STRICT : LOAD_PREPARED) < 0) err_die(&e);
    /* Снимок реестра — строго до registry_assign: тот перезапишет файл текущими
     * выходами, и метки удалённых/переименованных будут потеряны вместе с
     * единственным способом снять их правила из ядра. */
    registry_snapshot();
    if (registry_assign(cfg, &e) < 0) err_die(&e);
    tcp_redir_learn(cfg);
    if (!full) {
        outputs_adopt_active(cfg);
        return;
    }
    /* Раскладка набора правил — до генерации и до dry-run: интерфейс проверяет спеку именно
     * dry-run'ом, и печатать ему надо то, что реально встанет на этом ядре. */
    g_nftc = nftc >= 0 ? nftc : 0;
    /* Хук ingress (NFTC_INGRESS) — тем же разом, что раскладка, и ходит вместе с ней (--nftc):
     * проба `nft -c` на каждый apply была бы процессом на каждое сохранение настройки. Где
     * ingress не будет всё равно — телефон с устройствами раздачи по требованию, поле метки без
     * места под «разобран на ingress» (мини-сборка tgws), — ядро не спрашивается вовсе. */
    if (nftc < 0 && plat()->lan_devs_persist &&
        steer_ingress_seen_ok() && nft_ingress_ok())
        g_nftc |= NFTC_INGRESS;
    if (build_groups(cfg, gr, &e) < 0) err_die(&e);
    /* ДОМЕННЫЙ КАНАЛ В МИНИ-СБОРКЕ — ОТКАЗ, А НЕ ПРЕДУПРЕЖДЕНИЕ.
     *
     * Домены маршрутизируются через резолвер движка, а мини-сборка его не поднимает и
     * перенаправления DNS не ставит (см. генератор правил). Такая спека применилась бы и
     * не работала: имена не разрешаются нами, fake-адрес не появляется, канал стоит
     * пустым. Молчаливое применение здесь хуже отказа — искать причину пришлось бы на
     * роутере. */
    for (size_t i = 0; prof()->no_resolver && i < gr->n; i++)
        if (gr->g[i].domains)
            die("канал «%s» доменный, а эта сборка резолвера не поднимает: разрешать имена "
                "ей нечем. Переведите канал на адресный список или поставьте полное ядро steer",
                gr->g[i].name);
    /* Устройство выхода — то, что несёт трафик сейчас, а не первое в списке кандидатов.
     * Иначе применение настройки уводило бы таблицу с работающего запасного устройства на
     * неработающее основное, а при on_fail=drop ещё и ставило запрет — то есть каждое
     * сохранение в интерфейсе роняло бы пул до следующего прохода сторожа (до минуты). */
    outputs_adopt_active(cfg);
    /* Префикс хоста у донора IPv6 без `prefix:` — по ядру (failover.c, v6donor_derive): он уходит
     * элементом в набор v6donor. До генерации, как и устройство выше. */
    v6donor_adopt(cfg);
    if (report) report_v6_host(cfg);
    /* Проверка списков — ДО генерации и до dry-run.
     *
     * До dry-run намеренно: интерфейс проверяет спеку именно им, перед записью на диск.
     * Значит человек узнает про не тот список сразу при сохранении, а не потом, когда
     * apply молча не подействует. */
    if (check_address_lists(gr, &e) < 0) err_die(&e);
}

/* ЗАСЕВ НАБОРОВ КАНАЛОВ fake-IP — вокруг печати текста для ядра (доводы — в шапке
 * src/dnsd/fpseed.c и у print_elements в src/compile/print.c).
 *
 * Собирается только когда засев вообще печатается (не у отпечатка плана), в спеке есть канал
 * fake-IP и файл состояния что-то содержит — иначе печатать в наборы нечего, а читать правила
 * всех каналов ради пустого засева незачем.
 *
 * НЕ СОБРАЛСЯ (нехватка памяти) — не печатается и засев КАРТЫ. Карта без наборов — это ровно та
 * утечка, которую засев закрывает: подмена стоит, метки нет, пакет к поддельному адресу
 * разворачивается в настоящий и уходит в WAN. Без засева карты пакет к поддельному адресу до
 * прихода таблицы к резолверу подмены не находит и не уходит никуда (правило за dnat,
 * generate.c, build_fakeip): соединение ждёт резолвера, а не идёт мимо выхода.
 *
 * ФАЙЛ — СВЕЖИЙ (проверка на QEMU 98b7964). Резолвер переписывает
 * файл состояния не чаще раза в минуту, и засев из него отставал от памяти резолвера: новое имя —
 * без подмены (клиент с поддельным адресом в кэше: «без подмены — никуда», 3 запроса из 40 на три
 * замены), сменившийся адрес — прежним (и EEXIST резолвера его не исправлял). flush = 1 (загрузка,
 * не --dry-run): перед засевом резолвер этого каталога состояния по просьбе «flush» записывает файл
 * и отвечает уже после записи (supd_dnsd_flush). Резолвера нет — просить некого: файл последний,
 * какой он записал (при выходе он дописывает его сам). --dry-run резолвер не трогает: печать
 * вправе отстать от памяти, ядро она не меняет. */
static void seed_begin(const struct spec *cfg, const struct groups *gr, int flush) {
    if (!g_print_state_seed || !has_fakeip(gr)) return;
    if (flush) supd_dnsd_flush();
    char path[512];
    if (snprintf(path, sizeof(path), "%s/fakeip.state", steer_state_dir()) >= (int)sizeof(path))
        return;
    if (fpseed_build(cfg, path) != 0) {
        fprintf(stderr, LOG_W "fake-IP: засев наборов каналов не собран (нет памяти) — карта "
                        "подмены тоже не засевается: до таблицы резолверу соединения к поддельным "
                        "адресам ждут, а не уходят мимо выхода\n");
        g_print_state_seed = 0;
        return;
    }
    g_print_seed = fpseed_els;
}

static void seed_end(void) {
    if (!g_print_seed) return;
    g_print_seed = NULL;
    fpseed_free();
}

/* Засев набора failopen: метки выходов, у которых таблица уже без маршрута по умолчанию — тот же
 * предикат, что у failopen_mark и failopen_after_load. Элементы идут в тот же файл, что и таблица:
 * между `nft -f` и failopen_after_load (миллисекунды запуска ip и nft) postrouting_guard иначе
 * отбрасывала бы трафик выхода, пущенного напрямую. Только на загрузке; в --dry-run не зовётся. */
static unsigned *failopen_seed_buf;

static void failopen_seed_begin(const struct spec *cfg) {
    if (!cfg->out_n) return;
    failopen_seed_buf = malloc(cfg->out_n * sizeof(*failopen_seed_buf));
    if (!failopen_seed_buf) return;   /* без засева: failopen_after_load поставит отметки позже */
    size_t n = 0;
    for (size_t i = 0; i < cfg->out_n; i++) {
        const struct output *o = &cfg->out[i];
        if (o->mark && out_releasable(o) && out_has_device(o) && !table_has_default(o->table))
            failopen_seed_buf[n++] = o->mark;
    }
    g_failopen_seed = failopen_seed_buf;
    g_failopen_seed_n = n;
}

static void failopen_seed_end(void) {
    g_failopen_seed = NULL;
    g_failopen_seed_n = 0;
    free(failopen_seed_buf);
    failopen_seed_buf = NULL;
}

/* Одна транзакция: файл «добавить — удалить — новая таблица», nft -f.
 * 0 — ядро приняло; 1 — отвергло (прежняя таблица стоит, причина в журнале). */
static int ruleset_load(const struct spec *cfg, const struct groups *gr) {
    struct err e = {0};
    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-ruleset");
    int fd = mkstemp(tmp);
    if (fd < 0) die("не создать временный файл набора правил", NULL);
    FILE *f = fdopen(fd, "w");
    /* Крупный буфер на чисто дозаписывающий поток: musl по умолчанию даёт
     * BUFSIZ в 1 КБ, и набор на сотни тысяч элементов дробился на тысячи
     * мелких write. Статический — чтобы не зависеть от кучи в момент,
     * когда рядом nft уже строит своё дерево разбора. */
    static char genbuf[65536];
    setvbuf(f, genbuf, _IOFBF, sizeof(genbuf));
    /* ЗАМЕНА ТАБЛИЦЫ — ОДНОЙ ТРАНЗАКЦИЕЙ, и все три строки для этого нужны.
     *
     * Раньше здесь было два запуска nft: `nft delete table`, затем `nft -f` с новой таблицей,
     * хотя комментарий уже тогда обещал одну транзакцию. Между ними таблицы не было вовсе, а
     * на наборе в сотни тысяч элементов второй запуск на слабом роутере идёт секунды. Всё это
     * время DNS клиентов, который перенаправляет наша таблица, уходил в dnsmasq мимо
     * резолвера (имена доменных каналов разрешались настоящими адресами и шли напрямую), метки
     * не ставились, а запрет on_fail=drop держался только на маршрутной таблице. И если новый
     * набор nft отвергал, прежнего уже не было: один неудачный apply снимал маршрутизацию
     * целиком до следующего удачного.
     *
     * Теперь всё — в ОДНОМ файле, а `nft -f` применяет файл целиком или не применяет ничего:
     *   `table inet X`         — добавить таблицу, если её нет (без тела это «add», и на
     *                            существующей таблице он ничего не делает). Без этой строки
     *                            `delete` на самом первом apply отказал бы, а с ним — и
     *                            весь файл;
     *   `delete table inet X`  — снять прежнюю вместе с наборами и цепочками;
     *   `table inet X { … }`   — новая, из generate().
     * Снаружи видно либо прежнюю таблицу, либо новую, промежутка нет. Отказ nft оставляет
     * ПРЕЖНЮЮ таблицу стоять — то есть неудачный apply больше ничего не ломает.
     *
     * Цена одна, и её стоит знать: пока транзакция не закрыта, ядро держит и старые, и новые
     * наборы, то есть на время загрузки памяти под них нужно вдвое больше. Раньше старые
     * освобождались до загрузки новых. Проверено в `unshare -n` на nftables 1.0.9: файл такого
     * вида проходит и когда таблица есть, и когда её нет.
     *
     * В --dry-run эти две строки не печатаются: там выводится сам набор правил (его сверяют
     * стенды и интерфейс), а замена — дело применения. */
    fprintf(f, "table inet %s\ndelete table inet %s\n", nft_table(), nft_table());
    /* Таблицы ip и ip6 движка — остатки раскладки для Linux 4.9 (убрана, I-541): прежний apply
     * мог поставить их на телефоне, и оставшаяся там цепочка nat заворачивала бы DNS второй раз, а
     * карта fakeip в ней отставала бы от резолвера. Отсутствующую таблицу удалять нельзя —
     * `delete` отверг бы весь файл, — поэтому спрашиваем ядро, есть ли она. Где остатков нет
     * (роутер), файл остаётся прежним, байт в байт. */
    {
        static const char *const fams[2] = { "ip", "ip6" };
        for (int k = 0; k < 2; k++)
            if (nft_table_exists(fams[k]))
                fprintf(f, "delete table %s %s\n", fams[k], nft_table());
    }
    seed_begin(cfg, gr, 1);
    failopen_seed_begin(cfg);
    int grc = generate(cfg, gr, f, &e);
    failopen_seed_end();
    if (grc < 0) err_die(&e);
    seed_end();
    fclose(f);

    const char *load[] = { "nft", "-f", tmp, NULL };
    int rc = run(load);
    if (rc != 0) {
        fprintf(stderr, LOG_W "nft отверг набор правил, прежний остаётся (файл набора: %s)\n",
                tmp);
        const char *check[] = { "nft", "-c", "-f", tmp, NULL };
        run(check);
        return 1;
    }
    unlink(tmp);
    /* ЭЛЕМЕНТЫ real-ip — СРАЗУ, а не с таблицей от демона.
     *
     * Настоящие адреса из ответов, которые клиенты ещё держат в кэше, лежали в наборах каналов
     * real-ip со сроком — и новая таблица пришла без них. Текстом их сюда не положить: память о
     * них есть только у резолвера (realip.c), а в набор с auto-merge элемент со сроком
     * ложиться текстом не может вовсе — nft сливает соседние элементы в один со сроком
     * ПЕРВОГО, и префикс списка рядом с адресом стал бы истекающим (проверено на nftables
     * 1.0.9; довод — у print_elements в print.c). Возвращал их резолвер, когда до него
     * доходила таблица от демона, — а это после выхода ребёнка-загрузчика (ниже ещё метки
     * «пущен напрямую», карта balance, проверки) и после перечитывания списков, то есть сотни
     * миллисекунд, в которые пакеты клиента к этим адресам шли без метки, в WAN. Теперь
     * загрузчик просит резолвер сразу (просьба «reassert», src/dnsd/adopt.c), и окно сужается
     * до одного разговора по сокету; закрыть его совсем нельзя — элементы ставит другой
     * процесс после того, как таблица уже в ядре. Резолвера нет — просить некого, а элементов
     * и нет (память у резолвера). */
    supd_dnsd_reassert();
    return 0;
}

/* Метки «пущен напрямую» (набор failopen) — после загрузки набора правил, по таблицам выходов.
 *
 * Новый набор правил приходит с пустым набором failopen, а привязка выходов теперь идёт ДО
 * загрузки (ниже, «ПОРЯДОК»): отметку, которую apply_routing_one или проход ставили выходу,
 * оставшемуся без устройства в режиме direct/zapret, приняла ещё прежняя таблица и унесла с
 * собой. Поэтому после загрузки — по таблице каждого выхода: маршрута по умолчанию нет — выход
 * пущен напрямую, и отметка возвращается (так же apply-commit делал это для выходов, которых
 * --route не касался). Выход с on_fail=drop сюда не попадает: у него в таблице запрет, и
 * напрямую он не пускается (out_releasable).
 *
 * С цепочкой postrouting_guard (generate.c, «ПОМЕЧЕННЫЙ ПАКЕТ НЕ ТУДА — НИКУДА») от загрузки до
 * этой отметки — миллисекунды запуска ip и nft на выход — трафик выхода, уже пущенного напрямую,
 * отбрасывается, а не идёт в WAN: окно закрыто в сторону «не работает», а не «мимо». Засевать
 * отметки текстом (как карту fake-IP) нечем честно: план их отпечатка не видит, а решает о них
 * таблица выхода в ядре, которую читает этот же проход. */
static void failopen_after_load(const struct spec *cfg) {
    for (size_t i = 0; i < cfg->out_n; i++) {
        const struct output *o = &cfg->out[i];
        if (!out_releasable(o)) continue;
        if (!table_has_default(o->table)) failopen_mark(o, 1);
    }
}

/* Конец применения: снимок status, проверки чужого firewall, итоговая строка. */
static void apply_done_reports(const struct spec *cfg) {
    /* Снимок состояния СНИМАЕТСЯ: он описывает то, что было применено до этой транзакции, и
     * `status --fast` отдавал бы его как нынешнее — то есть прежние выходы и прежние каналы
     * ровно в тот момент, когда человек нажал «Применить» и смотрит, подействовало ли.
     * Пересобрать его здесь нельзя честно: правила уже стоят, а вот таблицы маршрутизации
     * привязывают к своим устройствам сами процессы выходов, и снимок, снятый сейчас, врал
     * бы в другую сторону. Пустое место `--fast` переживает — он тогда считает всё сам. */
    char snap[256];
    status_snap_path(snap, sizeof snap);
    unlink(snap);
    /* Проверки чужого firewall — про fw4: зона выхода и masquerade в его наборе правил. На
     * телефоне fw4 нет, трафик раздачи транслирует netd через iptables, и по дампу nftables
     * эти проверки говорили бы «устройство не упомянуто в firewall» и «нет masquerade» на
     * каждом apply — ложные тревоги, после которых настоящим перестают верить. */
    if (plat()->fw4) {
        report_output_deps(cfg);
        report_traceroute_dep(cfg);
    }
    report_mark_overlap();
    printf("steer: applied %zu channel(s), %zu output(s)\n", cfg->rule_n, cfg->out_n);
}

int cmd_apply(const char *spec, int dry) {
    /* Спека — значение, а не глобалы (правило 6): свой экземпляр у точки входа, static —
     * держать struct spec на стеке нельзя, он большой (правила, списки и клиенты — под 250 КБ). */
    static struct spec cfg;
    static struct groups gr;
    struct err e = {0};
    /* `apply --dry-run` — та же проверка, что check интерфейса: строгая. Просто `apply` — запуск. */
    apply_prepare(spec, &cfg, &gr, 1, -1, 1, dry);
    /* Снять накопленное ДО генерации: она вписывает эти значения в новые правила, иначе
     * каждый apply обнулял бы объёмы. Читаем и при --dry-run — так печатаемый текст остаётся
     * тем, что реально применится, а на машине без таблицы вывод не меняется вовсе. */
    counters_load();
    /* Ни одной группы — таблица всё равно ставится, с пустой цепочкой: так status
     * продолжает отвечать, а следующий apply не зависит от того, была ли таблица
     * раньше. */
    /* Файлы выходов kind=awg — проверяются и при --dry-run: им интерфейс проверяет спеку
     * перед записью, и ошибка в файле туннеля должна быть видна тогда же, а не после
     * применения. Предупреждением в stderr: набор правил от файла туннеля не зависит. */
    if (dry) {
        awg_check_all(&cfg);
        /* Засев — и в --dry-run: интерфейс и стенды сверяют именно то, что встанет в ядро. */
        seed_begin(&cfg, &gr, 0);
        if (generate(&cfg, &gr, stdout, &e) < 0) err_die(&e);
        seed_end();
        return 0;
    }

    /* ПОРЯДОК: МАРШРУТИЗАЦИЯ ДО НАБОРА ПРАВИЛ.
     *
     * Прежде набор правил грузился первым, а правила fwmark и таблицы выходов ставились следом.
     * Перепроверка на QEMU-роутере (2026-09-28) измерила этот
     * промежуток при старте: ~0,65 с метки и подмена fake-IP уже стоят, а ip rule и таблицы выхода
     * ещё нет — помеченный пакет не находит правила и уходит по таблице main, то есть в WAN, мимо
     * выхода и мимо on_fail=drop (запрет — маршрут в таблице выхода, а её никто не спрашивает).
     * Теперь метка не существует ни мгновения без своего правила: сначала устройства awg,
     * таблицы и правила выходов (и запрет on_fail при старте — apply_routing_one ставит его, если
     * устройства нет), потом набор правил.
     *
     * Правило fwmark без меток безвредно: оно спрашивает только пакеты со своей меткой, а метку
     * ставит набор правил — до его загрузки таких пакетов нет (или их метит прежний набор той же
     * меткой: реестр держит метку выхода по имени). Отметки «пущен напрямую», которые привязка
     * ставит выходу без устройства в режиме direct/zapret, принимает прежняя таблица, — новая
     * приходит с пустым набором, и они возвращаются после загрузки (failopen_after_load).
     *
     * Цена порядка — в отказе ядра: если nft отвергнет новый набор, прежний останется стоять, а
     * привязка выходов уже будет новой (новые выходы, сменённые устройства). Правила новых меток
     * безвредны по той же причине, что выше; сменённое устройство понесёт трафик прежнего набора
     * правил того же выхода. Снятие правил прежних меток (cleanup_stale_routing) — по-прежнему
     * только после удачной загрузки: прежний набор ещё метит ими. */
    /* Устройства выходов kind=awg — до привязки таблиц: apply_routing ставит маршрут в
     * устройство, и устройства к этому мгновению обязаны быть (см. src/kinds/awg.c). Отказ одного
     * туннеля не отменяет применённых правил: его таблица получит то же, что у любого выхода
     * без устройства (blackhole при on_fail=drop), а причина уже названа в журнале. */
    awg_apply_all(&cfg);
    apply_routing(&cfg);
    if (ruleset_load(&cfg, &gr) != 0) return 1;
    failopen_after_load(&cfg);
    tcp_redir_after_load(&cfg);
    /* Карта balance из набора правил — «все члены живы»; сразу к живым по подхвату, как её
     * поставил бы проход (fog_balance_adopt в fogroup.c). */
    fog_balance_adopt(&cfg);
    if (plat()->iptables_masq) iptables_masq_sync(&cfg);
    cleanup_stale_routing(&cfg);
    apply_done_reports(&cfg);
    return 0;
}

/* ---- служебные подкоманды демона: apply-plan и apply-commit ---------------------------------
 *
 * Apply-сверка (docs/architecture.md, «4а», «Apply-сверка»; устройство и доводы — в шапке
 * src/daemon/recon.c). Демон не компилирует спеку у себя в процессе: на больших списках это
 * секунды работы процессора и десятки мегабайт памяти, и цикл демона всё это время стоял бы, а
 * куча демона, который живёт месяцами, росла бы пиками. Поэтому план и применение — дети на
 * apply (процесс на команду, а не на проход), и обе половины — здесь, рядом с cmd_apply: те же
 * шаги тем же кодом, только нарезанные.
 *
 * В справке их нет: это не команды для человека, а договор демона с самим собой. Слова строки —
 * свои, короткий разбор ниже; неизвестное слово — отказ с кодом 2. */

struct recon_args {
    const char *spec, *state_dir;
    int nftc;                  /* -1 — спросить ядро */
    int ruleset, awg, masq, masq_ensure;
    int kelems;                /* apply-plan: сводка элементов статических наборов ядра */
    const char *route, *drop;  /* через запятую; NULL — нет */
    const char *rule;          /* только правило выхода, таблицу не трогать (починка демона) */
};

static void recon_args_parse(int argc, char **argv, struct recon_args *a, const char *who) {
    memset(a, 0, sizeof(*a));
    a->nftc = -1;
    a->spec = plat()->spec_path;
    for (int i = 0; i < argc; i++) {
        const char *k = argv[i], *v = i + 1 < argc ? argv[i + 1] : NULL;
        int val = 1;
        if (!strcmp(k, "--spec") && v) a->spec = v;
        else if (!strcmp(k, "--state-dir") && v) a->state_dir = v;
        else if (!strcmp(k, "--nftc") && v) a->nftc = atoi(v);
        else if (!strcmp(k, "--route") && v) a->route = v;
        else if (!strcmp(k, "--drop") && v) a->drop = v;
        else if (!strcmp(k, "--rule") && v) a->rule = v;
        else {
            val = 0;
            if (!strcmp(k, "--ruleset")) a->ruleset = 1;
            else if (!strcmp(k, "--awg")) a->awg = 1;
            else if (!strcmp(k, "--masq")) a->masq = 1;
            else if (!strcmp(k, "--masq-ensure")) a->masq_ensure = 1;
            else if (!strcmp(k, "--kernel-elems")) a->kelems = 1;
            else {
                fprintf(stderr, "steer %s: непонятное слово %s\n", who, k);
                exit(2);
            }
        }
        i += val;
    }
    if (a->state_dir) steer_set_state_dir(a->state_dir);
    /* Выбор select — рядом со спекой, как у демона и подкоманд (steer_keep_dir, platform.h):
     * подхват группы manual (outputs_adopt_active_st) решает по нему, к какому члену привязать её
     * таблицу. Без этого ребёнок демона читал бы файл из каталога платформы, а не рядом со спекой
     * демона: на роутере это один и тот же /etc/steer, а при спеке в другом месте — нет. */
    steer_set_keep_dir_of(plat_spec_resolve(a->spec));
}

/* Отпечаток набора правил без самого текста: generate пишет в поток, поток считает FNV-1a и
 * ничего не хранит. Текст бывает десятками мегабайт — держать его ради сравнения незачем ни в
 * плане, ни в демоне. */
static ssize_t fnv_write(void *c, const char *buf, size_t n) {
    unsigned long long *h = c;
    for (size_t i = 0; i < n; i++) { *h ^= (unsigned char)buf[i]; *h *= 1099511628211ULL; }
    return (ssize_t)n;
}
#ifdef __BIONIC__
/* Писатель для funopen (BSD): длина — int, а не size_t. */
static int fnv_write_bsd(void *c, const char *buf, int n) {
    return (int)fnv_write(c, buf, (size_t)n);
}
#endif

/* Подпись маршрутизации выхода — то, что apply ставит в ip rule и таблицу выхода и что
 * настраивает у выхода kind=awg: вид (каким он виден снаружи — у группы из пула v1 это
 * interface), метка, таблица, режим отказа, устройства кандидатов (у группы — членов; не
 * выбранное сторожем устройство: его смену сторож и так уже поставил в ядро), файл awg целиком.
 * Изменилась — выход привязывается заново; нет — его правило и таблица не трогаются. */
static unsigned long long out_route_sig(const struct spec *sp, const struct output *o, int *awg) {
    unsigned long long h = KIND_SIG_INIT;
    const char *kn = out_kind_name(o);
    kind_sig_mix(&h, kn, strlen(kn));
    kind_sig_mix(&h, &o->mark, sizeof(o->mark));
    kind_sig_mix(&h, &o->table, sizeof(o->table));
    int of = (int)o->on_fail;
    kind_sig_mix(&h, &of, sizeof(of));
    size_t mn = out_members_n(sp, o);
    for (size_t k = 0; k < mn; k++) {
        const char *dev = out_member(sp, o, k)->device;
        kind_sig_mix(&h, dev, strlen(dev));
    }
    if (!mn) kind_sig_mix(&h, o->device, strlen(o->device));
    /* Маршрутизация IPv6 (out_route6): появилась или пропала — выход привязывается заново. В
     * подпись входит только тогда, когда она есть, — у выходов без IPv6 подпись прежняя. */
    if (out_route6(o)) kind_sig_mix(&h, "ipv6", 4);
    *awg = !strcmp(kn, "awg");
    if (*awg) {
        /* Ключи и адреса — в файле, не в спеке: новый файл под тем же именем — тоже смена. */
        kind_sig_mix(&h, o->awg.conf, strlen(o->awg.conf));
        FILE *f = fopen(o->awg.conf, "r");
        if (f) {
            unsigned long long fh = KIND_SIG_INIT;
            char buf[4096];
            size_t m;
            while ((m = fread(buf, 1, sizeof(buf), f)) > 0) fnv_write(&fh, buf, m);
            fclose(f);
            kind_sig_mix(&h, &fh, sizeof(fh));
        }
    }
    return h;
}

/* Подпись того, что читает сторож (кроме помощника — его подпись сверяет супервизор): маршрут,
 * подложка over, выбор группы (pick и его числа). Изменилась — сторожу внеочередной проход. */
static unsigned long long out_watch_sig(const struct output *o, unsigned long long rsig) {
    unsigned long long h = rsig;
    kind_sig_mix(&h, o->over, strlen(o->over));
    const struct group_cfg *g = out_group(o);
    int lat[3] = { g ? (int)g->pick : 0, g ? g->lat_tolerance_ms : 0, g ? g->lat_interval_s : 0 };
    kind_sig_mix(&h, lat, sizeof(lat));
    return h;
}

/* apply-plan --spec ПУТЬ [--state-dir …] [--nftc N] [--kernel-elems]: всё, что делает `apply --dry-run` (те же
 * проверки, те же предупреждения в stderr, тот же код отказа), только набор правил не печатается,
 * а сворачивается в отпечаток. Счётчики из ядра не читаются нарочно: план не зовёт ни одного
 * процесса (раскладку демон передаёт готовой), а перенос счётчиков — дело apply-commit, который
 * пересобирает текст уже с ними. В stdout — план строками:
 *   nftc N                      раскладка набора правил (NFTC_*)
 *   ruleset ОТПЕЧАТОК           FNV-1a 64 текста набора правил без счётчиков
 *   counts КАНАЛОВ ВЫХОДОВ
 *   out ИМЯ МЕТКА ТАБЛИЦА С_УСТРОЙСТВОМ AWG ПОДПИСЬ_МАРШРУТА ПОДПИСЬ_СТОРОЖА
 *   stale МЕТКА ТАБЛИЦА         метка из прежнего реестра, которую не несёт ни один выход
 *   kelems СВОДКА ЧИСЛО         с --kernel-elems: сводка элементов статических наборов в ядре
 *                               (recon_kernel_elems; «kelems -» — снять не вышло). Дамп —
 *                               сотни тысяч элементов на больших списках, поэтому здесь, в
 *                               ребёнке, а не в цикле демона (шапка recon.c, «СВЕРКА
 *                               ЭЛЕМЕНТОВ»); процессов он не запускает. */
int cmd_apply_plan(int argc, char **argv) {
    struct recon_args a;
    recon_args_parse(argc, argv, &a, "apply-plan");
    static struct spec cfg;
    static struct groups gr;
    struct err e = {0};
    apply_prepare(a.spec, &cfg, &gr, 1, a.nftc, 1, 1);
    awg_check_all(&cfg);
    unsigned long long h = 14695981039346656037ULL;
    /* Поток-отпечаток: fopencookie есть в glibc и musl, но в bionic его нет вовсе (даже с
     * _GNU_SOURCE) — там его BSD-двойник funopen с писателем на int. Текст набора правил не
     * собирается в буфер целиком нарочно: на больших списках это мегабайты. */
#ifdef __BIONIC__
    FILE *f = funopen(&h, NULL, fnv_write_bsd, NULL, NULL);
#else
    cookie_io_functions_t io = { .write = fnv_write };
    FILE *f = fopencookie(&h, "w", io);
#endif
    if (!f) die("не открыть поток для отпечатка набора правил", NULL);
    static char buf[65536];
    setvbuf(f, buf, _IOFBF, sizeof(buf));
    /* Отпечаток — без засева карты fake-IP из файла состояния резолвера: файл растёт с каждым
     * выданным адресом, и с засевом та же спека давала бы новый отпечаток после любого нового
     * имени в сети, то есть полную замену таблицы на каждый reload (print.c, у print_elements).
     * Загрузка (apply-commit --ruleset, ruleset_load) печатает засев как прежде — план в ядро
     * не идёт и текста не хранит, так что другого читателя у этого флага здесь нет. */
    g_print_state_seed = 0;
    if (generate(&cfg, &gr, f, &e) < 0) err_die(&e);
    fclose(f);
    printf("nftc %d\nruleset %016llx\ncounts %zu %zu\n", g_nftc, h, cfg.rule_n, cfg.out_n);
    for (size_t i = 0; i < cfg.out_n; i++) {
        const struct output *o = &cfg.out[i];
        int awg = 0;
        unsigned long long rs = out_route_sig(&cfg, o, &awg);
        printf("out %s %x %d %d %d %016llx %016llx\n", o->name, o->mark, o->table,
               out_has_device(o), awg, rs, out_watch_sig(o, rs));
    }
    for (size_t i = 0; i < g_oldreg_n; i++) {
        int live = 0;
        for (size_t k = 0; k < cfg.out_n; k++)
            if (out_needs_mark(&cfg.out[k]) && cfg.out[k].mark == g_oldreg[i].mark) live = 1;
        if (!live) printf("stale %x %d\n", g_oldreg[i].mark, g_oldreg[i].table);
    }
    if (a.kelems) {
        uint64_t el = 0, en = 0;
        if (recon_kernel_elems(&el, &en) == 0)
            printf("kelems %016llx %llu\n", (unsigned long long)el, (unsigned long long)en);
        else
            printf("kelems -\n");
    }
    return 0;
}

/* Есть ли в таблице выхода маршрут по умолчанию (устройство или запрет). Нет — выход пущен
 * напрямую (apply_failed в режиме direct/zapret или неудачная привязка выше). */
static int table_has_default(int table) {
    /* Вопрос ядру по netlink, а не `ip -4 route show table N` через popen: apply спрашивает это
     * про каждый выход дважды, и с десятками выходов это были сотни процессов sh и ip на apply.
     * netlink отказал — как прежде при отказе popen: считаем, что маршрут есть. */
    int r = rtnl_table_has_default(table);
    return r < 0 ? 1 : r;
}

static int name_in_list(const char *list, const char *name) {
    if (!list) return 0;
    size_t n = strlen(name);
    for (const char *p = list; *p; ) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (l == n && !strncmp(p, name, n)) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

/* apply-commit --spec ПУТЬ [--ruleset] [--route А,Б] [--drop МЕТКА:ТАБЛИЦА,…] [--awg] [--masq]
 * [--nftc N] [--state-dir …]: применить ТОЛЬКО изменившиеся части — что именно, решил демон по
 * плану (recon.c).
 *   --ruleset  набор правил одной транзакцией, со счётчиками из ядра — тем же ruleset_load, что у
 *              подкоманды; отказ ядра — код 1, прежняя таблица стоит, остальное не трогается;
 *              принят — строка `recon-kernel НОМЕР ОТПЕЧАТОК` в stdout (ожидаемое сверки демона
 *              с ядром, снятое сразу после nft -f, — recon_kernel_print);
 *   --route    привязать таблицы и правила этих выходов (apply_routing_one);
 *   --drop     снять правило и таблицу меток, которых больше не несёт ни один выход (как
 *              cleanup_stale_routing);
 *   --awg      настроить устройства kind=awg (awg_apply_all — поверх, живые сессии не рвутся) и
 *              снять устройства убранных выходов;
 *   --masq     masquerade выходов на телефоне (iptables_masq_sync);
 *   --rule     вернуть только правило этих выходов (rule_ensure), таблицу не трогая, — починка
 *              демона после чужого удаления правил (src/daemon/rulewd.c): таблица выхода в этот
 *              момент цела, и в ней может стоять запрет сторожа (on_fail=drop), который
 *              перепривязка к устройству (--route) сняла бы до следующего прохода;
 *   --masq-ensure  вернуть недостающий masquerade, не снимая стоящего (iptables_masq_ensure):
 *              после перезапуска netd, а не после смены спеки.
 * Порядок — привязка (--awg, --route), затем набор правил (--ruleset), как у подкоманды. Новый
 * набор правил приходит с пустым набором «пущен напрямую»: отметки всех выходов возвращаются
 * после загрузки по их таблицам (failopen_after_load). */
int cmd_apply_commit(int argc, char **argv) {
    struct recon_args a;
    recon_args_parse(argc, argv, &a, "apply-commit");
    static struct spec cfg;
    static struct groups gr;
    apply_prepare(a.spec, &cfg, &gr, a.ruleset, a.nftc, a.ruleset, 0);
    /* Порядок — как у подкоманды (cmd_apply, «ПОРЯДОК»): устройства kind=awg, привязка выходов,
     * и только потом набор правил — чтобы новая метка не существовала без своего правила. Этим
     * путём идёт и старт демона (--apply: первый apply применяет всё). */
    if (a.awg) awg_apply_all(&cfg);
    for (size_t i = 0; i < cfg.out_n; i++)
        if (name_in_list(a.route, cfg.out[i].name)) apply_routing_one(&cfg.out[i]);
    if (a.ruleset) {
        counters_load();
        if (ruleset_load(&cfg, &gr) != 0) return 1;
        /* Ожидаемое для сверки демона с ядром — сразу после nft -f: правка таблицы снаружи за то
         * время, что идёт остальное, иначе вошла бы в ожидаемое (шапка recon.c, «СВЕРКА С
         * ЯДРОМ»). Строка — в stdout; демон вырезает её из ответа. Вместе с отпечатком — сводка
         * элементов статических наборов, и это дамп всех элементов (на 200 тысячах подсетей —
         * около 0,5 с машины разработки); привязка выходов теперь идёт ДО загрузки, так что он её
         * не задерживает, а откладывает только отметки «пущен напрямую» и карту balance ниже.
         * Засеянные в набор правил поддельные адреса (fpseed.c) и элементы real-ip, которые
         * резолвер вернул по просьбе загрузчика внутри ruleset_load, в сводку не входят: у
         * доменного набора она берёт только элементы без срока вне пула fake-IP (recon.c). */
        recon_kernel_print(stdout);
        /* Новый набор правил принёс пустой набор «пущен напрямую» и карты balance со всеми
         * членами: отметки — по таблицам выходов (и тех, что привязаны выше: их отметку приняла
         * прежняя таблица), карты — к живым, как у подкоманды. */
        failopen_after_load(&cfg);
        tcp_redir_after_load(&cfg);
        fog_balance_adopt(&cfg);
    }
    for (const char *p = a.drop; p && *p; ) {
        unsigned mark = 0;
        int table = 0;
        if (sscanf(p, "%x:%d", &mark, &table) == 2 && mark && !(mark & ~STEER_MARK_MASK)) {
            int live = 0;
            for (size_t k = 0; k < cfg.out_n; k++)
                if (out_needs_mark(&cfg.out[k]) && cfg.out[k].mark == mark) live = 1;
            if (!live) {
                routing_drop(mark, table);
            }
        }
        const char *e = strchr(p, ',');
        if (!e) break;
        p = e + 1;
    }
    for (size_t i = 0; i < cfg.out_n; i++) {
        const struct output *o = &cfg.out[i];
        if (!name_in_list(a.rule, o->name) || !out_has_device(o)) continue;
        rule_ensure(o->mark, o->table);
        /* Правило IPv6 — тем же ходом (страж ловит и RTNLGRP_IPV6_RULE, см. rulewd.c). */
        if (out_route6(o)) rule_ensure6(o->mark, o->table);
    }
    if (a.masq && plat()->iptables_masq) iptables_masq_sync(&cfg);
    else if (a.masq_ensure && plat()->iptables_masq) iptables_masq_ensure(&cfg);
    /* Починка (только --rule и --masq-ensure) — не применение: снимок status описывает то же, что
     * и до неё, а отчёты apply о зависимостях и итоговая строка в журнале демона были бы
     * повтором последнего apply. */
    if (!a.ruleset && !a.route && !a.drop && !a.awg && !a.masq) return 0;
    apply_done_reports(&cfg);
    return 0;
}
