/* steer — compile a channel spec into nftables rules and policy routing.
 *
 * Own table, not an fw4 include. Three reasons, all learned from splify:
 *   * an fw4 reload REPLACES table inet fw4, which drains every set living inside
 *     it — a separate `table inet steer` simply survives;
 *   * one `nft -f` is atomic: either the whole channel set applies or nothing does,
 *     with no window where a rule references a set that is not there yet;
 *   * uninstall is `nft delete table inet steer`, and nothing of ours can break
 *     someone else's firewall by being malformed.
 *
 * Precedence is expressed with `return` rather than a "mark is still zero" guard:
 * inside our own chain the first matching rule wins by construction, which is
 * exactly the ordered-channels semantics the spec promises.
 */
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
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "srsread.h"
#include "ctl.h"
#include "daemon.h"
#include "groups.h"
#include "v2.h"
#include "fogroup.h"
#include "ctlcall.h"
#include "modcmd.h"

/* ПОДКОМАНДА ПРИ ЖИВОМ ДЕМОНЕ — ЕГО ОТВЕТОМ. status и diag подкомандой собирают тот же ответ, что
 * демон (status_answer, diag_emit), но без его памяти: хода перебора узлов vless (клиент с
 * трубой событий файлов probe-* не пишет), замеров групп latency (живут в памяти сторожа),
 * состояния помощников (отставленные пути моста tgws). Клиент steer и так идёт к демону, а
 * мимо него остаётся прямой вызов `steerd status` — так его делает rpcd на роутере. Поэтому
 * подкоманда сперва спрашивает демон ЭТИХ спеки и каталога состояния (version, как клиент) и
 * отдаёт его ответ байт в байт, а сама считает, только когда демона нет, он чужой или не
 * ответил.
 *
 * Сокет, а не запись демоном хода перебора в файл на tmpfs: файл закрыл бы один перебор узлов,
 * а память демона — это ещё замеры и помощники, и писать её в файл на каждое событие значило
 * бы держать вторую копию состояния, которая однажды разойдётся с первой. Цена сокета — два
 * коротких запроса к демону, который отвечает на них из памяти за миллисекунды.
 *
 * STEER_DAEMON_ASKED — клиент steer уже спрашивал демон и отдал команду движку, потому что тот
 * не ответил или чужой: спрашивать второй раз незачем (зависший демон стоил бы второго срока). */
static int ask_daemon(const char *line, const char *spec, const char *state_dir) {
    const char *asked = getenv("STEER_DAEMON_ASKED");
    if (asked && *asked) return -1;
    ctlcall_socket(NULL);
    return ctlcall_forward(line, spec, state_dir, 10);
}

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы
 * здесь «apply»: все строки ниже пишутся при компиляции и применении спеки. Отказы
 * вызывающему (die и разбор аргументов) уровня НЕ несут и несут «steer: » — это ответ
 * тому, кто позвал, а не запись в журнал; так и записано в контракте. */
int dnsd_main(int argc, char **argv);
/* steer dns-probe — проверка DNS-серверов слоем апстримов резолвера (src/dnsd/dprobe.c). */
int dns_probe_main(int argc, char **argv);
void dns_probe_usage_flags(FILE *f);

/* Имя таблицы правил (nft_table) — в spec.h: его спрашивает и сторож, см. failopen_mark в
 * failover.c. */

int cmd_failover(const char *spec, int verbose);
void probe_rule_cleanup(void);   /* failover.c */
/* Свои флаги эти двое печатают сами — см. комментарии у объявлений. Справка по ним
 * склеивается из таблицы (что команда делает) и этих строк (чем ей управляют). */
void dnsd_usage_flags(FILE *out);
void aggregate_usage_flags(FILE *out);
/* Подпись таблицы доменных каналов: ею init-скрипт решает, хватит ли резолверу SIGHUP или
 * нужен перезапуск с пятисекундной паузой procd. Живёт в dnsd/table.c — там таблица. */
int dnsd_sig_print(const char *spec, FILE *out);
/* Та же таблица, которую демон шлёт резолверу трубой --table-fd (docs/architecture.md, раздел
 * 4а) — текстом в stdout, для стендов и ручной отладки. src/dnsd/tabfmt.c. */
void tabfmt_build(const struct spec *sp, FILE *out);
/* КОМАНДЫ МОДУЛЕЙ, КОТОРЫХ В СБОРКЕ МОЖЕТ НЕ БЫТЬ (docs/architecture.md, раздел 2, правило 3).
 *
 * Клиенты VLESS и xsteer, подписка, обфускатор, мост Telegram и служебные команды xsteer — команды
 * модулей; что с ними делает steerd (исполняет на месте в статической сборке, запускает
 * бинарник модуля или называет пакет), решает src/cli/modcmd.c, там же слабые ссылки на них и
 * контрактные тексты отказов. Здесь остался один хаб: он не модуль роутера, а отдельный архив
 * для VPS (профиль server).
 *
 * ЕДИНСТВЕННАЯ ПОДКОМАНДА «VLESS», КОТОРАЯ ОТВЕЧАЕТ БЕЗ МОДУЛЯ. Идентификатор роутера считает
 * src/tools/hwid.c, входящий в каждую сборку: читателей у него стало двое, и второй (телеметрия
 * splify2) работает на роутере, где расширенной части нет. Заглушки поэтому нет — есть
 * настоящая функция, объявленная в hwid.h. */
int cmd_xsteer_hub(const char *conf) __attribute__((weak));

static int no_hub(void) {
    /* ВТОРАЯ контрактная подстрока — «steer-hub». Она отличает «нужен другой пакет для
     * роутера» от «нужен артефакт для сервера», и без этого различия человека посылали бы
     * ставить steer-extended туда, где хаба всё равно не будет. */
    fprintf(stderr, "steer: хаб xsteer в этой сборке отсутствует — "
                    "он ставится на VPS из архива steer-hub\n");
    return 2;
}

int aggregate_main(int argc, char **argv);

/* Роль steer-tools (docs/architecture.md, раздел 2, «Процессы»): ссылка на steerd, и под этим
 * именем движок отвечает только на инструменты — то, что не трогает ни правил, ни демона и
 * нужно человеку и управляющему слою отдельно от движка. Отличается argv[0], а не сборкой: файл
 * один, и расходиться инструментам с движком негде. */
static const char *const TOOLS[] = {
    "fit", "srs-read", "obfs-server", "sub-fetch", "sub-quota", "sub-hwid", "dev-id",
    "tls-probe", "tgws-probe", "vless-nodes", "proxy-nodes", "xsteer-key", "xsteer-link", "xsteer-check",
    "xsteer-hub", "dnsd-table", NULL,
};

static int tools_role(const char *argv0) {
    const char *b = strrchr(argv0, '/');
    return !strcmp(b ? b + 1 : argv0, "steer-tools");
}

static int is_tool(const char *cmd) {
    for (size_t i = 0; TOOLS[i]; i++)
        if (!strcmp(TOOLS[i], cmd)) return 1;
    return 0;
}

int main(int argc, char **argv) {
    /* Платформа (src/platform/platform.h) — до всего остального (modcmd_platform_args, общая с
     * модулями): от неё зависят пути по умолчанию, справка и раскладка меток. */
    if (modcmd_platform_args(&argc, argv) != 0) return 2;
    plat();
    if (argc < 2) {
        cli_usage_short(stderr);
        return 2;
    }
    const char *cmd = argv[1];
    if (tools_role(argv[0]) && !is_tool(cmd) && strcmp(cmd, "help") && strcmp(cmd, "--help") &&
        strcmp(cmd, "-h") && strcmp(cmd, "version") && strcmp(cmd, "--version") &&
        strcmp(cmd, "-V")) {
        fprintf(stderr, "steer-tools: %s — не инструмент, а команда ядра: steer %s\n"
                        "       инструменты:", cmd, cmd);
        for (size_t i = 0; TOOLS[i]; i++) fprintf(stderr, " %s", TOOLS[i]);
        fputc('\n', stderr);
        return 2;
    }

    /* Справка и версия — до поиска команды: это не команды движка, а вопросы к нему.
     * Обе формы, и слово, и флаг: `steer --help` человек набирает не задумываясь, а
     * раньше получал «unknown command: --help» с кодом 2. */
    if (!strcmp(cmd, "help") || !strcmp(cmd, "--help") || !strcmp(cmd, "-h")) {
        if (argc > 2) {
            const struct cli_cmd *c = cli_lookup(argv[2]);
            if (!c) cli_unknown(argv[2]);
            cli_help(stdout, c);
        } else {
            cli_help(stdout, NULL);
        }
        return 0;
    }
    if (!strcmp(cmd, "version") || !strcmp(cmd, "--version") || !strcmp(cmd, "-V")) {
        cli_version(stdout);
        return 0;
    }
    /* Флаг вместо команды. Отдельная строка, потому что «нет такой команды: --spec»
     * не объясняет, что именно не так с порядком слов. */
    if (cmd[0] == '-') {
        fprintf(stderr, "steer: флаги идут после команды, а не до неё: %s\n", cmd);
        fprintf(stderr, "       например: steer apply --spec %s\n"
                        "       список команд: steer help\n", plat()->spec_path);
        return 2;
    }

    /* Служебные подкоманды демона (apply-сверка, src/daemon/recon.c): их запускает только сам
     * демон, в справке и таблице команд их нет, и слова у них свои. */
    if (!strcmp(cmd, "apply-plan")) return cmd_apply_plan(argc - 2, argv + 2);
    if (!strcmp(cmd, "apply-commit")) return cmd_apply_commit(argc - 2, argv + 2);

    const struct cli_cmd *c = cli_lookup(cmd);
    if (!c) cli_unknown(cmd);
    /* Просьба о справке перехватывается ДО разбора, одинаково для всех команд —
     * включая fit и dnsd, у которых свои парсеры аргументов. */
    if (cli_wants_help(argc - 2, argv + 2)) {
        cli_help(stdout, c);
        /* У команд со своим разбором список флагов знает только их парсер, поэтому
         * справка склеивается из двух половин. */
        if (c->passthru) {
            fputs("\nФлаги:\n", stdout);
            if (!strcmp(cmd, "fit")) aggregate_usage_flags(stdout);
            else if (!strcmp(cmd, "daemon") || !strcmp(cmd, "ctl-serve") || !strcmp(cmd, "ctl"))
                ctl_usage_flags(stdout);
            else if (!strcmp(cmd, "dns-probe")) dns_probe_usage_flags(stdout);
            else dnsd_usage_flags(stdout);
        }
        return 0;
    }

    /* У fit и dnsd свои аргументы, и общий разбор молча съел бы, например, --budget.
     * Такие команды помечены в таблице как passthru и получают argv как есть. */
    if (c->passthru) {
        if (!strcmp(cmd, "fit")) return aggregate_main(argc - 1, argv + 1);
        /* ctl-serve — прежнее имя демона: под ним его запускает сервис телефона
         * (vendor/der, init/steerd.rc), и оно остаётся синонимом. */
        if (!strcmp(cmd, "daemon") || !strcmp(cmd, "ctl-serve"))
            return ctl_serve_main(argc - 2, argv + 2);
        if (!strcmp(cmd, "ctl")) return ctl_client_main(argc - 2, argv + 2);
        if (!strcmp(cmd, "dns-probe")) return dns_probe_main(argc - 2, argv + 2);
        return dnsd_main(argc - 2, argv + 2);
    }

    struct cli_args a;
    /* Разбор спеки и раздача меток реестра возвращают отказ, а не завершают процесс сами
     * (правило 5, docs/architecture.md, раздел 2) — здесь, в точке входа, err_die довершает
     * то же самое: код 2, тот же текст, что раньше печатал die() изнутри load_spec. */
    struct err e = {0};
    /* Спека — значение, а не глобалы (правило 6): один экземпляр на весь диспетчер команд,
     * static — держать struct spec на стеке нельзя, он большой. */
    static struct spec cfg;
    static struct groups gr;
    cli_parse(c, argc, argv, 2, &a);
    if (a.state_dir) steer_set_state_dir(a.state_dir);
    /* Выбор человека (select) — рядом со спекой этого запуска (platform.h, steer_keep_dir). */
    steer_set_keep_dir_of(plat_spec_resolve(a.spec));
    const char *spec = a.spec, *arg = a.npos ? a.pos[0] : NULL;

    if (!strcmp(cmd, "apply")) return cmd_apply(spec, a.dry_run);
    /* Эти две исполняет демон, а посылает клиент steer (src/client/main.c). Сюда они доходят,
     * только если движок позвали напрямую или клиент не нашёл демона своей спеки. */
    if (!strcmp(cmd, "reload") || !strcmp(cmd, "subscribe")) {
        fprintf(stderr, "steer: команду %s исполняет демон ядра (steerd daemon), а посылает "
                        "ему клиент steer\n", cmd);
        return 2;
    }
    /* Перевод спеки в v2 (docs/spec-v2.md): разбор тем же load_spec, что у всех, и печать модели
     * спекой v2 (src/model/v2print.c). Спеку на диске не трогает. */
    if (!strcmp(cmd, "spec")) {
        if (strcmp(arg, "convert") != 0)
            die("steer spec понимает только convert, а не «%s»", arg);
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if ((a.json ? spec_print_v2_json(stdout, &cfg, &e) : spec_print_v2(stdout, &cfg, &e)) < 0)
            err_die(&e);
        return fflush(stdout) == 0 ? 0 : 1;
    }
    /* status и diag при живом демоне этой спеки — его ответом (ask_daemon): ход перебора узлов,
     * замеры групп и состояние помощников знает только он. --fast — снимок на диске, тот же у
     * обоих, спрашивать незачем. */
    if (!strcmp(cmd, "status")) {
        int rc = a.fast ? -1 : ask_daemon("status\n", spec, a.state_dir);
        return rc >= 0 ? rc : cmd_status(spec, a.fast);
    }
    if (!strcmp(cmd, "diag")) {
        int rc = ask_daemon("diag\n", spec, a.state_dir);
        return rc >= 0 ? rc : cmd_diag(spec);
    }
    if (!strcmp(cmd, "down")) return cmd_down();
    if (!strcmp(cmd, "supervise")) return cmd_supervise(spec);
    if (!strcmp(cmd, "failover"))
        return cmd_failover(spec, a.verbose);
    /* Без демона (клиент его не нашёл или движок позван напрямую): то же, что делает демон, но с
     * памятью сторожа в файлах каталога состояния (src/daemon/fogroup.c). */
    if (!strcmp(cmd, "select")) return cmd_select(spec, a.pos[0], a.pos[1]);
    if (!strcmp(cmd, "explain")) {
        /* Адрес ИЛИ имя. Проверка формы обязательна для обоих: аргумент подставляется в
         * вызов nft, и именно здесь однажды была дыра — адрес уходил в system(). */
        if (!addr_ok(arg) && !looks_like_name(arg))
            die("это не адрес и не имя: %s", arg);
        return cmd_explain(spec, arg);
    }
    /* Перечислить выходы заданного вида. Init-скрипту нужно знать, для каких выходов
     * поднимать процесс, и спрашивать об этом движок — то же правило, что с needs-dnsd:
     * grep по ключу в JSON ломается при первом же переименовании поля, причём молча. */
    if (!strcmp(cmd, "outputs")) {
        /* Вид проверяется по списку, а не сравнивается как есть: `--kind vles` (опечатка)
         * давал пустой вывод и код 0, а по этому выводу init-скрипт решает, каким выходам
         * поднимать процессы. Тишина вместо отказа означала бы не поднятый туннель без
         * единой строки о причине. */
        /* warp-masque — член kind: warp (TUN модуля steer-warpbox): в реестре видов его нет (руками в
         * спеке не пишется), но управляющему слою устройства таких членов нужны так же, как awg, — для
         * зоны фаервола. */
        if (a.kind && !kind_by_name(a.kind) && strcmp(a.kind, kind_warpm.name) != 0)
            die("--kind: нужен вид выхода (direct, block, interface, awg, vless, hysteria2, trojan, shadowsocks, socks, http, vmess, xsteer, tgws, group), а не %s", a.kind);
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        for (size_t i = 0; i < cfg.out_n; i++) {
            const char *k = out_kind_name(&cfg.out[i]);
            if (a.kind && strcmp(a.kind, k) != 0) continue;
            /* --obfs — отдельный признак, а не вид: обфускация есть свойство выхода,
             * и init-скрипту нужен именно список тех, кому поднимать процесс. */
            if (a.obfs && !iface_obfs(&cfg.out[i])) continue;
            if (a.via) {
                if (cfg.out[i].over[0]) printf("%s\t%s\n", cfg.out[i].name, cfg.out[i].over);
                continue;
            }
            /* --devices печатает устройство, и выход без устройства (kind=direct) при этом
             * пропускается: пустая строка в списке для настройки фаервола хуже её отсутствия. */
            if (a.devices) {
                if (cfg.out[i].device[0]) printf("%s\n", cfg.out[i].device);
                continue;
            }
            printf("%s\n", cfg.out[i].name);
        }
        return 0;
    }
    /* Нужен ли этой спеке резолвер. Спрашивают у движка, а не угадывают по тексту
     * файла: init-скрипт когда-то искал в нём буквальное `"domains_file"`, спека
     * обзавелась множественным `domains_files`, и совпадение молча перестало
     * находиться — резолвер не поднимался, а apply при этом ставил перенаправление
     * DNS, и каждый запрос из LAN уходил в закрытый порт. Что будет сгенерировано,
     * знает только движок, поэтому отвечает он. */
    /* Что поднимать init-скрипту для выходов kind=tgws: по строке на выход, код 0, если поднимать
     * есть что. Что печатается и почему, — kinds/tgws.c. */
    if (!strcmp(cmd, "tgws-instances")) {
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if (registry_assign(&cfg, &e) < 0) err_die(&e);
        return tgws_instances(&cfg);
    }
    /* ХВАТИТ ЛИ РЕЗОЛВЕРУ SIGHUP. Печатает подпись таблицы каналов по текущей спеке; сам
     * резолвер положил такую же в каталог состояния при запуске. Совпали — init-скрипт
     * посылает HUP, и локальная сеть не теряет разрешение имён ни на секунду; разошлись —
     * нужен перезапуск, потому что состав каналов HUP не пересобирает.
     *
     * Отдельной командой, а не полем status: её читает оболочка построчно и сравнивает
     * целиком, а не разбирает. Тот же довод, что у tgws-instances и needs-dnsd. */
    if (!strcmp(cmd, "dnsd-sig")) return dnsd_sig_print(spec, stdout);
    /* Та же таблица, которую резолвер получил бы трубой --table-fd — текстом в stdout, для
     * стендов (труба вместо файла спеки) и ручной отладки. Формат — src/dnsd/tabfmt.h. */
    if (!strcmp(cmd, "dnsd-table")) {
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        tabfmt_build(&cfg, stdout);
        return 0;
    }
    /* Спеку обе не читают: соединения сопоставляются с выходами по реестру меток (метки
     * ПРИМЕНЁННОЙ спеки — см. ctnl_conns_print), журнал отдаёт сам резолвер. --spec они
     * принимают ради управляющего сокета, который передаёт его каждой подкоманде. */
    if (!strcmp(cmd, "conns")) return ctnl_conns_print(stdout);
    if (!strcmp(cmd, "dns-log")) return dlog_print(stdout);
    if (!strcmp(cmd, "needs-dnsd")) {
        /* ВСЕГДА 0 — решение владельца, и оно про устройство, а не про экономию.
         *
         * Спека всё равно загружается: команда обязана отвечать отказом на спеке, которую
         * движок не понимает, иначе init-скрипт поднял бы резолвер под конфигурацию,
         * которую applyиный проход отверг бы. Ответ же не зависит от её содержимого:
         * перенаправление DNS теперь стоит всегда (см. генератор набора правил), и
         * резолвер, к которому оно ведёт, обязан существовать всегда вместе с ним.
         *
         * Чем это лучше прежнего `has_domains() ? 0 : 1`: доменность канала стала
         * зависеть от содержимого файлов списков (домен и подсеть лежат в одном), то есть
         * могла бы перевернуться ночным обновлением. Раньше этот код отвечал на вопрос
         * «нужен ли», теперь — «поднимаем», и переворачиваться нечему. */
        if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
        if (registry_assign(&cfg, &e) < 0) err_die(&e);
        if (build_groups(&cfg, &gr, &e) < 0) err_die(&e);
        return dnsd_wanted() ? 0 : 1;
    }
    if (!strcmp(cmd, "sub-hwid")) return cmd_sub_hwid();
    if (!strcmp(cmd, "dev-id")) return cmd_dev_id();
    if (!strcmp(cmd, "srs-read")) return srs_dump(arg, a.out_file, a.prefixes_out, a.meta_out);
    /* Хаб живёт на VPS: спека ему не нужна и не читается — там ни выходов, ни каналов, а
     * есть конфигурация звезды и порт. Прецедент тот же, что у obfs-server. */
    if (!strcmp(cmd, "xsteer-hub")) return cmd_xsteer_hub ? cmd_xsteer_hub(a.config) : no_hub();
    /* Команды модулей (VLESS и подписка, xsteer, обфускатор, мост Telegram): на месте, если
     * модуль слинкован в этот бинарник, иначе — запуском steer-<модуль> или отказом «нужен
     * пакет» (src/cli/modcmd.c). */
    {
        int mrc = modcmd_run(cmd, argc, argv, &a, spec, arg, &cfg);
        if (mrc != MODCMD_NONE) return mrc;
    }
    /* Сюда попасть нельзя: имя нашлось в таблице, значит ветка для него есть. Если
     * всё-таки попали — в таблицу добавили команду и забыли про диспетчер. */
    die("команда %s объявлена, но не подключена — это ошибка в ядре steer", cmd);
    return 2;
}

