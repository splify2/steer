/* Команды модулей (modcmd.h): и заглушки steerd, и настоящие ветки бинарников модулей.
 *
 * КОМАНДЫ МОДУЛЕЙ, КОТОРЫХ В СБОРКЕ МОЖЕТ НЕ БЫТЬ (docs/architecture.md, раздел 2, правило 3).
 *
 * Клиенты VLESS и xsteer, подписка, мост Telegram и обфускатор живут в своих файлах, и есть ли
 * они в бинарнике, решает список файлов в build/sources.mk. Ссылки на них здесь СЛАБЫЕ — как у
 * реестра видов (src/kinds/kind.c): файла в списке нет — адрес нулевой. Там, где команды нет,
 * она отвечает внятным отказом, а не отсутствует: «неизвестная команда» на steer vless
 * заставила бы искать опечатку вместо того, чтобы поставить нужный пакет.
 *
 * ТРИ СЛУЧАЯ ОДНОЙ КОМАНДЫ (для `steer vless …`):
 *   1. cmd_vless слинкована сюда — статическая сборка (телефон, стенды) или сам бинарник модуля
 *      steer-vless: команда исполняется на месте;
 *   2. её нет, но модуль установлен (steer-vless лежит рядом со steerd): steerd запускает его
 *      той же командной строкой — тот же разбор аргументов, тот же вывод и код выхода, splify2
 *      разницы не видит;
 *   3. её нет и модуля нет: отказ со словами «нужен пакет» и КОНТРАКТНОЙ подстрокой (ниже).
 *
 * ПОДСТРОКУ «steer-extended» В ОТКАЗАХ ЧИТАЮТ СНАРУЖИ — это контракт, а не просто текст.
 * splify2 определяет вид установленного пакета так:
 *     out="$(steer vless '' 2>&1)"; case "$out" in *steer-extended*) vless=0 ;; esac
 * и по результату решает, показывать ли вкладку VLESS целиком. С выпуска 1.10 пакетов на модуль
 * несколько (steer-vless, steer-xsteer, steer-obfs, steer-tgws), а steer-extended остался
 * пакетом, который ставит их все, — поэтому отказ называет и модуль, и steer-extended. Слово
 * steer-extended обязано в нём остаться, пока splify2 не научится читать имена модулей;
 * закреплено стендом tests/climatch.sh («vless '' называет пакет»).
 *
 * Объявлены здесь, а не подключением заголовков протоколов (tgws.h, subfetch.h): ядро не
 * включает заголовков протоколов, иначе его сборка без расширенной части формально зависела бы
 * от их файлов — tests/buildmatch.sh сверяет это замыканием по #include. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "spec.h"
#include "cli.h"
#include "evline.h"
#include "grpurl.h"
#include "module.h"
#include "modcmd.h"
#include "platform.h"
#include "registry.h"

int cmd_tgws(const char *spec_path, const char *out_name) __attribute__((weak));
int cmd_tgws_probe(int dc, int media, int direct, int timeout_s) __attribute__((weak));
int cmd_tls_probe(const char *host, const char *addr, int port, int local_port,
                  int quiet) __attribute__((weak));
int cmd_vless(const char *spec_path, const char *out_name) __attribute__((weak));
int cmd_vless_nodes(const char *spec_path, const char *out_name, int insecure) __attribute__((weak));
int cmd_vless_probe(const char *spec_path, const char *out_name, int node,
                    int timeout_s, int insecure) __attribute__((weak));
int cmd_hysteria2(const char *spec_path, const char *out_name) __attribute__((weak));
int cmd_hysteria2_nodes(const char *spec_path, const char *out_name, int insecure) __attribute__((weak));
int cmd_hysteria2_probe(const char *spec_path, const char *out_name, int node,
                        int timeout_s, int insecure) __attribute__((weak));
int cmd_proxy(const char *spec_path, const char *out_name) __attribute__((weak));
int cmd_proxy_nodes(const char *spec_path, const char *out_name, int insecure) __attribute__((weak));
int cmd_proxy_probe(const char *spec_path, const char *out_name, int node,
                    int timeout_s, int insecure) __attribute__((weak));
int cmd_warp(const char *spec_path, const char *group) __attribute__((weak));
int cmd_warp_reg(const char *path) __attribute__((weak));
int cmd_warp_scan(const char *spec_path, const char *group) __attribute__((weak));
int cmd_sub_fetch(const char *url, const char *out_path, const char *info_path) __attribute__((weak));
int cmd_sub_quota(const char *url, const char *info_path) __attribute__((weak));
int cmd_xsteer_key(void) __attribute__((weak));
int cmd_xsteer_check(const char *conf) __attribute__((weak));
int cmd_xsteer_link(const char *what, const char *name) __attribute__((weak));
int cmd_xsteer(const char *spec_path, const char *out_name, const char *conf,
               const char *device, int stream, int stream_port) __attribute__((weak));
int cmd_xsteer_peers(const char *spec_path, const char *out_name,
                     const char *conf) __attribute__((weak));
/* Обфускатор: src/proto/obfs/obfsmain.c (сам код клиента и сервера — в obfs.c, общий с xsteer). */
int cmd_obfs(const char *spec_path, const char *out_name) __attribute__((weak));
int cmd_obfs_server(int listen_port, const char *forward) __attribute__((weak));

int modcmd_builtin(const char *cmd) {
    if (!strcmp(cmd, "vless") || !strcmp(cmd, "vless-nodes") || !strcmp(cmd, "vless-probe"))
        return cmd_vless != NULL;
    if (!strcmp(cmd, "hysteria2") || !strcmp(cmd, "hysteria2-nodes") || !strcmp(cmd, "hysteria2-probe"))
        return cmd_hysteria2 != NULL;
    if (!strcmp(cmd, "proxy") || !strcmp(cmd, "proxy-nodes") || !strcmp(cmd, "proxy-probe"))
        return cmd_proxy != NULL;
    if (!strcmp(cmd, "warp") || !strcmp(cmd, "warp-reg") || !strcmp(cmd, "warp-scan")) return cmd_warp != NULL;
    if (!strcmp(cmd, "xsteer") || !strcmp(cmd, "xsteer-peers")) return cmd_xsteer != NULL;
    if (!strcmp(cmd, "tgws") || !strcmp(cmd, "tgws-probe")) return cmd_tgws != NULL;
    if (!strcmp(cmd, "obfs") || !strcmp(cmd, "obfs-server")) return cmd_obfs != NULL;
    return 0;
}

/* Команда, которой в этом бинарнике нет: запустить модуль, если он установлен, иначе назвать
 * пакет. Возвращает только код отказа: удачный запуск заменяет процесс (execv). */
static int absent(const char *cmd, const char *what, int argc, char **argv) {
    const char *mod = steer_cmd_module(cmd);
    char path[4096];
    if (mod && steer_module_path(mod, path, sizeof(path)) == 0) {
        char **av = calloc((size_t)argc + 1, sizeof(*av));
        if (av) {
            memcpy(av, argv, (size_t)argc * sizeof(*av));
            av[0] = path;
            execv(path, av);
            fprintf(stderr, "steer: не удалось запустить %s: %s\n", path, strerror(errno));
            free(av);
            return 2;
        }
    }
    /* steer-extended ставит остальные модули, но не hysteria2, proxy и warpbox: у них отдельные пакеты. */
    int in_ext = !mod || (strcmp(mod, "steer-hysteria2") != 0 && strcmp(mod, "steer-proxy") != 0 &&
                          strcmp(mod, "steer-warpbox") != 0);
    fprintf(stderr, "steer: %s в этой сборке отсутствует — нужен пакет %s%s\n",
            what, mod ? mod : "steer-extended", in_ext ? " (входит в steer-extended)" : "");
    return 2;
}

#define ABSENT_VLESS  absent(cmd, "клиент VLESS", argc, argv)
#define ABSENT_HY2    absent(cmd, "клиент hysteria2", argc, argv)
#define ABSENT_PROXY  absent(cmd, "клиент прокси", argc, argv)
#define ABSENT_WARP   absent(cmd, "WARP", argc, argv)
#define ABSENT_XS     absent(cmd, "клиент xsteer", argc, argv)
#define ABSENT_XSADM  absent(cmd, "служебные команды xsteer", argc, argv)
#define ABSENT_TGWS   absent(cmd, "мост Telegram", argc, argv)
#define ABSENT_OBFS   absent(cmd, "обфускатор", argc, argv)

/* SIGPIPE у модульных команд выключен: запись в закрытое соединение возвращается ошибкой EPIPE
 * вызывающему, а не убивает процесс.
 *
 * ЧТО БЫЛО. Демон держит SIGPIPE выключенным у себя (ctl.c), а детям возвращает умолчание —
 * loop_child_reset: иначе запущенные им ip, nft и curl унаследовали бы чужое «игнорировать» через
 * exec. Модуль — тоже ребёнок демона и жил с умолчанием. Запись TLS в сокет узла (tls13_write,
 * src/proto/tls/tls13.c: write() без MSG_NOSIGNAL; файл защищённый, правке не подлежит) в
 * соединение, которое узел уже закрыл, кончалась SIGPIPE, и умирал процесс ЦЕЛИКОМ — со всеми
 * остальными соединениями клиентов. На высокой скорости это не случайность, а правило: узел
 * закрывает соединение, пока стек ещё дописывает в него пакеты клиента, уже лежавшие в очереди
 * TUN. iperf3 -P 8 вверх через steer-vless (Xray 26.3.27 в роли узла) убивал модуль в большинстве
 * запусков: три из пяти на релизном пакете x86_64, три из трёх при повторе на сборке 404bbc3
 * (strace: write() записи в 1482 байта → EPIPE → SIGPIPE; демон: «vless tun вышел (сигнал 13) —
 * перезапуск через 5 с», дальше 10 и 20 с — пауза перезапуска удваивается), и всё это время
 * туннель стоял.
 *
 * ЧТО СТАЛО. Запись в закрытое соединение — обычный отказ записи, как ECONNRESET или таймаут
 * отправки: tls13_write отвечает TLS13_EIO, transport_write передаёт код, дайлер (vl_send)
 * отвечает SEND_FATAL, а стек шлёт клиенту RST и освобождает запись (conn_reset → conn_drop →
 * vl_close → transport_close: дескриптор и контексты шифров). Погибает одно соединение — то,
 * которое с той стороны и так закрыто, — а не туннель.
 *
 * ГДЕ. Здесь, а не в main() модуля и не в супервизоре демона: сюда приходят и бинарники модулей
 * (steer_module_main), и статические сборки, где помощник — это `steerd vless …` (телефон,
 * стенды); помощника запускает не только демон, но и procd, и человек, и тогда выключать
 * SIGPIPE некому. И только здесь видно, что команда МОДУЛЬНАЯ (steer_cmd_module): остальные
 * команды steerd (status, conns, explain) печатают в `| head`, и смерть от SIGPIPE там —
 * правильное поведение, которое ломать незачем.
 *
 * ЧТО ЭТО ЗАДЕВАЕТ. Закрытая труба событий (evline.c): запись в неё тоже становится EPIPE, и
 * помощник с меткой демона (STEER_SUPD) гасит себя тем же SIGTERM, что по PDEATHSIG, — раньше
 * это делал SIGPIPE. Мост tgws выключал SIGPIPE у себя и раньше (tgws.c), резолвер — тоже
 * (dnsd/proxy.c); теперь так у всех помощников, а не у двух. Дети модуля (ip, nft через run())
 * наследуют «игнорировать» — как и у детей самого демона. */
static void module_ignore_sigpipe(const char *cmd) {
    if (steer_cmd_module(cmd)) signal(SIGPIPE, SIG_IGN);
}

int modcmd_run(const char *cmd, int argc, char **argv, const struct cli_args *a,
               const char *spec, const char *arg, struct spec *cfg) {
    (void)cfg;
    module_ignore_sigpipe(cmd);
    if (!strcmp(cmd, "tgws")) return cmd_tgws ? cmd_tgws(spec, arg) : ABSENT_TGWS;
    if (!strcmp(cmd, "tls-probe")) {
        /* ХОСТ[:ПОРТ]; адрес назначения — флагом --out, исходящий порт — флагом --node.
         * Своих флагов не заводим: эти уже есть и значат ровно то, что нужно. */
        char hb[256];
        const char *h = arg ? arg : "";
        int pt = 443;
        snprintf(hb, sizeof(hb), "%s", h);
        char *c = strrchr(hb, ':');
        if (c) {
            *c = '\0';
            /* Порт — число 1..65535, иначе отказ: atoi на «host:abc» давал 0, и проба шла на
             * порт 0 с приговором «не отвечает» про узел, который никто не спрашивал. */
            char *pe = NULL;
            long v = strtol(c + 1, &pe, 10);
            if (pe == c + 1 || *pe || v < 1 || v > 65535) {
                fprintf(stderr, "неверный порт: %s\n", c + 1);
                return 2;
            }
            pt = (int)v;
        }
        if (!hb[0]) { fprintf(stderr, "нужно имя узла\n"); return 2; }
        if (!cmd_tls_probe) return ABSENT_VLESS;
        return cmd_tls_probe(hb, a->out_file, pt, a->node > 0 ? a->node : 0, 0);
    }
    if (!strcmp(cmd, "tgws-probe")) {
        /* Позиционный — не имя, а переключатель, и понимается ровно одно слово. Прежде
         * всё, что не «media», молча значило обычную точку: «steer tgws-probe medai»
         * проверял другую точку и отвечал «ок» (I-316). */
        if (arg && strcmp(arg, "media") != 0) {
            fprintf(stderr, "steer: команда tgws-probe понимает аргументом только «media», "
                    "а получила «%s»\n", arg);
            return 2;
        }
        if (!cmd_tgws_probe) return ABSENT_TGWS;
        return cmd_tgws_probe(a->node > 0 ? a->node : 2, arg && !strcmp(arg, "media"),
                              a->direct, a->timeout);
    }
    /* --insecure — только у перечня и проверки узлов ПО ФАЙЛУ подписки (разбор пускает флаг лишь к
     * *-nodes и *-probe). С именем выхода пригодность узлов с allowInsecure решает ключ insecure
     * самого выхода: флаг поверх него показал бы номера, которых у поднятого выхода нет. Проверка
     * здесь, до модуля: отказ один и в сборке без модуля, и в самом модуле. */
    if (a->insecure && !(arg && arg[0] == '/')) {
        fprintf(stderr, "steer: %s: --insecure — только с файлом подписки (путь с «/»); у выхода "
                "узлы с allowInsecure решает его ключ insecure\n", cmd);
        return 2;
    }
    if (!strcmp(cmd, "vless")) return cmd_vless ? cmd_vless(spec, arg) : ABSENT_VLESS;
    if (!strcmp(cmd, "vless-nodes"))
        return cmd_vless_nodes ? cmd_vless_nodes(spec, arg, a->insecure) : ABSENT_VLESS;
    if (!strcmp(cmd, "vless-probe"))
        return cmd_vless_probe ? cmd_vless_probe(spec, arg, a->node, a->timeout, a->insecure)
                               : ABSENT_VLESS;
    if (!strcmp(cmd, "hysteria2")) return cmd_hysteria2 ? cmd_hysteria2(spec, arg) : ABSENT_HY2;
    if (!strcmp(cmd, "hysteria2-nodes"))
        return cmd_hysteria2_nodes ? cmd_hysteria2_nodes(spec, arg, a->insecure) : ABSENT_HY2;
    if (!strcmp(cmd, "hysteria2-probe"))
        return cmd_hysteria2_probe ? cmd_hysteria2_probe(spec, arg, a->node, a->timeout, a->insecure)
                                   : ABSENT_HY2;
    if (!strcmp(cmd, "proxy")) return cmd_proxy ? cmd_proxy(spec, arg) : ABSENT_PROXY;
    if (!strcmp(cmd, "proxy-nodes"))
        return cmd_proxy_nodes ? cmd_proxy_nodes(spec, arg, a->insecure) : ABSENT_PROXY;
    if (!strcmp(cmd, "proxy-probe"))
        return cmd_proxy_probe ? cmd_proxy_probe(spec, arg, a->node, a->timeout, a->insecure)
                               : ABSENT_PROXY;
    if (!strcmp(cmd, "warp")) return cmd_warp ? cmd_warp(spec, arg) : ABSENT_WARP;
    if (!strcmp(cmd, "warp-reg")) return cmd_warp_reg ? cmd_warp_reg(arg) : ABSENT_WARP;
    if (!strcmp(cmd, "warp-scan")) return cmd_warp_scan ? cmd_warp_scan(spec, arg) : ABSENT_WARP;
    if (!strcmp(cmd, "sub-fetch"))
        return cmd_sub_fetch ? cmd_sub_fetch(arg, a->out_file, a->info_file) : ABSENT_VLESS;
    if (!strcmp(cmd, "sub-quota"))
        return cmd_sub_quota ? cmd_sub_quota(arg, a->info_file) : ABSENT_VLESS;
    if (!strcmp(cmd, "obfs")) return cmd_obfs ? cmd_obfs(spec, arg) : ABSENT_OBFS;
    /* Серверная половина. Спека ей не нужна и не читается: сервер живёт на VPS, где
     * ни выходов, ни каналов нет — есть порт, который слушать, и локальный WireGuard,
     * которому пересылать. */
    if (!strcmp(cmd, "xsteer")) {
        if (!cmd_xsteer) return ABSENT_XS;
        return cmd_xsteer(spec, arg, a->config, a->device, a->stream, a->stream_port);
    }
    if (!strcmp(cmd, "xsteer-peers"))
        return cmd_xsteer_peers ? cmd_xsteer_peers(spec, arg, a->config) : ABSENT_XS;
    if (!strcmp(cmd, "xsteer-key")) return cmd_xsteer_key ? cmd_xsteer_key() : ABSENT_XSADM;
    if (!strcmp(cmd, "xsteer-check"))
        return cmd_xsteer_check ? cmd_xsteer_check(a->config) : ABSENT_XSADM;
    /* Источник — позиционный аргумент, а если его нет, то --config: команда одинаково удобна и
     * в конвейере («steer xsteer-link -»), и там, где путь уже назван флагом, как у соседей. */
    if (!strcmp(cmd, "xsteer-link")) {
        if (!cmd_xsteer_link) return ABSENT_XSADM;
        return cmd_xsteer_link(a->npos > 0 ? a->pos[0] : a->config, a->name);
    }
    if (!strcmp(cmd, "obfs-server")) {
        if (!cmd_obfs_server) return ABSENT_OBFS;
        return cmd_obfs_server(a->listen, a->forward);
    }
    return MODCMD_NONE;
}

int modcmd_platform_args(int *argc, char **argv) {
    /* Платформа (src/platform/platform.h) — до всего остального: от неё зависят пути по
     * умолчанию, справка и раскладка меток. --platform понимает любая команда, в любом месте
     * строки, поэтому он вынимается из argv здесь, до разбора: у dnsd, fit и ctl свои парсеры,
     * и учить каждый из них этому флагу незачем. Выбор уходит и в окружение (plat_select) —
     * процессы, которые движок запускает сам, работают на той же платформе. */
    for (int i = 1; i < *argc; i++) {
        if (strcmp(argv[i], "--platform") != 0) continue;
        if (i + 1 >= *argc) {
            fprintf(stderr, "steer: флаг --platform остался без значения (%s)\n", plat_names());
            return 2;
        }
        if (plat_select(argv[i + 1]) != 0) {
            fprintf(stderr, "steer: --platform %s: такой платформы нет (есть %s)\n", argv[i + 1],
                    plat_names());
            return 2;
        }
        memmove(&argv[i], &argv[i + 2], (size_t)(*argc - i - 1) * sizeof *argv);
        *argc -= 2;
        i--;
    }
    return 0;
}

/* Точка входа модуля. Тот же путь, что у steerd, но короче: модуль знает только свои команды
 * (steer_cmd_module называет, чьи они), справка и разбор берутся из той же таблицы, что у
 * steerd, — значит, `steer-vless vless x --spec …` разбирается ровно так, как `steer vless x
 * --spec …`, и заглушке steerd достаточно передать командную строку как есть. */
int steer_module_main(int argc, char **argv, const char *module, const char *version) {
    if (modcmd_platform_args(&argc, argv) != 0) return 2;
    plat();
    /* Первое, что видит демон от модуля, — версия (evline.h, hello): модуль чужой версии он
     * отвергнёт, не дожидаясь up. Раньше разбора аргументов — чтобы и отказ разбора у модуля
     * чужой версии читался как «чужая версия», а не как «модуль сломан». */
    evline_hello(module, version);
    /* Модуль спеку читает, а группы не меряет: «https:// в адресе замера недоступен» решает steerd,
     * который меряет, — и решает по своему бинарнику, а не по бинарнику модуля (kinds/grpurl.c). */
    urltest_reader_only();
    if (argc < 2) {
        fprintf(stderr, "steer-%s: нужна команда (модуль запускает демон; человеку — steer <команда>)\n",
                module);
        return 2;
    }
    const char *cmd = argv[1];
    const char *mod = steer_cmd_module(cmd);
    char want[32];
    snprintf(want, sizeof(want), "steer-%s", module);
    if (!mod || strcmp(mod, want) != 0) {
        fprintf(stderr, "steer-%s: команда %s — не этого модуля\n", module, cmd);
        return 2;
    }
    const struct cli_cmd *c = cli_lookup(cmd);
    if (!c) cli_unknown(cmd);
    if (cli_wants_help(argc - 2, argv + 2)) {
        cli_help(stdout, c);
        return 0;
    }
    struct cli_args a;
    static struct spec cfg;
    cli_parse(c, argc, argv, 2, &a);
    if (a.state_dir) steer_set_state_dir(a.state_dir);
    steer_set_keep_dir_of(plat_spec_resolve(a.spec));
    const char *spec = a.spec, *arg = a.npos ? a.pos[0] : NULL;
    int rc = modcmd_run(cmd, argc, argv, &a, spec, arg, &cfg);
    if (rc == MODCMD_NONE) {
        fprintf(stderr, "steer-%s: команда %s объявлена, но не подключена — ошибка в модуле\n",
                module, cmd);
        return 2;
    }
    return rc;
}
