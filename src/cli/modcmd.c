/* Команды модуля ядра (modcmd.h): и заглушки steerd, и настоящие ветки бинарника модуля.
 *
 * Модуль ядра сейчас один — мост Telegram steer-tgws (вид tgws ещё в ядре). Ссылки на его команды
 * СЛАБЫЕ: в статической сборке (мини-пакет stgws, телефон, стенды) мост слинкован в steerd, и
 * команда исполняется на месте; в раскладке пакета её нет в steerd — тогда steerd запускает модуль
 * той же командной строкой, а без модуля отказывает словами «нужен пакет».
 *
 * ПРОТОКОЛОВ ЗДЕСЬ НЕТ. Их подкоманды (`vless-nodes`, `xsteer-peers`, `obfs-server`…) — плагинов:
 * ядро берёт их из манифестов (kinds/plugin.c, plugin_cmd_find) и имён их не знает. */
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
int modcmd_builtin(const char *cmd) {
    if (!strcmp(cmd, "tgws") || !strcmp(cmd, "tgws-probe")) return cmd_tgws != NULL;
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
    /* Текст прежний (контракт splify2: подстрока steer-extended), пока мост — модуль ядра. */
    fprintf(stderr, "steer: %s в этой сборке отсутствует — нужен пакет %s (входит в steer-extended)\n", what,
            mod ? mod : "steer-tgws");
    return 2;
}

#define ABSENT_TGWS   absent(cmd, "мост Telegram", argc, argv)

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
 * (steer_module_main), и статические сборки, где помощник — это `steerd tgws …`; помощника
 * запускает не только демон, но и procd, и человек, и тогда выключать SIGPIPE некому. Программы
 * плагинов делают то же сами (src/plugkit, pk_main). И только здесь видно, что команда МОДУЛЬНАЯ
 * (steer_cmd_module): остальные
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
