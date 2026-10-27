/* Управляющий сокет движка: демон `steer daemon` (он же `steer ctl-serve` — прежнее имя) и
 * `steer ctl` (клиент для отладки).
 *
 * ЗАЧЕМ. На роутере управляющий слой splify2 зовёт движок как программу: rpcd исполняет
 * `steer status`, кладёт спеку в /etc/steer и зовёт `steer apply`. На телефоне так нельзя.
 * Приложение splify2 живёт в домене splify2_app (vendor/der/sepolicy), и политика нарочно не
 * даёт ему ни исполнить движок, ни прочитать его файлы: движок невидим для всех приложений, и
 * исключение для одного из них — это одна дверь, а не ключи от всего дома. Эта дверь —
 * unix-сокет с меткой steerd_socket, к которому SELinux пускает только splify2_app. За дверью
 * сидит этот сервер и делает от имени приложения ровно то, что перечислено в таблице команд
 * ниже, — и ничего сверх.
 *
 * ПРОТОКОЛ (версия 1; то же самое для автора моста в приложении — в docs/ctl.md).
 *
 *   Одно соединение — один запрос и один ответ, затем сервер закрывает соединение.
 *   Исключение одно — subscribe: после ответа соединение остаётся открытым, и демон пишет в
 *   него события, строка JSON на событие ({"v":1,"ev":"applied",…}). Это расширение версии 1,
 *   а не новая версия: прежние команды и их ответы не изменились ни в одном байте.
 *
 *   Запрос — строка ASCII до 512 байт с '\n' в конце: имя команды и её слова через ОДИН
 *   пробел. У команд с телом (apply, check, put-file) последнее слово — длина тела в байтах
 *   десятичным числом, и сразу за '\n' идёт ровно столько байт тела:
 *       status\n
 *       explain youtube.com\n
 *       apply 1834\n{"schema":2,...}
 *       put-file yt.lst 52311\n<байты списка>
 *   Тело спеки — не больше 1 МиБ, файла списка — 16 МиБ. На весь запрос, строку и тело, — пять
 *   секунд.
 *
 *   Ответ — один объект JSON в одну строку с '\n' в конце:
 *       {"v":1,"cmd":"status","code":0,"stdout":"...","stderr":"..."}
 *   code — код возврата одноимённой подкоманды движка (0 — успех), stdout и stderr — её вывод
 *   строками (у status и diag stdout — сам JSON, его разбирают второй раз). stdout
 *   обрезается на 1 МиБ, stderr на 64 КиБ; обрезанное помечается "truncated":true.
 *   Отказ самого сервера — без code, с полем error и человеческим message:
 *       {"v":1,"error":"denied","message":"..."}
 *   Значения error: bad-request, too-large, unknown-command, denied, busy, internal, timeout
 *   (у timeout code есть: команда шла и была убита, её вывод до этого момента приложен) и
 *   in-use (rm-file файла, на который ссылается сохранённая спека).
 *   Команды apply, reload и файлов списков добавляют свои поля — см. их обработчики и
 *   docs/ctl.md.
 *
 * ПОЧЕМУ СТРОКА И ДЛИНА, а не JSON в запросе. Запрос короткий и его слова всё равно идут в
 * argv подкоманды — разбирать ради них JSON в движке значило бы завести второй разборщик
 * рядом со спекой ради двух слов. Длина тела объявляется ЗАРАНЕЕ, а не «читать до закрытия»:
 * так слишком большое тело отвергается до того, как прочитан первый его байт, а у клиента
 * не требуется полузакрытия сокета (у LocalSocket Android оно есть, но лишнее условие
 * совместимости — лишний способ сломаться).
 *
 * ИСПОЛНЕНИЕ. Демон — один процесс с одним циклом событий (loop.h): слушающий сокет,
 * соединения, трубы детей, сигналы и таймеры — всё в одном epoll, и без событий он спит без
 * срока. Команды делятся на два рода.
 *
 *   В процессе, из памяти: version, status, explain, conns, dns-log и файлы списков. Спеку и
 *   группы демон держит в памяти (state.h) — прочитанными при старте и перечитанными после
 *   apply и reload, — поэтому status и explain не читают спеку на каждый вызов и не платят
 *   запуском движка. Ответ при этом ровно тот же, что у подкоманды: его печатает тот же код
 *   (status_answer, explain_emit, ctnl_conns_print, dlog_print) — в поток в памяти, а не в
 *   stdout, — а stderr на время команды перенаправлен в файл в памяти. Одна правда на двоих,
 *   как и прежде, только без второго процесса.
 *
 *   Через ребёнка: apply и reload (план и применение изменившихся частей — apply-сверка,
 *   recon.c; у reload ещё dnsd-sig), check, diag, vless-probe, vless-nodes, sub-check — работа
 *   ядра, компиляция или долгий срок. Ребёнок — fork+exec самого себя с подкомандой, в
 *   своей группе процессов; его stdout и stderr — неблокирующие трубы в том же epoll, выход —
 *   через signalfd, срок — таймером цикла. Пока ребёнок работает, демон отвечает остальным:
 *   долгий vless-probe больше не держит status. Сбой в ребёнке (die, зависание на nft) по-
 *   прежнему задевает только его.
 *
 *   Изменяющие команды (apply, check, reload, rm-file) идут по одной: следующая ждёт в очереди
 *   демона, пока не кончится предыдущая. Раньше это делал flock на ctl.lock между процессами-
 *   обработчиками; теперь обработчик один, и очередь — его собственная.
 *
 *   С --watch в том же цикле живёт сторож выходов (watchd.c): таймер периода, события netlink и
 *   сам проход — автоматом на этом же цикле, без ребёнка. Пока идёт изменяющая команда, проход
 *   откладывается.
 *
 *   С --supervise там же живут дети демона (supd.c): помощники выходов с трубами событий и
 *   резолвер на таблице. reload и apply тогда не ищут резолвер и супервизор по /proc и не шлют
 *   им сигналов: демон сам сверяет помощников и пишет резолверу новую таблицу, перечитав спеку.
 *
 *   SIGTERM гасит всех детей демона: помощников и резолвер (supd_stop), проход сторожа и детей
 *   команд, которые ещё идут (их группы процессов — SIGTERM, по сроку SIGKILL), — демон не
 *   оставляет после себя процессов без присмотра.
 *
 * КОГО ПУСКАТЬ. Первый замок — SELinux: connectto к steerd разрешён splify2_app, и кроме него
 * к сокету может прийти разве что root (su на userdebug) и init. Второй замок — здесь, по
 * SO_PEERCRED и SO_PEERSEC: uid 0 (root) и 1000 (system) — да; процесс в домене splify2_app
 * — да, если он у владельца устройства (пользователь 0); прочие uid — только названные
 * флагом --allow-uid (стенд, отладка). UID приложения нигде не записан и не угадывается:
 * он назначается при установке и у каждого телефона свой, а читать /data/system/packages.list
 * значило бы дать движку ещё одно право. Вместо этого спрашивается ядро — какой у собеседника
 * контекст SELinux, — и ответ «splify2_app» дан той же привязкой в seapp_contexts (имя пакета
 * плюс платформенная подпись), на которой держится весь запрет. Подменить его приложению с
 * тем же именем пакета, но чужой подписью нельзя: seinfo считается по сертификату.
 * Почему только пользователь 0: движок меняет маршрутизацию ВСЕГО устройства, а гостевой
 * пользователь или рабочий профиль — не тот, кто ею распоряжается; Android по той же логике
 * не даёт вторичным пользователям настройки сети устройства.
 *
 * ПРЕДЕЛЫ. Не больше четырёх запросов одновременно (пятому — busy сразу, не очередь: очередь
 * держала бы соединения открытыми на неопределённое время); подписчиков — сколько позволит RLIMIT_NOFILE
 * процесса, и они в четыре запроса не входят. Строка 512 байт, тело 1 МиБ (файл списка — 16 МиБ); пять
 * секунд на запрос; у каждой команды через ребёнка свой срок, по истечении — SIGKILL всей
 * группе процессов команды (nft и ip, которых она запустила, тоже). Медленный или молчащий
 * клиент демон не держит: чтение и запись неблокирующие, со сроками, а очередь событий
 * подписчика ограничена — не успевающего читать демон отключает.
 *
 * БАТАРЕЯ. Демон спит в epoll_wait без срока: таймеры цикла взводятся только на время
 * запроса, ребёнка или отложенного закрытия и снимаются вместе с ними. Проснуться его может
 * только соединение, вывод ребёнка, сигнал или такой таймер. Стенд tests/ctlmatch.sh меряет
 * это числом добровольных переключений контекста в тишине. С --watch таймеров больше (период
 * сторожа, снимок status) — но только пока движок включён: выключенный движок не держит ни
 * одного таймера и ни одного сокета событий сети (srv_set_enabled), и демон не просыпается сам
 * вовсе (стенд tests/daemonmatch.sh). Таймеры — CLOCK_MONOTONIC (loop.c): во сне устройства
 * они стоят, не будят его и не догоняют пачкой; wakelock демон не берёт.
 *
 * ГДЕ СОКЕТ. /data/misc/steer/steer.sock, создаёт его сам сервер. Почему не опция `socket` у
 * init (сокет в /dev/socket, как у netd): каталог /dev/socket может листать любой домен
 * (system/sepolicy, domain.te: `allow domain socket_device:dir r_dir_perms`), то есть имя
 * steerd увидело бы любое приложение простым `ls` — а требование владельца в том, чтобы
 * движка для приложений не было видно. Каталог /data/misc/steer со своим типом приложениям
 * не листается; метку steerd_socket сокету ставит type_transition по имени файла (см.
 * vendor/der/sepolicy/private/steerd.te). Цена своего сокета — убрать прежний файл при
 * старте: сервер сначала пробует к нему подключиться (живой соседний сервер — отказ стартовать),
 * и только мёртвый файл удаляет. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <dirent.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#ifdef __BIONIC__
#include <sys/system_properties.h>
#endif

#include "platform.h"
#include "spec.h"
#include "groups.h"
#include "plugin.h"
#include "cli.h"
#include "daemon.h"
#include "loop.h"
#include "state.h"
#include "fostate.h"
#include "watchd.h"
#include "helpers.h"
#include "recon.h"
#include "rulewd.h"
#include "fogroup.h"
#include "nftcompat.h"
#include "ctl.h"
#include "ynode.h"
#include "plugso.h"

/* Путь сокета по умолчанию — путь платформы (ctl_sock, src/platform/platform.h). */

#define CTL_LINE_MAX    512
/* ТЕЛО СПЕКИ (check, apply) — защита демона от запроса, который просит памяти без меры (тело
 * читается в память целиком до разбора). Мегабайта хватает на спеку с сотнями правил и
 * выходов: длинные списки в спеку кладут файлами (domains_files, put-file), а не строками. Это
 * предел запроса, а не спеки: загрузчик с диска принимает спеку до 16 МиБ (SPEC_TEXT_MAX). */
#define CTL_BODY_MAX    (1024 * 1024)
/* ФАЙЛЫ СПИСКОВ (put-file) — свой предел тела, в шестнадцать раз больше спеки. Спека — это
 * настройки человека, и мегабайта ей хватает с многократным запасом; списки же бывают
 * по несколько мегабайт (антизапретный список подсетей, крупные доменные списки издателя
 * в текстовом виде), и общий предел в 1 МиБ отрезал бы ровно те файлы, ради которых команда
 * заведена. Предел остаётся: тело читается в память демона целиком (так оно проверяется
 * по объявленной длине до записи на диск), и без него один запрос мог бы попросить у
 * телефона сколько угодно памяти. 16 МиБ — с запасом больше самого крупного списка каталога
 * splify2-lists и всё ещё мелочь для памяти телефона на время одного запроса.
 *
 * К пределу одного файла — пределы каталога: не больше 4096 файлов и 128 МиБ всего. Каталог
 * лежит в /data, и приложение, которое заливает и забывает убирать (ошибка в его логике), не
 * должно понемногу съедать память телефона: упереться в предел и получить отказ лучше, чем
 * узнать о переполнении /data по отказу всех приложений сразу. Главный предел — 128 МиБ (это
 * ресурс: место в /data); число файлов ограничено отдельно только от бесконечной заливки
 * пустышек (и от каталога, который list-files придётся читать целиком), а не от больших спек:
 * четыре тысячи файлов — на порядок больше, чем списков в самой большой спеке. Раньше — 256, и
 * спека на триста списков из каталога splify2-lists в него не помещалась. */
#define CTL_FILE_MAX    (16 * 1024 * 1024)
#define CTL_FILES_MAX   4096
#define CTL_FILES_TOTAL (128LL * 1024 * 1024)
#define CTL_FNAME_MAX   64
/* Вывод ребёнка и ответ из памяти — до 256 МиБ: это защита от ребёнка, который пишет без
 * конца, а не рамка для честного ответа. Прежний мегабайт обрезал список соединений и status
 * большой спеки посреди JSON; ответ сверх предела по-прежнему помечается "truncated". */
#define CTL_OUT_MAX     (256LL * 1024 * 1024)
#define CTL_ERR_MAX     (64 * 1024)
#define CTL_CLIENTS_MAX 4
#define CTL_REQ_MS      5000
/* Сколько ждать, пока клиент заберёт ответ (раньше — SO_SNDTIMEO обработчика), и сколько
 * дочитывать непрочитанный остаток запроса после ответа (см. conn_drain). */
#define CTL_SEND_MS     5000
#define CTL_DRAIN_MS    1000
/* ПОДПИСЧИКИ. Число не ограничено: подписчики — приложение, отладка из adb и плагины (у
 * каждого свой), а каждый — открытый дескриптор и очередь в памяти демона. Предел у числа один —
 * RLIMIT_NOFILE процесса: мягкий предел при старте поднимается до жёсткого (ctl_serve_main), а
 * упёршись, accept ждёт освободившегося дескриптора (accept_tm).
 *
 * Очередь событий подписчика — 32 КиБ поверх буфера сокета (его демон уменьшает до 16 КиБ,
 * чтобы очередь, которую он видит, и была той, что ограничена). Событие — сотня байт, и
 * событий в минуту единицы: подписчик, отставший на три сотни событий, не читает вовсе, и
 * держать для него память дальше значило бы дать одному зависшему клиенту расти в демоне без
 * предела. Переполнение — отключить: подписчик переподключится и спросит status заново, это
 * честнее, чем тихо выбрасывать события из середины потока. */
#define CTL_SUBQ_MAX    (32 * 1024)
#define CTL_SUB_SNDBUF  (16 * 1024)
#define CTL_AID_SYSTEM  1000
#define CTL_USER_RANGE  100000   /* AID_USER_OFFSET: uid = пользователь * 100000 + приложение */

/* daemon.h заводит LOG_W с меткой apply; у сокета своя метка. */
#undef LOG_W
#define LOG_W "steer[warn] ctl: "
#define LOG_I "steer[info] ctl: "

struct ctl_conf {
    const char *sock;
    const char *spec;
    const char *state_dir;       /* NULL — умолчание движка, флаг подкомандам не передаётся */
    const char *lists_dir;       /* куда put-file кладёт файлы (lists_dir платформы, --lists-dir) */
    const char *allow_domain;    /* NULL или "" — по домену не пускать */
    uid_t *allow_uid;            /* куча: --allow-uid столько раз, сколько дано */
    int allow_uid_n;
    int watch;                   /* --watch: демон — сторож выходов (watchd.c) */
    int watch_period;            /* --watch-period, секунд */
    int supervise;               /* --supervise: помощники и резолвер — дети демона (supd.c) */
    int apply;                   /* --apply: применить спеку при старте (как reload) */
    const char **dnsd_flags;     /* --dnsd-flag: лишние флаги резолверу-ребёнку, NULL в конце (куча) */
    int dnsd_flag_n;
    char exe[PATH_MAX];
};

/* ---- буфер ---------------------------------------------------------------------------- */

struct cbuf {
    char *p;
    size_t n, cap;
    size_t max;      /* 0 — без предела */
    int trunc;
};

static void cb_put(struct cbuf *b, const void *s, size_t n) {
    if (b->max && b->n + n > b->max) {
        n = b->max > b->n ? b->max - b->n : 0;
        b->trunc = 1;
    }
    if (b->n + n + 1 > b->cap) {
        size_t c = b->cap ? b->cap : 1024;
        while (c < b->n + n + 1) c *= 2;
        char *q = realloc(b->p, c);
        if (!q) { b->trunc = 1; return; }
        b->p = q;
        b->cap = c;
    }
    if (n) memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void cb_str(struct cbuf *b, const char *s) { cb_put(b, s, strlen(s)); }

static void cb_fmt(struct cbuf *b, const char *fmt, ...) {
    char t[1024];
    va_list ap;
    va_start(ap, fmt);
    int k = vsnprintf(t, sizeof(t), fmt, ap);
    va_end(ap);
    if (k > 0) cb_put(b, t, (size_t)k < sizeof(t) ? (size_t)k : sizeof(t) - 1);
}

/* Обрезанный на пределе вывод может кончиться посреди символа UTF-8 (движок пишет
 * по-русски), и такой хвост разборщик приложения заменил бы мусором. Срезаем недописанный
 * символ целиком. */
static void cb_utf8_trim(struct cbuf *b) {
    if (!b->trunc || !b->n) return;
    size_t i = b->n, k = 0;
    while (i > 0 && k < 4 && ((unsigned char)b->p[i - 1] & 0xC0) == 0x80) { i--; k++; }
    if (i == 0) return;
    unsigned char lead = (unsigned char)b->p[i - 1];
    size_t need = lead >= 0xF0 ? 3 : lead >= 0xE0 ? 2 : lead >= 0xC0 ? 1 : 0;
    if (need != k) { b->n = lead >= 0xC0 ? i - 1 : b->n; b->p[b->n] = '\0'; }
}

/* Строка JSON. Байты от 0x80 идут как есть: вывод движка — UTF-8. */
static void cb_json(struct cbuf *b, const char *s, size_t n) {
    cb_put(b, "\"", 1);
    size_t st = 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        const char *e = NULL;
        char u[8];
        if (c == '"') e = "\\\"";
        else if (c == '\\') e = "\\\\";
        else if (c == '\n') e = "\\n";
        else if (c == '\t') e = "\\t";
        else if (c == '\r') e = "\\r";
        else if (c < 0x20 || c == 0x7f) { snprintf(u, sizeof(u), "\\u%04x", c); e = u; }
        if (!e) continue;
        cb_put(b, s + st, i - st);
        cb_str(b, e);
        st = i + 1;
    }
    cb_put(b, s + st, n - st);
    cb_put(b, "\"", 1);
}

static void cb_jstr(struct cbuf *b, const char *s) { cb_json(b, s, strlen(s)); }

/* ---- ввод-вывод ------------------------------------------------------------------------ */

static int ctl_write_all(int fd, const char *s, size_t n) {
    while (n) {
        ssize_t w = write(fd, s, n);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        s += w;
        n -= (size_t)w;
    }
    return 0;
}

/* ---- ответы ---------------------------------------------------------------------------- */

static void resp_begin(struct cbuf *r, const char *cmd) {
    cb_str(r, "{\"v\":1");
    if (cmd) { cb_str(r, ",\"cmd\":"); cb_jstr(r, cmd); }
}

static void resp_error(struct cbuf *r, const char *err, const char *msg) {
    cb_str(r, ",\"error\":");
    cb_jstr(r, err);
    cb_str(r, ",\"message\":");
    cb_jstr(r, msg);
}

static void resp_run(struct cbuf *r, int code, struct cbuf *out, struct cbuf *err) {
    cb_utf8_trim(out);
    cb_utf8_trim(err);
    cb_fmt(r, ",\"code\":%d,\"stdout\":", code);
    cb_json(r, out->p ? out->p : "", out->n);
    cb_str(r, ",\"stderr\":");
    cb_json(r, err->p ? err->p : "", err->n);
    if (out->trunc || err->trunc) cb_str(r, ",\"truncated\":true");
}

static void resp_bool(struct cbuf *r, const char *k, int v) {
    cb_fmt(r, ",\"%s\":%s", k, v ? "true" : "false");
}

/* Закрыть соединение, не оставив в нём непрочитанного запроса.
 *
 * Unix-сокет, закрытый с непрочитанными данными, ставит собеседнику ECONNRESET (ядро,
 * unix_release_sock), и тот получает его следующим чтением — СРАЗУ ПОСЛЕ нашего ответа. Ответ
 * при этом не теряется, но клиент, читающий «до закрытия», вместо конца потока получает
 * исключение (у LocalSocket Android — IOException). Так закрывался бы каждый отказ: слишком
 * длинная строка, тело больше предела, busy — всё это отвечается, не дочитав запрос. Поэтому:
 * полузакрыть запись (клиент видит конец ответа), дочитать и выбросить то, что он успел
 * прислать, и только потом закрыть. Отвеченное соединение дочитывается в цикле событий со
 * сроком в секунду (conn_drain); отказ при приёме (denied, busy) — здесь, только то, что уже
 * пришло: ждать ради того, кого не пустили, демону незачем. Дочитывается не больше двух
 * пределов тела файла: отвергнутое как слишком большое тело put-file (больше 16 МиБ) клиент
 * шлёт целиком, прежде чем читать ответ, и сброс на середине его записи он увидел бы ошибкой
 * записи, а не нашим too-large. По локальному сокету это десятки миллисекунд; дальше —
 * секунда срока, и хватит. */
static void ctl_close_now(int c) {
    shutdown(c, SHUT_WR);
    size_t total = 0;
    char buf[16384];
    while (total < 2 * (size_t)CTL_FILE_MAX) {
        ssize_t m = recv(c, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        total += (size_t)m;
    }
    close(c);
}

/* Отказ одной строкой — для тех, кого не пустили или кому некогда: соединения у них нет,
 * отвечает сам приём. Ответ короче буфера сокета, запись не блокирует. */
static void ctl_refuse_now(int c, const char *err, const char *msg) {
    struct cbuf r = {0};
    resp_begin(&r, NULL);
    resp_error(&r, err, msg);
    cb_str(&r, "}\n");
    if (r.p) {
        ssize_t w;
        do w = send(c, r.p, r.n, MSG_NOSIGNAL | MSG_DONTWAIT); while (w < 0 && errno == EINTR);
    }
    free(r.p);
    ctl_close_now(c);
}

/* ---- выключатель движка ---------------------------------------------------------------- */

#ifdef __BIONIC__
/* Выключатель движка — то же свойство, за которым следит init (vendor/der/init/steerd.rc). */
#define STEER_CTL_PROP "persist.der.steer.enabled"

static void ctl_prop_cb(void *cookie, const char *name, const char *value, uint32_t serial) {
    (void)name; (void)serial;
    snprintf((char *)cookie, PROP_VALUE_MAX, "%s", value);
}
#endif

/* Включён ли движок. На телефоне это свойство, которое ставит приложение и за которым
 * следит init: при выключенном движке apply через сокет только СОХРАНЯЕТ спеку — поставить
 * правила в ядро значило бы включить движок в обход выключателя, а демонов, которым их
 * обслуживать (резолвер, сторож), init при выключенном не держит. Включат — init применит
 * сохранённую спеку сам (steerd.rc).
 *
 * Вне bionic свойств нет; там это швы стенда: STEER_CTL_ENABLED=0 — выключен на всё время
 * процесса; STEER_CTL_ENABLED_FILE=ФАЙЛ — выключатель, который стенд переключает на ходу, как
 * приложение свойство (первый байт «0» — выключен, файла нет — включён). По умолчанию «включён». */
static int ctl_enabled(void) {
#ifdef __BIONIC__
    char v[PROP_VALUE_MAX] = "";
    const prop_info *pi = __system_property_find(STEER_CTL_PROP);
    if (pi) __system_property_read_callback(pi, ctl_prop_cb, v);
    return !strcmp(v, "1");
#else
    const char *e = getenv("STEER_CTL_ENABLED");
    if (e && !strcmp(e, "0")) return 0;
    const char *fp = getenv("STEER_CTL_ENABLED_FILE");
    if (fp && *fp) {
        char b = '1';
        int fd = open(fp, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            if (read(fd, &b, 1) != 1) b = '1';
            close(fd);
        }
        return b != '0';
    }
    return 1;
#endif
}

/* ---- таблица команд ------------------------------------------------------------------- */

enum ctl_argkind {
    CA_NONE = 0,
    CA_NAME,      /* имя выхода: [A-Za-z0-9_.-], до 31 знака, не с «-» и не с «.» */
    CA_TARGET,    /* адрес или имя для explain: ещё «:» и «/», до 253 знаков */
    CA_INT,       /* целое в [lo, hi] */
    CA_LIT,       /* ровно слово lit; уходит в argv одним флагом без значения */
    CA_FILE,      /* имя файла списка: [A-Za-z0-9_.-], до 64 знаков, не с «-»/«.», без «..» */
    /* Слова команд плагинов (plugin-*, src/pluginmgr): */
    CA_PLUGIN,    /* id плагина: [a-z0-9][a-z0-9-]*, до 64 знаков (manifest.md) */
    CA_VER,       /* версия: semver, [0-9A-Za-z.+~-], начинается с цифры, до 64 знаков */
    CA_WORD,      /* слово поиска: печатное без пробелов, не с «-», до 64 знаков */
    CA_URL,       /* адрес репозитория: http(s)://, печатное без пробелов, до 400 знаков */
    CA_KEYID,     /* номер ключа usign: ровно 16 знаков hex */
    CA_REPO,      /* имя репозитория: [A-Za-z0-9_.-], не с «-»/«.», до 64 знаков */
    CA_ONOFF,     /* on или off */
    CA_JOBID,     /* номер задания менеджера: [0-9-], до 32 знаков */
};

struct ctl_arg {
    enum ctl_argkind kind;
    const char *flag;    /* NULL — позиционный аргумент подкоманды */
    const char *lit;
    long lo, hi;
};

struct conn;
/* В процессе: ответ дописан в r к возврату. */
typedef void (*ctl_fn)(struct conn *c, struct cbuf *r);
/* Свой порядок шагов (обычно с детьми): ответ отдаёт conn_reply, когда шаги кончатся. */
typedef void (*ctl_start)(struct conn *c);

struct ctl_cmd {
    const char *name;
    const char *sub;          /* подкоманда движка для общего случая «через ребёнка» */
    ctl_fn fn;                /* исполняется в процессе демона */
    ctl_start start;          /* свои шаги */
    /* Предел тела в байтах; 0 — тела нет. Не 0 — после строки идёт тело, последнее слово
     * строки — его длина. Предел у каждой команды свой: спеке хватает мегабайта, файлу
     * списка — нет (см. CTL_FILE_MAX). */
    long body;
    int argmin, argmax;
    struct ctl_arg args[3];
    int timeout_s;            /* срок ребёнка (sub) */
    int spec;                 /* передать подкоманде --spec и --state-dir сервера */
    int lock;                 /* изменяющая: идёт по одной (очередь демона) */
};

struct ctl_srv;

struct ctl_req {
    const struct ctl_cmd *cmd;
    const struct ctl_conf *cf;
    const char *argv[3];
    int argc;
    const char *body;
    size_t body_n;
};

/* Ребёнок команды. Один на соединение: шаги apply идут друг за другом, не вместе. */
typedef void (*job_done_fn)(struct conn *c, int code);
struct job {
    pid_t pid;
    int po, pe;               /* трубы stdout и stderr; -1 — закрыта */
    int running, reaped, status, killed, timed_out;
    struct cbuf out, err;
    struct loop_timer *tm;
    job_done_fn done;
};

enum conn_state {
    C_REQ,        /* читаем строку и тело */
    C_WAIT,       /* изменяющая команда ждёт своей очереди */
    C_RUN,        /* исполняется (ребёнок или шаги) */
    C_SEND,       /* отдаём ответ */
    C_DRAIN,      /* ответ отдан, дочитываем остаток запроса перед закрытием */
    C_SUB,        /* подписчик: соединение открыто, пишем события */
};

/* Чья сверка набора правил без соединения (conn.resync; ниже, «сверка набора правил на проходе
 * сторожа»). */
enum { RESYNC_PASS = 1, RESYNC_LAN = 2 };

struct conn {
    struct conn *next;        /* все соединения демона */
    struct conn *qnext;       /* очередь изменяющих команд */
    struct ctl_srv *srv;
    int fd;
    enum conn_state st;
    int counted;              /* занимает одно из четырёх мест (CTL_CLIENTS_MAX) */
    int hup;                  /* собеседник ушёл, пока команда шла: ответ отдавать некому */
    int eof;                  /* подписчик закрыл свою половину — читать больше нечего */
    struct loop_timer *tm;    /* срок запроса, отдачи или дочитывания */
    char line[CTL_LINE_MAX + 1];
    size_t line_n;
    int have_line;
    struct ctl_req q;
    char *body;
    size_t body_got, body_want;
    /* Ответ, пока строится; потом — то, что уходит в сокет с позиции off. У подписчика —
     * очередь событий. */
    struct cbuf resp;
    size_t off;
    size_t drained;
    struct job job;
    /* Между шагами apply/check/reload. */
    char tmp[PATH_MAX];
    struct cbuf old;
    int had_old;
    pid_t dn[8];
    int dn_n;
    void (*after_reload)(struct conn *c);
    struct steerd_sub sub;
    /* Apply-сверка (recon.c): план новой спеки, решение, stderr плана, код и stderr reload. */
    struct recon_plan plan;
    struct recon_diff diff;
    struct cbuf perr;
    int watch;                /* сторожу внеочередной проход */
    int committed;            /* apply-commit запускался */
    int rcode;                /* код reload */
    int boot;                 /* применение при старте (--apply): соединения нет, итог — в журнал */
    int repair;               /* починка правил (rulewd.c): соединения нет, итог — в журнал */
    /* Починка набора правил по сверке прохода сторожа (srv_resync): reload без соединения.
     * RESYNC_PASS — расхождение нашёл проход, RESYNC_LAN — пересоздано устройство раздачи
     * (srv_lan). */
    int resync;
    struct recon_kernel kern; /* ядро после nft -f apply-commit (строка recon-kernel) */
    struct ctl_cmd pcmd;      /* строка команды плагина (plugin_ctl_cmd): её адрес — в q.cmd */
};

struct ctl_srv {
    struct ctl_conf cf;
    struct steerd d;
    struct loop *l;
    int lfd;
    ino_t ino;
    struct loop_timer *accept_tm;
    struct conn *conns;
    int active, subs;
    struct conn *lock_owner, *lockq;
    int hup_pending;
    struct watchd *watch;     /* сторож выходов; NULL — без --watch */
    struct recon_state rec;   /* что демон применил сам (apply-сверка, recon.c) */
    struct loop_timer *snap_tm;   /* освежение снимка status (с --watch), см. srv_snap */
    struct rulewd *rules;     /* страж правил выходов (с --watch); NULL — без него */
    int on;                   /* движок включён — как сказали последние apply, reload, SIGHUP */
    /* Когда ставились последние починки по сверке прохода (srv_resync), мс монотонных, по кругу;
     * 0 — не было. Размер — RESYNC_BURST. */
    long resync_at[3];
    int resync_i;
    /* Устройство раздачи пересоздано (srv_lan): сверка набора правил через LAN_SETTLE_MS; ещё
     * одна после идущей (lan_again) — та могла собрать план до нового устройства. Сверок по
     * устройствам раздачи за окно — lan_n с начала окна lan_win. */
    struct loop_timer *lan_tm;
    int lan_again;
    long lan_win;
    int lan_n;
    long lan_said;
    /* Лимит сверок прохода (srv_kcheck): когда устройство раздачи последний раз пропадало или
     * появлялось (lan_at) и когда начинался последний план (plan_at), мс монотонных. Расхождение
     * после смены устройства раздачи, которую ещё не видел ни один план, — объяснимое и не в счёт
     * RESYNC_BURST. resync_said — окно (самая старая починка в нём), о котором отказ уже сказан. */
    long lan_at, plan_at, resync_said;
};

static void mem_version(struct conn *c, struct cbuf *r);
static void mem_status(struct conn *c, struct cbuf *r);
static void mem_diag(struct conn *c, struct cbuf *r);
static void mem_explain(struct conn *c, struct cbuf *r);
static void mem_conns(struct conn *c, struct cbuf *r);
static void mem_dns_log(struct conn *c, struct cbuf *r);
static void ctl_do_put_file(struct conn *c, struct cbuf *r);
static void ctl_do_list_files(struct conn *c, struct cbuf *r);
static void ctl_do_rm_file(struct conn *c, struct cbuf *r);
static void mem_select(struct conn *c, struct cbuf *r);
static void mem_helper(struct conn *c, struct cbuf *r);
static void st_apply(struct conn *c);
static void st_check(struct conn *c);
static void st_reload(struct conn *c);
static void st_plugcmd_body(struct conn *c);
static int plugin_ctl_cmd(const char *name, struct ctl_cmd *k);
static void st_subscribe(struct conn *c);
static void st_repair(struct conn *c);
static void st_plugin(struct conn *c);
static void st_plugin_reload(struct conn *c);
static void mem_plugin_event(struct conn *c, struct cbuf *r);

/* ТАБЛИЦА — единственное, что сервер умеет. Команда, которой здесь нет, не исполняется ни в
 * каком виде: слова запроса никогда не становятся именем подкоманды, в argv идут только
 * проверенные по виду аргументы на заранее назначенных местах.
 *
 * Новая команда поверх готовой подкоманды движка — одна строка с sub: она исполняется
 * ребёнком, и то, что приложение видит через сокет, человек получает той же подкомандой в adb
 * root shell. Команда, ответ которой демон может собрать из памяти, — строка с fn: ответ
 * собирает тот же код, что печатает подкоманда (см. «ИСПОЛНЕНИЕ» в шапке).
 *
 * Файлы списков (put-file, list-files, rm-file) — своя обработка, без подкоманды: это работа
 * с каталогом, которую делает сам демон, и подкоманда ради неё была бы вторым путём записи в
 * каталог, которым никто, кроме сервера, не пользуется.
 *
 * Сроки детей — у строк; check и apply — свои (см. st_check, st_apply).
 *
 * КОМАНДЫ ПЛАГИНОВ (steer-api.md, 4.3). Подкоманда из манифеста с `ctl` получает строку здесь же,
 * собранную из манифеста (plugin_ctl_cmd): слова — по видам ctl.args, срок — ctl.timeout_s, тело —
 * файлом (ctl.body: file). Исполняет её ребёнок `steerd <команда> <слова…>` — тот же путь, что у
 * человека в shell (plugin_cmd_exec), с --spec и --state-dir демона: у команды с conf по ним ядро
 * кладёт {conf} выхода. Имён команд плагинов ядро не знает; команда ядра с тем же именем — первая. */
static const struct ctl_cmd CTL_CMDS[] = {
    {"version",     NULL, mem_version, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"status",      NULL, mem_status, NULL, 0, 0, 1, {{CA_LIT, "--fast", "fast", 0, 0}}, 0, 0, 0},
    {"diag",        NULL, mem_diag, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"explain",     NULL, mem_explain, NULL, 0, 1, 1, {{CA_TARGET, NULL, NULL, 0, 0}}, 0, 0, 0},
    {"check",       NULL, NULL, st_check,  CTL_BODY_MAX, 0, 0, {{0}}, 0, 1, 1},
    {"apply",       NULL, NULL, st_apply,  CTL_BODY_MAX, 0, 0, {{0}}, 0, 1, 1},
    {"reload",      NULL, NULL, st_reload, 0, 0, 0, {{0}}, 0, 1, 1},
    {"conns",       NULL, mem_conns, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"helper",      NULL, mem_helper, NULL, 0, 1, 1, {{CA_NAME, NULL, NULL, 0, 0}}, 0, 0, 0},
    {"dns-log",     NULL, mem_dns_log, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"put-file",    NULL, ctl_do_put_file, NULL, CTL_FILE_MAX, 1, 1, {{CA_FILE, NULL, NULL, 0, 0}}, 0, 0, 0},
    {"list-files",  NULL, ctl_do_list_files, NULL, 0, 0, 0, {{0}}, 0, 0, 0},
    {"rm-file",     NULL, ctl_do_rm_file, NULL, 0, 1, 1, {{CA_FILE, NULL, NULL, 0, 0}}, 0, 0, 1},
    {"subscribe",   NULL, NULL, st_subscribe, 0, 0, 0, {{0}}, 0, 0, 0},
    /* Выбор члена группы pick: manual (docs/ctl.md): в процессе, без apply — изменяющая, идёт по
     * одной с apply и reload (они пишут те же таблицы). */
    {"select",      NULL, mem_select, NULL, 0, 2, 2,
        {{CA_NAME, NULL, NULL, 0, 0}, {CA_NAME, NULL, NULL, 0, 0}}, 0, 0, 1},
    /* МЕНЕДЖЕР ПЛАГИНОВ (steer-api.md, 4.2; src/pluginmgr): ребёнок `steerd plugin <действие> … --json`,
     * тот же, что у человека в shell. Изменяющие идут под СВОЕЙ блокировкой менеджера (flock), а не в
     * очереди apply: установка ждёт сеть и проверку здоровья до десяти минут, а проверке здоровья
     * нужен plugin-reload — изменяющая команда демона; в общей очереди они ждали бы друг друга.
     * Занятый менеджер отвечает «busy: …» кодом 1. Сам plugin-reload — в очереди apply.
     * Тело plugin-repo-add — открытый ключ, plugin-install-file — архив .s2p, plugin-ensure — id
     * плагинов через пробел (их может быть сколько угодно, а слов в строке запроса — пять). */
    {"plugin-list",         "list", NULL, st_plugin, 0, 0, 0, {{0}}, 60, 0, 0},
    {"plugin-search",       "search", NULL, st_plugin, 0, 0, 1, {{CA_WORD, NULL, NULL, 0, 0}}, 180, 0, 0},
    {"plugin-status",       "status", NULL, st_plugin, 0, 0, 1, {{CA_PLUGIN, NULL, NULL, 0, 0}}, 60, 0, 0},
    {"plugin-install",      "install", NULL, st_plugin, 0, 1, 2,
        {{CA_PLUGIN, NULL, NULL, 0, 0}, {CA_VER, NULL, NULL, 0, 0}}, 600, 0, 0},
    {"plugin-install-file", "install", NULL, st_plugin, 64L * 1024 * 1024, 0, 1,
        {{CA_LIT, "--unsigned", "unsigned", 0, 0}}, 600, 0, 0},
    {"plugin-update",       "update", NULL, st_plugin, 0, 0, 1, {{CA_PLUGIN, NULL, NULL, 0, 0}}, 3600, 0, 0},
    {"plugin-remove",       "remove", NULL, st_plugin, 0, 1, 3,
        {{CA_PLUGIN, NULL, NULL, 0, 0}, {CA_LIT, "--force", "force", 0, 0}, {CA_LIT, "--purge", "purge", 0, 0}}, 300, 0, 0},
    {"plugin-enable",       "enable", NULL, st_plugin, 0, 1, 1, {{CA_PLUGIN, NULL, NULL, 0, 0}}, 300, 0, 0},
    {"plugin-disable",      "disable", NULL, st_plugin, 0, 1, 1, {{CA_PLUGIN, NULL, NULL, 0, 0}}, 300, 0, 0},
    {"plugin-autoupdate",   "autoupdate", NULL, st_plugin, 0, 2, 2,
        {{CA_PLUGIN, NULL, NULL, 0, 0}, {CA_ONOFF, NULL, NULL, 0, 0}}, 30, 0, 0},
    {"plugin-ensure",       "ensure", NULL, st_plugin, 64 * 1024, 0, 0, {{0}}, 3600, 0, 0},
    {"plugin-job",          "job", NULL, st_plugin, 0, 1, 1, {{CA_JOBID, NULL, NULL, 0, 0}}, 10, 0, 0},
    {"plugin-repo-list",    "repo list", NULL, st_plugin, 0, 0, 0, {{0}}, 30, 0, 0},
    {"plugin-repo-add",     "repo add", NULL, st_plugin, 64 * 1024, 2, 2,
        {{CA_URL, NULL, NULL, 0, 0}, {CA_KEYID, NULL, NULL, 0, 0}}, 120, 0, 0},
    {"plugin-repo-del",     "repo del", NULL, st_plugin, 0, 1, 1, {{CA_REPO, NULL, NULL, 0, 0}}, 30, 0, 0},
    /* Перечитать плагины (реестр ядра, kinds/plugin.c) и спеку — как reload; зовёт менеджер после
     * каждого изменения. Изменяющая: в очереди с apply. */
    {"plugin-reload",       NULL, NULL, st_plugin_reload, 0, 0, 0, {{0}}, 0, 1, 1},
    /* Событие `plugin` подписчикам: менеджер сообщает, что сделал (тело — объект JSON). */
    {"plugin-event",        NULL, mem_plugin_event, NULL, 64 * 1024, 0, 0, {{0}}, 0, 0, 0},
};

static const struct ctl_cmd *ctl_lookup(const char *name) {
    for (size_t i = 0; i < sizeof(CTL_CMDS) / sizeof(CTL_CMDS[0]); i++)
        if (!strcmp(CTL_CMDS[i].name, name)) return &CTL_CMDS[i];
    return NULL;
}

/* Проверка слова по виду. Слова идут в argv без shell, но слово с «-» в начале подкоманда
 * приняла бы за флаг — `explain --spec` читал бы чужой файл, — поэтому вид проверяется
 * строго, до запуска. */
static const char *ctl_arg_bad(const struct ctl_arg *a, const char *w) {
    size_t n = strlen(w);
    switch (a->kind) {
    case CA_LIT:
        return strcmp(w, a->lit) ? "здесь понимается только одно слово" : NULL;
    case CA_INT: {
        char *e = NULL;
        errno = 0;
        long v = strtol(w, &e, 10);
        if (!n || n > 6 || *e || errno) return "нужно целое число";
        if (v < a->lo || v > a->hi) return "число вне допустимого";
        return NULL;
    }
    case CA_NAME:
    case CA_TARGET: {
        size_t lim = a->kind == CA_NAME ? 31 : 253;
        if (!n || n > lim) return "слишком длинное или пустое";
        if (w[0] == '-' || w[0] == '.') return "не может начинаться с «-» или «.»";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            int ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                     (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-';
            if (a->kind == CA_TARGET && (c == ':' || c == '/')) ok = 1;
            if (!ok) return "недопустимый знак";
        }
        return NULL;
    }
    case CA_FILE: {
        /* Имя файла становится путём <каталог списков>/<имя>, поэтому вид строже, чем у
         * имени выхода: ни «/», ни «..» (выход из каталога), ни точки в начале (скрытые имена
         * заняты временными файлами самого сервера, .put-XXXXXX), ни «-» в начале (имя может
         * оказаться в argv подкоманды через спеку). Знаки — те же, что у имён файлов в
         * каталоге splify2-lists. */
        if (!n || n > CTL_FNAME_MAX) return "слишком длинное или пустое имя файла";
        if (w[0] == '-' || w[0] == '.') return "имя файла не может начинаться с «-» или «.»";
        if (strstr(w, "..")) return "в имени файла не может быть «..»";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-'))
                return "недопустимый знак в имени файла";
        }
        return NULL;
    }
    case CA_PLUGIN:
        if (!n || n > 64) return "недопустимое имя плагина";
        if (!((w[0] >= 'a' && w[0] <= 'z') || (w[0] >= '0' && w[0] <= '9'))) return "недопустимое имя плагина";
        for (size_t i = 0; i < n; i++)
            if (!((w[i] >= 'a' && w[i] <= 'z') || (w[i] >= '0' && w[i] <= '9') || w[i] == '-'))
                return "недопустимое имя плагина";
        return NULL;
    case CA_VER:
        if (!n || n > 64 || !(w[0] >= '0' && w[0] <= '9')) return "недопустимая версия";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '.' || c == '+' || c == '~' || c == '-'))
                return "недопустимая версия";
        }
        return NULL;
    case CA_WORD:
    case CA_URL:
        if (!n || n > (a->kind == CA_URL ? 400u : 64u)) return "слишком длинное или пустое слово";
        if (w[0] == '-') return "слово не может начинаться с «-»";
        for (size_t i = 0; i < n; i++)
            if ((unsigned char)w[i] <= ' ' || w[i] == 0x7f) return "недопустимый знак";
        if (a->kind == CA_URL && strncmp(w, "https://", 8) && strncmp(w, "http://", 7))
            return "адрес репозитория — https://…";
        return NULL;
    case CA_KEYID:
        if (n != 16 || strspn(w, "0123456789abcdefABCDEF") != 16) return "номер ключа — 16 знаков hex";
        return NULL;
    case CA_REPO:
        if (!n || n > 64 || w[0] == '-' || w[0] == '.') return "недопустимое имя репозитория";
        for (size_t i = 0; i < n; i++) {
            unsigned char c = (unsigned char)w[i];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
                  c == '_' || c == '.' || c == '-'))
                return "недопустимое имя репозитория";
        }
        return NULL;
    case CA_ONOFF:
        return strcmp(w, "on") && strcmp(w, "off") ? "нужно on или off" : NULL;
    case CA_JOBID:
        if (!n || n > 32 || strspn(w, "0123456789-") != n || w[0] == '-') return "недопустимый номер задания";
        return NULL;
    default:
        return "лишнее слово";
    }
}

/* argv подкоманды: движок, подкоманда, аргументы по местам, затем спека и состояние. */
static size_t ctl_argv(const struct ctl_req *q, const char *sub, char **av, size_t cap) {
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = (char *)sub;
    for (int i = 0; i < q->argc && n + 2 < cap; i++) {
        const struct ctl_arg *a = &q->cmd->args[i];
        if (a->flag) av[n++] = (char *)a->flag;
        if (a->kind != CA_LIT || !a->flag) av[n++] = (char *)q->argv[i];
    }
    if (q->cmd->spec && n + 5 < cap) {
        av[n++] = "--spec";
        av[n++] = (char *)q->cf->spec;
        if (q->cf->state_dir) {
            av[n++] = "--state-dir";
            av[n++] = (char *)q->cf->state_dir;
        }
    }
    av[n] = NULL;
    return n;
}

/* ---- соединения: ответ, отдача, дочитывание ---------------------------------------------- */

static void conn_free(struct conn *c);
static void conn_exec(struct conn *c);
static void conn_ev(struct loop *l, int fd, uint32_t ev, void *arg);

/* Изменяющая команда кончилась: следующая из очереди — сейчас же. SIGHUP, пришедший, пока
 * шла команда, перечитывает спеку после неё: перечитывание пишет реестр меток, как и
 * dry-run, и вперемешку с чужим apply им нельзя. */
static void srv_spec_changed(struct ctl_srv *s, const char *by, int enabled,
                             const struct recon_diff *d, int watch, struct cbuf *changed);

static void lock_release(struct ctl_srv *s) {
    s->lock_owner = NULL;
    struct conn *n = s->lockq;
    if (n) {
        s->lockq = n->qnext;
        n->qnext = NULL;
        conn_exec(n);
        return;
    }
    if (s->hup_pending) {
        s->hup_pending = 0;
        srv_spec_changed(s, "hup", ctl_enabled(), NULL, 1, NULL);
    }
    /* Проверка правил, отложенная до конца своей операции (rulewd.h). */
    rulewd_kick(s->rules);
}

static void conn_events(struct conn *c, uint32_t ev) {
    if (!c->hup) loop_fd_mod(c->srv->l, c->fd, ev);
}

/* Отдать, сколько сокет примет. 0 — всё отдано или ждём EPOLLOUT; -1 — соединение закрыто
 * (освобождено здесь же — трогать c после этого нельзя). */
static int conn_flush(struct conn *c) {
    int progress = 0;
    while (c->off < c->resp.n) {
        ssize_t w = send(c->fd, c->resp.p + c->off, c->resp.n - c->off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w > 0) { c->off += (size_t)w; progress = 1; continue; }
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            if (c->st == C_SEND && progress) loop_timer_set(c->tm, CTL_SEND_MS);
            conn_events(c, EPOLLOUT | (c->st == C_SUB && !c->eof ? EPOLLIN : 0));
            return 0;
        }
        conn_free(c);
        return -1;
    }
    if (c->st == C_SUB) {
        c->resp.n = c->off = 0;
        conn_events(c, c->eof ? 0 : EPOLLIN);
        return 0;
    }
    /* Ответ отдан целиком: полузакрыть запись (клиент видит конец ответа) и дочитать то, что
     * он ещё шлёт, — см. «Закрыть соединение, не оставив…». */
    shutdown(c->fd, SHUT_WR);
    c->st = C_DRAIN;
    c->drained = 0;
    loop_timer_set(c->tm, CTL_DRAIN_MS);
    conn_events(c, EPOLLIN);
    return 0;
}

static void conn_drain(struct conn *c) {
    char buf[16384];
    for (;;) {
        ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (m <= 0) { conn_free(c); return; }
        c->drained += (size_t)m;
        if (c->drained >= 2 * (size_t)CTL_FILE_MAX) { conn_free(c); return; }
    }
}

/* Ответ готов (в c->resp без закрывающей скобки) — отдать. Снимает блокировку изменяющих
 * команд, если она у этого соединения. */
static void conn_reply(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (s->lock_owner == c) lock_release(s);
    if (c->hup) { conn_free(c); return; }
    cb_str(&c->resp, "}\n");
    c->st = C_SEND;
    c->off = 0;
    loop_timer_set(c->tm, CTL_SEND_MS);
    conn_flush(c);
}

/* Отказ посреди запроса: всё, что успели дописать в ответ, выбрасывается. */
static void conn_refuse(struct conn *c, const char *cmd, const char *err, const char *msg) {
    c->resp.n = 0;
    c->resp.trunc = 0;
    resp_begin(&c->resp, cmd);
    resp_error(&c->resp, err, msg);
    conn_reply(c);
}

/* ---- ребёнок ------------------------------------------------------------------------------ */

static void job_check(struct conn *c) {
    struct job *j = &c->job;
    if (!j->running || j->po >= 0 || j->pe >= 0 || !j->reaped) return;
    j->running = 0;
    loop_timer_stop(j->tm);
    int st = j->status, code = -1;
    if (WIFEXITED(st)) code = WEXITSTATUS(st);
    else if (WIFSIGNALED(st)) code = 128 + WTERMSIG(st);
    j->done(c, code);
}

static void job_close_pipe(struct conn *c, int *fd) {
    if (*fd < 0) return;
    loop_fd_del(c->srv->l, *fd);
    close(*fd);
    *fd = -1;
}

static void job_pipe(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)l; (void)ev;
    struct conn *c = arg;
    struct job *j = &c->job;
    int *pfd = fd == j->po ? &j->po : &j->pe;
    struct cbuf *b = fd == j->po ? &j->out : &j->err;
    char buf[16384];
    for (;;) {
        ssize_t m = read(fd, buf, sizeof(buf));
        if (m > 0) { cb_put(b, buf, (size_t)m); continue; }
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        job_close_pipe(c, pfd);
        break;
    }
    job_check(c);
}

static void job_child(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l; (void)pid;
    struct conn *c = arg;
    c->job.reaped = 1;
    c->job.status = status;
    job_check(c);
}

/* Срок. Первый раз — SIGKILL всей группе команды и ещё две секунды на то, чтобы трубы
 * закрылись; второй — трубы держит кто-то вне группы, хватит ждать: закрыть их самим. */
static void job_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct conn *c = arg;
    struct job *j = &c->job;
    if (!j->running) return;
    if (!j->killed) {
        kill(-j->pid, SIGKILL);
        if (!j->reaped) kill(j->pid, SIGKILL);
        j->killed = 1;
        j->timed_out = 1;
        loop_timer_set(j->tm, 2000);
        return;
    }
    job_close_pipe(c, &j->po);
    job_close_pipe(c, &j->pe);
    job_check(c);
}

/* Запустить движок с argv: вывод копится в job.out/job.err (с пределами outmax/errmax), по
 * выходу — done(c, код) (убитый сигналом — 128 + номер, как в shell). -1 — запустить не
 * удалось (done не будет). */
static int job_start(struct conn *c, char *const argv[], int timeout_s, size_t outmax,
                     size_t errmax, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    free(j->out.p);
    free(j->err.p);
    memset(&j->out, 0, sizeof(j->out));
    memset(&j->err, 0, sizeof(j->err));
    j->out.max = outmax;
    j->err.max = errmax;
    j->reaped = j->killed = j->timed_out = j->status = 0;
    j->po = j->pe = -1;
    j->done = done;
    if (!j->tm && !(j->tm = loop_timer_new(s->l, job_timer, c))) return -1;
    int po[2], pe[2];
    /* Ход перебора узлов vless из памяти супервизора (--supervise) — ребёнку в окружение: клиенты
     * с трубой событий файлов probe-* не пишут, а подкоманды спрашивают probe_read. Запись
     * потерянного узла несёт причину (закодированной — до пятисот байт на выход), отсюда запас. */
    char *pmem = supd_probe_env(s->d.sup);      /* без предела: строка в куче по числу выходов */
    if (pipe2(po, O_CLOEXEC) != 0) { free(pmem); return -1; }
    if (pipe2(pe, O_CLOEXEC) != 0) { close(po[0]); close(po[1]); free(pmem); return -1; }
    pid_t pid = fork();
    if (pid < 0) {
        close(po[0]); close(po[1]); close(pe[0]); close(pe[1]);
        free(pmem);
        return -1;
    }
    if (pid == 0) {
        /* Своя группа процессов: по сроку убивается и то, что команда успела запустить
         * (nft, ip, iptables), а не только она сама. */
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDONLY);
        if (nul >= 0) dup2(nul, 0);
        dup2(po[1], 1);
        dup2(pe[1], 2);
        /* Сигналы цикла заблокированы, SIGPIPE игнорируется — и то и другое наследуется
         * через exec, а подкоманды рассчитывают на обычное поведение. */
        loop_child_reset();
        if (pmem) putenv(pmem);
        execv(s->cf.exe, argv);
        dprintf(2, LOG_W "не запустить %s: %s\n", s->cf.exe, strerror(errno));
        _exit(127);
    }
    free(pmem);
    close(po[1]);
    close(pe[1]);
    /* Неблокирующим — только наш конец: у ребёнка stdout обычный. */
    fcntl(po[0], F_SETFL, fcntl(po[0], F_GETFL) | O_NONBLOCK);
    fcntl(pe[0], F_SETFL, fcntl(pe[0], F_GETFL) | O_NONBLOCK);
    j->pid = pid;
    j->po = po[0];
    j->pe = pe[0];
    j->running = 1;
    if (loop_fd_add(s->l, j->po, EPOLLIN, job_pipe, c) != 0) { close(j->po); j->po = -1; }
    if (loop_fd_add(s->l, j->pe, EPOLLIN, job_pipe, c) != 0) { close(j->pe); j->pe = -1; }
    loop_child(s->l, pid, job_child, c);
    loop_timer_set(j->tm, (long)timeout_s * 1000L);
    return 0;
}

/* Общий случай: подкоманда целиком — её код и вывод. */
static void sub_done(struct conn *c, int code) {
    struct job *j = &c->job;
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться ядра"); conn_reply(c); return; }
    resp_run(&c->resp, code, &j->out, &j->err);
    if (j->timed_out) resp_error(&c->resp, "timeout", "команда не уложилась в свой срок и остановлена");
    conn_reply(c);
}

static void st_sub(struct conn *c) {
    char *av[16];
    ctl_argv(&c->q, c->q.cmd->sub, av, sizeof(av) / sizeof(av[0]));
    if (job_start(c, av, c->q.cmd->timeout_s, CTL_OUT_MAX, CTL_ERR_MAX, sub_done) != 0) {
        resp_error(&c->resp, "internal", "не удалось запустить ядро");
        conn_reply(c);
    }
}

/* ---- в процессе: stdout в память, stderr в файл в памяти -------------------------------- *
 *
 * Ответ команды в процессе должен быть тем же, что у подкоманды, — и stdout, и stderr: у conns
 * причина отказа («нет модуля nf_conntrack_netlink») лежит именно в stderr, и приложение её
 * показывает. stdout печатается в поток open_memstream (функции ответа принимают FILE*), а
 * stderr на время команды — дескриптор 2, перенаправленный в memfd: так в ответ попадает и
 * то, что пишет глубоко вложенный код (виды выходов, nft в popen со своим stderr), без
 * протаскивания второго потока через всё дерево. Демон однопоточный, и на время команды
 * других записей в журнал у него нет. Нет memfd (ядро старше 3.17) — удалённый временный файл
 * в каталоге состояния; нет и его — stderr остаётся в журнале, а в ответе пусто. */
struct mem_run {
    FILE *f;
    char *p;
    size_t n;
    int saved, fd;
};

static int cap_fd(void) {
#ifdef SYS_memfd_create
    int fd = (int)syscall(SYS_memfd_create, "steer-ctl", 1u /* MFD_CLOEXEC */);
    if (fd >= 0) return fd;
#endif
    char t[PATH_MAX];
    snprintf(t, sizeof(t), "%s/.ctl-err-XXXXXX", steer_state_dir());
    int fd2 = mkostemp(t, O_CLOEXEC);
    if (fd2 >= 0) unlink(t);
    return fd2;
}

static FILE *mem_begin(struct mem_run *m) {
    memset(m, 0, sizeof(*m));
    m->saved = m->fd = -1;
    m->f = open_memstream(&m->p, &m->n);
    if (!m->f) return NULL;
    fflush(stderr);
    m->fd = cap_fd();
    if (m->fd >= 0) {
        m->saved = fcntl(2, F_DUPFD_CLOEXEC, 3);
        if (m->saved < 0 || dup2(m->fd, 2) < 0) {
            if (m->saved >= 0) close(m->saved);
            close(m->fd);
            m->saved = m->fd = -1;
        }
    }
    return m->f;
}

static void mem_end(struct mem_run *m, struct cbuf *r, int code) {
    struct cbuf out = { .max = CTL_OUT_MAX }, err = { .max = CTL_ERR_MAX };
    fflush(stderr);
    if (m->saved >= 0) {
        dup2(m->saved, 2);
        close(m->saved);
        char buf[16384];
        ssize_t k;
        if (lseek(m->fd, 0, SEEK_SET) == 0)
            while ((k = read(m->fd, buf, sizeof(buf))) > 0) cb_put(&err, buf, (size_t)k);
        close(m->fd);
    }
    fclose(m->f);
    if (m->p) cb_put(&out, m->p, m->n);
    free(m->p);
    resp_run(r, code, &out, &err);
    free(out.p);
    free(err.p);
}

/* Отказ разбора спеки — тем же текстом, что err_die у подкоманды. */
static int mem_no_spec(const struct steerd *d) {
    fprintf(stderr, "%s%s\n", "steer: ", d->err);
    return 2;
}

/* version — ещё и то, чью спеку демон обслуживает: spec_path и state_dir полными путями. По ним
 * клиент steer решает, отдавать ли демону `steer status --spec X` (та же спека) или движку
 * (чужая: стенд, ручной запуск). Поля добавлены к версии 1 — прежние не изменились. */
static void mem_version(struct conn *c, struct cbuf *r) {
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    cli_version(f);
    mem_end(&m, r, 0);
    /* realpath на каждый ответ, а не при старте: спеки при старте может ещё не быть (роутер без
     * настройки), а файла нет — путь как написан. */
    char rp[PATH_MAX];
    /* Файл, который спека сейчас (plat_spec_resolve): init-скрипт называет spec.json и тогда,
     * когда лежит spec.yaml, а клиент без --spec сверяет с тем, что лежит. */
    const char *sp = plat_spec_resolve(c->srv->cf.spec);
    cb_str(r, ",\"spec_path\":");
    cb_jstr(r, realpath(sp, rp) ? rp : sp);
    cb_str(r, ",\"state_dir\":");
    cb_jstr(r, realpath(steer_state_dir(), rp) ? rp : steer_state_dir());
}

/* status из памяти: спека и группы — демона, а то, что меняется без спеки (устройство,
 * выбранное сторожем, /sys, счётчики nft, реестр), читается на каждый вызов, как у подкоманды.
 * fast — запомненный снимок, как `status --fast`. */
static void mem_status(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = 0;
    if (c->q.argc > 0 && status_fast(f) == 0) {
        /* запомненное отдано */
    } else if (!d->have) {
        code = mem_no_spec(d);
    } else {
        memcpy(d->view, d->sp, sizeof(*d->view));
        /* Выбор устройств — из памяти сторожа, если сторож — сам демон (--watch); иначе из
         * файла, который пишет `steer failover`. */
        outputs_adopt_active_st(d->view, d->outs ? d->outs : &fo_store_files);
        /* Дамп ruleset для fw_check — один на процесс подкоманды; у демона процесс один на
         * всё время, и дамп берётся заново на каждый ответ. */
        fwcheck_reset_cache();
        status_answer(d->view, d->gr, f);
    }
    mem_end(&m, r, code);
}

/* diag из памяти — тем же кодом, что подкоманда (diag_emit), и без единого процесса: прежде это
 * был ребёнок `steerd diag`, а он сам запускал около двадцати (nft, pgrep, ip, пробы `nft -c`).
 * Спека и группы — демона, устройство — по выбору сторожа, как у status. Цикл на время отчёта
 * занят: проверки — вопросы ядру по netlink, обход /proc и чтение файлов списков (публичный
 * резолвер в списке канала vless), то есть миллисекунды, а не секунды пробы. */
static void mem_diag(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code;
    if (!d->have) {
        code = mem_no_spec(d);
    } else {
        memcpy(d->view, d->sp, sizeof(*d->view));
        outputs_adopt_active_st(d->view, d->outs ? d->outs : &fo_store_files);
        fwcheck_reset_cache();
        code = diag_emit(d->view, d->gr, f);
    }
    mem_end(&m, r, code);
}

static void mem_explain(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    const char *what = c->q.argv[0];
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code;
    /* Тот же порядок проверок, что у подкоманды (main.c): форма аргумента, затем спека. */
    if (!addr_ok(what) && !looks_like_name(what)) {
        fprintf(stderr, "%s%s%s\n", "steer: ", "это не адрес и не имя: ", what);
        code = 2;
    } else if (!d->have) {
        code = mem_no_spec(d);
    } else {
        code = explain_emit(d->sp, d->gr, what, f);
    }
    mem_end(&m, r, code);
}

static void mem_conns(struct conn *c, struct cbuf *r) {
    (void)c;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = ctnl_conns_print(f);
    mem_end(&m, r, code);
}

/* select ГРУППА ЧЛЕН — выбор члена группы pick: manual без apply (fogroup.c, fog_select): выбор
 * кладётся в память сторожа (и в файл select рядом со спекой), таблица группы тут же
 * переписывается на лист члена, подписчикам — switched с by: select (или failed, если член не
 * работает: у manual это on_fail группы, а не другой член). Идущий проход сторожа прерывается —
 * его решения легли бы поверх выбора, — и следующий идёт после успокоения. Движок выключен —
 * выбор только запоминается. */
static void sel_emit(void *arg, const struct fo_event *e) {
    steerd_fo_emit(arg, e);
}

static void mem_select(struct conn *c, struct cbuf *r) {
    struct ctl_srv *s = c->srv;
    struct steerd *d = &s->d;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code;
    if (!d->have) {
        code = mem_no_spec(d);
    } else {
        watchd_preempt(s->watch);
        memcpy(d->view, d->sp, sizeof(*d->view));
        code = fog_select(d->view, d->outs ? d->outs : &fo_store_files, c->q.argv[0], c->q.argv[1],
                          ctl_enabled(), sel_emit, d, f);
        if (code == 0) watchd_spec_changed(s->watch);
    }
    mem_end(&m, r, code);
}

/* helper ВЫХОД — живое состояние помощников выхода из памяти супервизора (--supervise): процесс,
 * up, причина отказа, перезапуски, узел vless, отставленные пути моста tgws (supd_helper_json).
 * Этим отвечает `steer xsteer-peers` у выхода под демоном: клиент xsteer с трубой событий файла
 * xsteer-<выход>.json не пишет. Помощника нет (демон не супервизор, выход без помощника) — код 1. */
static void mem_helper(struct conn *c, struct cbuf *r) {
    struct steerd *d = &c->srv->d;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = 0;
    if (supd_helper_json(d->sup, c->q.argv[0], f) != 0) {
        fprintf(stderr, "steer: helper: у выхода %s нет помощника под этим демоном\n", c->q.argv[0]);
        code = 1;
    }
    mem_end(&m, r, code);
}

/* Журнал резолвера — разговор с его сокетом (dlog_print): он отвечает из памяти, за
 * миллисекунды; зависший резолвер держит демон не дольше трёх секунд срока чтения. */
static void mem_dns_log(struct conn *c, struct cbuf *r) {
    (void)c;
    struct mem_run m;
    FILE *f = mem_begin(&m);
    if (!f) { resp_error(r, "internal", "нет памяти под ответ"); return; }
    int code = dlog_print(f);
    mem_end(&m, r, code);
}

/* Снимок status (status.json, его отдаёт `status --fast`) — раз в пять минут, с --watch.
 *
 * До демона это делал отдельный экземпляр procd (`while :; do steer status; sleep 300; done` в
 * init.d): снимок обязан быть свежим к моменту, когда человек ОТКРЫВАЕТ окно splify2, а пока
 * окно закрыто, полных status никто не спрашивает. Один сервис — один процесс, и круг переехал
 * сюда. Только с --watch: это режим, в котором демон — весь движок (procd, сервис телефона);
 * стенды и ручной запуск без сторожа лишних ответов не считают. Пока идёт изменяющая команда —
 * пропуск до следующего раза: спека в памяти как раз меняется. */
#define CTL_SNAP_MS (300L * 1000L)

static void srv_snap(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l;
    struct ctl_srv *s = arg;
    struct steerd *d = &s->d;
    if (d->have && !s->lock_owner) {
        FILE *f = fopen("/dev/null", "w");
        if (f) {
            memcpy(d->view, d->sp, sizeof(*d->view));
            outputs_adopt_active_st(d->view, d->outs ? d->outs : &fo_store_files);
            fwcheck_reset_cache();
            status_answer(d->view, d->gr, f);
            fclose(f);
        }
    }
    /* Выключенному движку снимок не нужен (и пробуждение раз в пять минут — тоже): таймер
     * заведёт srv_set_enabled, когда движок включат. */
    if (s->on) loop_timer_set(t, CTL_SNAP_MS);
}

/* ---- apply и check ---------------------------------------------------------------------- */

static const char *ctl_state_dir(const struct ctl_conf *cf) {
    return cf->state_dir ? cf->state_dir : plat()->state_dir;
}

/* Записать данные во временный файл РЯДОМ с целевым (тот же довод, что у spec_set в
 * splify2: rename атомарен только внутри одной файловой системы). 0 — готово, имя в tmp. */
static int ctl_write_tmp(const char *final, const char *data, size_t n, char *tmp, size_t tn) {
    if ((size_t)snprintf(tmp, tn, "%s.ctl-XXXXXX", final) >= tn) return -1;
    int fd = mkostemp(tmp, O_CLOEXEC);
    if (fd < 0) return -1;
    int ok = ctl_write_all(fd, data, n) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok) { unlink(tmp); return -1; }
    return 0;
}

/* Каталог после rename — чтобы новое имя пережило обрыв питания, а не только новое
 * содержимое. */
static void ctl_fsync_dir(const char *path) {
    char d[PATH_MAX];
    snprintf(d, sizeof(d), "%s", path);
    char *s = strrchr(d, '/');
    if (!s) snprintf(d, sizeof(d), ".");
    else if (s == d) d[1] = '\0';
    else *s = '\0';
    int fd = open(d, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd >= 0) { fsync(fd); close(fd); }
}

/* Прочитать файл целиком. 1 — прочитан, 0 — его нет, -1 — не прочитать. */
static int ctl_read_file(const char *path, struct cbuf *b, size_t max) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return errno == ENOENT ? 0 : -1;
    char buf[16384];
    ssize_t m;
    b->max = max;
    while ((m = read(fd, buf, sizeof(buf))) > 0) cb_put(b, buf, (size_t)m);
    close(fd);
    if (m < 0 || b->trunc) return -1;
    if (!b->p) cb_put(b, "", 0);
    return 1;
}

/* Поле changed ответа и события applied (docs/ctl.md): что тронула сверка. Набор правил и
 * маршрутизация — по решению apply-сверки (d; NULL — в ядро ничего не шло), помощники и таблица
 * резолвера — по сверке супервизора. */
static void changed_json(struct cbuf *b, const struct recon_diff *d, const struct supd_changes *ch) {
    cb_fmt(b, ",\"changed\":{\"ruleset\":%s,\"routing\":[", d && d->ruleset ? "true" : "false");
    for (size_t i = 0; d && i < d->route_n; i++) {
        if (i) cb_str(b, ",");
        cb_jstr(b, d->route[i]);
    }
    cb_str(b, "],\"helpers\":[");
    for (size_t i = 0; ch && i < ch->helpers_n; i++) {
        if (i) cb_str(b, ",");
        cb_jstr(b, ch->helpers[i]);
    }
    cb_fmt(b, "],\"dnsd\":%s}", ch && ch->dnsd ? "true" : "false");
}

/* Положение выключателя — после apply, reload и SIGHUP (их и зовёт init, включая и выключая
 * движок). Выключенный движок не держит ни одного таймера цикла: ни прохода сторожа, ни снимка
 * status, ни стража правил — демон спит в epoll_wait без срока до запроса по сокету (требование
 * батареи телефона; стенд daemonmatch считает переключения контекста). Включили — всё заводится
 * снова. */
static void srv_set_enabled(struct ctl_srv *s, int on) {
    on = !!on;
    watchd_enable(s->watch, on);
    rulewd_enable(s->rules, on);
    if (s->snap_tm) {
        if (!on) loop_timer_stop(s->snap_tm);
        else if (!s->on || !loop_timer_armed(s->snap_tm)) loop_timer_set(s->snap_tm, CTL_SNAP_MS);
    }
    s->on = on;
}

/* Спека на диске изменилась (apply, reload, SIGHUP) — перечитать её в память и сказать
 * подписчикам. Удалось — супервизор сверяет помощников и таблицу резолвера, событие applied с
 * отпечатком и полем changed; нет — spec-error, а в памяти остаётся прежняя спека: демон
 * продолжает отвечать по последней годной. watch — сторожу внеочередной проход (изменились
 * выходы; помощники — тоже повод, их супервизор называет сам). changed (может быть NULL) — куда
 * дописать поле changed для ответа. */
static void srv_spec_changed(struct ctl_srv *s, const char *by, int enabled,
                             const struct recon_diff *d, int watch, struct cbuf *changed) {
    struct supd_changes ch;
    memset(&ch, 0, sizeof(ch));
    struct cbuf cj = {0};
    /* Правила прежней спеки — до замены в памяти: у правила, которому сменили выход, соединения
     * прежнего выхода снимаются (conns.c, reroute_evict). Только когда в ядро ушёл новый набор
     * правил: без него маршрут соединений не менялся. */
    struct rr_snap *rr = d && d->ruleset && s->d.have ? reroute_snap(s->d.sp) : NULL;
    if (steerd_load(&s->d) == 0) {
        if (rr) reroute_evict(rr, s->d.sp, s->d.gr);
        supd_spec_changed(s->d.sup, &ch, d && d->ruleset);
        changed_json(&cj, d, &ch);
        struct cbuf f = {0};
        cb_fmt(&f, ",\"by\":\"%s\",\"spec\":\"%s\",\"enabled\":%s", by, s->d.fp,
               enabled ? "true" : "false");
        if (cj.p) cb_put(&f, cj.p, cj.n);
        steerd_emit(&s->d, "applied", f.p ? f.p : "");
        free(f.p);
        if (watch || ch.helpers_n) watchd_spec_changed(s->watch);
    } else {
        changed_json(&cj, d, NULL);
        fprintf(stderr, LOG_W "спека не прочитана (%s): %s\n", by, s->d.err);
        char m[2304], f[2560];
        steerd_json_str(m, sizeof(m), s->d.err);
        snprintf(f, sizeof(f), ",\"by\":\"%s\",\"message\":%s", by, m);
        steerd_emit(&s->d, "spec-error", f);
    }
    if (changed && cj.p) cb_put(changed, cj.p, cj.n);
    free(cj.p);
    reroute_snap_free(rr);
    supd_changes_free(&ch);
    /* После watchd_spec_changed: включённый сейчас сторож проходит сразу, а не через успокоение. */
    srv_set_enabled(s, enabled);
}

/* argv проверки кандидата: `apply --dry-run --spec ПУТЬ [--state-dir …]`. */
static void dry_argv(struct conn *c, const char *path, char **av) {
    size_t n = 0;
    av[n++] = c->srv->cf.exe;
    av[n++] = "apply";
    av[n++] = "--dry-run";
    av[n++] = "--spec";
    av[n++] = (char *)path;
    if (c->srv->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)c->srv->cf.state_dir; }
    av[n] = NULL;
}

static void check_done(struct conn *c, int code) {
    struct cbuf none = {0};
    unlink(c->tmp);
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться ядра"); conn_reply(c); return; }
    resp_run(&c->resp, code, &none, &c->job.err);
    if (c->job.timed_out) resp_error(&c->resp, "timeout", "проверка не уложилась в свой срок и остановлена");
    conn_reply(c);
}

/* check — проверить присланную спеку и ничего не менять: для кнопки «Проверить» и для
 * предупреждений до сохранения. Кандидат — во временный файл рядом со спекой и `apply
 * --dry-run` по нему; текст набора правил (stdout) не нужен и не копится, stderr —
 * предупреждения и причина отказа — идёт в ответ.
 *
 * Идёт в очереди изменяющих, хотя спеку не трогает: dry-run не чисто читающий — он раздаёт
 * выходам метки в реестре каталога состояния (registry_assign в cmd_apply), и проверка,
 * идущая одновременно с чужим apply, писала бы реестр посреди его применения. */
static void st_check(struct conn *c) {
    if (ctl_write_tmp(c->srv->cf.spec, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл спеки");
        conn_reply(c);
        return;
    }
    char *av[10];
    dry_argv(c, c->tmp, av);
    if (job_start(c, av, 120, 1, CTL_ERR_MAX, check_done) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить ядро");
        conn_reply(c);
    }
}

static void reload_begin(struct conn *c);

/* ---- apply-сверка: план и применение ----------------------------------------------------------
 *
 * Устройство и доводы — в шапке recon.c. Здесь — шаги на цикле демона: ребёнок `apply-plan`
 * (проверки dry-run и отпечатки частей), решение recon_decide, ребёнок `apply-commit` только с
 * изменившимися частями — или никакого, если меняться нечему. */

/* Ребёнок-план по спеке path; раскладку набора правил, узнанную у прежнего плана, — готовой. */
static int plan_start(struct conn *c, const char *path, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    char *av[12], nb[16];
    size_t n = 0;
    s->plan_at = loop_now_ms();     /* после него устройства раздачи план уже видел (srv_kcheck) */
    av[n++] = s->cf.exe;
    av[n++] = "apply-plan";
    av[n++] = "--spec";
    av[n++] = (char *)path;
    if (s->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)s->cf.state_dir; }
    if (s->rec.nftc >= 0) {
        snprintf(nb, sizeof(nb), "%d", s->rec.nftc);
        av[n++] = "--nftc";
        av[n++] = nb;
    }
    /* Сводка элементов статических наборов ядра — только когда есть с чем её сравнить
     * (recon.c, «СВЕРКА ЭЛЕМЕНТОВ»): дамп больших списков стоит своих миллисекунд. */
    if (s->rec.valid && s->rec.kel_ok) av[n++] = "--kernel-elems";
    av[n] = NULL;
    return job_start(c, av, 120, CTL_OUT_MAX, CTL_ERR_MAX, done);
}

/* План пришёл: разобрать и запомнить его stderr (предупреждения проверки). 0 — годный. */
static int plan_take(struct conn *c) {
    struct job *j = &c->job;
    if (recon_plan_parse(j->out.p ? j->out.p : "", j->out.n, &c->plan) != 0) return -1;
    free(c->perr.p);
    c->perr = j->err;
    memset(&j->err, 0, sizeof(j->err));
    c->srv->rec.nftc = c->plan.nftc;
    c->watch = recon_watch_changed(&c->srv->rec, &c->plan);
    return 0;
}

/* Решить, что применять, и применить: ребёнок apply-commit или сразу done(c, 0), если в ядро
 * идти незачем. */
static void commit_start(struct conn *c, job_done_fn done) {
    struct ctl_srv *s = c->srv;
    /* Снятые снаружи правила выходов — сначала страж, одним сообщением rtnetlink на правило, и
     * только потом решение (srv_rules_busy — доводы): иначе решение, увидев «правила нет»,
     * перепривязало бы выходы ребёнком по одному, а набор правил встал бы только после них. План
     * уже кончился, ребёнок применения ещё не запущен — в ядро наши сейчас не пишут. */
    c->committed = 0;       /* на время проверки стража команда ещё ничего не держит (srv_rules_held) */
    rulewd_settle(s->rules);
    /* Спека в памяти — последняя применённая: по ней сверка знает, как должна стоять
     * маршрутизация выходов, чья подпись не изменилась; память сторожа — какие из них в отказе. */
    recon_decide(&s->rec, &c->plan, s->d.have ? s->d.sp : NULL, s->d.outs, &c->diff);
    /* Расхождение в ядре — сторожу внеочередной проход после применения (recon.c). */
    if (c->diff.watch) c->watch = 1;
    c->committed = 0;
    if (!recon_diff_any(&c->diff)) { done(c, 0); return; }
    char *av[24];
    char *abuf = recon_commit_argv(&c->diff, s->cf.exe, s->cf.spec, s->cf.state_dir, s->rec.nftc, av);
    if (!abuf) { done(c, -1); return; }
    c->committed = 1;
    int jrc = job_start(c, av, 300, CTL_OUT_MAX, CTL_ERR_MAX, done);
    free(abuf);                     /* строки argv нужны до запуска ребёнка — job_start уже вернулся */
    if (jrc != 0) {
        c->committed = 0;
        done(c, -1);
    }
}

/* stdout и stderr применения для ответа: у apply-commit — его; набор правил он собирал сам (и
 * предупреждения проверки повторил), иначе впереди — предупреждения плана. Без apply-commit —
 * строка итога, как у подкоманды. */
static void commit_output(struct conn *c, struct cbuf *out, struct cbuf *err) {
    struct job *j = &c->job;
    memset(out, 0, sizeof(*out));
    memset(err, 0, sizeof(*err));
    out->max = CTL_OUT_MAX;
    err->max = CTL_ERR_MAX;
    /* Ядро сразу после nft -f ребёнка (строка recon-kernel) — для recon_applied, не для ответа. */
    memset(&c->kern, 0, sizeof(c->kern));
    if (c->committed && j->out.p) recon_kernel_take(j->out.p, &j->out.n, &c->kern);
    if (c->committed && j->out.p) cb_put(out, j->out.p, j->out.n);
    if (!c->committed)
        cb_fmt(out, "steer: applied %zu channel(s), %zu output(s)\n", c->plan.ch_n, c->plan.out_n);
    if (!(c->committed && c->diff.ruleset) && c->perr.p) cb_put(err, c->perr.p, c->perr.n);
    if (c->committed && j->err.p) cb_put(err, j->err.p, j->err.n);
}

static void apply_finish(struct conn *c) {
    srv_spec_changed(c->srv, "apply", 1, &c->diff, c->watch, &c->resp);
    conn_reply(c);
}

static void apply_committed(struct conn *c, int code);

/* Шаг 2 apply: план прошёл (проверки те же, что у dry-run). */
static void apply_planned(struct conn *c, int code) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    struct cbuf none = {0};
    /* Тело ложится в тот файл, который спека сейчас (spec.json или spec.yaml): под именем из
     * --spec рядом со spec.yaml легла бы вторая спека, и следующее чтение отказало бы. */
    const char *spec = plat_spec_resolve(s->cf.spec);
    if (code != 0 || j->timed_out) {
        unlink(c->tmp);
        if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться ядра"); conn_reply(c); return; }
        resp_run(&c->resp, code, &none, &j->err);
        resp_bool(&c->resp, "saved", 0);
        resp_bool(&c->resp, "applied", 0);
        if (j->timed_out) resp_error(&c->resp, "timeout", "проверка не уложилась в свой срок и остановлена");
        conn_reply(c);
        return;
    }
    if (plan_take(c) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "план применения не разобран");
        conn_reply(c);
        return;
    }
    free(c->old.p);
    memset(&c->old, 0, sizeof(c->old));
    c->had_old = ctl_read_file(spec, &c->old, 4 * CTL_BODY_MAX);
    if (rename(c->tmp, spec) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось заменить спеку");
        conn_reply(c);
        return;
    }
    ctl_fsync_dir(spec);

    if (!ctl_enabled()) {
        /* Правила снимет и поставит init, когда движок выключат и включат: что будет в ядре
         * потом, демон не знает. */
        recon_forget(&s->rec);
        recon_diff_free(&c->diff);
        resp_run(&c->resp, 0, &none, &c->perr);
        resp_bool(&c->resp, "saved", 1);
        resp_bool(&c->resp, "applied", 0);
        resp_bool(&c->resp, "enabled", 0);
        srv_spec_changed(s, "apply", 0, &c->diff, c->watch, &c->resp);
        conn_reply(c);
        return;
    }
    commit_start(c, apply_committed);
}

/* Шаг 3 apply: ядро приняло изменившиеся части — или нет, и тогда прежняя спека возвращается на
 * место. */
static void apply_committed(struct conn *c, int code) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    const char *spec = plat_spec_resolve(s->cf.spec);  /* тот же файл, что в apply_planned */
    struct cbuf out, err;
    commit_output(c, &out, &err);
    if (code != 0 || (c->committed && j->timed_out)) {
        /* Что успело встать до отказа, не знаем (ядро отвергло набор — ничего, срок вышел посреди
         * маршрутизации — часть): следующий apply применит всё. */
        recon_forget(&s->rec);
        int rolled = 0;
        if (c->had_old == 1) {
            char t2[PATH_MAX];
            if (ctl_write_tmp(spec, c->old.p, c->old.n, t2, sizeof(t2)) == 0) {
                if (rename(t2, spec) == 0) rolled = 1;
                else unlink(t2);
            }
        } else if (c->had_old == 0) {
            rolled = unlink(spec) == 0;
        }
        if (rolled) ctl_fsync_dir(spec);
        else cb_str(&err, LOG_W "прежнюю спеку вернуть не удалось — на диске новая\n");
        fprintf(stderr, LOG_W "apply отвергнут (код %d)%s\n", code,
                rolled ? " — прежняя спека возвращена" : "");
        resp_run(&c->resp, code < 0 ? 127 : code, &out, &err);
        resp_bool(&c->resp, "saved", !rolled);
        resp_bool(&c->resp, "applied", 0);
        resp_bool(&c->resp, "enabled", 1);
        resp_bool(&c->resp, "rolled_back", rolled);
        if (c->committed && j->timed_out)
            resp_error(&c->resp, "timeout", "применение не уложилось в свой срок и остановлено");
        /* Вернуть не удалось — на диске новая спека, и память идёт за диском (молча: в ядре
         * она не стоит, события applied нет). */
        if (!rolled) steerd_load(&s->d);
        free(out.p);
        free(err.p);
        conn_reply(c);
        return;
    }
    recon_applied(&s->rec, &c->plan, &c->diff, &c->kern);
    fprintf(stderr, LOG_I "спека применена%s\n", c->committed ? "" : " (в ядре менять нечего)");
    resp_run(&c->resp, 0, &out, &err);
    free(out.p);
    free(err.p);
    resp_bool(&c->resp, "saved", 1);
    resp_bool(&c->resp, "applied", 1);
    resp_bool(&c->resp, "enabled", 1);
    /* Что изменили хуки плагинов при подготовке спеки (pre_apply, expand): отчёт шага
     * подготовки (model/plugprep.c) — поле plugins. Нет хуков, нет и поля. */
    {
        char *rep = NULL;
        if (spec_prepare_report(spec, &rep) == 0) {
            size_t rl = strlen(rep);
            while (rl && (rep[rl - 1] == '\n' || rep[rl - 1] == ' ')) rep[--rl] = '\0';
            cb_str(&c->resp, ",\"plugins\":");      /* отчёт любой длины: cb_fmt режет на 1 КиБ */
            cb_str(&c->resp, rep);
            free(rep);
        }
    }
    c->after_reload = apply_finish;
    reload_begin(c);
}

/* apply — приложение присылает спеку ЦЕЛИКОМ; демон проверяет её, атомарно кладёт на место и
 * применяет то, что в ней изменилось. Порядок и доводы:
 *
 *   1. Очередь изменяющих команд (см. «ИСПОЛНЕНИЕ» в шапке).
 *   2. Кандидат — во временный файл рядом со спекой и `apply-plan` по нему: те же проверки, что
 *      у `apply --dry-run`, и отпечатки частей (набор правил, маршрутизация выходов). Отказ —
 *      временный файл удаляется, spec.json не тронут; в ответе код и stderr проверки,
 *      "saved":false.
 *   3. Прежняя спека читается в память — на случай отката в п. 5 — и кандидат становится
 *      spec.json переименованием: снаружи виден либо прежний файл, либо новый целиком.
 *   4. Движок выключен — на этом всё: "saved":true, "applied":false, "enabled":false.
 *      Правила поставит init, когда движок включат (см. ctl_enabled).
 *   5. Сверка с применённым (recon.c): изменившиеся части — `apply-commit` (набор правил одной
 *      транзакцией, привязка изменившихся выходов, снятие правил убранных); не изменилось ничего
 *      — в ядро демон не идёт вовсе. Отказ (ядро не приняло набор — план ядро не спрашивает) —
 *      прежняя спека возвращается на место, и в ядре, и на диске остаётся то, что было: иначе
 *      init повторял бы отвергнутую спеку на каждой загрузке и перезапуске netd.
 *      "saved":false, "rolled_back":true.
 *   6. Успех — перечитать спеку резолвером и супервизором (как reload), "reload" в ответе.
 *
 * После п. 4 и п. 6 демон перечитывает спеку в память и шлёт подписчикам applied; в ответе и в
 * событии — поле changed. */
static void st_apply(struct conn *c) {
    if (ctl_write_tmp(c->srv->cf.spec, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл спеки");
        conn_reply(c);
        return;
    }
    if (plan_start(c, c->tmp, apply_planned) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить ядро");
        conn_reply(c);
    }
}

/* ---- reload ------------------------------------------------------------------------------ */

/* Процессы этого же движка с подкомандой sub: /proc/<pid>/exe совпадает с нашим, а второе
 * слово командной строки — sub. Искать по исполняемому файлу, а не по имени процесса:
 * имя подделать может любой, а на телефоне к тому же SELinux пускает steerd читать /proc
 * только своего домена (r_dir_file(domain, self)) — чужие процессы здесь не видны вовсе.
 * pid-файлов резолвер и супервизор не пишут, а заводить их ради этого — ещё одна вещь,
 * способная устареть (процесс умер, файл остался, сигнал ушёл чужому pid). */
static int ctl_find(const char *exe, const char *sub, pid_t *out, int max) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    int n = 0;
    pid_t me = getpid();
    struct dirent *e;
    while ((e = readdir(d)) && n < max) {
        char *end = NULL;
        long p = strtol(e->d_name, &end, 10);
        if (!end || *end || p <= 0 || p == me) continue;
        char path[64], link[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%ld/exe", p);
        ssize_t l = readlink(path, link, sizeof(link) - 1);
        if (l <= 0) continue;
        link[l] = '\0';
        if (strcmp(link, exe) != 0) continue;
        snprintf(path, sizeof(path), "/proc/%ld/cmdline", p);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) continue;
        char cl[256];
        ssize_t m = read(fd, cl, sizeof(cl) - 1);
        close(fd);
        if (m <= 0) continue;
        cl[m] = '\0';
        size_t a0 = strlen(cl);
        if ((ssize_t)a0 + 1 >= m) continue;
        if (strcmp(cl + a0 + 1, sub) != 0) continue;
        out[n++] = (pid_t)p;
    }
    closedir(d);
    return n;
}

static void ctl_rstrip(struct cbuf *b) {
    while (b->n && (b->p[b->n - 1] == '\n' || b->p[b->n - 1] == '\r')) b->p[--b->n] = '\0';
}

/* Перечитать спеку резолвером и супервизором помощников — поле "reload" ответа.
 *
 * РЕЗОЛВЕР — тем же решением, что init-скрипт роутера (files/etc/init.d/steer, reload_dnsd):
 * подпись таблицы каналов по новой спеке (`steer dnsd-sig`, ребёнком) сравнивается с той, что
 * резолвер положил в dnsd.sig при запуске. Совпали — SIGHUP: списки перечитываются без потери
 * запросов. Разошлись или подписи нет — SIGTERM: состав каналов HUP не пересобирает, а init
 * поднимает вышедший сервис заново (он не oneshot). "hup" | "restart" | "none" (не запущен).
 *
 * СУПЕРВИЗОР — SIGHUP: сверить состав помощников со спекой; помощник выхода, у которого
 * изменились параметры, перезапускается им же (см. cmd_supervise). "hup" | "none".
 *
 * Кончив, зовёт c->after_reload. */
static void reload_finish(struct conn *c, const char *dn) {
    pid_t pids[8];
    const char *sv = "none";
    int k = ctl_find(c->srv->cf.exe, "supervise", pids, 8);
    for (int i = 0; i < k; i++) kill(pids[i], SIGHUP);
    if (k > 0) sv = "hup";
    cb_fmt(&c->resp, ",\"reload\":{\"dnsd\":\"%s\",\"outputs\":\"%s\"}", dn, sv);
    c->after_reload(c);
}

static void reload_sig(struct conn *c, int code) {
    struct job *j = &c->job;
    struct cbuf run = {0};
    char sp[PATH_MAX];
    snprintf(sp, sizeof(sp), "%s/dnsd.sig", ctl_state_dir(&c->srv->cf));
    int have = ctl_read_file(sp, &run, CTL_OUT_MAX) == 1;
    ctl_rstrip(&j->out);
    ctl_rstrip(&run);
    int same = code == 0 && !j->timed_out && have && run.n && j->out.n == run.n &&
               !memcmp(j->out.p, run.p, run.n);
    for (int i = 0; i < c->dn_n; i++) kill(c->dn[i], same ? SIGHUP : SIGTERM);
    free(run.p);
    reload_finish(c, same ? "hup" : "restart");
}

static void reload_begin(struct conn *c) {
    struct ctl_srv *s = c->srv;
    /* --supervise: резолвер и помощники — дети демона, и искать их по /proc незачем (а сигнал
     * резолверу на таблице был бы ошибкой: dnsd.sig он не пишет, и сверка подписей всегда
     * давала бы TERM). Новую таблицу и сверку помощников делает supd_spec_changed, когда демон
     * перечитает спеку (after_reload → srv_spec_changed). */
    if (s->d.sup) {
        cb_str(&c->resp, ",\"reload\":{\"dnsd\":\"table\",\"outputs\":\"daemon\"}");
        c->after_reload(c);
        return;
    }
    c->dn_n = ctl_find(s->cf.exe, "dnsd", c->dn, 8);
    if (c->dn_n <= 0) { reload_finish(c, "none"); return; }
    char *av[8];
    size_t n = 0;
    av[n++] = s->cf.exe;
    av[n++] = "dnsd-sig";
    av[n++] = "--spec";
    av[n++] = (char *)s->cf.spec;
    if (s->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)s->cf.state_dir; }
    av[n] = NULL;
    if (job_start(c, av, 30, CTL_OUT_MAX, CTL_ERR_MAX, reload_sig) != 0) {
        memset(&c->job.out, 0, sizeof(c->job.out));
        reload_sig(c, -1);
    }
}

static void reload_done(struct conn *c) {
    /* Починка по сверке прохода сторожа — событие applied с by: watch (docs/ctl.md): интерфейс
     * отличает её от reload, который позвал человек или init. */
    srv_spec_changed(c->srv, c->resync ? "watch" : "reload", ctl_enabled(), &c->diff, c->watch,
                     &c->resp);
    /* Стартовое применение кончилось — удачно или нет: теперь первый проход сторожа (см.
     * «ПЕРВЫЙ ПРОХОД — ПОСЛЕ СТАРТОВОГО APPLY» в watchd.c). */
    if (c->boot) watchd_release(c->srv->watch);
    struct ctl_srv *s = c->srv;
    int resync = c->resync;
    conn_reply(c);
    /* Устройство раздачи пересоздали, пока шла эта сверка (её план мог собраться ещё без него), —
     * ещё одна, сразу (srv_lan). */
    if (resync && s->lan_again && s->lan_tm) {
        s->lan_again = 0;
        loop_timer_set(s->lan_tm, 0);
    }
}

/* Голова ответа reload: код (не 0 — ядро не приняло набор или план не прошёл, причина в
 * stderr), выключатель. Дальше — прежние шаги reload. */
static void reload_head(struct conn *c, int enabled, struct cbuf *err) {
    if (c->boot) {
        if (c->rcode != 0)
            fprintf(stderr, LOG_W "применение при старте не прошло (код %d)%s%.*s", c->rcode,
                    err && err->n ? ":\n" : "\n", err ? (int)err->n : 0,
                    err && err->p ? err->p : "");
        else if (enabled)
            fprintf(stderr, LOG_I "спека применена при старте\n");
    }
    if (c->resync) {
        if (c->rcode != 0)
            fprintf(stderr, LOG_W "набор правил вернуть не удалось (код %d)%s%.*s", c->rcode,
                    err && err->n ? ":\n" : "\n", err ? (int)err->n : 0,
                    err && err->p ? err->p : "");
        else if (enabled)
            fprintf(stderr, LOG_I "набор правил сверен с ядром %s%s\n",
                    c->resync == RESYNC_LAN ? "по новому устройству раздачи" : "проходом сторожа",
                    c->diff.ruleset ? " — поставлен заново" : " — менять уже нечего");
    }
    cb_fmt(&c->resp, ",\"code\":%d", c->rcode);
    if (c->rcode != 0) {
        cb_utf8_trim(err);
        cb_str(&c->resp, ",\"stderr\":");
        cb_json(&c->resp, err->p ? err->p : "", err->n);
    }
    resp_bool(&c->resp, "enabled", enabled);
    c->after_reload = reload_done;
    reload_begin(c);
}

static void reload_committed(struct conn *c, int code) {
    struct cbuf out, err;
    commit_output(c, &out, &err);
    if (code != 0 || (c->committed && c->job.timed_out)) {
        /* Спеки на откат у reload нет: на диске она та же. Ядро отвергло набор — прежний стоит;
         * что успело встать до срока — не знаем. Остальное reload делает, как прежде. */
        recon_forget(&c->srv->rec);
        c->rcode = code < 0 ? 127 : code;
        recon_diff_free(&c->diff);
        fprintf(stderr, LOG_W "reload: применение не прошло (код %d)\n", code);
    } else {
        recon_applied(&c->srv->rec, &c->plan, &c->diff, &c->kern);
    }
    free(out.p);
    reload_head(c, 1, &err);
    free(err.p);
}

static void reload_planned(struct conn *c, int code) {
    struct job *j = &c->job;
    if (code != 0 || j->timed_out || plan_take(c) != 0) {
        /* Спека не проходит проверку (или план не разобран): в ядро не идём, остальное — как
         * прежде (перечитывание само скажет spec-error, если спека не читается). */
        c->rcode = code > 0 ? code : 127;
        c->watch = 1;
        recon_diff_free(&c->diff);
        reload_head(c, 1, &j->err);
        return;
    }
    commit_start(c, reload_committed);
}

/* reload — то же, что apply, без новой спеки: сверка той, что на диске, с применённой (набор
 * правил, маршрутизация, помощники, таблица резолвера — только изменившееся), и перечитывание.
 * Движок выключен — в ядро не идём. */
static void st_reload(struct conn *c) {
    c->rcode = 0;
    if (!ctl_enabled()) {
        recon_forget(&c->srv->rec);
        c->watch = 1;
        recon_diff_free(&c->diff);
        reload_head(c, 0, NULL);
        return;
    }
    if (plan_start(c, c->srv->cf.spec, reload_planned) != 0) {
        struct cbuf e = {0};
        cb_str(&e, LOG_W "не удалось запустить ядро\n");
        c->rcode = 127;
        c->watch = 1;
        recon_diff_free(&c->diff);
        reload_head(c, 1, &e);
        free(e.p);
    }
}

/* ---- файлы списков: put-file, list-files, rm-file --------------------------------------------
 *
 * ЗАЧЕМ. Спека ссылается на файлы — списки доменов и подсетей (domains_files, prefixes_files),
 * файл подписки выхода VLESS, — и движок читает их сам, по путям из спеки. На роутере их
 * кладёт в /etc/steer управляющий слой splify2 (rpcd), на телефоне так нельзя: приложение
 * splify2 в каталог движка писать не может (SELinux: steerd_data_file ему закрыт целиком, см.
 * neverallow в vendor/der/sepolicy/private/steerd.te), и открывать его значило бы открыть и
 * спеку, и состояние. Поэтому файлы идут через ту же дверь, что спека: приложение скачивает
 * список, присылает его телом put-file, сервер кладёт его в lists_dir платформы, а в спеку
 * приложение пишет путь, который вернул ответ.
 *
 * Разбор спеки этим не ограничен: спека с путями ВНЕ каталога списков по-прежнему законна
 * (adb root shell, стенд, файлы, положенные руками). Каталог — место, куда может писать
 * приложение, а не единственное место, откуда может читать движок.
 *
 * АТОМАРНОСТЬ. Файл пишется во временный рядом (.put-XXXXXX в том же каталоге: rename атомарен
 * только внутри одной файловой системы), с fsync, и становится <имя> переименованием. Резолвер
 * перечитывает списки по SIGHUP в любой момент, apply читает их при применении, — и оба видят
 * либо прежний файл целиком, либо новый целиком, но не обрубок на середине записи. Имя
 * временного файла начинается с точки, а имя от приложения точкой начинаться не может
 * (CA_FILE): совпасть им негде, и list-files точечные имена не показывает. Временный файл,
 * оставшийся от демона, убитого посреди записи, убирает он же при старте (ctl_lists_sweep) —
 * в это время ни одной записи ещё не идёт, и убрать чужой живой файл нельзя.
 *
 * Очередь изменяющих команд put-file не ждёт: замена файла атомарна, и apply, идущий рядом,
 * прочтёт прежний или новый — то же, что при записи до или после него. rm-file идёт в ней:
 * он сверяется с сохранённой спекой, и сверка имеет смысл, только пока спеку никто не
 * меняет (см. ctl_do_rm_file). */

/* Сколько файлов и байт в каталоге списков, не считая временных и файла skip (его put-file
 * сейчас заменит, и его прежний размер в итог не входит). */
static void ctl_lists_usage(const char *dir, const char *skip, int *files, long long *bytes) {
    *files = 0;
    *bytes = 0;
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d))) {
        if (e->d_name[0] == '.' || (skip && !strcmp(e->d_name, skip))) continue;
        struct stat sb;
        if (fstatat(dirfd(d), e->d_name, &sb, AT_SYMLINK_NOFOLLOW) != 0 || !S_ISREG(sb.st_mode))
            continue;
        (*files)++;
        *bytes += (long long)sb.st_size;
    }
    closedir(d);
}

/* Убрать временные файлы put-file, брошенные убитым обработчиком. Только при старте сервера. */
static void ctl_lists_sweep(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return;
    struct dirent *e;
    while ((e = readdir(d)))
        if (!strncmp(e->d_name, ".put-", 5)) unlinkat(dirfd(d), e->d_name, 0);
    closedir(d);
}

/* put-file <имя> <длина> + тело — положить файл в каталог списков.
 * Ответ: "code":0, "name", "size" (байт) и "path" — полный путь, который пишется в спеку. */
static void ctl_do_put_file(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *dir = q->cf->lists_dir, *name = q->argv[0];
    /* Каталог — при первом put, 0700: владелец движок, остальным (и shell) в нём делать нечего,
     * как в state и tmp. Родитель (каталог спеки) создан init-ом. */
    if (mkdir(dir, 0700) != 0 && errno != EEXIST) {
        resp_error(r, "internal", "не удалось создать каталог списков");
        return;
    }
    struct stat sb;
    if (stat(dir, &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        resp_error(r, "internal", "каталог списков — не каталог");
        return;
    }
    int files;
    long long bytes;
    ctl_lists_usage(dir, name, &files, &bytes);
    if (files >= CTL_FILES_MAX) {
        char why[256];
        snprintf(why, sizeof(why), "в каталоге списков уже %d файлов — предел от бесконечной заливки; "
                 "уберите ненужные (rm-file)", CTL_FILES_MAX);
        resp_error(r, "too-large", why);
        return;
    }
    if (bytes + (long long)q->body_n > CTL_FILES_TOTAL) {
        resp_error(r, "too-large", "файлы списков заняли бы больше 128 МиБ — уберите ненужные (rm-file)");
        return;
    }
    char path[PATH_MAX], tmp[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, name) >= sizeof(path) ||
        (size_t)snprintf(tmp, sizeof(tmp), "%s/.put-XXXXXX", dir) >= sizeof(tmp)) {
        resp_error(r, "internal", "слишком длинный путь каталога списков");
        return;
    }
    int fd = mkostemp(tmp, O_CLOEXEC);          /* создаётся с правами 0600 */
    if (fd < 0) {
        resp_error(r, "internal", "не удалось создать временный файл в каталоге списков");
        return;
    }
    int ok = ctl_write_all(fd, q->body, q->body_n) == 0 && fsync(fd) == 0;
    if (close(fd) != 0) ok = 0;
    if (!ok || rename(tmp, path) != 0) {
        unlink(tmp);
        resp_error(r, "internal", "не удалось записать файл (нет места?)");
        return;
    }
    ctl_fsync_dir(path);
    fprintf(stderr, LOG_I "положен файл %s (%zu байт)\n", name, q->body_n);
    cb_fmt(r, ",\"code\":0,\"name\":");
    cb_jstr(r, name);
    cb_fmt(r, ",\"size\":%zu,\"path\":", q->body_n);
    cb_jstr(r, path);
}

static int ctl_name_cmp(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}

/* list-files — что лежит в каталоге списков: "files":[{"name","size","mtime"}], по имени.
 * mtime — секунды Unix (время последнего put-file этого имени). Каталога ещё нет — пустой
 * список: для приложения это то же самое, что «ничего не залито». */
static void ctl_do_list_files(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *dir = q->cf->lists_dir;
    cb_str(r, ",\"code\":0,\"dir\":");
    cb_jstr(r, dir);
    cb_str(r, ",\"files\":[");
    DIR *d = opendir(dir);
    char **names = NULL;                    /* по числу файлов в каталоге */
    size_t n = 0, ncap = 0;
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            if (n == ncap) {
                size_t nc = ncap ? ncap * 2 : 64;
                char **nn = realloc(names, nc * sizeof(*nn));
                if (!nn) break;
                names = nn;
                ncap = nc;
            }
            names[n] = strdup(e->d_name);
            if (names[n]) n++;
        }
    }
    if (n) qsort(names, n, sizeof(names[0]), ctl_name_cmp);
    int first = 1;
    for (size_t i = 0; i < n; i++) {
        struct stat sb;
        if (fstatat(dirfd(d), names[i], &sb, AT_SYMLINK_NOFOLLOW) == 0 && S_ISREG(sb.st_mode)) {
            cb_str(r, first ? "{\"name\":" : ",{\"name\":");
            cb_jstr(r, names[i]);
            cb_fmt(r, ",\"size\":%lld,\"mtime\":%lld}", (long long)sb.st_size,
                   (long long)sb.st_mtime);
            first = 0;
        }
        free(names[i]);
    }
    free(names);
    if (d) closedir(d);
    cb_str(r, "]");
}

/* Упомянут ли путь в тексте спеки — строкой JSON, как его пишет приложение ("…/lists/имя"),
 * или с экранированными косыми ("…\/lists\/имя": так пишут некоторые сериализаторы JSON). */
/* Упоминает ли спека файл path. Спека разбирается тем же ynode, что читает её ядро (YAML и JSON), и
 * путь сверяется с КАЖДЫМ скаляром: прежде путь искался текстом только в двойных кавычках, а в YAML
 * путь пишется без них — и rm-file удалял файл, на который спека ссылается. Относительный путь спеки
 * v2 считается от её каталога (docs/spec-v2.md), так и сверяется. Спека не разобралась — поиск
 * текстом, и без кавычек тоже: лишний отказ «in-use» дешевле пропавшего файла списка. */
static int ynode_mentions(const struct ynode *n, const char *path, const char *dir) {
    if (!n) return 0;
    if (n->kind == YN_SCALAR) {
        if (!n->str) return 0;
        if (!strcmp(n->str, path)) return 1;
        if (n->str[0] != '/' && dir[0]) {
            char full[PATH_MAX];
            if ((size_t)snprintf(full, sizeof(full), "%s/%s", dir, n->str) < sizeof(full) && !strcmp(full, path))
                return 1;
        }
        return 0;
    }
    size_t cnt = n->kind == YN_MAP ? 2 * n->len : n->len;
    for (size_t i = 0; i < cnt; i++)
        if (ynode_mentions(n->items[i], path, dir)) return 1;
    return 0;
}

static int ctl_spec_mentions(const struct cbuf *spec, const char *path, const char *spec_path) {
    if (!spec->p) return 0;
    char dir[PATH_MAX] = "";
    const char *sl = spec_path ? strrchr(spec_path, '/') : NULL;
    if (sl && (size_t)(sl - spec_path) < sizeof(dir)) snprintf(dir, sizeof(dir), "%.*s", (int)(sl - spec_path), spec_path);
    struct err e = { { 0 } };
    struct ydoc *d = ydoc_parse_buf(spec->p, strlen(spec->p), "spec", &e);
    if (d) {
        int m = ynode_mentions(ydoc_root(d), path, dir);
        ydoc_free(d);
        return m;
    }
    return strstr(spec->p, path) != NULL;
}

/* rm-file <имя> — убрать файл из каталога списков. Ответ: "code":0, "name", "removed" (false —
 * такого файла и не было: повторное удаление не ошибка, приложению незачем помнить, что оно
 * уже убрало).
 *
 * ФАЙЛ, НА КОТОРЫЙ ССЫЛАЕТСЯ СОХРАНЁННАЯ СПЕКА, НЕ УДАЛЯЕТСЯ — отказ "in-use". Цена ошибки
 * порядка («сначала убрать файл, потом применить спеку без него» вместо обратного, или apply,
 * который не прошёл и вернул прежнюю спеку) — движок, который перестаёт подниматься: init
 * применяет сохранённую спеку на каждой загрузке и после каждого перезапуска netd, а спека с
 * пропавшим файлом списка к применению уже не годится, и резолвер перестаёт узнавать имена
 * канала. Команда идёт в очереди изменяющих: пока она исполняется, apply ждёт, и «не упомянут»
 * остаётся правдой до самого unlink. */
static void ctl_do_rm_file(struct conn *c, struct cbuf *r) {
    const struct ctl_req *q = &c->q;
    const char *name = q->argv[0];
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", q->cf->lists_dir, name) >= sizeof(path)) {
        resp_error(r, "internal", "слишком длинный путь каталога списков");
        return;
    }
    struct cbuf spec = {0};
    const char *spec_path = plat_spec_resolve(q->cf->spec);
    int have = ctl_read_file(spec_path, &spec, 4 * CTL_BODY_MAX);
    if (have < 0) {
        resp_error(r, "internal", "не удалось прочитать сохранённую спеку");
    } else if (have == 1 && ctl_spec_mentions(&spec, path, spec_path)) {
        resp_error(r, "in-use", "файл упомянут в сохранённой спеке — сначала примените спеку без него");
    } else {
        int removed = unlink(path) == 0;
        if (!removed && errno != ENOENT) {
            resp_error(r, "internal", "не удалось удалить файл");
        } else {
            if (removed) {
                ctl_fsync_dir(path);
                fprintf(stderr, LOG_I "убран файл %s\n", name);
            }
            cb_str(r, ",\"code\":0,\"name\":");
            cb_jstr(r, name);
            resp_bool(r, "removed", removed);
        }
    }
    free(spec.p);
}

/* ---- команды плагинов (steer-api.md, 4.3) --------------------------------------------------------- */

/* Строка таблицы для подкоманды плагина name из манифеста. 0 — есть; -1 — такой подкоманды с ctl нет
 * или слов у неё больше, чем держит строка таблицы (args). */
static int plugin_ctl_cmd(const char *name, struct ctl_cmd *k) {
    const struct plugin_cmd *pc = plugin_cmd_find(name);
    if (!pc || !pc->ctl || pc->ctl_args_n > sizeof(k->args) / sizeof(k->args[0])) return -1;
    memset(k, 0, sizeof(*k));
    k->name = pc->name;
    k->sub = pc->name;
    k->start = pc->ctl_body_max ? st_plugcmd_body : NULL;
    k->body = pc->ctl_body_max;
    k->argmax = (int)pc->ctl_args_n;
    k->argmin = k->argmax - pc->ctl_optional < 0 ? 0 : k->argmax - pc->ctl_optional;
    for (size_t i = 0; i < pc->ctl_args_n; i++) {
        const struct plugin_ctl_arg *a = &pc->ctl_args[i];
        struct ctl_arg *t = &k->args[i];
        t->kind = !strcmp(a->kind, "name") ? CA_NAME : !strcmp(a->kind, "int") ? CA_INT :
                  !strcmp(a->kind, "target") ? CA_TARGET : !strcmp(a->kind, "file") ? CA_FILE : CA_WORD;
        t->flag = a->flag;
        t->lo = a->lo;
        t->hi = a->hi;
    }
    k->timeout_s = pc->ctl_timeout_s > 0 ? pc->ctl_timeout_s : 60;
    k->spec = pc->conf;
    k->lock = pc->ctl_lock;
    return 0;
}

static void plugcmd_body_done(struct conn *c, int code) {
    unlink(c->tmp);
    if (code < 0) { resp_error(&c->resp, "internal", "не удалось дождаться ядра"); conn_reply(c); return; }
    resp_run(&c->resp, code, &c->job.out, &c->job.err);
    if (c->job.timed_out) resp_error(&c->resp, "timeout", "команда не уложилась в свой срок и остановлена");
    conn_reply(c);
}

/* Команда плагина с телом (ctl.body: file): тело — во временный файл каталога времянок движка, его путь
 * (абсолютный) — последним словом подкоманды; файл удаляется, когда она кончится. Так `sub-check`
 * плагина vless разбирает присланную подписку, ничего не сохраняя. */
static void st_plugcmd_body(struct conn *c) {
    char stem[PATH_MAX];
    snprintf(stem, sizeof stem, "%s/%s", plat()->tmp_dir, c->q.cmd->name);
    if (ctl_write_tmp(stem, c->q.body, c->q.body_n, c->tmp, sizeof(c->tmp)) != 0) {
        resp_error(&c->resp, "internal", "не удалось записать временный файл тела");
        conn_reply(c);
        return;
    }
    char *av[20];
    size_t n = ctl_argv(&c->q, c->q.cmd->sub, av, sizeof(av) / sizeof(av[0]) - 1);
    /* Путь тела — после слов, до --spec (ctl_argv кладёт его последним). */
    size_t at = n;
    for (size_t i = 2; i < n; i++) if (!strcmp(av[i], "--spec")) { at = i; break; }
    memmove(&av[at + 1], &av[at], (n - at + 1) * sizeof(*av));
    av[at] = c->tmp;
    if (job_start(c, av, c->q.cmd->timeout_s, CTL_OUT_MAX, CTL_ERR_MAX, plugcmd_body_done) != 0) {
        unlink(c->tmp);
        resp_error(&c->resp, "internal", "не удалось запустить ядро");
        conn_reply(c);
    }
}

/* ---- subscribe ------------------------------------------------------------------------------
 *
 * Подписчик — соединение, которое после ответа не закрывается: демон дописывает в него
 * события (steerd_emit, state.h), строка JSON на событие. Ответ на сам subscribe — обычная
 * строка {"v":1,"cmd":"subscribe","code":0,"spec":"<отпечаток>"}: с чем подписчик начинает.
 *
 * Очередь событий — тот же буфер, что у ответа, с пределом CTL_SUBQ_MAX: запись неблокирующая,
 * что сокет не принял, ждёт EPOLLOUT; событие, которое не влезло бы, отключает подписчика
 * (см. CTL_SUBQ_MAX). Что подписчик пишет после subscribe, демон читает и выбрасывает; конец
 * его записи (shutdown) — не уход: `steer ctl subscribe` полузакрывает запись сразу после
 * запроса и ждёт событий. Уход — это EPOLLHUP или ошибка записи. */
static void sub_push(struct steerd_sub *sb, const char *line, size_t n) {
    struct conn *c = sb->arg;
    size_t pending = c->resp.n - c->off;
    if (pending + n > CTL_SUBQ_MAX) {
        fprintf(stderr, LOG_W "подписчик не забирает события (в очереди %zu байт) — отключён\n",
                pending);
        conn_free(c);
        return;
    }
    if (c->off) {
        memmove(c->resp.p, c->resp.p + c->off, pending);
        c->resp.n = pending;
        c->off = 0;
    }
    cb_put(&c->resp, line, n);
    conn_flush(c);
}

static void st_subscribe(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (c->counted) { c->counted = 0; s->active--; }
    s->subs++;
    c->st = C_SUB;
    loop_timer_stop(c->tm);
    int sb = CTL_SUB_SNDBUF;
    setsockopt(c->fd, SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));
    cb_str(&c->resp, ",\"code\":0");
    if (s->d.have) cb_fmt(&c->resp, ",\"spec\":\"%s\"", s->d.fp);
    cb_str(&c->resp, "}\n");
    c->off = 0;
    c->sub.push = sub_push;
    c->sub.arg = c;
    steerd_sub_add(&s->d, &c->sub);
    conn_flush(c);
}

/* ---- менеджер плагинов ---------------------------------------------------------------------------
 *
 * Команды plugin-* — дети `steerd plugin <действие> … --json` (src/pluginmgr/pmmain.c): ответ — их код,
 * stdout (объект JSON) и stderr (ход). Тело, если есть, — во временный файл каталога состояния, путь —
 * флагом (--file, --key-file); у plugin-ensure тело — id плагинов, они идут словами. */

/* Реестр плагинов ядра (src/kinds/plugin.c): слабо — в сборке без него plugin-reload просто
 * перечитывает спеку. */
int plugin_reload(const char *root) __attribute__((weak));

static void plugin_done(struct conn *c, int code) {
    if (c->tmp[0]) { unlink(c->tmp); c->tmp[0] = '\0'; }
    sub_done(c, code);
}

static int plugin_id_ok(const char *w, size_t n) {
    if (!n || n > 64 || !((w[0] >= 'a' && w[0] <= 'z') || (w[0] >= '0' && w[0] <= '9'))) return 0;
    for (size_t i = 0; i < n; i++)
        if (!((w[i] >= 'a' && w[i] <= 'z') || (w[i] >= '0' && w[i] <= '9') || w[i] == '-')) return 0;
    return 1;
}

static void st_plugin(struct conn *c) {
    const struct ctl_req *q = &c->q;
    const char *name = q->cmd->name;
    c->tmp[0] = '\0';
    /* Слова тела plugin-ensure — сколько угодно; argv — в куче по их числу. */
    size_t nwords = 0;
    if (!strcmp(name, "plugin-ensure")) {
        for (size_t i = 0; i < q->body_n; ) {
            while (i < q->body_n && (q->body[i] == ' ' || q->body[i] == '\n' || q->body[i] == '\t' || q->body[i] == '\r')) i++;
            size_t st = i;
            while (i < q->body_n && !(q->body[i] == ' ' || q->body[i] == '\n' || q->body[i] == '\t' || q->body[i] == '\r')) i++;
            if (i == st) continue;
            if (!plugin_id_ok(q->body + st, i - st)) {
                resp_error(&c->resp, "bad-request", "недопустимое имя плагина в теле");
                conn_reply(c);
                return;
            }
            nwords++;
        }
        if (!nwords) { resp_error(&c->resp, "bad-request", "тело — id плагинов через пробел"); conn_reply(c); return; }
    }
    size_t cap = nwords + 16;
    char **av = calloc(cap, sizeof(char *));
    char *words = NULL;
    if (!av) { resp_error(&c->resp, "internal", "нет памяти"); conn_reply(c); return; }
    size_t n = 0;
    av[n++] = (char *)q->cf->exe;
    av[n++] = "plugin";
    char sub[32];
    snprintf(sub, sizeof(sub), "%s", q->cmd->sub);
    char *sp = strchr(sub, ' ');
    if (sp) { *sp = '\0'; av[n++] = sub; av[n++] = sp + 1; }
    else av[n++] = sub;
    for (int i = 0; i < q->argc; i++) {
        const struct ctl_arg *a = &q->cmd->args[i];
        if (a->flag) av[n++] = (char *)a->flag;
        if (a->kind != CA_LIT || !a->flag) av[n++] = (char *)q->argv[i];
    }
    if (nwords) {
        words = malloc(q->body_n + 1);
        if (!words) { free(av); resp_error(&c->resp, "internal", "нет памяти"); conn_reply(c); return; }
        memcpy(words, q->body, q->body_n);
        words[q->body_n] = '\0';
        for (char *t = strtok(words, " \t\r\n"); t; t = strtok(NULL, " \t\r\n")) av[n++] = t;
    } else if (q->cmd->body) {
        const char *flag = !strcmp(name, "plugin-repo-add") ? "--key-file" : "--file";
        char final[PATH_MAX];
        snprintf(final, sizeof(final), "%s/plugin-%s", ctl_state_dir(q->cf),
                 !strcmp(name, "plugin-repo-add") ? "key.pub" : "upload.s2p");
        if (ctl_write_tmp(final, q->body ? q->body : "", q->body_n, c->tmp, sizeof(c->tmp)) != 0) {
            free(av);
            c->tmp[0] = '\0';
            resp_error(&c->resp, "internal", "не записать тело во временный файл");
            conn_reply(c);
            return;
        }
        av[n++] = (char *)flag;
        av[n++] = c->tmp;
    }
    av[n++] = "--json";
    av[n] = NULL;
    int rc = job_start(c, av, q->cmd->timeout_s, CTL_OUT_MAX, CTL_ERR_MAX, plugin_done);
    free(av);
    free(words);
    if (rc != 0) {
        if (c->tmp[0]) { unlink(c->tmp); c->tmp[0] = '\0'; }
        resp_error(&c->resp, "internal", "не удалось запустить ядро");
        conn_reply(c);
    }
}

/* plugin-reload: реестр плагинов ядра заново, затем то же, что reload (спека, помощники, правила). */
static void st_plugin_reload(struct conn *c) {
    if (plugin_reload) plugin_reload(NULL);
    st_reload(c);
}

/* plugin-event: тело — объект JSON от менеджера; подписчикам уходит событие `plugin` с полями id,
 * state, version, from, why, by (steer-api.md, 4.1). Прочие поля тела не пересылаются. */
static void mem_plugin_event(struct conn *c, struct cbuf *r) {
    struct err e = {{0}};
    struct ydoc *d = c->q.body_n ? ydoc_parse_buf(c->q.body, c->q.body_n, "plugin-event", &e) : NULL;
    const struct ynode *root = d ? ydoc_root(d) : NULL;
    const struct ynode *id = ynode_get(root, "id"), *st = ynode_get(root, "state");
    if (!root || root->kind != YN_MAP || !id || id->kind != YN_SCALAR || !st || st->kind != YN_SCALAR) {
        if (d) ydoc_free(d);
        resp_error(r, "bad-request", "тело — объект JSON с id и state");
        return;
    }
    struct cbuf f = {0};
    static const char *const keys[] = {"id", "state", "version", "from", "why", "by", NULL};
    for (int i = 0; keys[i]; i++) {
        const struct ynode *v = ynode_get(root, keys[i]);
        cb_fmt(&f, ",\"%s\":", keys[i]);
        if (v && v->kind == YN_SCALAR && !(v->style == YS_PLAIN && ynode_is_null(v))) cb_jstr(&f, v->str);
        else cb_str(&f, "null");
    }
    cb_put(&f, "", 0);
    fprintf(stderr, LOG_I "плагин %s: %s\n", id->str, st->str);
    steerd_emit(&c->srv->d, "plugin", f.p);
    free(f.p);
    ydoc_free(d);
    cb_str(r, ",\"code\":0,\"stdout\":\"\",\"stderr\":\"\"");
}

/* ---- автообновление плагинов (s2p.md, «Фоновое автообновление») ----------------------------------
 *
 * Таймер в цикле демона, без cron и отдельного сторожа: по сроку — ребёнок `steerd plugin update
 * --auto`, демон его не ждёт (только подбирает по выходу). Когда звать в следующий раз, решает сам
 * менеджер: он пишет срок в state.json (auto.next — раз в сутки со сдвигом до часа, раньше — к
 * началу ночного окна, если есть обновления, и повтор плагинов pending). Демон этот срок читает
 * после каждого прохода. Нет каталога плагинов — таймера нет (стенды, телефон). */
#define PLUGAUTO_FIRST_MS (5L * 60 * 1000)

static const char *plugauto_root(void) {
    const char *v = getenv("STEER_PLUGIN_DIR");
    return v && *v ? v : "/usr/lib/steer/plugins";
}

static long plugauto_delay_ms(void) {
    const char *etc = getenv("STEER_PLUGIN_ETC");
    char p[PATH_MAX];
    snprintf(p, sizeof(p), "%s/state.json", etc && *etc ? etc : "/etc/steer/plugins");
    struct cbuf b = {0};
    long ms = 24L * 3600 * 1000;
    if (ctl_read_file(p, &b, 64L * 1024 * 1024) == 1) {
        struct err e = {{0}};
        struct ydoc *d = ydoc_parse_buf(b.p, b.n, "state.json", &e);
        const struct ynode *nx = d ? ynode_get(ynode_get(ydoc_root(d), "auto"), "next") : NULL;
        if (nx && nx->kind == YN_SCALAR) {
            struct tm tm = {0};
            if (strptime(nx->str, "%Y-%m-%dT%H:%M:%SZ", &tm)) {
                time_t t = timegm(&tm), now = time(NULL);
                ms = t > now ? (long)(t - now) * 1000L : 1000L;
            }
        } else {
            ms = PLUGAUTO_FIRST_MS;
        }
        if (d) ydoc_free(d);
    } else {
        ms = PLUGAUTO_FIRST_MS;
    }
    free(b.p);
    if (ms < 1000) ms = 1000;
    return ms;
}

static struct loop_timer *g_plugauto_tm;
static pid_t g_plugauto_pid;

static void plugauto_exit(struct loop *l, pid_t pid, int status, void *arg) {
    (void)l; (void)pid; (void)arg;
    g_plugauto_pid = 0;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        fprintf(stderr, LOG_W "фоновое обновление плагинов не прошло (код %d) — подробности в steer plugin status\n",
                WIFEXITED(status) ? WEXITSTATUS(status) : 128);
    if (g_plugauto_tm) loop_timer_set(g_plugauto_tm, plugauto_delay_ms());
}

static void plugauto_fire(struct loop *l, struct loop_timer *t, void *arg) {
    struct ctl_srv *s = arg;
    (void)t;
    if (g_plugauto_pid) return;
    pid_t pid = fork();
    if (pid < 0) { loop_timer_set(g_plugauto_tm, 600000L); return; }
    if (pid == 0) {
        setpgid(0, 0);
        int nul = open("/dev/null", O_RDWR);
        if (nul >= 0) { dup2(nul, 0); dup2(nul, 1); }
        loop_child_reset();
        char *av[] = { s->cf.exe, "plugin", "update", "--auto", NULL };
        execv(s->cf.exe, av);
        _exit(127);
    }
    g_plugauto_pid = pid;
    loop_child(l, pid, plugauto_exit, s);
}

static void plugauto_start(struct ctl_srv *s) {
    const char *off = getenv("STEER_PLUGIN_AUTO");
    if (off && !strcmp(off, "0")) return;
    struct stat st;
    if (stat(plugauto_root(), &st) != 0 || !S_ISDIR(st.st_mode)) return;
    g_plugauto_tm = loop_timer_new(s->l, plugauto_fire, s);
    if (g_plugauto_tm) loop_timer_set(g_plugauto_tm, plugauto_delay_ms());
}

/* ---- запрос ------------------------------------------------------------------------------------ */

/* Строка запроса пришла целиком: разобрать слова, проверить их по таблице, завести тело.
 * 0 — можно читать тело или исполнять; -1 — отказ уже отдан. */
static int conn_parse(struct conn *c) {
    char *tok[6];
    int nt = 0;
    for (char *s = c->line; nt < 6; ) {
        char *sp = strchr(s, ' ');
        if (sp) *sp = '\0';
        tok[nt++] = s;
        if (!sp) break;
        s = sp + 1;
        if (nt == 6) { conn_refuse(c, NULL, "bad-request", "слишком много слов в запросе"); return -1; }
    }
    for (int i = 0; i < nt; i++)
        if (!tok[i][0]) { conn_refuse(c, NULL, "bad-request", "пустое слово: слова разделяются одним пробелом"); return -1; }
    const struct ctl_cmd *cmd = ctl_lookup(tok[0]);
    if (!cmd && plugin_ctl_cmd(tok[0], &c->pcmd) == 0) cmd = &c->pcmd;
    if (!cmd) { conn_refuse(c, NULL, "unknown-command", "такой команды нет"); return -1; }

    if (!c->counted) {
        if (!strcmp(cmd->name, "subscribe")) { /* не занимает место */ }
        else if (c->srv->active >= CTL_CLIENTS_MAX) {
            conn_refuse(c, cmd->name, "busy", "сервер занят другими запросами — повторите позже");
            return -1;
        } else { c->counted = 1; c->srv->active++; }
    }
    memset(&c->q, 0, sizeof(c->q));
    c->q.cmd = cmd;
    c->q.cf = &c->srv->cf;
    int na = nt - 1;
    size_t blen = 0;
    if (cmd->body) {
        if (na < 1) { conn_refuse(c, cmd->name, "bad-request", "нужна длина тела последним словом"); return -1; }
        const char *w = tok[nt - 1];
        size_t wl = strlen(w);
        if (wl > 10 || strspn(w, "0123456789") != wl) {
            conn_refuse(c, cmd->name, "bad-request", "длина тела — десятичное число байт");
            return -1;
        }
        unsigned long long v = strtoull(w, NULL, 10);
        if (v > (unsigned long long)cmd->body) {
            char m[64];
            snprintf(m, sizeof(m), "тело больше %ld МиБ", cmd->body / (1024 * 1024));
            conn_refuse(c, cmd->name, "too-large", m);
            return -1;
        }
        blen = (size_t)v;
        na--;
    }
    if (na < cmd->argmin || na > cmd->argmax) {
        conn_refuse(c, cmd->name, "bad-request", "не то число слов у команды");
        return -1;
    }
    for (int i = 0; i < na; i++) {
        const char *why = ctl_arg_bad(&cmd->args[i], tok[i + 1]);
        if (why) { conn_refuse(c, cmd->name, "bad-request", why); return -1; }
        c->q.argv[i] = tok[i + 1];     /* указывают в c->line — живёт до конца соединения */
    }
    c->q.argc = na;
    if (cmd->body) {
        c->body = malloc(blen + 1);
        if (!c->body) { conn_refuse(c, cmd->name, "internal", "нет памяти под тело"); return -1; }
        c->body_want = blen;
        c->body_got = 0;
    }
    return 0;
}

/* Запрос прочитан: исполнить сейчас или встать в очередь изменяющих. */
static void conn_dispatch(struct conn *c) {
    struct ctl_srv *s = c->srv;
    loop_timer_stop(c->tm);
    /* Пока команда идёт, из сокета не читаем: всё, что клиент пришлёт сверх запроса, дочитает
     * conn_drain после ответа. Уход клиента (EPOLLHUP) epoll сообщает и так. */
    conn_events(c, 0);
    if (c->body) {
        c->body[c->body_got] = '\0';
        c->q.body = c->body;
        c->q.body_n = c->body_got;
    }
    resp_begin(&c->resp, c->q.cmd->name);
    if (c->q.cmd->lock && s->lock_owner) {
        c->st = C_WAIT;
        struct conn **pp = &s->lockq;
        while (*pp) pp = &(*pp)->qnext;
        *pp = c;
        return;
    }
    conn_exec(c);
}

static void conn_exec(struct conn *c) {
    const struct ctl_cmd *k = c->q.cmd;
    if (k->lock) c->srv->lock_owner = c;
    c->st = C_RUN;
    if (k->fn) { k->fn(c, &c->resp); conn_reply(c); }
    else if (k->start) k->start(c);
    else st_sub(c);
}

/* Читать запрос, сколько пришло. Строка — кусками, и то, что пришло за '\n', — начало тела:
 * обработчик больше не читает по байту (там это было ради того, чтобы не захватить тело), —
 * лишнее просто переносится в тело. */
static void conn_read_req(struct conn *c) {
    char buf[4096];
    for (;;) {
        if (c->have_line) {
            size_t want = c->body_want - c->body_got;
            if (!want) { conn_dispatch(c); return; }
            ssize_t m = recv(c->fd, c->body + c->body_got, want, MSG_DONTWAIT);
            if (m < 0 && errno == EINTR) continue;
            if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
            if (m < 0) { conn_free(c); return; }
            if (m == 0) {
                conn_refuse(c, c->q.cmd->name, "bad-request", "тело не пришло целиком за 5 секунд");
                return;
            }
            c->body_got += (size_t)m;
            continue;
        }
        ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (m < 0 && errno == EINTR) continue;
        if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return;
        if (m < 0) { conn_free(c); return; }
        if (m == 0) { conn_refuse(c, NULL, "bad-request", "запрос не пришёл целиком за 5 секунд"); return; }
        char *nl = memchr(buf, '\n', (size_t)m);
        size_t take = nl ? (size_t)(nl - buf) : (size_t)m;
        if (c->line_n + take > CTL_LINE_MAX) {
            conn_refuse(c, NULL, "too-large", "строка запроса длиннее 512 байт");
            return;
        }
        memcpy(c->line + c->line_n, buf, take);
        c->line_n += take;
        if (!nl) continue;
        if (c->line_n && c->line[c->line_n - 1] == '\r') c->line_n--;
        c->line[c->line_n] = '\0';
        c->have_line = 1;
        if (conn_parse(c) != 0) return;
        if (!c->q.cmd->body) { conn_dispatch(c); return; }
        size_t rest = (size_t)m - take - 1;
        if (rest > c->body_want) rest = c->body_want;
        memcpy(c->body, nl + 1, rest);
        c->body_got = rest;
    }
}

static void conn_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct conn *c = arg;
    switch (c->st) {
    case C_REQ:
        if (c->have_line)
            conn_refuse(c, c->q.cmd->name, "bad-request", "тело не пришло целиком за 5 секунд");
        else
            conn_refuse(c, NULL, "bad-request", "запрос не пришёл целиком за 5 секунд");
        break;
    case C_SEND:
    case C_DRAIN:
        conn_free(c);
        break;
    default:
        break;
    }
}

static void conn_ev(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)fd;
    struct conn *c = arg;
    int gone = (ev & (EPOLLHUP | EPOLLERR)) != 0;
    switch (c->st) {
    case C_REQ:
        conn_read_req(c);
        break;
    case C_WAIT:
    case C_RUN:
        /* Клиент ушёл, пока команда шла или ждала очереди. Ждущему — выйти из очереди сразу;
         * идущую — довести (apply посреди шагов не бросают), а ответ не отдавать. Дескриптор
         * снимается с epoll: иначе HUP будил бы демон на каждом обороте до конца команды. */
        if (!gone) break;
        if (c->st == C_WAIT) { conn_free(c); break; }
        loop_fd_del(l, c->fd);
        c->hup = 1;
        break;
    case C_SEND:
        if (ev & EPOLLOUT) conn_flush(c);
        else if (gone) conn_free(c);
        break;
    case C_DRAIN:
        conn_drain(c);
        break;
    case C_SUB:
        if (ev & EPOLLOUT) { if (conn_flush(c) != 0) break; }
        if (ev & EPOLLIN) {
            char buf[512];
            for (;;) {
                ssize_t m = recv(c->fd, buf, sizeof(buf), MSG_DONTWAIT);
                if (m > 0) continue;
                if (m < 0 && errno == EINTR) continue;
                if (m == 0) {
                    c->eof = 1;
                    conn_events(c, c->off < c->resp.n ? EPOLLOUT : 0);
                }
                break;
            }
        }
        if (gone) conn_free(c);
        break;
    }
}

static void conn_free(struct conn *c) {
    struct ctl_srv *s = c->srv;
    if (c->st == C_SUB) { steerd_sub_del(&s->d, &c->sub); s->subs--; }
    if (c->counted) s->active--;
    for (struct conn **pp = &s->lockq; *pp; pp = &(*pp)->qnext)
        if (*pp == c) { *pp = c->qnext; break; }
    for (struct conn **pp = &s->conns; *pp; pp = &(*pp)->next)
        if (*pp == c) { *pp = c->next; break; }
    if (s->lock_owner == c) lock_release(s);
    if (!c->hup) loop_fd_del(s->l, c->fd);
    if (c->fd >= 0) close(c->fd);
    loop_timer_free(c->tm);
    loop_timer_free(c->job.tm);
    free(c->job.out.p);
    free(c->job.err.p);
    free(c->resp.p);
    free(c->old.p);
    free(c->perr.p);
    recon_plan_free(&c->plan);      /* массивы плана и решения растут по числу выходов (recon.h) */
    recon_diff_free(&c->diff);
    free(c->body);
    free(c);
}

/* ---- кого пускать ---------------------------------------------------------------------------- */

/* Домен из контекста SELinux «u:r:ДОМЕН:s0:c...» — третье поле. */
static int ctl_ctx_domain_is(const char *ctx, const char *dom) {
    const char *a = strchr(ctx, ':');
    if (!a) return 0;
    const char *b = strchr(a + 1, ':');
    if (!b) return 0;
    const char *e = strchr(b + 1, ':');
    size_t n = e ? (size_t)(e - (b + 1)) : strlen(b + 1);
    return n == strlen(dom) && !strncmp(b + 1, dom, n);
}

/* 1 — пустить. who — для журнала при отказе. */
static int ctl_peer_ok(int c, const struct ctl_conf *cf, char *who, size_t wn) {
    struct ucred uc;
    socklen_t l = sizeof(uc);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0) {
        snprintf(who, wn, "неизвестный собеседник (%s)", strerror(errno));
        return 0;
    }
    snprintf(who, wn, "uid %u pid %d", (unsigned)uc.uid, (int)uc.pid);
    if (uc.uid == 0 || uc.uid == CTL_AID_SYSTEM) return 1;
    for (int i = 0; i < cf->allow_uid_n; i++)
        if (cf->allow_uid[i] == uc.uid) return 1;
    if (cf->allow_domain && cf->allow_domain[0] && uc.uid < CTL_USER_RANGE) {
        char ctx[256];
        socklen_t cl = sizeof(ctx) - 1;
        if (getsockopt(c, SOL_SOCKET, SO_PEERSEC, ctx, &cl) == 0) {
            ctx[cl < sizeof(ctx) ? cl : sizeof(ctx) - 1] = '\0';
            if (ctl_ctx_domain_is(ctx, cf->allow_domain)) return 1;
            size_t wl = strlen(who);
            snprintf(who + wl, wn - wl, " %s", ctx);
        }
    }
    return 0;
}

/* ---- сервер ------------------------------------------------------------------------------------ */

static void srv_accept_resume(struct loop *l, struct loop_timer *t, void *arg) {
    (void)t;
    struct ctl_srv *s = arg;
    loop_fd_mod(l, s->lfd, EPOLLIN);
}

static void srv_accept(struct loop *l, int fd, uint32_t ev, void *arg) {
    (void)ev;
    struct ctl_srv *s = arg;
    for (;;) {
        int c = accept4(fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
        if (c < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            /* Нехватка дескрипторов или памяти не проходит сама за микросекунду, а соединение
             * так и ждёт в очереди — epoll будил бы демон сразу же, и он крутился бы вхолостую.
             * Приём снимается на 200 мс; в обычной работе сюда не попасть. */
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                loop_fd_mod(l, fd, 0);
                loop_timer_set(s->accept_tm, 200);
            }
            return;
        }
        char who[320];
        if (!ctl_peer_ok(c, &s->cf, who, sizeof(who))) {
            fprintf(stderr, LOG_W "отказ: %s\n", who);
            ctl_refuse_now(c, "denied", "этому процессу управлять ядром steer нельзя");
            continue;
        }
        struct conn *n = calloc(1, sizeof(*n));
        if (n) {
            n->srv = s;
            n->fd = c;
            n->job.po = n->job.pe = -1;
            n->tm = loop_timer_new(l, conn_timer, n);
        }
        if (!n || !n->tm || loop_fd_add(l, c, EPOLLIN, conn_ev, n) != 0) {
            if (n) loop_timer_free(n->tm);
            free(n);
            ctl_refuse_now(c, "internal", "не удалось начать обработку запроса");
            continue;
        }
        n->st = C_REQ;
        /* Четыре запроса — это ИДУЩИЕ команды. Соединение, которое ещё не прислало строку,
         * место занимает, пока оно есть; сверх четырёх оно принимается без места и получает его
         * по строке (conn_parse) — или busy, если это не subscribe: подписчики, которых плагины
         * поднимают разом, в четыре запроса не входят и не упираются в них. */
        if (s->active < CTL_CLIENTS_MAX) { n->counted = 1; s->active++; }
        n->next = s->conns;
        s->conns = n;
        loop_timer_set(n->tm, CTL_REQ_MS);
    }
}

/* Идёт изменяющая команда — сторож откладывает проход (watchd.h). */
static int srv_busy(void *arg) {
    return ((struct ctl_srv *)arg)->lock_owner != NULL;
}

/* Страж правил (rulewd_conf.busy): ждать ли конца своей операции, прежде чем возвращать снятые
 * правила. Прежде здесь стоял srv_busy — «идёт любая изменяющая команда», — и страж проигрывал
 * сверке на `network restart` (проверка на QEMU-роутере 4192267, 2026-09-29): новый
 * br-lan ставит сверку набора правил (srv_lan), netifd через 50–200 мс снимает правила, страж
 * видит очередь занятой и молчит, а сверка в своём решении (recon_decide в commit_start) видит
 * «правила нет» и перепривязывает выходы ребёнком apply-commit --route — по одному, ~0,4 с на
 * выход. Пауза — это запуски ip в apply_routing_one (запрет и маршрут в таблицу, её чистка,
 * `ip rule show` и `ip rule add` в rule_ensure, то же для IPv6 — около десятка процессов), а
 * набор правил с цепочкой ingress_mark встаёт только после привязки (--ruleset идёт после
 * --route, cmd_apply_commit): цепочка возвращалась через 3,3–4,4 с вместо ~350 мс, в 4 прогонах из 5.
 *
 * Ждать страж обязан одного — своей операции, которая САМА снимает правила выходов: посреди неё
 * правило уже снято, а таблица ещё не сброшена, и страж вернул бы правило туда, где его сняли
 * нарочно. У apply и reload правила снимает только ребёнок apply-commit, и только в двух частях:
 * --drop (метки, которых больше не несёт ни один выход) и --route (apply_routing_one снимает IPv6
 * выхода, у которого спека IPv6 отняла). Поэтому:
 *   - пока идёт план (ребёнок apply-plan в ядро не пишет) — возвращать сразу; решит потом сверка
 *     снять метку — rule_drop снимет и вернутую копию (он снимает все);
 *   - применение без --drop и --route (сверка по новому мосту: только набор правил) правил не
 *     снимает — тоже сразу. Сообщение rtnetlink стража с nft -f ребёнка не спорит: набор правил
 *     правил маршрутизации не касается;
 *   - применение с --drop или --route — не ждать целиком: ждёт только правило того выхода, который
 *     команда сама может снять (srv_rules_held ниже). Прежде страж молчал до конца команды, а
 *     команда с --route на `network restart` шла секунду с лишним (проверка на QEMU, 1,3–1,65 с;
 *     ~0,4 с на выход, и набор правил с ingress_mark после привязок), — всё это время правило,
 *     снятое netifd посреди неё, не стояло, и возвращал его сам reload («привязываю заново»),
 *     когда доходил до выхода;
 *   - прочие изменяющие команды (починка ребёнком, выключатель, restart…) — ждать, как прежде.
 * Чтобы само решение сверки не увидело снятое правило раньше стража (событие ещё в очереди
 * цикла или в пачке на 100 мс), commit_start перед recon_decide зовёт rulewd_settle.
 *
 * Возвращать при идущем --route безопасно, и вот почему. Возврат — одно сообщение rtnetlink,
 * идемпотентное: rtnl_rule_fwmark с NLM_F_EXCL на точную копию получает EEXIST и считает это
 * успехом. Приоритет страж ставит тот же, что был у снятого правила (событие его несёт; на
 * телефоне он свой), а rule_ensure ребёнка сначала читает дамп: увидев верную копию (метка, наша
 * маска, таблица), он ничего не добавляет, а лишние снимает — так что приоритет чужого возврата
 * значения не имеет. Остаётся окно между дампом ребёнка и его `ip rule add`: если страж вернул
 * правило именно там, копий станет две — обе ведут в ту же таблицу, трафик идёт верно, лишнюю
 * снимет следующий rule_ensure (следующая привязка) — вред только косметический, а не утечка.
 * Ждать ради этого окна значило бы держать выход без правила на всё время команды: помеченный
 * трафик выхода идёт тогда через postrouting_guard в отбрасывание, то есть «не работает». */
static int srv_rules_busy(void *arg) {
    const struct conn *c = ((struct ctl_srv *)arg)->lock_owner;
    if (!c) return 0;
    const char *name = c->q.cmd ? c->q.cmd->name : "";
    return strcmp(name, "apply") != 0 && strcmp(name, "reload") != 0;
}

/* Страж правил (rulewd_conf.held): выход o, чьи правила идущий apply или reload сам снимает или
 * может снять, — пока команда идёт, страж их не возвращает (потом проверит, rulewd_defer):
 *   - метка из --drop: rule_drop снимет и вернутую копию, но правило и таблицу он снимает двумя
 *     шагами, и вернуть правило между ними значило бы оставить его без таблицы;
 *   - выход из --route, у которого изменилась подпись маршрутизации (или полный apply): спека
 *     могла отнять у него IPv6 (apply_routing_one снимет правило и таблицу IPv6), а страж судит
 *     по спеке в памяти — прежней, пока команда не кончится;
 *   - выход из --route только из-за расхождения с ядром (recon_diff.route_kern) — не держится:
 *     привязка ничего не снимает нарочно, правило она лишь оставляет или ставит. Это и есть путь
 *     `network restart`, когда правила снял netifd. */
static int srv_rules_held(void *arg, const struct output *o) {
    const struct conn *c = ((struct ctl_srv *)arg)->lock_owner;
    if (!c || !c->committed) return 0;
    const char *name = c->q.cmd ? c->q.cmd->name : "";
    if (strcmp(name, "apply") != 0 && strcmp(name, "reload") != 0) return 0;
    for (size_t i = 0; i < c->diff.drop_n; i++)
        if (c->diff.drop[i].mark == o->mark) return 1;
    for (size_t i = 0; i < c->diff.route_n; i++)
        if (!strcmp(c->diff.route[i], o->name)) return !c->diff.route_kern[i];
    return 0;
}

/* Дети команд, которые ещё идут (apply, diag, vless-probe…): их группам процессов — SIGTERM,
 * через две секунды — SIGKILL. Раньше демон выходил, оставляя их доживать сиротами: `apply`
 * посреди nft или vless-probe на три минуты перебора. Ждёт сам — цикл уже не крутится. */
static void srv_jobs_stop(struct ctl_srv *s) {
    int any = 0;
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) { kill(-c->job.pid, SIGTERM); any = 1; }
    long dl = loop_now_ms() + 2000;
    while (any) {
        any = 0;
        for (struct conn *c = s->conns; c; c = c->next) {
            struct job *j = &c->job;
            if (!j->running || j->reaped) continue;
            pid_t w = waitpid(j->pid, NULL, WNOHANG);
            if (w == j->pid || (w < 0 && errno == ECHILD)) { j->reaped = 1; continue; }
            if (loop_now_ms() < dl) { any = 1; continue; }
            kill(-j->pid, SIGKILL);
            kill(j->pid, SIGKILL);
            while (waitpid(j->pid, NULL, 0) < 0 && errno == EINTR) {}
            j->reaped = 1;
        }
        if (any) {
            struct timespec ts = { 0, 50000000L };
            nanosleep(&ts, NULL);
        }
    }
    /* Внуки, пережившие лидера группы (nft, запущенный командой), — туда же. */
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) kill(-c->job.pid, SIGKILL);
}

static void srv_term(struct loop *l, int signo, void *arg) {
    (void)signo;
    struct ctl_srv *s = arg;
    struct stat sb;
    if (s->ino && stat(s->cf.sock, &sb) == 0 && sb.st_ino == s->ino) unlink(s->cf.sock);
    watchd_stop(s->watch);
    /* Детям команд — SIGTERM сразу: гаснут, пока демон по одному гасит помощников. */
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->job.running) kill(-c->job.pid, SIGTERM);
    supd_stop(s->d.sup);
    srv_jobs_stop(s);
    loop_stop(l, 0);
}

/* SIGHUP — перечитать спеку в память, как после reload (без сигналов резолверу и супервизору:
 * им говорит reload). Идёт ли изменяющая команда — после неё (lock_release). */
static void srv_hup(struct loop *l, int signo, void *arg) {
    (void)l; (void)signo;
    struct ctl_srv *s = arg;
    if (s->lock_owner) s->hup_pending = 1;
    else srv_spec_changed(s, "hup", ctl_enabled(), NULL, 1, NULL);
}

/* --apply: применить спеку при старте демона — тем же reload, что по сокету, только без
 * соединения (итог — строкой в журнал, см. reload_head). Нужен одному сервису: procd на роутере
 * и init на телефоне держат один steerd, и отдельного `steer apply` перед ним больше нет. Через
 * сверку, а не подкомандой apply: демон тогда помнит применённое, и первое же «Применить» из
 * интерфейса трогает только изменившееся, а не ставит всё заново (наборы, которые наполнил
 * резолвер, при этом не опустошаются). Идёт в очереди изменяющих команд — apply, пришедший по
 * сокету сразу после старта, подождёт его. */
static int boot_apply(struct ctl_srv *s) {
    struct conn *c = calloc(1, sizeof(*c));
    if (!c) return -1;
    c->srv = s;
    c->fd = -1;
    c->hup = 1;          /* ответ отдавать некому: conn_reply освобождает соединение */
    c->boot = 1;
    c->st = C_RUN;
    c->q.cmd = ctl_lookup("reload");
    c->q.cf = &s->cf;
    c->next = s->conns;
    s->conns = c;
    resp_begin(&c->resp, "reload");
    conn_exec(c);
    return 0;
}

/* ---- починка правил выходов (страж правил, rulewd.c) --------------------------------------------
 *
 * Страж увидел, что правила выхода нет, а таблица его занята, — правило сняли не мы (netd при
 * перезапуске, чужой `ip rule flush`). Починка — изменяющая команда без соединения, как стартовое
 * применение: встаёт в ту же очередь (apply, пришедший по сокету, её подождёт, и наоборот) и не
 * видна в таблице команд — приложению её не позвать. Что чинить, решается заново в начале:
 * пока починка ждала очереди, apply мог уже всё поставить. */
static const struct ctl_cmd CTL_REPAIR = {"repair", NULL, NULL, st_repair, 0, 0, 0, {{0}}, 0, 0, 1};

/* Правила возвращены (list — выходы через запятую): событие repaired подписчикам и внеочередной
 * проход сторожа, который сверит остальную маршрутизацию выходов (и masquerade на телефоне:
 * проход после события сверяет его сразу, watch_masq_due). masq — masquerade вернули уже здесь. */
static void repaired_emit(struct ctl_srv *s, const char *list, int masq) {
    struct cbuf f = {0};
    cb_str(&f, ",\"outputs\":[");
    int first = 1;
    for (const char *p = list; *p; ) {
        const char *e = strchr(p, ',');
        size_t l = e ? (size_t)(e - p) : strlen(p);
        if (!first) cb_str(&f, ",");
        cb_json(&f, p, l);
        first = 0;
        if (!e) break;
        p = e + 1;
    }
    cb_fmt(&f, "],\"masq\":%s", masq ? "true" : "false");
    steerd_emit(&s->d, "repaired", f.p ? f.p : "");
    free(f.p);
    watchd_spec_changed(s->watch);
}

static void repair_done(struct conn *c, int code) {
    struct ctl_srv *s = c->srv;
    struct job *j = &c->job;
    int masq = plat()->iptables_masq != 0;
    if (code != 0 || j->timed_out) {
        cb_utf8_trim(&j->err);
        fprintf(stderr, LOG_W "правила выходов (%s) вернуть не удалось (код %d)%s%.*s", c->tmp,
                code, j->err.n ? ":\n" : "\n", (int)j->err.n, j->err.p ? j->err.p : "");
    } else {
        fprintf(stderr, LOG_I "правила выходов сняты снаружи — возвращены: %s%s\n", c->tmp,
                masq ? " (и masquerade)" : "");
        if (j->err.n) fprintf(stderr, "%.*s", (int)j->err.n, j->err.p);
        repaired_emit(s, c->tmp, masq);
    }
    conn_reply(c);
}

/* Обратный вызов стража: правила он вернул сам, в процессе демона (rulewd.c, «СРАЗУ, А НЕ ЧЕРЕЗ
 * СЕКУНДУ»). Очередь изменяющих команд не нужна: одно сообщение rtnetlink на правило, таблицы не
 * тронуты. masquerade (телефон) вернёт проход сторожа, который repaired_emit зовёт. Запасной запрет
 * IPv6 (его ядро снимает вместе с lo — rulewd.c, «ЗАПРЕТ IPv6 УХОДИТ ВМЕСТЕ С lo») — своей строкой:
 * правил в этом случае никто не снимал, и строка о них была бы неправдой. */
static void srv_restored(void *arg, const char *all, const char *rules, const char *bs6) {
    struct ctl_srv *s = arg;
    if (rules[0]) fprintf(stderr, LOG_I "правила выходов сняты снаружи — возвращены: %s\n", rules);
    if (bs6[0])
        fprintf(stderr, LOG_I "запрет IPv6 в таблице выхода снят (вместе с lo или снаружи) — "
                        "возвращён: %s\n", bs6);
    repaired_emit(s, all, 0);
}

static void st_repair(struct conn *c) {
    struct ctl_srv *s = c->srv;
    char *miss = NULL;
    if (!s->on || !s->d.have || rulewd_missing(s->d.sp, &miss) <= 0) {
        free(miss);
        conn_reply(c);
        return;
    }
    /* Список выходов — своя строка в куче, а не c->tmp на PATH_MAX: на сотнях выходов он
     * длиннее пути. av[] её только называет, и job_start копирует аргументы до возврата. */
    char *av[12];
    size_t n = 0;
    av[n++] = s->cf.exe;
    av[n++] = "apply-commit";
    av[n++] = "--spec";
    av[n++] = (char *)s->cf.spec;
    if (s->cf.state_dir) { av[n++] = "--state-dir"; av[n++] = (char *)s->cf.state_dir; }
    av[n++] = "--rule";
    av[n++] = miss;
    av[n++] = "--masq-ensure";
    av[n] = NULL;
    if (job_start(c, av, 60, CTL_ERR_MAX, CTL_ERR_MAX, repair_done) != 0) {
        fprintf(stderr, LOG_W "правила выходов (%s): не удалось запустить ядро\n", miss);
        conn_reply(c);
    }
    free(miss);
}

/* Обратный вызов стража: поставить починку в очередь изменяющих команд. Уже ждёт или идёт —
 * вторая незачем. */
static void srv_repair(void *arg) {
    struct ctl_srv *s = arg;
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->repair) return;
    struct conn *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->srv = s;
    c->fd = -1;
    c->hup = 1;
    c->repair = 1;
    c->job.po = c->job.pe = -1;
    c->q.cmd = &CTL_REPAIR;
    c->q.cf = &s->cf;
    c->next = s->conns;
    s->conns = c;
    resp_begin(&c->resp, "repair");
    if (s->lock_owner) {
        c->st = C_WAIT;
        struct conn **pp = &s->lockq;
        while (*pp) pp = &(*pp)->qnext;
        *pp = c;
        return;
    }
    conn_exec(c);
}

/* ---- сверка набора правил на проходе сторожа ---------------------------------------------------
 *
 * Решение владельца 2026-09-28 (устройство и доводы — в шапке recon.c, «СВЕРКА НА ПРОХОДЕ
 * СТОРОЖА»): сторож в начале каждого прохода зовёт srv_kcheck, и тот сверяет номер и отпечаток
 * наших таблиц в ядре с запомненными после последнего нашего nft -f — четыре обмена netlink, без
 * процессов. Разошлось — строка в журнал и починка в очереди изменяющих команд: reload без
 * соединения (как стартовое применение), то есть тот же путь, что apply той же спеки. Проход её
 * не ждёт. */

/* Починок — не больше RESYNC_BURST за RESYNC_WINDOW_MS: тот, кто правит нашу таблицу без
 * остановки, не должен превращать каждый проход (а после событий сети они идут через 5 с) в
 * компиляцию и nft -f. Не интервал между починками, а их число в окне: два независимых
 * вмешательства подряд (снятое правило, потом чужая таблица) чинятся оба сразу, а бесконечная
 * драка стоит трёх починок за пять минут. Пропущенное расхождение найдёт первый проход после
 * того, как окно освободится. */
#define RESYNC_BURST 3
#define RESYNC_WINDOW_MS (5 * 60 * 1000L)

/* Сверка в очередь. kind — RESYNC_PASS (идёт в счёт RESYNC_BURST) или RESYNC_LAN (свой счёт,
 * srv_lan). */
static void srv_resync(struct ctl_srv *s, int kind) {
    struct conn *c = calloc(1, sizeof(*c));
    if (!c) return;
    c->srv = s;
    c->fd = -1;
    c->hup = 1;          /* ответ отдавать некому: conn_reply освобождает соединение */
    c->resync = kind;
    c->job.po = c->job.pe = -1;
    c->q.cmd = ctl_lookup("reload");
    c->q.cf = &s->cf;
    c->next = s->conns;
    s->conns = c;
    resp_begin(&c->resp, "reload");
    if (kind == RESYNC_PASS) {
        s->resync_at[s->resync_i] = loop_now_ms();
        s->resync_i = (s->resync_i + 1) % RESYNC_BURST;
    }
    if (s->lock_owner) {
        c->st = C_WAIT;
        struct conn **pp = &s->lockq;
        while (*pp) pp = &(*pp)->qnext;
        *pp = c;
        return;
    }
    conn_exec(c);
}

/* ЛИМИТ МОЛЧАЛ (проверка на QEMU 04664a5). После четвёртого и
 * шестого `network restart` за пять минут цепочка ingress не вернулась: сработали «три починки за
 * пять минут», и вернулась она через ~80 с, а в журнале — ни строки. Теперь:
 *   - отказ по лимиту — строка в журнал, одна на окно (окно узнаётся по самой старой починке в нём:
 *     следующая починка — новое окно, и о нём скажут снова), с тем, что разошлось, и через сколько
 *     секунд проход починит;
 *   - что лимит ограничивает. Он заведён против того, кто правит нашу таблицу без остановки, а не
 *     против законных пересозданий устройств раздачи: цепочку ingress_mark ядро снимает вместе с
 *     устройством, и такое расхождение не чья-то драка с нами, а следствие `network restart`.
 *     Расхождение, найденное после того, как устройство раздачи пропало или появилось, а плана с
 *     тех пор не было (lan_at не раньше plan_at), — объяснимое: починка идёт вне RESYNC_BURST, в
 *     счёт предела сверок по устройствам раздачи (srv_lan_budget, 20 за пять минут). Отличить
 *     «цепочку сняло ядро» от «цепочку снял кто-то в тот же миг» по отпечатку нельзя (он один на
 *     таблицу), но и незачем: починка у обоих одна и та же — замена набора, — а шторм чужих правок
 *     без пересозданий моста по-прежнему упирается в три за пять минут. Сверка по новому
 *     устройству (srv_lan) обычно успевает раньше прохода, и сюда такое расхождение не доходит;
 *     сюда — когда проход пришёл, пока устройства ещё нет, или событие потерялось. */
static int srv_lan_budget(struct ctl_srv *s);

/* ТАБЛИЦЫ ДВИЖКА НЕТ, А ПРАВИЛА ВЫХОДОВ СТОЯТ — ЕЁ СНЯЛИ МИМО НАС (steer#4, проверка на QEMU
 * a5d8f10). `/etc/init.d/firewall stop` — это `fw4 flush`, а он снимает не свою inet fw4, а ВСЕ
 * таблицы nftables подряд (`nft list tables | while … nft delete table`), и наши вместе с ними.
 * `firewall start` следом ставит только fw4. Прежде проход сторожа принимал «таблицы inet нет» за
 * `steer down` и молчал: метки не ставились, postrouting_guard (он в той же таблице) не держал, и
 * трафик каналов шёл напрямую — на стенде 90 с и дольше, до перезапуска службы, ни строки в
 * журнале. (`firewall restart` и `reload` таблицы движка не трогают: restart — это `fw4 stop` +
 * `start`, а stop снимает одну inet fw4.)
 *
 * Признак «снято мимо нас» — таблицы inet нет, движок включён, и хоть у одного выхода с
 * устройством правило и таблица на месте (rulewd_missing не насчитал пропажу у всех): fw4 flush
 * правил маршрутизации не касается. Штатная остановка сюда не попадает — init зовёт `steer down`
 * после выхода демона, — а условие по правилам держит от гонки при выключении, когда таблицы уже
 * сняты, а правила ещё нет. Ручной `steerd down` при живом демоне (правила сторож возвращает сам
 * через проход) после этого возвращается и таблицей — прежде движок оставался полусобранным.
 * Выходов с устройством нет (одни zapret и direct) — отличить нечем, и остаётся прежнее «движок
 * снят». Дамп правил — в процессе, rtnetlink, и только когда таблицы нет: проход по здоровому ядру
 * его не делает. */
static int srv_table_flushed(struct ctl_srv *s) {
    if (!s->d.have || !ctl_enabled()) return 0;
    /* Прямо: стоит ли правило хоть у одного выхода. Прежде — «не у всех выходов не хватает правила»,
     * а нехватку у выхода с ПУСТОЙ таблицей rulewd нарочно не считает: после штатного `steer down`
     * (таблицы опустошены, правила сняты) выходило «правила стоят», и сторож возвращал снятое. */
    return rulewd_present(s->d.sp) > 0;
}

static void srv_kcheck(void *arg) {
    struct ctl_srv *s = arg;
    /* Своя изменяющая команда идёт или ждёт очереди — её замена набора правил ещё не запомнена
     * (или уже в полёте), и расхождение с ней не расхождение. Проход при этом и не начинается
     * (srv_busy), но починка, поставленная прошлым проходом, может ждать в очереди. */
    if (!s->on || !s->rec.valid || s->lock_owner || s->lockq) return;
    for (struct conn *c = s->conns; c; c = c->next)
        if (c->resync) return;
    const char *why = "";
    int drift = recon_kernel_drift(&s->rec, &why);
    if (drift == 2 && srv_table_flushed(s)) {
        why = "таблицы ядра steer нет в ядре Linux, а правила выходов стоят — её снял кто-то другой";
        drift = 1;
    }
    if (drift != 1) return;
    long now = loop_now_ms();
    int lan = s->lan_at && s->lan_at >= s->plan_at;
    if (lan && srv_lan_budget(s)) {
        fprintf(stderr, LOG_W "проход сторожа: набор правил в ядре разошёлся с поставленным (%s) "
                              "после пересоздания устройства раздачи — сверка в очереди\n", why);
        srv_resync(s, RESYNC_LAN);
        return;
    }
    /* resync_at[resync_i] — самая старая из последних RESYNC_BURST починок (0 — их было меньше). */
    long oldest = s->resync_at[s->resync_i];
    if (oldest && now - oldest < RESYNC_WINDOW_MS) {
        if (s->resync_said != oldest) {
            s->resync_said = oldest;
            fprintf(stderr, LOG_W "проход сторожа: набор правил в ядре разошёлся с поставленным (%s), "
                    "но починок по сверке уже %d за %ld мин — следующая через %ld с\n", why,
                    RESYNC_BURST, RESYNC_WINDOW_MS / 60000L,
                    (oldest + RESYNC_WINDOW_MS - now + 999) / 1000);
        }
        return;
    }
    fprintf(stderr, LOG_W "проход сторожа: набор правил в ядре разошёлся с поставленным (%s) — "
                          "сверка в очереди\n", why);
    srv_resync(s, RESYNC_PASS);
}

/* ---- устройство раздачи пересоздано: сверка сразу, а не проходом ---------------------------------
 *
 * Проверка на QEMU 04664a5: после `/etc/init.d/network restart`
 * br-lan пересоздан, и цепочку ingress_mark ядро сняло вместе со старым устройством. Прежде её
 * возвращала сверка на проходе сторожа — проход после события сети идёт через WATCH_SETTLE_S, и
 * цепочка возвращалась через 3,6-8,6 с. Теперь сторож разбирает события сети сам (watchd.c,
 * «УСТРОЙСТВА РАЗДАЧИ») и зовёт srv_lan на новый номер устройства раздачи; сверка — тот же reload
 * без соединения, что у прохода (план увидит новое устройство или снятую ядром цепочку, и набор
 * правил встанет одной транзакцией), через LAN_SETTLE_MS: netifd поднимает мосты пачкой (br-lan,
 * гостевой), и на пачку хватает одной сверки. Сверка уже идёт — ещё одна после неё (lan_again):
 * её план мог собраться до нового устройства.
 *
 * Только если раскладка вообще ставит ingress (NFTC_INGRESS; раскладка ещё не известна — сверяем): иначе цепочки нет и возвращать нечего. Пропавшее устройство (up = 0) сверки
 * не зовёт: вешать цепочку не на что, а пересчитать набор без него успеет сверка по появлению — или
 * проход, если устройство ушло насовсем.
 *
 * СВОЙ СЧЁТ, НЕ RESYNC_BURST. Лимит сверок прохода — против того, кто правит нашу таблицу без
 * остановки. Пересоздание моста — законное событие, и три `network restart` за пять минут не
 * должны оставлять четвёртый без цепочки. От шторма (мост, который пересоздаётся по кругу, —
 * сломанный драйвер или скрипт) — свой предел: LAN_RESYNC_BURST сверок за RESYNC_WINDOW_MS, одна
 * строка в журнал на окно; дальше цепочку вернёт проход, как прежде, в пределах RESYNC_BURST. */
#define LAN_SETTLE_MS 300
#define LAN_RESYNC_BURST 20

static int srv_resync_pending(const struct ctl_srv *s) {
    for (const struct conn *c = s->conns; c; c = c->next)
        if (c->resync) return 1;
    return 0;
}

/* Ещё одна сверка по устройствам раздачи в окне: 1 — можно (и посчитана), 0 — предел, строка в
 * журнал одна на окно. */
static int srv_lan_budget(struct ctl_srv *s) {
    long now = loop_now_ms();
    if (!s->lan_win || now - s->lan_win >= RESYNC_WINDOW_MS) { s->lan_win = now; s->lan_n = 0; }
    if (s->lan_n >= LAN_RESYNC_BURST) {
        if (s->lan_said != s->lan_win) {
            s->lan_said = s->lan_win;
            fprintf(stderr, LOG_W "устройства раздачи пересоздают снова и снова (%d раз за %ld мин) — "
                    "дальше цепочку ingress вернёт проход сторожа, не чаще трёх раз за %ld мин\n",
                    LAN_RESYNC_BURST, RESYNC_WINDOW_MS / 60000L, RESYNC_WINDOW_MS / 60000L);
        }
        return 0;
    }
    s->lan_n++;
    return 1;
}

static void srv_lan_timer(struct loop *l, struct loop_timer *t, void *arg) {
    (void)l; (void)t;
    struct ctl_srv *s = arg;
    if (!s->on || !s->d.have || !s->rec.valid) return;
    if (srv_resync_pending(s)) { s->lan_again = 1; return; }
    if (!srv_lan_budget(s)) return;
    fprintf(stderr, LOG_I "устройство раздачи появилось заново — набор правил сверяется с ядром\n");
    srv_resync(s, RESYNC_LAN);
}

static void srv_lan(void *arg, const char *dev, int up) {
    struct ctl_srv *s = arg;
    (void)dev;
    if (!s->on || !s->d.have || !s->lan_tm) return;
    int nftc = s->rec.nftc;
    if (nftc >= 0 && !(nftc & NFTC_INGRESS)) return;
    /* И пропажа, и появление объясняют расхождение, которое найдёт проход (srv_kcheck). */
    s->lan_at = loop_now_ms();
    if (!up) return;
    loop_timer_set(s->lan_tm, LAN_SETTLE_MS);
}

static void ctl_bad_flag(const char *cmd, const char *msg, const char *arg) {
    fprintf(stderr, "steer: %s: %s%s%s\n", cmd, msg, arg ? ": " : "", arg ? arg : "");
    exit(2);
}

void ctl_usage_flags(FILE *out) {
    const struct platform_ops *p = plat();
    fprintf(out,
          "  --socket ФАЙЛ       управляющий сокет (по умолчанию %s)\n"
          "  --spec ФАЙЛ         daemon: спека, которую читают и заменяют команды\n"
          "                      (по умолчанию %s)\n"
          "  --state-dir КАТАЛОГ daemon: каталог состояния (по умолчанию %s)\n"
          "  --allow-uid N       daemon: пускать и этот uid (сколько угодно раз); root и system\n"
          "                      пускаются всегда\n"
          "  --allow-domain ИМЯ  daemon: пускать процессы этого домена SELinux у владельца\n"
          "                      устройства (по умолчанию splify2_app на платформе Android;\n"
          "                      пустое значение — не пускать по домену)\n"
          "  --lists-dir КАТАЛОГ daemon: куда put-file кладёт файлы списков\n"
          "                      (по умолчанию %s)\n"
          "  --watch             daemon: сторожить выходы самому\n"
          "  --watch-period СЕК  daemon: период прохода сторожа в тишине (по умолчанию 60)\n"
          "  --supervise         daemon: держать помощников выходов и резолвер самому (вместо\n"
          "                      procd или steer supervise; оба сразу не запускать)\n"
          "  --dnsd-flag ФЛАГ    daemon: передать резолверу ещё и этот флаг (сколько угодно раз)\n"
          "  --apply             daemon: применить спеку при старте (сверкой, как reload)\n",
          p->ctl_sock, p->spec_path, p->state_dir, p->lists_dir);
}

static int ctl_listen(const struct ctl_conf *cf, ino_t *ino) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if (strlen(cf->sock) >= sizeof(a.sun_path)) ctl_bad_flag("daemon", "слишком длинный путь сокета", cf->sock);
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", cf->sock);

    /* Прежний файл: живой сервер за ним — отказ стартовать (второй сервер отнял бы сокет у
     * первого молча); мёртвый — удалить, это след упавшего или убитого. */
    int t = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (t >= 0) {
        if (connect(t, (struct sockaddr *)&a, sizeof(a)) == 0) {
            close(t);
            fprintf(stderr, LOG_W "на %s уже отвечает другой сервер — второй не нужен\n", cf->sock);
            exit(1);
        }
        close(t);
    }
    unlink(cf->sock);

    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (s < 0) { fprintf(stderr, LOG_W "socket: %s\n", strerror(errno)); exit(1); }
    /* Права 0666 — с рождения, через umask, а не chmod после bind: так нет мгновения, когда
     * файл уже есть, а права у него чужие. Открыто по правам файла нарочно: у приложения свой
     * uid и своя группа, которых заранее не знать, а пускает его не DAC, а SELinux (connectto
     * и метка steerd_socket) и проверка собеседника в ctl_peer_ok. */
    mode_t old = umask(0111);
    int rc = bind(s, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0) {
        fprintf(stderr, LOG_W "не занять %s: %s\n", cf->sock, strerror(errno));
        exit(1);
    }
    if (listen(s, 16) != 0) {
        fprintf(stderr, LOG_W "listen: %s\n", strerror(errno));
        exit(1);
    }
    struct stat sb;
    *ino = stat(cf->sock, &sb) == 0 ? sb.st_ino : 0;
    return s;
}

int ctl_serve_main(int argc, char **argv) {
    static struct ctl_srv S;
    struct ctl_conf *cf = &S.cf;
    cf->sock = plat()->ctl_sock;
    /* spec.json или spec.yaml — какая из двух лежит (plat_spec_default); apply кладёт тело в неё
     * же, какого бы формата тело ни было: формат load_spec узнаёт по содержимому. */
    cf->spec = plat_spec_default();
    cf->lists_dir = plat()->lists_dir;
    cf->allow_domain = plat()->ctl_allow_domain;
    /* Дескрипторы: каждый подписчик и каждый запрос — по одному, а плагинов и подписчиков
     * не ограничено. Мягкий предел поднимается до жёсткого — права для этого не нужны. */
    struct rlimit rl;
    if (getrlimit(RLIMIT_NOFILE, &rl) == 0 && rl.rlim_cur < rl.rlim_max) {
        rl.rlim_cur = rl.rlim_max;
        setrlimit(RLIMIT_NOFILE, &rl);
    }
    for (int i = 0; i < argc; i++) {
        const char *f = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;
        if (!strcmp(f, "--socket") || !strcmp(f, "--spec") || !strcmp(f, "--state-dir") ||
            !strcmp(f, "--allow-uid") || !strcmp(f, "--allow-domain") ||
            !strcmp(f, "--lists-dir")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            if (!strcmp(f, "--socket")) cf->sock = v;
            else if (!strcmp(f, "--spec")) cf->spec = v;
            else if (!strcmp(f, "--state-dir")) cf->state_dir = v;
            else if (!strcmp(f, "--allow-domain")) cf->allow_domain = v;
            else if (!strcmp(f, "--lists-dir")) cf->lists_dir = v;
            else {
                char *e = NULL;
                unsigned long u = strtoul(v, &e, 10);
                if (!*v || *e || u > 0xfffffffful) ctl_bad_flag("daemon", "--allow-uid: нужно число", v);
                uid_t *nu = realloc(cf->allow_uid, ((size_t)cf->allow_uid_n + 1) * sizeof(*nu));
                if (!nu) ctl_bad_flag("daemon", "нет памяти", NULL);
                cf->allow_uid = nu;
                cf->allow_uid[cf->allow_uid_n++] = (uid_t)u;
            }
            continue;
        }
        if (!strcmp(f, "--watch")) { cf->watch = 1; continue; }
        if (!strcmp(f, "--supervise")) { cf->supervise = 1; continue; }
        if (!strcmp(f, "--apply")) { cf->apply = 1; continue; }
        if (!strcmp(f, "--dnsd-flag")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            /* Место и под закрывающий NULL. */
            const char **nf = realloc(cf->dnsd_flags, ((size_t)cf->dnsd_flag_n + 2) * sizeof(*nf));
            if (!nf) ctl_bad_flag("daemon", "нет памяти", NULL);
            cf->dnsd_flags = nf;
            cf->dnsd_flags[cf->dnsd_flag_n++] = v;
            cf->dnsd_flags[cf->dnsd_flag_n] = NULL;
            continue;
        }
        if (!strcmp(f, "--watch-period")) {
            if (!v) ctl_bad_flag("daemon", "у флага нет значения", f);
            i++;
            char *e = NULL;
            long p = strtol(v, &e, 10);
            if (!*v || *e || p < 1 || p > 86400) ctl_bad_flag("daemon", "--watch-period: нужно число 1..86400", v);
            cf->watch_period = (int)p;
            continue;
        }
        ctl_bad_flag("daemon", "неизвестный флаг", f);
    }
    ssize_t el = readlink("/proc/self/exe", cf->exe, sizeof(cf->exe) - 1);
    if (el <= 0) { fprintf(stderr, LOG_W "не найти свой исполняемый файл\n"); return 1; }
    cf->exe[el] = '\0';
    /* Команды в процессе (status, conns, dns-log) читают каталог состояния сами — тот же,
     * что подкомандам передаётся флагом. */
    if (cf->state_dir) steer_set_state_dir(cf->state_dir);
    /* Выбор select — рядом со спекой демона (platform.h, steer_keep_dir): переживает перезагрузку. */
    steer_set_keep_dir_of(plat_spec_resolve(cf->spec));

    /* Запись в ушедший сокет — ошибка send (MSG_NOSIGNAL), а не смерть демона; SIGPIPE
     * игнорируется ещё и ради записи, которую делает код в процессе. Детям он возвращается
     * (loop_child_reset). */
    signal(SIGPIPE, SIG_IGN);
    S.l = loop_new();
    if (!S.l) { fprintf(stderr, LOG_W "цикл событий: %s\n", strerror(errno)); return 1; }
    S.lfd = ctl_listen(cf, &S.ino);
    /* После ctl_listen: живой соседний сервер там уже дал бы отказ стартовать, и временные
     * файлы его обработчиков не тронуты. */
    ctl_lists_sweep(cf->lists_dir);
    recon_init(&S.rec);
    if (steerd_init(&S.d, S.l, cf->spec, cf->state_dir) != 0) {
        fprintf(stderr, LOG_W "нет памяти под спеку\n");
        return 1;
    }
    /* Спека не прочиталась — демон всё равно работает: apply через сокет её и исправляет, а
     * status до тех пор отвечает тем же отказом, что подкоманда. */
    if (steerd_load(&S.d) != 0) fprintf(stderr, LOG_W "спека не прочитана: %s\n", S.d.err);
    S.accept_tm = loop_timer_new(S.l, srv_accept_resume, &S);
    if (!S.accept_tm || loop_fd_add(S.l, S.lfd, EPOLLIN, srv_accept, &S) != 0) {
        fprintf(stderr, LOG_W "цикл событий: %s\n", strerror(errno));
        return 1;
    }
    loop_signal(S.l, SIGTERM, srv_term, &S);
    loop_signal(S.l, SIGINT, srv_term, &S);
    loop_signal(S.l, SIGHUP, srv_hup, &S);
    S.on = ctl_enabled();
    if (cf->watch) {
        struct watchd_conf wc = { cf->watch_period ? cf->watch_period : 60, ctl_enabled,
                                  srv_busy, &S, srv_kcheck, srv_lan };
        S.lan_tm = loop_timer_new(S.l, srv_lan_timer, &S);
        /* С --apply первый проход — после стартового применения (watchd_release в reload_done). */
        S.watch = watchd_start(&S.d, &wc, S.on, cf->apply && S.d.have);
        if (!S.watch) { fprintf(stderr, LOG_W "сторож: нет памяти\n"); return 1; }
        S.snap_tm = loop_timer_new(S.l, srv_snap, &S);
        if (S.snap_tm && S.on) loop_timer_set(S.snap_tm, CTL_SNAP_MS);
        struct rulewd_conf rc = { .busy = srv_rules_busy, .held = srv_rules_held, .repair = srv_repair,
                                  .restored = srv_restored, .arg = &S };
        S.rules = rulewd_start(&S.d, &rc, S.on);
        if (!S.rules) { fprintf(stderr, LOG_W "страж правил: нет памяти\n"); return 1; }
    }
    if (cf->supervise) {
        struct supd_conf sc = { ctl_enabled, cf->dnsd_flags };
        if (!supd_start(&S.d, &sc)) { fprintf(stderr, LOG_W "супервизор: нет памяти\n"); return 1; }
    }
    /* .so-плагины (steer-abi): после супервизора, чтобы host_v1 видел и спеку, и сторожа, и помощников. */
    plugso_boot(&S.d);
    plugauto_start(&S);
    fprintf(stderr, LOG_I "слушаю %s%s%s\n", cf->sock, cf->watch ? ", сторожу выходы" : "",
            cf->supervise ? ", держу помощников" : "");
    if (cf->apply) {
        if (!S.d.have) fprintf(stderr, LOG_W "спеки нет — применять при старте нечего\n");
        else if (boot_apply(&S) != 0) watchd_release(S.watch);
    }
    int rc = loop_run(S.l);
    plugso_fini_all();
    return rc;
}

/* ---- клиент ------------------------------------------------------------------------------------ */

/* `steer ctl [--socket ФАЙЛ] КОМАНДА [СЛОВО...]` — тот же запрос, что пошлёт приложение, для
 * adb root shell и стенда. Тело команд apply, check и sub-check — со стандартного ввода, у
 * put-file — из файла, названного последним словом (`steer ctl put-file ИМЯ ФАЙЛ`; «-» —
 * стандартный ввод): имя в каталоге списков и путь на машине, откуда файл берётся, — разные
 * вещи, и имя из пути не выводится, чтобы залить /sdcard/x.txt под именем yt.lst. Печатает
 * ответ сервера как есть (строка JSON); у subscribe — строки событий по мере прихода, пока
 * демон не закроет соединение. Код: 0 — ответ с "code":0 и без "error"; 1 — иной
 * ответ; 2 — ошибка вызова или нет соединения. */
int ctl_client_main(int argc, char **argv) {
    const char *sock = plat()->ctl_sock;
    int i = 0;
    for (; i < argc; i++) {
        if (!strcmp(argv[i], "--socket")) {
            if (i + 1 >= argc) ctl_bad_flag("ctl", "у флага нет значения", argv[i]);
            sock = argv[++i];
        } else break;
    }
    if (i >= argc) ctl_bad_flag("ctl", "нужна команда", NULL);
    struct cbuf req = {0}, body = {0};
    const struct ctl_cmd *cmd = ctl_lookup(argv[i]);
    static struct ctl_cmd pk;
    if (!cmd && plugin_ctl_cmd(argv[i], &pk) == 0) cmd = &pk;      /* команда плагина: тело — по её манифесту */
    int words = argc, from_fd = 0;
    if (cmd && cmd->body && !strcmp(cmd->name, "put-file")) {
        if (argc - i != 3) ctl_bad_flag("ctl", "put-file: нужны имя и файл (или «-»)", NULL);
        const char *src = argv[argc - 1];
        words = argc - 1;
        if (strcmp(src, "-") != 0) {
            from_fd = open(src, O_RDONLY | O_CLOEXEC);
            if (from_fd < 0) ctl_bad_flag("ctl", "не открыть файл", src);
        }
    }
    for (int k = i; k < words; k++) {
        if (k > i) cb_put(&req, " ", 1);
        cb_str(&req, argv[k]);
    }
    if (cmd && cmd->body) {
        char buf[65536];
        ssize_t m;
        /* Предел клиента — с запасом выше предела сервера: слишком большое тело должен
         * отвергнуть сервер (too-large), а клиент — только не съесть всю память. */
        body.max = 4 * (size_t)CTL_FILE_MAX;
        while ((m = read(from_fd, buf, sizeof(buf))) > 0) cb_put(&body, buf, (size_t)m);
        if (from_fd > 0) close(from_fd);
        if (body.trunc) ctl_bad_flag("ctl", "тело больше 64 МиБ — такое сервер не примет", NULL);
        cb_fmt(&req, " %zu", body.n);
    }
    cb_put(&req, "\n", 1);

    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof(a.sun_path), "%s", sock);
    int s = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (s < 0 || connect(s, (struct sockaddr *)&a, sizeof(a)) != 0) {
        fprintf(stderr, "steer: ctl: нет соединения с %s: %s\n", sock, strerror(errno));
        return 2;
    }
    signal(SIGPIPE, SIG_IGN);
    /* Ошибка записи не повод молчать: сервер мог отказать (слишком большое тело) и закрыть
     * соединение, не читая, — его ответ всё равно лежит в сокете. */
    if (ctl_write_all(s, req.p, req.n) == 0 && body.n) ctl_write_all(s, body.p, body.n);
    shutdown(s, SHUT_WR);
    struct cbuf resp = {0};
    char buf[16384];
    ssize_t m;
    /* ECONNRESET после ответа — не ошибка: сервер отказал, не дочитав запрос (см. ctl_close),
     * а ответ уже прочитан. */
    /* subscribe — поток событий до закрытия: печатать по мере прихода, а не в конце. В
     * памяти копится только первая строка (ответ на сам subscribe) — по ней код выхода. */
    int stream = cmd && cmd->start == st_subscribe;
    while ((m = read(s, buf, sizeof(buf))) > 0 || (m < 0 && errno == EINTR)) {
        if (m <= 0) continue;
        if (!stream) { cb_put(&resp, buf, (size_t)m); continue; }
        fwrite(buf, 1, (size_t)m, stdout);
        fflush(stdout);
        if (!memchr(resp.p ? resp.p : "", '\n', resp.n)) cb_put(&resp, buf, (size_t)m);
    }
    close(s);
    if (!resp.n) { fprintf(stderr, "steer: ctl: сервер закрыл соединение без ответа\n"); return 2; }
    if (!stream) fwrite(resp.p, 1, resp.n, stdout);
    int ok = strstr(resp.p, ",\"code\":0,") && !strstr(resp.p, "\"error\":");
    free(req.p);
    free(body.p);
    free(resp.p);
    return ok ? 0 : 1;
}

