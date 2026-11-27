#include "dnsd_int.h"
#include "tabfmt.h"
#include "table_ack.h"
#include <poll.h>
#include <syslog.h>             /* константы LOG_*; сам syslog(3) не зовётся (stderr_rescue) */

/* ---- управляющий сокет резолвера: новый демон забирает живой резолвер ------------------------
 *
 * ЗАЧЕМ. Резолвер — ребёнок демона (src/daemon/supd.c) и прежде выходил, как только закрывалась
 * труба таблицы. Падение демона (kill -9, OOM) уносило поэтому и резолвер, и до перезапуска
 * procd (~5 с) DNS клиентов, завёрнутый на резолвер, не отвечал вовсе. Проверка 1.8 на
 * QEMU-роутере. Теперь EOF трубы — «демона нет» (proxy.c,
 * table_pipe_lost): резолвер отвечает по последней таблице, а новый демон, поднявшись, находит
 * его здесь и забирает.
 *
 * КАК ЗАБИРАЕТ — НОВОЙ ТРУБОЙ ЧЕРЕЗ SCM_RIGHTS, а не таблицей по этому сокету. Демон заводит
 * трубу, как для ребёнка, и отдаёт резолверу её конец чтения; дальше таблица идёт по трубе тем
 * же кодом, что у только что запущенного резолвера (tab_send в supd.c, tabfmt_feed здесь), и
 * смерть демона видна тем же EOF. Таблица по сокету дала бы второй путь с той же обязанностью:
 * свой разбор кадров, свою очередь у демона и свой признак смерти хозяина — и расходиться этим
 * путям было бы с чего. Сокет несёт одну просьбу, и её легко проверить целиком.
 *
 * НАЙТИ — ПО ИМЕНИ: <каталог состояния>/dnsd-ctl.sock (DNSD_CTL_SOCK, tabfmt.h). Pidfile не
 * нужен: подключение и есть проверка «жив ли», а pid собеседника даёт SO_PEERCRED. Сокет
 * отдельный от журнала имён (dlog.c): тот отвечает сразу и ничего не читает, этот ждёт просьбу.
 *
 * ПРОТОКОЛ. Демон подключается и пишет «adopt\n» с дескрипторами в SCM_RIGHTS: первый — конец
 * чтения новой трубы таблицы, второй (необязательный) — его stderr: прежний, унаследованный от
 * умершего демона, ведёт в трубу журнала, которую procd уже закрыл. Ответ — «ok\n» (труба взята)
 * или «busy\n» (у резолвера живой хозяин — его труба открыта; proxy.c, table_pipe_take).
 * Соединение после «ok» остаётся открытым до выхода резолвера: по его закрытию демон узнаёт, что
 * не своего ребёнка больше нет (выход не своего ребёнка waitpid не покажет). Всё прочее, в том
 * числе подключение без просьбы (демон спросил только pid, чтобы погасить), просто закрывается.
 *
 * ВТОРАЯ ПРОСЬБА — «down\n»: её шлёт `steerd down` (src/daemon/apply.c, cmd_down; сам разговор —
 * supd_orphan_down в supd.c). Остановка службы в окне после падения демона — kill -9, и сразу
 * stop, пока procd не поднял его снова (~5 с), — не находила резолвер ничем: stop_service берёт
 * pid экземпляра из ubus, а экземпляра в этот миг нет. Таблицу снимал `steerd down`, а резолвер
 * жил ещё до 60 с на своём порту, дожидаясь демона, которого уже не будет. Ответ — «ok\n», если
 * хозяина нет (труба таблицы закрыта): резолвер выходит штатно, сокет снимает сам, соединение
 * закрывается его выходом; «busy\n» — хозяин жив, и резолвер остаётся: `steer down` руками при
 * живом демоне не должен гасить то, что демон держит и поднял бы заново. Решает сам резолвер, а
 * не спрашивающий: только он знает, открыта ли его труба.
 *
 * ТРЕТЬЯ ПРОСЬБА — «reassert\n»: её шлёт загрузчик набора правил (ребёнок демона apply-commit или
 * подкоманда `steer apply`) сразу после nft -f (supd_dnsd_reassert в supd.c; зачем — у
 * ruleset_load в src/daemon/apply.c). Резолвер возвращает в новые наборы элементы real-ip из своей
 * памяти (realip_reassert) и отвечает «ok\n»; соединение закрывается. Хозяина она не требует и
 * ничем его не меняет — просит её не демон, а тот, кто только что заменил таблицу.
 *
 * ЧЕТВЁРТАЯ ПРОСЬБА — «flush\n»: её шлёт тот же загрузчик прямо перед засевом карты и наборов
 * fake-IP из файла состояния (supd_dnsd_flush в supd.c, зовёт ruleset_load в src/daemon/apply.c).
 * Резолвер записывает файл, если в памяти есть незаписанное (fakeip_state_flush), и отвечает
 * «ok\n» уже после записи; соединение закрывается. Зачем — у fakeip_state_flush в fakeip.c:
 * перезапись по сроку отставала от памяти до минуты, и засев ставил в новую таблицу имена без
 * подмены и прежние адреса. Хозяина не требует, как и «reassert».
 *
 * ДОСТУП — как у журнала: каталог состояния 0700, сокет 0600 с рождения, собеседник сверяется
 * по SO_PEERCRED — root или тот же uid, что у резолвера (на роутере и телефоне оба — root).
 *
 * ГДЕ ЭТО НЕ ПОМОГАЕТ. На телефоне init при смерти службы гасит всю группу её процессов, и
 * резолвер уходит вместе с демоном; новый демон подключения не находит и поднимает свой резолвер,
 * как прежде. На роутере procd, насколько известно, после падения экземпляра поднимает его снова
 * и прочих процессов не трогает — это проверяется на QEMU-роутере. */
int g_adopt_fd = -1;          /* слушающий */
int g_adopt_conn = -1;        /* принятый, ждёт просьбы */
int g_adopt_owner = -1;       /* соединение нынешнего хозяина (после «ok») */
static char g_adopt_path[PATH_MAX];
static ino_t g_adopt_ino;
static int g_adopt_leaving;   /* просьба «down» принята — резолвер выходит на этом обороте */

#ifndef MSG_CMSG_CLOEXEC
#define MSG_CMSG_CLOEXEC 0x40000000
#endif

void adopt_listen(void) {
    struct sockaddr_un a;
    memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    if ((size_t)snprintf(g_adopt_path, sizeof(g_adopt_path), "%s/" DNSD_CTL_SOCK,
                         steer_state_dir()) >= sizeof(a.sun_path)) {
        fprintf(stderr, "steer[warn] dnsd: путь управляющего сокета слишком длинный — "
                        "новый демон резолвер не заберёт\n");
        g_adopt_path[0] = '\0';
        return;
    }
    memcpy(a.sun_path, g_adopt_path, strlen(g_adopt_path) + 1);   /* длина сверена выше */
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return;
    /* Прежний файл — от упавшего резолвера: живого демон погасил бы до запуска нового. */
    unlink(g_adopt_path);
    mode_t old = umask(0177);
    int rc = bind(fd, (struct sockaddr *)&a, sizeof(a));
    umask(old);
    if (rc != 0 || listen(fd, 2) != 0) {
        fprintf(stderr, "steer[warn] dnsd: управляющий сокет %s: %s — новый демон резолвер не "
                        "заберёт\n", g_adopt_path, strerror(errno));
        close(fd);
        g_adopt_path[0] = '\0';
        return;
    }
    struct stat sb;
    g_adopt_ino = stat(g_adopt_path, &sb) == 0 ? sb.st_ino : 0;
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_adopt_fd;
    g_adopt_fd = fd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev) != 0) {
        close(fd);
        g_adopt_fd = -1;
        unlink(g_adopt_path);
        g_adopt_path[0] = '\0';
    }
}

static void conn_drop(int *slot) {
    if (*slot < 0) return;
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, *slot, NULL);
    close(*slot);
    *slot = -1;
}

void adopt_close(void) {
    conn_drop(&g_adopt_conn);
    conn_drop(&g_adopt_owner);
    if (g_adopt_fd < 0) return;
    close(g_adopt_fd);
    g_adopt_fd = -1;
    struct stat sb;
    if (g_adopt_path[0] && g_adopt_ino && stat(g_adopt_path, &sb) == 0 && sb.st_ino == g_adopt_ino)
        unlink(g_adopt_path);
}

void adopt_accept(void) {
    for (int k = 0; k < 4; k++) {
        int c = accept(g_adopt_fd, NULL, NULL);
        if (c < 0) return;
        fcntl(c, F_SETFD, FD_CLOEXEC);
        fcntl(c, F_SETFL, fcntl(c, F_GETFL) | O_NONBLOCK);
        struct dnsd_ucred uc;
        socklen_t l = sizeof(uc);
        if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &uc, &l) != 0 ||
            (uc.uid != 0 && uc.uid != geteuid())) {
            close(c);
            continue;
        }
        /* Резолвер уже уходит по просьбе «down»: её соединение открыто до выхода (его закрытие
         * спрашивающему и есть «вышел»), и снимать его ради нового незачем. */
        if (g_adopt_leaving) { close(c); continue; }
        /* Ждёт просьбы одно соединение: демон пишет её сразу после connect, а второе подряд —
         * это уже следующий демон (или прежний, спросивший только pid). Но прежде чем снять
         * ждущее, его надо дочитать: просьбу «reassert» шлёт загрузчик набора правил, и её законно
         * застать рядом с «adopt» стартующего демона. Обе пишутся сразу после connect, так что к
         * этому мигу первая обычно уже лежит в сокете, а снять «adopt» непрочитанным значило бы
         * отказать демону в резолвере — он погасил бы живой и поднял свой. */
        if (g_adopt_conn >= 0) adopt_conn_event(&g_adopt_conn);
        if (g_adopt_leaving) { close(c); continue; }
        conn_drop(&g_adopt_conn);
        struct epoll_event ev = {0};
        ev.events = EPOLLIN;
        ev.data.ptr = &g_adopt_conn;
        if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, c, &ev) != 0) { close(c); continue; }
        g_adopt_conn = c;
    }
}

static void say(int fd, const char *s) {
    ssize_t w = send(fd, s, strlen(s), MSG_NOSIGNAL | MSG_DONTWAIT);
    (void)w;
}

void adopt_conn_event(int *slot) {
    if (*slot < 0) return;
    if (slot == &g_adopt_owner) {
        /* Хозяин ничего не пишет после «ok»: читаемость — это его выход (EOF). */
        char b[64];
        ssize_t m = recv(*slot, b, sizeof(b), MSG_DONTWAIT);
        if (m == 0 || (m < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
            conn_drop(slot);
        return;
    }
    char buf[32];
    union { struct cmsghdr h; char b[CMSG_SPACE(2 * sizeof(int))]; } cm;
    struct iovec iov = { buf, sizeof(buf) - 1 };
    struct msghdr mh;
    memset(&mh, 0, sizeof(mh));
    mh.msg_iov = &iov;
    mh.msg_iovlen = 1;
    mh.msg_control = cm.b;
    mh.msg_controllen = sizeof(cm.b);
    ssize_t m = recvmsg(*slot, &mh, MSG_DONTWAIT | MSG_CMSG_CLOEXEC);
    if (m < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
    int fds[2] = { -1, -1 };
    size_t nfd = 0;
    for (struct cmsghdr *c = m > 0 ? CMSG_FIRSTHDR(&mh) : NULL; c; c = CMSG_NXTHDR(&mh, c)) {
        if (c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS) continue;
        size_t n = (c->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        for (size_t i = 0; i < n; i++) {
            int fd;
            memcpy(&fd, CMSG_DATA(c) + i * sizeof(int), sizeof(int));
            if (nfd < 2) fds[nfd++] = fd;
            else close(fd);
        }
    }
    if (m == 9 && !memcmp(buf, "reassert\n", 9)) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        /* Набор правил только что заменён (просьбу шлёт загрузчик сразу после nft -f, supd.c,
         * supd_dnsd_reassert): наборы каналов пришли в новой таблице без элементов real-ip, а
         * их память — только здесь. Вернуть их сейчас, по нынешней таблице каналов, а не ждать
         * таблицы от демона: она придёт, лишь когда ребёнок-загрузчик выйдет, и перед проходом
         * резолвер ещё перечитает списки. Имена наборов у неизменившихся каналов те же, и
         * элементы встают в новые наборы; у переименованных вставка отказывает (набора с
         * прежним именем нет) — их вернёт проход после таблицы, как прежде. Поддельные адреса
         * здесь не ставятся: новый набор правил принёс их сам (засев, src/dnsd/fpseed.c). */
        size_t n = realip_reassert();
        if (n)
            fprintf(stderr, "steer dnsd: real-ip: %zu element(s) re-asserted right after the "
                            "ruleset load\n", n);
        say(*slot, "ok\n");
        conn_drop(slot);
        return;
    }
    if (m == 6 && !memcmp(buf, "flush\n", 6)) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        /* Загрузчик сейчас засеет карту и наборы из файла состояния (fpseed.c): файл обязан
         * быть тем, что знает память, а не тем, что было до минуты назад (fakeip_state_flush). */
        fakeip_state_flush();
        say(*slot, "ok\n");
        conn_drop(slot);
        return;
    }
    if (m == 5 && !memcmp(buf, "down\n", 5)) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        if (table_pipe_release() != 0) {
            say(*slot, "busy\n");
            conn_drop(slot);
            return;
        }
        g_adopt_leaving = 1;
        stderr_rescue();
        fprintf(stderr, "steer[info] dnsd: служба остановлена без демона (steerd down) — "
                        "выхожу\n");
        say(*slot, "ok\n");
        /* Соединение остаётся открытым до выхода: его закрытие спрашивающему и есть «вышел». */
        return;
    }
    struct stat sb;
    int ok = m == 6 && !memcmp(buf, "adopt\n", 6) && nfd >= 1 && !(mh.msg_flags & MSG_CTRUNC) &&
             fstat(fds[0], &sb) == 0 &&
             (S_ISFIFO(sb.st_mode) || (S_ISSOCK(sb.st_mode) && table_ack_is_socket(fds[0])));
    if (!ok) {
        for (size_t i = 0; i < nfd; i++) close(fds[i]);
        conn_drop(slot);
        return;
    }
    long waited = 0;
    if (table_pipe_take(fds[0], &waited) != 0) {
        close(fds[0]);
        if (fds[1] >= 0) close(fds[1]);
        say(*slot, "busy\n");
        conn_drop(slot);
        return;
    }
    if (fds[1] >= 0) {
        /* После stderr_rescue fd 2 — конец записи своей трубы в syslog: dup2 его закрывает,
         * slog_stop дочитывает то, что в трубе осталось, и убирает её конец чтения из epoll.
         * dup2 не удался — труба остаётся, и строка об этом уйдёт в syslog. */
        if (dup2(fds[1], 2) < 0)
            fprintf(stderr, "steer[warn] dnsd: stderr нового демона не взят: %s\n", strerror(errno));
        else
            slog_stop();
        close(fds[1]);
    }
    fprintf(stderr, "steer[info] dnsd: новый демон забрал резолвер (без демона — %ld с)\n", waited);
    say(*slot, "ok\n");
    /* Соединение — теперь хозяина: прежнего (умершего демона) закрыть, это перевести. */
    conn_drop(&g_adopt_owner);
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_adopt_owner;
    g_adopt_owner = *slot;
    *slot = -1;
    if (epoll_ctl(g_epfd, EPOLL_CTL_MOD, g_adopt_owner, &ev) != 0) {
        close(g_adopt_owner);
        g_adopt_owner = -1;
    }
}

/* ---- stderr резолвера без демона ----------------------------------------------------------------
 *
 * ЗАЧЕМ. stderr резолвера — унаследованный от демона конец трубы журнала procd (`procd_set_param
 * stderr 1`). Пережив демон, резолвер пишет в ту же трубу, и пока procd держит экземпляр, строки
 * доходят до logread. Остановили службу — procd закрывает свой конец, и всё, что резолвер скажет
 * потом («нового демона нет 60 с — выхожу», «служба остановлена без демона»), уходит в EPIPE
 * (SIGPIPE резолвер не слушает) — то есть ровно те строки, по которым видно, куда делся резолвер,
 * в журнал не попадали (проверка долгов на QEMU-роутере).
 *
 * ЧТО БЫЛО. Первая починка делала fd 2 датаграммным сокетом /dev/log прямо: строка stderr уходила
 * датаграммой как есть, без заголовка `<PRI>`. Комментарий обещал, что syslog даст ей user.notice,
 * но logd OpenWrt так не делает: приоритет без заголовка у него 0, и перепроверка на QEMU-роутере
 * (2026-09-28) показала в logread `kern.emerg steer[info] dnsd: служба остановлена без демона …` —
 * самый тяжёлый уровень у самой мирной строки. И второе, чего тогда не заметили: небуферизованный
 * stderr печатает fprintf не одним write. musl (OpenWrt) подменяет буфер своим, в 80 байт
 * (vfprintf, internal_buf), и длинный кусок формата пишет мимо него; glibc пишет кусками через свой
 * малый буфер. strace на строке «демон пропал … жду нового демона %d с»: musl 1.2.4 — два writev,
 * 179 и 6 байт (до %d и остаток), glibc 2.39 — два write, 128 и 57. У датаграмм граница записи и
 * есть граница сообщения, так что такая строка приходила бы в журнал двумя обрывками, и второй —
 * без «steer[…] dnsd:», по которому её ищут.
 *
 * КАК ТЕПЕРЬ. Запись в трубу без читателя poll отмечает POLLERR — это и проверяется, без записи
 * пробы, перед каждой строкой, которую резолвер может сказать уже без читателя stderr (proxy.c:
 * демон пропал, срок ожидания нового вышел; просьба «down» ниже); стоит один poll, строки редки.
 * Сломан — fd 2 становится концом записи СВОЕЙ трубы, неблокирующей, а конец чтения заводится в
 * epoll резолвера (g_slog_rd; обработчик — slog_pump, из цикла run_proxy). Обработчик режет
 * прочитанное на строки по '\n' и каждую шлёт одной датаграммой в /dev/log с заголовком, какой
 * ставит syslog(3): `<PRI>Mmm dd hh:mm:ss steer[pid]: текст`. Труба, а не socketpair SOCK_DGRAM:
 * у датаграмм обрывки одного fprintf стали бы отдельными сообщениями, а поток склеивает их обратно,
 * и граница строки — '\n', который fprintf ставит сам. Резолвер однопоточный, и все куски одного
 * fprintf лежат в трубе раньше, чем цикл событий до неё доберётся, — и разбор по '\n' строку не
 * разрежет. Перехват же нужен на ВСЕ строки stderr (их по коду резолвера сотни: после «демон
 * пропал» резолвер ещё до 60 с отвечает клиентам и может сказать что угодно), поэтому fd 2 и
 * подменяется целиком, а не обёртываются вызовы.
 *
 * Уровень — по началу строки, по тем же словам, что читает человек: `steer[warn]` — LOG_WARNING,
 * `steer[info]` — LOG_INFO, `steer[err]`/`steer[error]` — LOG_ERR, прочее («steer dnsd: …»,
 * «nftlk: …») — LOG_NOTICE, как выходит у logger(1) без -p. Facility — LOG_USER. Текст строки
 * остаётся целым, с тем же «steer[…] dnsd:» в начале: по нему строку ищут и в stderr демона, и в
 * logread. Метка времени — местная (как у glibc; syslog(3) musl 1.2.5 берёт gmtime_r, UTC — но
 * logd и journald метку клиента всё равно отбрасывают), месяц — английскими
 * буквами из своей таблицы, а не strftime %b: %b зависит от локали, а разбор logd и journald
 * проверяет буквы и разделители на местах. logd OpenWrt снимает метку по разделителям (buf[3] ' ',
 * [6] ' ', [9] ':', [12] ':', [15] ' ') и ставит своё время приёма; journald
 * (syslog_skip_timestamp) — по той же раскладке; syslogd busybox — так же, и без -t печатает её.
 * День — с пробелом-заполнителем (как %e), иначе смещения разделителей съехали бы у дней 1-9.
 * Проверено: tests/supdmatch.sh ловит датаграммы своим приёмником и разбирает их по правилам
 * logd и journald (строка «демон пропал» там же — та, что glibc пишет двумя write, — приходит
 * целой); syslogd busybox 1.36, поднятый на своём /dev/log в отдельном пространстве имён
 * монтирования, показал эти строки как user.warn, user.info и user.notice с тегом steer[pid] —
 * а строку прежнего вида, без заголовка, как user.notice: отсюда и ошибка прежнего комментария,
 * у logd OpenWrt умолчание другое.
 *
 * ГРАНИЦЫ. Запись в трубу неблокирующая: переполнится (64 КБ строк, а цикл их не вычитал) —
 * строка теряется, но резолвер не встаёт на записи в stderr. logd занят (EAGAIN) — строка тоже
 * теряется; logd перезапущен (ECONNREFUSED и прочие «соединения нет») — переподключиться и
 * повторить один раз, как делает syslog(3) musl. Строка длиннее буфера (1024 байта — столько же
 * syslog(3) musl отводит на всё сообщение) уходит кусками. Перед выходом резолвера (оба пути:
 * срок ожидания нового демона и «down») остаток трубы дочитывается и уходит в журнал —
 * slog_stop в конце run_proxy: последняя строка («… — выхожу») пишется прямо перед выходом из
 * цикла, и без слива терялась бы именно она. Новый демон забрал резолвер («adopt» ниже) — fd 2
 * заменён его stderr, труба дочитывается, конец чтения уходит из epoll и закрывается: дальше
 * строки идут демону, как у своего ребёнка.
 *
 * НЕТ /dev/log (стенд, телефон — там резолвер и не переживает демон) — fd 2 становится /dev/null,
 * как и прежде: писать в сломанную трубу всё равно некуда. Путь сокета — шов стенда
 * STEER_SYSLOG_SOCK (tests/supdmatch.sh подставляет свой приёмник): в системный журнал машины
 * стенд писать не должен. */
int g_slog_rd = -1;                     /* конец чтения трубы stderr; в epoll под &g_slog_rd */
static int g_slog_sock = -1;            /* датаграммный сокет syslog, connect'нут */
static struct sockaddr_un g_slog_addr;
static char g_slog_buf[1024];           /* недописанная строка */
static size_t g_slog_len;

/* Дескриптор 0-2 (у резолвера мог быть закрыт fd 2 — POLLNVAL — и тогда pipe/socket вернули бы
 * его) — выше: fd 2 займёт конец записи, и затереть им свой же сокет или конец чтения нельзя. */
static int fd_high(int fd) {
    if (fd < 0 || fd > 2) return fd;
    int n = fcntl(fd, F_DUPFD_CLOEXEC, 3);
    close(fd);
    return n;
}

static int slog_lost_conn(int e) {
    return e == ECONNREFUSED || e == ECONNRESET || e == ENOTCONN || e == EPIPE;
}

static void slog_send(const char *s, size_t n) {
    if (g_slog_sock < 0 || n == 0) return;
    static const char mon[12][4] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    int lvl = LOG_NOTICE;
    if (n >= 11 && !memcmp(s, "steer[warn]", 11)) lvl = LOG_WARNING;
    else if (n >= 11 && !memcmp(s, "steer[info]", 11)) lvl = LOG_INFO;
    else if ((n >= 10 && !memcmp(s, "steer[err]", 10)) ||
             (n >= 12 && !memcmp(s, "steer[error]", 12))) lvl = LOG_ERR;
    time_t now = time(NULL);
    struct tm tm;
    if (!localtime_r(&now, &tm)) memset(&tm, 0, sizeof(tm));
    char m[64 + sizeof(g_slog_buf)];
    int h = snprintf(m, sizeof(m), "<%d>%s %2d %02d:%02d:%02d steer[%ld]: ", LOG_USER | lvl,
                     mon[(unsigned)tm.tm_mon % 12], tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                     (long)getpid());
    if (h < 0 || (size_t)h >= sizeof(m)) return;
    if (n > sizeof(m) - (size_t)h) n = sizeof(m) - (size_t)h;
    memcpy(m + h, s, n);
    size_t l = (size_t)h + n;
    if (send(g_slog_sock, m, l, MSG_DONTWAIT | MSG_NOSIGNAL) >= 0 || !slog_lost_conn(errno))
        return;
    if (connect(g_slog_sock, (struct sockaddr *)&g_slog_addr, sizeof(g_slog_addr)) == 0) {
        ssize_t w = send(g_slog_sock, m, l, MSG_DONTWAIT | MSG_NOSIGNAL);
        (void)w;
    }
}

/* Вычитать трубу до EAGAIN и отправить целые строки; flush — и недописанный хвост (выход,
 * adopt). 1 — писателей не осталось (EOF), 0 — труба жива. */
static int slog_read(int flush) {
    int eof = 0;
    while (g_slog_rd >= 0) {
        ssize_t r = read(g_slog_rd, g_slog_buf + g_slog_len, sizeof(g_slog_buf) - g_slog_len);
        if (r < 0 && errno == EINTR) continue;
        if (r <= 0) { eof = r == 0; break; }
        g_slog_len += (size_t)r;
        size_t off = 0;
        for (char *nl; (nl = memchr(g_slog_buf + off, '\n', g_slog_len - off)); ) {
            slog_send(g_slog_buf + off, (size_t)(nl - (g_slog_buf + off)));
            off = (size_t)(nl - g_slog_buf) + 1;
        }
        if (off == 0 && g_slog_len == sizeof(g_slog_buf)) {
            slog_send(g_slog_buf, g_slog_len);          /* строка длиннее буфера — кусками */
            off = g_slog_len;
        }
        memmove(g_slog_buf, g_slog_buf + off, g_slog_len - off);
        g_slog_len -= off;
    }
    if ((flush || eof) && g_slog_len) {
        slog_send(g_slog_buf, g_slog_len);
        g_slog_len = 0;
    }
    return eof;
}

void slog_stop(void) {
    if (g_slog_rd < 0) return;
    slog_read(1);
    epoll_ctl(g_epfd, EPOLL_CTL_DEL, g_slog_rd, NULL);
    close(g_slog_rd);
    g_slog_rd = -1;
    if (g_slog_sock >= 0) close(g_slog_sock);
    g_slog_sock = -1;
    g_slog_len = 0;
}

void slog_pump(void) {
    /* EOF — писателей трубы больше нет (fd 2 заменён не через adopt): держать конец чтения в
     * epoll незачем, он будил бы цикл без конца. */
    if (slog_read(0)) slog_stop();
}

/* Своя труба stderr → syslog: конец записи (для fd 2) или -1 — syslog нет, и тогда /dev/null. */
static int slog_open(void) {
    const char *path = getenv("STEER_SYSLOG_SOCK");
    if (!path || !*path) path = "/dev/log";
    memset(&g_slog_addr, 0, sizeof(g_slog_addr));
    g_slog_addr.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(g_slog_addr.sun_path) || g_epfd < 0) return -1;
    memcpy(g_slog_addr.sun_path, path, strlen(path) + 1);
    int s = fd_high(socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
    if (s < 0) return -1;
    if (connect(s, (struct sockaddr *)&g_slog_addr, sizeof(g_slog_addr)) != 0) {
        close(s);
        return -1;
    }
    int p[2];
    if (pipe(p) != 0) {
        close(s);
        return -1;
    }
    int rd = fd_high(p[0]);
    int wr = p[1];
    if (rd < 0) {
        close(wr);
        close(s);
        return -1;
    }
    fcntl(rd, F_SETFD, FD_CLOEXEC);
    fcntl(wr, F_SETFD, FD_CLOEXEC);     /* dup2 на fd 2 этот флаг снимет — там он и не нужен */
    /* O_NONBLOCK — на описании трубы, общем для обоих концов: и чтение до EAGAIN, и запись,
     * которая при переполнении теряет строку, а не стоит. */
    fcntl(rd, F_SETFL, fcntl(rd, F_GETFL) | O_NONBLOCK);
    fcntl(wr, F_SETFL, fcntl(wr, F_GETFL) | O_NONBLOCK);
    struct epoll_event ev = {0};
    ev.events = EPOLLIN;
    ev.data.ptr = &g_slog_rd;
    if (epoll_ctl(g_epfd, EPOLL_CTL_ADD, rd, &ev) != 0) {
        close(rd);
        close(wr);
        close(s);
        return -1;
    }
    g_slog_rd = rd;
    g_slog_sock = s;
    g_slog_len = 0;
    return wr;
}

void stderr_rescue(void) {
    struct pollfd p = { 2, POLLOUT, 0 };
    if (poll(&p, 1, 0) != 1 || !(p.revents & (POLLERR | POLLHUP | POLLNVAL))) return;
    /* Своя труба сломаться не может, пока жив её конец чтения, — значит, прежней нет; но если
     * есть, она уже не fd 2 и держать её незачем. */
    slog_stop();
    int fd = slog_open();
    if (fd < 0) fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
    if (fd < 0) return;
    /* fd 2 был закрыт вовсе (POLLNVAL) — новый дескриптор и есть 2 (dup2 снял бы с него же
     * FD_CLOEXEC — здесь это надо сделать самому). */
    if (fd == 2) {
        fcntl(2, F_SETFD, 0);
        return;
    }
    dup2(fd, 2);
    close(fd);
}
