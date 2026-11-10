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
#include <sys/syscall.h>
#include <time.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "run.h"

/* СРОК КОМАНДЫ. Сюда ходят nft, ip и tc из демона — из его единственного цикла событий: применение
 * спеки, сторож выходов, починка правил. Прежде run ждал ребёнка без срока, и nft, повисший на
 * netlink (ядро под нагрузкой, взаимная блокировка с чужим nft, отладчик), останавливал демон
 * целиком: сторож не ходил, помощники не поднимались, сокет управления не отвечал — до перезапуска
 * службы руками. Теперь у команды срок RUN_DEADLINE_MS: команды здесь короткие (самая долгая —
 * `nft -f` набора в десятки тысяч префиксов, секунды на медленном роутере), и вышедшая за минуту
 * уже не ответит. Просрочившая снимается SIGKILL вместе со своей группой процессов (`sh -c` с
 * детьми) и считается неудачей (-1): вызывающие и так разбирают отказ команды. STEER_RUN_DEADLINE_MS
 * — шов стенда (tests/runmatch.c).
 *
 * Ждать — по pidfd (ядро ≥ 5.3): проснуться ровно в миг выхода. Ядро без него — waitpid с шагом
 * 20 мс; это только старые ядра Android, на роутере его нет. */
#define RUN_DEADLINE_MS 60000L

static long run_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* 1 — ребёнок вышел до срока (не пожат), 0 — срок вышел. */
static int run_wait_exit(pid_t p, long deadline) {
#ifdef SYS_pidfd_open
    int pfd = (int)syscall(SYS_pidfd_open, p, 0);
    if (pfd >= 0) {
        int r;
        for (;;) {
            long left = deadline - run_now_ms();
            if (left <= 0) { r = 0; break; }
            struct pollfd q = { .fd = pfd, .events = POLLIN };
            int n = poll(&q, 1, left > 1000000L ? 1000000 : (int)left);
            if (n > 0) { r = 1; break; }
            if (n < 0 && errno != EINTR) { r = 1; break; }   /* poll не работает — ждать без срока */
        }
        close(pfd);
        return r;
    }
#endif
    for (;;) {
        siginfo_t si;
        memset(&si, 0, sizeof(si));
        if (waitid(P_PID, (id_t)p, &si, WEXITED | WNOHANG | WNOWAIT) == 0 && si.si_pid == p) return 1;
        if (run_now_ms() >= deadline) return 0;
        struct timespec ts = { 0, 20 * 1000000L };
        nanosleep(&ts, NULL);
    }
}

int run(const char *const argv[]) {
    pid_t p = fork();
    if (p < 0) return -1;
    if (p == 0) {
        /* Своя группа процессов: по сроку снимается команда вместе с её детьми. */
        setpgid(0, 0);
        /* Both streams: `nft get element` prints the whole set on success, which
         * would otherwise land in the middle of explain's answer. */
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        /* SIG_IGN переживает execve: модульные команды выключают SIGPIPE (cli/modcmd.c), и без
         * сброса его унаследовали бы nft, ip и загрузчик подписок. */
        signal(SIGPIPE, SIG_DFL);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    setpgid(p, p);                        /* и здесь: kill(-p) не должен опередить setpgid ребёнка */
    long limit = RUN_DEADLINE_MS;
    const char *e = getenv("STEER_RUN_DEADLINE_MS");
    if (e && atol(e) > 0) limit = atol(e);
    int late = !run_wait_exit(p, run_now_ms() + limit);
    if (late) {
        kill(-p, SIGKILL);
        kill(p, SIGKILL);
        fprintf(stderr, "steer[warn] команда «%s» не ответила за %ld с — снята\n", argv[0],
                (limit + 999) / 1000);
    }
    int st = 0;
    while (waitpid(p, &st, 0) < 0 && errno == EINTR) {}
    if (late) return -1;
    return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}

int run_quiet(const char *const argv[]) { return run(argv); }
