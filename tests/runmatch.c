/* run()/run_quiet() (src/lib/run.c): ребёнок получает SIGPIPE по умолчанию, даже если у самого
 * процесса он выключен. Модульные команды выключают SIGPIPE (cli/modcmd.c), а SIG_IGN переживает
 * execve: без сброса nft, ip и загрузчик подписок, запущенные модулем, наследовали бы его.
 *
 * Второе — срок: повисшая команда (nft на netlink) не держит вызывающего дольше срока, снимается
 * вместе со своими детьми, и это отказ (-1); код выхода уложившейся команды — прежний. */
#include "run.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

static int deadline_checks(void) {
    int bad = 0;
    setenv("STEER_RUN_DEADLINE_MS", "300", 1);
    char pidf[] = "/tmp/runmatch-pid.XXXXXX";
    int fd = mkstemp(pidf);
    if (fd < 0) { perror("mkstemp"); return 1; }
    close(fd);
    char cmd[160];
    /* Внук (sleep в фоне) пишет свой pid: снят должен быть и он, а не только sh. */
    snprintf(cmd, sizeof cmd, "sleep 30 & echo $! > %s; wait", pidf);
    const char *const hang[] = { "sh", "-c", cmd, NULL };
    long t0 = now_ms();
    int rc = run(hang);
    long dt = now_ms() - t0;
    printf("run: повисшая команда — rc=%d за %ld мс\n", rc, dt);
    if (rc != -1) { printf("повисшая команда — отказ -1 ПРОВАЛ\n"); bad = 1; }
    if (dt > 3000) { printf("повисшая команда снята по сроку (≤ 3 с) ПРОВАЛ\n"); bad = 1; }
    FILE *f = fopen(pidf, "r");
    long gp = 0;
    if (f) { if (fscanf(f, "%ld", &gp) != 1) gp = 0; fclose(f); }
    unlink(pidf);
    struct timespec ts = { 0, 100 * 1000000L };
    nanosleep(&ts, NULL);
    if (gp > 0 && kill((pid_t)gp, 0) == 0) {
        printf("её ребёнок (sleep, pid %ld) снят вместе с ней ПРОВАЛ\n", gp);
        kill((pid_t)gp, SIGKILL);
        bad = 1;
    }
    const char *const quick[] = { "sh", "-c", "exit 3", NULL };
    rc = run(quick);
    if (rc != 3) { printf("уложившаяся в срок команда отдаёт свой код (3, а не %d) ПРОВАЛ\n", rc); bad = 1; }
    unsetenv("STEER_RUN_DEADLINE_MS");
    if (!bad) printf("срок команды: повисшая снята с детьми за %ld мс, код уложившейся прежний ok\n", dt);
    return bad;
}

int main(void) {
    char path[] = "/tmp/runmatch.XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { perror("mkstemp"); return 2; }
    close(fd);
    signal(SIGPIPE, SIG_IGN);
    char cmd[128];
    snprintf(cmd, sizeof cmd, "grep '^SigIgn:' /proc/self/status > %s", path);
    const char *const argv[] = { "sh", "-c", cmd, NULL };
    int rc = run(argv);
    unsigned long long mask = 0;
    FILE *f = fopen(path, "r");
    char line[64];
    if (f && fgets(line, sizeof line, f)) sscanf(line, "SigIgn: %llx", &mask);
    if (f) fclose(f);
    unlink(path);
    int ignored = (int)((mask >> 12) & 1);              /* SIGPIPE — сигнал 13, бит 12 */
    printf("run: ребёнок запущен (rc=%d), SigIgn=%llx\n", rc, mask);
    printf("ребёнок run() получает SIGPIPE по умолчанию, а не игнорируемый %s\n", ignored ? "ПРОВАЛ" : "ok");
    int bad = deadline_checks();
    return rc != 0 || ignored || bad;
}
