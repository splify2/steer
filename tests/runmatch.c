/* run()/run_quiet() (src/lib/run.c): ребёнок получает SIGPIPE по умолчанию, даже если у самого
 * процесса он выключен. Модульные команды выключают SIGPIPE (cli/modcmd.c), а SIG_IGN переживает
 * execve: без сброса nft, ip и загрузчик подписок, запущенные модулем, наследовали бы его. */
#include "run.h"
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

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
    return rc != 0 || ignored;
}
