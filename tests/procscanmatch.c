/* Обход /proc (src/lib/procscan.c): искомое в хвосте длинной командной строки находится.
 *
 * Раньше читались первые 511 байт командной строки, и `--qnum=N` в хвосте длинной (обработчик с
 * длинным списком путей) оставался невидимым: сторож и diag считали очередь без слушателя (I-525).
 * Дочерний процесс — sh с четырьмя тысячами байт заполнителя и --qnum=<номер> в самом конце; номер
 * свой у каждого запуска, чтобы искомое не нашлось в чужой командной строке (в том числе в той, что
 * запустила стенд). */
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#include "procscan.h"
#include "unit.h"

int main(void) {
    static char pad[4096 + 1];
    char want[64], prefix[64], other[64];
    int q = 10000 + (int)(getpid() % 50000);
    snprintf(want, sizeof(want), "--qnum=%d", q * 10 + 7);
    snprintf(prefix, sizeof(prefix), "--qnum=%d", q);
    snprintf(other, sizeof(other), "--qnum=%d", q * 10 + 8);
    memset(pad, 'x', sizeof(pad) - 1);
    pid_t pid = fork();
    if (pid == 0) {
        execlp("sh", "sh", "-c", "sleep 30", pad, want, (char *)NULL);
        _exit(127);
    }
    if (pid < 0) return 1;
    /* exec — не мгновенный: ждём, пока в /proc появится его командная строка. */
    int seen = 0;
    for (int i = 0; i < 200 && !seen; i++) {
        seen = proc_cmdline_find(want, 0);
        if (!seen) usleep(10000);
    }
    check("хвост длинной командной строки найден", 1, seen);
    check("… цифра за искомым: приставка номера с требованием конца не находится", 0,
          proc_cmdline_find(prefix, 1));
    check("… а без требования конца — находится", 1, proc_cmdline_find(prefix, 0));
    check("чужого нет", 0, proc_cmdline_find(other, 0));
    kill(pid, SIGTERM);
    waitpid(pid, NULL, 0);
    return unit_done("procscanmatch");
}
