#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>

#include "procscan.h"

/* Обход /proc — доводы в procscan.h.
 *
 * Почему вообще /proc, а не вопрос ядру: списка «кто слушает очередь nfqueue N» ядро не
 * отдаёт ни через netlink, ни через /proc/net/netfilter/nfnetlink_queue (там номер очереди
 * и pid, но только для очередей, через которые уже прошёл пакет, — то есть у поднятого и
 * ещё не нагруженного обработчика запись отсутствует). Командная строка с --qnum=N
 * отвечает на тот же вопрос и отвечает всегда.
 *
 * digit_end — требовать, чтобы сразу за NEEDLE не стояла цифра: так «--qnum=830» перестаёт
 * находиться в «--qnum=8300». */
int proc_cmdline_find(const char *needle, int digit_end) {
    DIR *d = opendir("/proc");
    if (!d) return 0;
    struct dirent *dir;
    int found = 0;
    char path[300];
    char *buf = NULL;
    size_t cap = 0;

    while ((dir = readdir(d)) != NULL && !found) {
        if (!isdigit(dir->d_name[0])) continue;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", dir->d_name);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            /* До конца, а не первые 511 байт: --qnum=N бывает в хвосте длинной командной строки
             * (обработчик с длинным списком доменов или путей), и обрезка прятала бы его. */
            ssize_t n = 0;
            for (;;) {
                if ((size_t)n + 1 >= cap) {
                    size_t nc = cap ? cap * 2 : 4096;
                    char *g = realloc(buf, nc);
                    if (!g) { n = -1; break; }
                    buf = g;
                    cap = nc;
                }
                ssize_t r = read(fd, buf + n, cap - (size_t)n - 1);
                if (r <= 0) { if (r < 0) n = -1; break; }
                n += r;
            }
            if (n > 0) {
                buf[n] = '\0';
                for (ssize_t i = 0; i < n; i++) {
                    if (buf[i] == '\0') buf[i] = ' ';
                }
                for (const char *q = strstr(buf, needle); q; q = strstr(q + 1, needle)) {
                    char after = q[strlen(needle)];
                    if (digit_end && after >= '0' && after <= '9') continue;
                    found = 1;
                    break;
                }
            }
            close(fd);
        }
    }
    free(buf);
    closedir(d);
    return found;
}

