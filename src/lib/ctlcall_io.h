/* Обмен на уже соединённом fd. И ctlcall, и менеджер группы владеют своим
 * соединением и закрывают его сами. Эти операции не входят в ABI libsteer. */
#ifndef STEER_CTLCALL_IO_H
#define STEER_CTLCALL_IO_H

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static inline int ctl_write_all(int fd, const char *p, size_t n, int *sent) {
    while (n) {
        ssize_t w = send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return -1;
        if (sent) *sent = 1;
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static inline char *ctl_read_reply(int fd) {
    /* stdout до 1 МиБ и stderr до 64 КиБ; \u00XX раздувает ответ до шести раз. */
    const size_t limit = 8UL * 1024UL * 1024UL;
    size_t cap = 4096, n = 0;
    char *r = malloc(cap);
    if (!r) return NULL;
    for (;;) {
        if (n + 1 >= cap) {
            if (cap >= limit) break;
            char *q = realloc(r, cap * 2);
            if (!q) break;
            r = q;
            cap *= 2;
        }
        ssize_t m = read(fd, r + n, cap - n - 1);
        if (m < 0 && errno == EINTR) continue;
        if (m <= 0) break;
        n += (size_t)m;
        if (memchr(r + n - (size_t)m, '\n', (size_t)m)) break;
    }
    r[n] = '\0';
    char *nl = strchr(r, '\n');
    if (!nl) { free(r); return NULL; }
    *nl = '\0';
    return r;
}
#endif
