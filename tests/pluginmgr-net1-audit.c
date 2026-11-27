/* Только для стенда glibc: какой ELF действительно попал в link_map,
 * в том числе до отказа релокации. Не подменять ни поиск, ни символы. */
#define _GNU_SOURCE
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

unsigned int la_version(unsigned int version) { return version < LAV_CURRENT ? 0 : LAV_CURRENT; }
unsigned int la_objopen(struct link_map *m, Lmid_t ns, uintptr_t *cookie) {
    (void)ns;
    (void)cookie;
    const char *name = strrchr(m->l_name, '/'), *fd = getenv("NET1_TRACE_FD");
    if (fd && name && !strcmp(name, "/libs2p-net.so.1")) {
        char exe[4096];
        ssize_t n = readlink("/proc/self/exe", exe, sizeof(exe)-1);
        if (n < 0) _exit(120);
        exe[n] = 0;
        if (dprintf(atoi(fd), "%s\t%s\n", exe, m->l_name) < 0) _exit(121);
    }
    return 0;
}
