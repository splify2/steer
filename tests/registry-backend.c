/* Изоляция tests/registrymatch.py. Единственный разрешённый сетевой API — Unix-сокет ctl. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include "platform.h"
#include "tmpfile.h"

int __real_socket(int domain, int type, int protocol);

int __wrap_socket(int domain, int type, int protocol) {
    if (domain == AF_UNIX) return __real_socket(domain, type, protocol);
    errno = EAFNOSUPPORT;
    return -1;
}

const char *__wrap_steer_rt_tables_dir(void) {
    return getenv("REGISTRY_TEST_RT_TABLES");
}

void __wrap_steer_tmp_template(char *dst, size_t n, const char *stem) {
    const char *dir = getenv("REGISTRY_TEST_TMP");
    if (!dir || snprintf(dst, n, "%s/%s.XXXXXX", dir, stem) >= (int)n) abort();
}
