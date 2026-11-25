/* Только для стенда: перехватываем реальные rename, не подменяя pminst/pmstate. */
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

int __real_rename(const char *from, const char *to);

static int ends(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && !strcmp(s + n - m, suffix);
}

int __wrap_rename(const char *from, const char *to) {
    const char *fault = getenv("PM_TEST_FAULT");
    const char *step = NULL;
    if (ends(to, "/.prev/demo")) step = "prev";
    else if (strstr(from, "/.stage/") && ends(to, "/plugins/demo")) step = "place";
    else if (strstr(from, ".steer-plugin.") && ends(to, "/demo-new")) step = "link";
    else if (ends(to, "/state.json")) step = "state";
    else if (ends(to, "/keep.d/plugins")) step = "keep";
    if (fault && step && strchr(fault, ':') && !strcmp(strchr(fault, ':') + 1, step)) {
        if (!strncmp(fault, "eio:", 4)) {
            unsetenv("PM_TEST_FAULT"); /* повторная запись при откате не ломается */
            errno = EIO;
            return -1;
        }
        if (!strncmp(fault, "before:", 7)) raise(SIGKILL);
        if (!strncmp(fault, "after:", 6)) {
            int r = __real_rename(from, to);
            if (!r) raise(SIGKILL);
            return r;
        }
    }
    return __real_rename(from, to);
}
