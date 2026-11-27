/* Только для стенда: перехватываем реальные rename, не подменяя pminst/pmstate. */
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

int __real_rename(const char *from, const char *to);
int __real_unlink(const char *path);

static int ends(const char *s, const char *suffix) {
    size_t n = strlen(s), m = strlen(suffix);
    return n >= m && !strcmp(s + n - m, suffix);
}

/* 1 — ошибка вместо операции, 2 — убить после её успешного выполнения. */
static int cut(const char *step) {
    const char *fault = getenv("PM_TEST_FAULT");
    if (fault && step && strchr(fault, ':') && !strcmp(strchr(fault, ':') + 1, step)) {
        const int once = !strncmp(fault, "eio:", 4);
        if (once || !strncmp(fault, "eio-always:", 11)) {
            if (once) unsetenv("PM_TEST_FAULT");
            errno = EIO;
            return 1;
        }
        if (!strncmp(fault, "before:", 7)) raise(SIGKILL);
        if (!strncmp(fault, "after:", 6)) return 2;
    }
    return 0;
}

int __wrap_rename(const char *from, const char *to) {
    const char *step = NULL;
    if (ends(to, "/.prev/demo")) step = "prev";
    else if (strstr(from, "/.stage/") && ends(to, "/plugins/demo")) step = "place";
    else if (strstr(from, "/.prev/") && ends(to, "/plugins/demo")) step = "restore";
    else if (ends(from, "/plugins/demo") && strstr(to, "/.stage/")) step = "unplace";
    else if (strstr(from, ".steer-plugin.") && ends(to, "/demo-new")) step = "link";
    else if (strstr(from, ".steer-plugin.") && ends(to, "/demo-old")) step = "link-old";
    else if (ends(to, "/state.json")) step = "state";
    else if (ends(to, "/keep.d/plugins")) step = "keep";
    else if (ends(to, "/.install-in-progress")) step = "marker";
    int k = cut(step);
    int r = k == 1 ? -1 : __real_rename(from, to);
    if (k == 2 && r == 0) raise(SIGKILL);
    return r;
}

int __wrap_unlink(const char *path) {
    int k = cut(ends(path, "/.install-in-progress") ? "commit" : NULL);
    int r = k == 1 ? -1 : __real_unlink(path);
    if (k == 2 && r == 0) raise(SIGKILL);
    return r;
}
