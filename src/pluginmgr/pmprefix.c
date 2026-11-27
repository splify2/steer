/* Явный автономный файловый профиль. Не распознаётся по пустоте каталога,
 * переменной окружения или состоянию управляющего сокета. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "pm.h"
#include "pmstatx.h"
#include "platform.h"

static int selected;
int pm_managed(void) { return selected; }

/* Родители раньше детей: при проверке lstat каждый компонент уже проверен.
 * .lock — каталог навсегда, а не временно занятый flock. Старые менеджеры не
 * должны также увидеть новые repo definitions при search (до pm_lock). */
static const char *const dirs[] = {
    "installed", "installed/.lock", "installed/.stage", "installed/.prev",
    "etc", "etc/sources.d", "keys", "keys/plugins", "seed", "run", "run/state",
    "tmp", "keep", "sysroot"
};
#define EMPTY_STATE "{\"schema\":1,\"plugins\":{}}\n"
static const struct { const char *name, *initial; int constant; } files[] = {
    {"installed/.lock/writer", "", 1}, {"etc/repos.d", "steer-managed-linux/1\n", 1},
    {"etc/state.json", EMPTY_STATE, 1}, {"etc/registry.json", EMPTY_STATE, 0}
};
static const struct { const char *env, *rel; } paths[] = {
    {"STEER_PLUGIN_DIR","installed"}, {"STEER_PLUGINS_ROOT","installed"},
    {"STEER_PLUGIN_ETC","etc"}, {"STEER_PLUGINS_ETC","etc"},
    {"STEER_PLUGIN_KEYS","keys"}, {"STEER_PLUGIN_SEED","seed"},
    {"STEER_PLUGIN_RUN","run"}, {"STEER_PLUGIN_TMP","tmp"},
    {"TMPDIR","tmp"},
    {"STEER_PLUGIN_KEEPD","keep/plugins"}, {"STEER_PLUGIN_SYSROOT","sysroot"},
    {"STEER_PLUGIN_PANEL_DIR","etc/panel"}, {"STEER_PLUGIN_SPEC","etc/spec"},
    {"STEER_SPEC","etc/spec"}, {"STEER_SOCKET","run/ctl"}
};
#define COUNT(a) (sizeof(a)/sizeof((a)[0]))

static int below(const char *path, const char *dir) {
    size_t n = strlen(dir);
    return !strncmp(path, dir, n) && (!path[n] || path[n] == '/');
}

/* И когда штатного каталога ещё нет: /var/run может быть ссылкой на /run.
 * Произвольные пути чужого запущенного менеджера этим не определяются. */
static int overlaps_legacy(const char *prefix) {
    const char *const legacy[] = {pm_root(), pm_etc(), pm_keys(), pm_seed(), pm_run(), pm_tmp(),
                                  pm_keepd(), "/etc/steer", "/var/lib/steer"};
    for (size_t i = 0; i < COUNT(legacy); i++) {
        char *part = pm_strdup(legacy[i]), real[PATH_MAX];
        while (!realpath(part, real)) {
            char *end = strrchr(part, '/');
            if (!end || end == part) { strcpy(real, "/"); part[1] = 0; break; }
            *end = 0;
        }
        char *path = pm_fmt("%s%s", real, legacy[i] + strlen(part));
        int conflict = below(prefix, path) || below(path, prefix);
        free(path);
        free(part);
        if (conflict) return 1;
    }
    return 0;
}

static int safe_parent(const char *parent) {
    char real[PATH_MAX];
    struct stat st;
    if (!realpath(parent, real) || strcmp(parent, real) || stat(real, &st) ||
        !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077)) return 0;
    /* Владелец каталога выше не должен иметь возможность подменить родителя.
     * /tmp со sticky-bit допустим как предок личного каталога. */
    for (;;) {
        /* Не публиковать вложенный префикс даже в приватном tmp первого. */
        if (!(st.st_mode & 022) && st.st_uid == geteuid()) {
            char *marker = pm_path(real, "etc/repos.d");
            struct stat mark;
            int nested = !lstat(marker, &mark);
            free(marker);
            if (nested) return 0;
        }
        char *s = strrchr(real, '/');
        if (!s || s == real) break;
        *s = 0;
        if (stat(real, &st) || (st.st_uid && st.st_uid != geteuid()) ||
            ((st.st_mode & 022) && !(st.st_mode & S_ISVTX))) return 0;
    }
    return 1;
}

/* st_dev не отличает bind одного каталога на том же разделе. Если ядро
 * не может подтвердить границу монтирования, не обещаем её и при init. */
static unsigned long long mount_id(const char *path) {
    uint64_t id;
    return pm_statx_mount_id(path, &id) == 0 ? id : 0;
}

static int object(const char *path, int dir, unsigned long long mount) {
    struct stat s;
    return !lstat(path, &s) && s.st_uid == geteuid() && !(s.st_mode & 022) && mount_id(path) == mount &&
           (dir ? S_ISDIR(s.st_mode) && (s.st_mode & 0700) == 0700 :
                  S_ISREG(s.st_mode) && s.st_nlink == 1 && (s.st_mode & 0600) == 0600);
}

static int sync_dir(const char *dir) {
    int fd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return -1;
    int rc = fsync(fd);
    close(fd);
    return rc;
}

static int layout(const char *base, int create, unsigned long long mount) {
    struct stat s;
    if (!object(base, 1, mount) || lstat(base, &s) || (s.st_mode & 077)) return -1;
    for (size_t i = 0; i < COUNT(dirs); i++) {
        char *p = pm_path(base, dirs[i]);
        int ok = create ? mkdir(p, 0700) == 0 : object(p, 1, mount);
        free(p);
        if (!ok) return -1;
    }
    for (size_t i = 0; i < COUNT(files); i++) {
        char *p = pm_path(base, files[i].name);
        size_t n = strlen(files[i].initial);
        int ok = create ? pm_write_atomic(p, files[i].initial, n, 0600) == 0 : object(p, 0, mount);
        if (ok && !create && files[i].constant) {
            char buf[64];
            int fd = open(p, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
            ok = fd >= 0 && read(fd, buf, sizeof(buf)) == (ssize_t)n && !memcmp(buf, files[i].initial, n);
            if (fd >= 0) close(fd);
        } else if (ok && !create) {
            struct ydoc *d = pm_json_load(p, NULL);
            ok = !lstat(p, &s) && (s.st_mode & 0777) == 0600 && d && pm_registry_valid(ydoc_root(d));
            if (d) ydoc_free(d);
        }
        free(p);
        if (!ok) return -1;
    }
    if (create) {
        for (size_t i = COUNT(dirs); i--;) {
            char *p = pm_path(base, dirs[i]);
            int rc = sync_dir(p);
            free(p);
            if (rc) return -1;
        }
        return sync_dir(base);
    }
    char *sock = pm_path(base, "run/ctl");
    int absent = lstat(sock, &s) < 0 && errno == ENOENT;
    free(sock);
    return absent ? 0 : -1;
}

static int initialize(const char *parent, const char *base, unsigned long long mount) {
    struct stat st;
    if (!lstat(base, &st) || errno != ENOENT) return -1;
    char *tmp = pm_path(parent, ".steer-init-XXXXXX");
    if (!mkdtemp(tmp)) { free(tmp); return -1; }
    int rc = layout(tmp, 1, mount);
#ifdef SYS_renameat2
    if (!rc) rc = syscall(SYS_renameat2, AT_FDCWD, tmp, AT_FDCWD, base, RENAME_NOREPLACE);
#else
    rc = -1;
#endif
    if (rc) pm_rmrf(tmp);
    else if (sync_dir(parent)) rc = -2; /* опубликованный каталог уже не наш временный */
    free(tmp);
    return rc;
}

static int bind_paths(const char *base) {
    for (size_t i = 0; i < COUNT(paths); i++) {
        char *p = pm_path(base, paths[i].rel);
        int rc = setenv(paths[i].env, p, 1);
        free(p);
        if (rc) return -1;
    }
    struct utsname u;
    if (uname(&u) || setenv("STEER_PLUGIN_ARCH", u.machine, 1) ||
        setenv("STEER_PLUGIN_HOST_API", "", 1) || setenv("STEER_PLUGIN_SPLIFY2", "", 1) ||
        setenv("STEER_PLUGIN_INITD", "", 1)) return -1;
    steer_set_state_dir(pm_path(base, "run/state")); /* процесс одной команды */
    return 0;
}

static int refuse(int json, const char *code, const char *why) {
    fprintf(stderr, "steerd: %s\n", why);
    if (json) {
        struct pm_err e = {0};
        char buf[8192];
        pm_errc(&e, code, NULL, "%s", why);
        pm_err_json(&e, buf, sizeof(buf));
        puts(buf);
    }
    return 1;
}

int pm_prefix_main(const char *prefix, int argc, char **argv) {
    int json = argc && !strcmp(argv[argc-1], "--json");
    int n = argc - json;
    int init = n == 1 && !strcmp(argv[0], "init");
    if (!init && !(n == 1 && !strcmp(argv[0], "list")) &&
        !((n == 1 || (n == 2 && pm_id_ok(argv[1]))) && !strcmp(argv[0], "status")) &&
        !(n == 2 && !strcmp(argv[0], "remove") && pm_id_ok(argv[1])) &&
        !(n == 3 && !strcmp(argv[0], "install") && !strcmp(argv[1], "--file") && argv[2][0] == '/'))
        return refuse(json, "plugin.prefix_operation", "для префикса доступны init, install --file /архив, list, status [id], remove id");
    for (char **ep = environ; *ep; ep++)
        if (!strncmp(*ep, "STEER_", 6))
            return refuse(json, "plugin.prefix_conflict", "явный префикс несовместим с переопределениями STEER_*");
    const char *slash = strrchr(prefix, '/');
    if (*prefix != '/' || prefix[1] == '/' || !slash || slash == prefix || !slash[1] || !strcmp(slash+1, ".") ||
        !strcmp(slash+1, "..") || !strncmp(slash+1, ".steer-init-", 12) ||
        strlen(prefix) + sizeof("/run/ctl") > sizeof(((struct sockaddr_un *)0)->sun_path))
        return refuse(json, "plugin.prefix_invalid", "нужен канонический абсолютный путь внутри личного каталога, пригодный для Unix-сокета");
    if (overlaps_legacy(prefix))
        return refuse(json, "plugin.prefix_conflict", "префикс пересекается со штатным путём 2.x");
    const char *override = getenv("TMPDIR");
    char *tmp = pm_path(prefix, "tmp");
    int conflict = override && strcmp(override, tmp);
    free(tmp);
    if (conflict) return refuse(json, "plugin.prefix_conflict", "TMPDIR указывает за пределы выбранного tmp");
    umask(0077);
    char *parent = strndup(prefix, slash-prefix);
    int ok = parent && safe_parent(parent);
    unsigned long long mount = ok ? mount_id(parent) : 0;
    int result = !mount ? -1 : init ? initialize(parent, prefix, mount) : layout(prefix, 0, mount);
    free(parent);
    if (result == -2) return refuse(json, "plugin.prefix_sync", "префикс опубликован, но не подтверждена запись родительского каталога");
    if (result) return refuse(json, "plugin.prefix_invalid", init ? "не создан новый префикс: проверьте родителя и отсутствие назначения" :
                          "не подтверждены каталоги, границы формата или отсутствие endpoint префикса");
    if (init) { if (json) puts("{\"ok\":true}"); return 0; }
    if (bind_paths(prefix)) return refuse(json, "plugin.prefix_invalid", "не привязаны пути префикса");
    selected = 1;
    return pm_main(argc, argv);
}
