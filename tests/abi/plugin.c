/* Плагин .so для стенда tests/abimatch.sh: один исходник, поведение — макросом MODE (сборка вариантов в
 * стенде) и командой ctl. Подключает копию контракта src/daemon/plugabi.h, как это делал бы плагин с
 * steer/plugin.h из SDK: связи с libsteer нет, ядро — только таблица host_v1. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "plugabi.h"

#ifndef PLUGIN_ID
#define PLUGIN_ID "abitest"
#endif
#ifndef PLUGIN_VERSION
#define PLUGIN_VERSION "1.0.0"
#endif
#ifndef ABI_MAJOR
#define ABI_MAJOR STEER_ABI_MAJOR
#endif
#ifndef ABI_MINOR
#define ABI_MINOR STEER_ABI_MINOR
#endif

#ifndef FP_XOR
#define FP_XOR 0
#endif

enum { M_OK, M_CRASH_INIT, M_FAIL_INIT, M_CRASH_TIMER, M_HANG_TIMER, M_CRASH_HEALTH, M_HANG_HEALTH,
       M_CRASH_EVENT, M_ABORT_HEALTH };
#ifndef MODE
#define MODE M_OK
#endif

static const struct steer_host_v1 *api;
static struct steer_host *self;
static int pipefd[2] = { -1, -1 };

static volatile unsigned long wild = 8;   /* адрес, которого нет: компилятор не вырежет запись как UB */
static void boom(void *arg) {
    (void)arg;
    *(volatile int *)wild = 1;
}
static void hang(void *arg) {
    (void)arg;
    for (;;) usleep(1000);
}
static void t_fired(void *arg) { api->log(self, STEER_LOG_INFO, "TIMER fired arg=%s", (const char *)arg); }
static void t_never(void *arg) { (void)arg; api->log(self, STEER_LOG_ERR, "TIMER cancelled but fired"); }
static void fd_ready(void *arg, int fd, uint32_t ev) {
    char b[8];
    ssize_t n = read(fd, b, sizeof b);
    api->log(self, STEER_LOG_INFO, "FD ready ev=0x%x n=%zd arg=%s", ev, n, (const char *)arg);
    api->unwatch_fd(self, fd);
}
static void res_done(void *arg, int rc, const void *addrs, size_t n) {
    (void)addrs;
    api->log(self, STEER_LOG_INFO, "RESOLVE rc=%d n=%zu arg=%s", rc, n, (const char *)arg);
}
static void http_done(void *arg, int status, const char *body, size_t len, const char *why) {
    api->log(self, STEER_LOG_INFO, "HTTP status=%d len=%zu body=%.*s why=%s arg=%s", status, len, (int)len, body,
             why ? why : "-", (const char *)arg);
}

static int p_init(struct steer_host *h, const struct steer_host_v1 *host, char *why, size_t n) {
    self = h;
    api = host;
    api->log(self, STEER_LOG_INFO, "INIT abi=%u.%u size_ok=%d core=%s api=%s plugin_dir=%s conf=%s state=%s",
             host->abi_major, host->abi_minor, STEER_HAS(host, member_verdict), host->core_version,
             host->api_version, host->plugin_dir, host->conf_dir, host->state_dir);
    void *p = api->alloc(16);
    api->free(p);
    if (MODE == M_CRASH_INIT) boom(NULL);
    if (MODE == M_FAIL_INIT) {
        snprintf(why, n, "отказ из init");
        return -1;
    }
    if (MODE == M_CRASH_TIMER) api->timer(self, 300, boom, NULL);
    if (MODE == M_HANG_TIMER) api->timer(self, 300, hang, NULL);
    return 0;
}
static void p_fini(struct steer_host *h) { (void)h; api->log(self, STEER_LOG_INFO, "FINI"); }

static void say_out(const char *what, const struct steer_spec *sp, const struct steer_out *out) {
    const char *keys = api->out_keys_json(out);
    const char *conf = api->out_conf_json(out);
    const char *owner = api->out_owner(out);
    const struct steer_out *again = api->out_by_name(self, sp, api->out_name(out));
    api->log(self, STEER_LOG_INFO, "%s out=%s kind=%s dev=%s mark=%u table=%d count=%zu byname=%d at0=%s owner=%s keys=%s conf=%s",
             what, api->out_name(out), api->out_kind(out), api->out_device(out), api->out_mark(out),
             api->out_table(out), api->out_count(self, sp), again == out, api->out_name(api->out_at(self, sp, 0)),
             owner ? owner : "-", keys ? keys : "-", conf ? conf : "-");
}

static int k_check(struct steer_host *h, const struct steer_spec *sp, const struct steer_out *out, char *why, size_t n) {
    (void)h;
    say_out("CHECK", sp, out);
    if (!strcmp(api->out_name(out), "bad")) {
        snprintf(why, n, "выход bad не годится");
        return -1;
    }
    return 0;
}
static void k_emit(struct steer_host *h, const struct steer_spec *sp, const struct steer_out *out) {
    (void)h;
    say_out("EMIT", sp, out);
    int r1 = api->nft_rule(self, "forward", "counter accept");
    int r2 = api->nft_rule(self, "forward", "meta mark 0x1 drop");
    api->log(self, STEER_LOG_INFO, "EMIT nft rc=%d,%d", r1, r2);
}
static int k_health(struct steer_host *h, const struct steer_spec *sp, const struct steer_out *out, const char *dev) {
    (void)h; (void)sp; (void)out;
    if (MODE == M_CRASH_HEALTH) boom(NULL);
    if (MODE == M_HANG_HEALTH) hang(NULL);
    if (MODE == M_ABORT_HEALTH) abort();
    return dev && !strcmp(dev, "wg0") ? 1 : 0;
}
static int k_revive(struct steer_host *h, const struct steer_spec *sp, const struct steer_out *out, const char *dev) {
    (void)h; (void)sp; (void)out;
    api->log(self, STEER_LOG_INFO, "REVIVE dev=%s", dev);
    return 7;
}
static int k_apply_all(struct steer_host *h, const struct steer_spec *sp, char *why, size_t n) {
    (void)h; (void)why; (void)n;
    api->log(self, STEER_LOG_INFO, "APPLY_ALL count=%zu", api->out_count(self, sp));
    return 0;
}
static int k_down_all(struct steer_host *h, const struct steer_spec *sp) {
    (void)h; (void)sp;
    return 3;
}
static char *k_status(struct steer_host *h, const struct steer_spec *sp, const struct steer_out *out) {
    (void)h; (void)sp;
    char *s = api->alloc(64);
    snprintf(s, 64, "{\"up\":true,\"out\":\"%s\"}", api->out_name(out));
    api->set_status(self, out, s);
    return s;
}
static int k_expand(struct steer_host *h, const char *out_json, char **frag, char *why, size_t n) {
    (void)h; (void)why; (void)n;
    char *s = api->alloc(strlen(out_json) + 16);
    sprintf(s, "{\"echo\":%s}", out_json);
    *frag = s;
    return 0;
}

static const struct steer_kind_v1 kind = {
    .size = sizeof kind, .name = "abikind", .caps = STEER_CAP_DEVICE | STEER_CAP_MARK,
    .check = k_check, .emit = k_emit, .health = k_health, .revive = k_revive,
    .apply_all = k_apply_all, .down_all = k_down_all, .status = k_status, .expand = k_expand,
};
static const struct steer_kind_v1 *const kinds[] = { &kind, NULL };

static int p_pre_apply(struct steer_host *h, const char *spec_json, char **out_json, char *why, size_t n) {
    (void)h; (void)why; (void)n;
    char *s = api->alloc(strlen(spec_json) + 8);
    sprintf(s, "%s", spec_json);
    *out_json = s;
    return 0;
}
static void p_on_event(struct steer_host *h, const char *ev) {
    (void)h;
    if (MODE == M_CRASH_EVENT && strstr(ev, "\"boom\"")) boom(NULL);
    api->log(self, STEER_LOG_INFO, "EVENT %s", ev);
}

/* ctl: «async» — свои дескрипторы, таймеры, имена, HTTPS, события; «emit» — событие подписчикам. */
static int p_ctl(struct steer_host *h, const char *cmd, const char *const *argv, size_t argc, const char *body,
                 size_t body_len, char **resp) {
    (void)h; (void)argv; (void)argc; (void)body; (void)body_len;
    if (!strcmp(cmd, "async")) {
        int t1 = api->timer(self, 100, t_fired, "one");
        int t2 = api->timer(self, 50, t_never, NULL);
        api->timer_cancel(self, t2);
        api->timer_cancel(self, 999999);   /* чужого номера нет — ничего не случается */
        if (pipe(pipefd) == 0) {
            api->watch_fd(self, pipefd[0], STEER_FD_IN, fd_ready, "pipe");
            ssize_t w = write(pipefd[1], "x", 1);
            (void)w;
        }
        int rr = api->resolve(self, "localhost", 80, 0, res_done, "lo");
        struct steer_http_req rq = { .size = sizeof rq, .method = "GET", .url = "https://example.invalid/x" };
        int rh = api->http(self, &rq, http_done, "h");
        api->log(self, STEER_LOG_INFO, "ASYNC started t1>0=%d resolve=%d http=%d", t1 > 0, rr, rh);
        *resp = api->alloc(8);
        strcpy(*resp, "{}");
        return 0;
    }
    if (!strcmp(cmd, "emit")) {
        int r1 = api->emit(self, "abievent", "{\"a\":1,\"b\":\"x\"}");
        int r2 = api->emit(self, "Bad Name", "{}");
        int r3 = api->emit(self, "abiempty", "{}");
        int r4 = api->emit(self, "abinull", NULL);
        int r5 = api->emit(self, "abibad", "{\"a\":\n1}");
        api->log(self, STEER_LOG_INFO, "EMIT-EV %d %d %d %d %d", r1, r2, r3, r4, r5);
        *resp = NULL;
        return 0;
    }
    if (!strcmp(cmd, "nft-outside")) {
        api->log(self, STEER_LOG_INFO, "NFT-OUTSIDE rc=%d", api->nft_rule(self, "forward", "accept"));
        return 0;
    }
    return -1;
}

static const struct steer_plugin_v1 plugin = {
    .size = sizeof plugin, .abi_major = ABI_MAJOR, .abi_minor = ABI_MINOR, .fingerprint = STEER_ABI_FINGERPRINT ^ FP_XOR,
    .id = PLUGIN_ID, .version = PLUGIN_VERSION, .init = p_init, .fini = p_fini, .kinds = kinds,
    .pre_apply = p_pre_apply, .on_event = p_on_event, .ctl = p_ctl,
};

#ifdef REFUSE_ENTRY
__attribute__((visibility("default")))
const struct steer_plugin_v1 *steer_plugin_v1_entry(uint16_t host_major, uint16_t host_minor) {
    (void)host_major; (void)host_minor;
    return NULL;
}
#else
__attribute__((visibility("default")))
const struct steer_plugin_v1 *steer_plugin_v1_entry(uint16_t host_major, uint16_t host_minor) {
#ifndef NO_VERSION_CHECK
    if (host_major != STEER_ABI_MAJOR || host_minor < STEER_ABI_MINOR) return NULL;
#else
    (void)host_major; (void)host_minor;
#endif
    return &plugin;
}
#endif
