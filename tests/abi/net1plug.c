/* .so-плагин steerd, которому нужен net1 (стенд tests/libs-test.sh, «net1 в процессе steerd»).
 *
 * net1 — библиотека программ протоколов; .so-плагину ядра (steer-abi) она нужна так же: DT_NEEDED
 * libs2p-net.so.1, RUNPATH на каталог net1, имена s2p_*. steerd грузит такой плагин dlopen'ом, а с ним и
 * net1 — значит, её TLS (__thread в стеке, TLS, транспортах) обязан работать в библиотеке, загруженной
 * dlopen: модель global-dynamic, а не initial-exec (в статическом блоке TLS процесса места на неё нет).
 * В init плагин зовёт функцию net1, которая пишет в свою __thread-переменную, и называет ответ журналом. */
#include <stdio.h>
#include <string.h>

#include "plugabi.h"

/* Имя net1 (build/net1/libs2p-net.map): текст причины отказа транспорта; код TR_EUPSTATUS (-40) пишет
 * в __thread-буфер (src/proto/transport/transport.c). */
const char *s2p_transport_strerror(int rc);

static const struct steer_host_v1 *api;
static struct steer_host *self;

static int p_init(struct steer_host *h, const struct steer_host_v1 *host, char *why, size_t n) {
    (void)why; (void)n;
    self = h;
    api = host;
    const char *t = s2p_transport_strerror(-40);
    api->log(self, STEER_LOG_INFO, "NET1 strerror=%s", t && *t ? t : "-");
    return 0;
}

static void p_fini(struct steer_host *h) { (void)h; }

static const struct steer_plugin_v1 plugin = {
    .size = sizeof plugin, .abi_major = STEER_ABI_MAJOR, .abi_minor = STEER_ABI_MINOR,
    .fingerprint = STEER_ABI_FINGERPRINT, .id = "net1test", .version = "1.0.0", .init = p_init, .fini = p_fini,
};

__attribute__((visibility("default")))
const struct steer_plugin_v1 *steer_plugin_v1_entry(uint16_t host_major, uint16_t host_minor) {
    if (host_major != STEER_ABI_MAJOR || host_minor < STEER_ABI_MINOR) return NULL;
    return &plugin;
}
