/* Программа плагина obfs: помощник обфускатора для выхода `interface` с ключом obfs и сервер обфускации
 * для VPS (`obfs-server`).
 *
 * Клиент и сервер сами (obfs.c) — общий код: их зовёт и клиент xsteer (поддельный TCP). Здесь —
 * только подкоманды. Помощника ядро запускает по манифесту плагина: вид ядра interface (impl: core),
 * helper.when: obfs — у выхода с этим ключом (plugin-sdk/docs/manifest.md). О выходе программа знает
 * только из {conf}: ключ obfs, метка своих сокетов. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "obfs.h"
#include "plugkit.h"

/* «адрес:порт» → адрес и порт 1..65535. Ядро уже проверило запись при разборе спеки (obfs_set). */
static int hostport(const char *v, char *host, size_t hn, int *port) {
    const char *c = v ? strrchr(v, ':') : NULL;
    if (!c || c == v || (size_t)(c - v) >= hn) return -1;
    char *e;
    long p = strtol(c + 1, &e, 10);
    if (e == c + 1 || *e || p < 1 || p > 65535) return -1;
    memcpy(host, v, (size_t)(c - v));
    host[c - v] = '\0';
    *port = (int)p;
    return 0;
}

static int split(const char *v, const char *what, char *host, size_t hn, int *port) {
    if (!v || hostport(v, host, hn, port) != 0) {
        fprintf(stderr, "steer: obfs.%s — адрес:порт, а не «%s»\n", what, v ? v : "");
        return -1;
    }
    return 0;
}

int cmd_obfs(const struct pk_out *o) {
    const struct pkj *ob = pkj_get(o->keys, "obfs");
    if (!ob) pk_fail("у выхода %s не настроен obfs", o->tun.name);
    char sh[80], lh[80];
    int sp = 0, lp = 0;
    if (split(pkj_str(pkj_get(ob, "server")), "server", sh, sizeof sh, &sp) != 0 ||
        split(pkj_str(pkj_get(ob, "listen")), "listen", lh, sizeof lh, &lp) != 0)
        return 2;
    /* Метка сокета к серверу обфускации — из {conf}: метка выхода-подложки при over, иначе «мимо
     * каналов». Обязательна при over: без неё сокет ушёл бы напрямую, мимо подложки. */
    obfs_set_sock_mark(pk_sock_mark(o), o->sock_mark_required);
    return obfs_client(o->tun.name, sh, sp, lh, lp);
}

int cmd_obfs_server(int listen_port, const char *forward) {
    if (!listen_port) pk_fail("нужен --listen ПОРТ (порт поддельного TCP)");
    if (!forward) pk_fail("нужен --forward АДРЕС:ПОРТ (куда отдавать датаграммы)");
    char host[80];
    int fport = 0;
    if (hostport(forward, host, sizeof(host), &fport) != 0)
        pk_fail("--forward должен быть вида адрес:порт, а не %s", forward);
    return obfs_server(listen_port, host, fport);
}
