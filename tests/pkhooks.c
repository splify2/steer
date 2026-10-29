/* Хуки программ официальных плагинов — для стендов ядра без сети и TLS (tests/plugroot.sh).
 *
 * Ядро исполняет хуки check и expand видов плагинов при подготовке спеки (steer-api.md, 3). Настоящие
 * программы протоколов собираются с net1 (TLS, QUIC) — `make test` их не собирает; а хуки у них — чистый
 * разбор входа, и этот бинарник несёт ровно его: те же функции, что программы плагинов (src/plugkit/
 * pktun.c, src/proto/xsteer/xshook.c, src/proto/tgws/tghook.c, src/proto/warp/wbexpand.c). Чей хук — по STEER_PLUGIN_ID, который
 * ядро ставит каждой программе плагина (steer-api.md, 1.2). Помощника и подкоманд здесь нет: код 2. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pktun.h"
#include "tghook.h"
#include "wbexpand.h"
#include "xshook.h"

int main(int argc, char **argv) {
    const char *id = getenv("STEER_PLUGIN_ID");
    const char *cmd = argc > 1 ? argv[1] : "";
    if (!id) id = "";
    if (!strcmp(cmd, "check")) {
        if (!strcmp(id, "xsteer")) return xs_check_hook();
        if (!strcmp(id, "tgws")) return tg_check_hook();
        return pk_tun_check_hook(NULL);
    }
    if (!strcmp(cmd, "warp-expand")) return cmd_warp_expand();
    fprintf(stderr, "pkhooks (%s): «%s» — у стенда только хуки check и warp-expand\n", id, cmd);
    return 2;
}
