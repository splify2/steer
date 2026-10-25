/* main бинарника steer-proxy — модуль протоколов прокси (trojan, shadowsocks, socks, http, vmess;
 * docs/proxy.md). Всё дело — в steer_module_main (src/cli/modcmd.c): платформа, hello с версией
 * этого бинарника, разбор аргументов и вызов cmd_proxy и остальных команд (src/proto/proxy/pxmain.c).
 *
 * Модуль есть только в раскладке с libsteer.so (build/sources.mk, PROFILE_mod_proxy): ни в
 * статических сборках, ни в профиле телефона его нет (как steer-hysteria2). */
#include "modcmd.h"
#include "plugconf.h"

#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

int main(int argc, char **argv) {
    /* --conf {conf} помощника плагина — в прежние --spec и --state-dir (plugconf.h). */
    argv = plugconf_argv(&argc, argv);
    return steer_module_main(argc, argv, "proxy", STEER_VERSION);
}
