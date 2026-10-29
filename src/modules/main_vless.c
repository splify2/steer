/* Программа плагина vless (plugins/vless/plugin.json): помощник выхода `tunnel:vless`, хук check его
 * вида и подкоманды `steer vless-nodes`, `vless-probe`, `sub-fetch`, `sub-quota`, `tls-probe`.
 *
 * С ядром программа говорит только через API (plugin-sdk/docs/steer-api.md, src/plugkit): ядро
 * запускает её по манифесту, о выходе она знает из {conf}, о себе говорит событиями и файлом
 * состояния. Модели спеки ядра в ней нет. Версия — этой сборки (hello). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "plugkit.h"
#include "pktun.h"
#include "vlcmd.h"


static int r_vless(const struct pk_args *a) { return cmd_vless(a->out); }

/* --insecure — только у перечня и проверки узлов ПО ФАЙЛУ подписки: у выхода пригодность узлов с
 * allowInsecure решает его ключ insecure, и флаг поверх него показал бы номера, которых у поднятого
 * выхода нет. */
static int insecure_ok(const struct pk_args *a) {
    if (pk_has(a, "insecure") && a->pos[0][0] != '/') {
        fprintf(stderr, "steer: %s: --insecure — только с файлом подписки (путь с «/»); у выхода узлы с "
                "allowInsecure решает его ключ insecure\n", a->cmd);
        return 0;
    }
    return 1;
}

static int r_nodes(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_vless_nodes(a->out, a->pos[0], pk_has(a, "insecure"));
}

static int r_probe(const struct pk_args *a) {
    if (!insecure_ok(a)) return 2;
    return cmd_vless_probe(a->out, a->pos[0], (int)pk_opt_long(a, "node", -1, -1, 65535),
                           (int)pk_opt_long(a, "timeout", 5, 1, 3600), pk_has(a, "insecure"));
}

static int r_fetch(const struct pk_args *a) { return cmd_sub_fetch(a->pos[0], pk_opt(a, "out"), pk_opt(a, "info")); }
static int r_quota(const struct pk_args *a) { return cmd_sub_quota(a->pos[0], pk_opt(a, "info")); }

/* ХОСТ[:ПОРТ]; адрес назначения — флагом --out, исходящий порт — флагом --node. */
static int r_tls(const struct pk_args *a) {
    char hb[256];
    int pt = 443;
    snprintf(hb, sizeof(hb), "%s", a->pos[0]);
    char *c = strrchr(hb, ':');
    if (c) {
        *c = '\0';
        char *pe = NULL;
        long v = strtol(c + 1, &pe, 10);
        if (pe == c + 1 || *pe || v < 1 || v > 65535) { fprintf(stderr, "неверный порт: %s\n", c + 1); return 2; }
        pt = (int)v;
    }
    if (!hb[0]) { fprintf(stderr, "нужно имя узла\n"); return 2; }
    long lp = pk_opt_long(a, "node", 0, -1, 65535);
    return cmd_tls_probe(hb, pk_opt(a, "out"), pt, lp > 0 ? (int)lp : 0, 0);
}

static int r_check(const struct pk_args *a) { (void)a; return pk_tun_check_hook(NULL); }

static const struct pk_cmd CMDS[] = {
    { "vless", "<выход>", 0, 1, "", "поднять TUN и клиент выхода tunnel:vless по его {conf}", 1, r_vless },
    { "vless-nodes", "<выход|/файл>", 1, 1, "insecure",
      "узлы подписки выхода или файла: номер узла — то, что ждёт --node у vless-probe", 0, r_nodes },
    { "vless-probe", "<выход|/файл>", 1, 1, "node: timeout: insecure",
      "проверить узел выхода (или файла подписки) и измерить задержку", 0, r_probe },
    { "sub-fetch", "<ссылка>", 1, 1, "out: info:", "скачать подписку в --out", 0, r_fetch },
    { "sub-quota", "<ссылка>", 1, 1, "info:", "остаток трафика подписки", 0, r_quota },
    { "tls-probe", "ХОСТ[:ПОРТ]", 1, 1, "out: node:", "проверить TLS узла", 0, r_tls },
    { "check", "", 0, 0, "", "хук check вида tunnel:vless: вход — JSON выхода в stdin", 0, r_check },
};

PK_PROGRAM("vless", CMDS);
