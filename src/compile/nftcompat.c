#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/wait.h>
#include "spec.h"
#include "tmpfile.h"
#include "nftcompat.h"
#include "nftdump.h"

/* Примет ли ядро этот текст: `nft -c -f` над временным файлом. 1 — принял, 0 — отверг,
 * -1 — спросить не удалось (нет nft, нет прав, не создать файл).
 *
 * Свой fork, а не run_quiet из lib/run.c: пробу зовёт и резолвер, а стенд dnsmatch собирает
 * его вместе с этим файлом без lib/run.c. Вывод nft гасится — отказ здесь ожидаем и не ошибка. */
static int nft_check_text(const char *text) {
    char tmp[256];
    steer_tmp_template(tmp, sizeof(tmp), "steer-nprobe");
    int fd = mkstemp(tmp);
    if (fd < 0) return -1;
    size_t len = strlen(text);
    int ok = write(fd, text, len) == (ssize_t)len;
    close(fd);
    if (!ok) { unlink(tmp); return -1; }
    pid_t p = fork();
    if (p < 0) { unlink(tmp); return -1; }
    if (p == 0) {
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, 1); dup2(devnull, 2); close(devnull); }
        execlp("nft", "nft", "-c", "-f", tmp, (char *)NULL);
        _exit(127);
    }
    int st = 0;
    waitpid(p, &st, 0);
    unlink(tmp);
    if (!WIFEXITED(st) || WEXITSTATUS(st) == 127) return -1;
    return WEXITSTATUS(st) == 0;
}

/* Раскладка набора правил этого запуска (nftcompat.h). */
int g_nftc;

/* Составной интервальный набор (ipv4_addr . inet_proto . inet_service, flags interval,timeout):
 * примет ли его ядро. Нужен только каналам, у списка которых сужение СМЕШАННОЕ (набор .srs, где
 * часть подсетей — «udp 50000-65535», часть — без сужения, см. src/model/srsplan.c): такой
 * список ложится в ядро одним набором и одним правилом. Интервалы в составном ключе (pipapo)
 * есть с Linux 5.6; на 5.2-5.5 раскладка современная, но набор не примется — поэтому
 * спрашивается ядро, пробной таблицей через `nft -c`. Нет — канал делится на группы по сужению, как раньше делились
 * каналы с разными портами.
 *
 * Спрашивается лениво — только когда такой канал есть, — и один раз на процесс. STEER_NFT_CONCAT
 * (0 или 1) переопределяет ответ для стендов. */
int nft_concat_ok(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    const char *o = getenv("STEER_NFT_CONCAT");
    if (o && (!strcmp(o, "0") || !strcmp(o, "1"))) return cached = o[0] == '1';
    char text[512];
    snprintf(text, sizeof(text),
             "table inet %s_nprobe {\n"
             "    set s {\n"
             "        type ipv4_addr . inet_proto . inet_service\n"
             "        flags interval,timeout\n"
             "        elements = { 192.0.2.0/24 . 0-255 . 0-65535 }\n"
             "    }\n"
             "}\n", nft_table());
    return cached = nft_check_text(text) == 1;
}

/* Цепочка inet ingress (разметка каналов, compile/generate.c, «разметка на ingress»): примет ли
 * её ядро. Хук ingress в семействе inet — Linux 5.10 (и nftables 0.9.7, иначе отказ разбора), и
 * нужен ещё CONFIG_NETFILTER_INGRESS; номер версии здесь не ответ — ответ даёт
 * ядро. Проба — на lo: цепочка ingress ставится только на существующее устройство (иначе ядро
 * отвергает всю транзакцию, «No such file or directory»), а lo есть в любом сетевом
 * пространстве. Не смогли спросить (нет nft, нет прав) — «нет»: без ingress движок работает так,
 * как работал до него, и это безопасный ответ на незнание.
 *
 */
static int ingress_env(void) {
    const char *o = getenv("STEER_NFT_INGRESS");
    if (!o) return -1;
    if (!strcmp(o, "0")) return 0;
    if (!strcmp(o, "1")) return 1;
    if (!strcmp(o, "all")) return 2;
    return -1;
}

int nft_ingress_all_devs(void) {
    return ingress_env() == 2;
}

int nft_ingress_ok(void) {
    static int cached = -1;
    if (cached >= 0) return cached;
    int o = ingress_env();
    if (o >= 0) return cached = o != 0;
    char text[512];
    snprintf(text, sizeof(text),
             "table inet %s_nprobe {\n"
             "    chain c {\n"
             "        type filter hook ingress device \"lo\" priority 10; policy accept;\n"
             "    }\n"
             "}\n", nft_table());
    return cached = nft_check_text(text) == 1;
}
