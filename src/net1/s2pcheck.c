/* Сверка net1 при запуске помощника протокола (s2pnet.h, «ABI»).
 *
 * Загрузчик уже нашёл libs2p-net.so.1 (major совпал по SONAME); здесь — то, чего SONAME не говорит:
 * minor библиотеки не меньше того, с которым собран плагин (иначе в ней может не быть нужного
 * экспорта — загрузчик сказал бы об этом сам, но словами компоновщика), и раскладка структур границы
 * та же. Не так — отказ строкой с обеими версиями до первого вызова стека: «перемешались плагин и
 * net1 разных сборок» должно читаться в журнале, а не порчей памяти. Код выхода 2 — отказ
 * (steer-api.md, 1.5). Конструктор, а не вызов из main: main у помощника общий (modcmd.c).
 *
 * ПРОБА (STEER_LIB_PROBE=1). Менеджер плагинов, ставя библиотеку, запускает программы стоящих зависимых
 * с LD_LIBRARY_PATH на её новую копию (src/pluginmgr/pminst.c, «ABI библиотек»): сверка прошла — строка
 * «steer: net1 … подходит» и выход 0 здесь же, до main; не прошла — тот же отказ с кодом 2. Программы
 * прежних сборок переменной не знают: у них сверка та же, а дальше main без подкоманды (код 2 без строки
 * «steer: библиотека») — менеджер различает по строке. */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "s2pnet.h"

__attribute__((constructor)) static void s2p_net_check(void) {
    const struct s2p_net_abi *a = s2p_net_abi();
    if (a->major != S2P_NET_ABI_MAJOR || a->minor < S2P_NET_ABI_MINOR) {
        fprintf(stderr, "steer: библиотека net1 %s (ABI %u.%u), а плагин собран для ABI %u.%u — обновите net1\n",
                a->version, a->major, a->minor, S2P_NET_ABI_MAJOR, S2P_NET_ABI_MINOR);
        exit(2);
    }
    if (a->fingerprint != s2p_net_fingerprint_calc()) {
        fprintf(stderr, "steer: библиотека net1 %s собрана с другой раскладкой структур, чем плагин "
                "(отпечаток %016llx, у плагина %016llx) — нужны net1 и плагин одной ветки ABI\n",
                a->version, (unsigned long long)a->fingerprint,
                (unsigned long long)s2p_net_fingerprint_calc());
        exit(2);
    }
    const char *probe = getenv("STEER_LIB_PROBE");
    if (probe && *probe == '1') {
        printf("steer: net1 %s (ABI %u.%u, отпечаток %016llx) подходит\n", a->version, a->major, a->minor,
               (unsigned long long)a->fingerprint);
        fflush(stdout);
        _exit(0);
    }
}
