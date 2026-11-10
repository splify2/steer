/* Инструмент стенда tests/rtnlmatch.sh: дампы ядра через src/lib/rtnl.c, результат — числа.
 *   rules 4|6          — строк в дампе правил;
 *   routes 4|6 TABLE   — строк в дампе таблицы (-1 — не прочитано);
 *   main6              — сколько маршрутов IPv6 main отдал rtnl_main6_routes;
 *   addrs6             — сколько адресов IPv6 отдал rtnl_addrs6;
 *   flush TABLE        — код rtnl_table_flush;
 *   defdevs            — устройства маршрутов по умолчанию main (rtnl_default_devs), через пробел
 *                        по порядку дампа; «-» — дамп не прочитан. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rtnl.h"

static void dev_add(const char *dev, void *ctx) {
    char *line = ctx;
    size_t n = strlen(line);
    snprintf(line + n, 512 - n, "%s%s", n ? " " : "", dev);
}

static long lines(const char *s) {
    long n = 0;
    for (; *s; s++) n += *s == '\n';
    return n;
}

int main(int argc, char **argv) {
    if (argc >= 3 && !strcmp(argv[1], "rules")) {
        char *d = rtnl_rules_dup(atoi(argv[2]) == 6);
        printf("%ld\n", d ? lines(d) : -1L);
        free(d);
    } else if (argc >= 4 && !strcmp(argv[1], "routes")) {
        char *d = rtnl_routes_dup(atoi(argv[3]), atoi(argv[2]) == 6);
        printf("%ld\n", d ? lines(d) : -1L);
        free(d);
    } else if (argc >= 2 && !strcmp(argv[1], "main6")) {
        struct rtnl_route6 *v;
        printf("%d\n", rtnl_main6_routes(&v));
        free(v);
    } else if (argc >= 2 && !strcmp(argv[1], "addrs6")) {
        struct rtnl_addr6 *v;
        printf("%d\n", rtnl_addrs6(&v));
        free(v);
    } else if (argc >= 3 && !strcmp(argv[1], "flush")) {
        printf("%d\n", rtnl_table_flush(atoi(argv[2])));
    } else if (argc >= 2 && !strcmp(argv[1], "defdevs")) {
        char line[512] = "";
        if (rtnl_default_devs(dev_add, line) != 0) printf("-\n");
        else printf("%s\n", line);
    } else {
        fprintf(stderr, "rtnl-tool: rules|routes|main6|addrs6|flush|defdevs\n");
        return 2;
    }
    return 0;
}
