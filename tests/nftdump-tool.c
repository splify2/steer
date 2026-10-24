/* Инструмент стенда tests/nftdumpmatch.sh: дампы nftables по netlink (src/lib/nftdump.c).
 *   rules TABLE CHAIN        — сколько правил цепочки отдал nfd_chain_rules;
 *   chain TABLE CHAIN        — nfd_chain_exists (1/0);
 *   sets TABLE               — имена наборов таблицы, по одному в строке;
 *   elems TABLE SET          — «число_элементов длина_ключа» первого элемента. */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "nftdump.h"

static void rule_cb(void *arg, const char *comment, int has_counter, uint64_t p, uint64_t b) {
    (void)comment; (void)has_counter; (void)p; (void)b;
    (*(int *)arg)++;
}

static void set_cb(void *arg, const struct nfd_set *s) {
    (void)arg;
    printf("%s\n", s->name);
}

struct el { int n; size_t klen; };

static void elem_cb(void *arg, const struct nfd_elem *e) {
    struct el *x = arg;
    if (!x->n++) x->klen = e->klen;
}

int main(int argc, char **argv) {
    if (argc >= 4 && !strcmp(argv[1], "rules")) {
        int n = 0;
        const char *ch[1] = { argv[3] };
        int rc = nfd_chain_rules(NFD_INET, argv[2], ch, 1, rule_cb, &n);
        printf("%d\n", rc ? -1 : n);
    } else if (argc >= 4 && !strcmp(argv[1], "chain")) {
        printf("%d\n", nfd_chain_exists(NFD_INET, argv[2], argv[3]));
    } else if (argc >= 3 && !strcmp(argv[1], "sets")) {
        return nfd_sets(argv[2], set_cb, NULL) != 0;
    } else if (argc >= 4 && !strcmp(argv[1], "elems")) {
        struct el x = { 0, 0 };
        int rc = nfd_set_elems(NFD_INET, argv[2], argv[3], elem_cb, NULL, &x, NULL);
        printf("%d %zu\n", rc ? -1 : x.n, x.klen);
    } else {
        fprintf(stderr, "nftdump-tool: rules|chain|sets|elems\n");
        return 2;
    }
    return 0;
}
