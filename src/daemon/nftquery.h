#ifndef STEER_NFTQUERY_H
#define STEER_NFTQUERY_H

/* Мелкие запросы к живому ядру — общие для diag.c и explain.c (src/daemon/nftquery.c). Ядро
 * спрашивается по netlink (src/lib/nftdump.c), без запуска nft. */

#include <stdint.h>

long set_count(const char *name);
int nft_chain_here(const char *chain);
int parse_prefix(const char *s, uint32_t *net, uint32_t *mask);
int ipv4_span(const char *t, uint32_t *lo, uint32_t *hi);
int ipv6_span(const char *t, uint8_t lo[16], uint8_t hi[16]);

#endif
