#ifndef STEER_NFTNL_H
#define STEER_NFTNL_H
#include <stdint.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "nlbuf.h"

#define NFTLK_MSG_CAP     512   /* biggest msg we build: hdrs + ~3 nested attrs */

/* SPLIFY_DNSD_DEBUG за окружением — см. dbg() в nftnl.c. Общий для всего резолвера: netlink
 * (эта библиотека) и горячий путь proxy.c спрашивают его же. */
int dbg(void);

extern const char *g_nft_table;      /* "<family> <table>" — наборы и карты fakeip (см. nftnl.c) */
extern int g_nlk_fd;                 /* долгоживущий сокет nfnetlink, -1 — не открыт */

int nftlk_open(void);
int nftlk_elem_msg(uint16_t nft_msg_type, const char *table,
                    const char *obj_name, const void *key_net,
                    int interval, const void *data_net,
                    uint64_t timeout_ms);
uint32_t set_ttl_clamp(uint32_t ttl);
int nft_add_element(const char *set_name, uint32_t key_host, uint32_t ttl);
/* Ответ ядра на последнее добавление элемента (0, -EEXIST, -ENOENT…): nft_add_element сводит его
 * к 0/-1, а восстановлению после старта нужно отличить «набора нет вовсе» (fakeip_rehydrate). */
extern int nft_last_add_rc;
int nft_set_has(const char *set_name, const void *key_net, size_t alen);
/* Элемент составного набора `ipv4_addr . inet_proto . inet_service` (см. nftnl.c): адрес и
 * ящик «протоколы × порты». add — положить (ttl в секундах, 0 — навсегда) или убрать. 0 —
 * в ядре желаемое состояние (EEXIST при добавлении и ENOENT при удалении — тоже). */
struct nftlk_box { uint8_t plo, phi; uint16_t lo, hi; };
int nft_concat_element(int add, const char *set_name, uint32_t addr_host,
                       const struct nftlk_box *box, uint32_t ttl);
int nft_map_set_element(const char *map_name, uint32_t fake_host,
                         uint32_t real_host, uint32_t known_real);

/* IPv6 (fake-IP v6 и real-ip v6, docs/architecture.md, «4б»): те же операции с адресами из 16
 * байт в порядке сети. known_real — установленное значение карты или NULL («не знаем»). */
int nftlk_elem_msg6(uint16_t nft_msg_type, const char *table,
                     const char *obj_name, const uint8_t key[16],
                     int interval, const uint8_t *data, uint64_t timeout_ms);
int nft_add_element6(const char *set_name, const uint8_t key[16], uint32_t ttl);
int nft_concat_element6(int add, const char *set_name, const uint8_t addr[16],
                        const struct nftlk_box *box, uint32_t ttl);
int nft_map_set_element6(const char *map_name, const uint8_t fake[16], const uint8_t real[16],
                         const uint8_t *known_real);
/* Подмена fake → real по тому, что стоит в ядре, а не по памяти (после замены набора правил карта
 * засеяна из файла, и память ей не свидетель — доводы у map_ensure в nftnl.c). 0 — в ядре
 * желаемое значение, 1 — стояло другое и заменено, иначе отрицательный errno. */
int nft_map_ensure_element(const char *map_name, uint32_t fake_host, uint32_t real_host);
int nft_map_ensure_element6(const char *map_name, const uint8_t fake[16],
                            const uint8_t real[16]);
/* Снять адрес key (alen — 4 или 16, порядок сети) из интервального набора g_nft_table, где он
 * лежит внутри слитого отрезка (засев набора правил и auto-merge): отрезок заменяется его частями
 * без key одной транзакцией. Только отрезок без срока, целиком внутри [lo, hi] (пул fake-IP). 0 —
 * вырезан; -ENOENT — такого отрезка нет (или он не наш); иное — отказ ядра. Доводы — в nftnl.c. */
int nft_elem_carve(const char *set, const uint8_t *key, size_t alen, const uint8_t *lo,
                   const uint8_t *hi);

#endif
