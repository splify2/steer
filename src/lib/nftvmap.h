/* nf_tables по netlink — КАРТА ВЕРДИКТОВ группы pick: balance (docs/architecture.md, «4в»).
 *
 * ЗАЧЕМ. Правило группы balance ищет номер `numgen random mod N` в карте `type mark : verdict`,
 * и элемент карты говорит, в цепочку какого члена уйти (`goto`). Упавший член должен выпасть из
 * раздачи сразу, а ожившее — вернуться, и делать это перезагрузкой всего набора правил нельзя:
 * apply пересоздаёт таблицу, а с ней счётчики и наборы резолвера. Сторож меняет только
 * элементы карты — одной транзакцией nf_tables, без процесса nft.
 *
 * КЛЮЧ. Тип `mark` — целое В ПОРЯДКЕ ХОСТА (так его пишет nft и так его выдаёт numgen в регистр):
 * четыре байта ключа — uint32_t номера как есть в памяти, без htonl. Проверено дампом элемента,
 * положенного `nft add element` (tests/nftvmapmatch.sh). Код вердикта и сам вердикт — как у
 * всех скаляров nf_tables: big-endian.
 *
 * АТОМАРНОСТЬ. Запись — один батч NFNL_MSG_BATCH_BEGIN … END: снятие прежних элементов и
 * добавление новых. Ядро применяет батч целиком или не применяет вовсе, поэтому пакет не
 * застаёт карту «наполовину»: элемент, который меняет цепочку, снимается и кладётся в той же
 * транзакции, и промежутка без него нет.
 *
 * Синхронно, свой сокет на вызов — как nftdump.c. Глобалов резолвера (nftnl.c) не трогает. */
#ifndef STEER_NFTVMAP_H
#define STEER_NFTVMAP_H

#include <stdint.h>
#include <stddef.h>

#define NFV_CHAIN_MAX 32

/* Карта `type mark : verdict` таблицы family/table: элементы «номер → goto цепочка».
 * chain[i] — имя цепочки перехода элемента с ключом i ("" — элемента нет), i < slots.
 * Возврат — сколько элементов прочитано (>= 0); -1 — карты нет или ядро не ответило (errno). */
int nfv_map_read(uint8_t family, const char *table, const char *map, char (*chain)[NFV_CHAIN_MAX],
                 size_t slots);

/* Привести карту к want одной транзакцией (батч NFNL_MSG_BATCH_BEGIN … END): для каждого i, где
 * have[i] != want[i], — снять прежний элемент (если have[i] не пуст) и положить новый (goto
 * want[i], если не пуст). have — то, что прочитал nfv_map_read (NULL — считать карту пустой).
 * 0 — ядро приняло всё; -1 — отказ (errno), и тогда ядро не изменилось (транзакция целиком). */
int nfv_map_write(uint8_t family, const char *table, const char *map,
                  const char (*want)[NFV_CHAIN_MAX], const char (*have)[NFV_CHAIN_MAX],
                  size_t slots);

/* ИНТЕРВАЛЬНЫЙ НАБОР ipv6_addr — префикс хоста у донора IPv6 (набор v6donor, шаг 8 выпуска 1.10).
 * Здесь же, а не в nftnl.c резолвера, по той же причине, что карта: пишет его сторож (v6donor_sync
 * в failover.c) — без процесса nft и без глобалов резолвера, одной транзакцией.
 *
 * Отрезок — [lo, hi): в ядре это два элемента, начало и маркер конца (NFT_SET_ELEM_INTERVAL_END)
 * с ключом hi, как их кладёт `nft add element … { 2001:db8:1::/56 }`.
 *
 * Чтение: сколько отрезков в наборе (в v — первые max, по возрастанию); -1 — набора нет, ядро не
 * ответило или элементов больше NFV_RANGES6_MAX (errno). Запись: набор целиком становится want —
 * сброс и новые отрезки в одном батче; 0 или -1 (errno), и тогда ядро не изменилось. */
#define NFV_RANGES6_MAX 16
struct nfv_range6 { uint8_t lo[16], hi[16]; };
int nfv_ranges6_read(uint8_t family, const char *table, const char *set, struct nfv_range6 *v,
                     size_t max);
int nfv_ranges6_write(uint8_t family, const char *table, const char *set,
                      const struct nfv_range6 *want, size_t n);

/* Набор имён устройств (type ifname, ключ — IFNAMSIZ байт с нулями) целиком становится names[0..n):
 * сброс и новые элементы одной транзакцией, как у nfv_ranges6_write. Набора нет — -1 и ENOENT.
 * 0 или -1 с errno. */
int nfv_ifnames_write(uint8_t family, const char *table, const char *set, const char *const *names, size_t n);

#endif
