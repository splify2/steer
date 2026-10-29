/* Торренты клиентов правила (`torrent: block | direct` правила v2) — распознавание и запоминание
 * в наборе правил. Устройство и доводы — в torrent.c. */
#ifndef STEER_TORRENT_H
#define STEER_TORRENT_H
#include <stdio.h>

struct nft_table;
struct groups;

/* Цепочки распознавания (по политике): правило канала с ключом переходит в цепочку своей
 * политики раньше своей метки. */
#define TORRENT_CHAIN_BLOCK  "torrent_block"
#define TORRENT_CHAIN_DIRECT "torrent_direct"
/* Срок памяти и её потолок (доводы — у torrent_emit). */
#define TORRENT_TTL  "10m"
#define TORRENT_SIZE 65535ul

/* Есть ли у каналов gr политика pol (TORRENT_BLOCK, TORRENT_DIRECT); pol 0 — любая. */
int torrent_used(const struct groups *gr, int pol);
/* Наборы памяти и цепочки распознавания тех политик, что есть у каналов gr. Ставится ДО цепочки
 * разметки: правило с переходом в цепочку, объявленную ниже по тексту, nft -f не примет. */
void torrent_emit(struct nft_table *t, const struct groups *gr);
/* Поле status `torrent` (только если у каналов есть политика): счётчики отвергнутого и пущенного
 * напрямую из ядра и число запомненных записей. */
void torrent_status_print(FILE *out, const struct groups *gr);

#endif
