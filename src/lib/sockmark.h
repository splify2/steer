/* Метка собственного сокета steer: метка выхода (или 0 — напрямую) и бит «не твой» общему обходу DPI.
 *
 * ЗАЧЕМ. Общий zapret роутера (nfqws по TCP 443 и QUIC) входит в пакет по условию
 * `meta mark & 0x40000000 == 0` (ZAPRET_SKIP_MARK, marks.h). Трафику клиентов, которого ведёт ядро
 * steer, этот бит ставит правило разметки (out_skips_zapret), а собственные соединения steer — DoH,
 * DoT и DoQ резолвера, соединения модулей с узлами, замеры групп — шли к
 * zapret без него, и тот «рассинхронизировал» их рукопожатие TLS: DoH отваливался то и дело
 * (жалоба владельца 2026-10-13, «кажись я знаю кто причина — zapret»). Теперь бит стоит на каждом
 * сокете steer, где бы тот ни шёл.
 *
 * Только на платформе с zapret (plat()->zapret): на телефоне метки сокетов — поле netd, и лишний бит
 * там ни к чему. Метка выхода не ноль — отказ SO_MARK ошибка, как прежде (без неё соединение ушло бы
 * мимо выхода); ноль — отказ не ошибка: без прав (стенды не от root) сокет остаётся прежним. */
#ifndef STEER_SOCKMARK_H
#define STEER_SOCKMARK_H
#include <stdint.h>
#include <sys/socket.h>
#include "spec.h"
#include "marks.h"
#include "platform.h"

/* Ссылка на plat слабая: стенды компонуют транспорт без платформы (tests/trdialmatch.c) — там бит
 * ставится, как на роутере. */
#pragma weak plat
static inline uint32_t steer_own_mark(uint32_t mark) {
    return !plat || plat()->zapret ? mark | ZAPRET_SKIP_MARK : mark;
}

/* 0 — метка стоит (или ставить нечего), -1 — метку выхода поставить не удалось. */
static inline int steer_sock_mark(int fd, uint32_t mark) {
    uint32_t m = steer_own_mark(mark);
    if (!m) return 0;
    if (setsockopt(fd, SOL_SOCKET, SO_MARK, &m, sizeof(m)) == 0) return 0;
    return mark ? -1 : 0;
}
#endif
