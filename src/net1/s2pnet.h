/* net1 — плагин-библиотека сетевого стека протоколов (libs2p-net.so.1).
 *
 * Что это и почему так — plugin-sdk/docs/steer-abi.md, «Сервисы протоколам», и open.md, О-1; что
 * линкуется куда — build/sources.mk, «РАСКЛАДКА 2.1». Здесь — только договор версии.
 *
 * ИМЕНА. Наружу net1 отдаёт только s2p_*: имена исходников стека (transport_dial, tls13_read, plat…)
 * переименовывает заголовок, порождённый сборкой из карты build/net1/libs2p-net.map и подключаемый
 * ключом -include и к самой библиотеке, и к плагинам на ней. Исходники не меняются и собираются
 * дважды: в ядро — со своими именами, в net1 — с приставкой. wolfSSL и ngtcp2 вкомпилированы внутрь и
 * скрыты (local: *). В процессе steerd (.so-плагин, которому нужен net1) ни одно имя net1 не совпадает
 * с libsteer и libsteer-wolfssl — musl версий символов не различает.
 *
 * ABI. SONAME несёт major (libs2p-net.so.1), карта — узел LIBS2P_NET_1. minor добавляет экспорт, major
 * ломает. Типы на границе — структуры исходников (struct tun_out, pool_cfg, platform_ops, transport…):
 * плагин и net1 обязаны видеть их одинаково. Это ловит ОТПЕЧАТОК — размеры структур границы,
 * разрядность и порядок байт; помощник сверяет его при запуске (s2pcheck.c) и отказывает строкой,
 * а не портит память. Изменилась раскладка структуры границы или экспорт — новая версия net1 (не меньше
 * minor) и строка в build/net1/abi.lst: tests/buildmatch.sh сверяет отпечаток и экспорт дерева с записанными
 * для S2P_NET_VERSION, так что «та же версия, другая раскладка» не собирается. Плагины на net1 требуют
 * ^<эту версию>; совместимость стоящих плагинов с новой net1 менеджер проверяет пробой до подмены
 * (STEER_LIB_PROBE, s2pcheck.c; src/pluginmgr/pminst.c, «ABI библиотек»). */
#ifndef STEER_S2PNET_H
#define STEER_S2PNET_H

#include <stdint.h>
#include <time.h>

#include "platform.h"
#include "stack.h"
#include "profile.h"
#include "pool.h"
#include "dialer.h"
#include "transport.h"
#include "tun.h"
#include "quic.h"

#define S2P_NET_ABI_MAJOR 1
#define S2P_NET_ABI_MINOR 4
/* Версия плагина net1 (plugins/net1/plugin.json, сверяет tests/buildmatch.sh): major = номер в id. */
#define S2P_NET_VERSION "1.4.0"

struct s2p_net_abi {
    uint32_t size;           /* sizeof(struct s2p_net_abi) — новые поля только в конец */
    uint16_t major, minor;
    uint64_t fingerprint;
    const char *version;     /* S2P_NET_VERSION сборки библиотеки */
};

/* Отпечаток раскладки границы. Считается в заголовке, чтобы плагин и библиотека считали его каждый
 * из СВОИХ определений типов: расхождение и есть то, что нужно поймать. */
#define S2P_FP_MIX(h, v) ((h) = ((h) ^ (uint64_t)(v)) * 1099511628211ull)
static inline uint64_t s2p_net_fingerprint_calc(void) {
    uint64_t h = 14695981039346656037ull;
    S2P_FP_MIX(h, sizeof(void *));
    S2P_FP_MIX(h, sizeof(long));
    S2P_FP_MIX(h, sizeof(time_t));
    S2P_FP_MIX(h, (uint16_t)0x0102 == *(const uint8_t *)&(const uint16_t){0x0102} ? 1 : 2);
    S2P_FP_MIX(h, sizeof(struct tun_out));
    S2P_FP_MIX(h, sizeof(struct platform_ops));
    S2P_FP_MIX(h, sizeof(struct profile));
    S2P_FP_MIX(h, sizeof(struct pool_cfg));
    S2P_FP_MIX(h, sizeof(struct pool_proto));
    S2P_FP_MIX(h, sizeof(struct dialer_ops));
    S2P_FP_MIX(h, sizeof(struct dialer));
    S2P_FP_MIX(h, sizeof(struct tr_node));
    S2P_FP_MIX(h, sizeof(struct transport));
    S2P_FP_MIX(h, sizeof(struct tun_dev));
    S2P_FP_MIX(h, sizeof(struct qc_cfg));
    S2P_FP_MIX(h, sizeof(struct qc_ops));
    return h;
}

/* Единственная «родная» функция net1: с чем собрана библиотека. Приставка s2p_ у неё в исходнике —
 * переименованию она не подлежит (build/build-libs.sh пропускает имена s2p_net_*). */
const struct s2p_net_abi *s2p_net_abi(void);

#endif
