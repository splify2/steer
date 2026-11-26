/* Устройство AmneziaWG/WireGuard по файлу — слой под видом awg (src/kinds/awgdev.c). Общий у вида awg ядра
 * и программы плагина warpbox: модели спеки в нём нет. */
#ifndef STEER_AWGDEV_H
#define STEER_AWGDEV_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "awg.h"

#define AWG_LINK_MARKER_MAX 64u
struct kind_name;

struct awg_live_peer {
    uint8_t pub[AWG_KEY_LEN];
    int64_t hs;                     /* время последнего рукопожатия, секунды эпохи; 0 — не было */
    uint64_t rx, tx;
    struct sockaddr_storage ep;
    socklen_t ep_len;
};

struct awg_live {
    size_t peer_n;
    struct awg_live_peer peer[AWG_MAX_PEERS * 2];
    uint32_t fwmark;
};

/* Поднять и настроить устройство dev по файлу conf_path: создать, если нет (amneziawg, при
 * отсутствии модуля и файле без обфускации — wireguard), настроить одним сообщением, MTU, адреса,
 * подъём. fwmark — метка сокета туннеля (подложка или «мимо каналов»); via — имя подложки (только
 * для слов журнала и правила «через подложку — только IPv4»), NULL — напрямую. who — как назвать
 * в журнале («выход nl»). loud — предупреждения о файле; fresh — пиры заново (новая сессия);
 * names — ответы сторожа на имена Endpoint (NULL — разрешить самим). 0 — готово. */
int awg_dev_configure(const char *who, const char *dev, const char *conf_path, uint32_t fwmark,
                      const char *via, int loud, int fresh, const struct kind_name *names, size_t nn);

/* Устройство: 0 — есть (kind — вид ядра, index — номер; оба необязательны), иначе errno. */
int awg_dev_link_query(const char *ifname, char *kind, size_t kn, int *index);
int awg_dev_link_delete(const char *ifname);
/* Marker companions for journaled managed resources; legacy helpers unchanged.
 * This emits IFLA_IFALIAS in the creation request, but pinned Linux ignores
 * alias at create. Managed creation must use the composite owned API below.
 * Marker is a bounded nonsecret owner token, never credentials. Missing/wrong
 * marker refuses mutation. Caller pins boot/netns identity and serializes
 * privileged ownership; rtnetlink supplies no cross-process marker CAS. */
int awg_dev_link_query_marked(const char *,char *,size_t,int *,char *,size_t);
int awg_dev_link_create_marked(const char *,const char *,int,const char *,int *);
int awg_dev_link_down_marked(const char *,const char *,int,const char *);
int awg_dev_link_delete_marked(const char *,const char *,int,const char *);
/* Managed variants preserve ONE absolute CLOCK_MONOTONIC deadline across
 * identity query and mutation. Zero is invalid, never a timeout reset. */
int awg_dev_link_query_marked_until(const char *,char *,size_t,int *,char *,size_t,uint64_t);
int awg_dev_link_create_marked_until(const char *,const char *,int,const char *,int *,uint64_t);
int awg_dev_link_down_marked_until(const char *,const char *,int,const char *,uint64_t);
int awg_dev_link_delete_marked_until(const char *,const char *,int,const char *,uint64_t);

/* Composite managed ownership. The coordinator MUST durably record a freshly
 * cryptographic-random physical name (not the logical spec name), nonzero random
 * group, boot/netns identity BEFORE create. Intended marker entropy: 13 base32
 * name characters + 32 group bits. These helpers never generate/adopt a marker.
 * Fresh query verifies persisted group; mutators use precise ifindex only after
 * name/kind/index/group comparison. Never group-only delete/change. External
 * privileged mutation between query and action is not an atomic kernel CAS. */
int awg_dev_link_query_owned_until(const char *,char *,size_t,int *,uint32_t *,uint64_t);
/* Fresh exact-owned link state; 0 only when confirmed UP. */
int awg_dev_link_require_up_owned_until(const char *,const char *,int,uint32_t,uint64_t);
/* Compare effective key material without returning it; no mutations. */
int awg_dev_attest_single_wg_until(const char *,int,uint32_t,const struct awg_conf *,
    const struct awg_secrets *,uint64_t);
/* Inbound identity only: exactly one peer and one IPv4 /32 AllowedIPs entry.
 * Endpoint is intentionally ignored (roaming); no local address or secret
 * material is attested. Refuses split/ambiguous device replies. */
int awg_dev_attest_inbound_peer_until(const char *,int,uint32_t,const uint8_t public_key[32],
    const struct awg_prefix *,uint64_t);
/* Exact RTM_GETLINK by index: zero means a link exists, ENODEV means absent. */
int awg_dev_link_index_until(int index,uint64_t deadline);
int awg_dev_link_create_owned_until(const char *,const char *,int,uint32_t,int *,uint64_t);
int awg_dev_link_down_owned_until(const char *,const char *,int,uint32_t,uint64_t);
int awg_dev_link_delete_owned_until(const char *,const char *,int,uint32_t,uint64_t);
/* Stage one address on a verified DOWN link, exclusive (no replace/delete).
 * UP is a separate guarded step; caller must have installed packet admission
 * policy first. All errors after send need observation before claiming rollback. */
int awg_dev_link_require_down_owned_until(const char *,const char *,int,uint32_t,uint64_t);
int awg_dev_address_add_owned_until(const char *,const char *,int,uint32_t,const struct awg_prefix *,uint64_t);
int awg_dev_link_up_owned_until(const char *,const char *,int,uint32_t,uint64_t);
/* Isolated IPv4 egress: exclusive main-table link route. No replace or
 * default route; deleting the owned link also removes its attached route. */
int awg_dev_route_add_owned_until(const char *,const char *,int,uint32_t,const struct awg_prefix *,uint64_t);
int awg_dev_route_check_owned_until(const char *,const char *,int,uint32_t,const struct awg_prefix *,uint64_t);
/* Disposable namespace only. Group-derived private table; exact oif lookup
 * and terminal stop rules. Retire rules before deleting the owned link. */
int awg_dev_scoped_route_add_until(const char *,const char *,int,uint32_t,const struct awg_prefix *,uint64_t);
int awg_dev_scoped_route_check_until(const char *,const char *,int,uint32_t,const struct awg_prefix *,uint64_t);
int awg_dev_scoped_route_match_until(int,uint32_t,const struct awg_prefix *,const uint8_t [4],const uint8_t [4],uint64_t);
int awg_dev_scoped_rules_retire_until(const char *,int,uint32_t,uint64_t);

/* Exclusive device creation for the experimental owned-device adapter. Never
 * adopts/reconfigures an existing link. kind must be wireguard/amneziawg.
 * On success out_index identifies the fresh link in the current net namespace;
 * a captured index may also be returned on later ACK failure for rollback.
 * Same namespace and serialized privileged ownership are caller obligations. */
int awg_dev_link_create_exclusive(const char *ifname, const char *kind, int mtu,
                                  int *out_index);
/* Deletes by captured index only after name/kind/index identity matches.
 * Replacement links are refused with ESTALE; legacy delete-by-name unchanged. */
int awg_dev_link_delete_owned(const char *ifname, const char *kind, int index);
/* Fail-closed quiesce by captured identity; never changes a replacement link. */
int awg_dev_link_down_owned(const char *ifname, const char *kind, int index);
/* Managed parsed-input companions. Caller owns immutable config/keys through
 * return, including every non-NULL istr target (deep owned or prepared pin).
 * All temporary message storage is operation-owned and wiped. No
 * file/state writes, DNS, create/recreate, address changes or implicit UP.
 * Numeric endpoints must already be resolved. Exact IFINDEX is sent after a
 * fresh composite check; caller additionally pins boot/netns and guards policy.
 * Errors after mutation submission may mean UNCERTAIN, not rolled back. */
int awg_dev_configure_owned_until(const char *,const char *,int,uint32_t,
    const struct awg_conf *,const struct awg_secrets *,uint32_t,uint64_t);
int awg_dev_live_read_owned_until(const char *,const char *,int,uint32_t,struct awg_live *,uint64_t);
/* Вид устройства — наш туннель (amneziawg или wireguard). */
int awg_dev_ours(const char *kind);
/* Пиры устройства из ядра (рукопожатие, счётчики, эндпоинт). 0 — прочитано. */
int awg_dev_live_read(const char *ifname, const char *kind, struct awg_live *L);
/* Забыть файлы состояния устройства (подпись параметров, замер счётчиков). */
void awg_dev_state_drop(const char *dev);
/* Обрезать пробелы по краям (на месте). */
char *awg_dev_trim(char *s);

#endif
