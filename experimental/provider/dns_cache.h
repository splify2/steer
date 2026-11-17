#ifndef STEER_DRAFT_DNS_CACHE_H
#define STEER_DRAFT_DNS_CACHE_H
#include "dns_wire.h"
struct steer_dns_cache;
/* Separate immutable identity for provider+policy. Host derives this from exact
 * validated configuration; a reload changing route/provider/policy must change
 * it. Stored entries from other identities are never accepted. */
struct steer_dns_cache_key {uint8_t identity[32];char name[254];uint16_t type;};
struct steer_dns_cache *steer_dns_cache_create(uint32_t);
void steer_dns_cache_free(struct steer_dns_cache *);
int steer_dns_cache_put(struct steer_dns_cache *,const struct steer_dns_cache_key *,const struct steer_dns_answer *,uint64_t now_ms);
int steer_dns_cache_get(struct steer_dns_cache *,const struct steer_dns_cache_key *,uint64_t now_ms,struct steer_dns_answer *);
int steer_dns_cache_reverse(struct steer_dns_cache *,const uint8_t identity[32],uint8_t family,const uint8_t *,uint64_t now_ms,char name[254]);
/* Versioned bounded binary snapshot, contains positive address answers only.
 * Pure memory routines: filesystem read/write/rename/fsync MUST use shared host
 * workers, never owner loop IO. Export snapshots borrowed cache on owner, then
 * worker writes copied bytes. Import only at generation prepare, before use.
 * Wall clock is explicit; backwards clock movement rejects snapshot, maximum
 * persisted lifetime one day. Invalid/trailing bytes reject entire import.
 * No raw upstream packets or untrusted file paths enter live cache. */
size_t steer_dns_cache_snapshot_max(const struct steer_dns_cache *);
int steer_dns_cache_export(const struct steer_dns_cache *,uint64_t mono_ms,uint64_t wall_seconds,uint8_t *,size_t,size_t *);
int steer_dns_cache_import(struct steer_dns_cache *,const uint8_t identity[32],uint64_t mono_ms,uint64_t wall_seconds,const uint8_t *,size_t);
#endif
