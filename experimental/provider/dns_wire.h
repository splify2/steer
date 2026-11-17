#ifndef STEER_DRAFT_DNS_WIRE_H
#define STEER_DRAFT_DNS_WIRE_H
#include <stddef.h>
#include <stdint.h>
#define STEER_DNS_PACKET_MAX 4096u
#define STEER_DNS_ADDRESS_MAX 16u
struct steer_dns_question { char name[254]; uint16_t id,type; size_t end; };
struct steer_dns_address { uint8_t family,bytes[16]; uint32_t ttl; };
struct steer_dns_answer { uint16_t rcode; uint32_t ttl,count; struct steer_dns_address addresses[STEER_DNS_ADDRESS_MAX]; };
/* Strict single IN question. Names are normalized ASCII lowercase; compression
 * is accepted with bounded traversal, including questions in upstream replies. */
int steer_dns_question_read(const uint8_t *,size_t,struct steer_dns_question *);
int steer_dns_query(const char *,uint16_t,uint16_t,uint8_t *,size_t,size_t *);
/* Verifies ID, QR/opcode, question identity and every record boundary. TC is an
 * error (transport must explicitly retry); unrelated RR addresses are excluded.
 * CNAME chains are bounded, conflicting aliases rejected. No DNSSEC claim. */
int steer_dns_answer_read(const uint8_t *,size_t,const struct steer_dns_question *,int ipv4_only,struct steer_dns_answer *);
/* Empty NOERROR reply for policy synthesis (e.g. AAAA, HTTPS/SVCB suppression).
 * Copies only a validated question; preserves RD, sets QR+RA. */
int steer_dns_empty(const uint8_t *,size_t,uint8_t *,size_t,size_t *);
#endif
