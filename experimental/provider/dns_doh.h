#ifndef STEER_DRAFT_DNS_DOH_H
#define STEER_DRAFT_DNS_DOH_H
#include "dns_wire.h"
/* HTTP/1.1 POST codec for a verified TLS origin stream. No networking authority
 * or DNS bootstrap is acquired here. Host/path are trusted validated provider
 * configuration, never query input. One request per origin stream. */
#define STEER_DNS_DOH_HTTP_MAX 12288u
int steer_dns_doh_request(const char *,const char *,const uint8_t *,size_t,uint8_t *,size_t,size_t *);
/* 0 incomplete, 1 complete, -1 invalid/unsupported. Bounded HTTP headers and DNS
 * body; rejects ambiguity, trailers, HTTP upgrades, redirects and excess bytes.
 * Supports Content-Length and chunked; no close-delimited bodies. DNS matching
 * and cache decisions remain in dns_runtime. */
int steer_dns_doh_response(const uint8_t *,size_t,uint8_t *,size_t,size_t *);
#endif
