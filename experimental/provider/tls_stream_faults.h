#ifndef STEER_TEST_TLS_STREAM_FAULTS_H
#define STEER_TEST_TLS_STREAM_FAULTS_H
#include "stream_backend.h"
struct loop;
struct tls_probe_fault;
/* Test executable only; linker wrapping, no production injection seam. */
struct tls_probe_fault *tls_probe_fault_create(struct loop *,const char *,void (*)(void *),void *);
void tls_probe_fault_enter(struct tls_probe_fault *);
int tls_probe_fault_blocked(const struct tls_probe_fault *);
void tls_probe_fault_unblock(struct tls_probe_fault *);
void tls_probe_fault_lower(struct tls_probe_fault *,struct steer_pv1_stream_ref);
unsigned tls_probe_fault_seen(const struct tls_probe_fault *);
void tls_probe_fault_mark(struct tls_probe_fault *);
void tls_probe_fault_destroy(struct tls_probe_fault *);
#endif
