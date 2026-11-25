/* SPDX-License-Identifier: GPL-3.0-only
 * One bounded prepare worker, source-only host seam. */
#ifndef STEER_PROTOTYPE_PREPARE_H
#define STEER_PROTOTYPE_PREPARE_H
#include "prototype_config.h"
struct loop;
struct steer_prototype_prepare;
struct steer_prototype_prepared_input {
    struct steer_prototype_config *config;
#ifdef STEER_PROTOTYPE_HY2
    struct steer_hy2_profile *hy2_out[STEER_POLICY_STREAM_BINDINGS_MAX];
    struct qc_server_tls *tls[STEER_PROTOTYPE_MAX_LISTENERS];
    uint8_t certificate_hash[STEER_PROTOTYPE_MAX_LISTENERS][32];
    uint8_t private_key_hash[STEER_PROTOTYPE_MAX_LISTENERS][32];
#endif
    uint64_t expected,serial,deadline_ms;
    unsigned control_index;
    int validate,error; /* HTTP-style error;499 means cancelled, never published */
};
#ifdef STEER_PROTOTYPE_HY2
/* Worker or bootstrap only. The environment is immutable for this process. */
int steer_prototype_prepare_hy2_outbound(const struct steer_prototype_stream_outbound *,
    uint64_t generation,struct steer_hy2_profile **);
#endif
/* Callback runs on owner loop after synchronized immutable result handoff.
 * Borrowed result is disposed after return: take ownership by clearing fields.
 * No control/listener pointers cross to worker. Inputs are copied before submit. */
typedef void (*steer_prototype_prepare_done)(void *,struct steer_prototype_prepared_input *);
/* The startup allowlist, if supplied, stays immutable until the worker joins. */
int steer_prototype_prepare_create(struct loop *,steer_prototype_prepare_done,void *,
    const struct steer_prototype_socks_vpn_allowlist *,struct steer_prototype_prepare **);
int steer_prototype_prepare_submit(struct steer_prototype_prepare *,const char *,size_t,
    uint64_t generation,uint64_t expected,unsigned control_index,uint64_t serial,int validate,uint64_t deadline_ms);
void steer_prototype_prepare_cancel(struct steer_prototype_prepare *,unsigned,uint64_t);
void steer_prototype_prepare_stop(struct steer_prototype_prepare *);
int steer_prototype_prepare_busy(struct steer_prototype_prepare *);
int steer_prototype_prepare_result_pending(struct steer_prototype_prepare *); /* diagnostic, owner loop */
/* Only after stop and worker exit/result drain. Join occurs with no IO/lock held. */
int steer_prototype_prepare_destroy(struct steer_prototype_prepare *);
/* Startup-failure / after-loop cleanup only, never while serving dataplane.
 * Stops and joins before releasing state; regular-file IO cannot be force-killed. */
void steer_prototype_prepare_join_destroy(struct steer_prototype_prepare *);
#endif
