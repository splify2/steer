#ifndef STEER_PROTOTYPE_LINKED_WG_H
#define STEER_PROTOTYPE_LINKED_WG_H
#include "kernel_wg_v3.h"
#include "kernel_wg_stream.h"

struct steer_prototype_config;
struct steer_prototype_linked_wg;
struct steer_linked_wg_config {
    struct steer_draft_wg_v3_config cfg;
    struct awg_prefix route;
    char private_env[64], psk_env[64];
};
int steer_linked_wg_open(const char *,int outer,struct steer_prototype_linked_wg **);
void steer_linked_wg_close(struct steer_prototype_linked_wg *);
int steer_linked_wg_keys(const struct steer_linked_wg_config *,struct awg_secrets *);
int steer_linked_wg_recover(struct steer_prototype_linked_wg *,const struct steer_prototype_config *,
    uint64_t *next,struct steer_draft_wg_stream **);
int steer_linked_wg_stage(struct steer_prototype_linked_wg *,const struct steer_prototype_config *,
    const struct awg_secrets *,uint64_t deadline,struct steer_draft_wg_stream **);
void steer_linked_wg_commit(struct steer_prototype_linked_wg *,const struct steer_prototype_config *);
int steer_linked_wg_retire(struct steer_prototype_linked_wg *,uint64_t);
#endif
