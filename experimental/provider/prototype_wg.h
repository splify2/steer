#ifndef STEER_PROTOTYPE_WG_H
#define STEER_PROTOTYPE_WG_H
#include <stddef.h>
#include <stdint.h>
struct steer_prototype_wg;
/* Isolated host profile, never enabled in the default binary. */
int steer_prototype_wg_open(const char *,int outer_ns,struct steer_prototype_wg **);
void steer_prototype_wg_close(struct steer_prototype_wg *);
int steer_prototype_wg_request(struct steer_prototype_wg *,int operation,uint64_t expected,
    const char *,size_t,char *,size_t,size_t *);
#endif
