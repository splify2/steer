#ifndef STEER_PROTOTYPE_WG_H
#define STEER_PROTOTYPE_WG_H
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
struct steer_pv1_flow_metadata;
struct steer_prototype_wg;
/* Isolated host profile, never enabled in the default binary. */
int steer_prototype_wg_open(const char *,int outer_ns,uint16_t socks_port,int scoped,struct steer_prototype_wg **);
void steer_prototype_wg_close(struct steer_prototype_wg *);
int steer_prototype_wg_request(struct steer_prototype_wg *,int operation,uint64_t expected,
    const char *,size_t,char *,size_t,size_t *);
uint64_t steer_prototype_wg_revision(const struct steer_prototype_wg *);
int steer_prototype_wg_select(const struct steer_prototype_wg *,uint64_t,const struct steer_pv1_flow_metadata *);
/* Native connector callback: refuses rather than dial an unbound socket. */
uint32_t steer_prototype_wg_bind_stream(void *,int,const struct sockaddr_storage *,uint64_t);
#endif
