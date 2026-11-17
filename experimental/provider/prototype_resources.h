/* SPDX-License-Identifier: GPL-3.0-only */
#ifndef STEER_DRAFT_PROTOTYPE_RESOURCES_H
#define STEER_DRAFT_PROTOTYPE_RESOURCES_H
#include "buffers.h"
#include "hy2_datagram.h"
/* Caller supplies bounded host settings, never peer input. Preserve original
 * TCP byte/object reserve alongside the independently admitted UDP allowance. */
static inline struct steer_draft_buffer_limits steer_draft_prototype_buffer_limits(unsigned clients,uint32_t capacity,int udp){
    struct steer_draft_buffer_limits limits={2ULL*clients*(capacity+256ULL),2*clients,1};
    if(udp){
        limits.max_bytes+=(uint64_t)STEER_DRAFT_HY2_UDP_RECEIVES*(STEER_DRAFT_HY2_UDP_MESSAGE_BYTES+256ULL)+
            STEER_DRAFT_HY2_UDP_UPLOAD_BYTES+(uint64_t)STEER_DRAFT_HY2_UDP_PACKETS*256;
        limits.max_buffers+=STEER_DRAFT_HY2_UDP_RECEIVES+STEER_DRAFT_HY2_UDP_PACKETS;
    }
    return limits;
}
#endif
