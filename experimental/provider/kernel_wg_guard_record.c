#include "kernel_wg_guard_record.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

enum {
    LINK = 8,
    INDEX = LINK + STEER_DRAFT_WG_RECORD_BYTES,
    HANDLE = INDEX + 4,
    TABLE = HANDLE + 8,
    MARKER = TABLE + 26
};
_Static_assert(MARKER + 42 == STEER_DRAFT_WG_GUARD_RECORD_BYTES, "guard payload size");

static int prefixed_hex(const char *s,size_t n,const char *prefix){
    size_t p=strlen(prefix);
    if(memcmp(s,prefix,p)||s[n-1])return 0;
    for(;p<n-1;p++)
        if(!((s[p]>='0'&&s[p]<='9')||(s[p]>='a'&&s[p]<='f')))return 0;
    return 1;
}

static int valid_fields(const struct steer_draft_wg_guard_record *r){
    return r->ifindex&&r->ifindex<=INT_MAX&&!memcmp(r->link.kind,"wireguard",10)&&
        prefixed_hex(r->table,sizeof(r->table),"steer_wg_")&&
        prefixed_hex(r->marker,sizeof(r->marker),"steer-wg:");
}

static void put(uint8_t *p,uint64_t v,unsigned n){
    for(unsigned i=0;i<n;i++)p[i]=(uint8_t)(v>>(8*i));
}

static uint64_t get(const uint8_t *p,unsigned n){
    uint64_t v=0;
    for(unsigned i=0;i<n;i++)v|=(uint64_t)p[i]<<(8*i);
    return v;
}

int steer_draft_wg_guard_record_encode(const struct steer_draft_wg_guard_record *r,
    uint8_t out[STEER_DRAFT_WG_GUARD_RECORD_BYTES]){
    if(!r||!out||!valid_fields(r))return EINVAL;
    if(steer_draft_wg_identity_encode(&r->link,out+LINK))return EINVAL;
    memcpy(out,"SWGG0001",LINK);
    put(out+INDEX,r->ifindex,4);
    put(out+HANDLE,r->handle,8);
    memcpy(out+TABLE,r->table,sizeof(r->table));
    memcpy(out+MARKER,r->marker,sizeof(r->marker));
    return 0;
}

int steer_draft_wg_guard_record_decode(const uint8_t *p,size_t n,
    struct steer_draft_wg_guard_record *out){
    if(!out)return EINVAL;
    *out=(struct steer_draft_wg_guard_record){0};
    if(!p||n!=STEER_DRAFT_WG_GUARD_RECORD_BYTES||memcmp(p,"SWGG0001",LINK))return EINVAL;
    struct steer_draft_wg_guard_record r={0};
    if(steer_draft_wg_identity_decode(p+LINK,STEER_DRAFT_WG_RECORD_BYTES,&r.link))return EINVAL;
    r.ifindex=(uint32_t)get(p+INDEX,4);
    r.handle=get(p+HANDLE,8);
    memcpy(r.table,p+TABLE,sizeof(r.table));
    memcpy(r.marker,p+MARKER,sizeof(r.marker));
    if(!valid_fields(&r))return EINVAL;
    *out=r;
    return 0;
}

int steer_draft_wg_guard_record_restore(const uint8_t *intent,size_t intent_len,
    const uint8_t *outcome,size_t outcome_len,struct steer_draft_wg_guard_record *out){
    if(!out)return EINVAL;
    *out=(struct steer_draft_wg_guard_record){0};
    struct steer_draft_wg_guard_record before,after;
    if(steer_draft_wg_guard_record_decode(intent,intent_len,&before))return EINVAL;
    if(!outcome){
        if(outcome_len)return EINVAL;
        before.handle=0;  /* A lost outcome cannot confirm the live handle. */
        *out=before;
        return 0;
    }
    if(steer_draft_wg_guard_record_decode(outcome,outcome_len,&after)||!after.handle||
       after.handle==before.handle||memcmp(intent,outcome,HANDLE)||
       memcmp(intent+TABLE,outcome+TABLE,STEER_DRAFT_WG_GUARD_RECORD_BYTES-TABLE))
        return EINVAL;
    *out=after;
    return 0;
}

uint32_t steer_draft_wg_guard_record_observe(const struct steer_draft_wg_guard_record *r,
    uint64_t handle,const char *marker){
    if(!r||!marker||!valid_fields(r))return STEER_DRAFT_WG_UNKNOWN;
    if(!handle)return *marker?STEER_DRAFT_WG_UNKNOWN:STEER_DRAFT_WG_ABSENT;
    if(strcmp(r->marker,marker))return STEER_DRAFT_WG_FOREIGN;
    return r->handle==handle?STEER_DRAFT_WG_OWNED:STEER_DRAFT_WG_UNKNOWN;
}
