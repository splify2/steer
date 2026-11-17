#define _GNU_SOURCE
#include "kernel_wg_ownership.h"
#include "awgdev.h"
#include <steer/draft/device_v1.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static uint64_t now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*1000000000u+(uint64_t)t.tv_nsec;}
static int interrupted(uint64_t deadline,const atomic_uint *cancel){
    if(!deadline)return EINVAL;
    if(cancel&&atomic_load_explicit(cancel,memory_order_relaxed))return ECANCELED;
    uint64_t now=now_ns();return !now?EIO:now>=deadline?ETIMEDOUT:0;
}
static int hex(unsigned char c){return c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:-1;}
static int boot_id(uint8_t out[16]){
    unsigned char text[38];int fd=open("/proc/sys/kernel/random/boot_id",O_RDONLY|O_CLOEXEC|O_NONBLOCK);if(fd<0)return errno;
    ssize_t n=read(fd,text,sizeof text);int saved=errno;close(fd);if(n!=37||text[36]!='\n')return n<0?saved:EPROTO;
    unsigned i=0;for(unsigned j=0;j<36;){if(j==8||j==13||j==18||j==23){if(text[j++]!='-')return EPROTO;continue;}
        int a=hex(text[j++]),b=hex(text[j++]);if(a<0||b<0||i>=16)return EPROTO;out[i++]=(uint8_t)((a<<4)|b);}
    return i==16?0:EPROTO;
}
static int valid(const struct steer_draft_wg_identity *i){
    if(!i||!i->generation||!i->instance_token||!i->namespace_inode||!i->group)return 0;
    if(memcmp(i->physical_name,"sw",2)||i->physical_name[15])return 0;
    for(unsigned j=2;j<15;j++){unsigned c=(unsigned char)i->physical_name[j];if(!((c>='a'&&c<='z')||(c>='2'&&c<='7')))return 0;}
    if(memcmp(i->kind,"wireguard",10)&&memcmp(i->kind,"amneziawg",10))return 0;
    for(unsigned j=10;j<16;j++)if(i->kind[j])return 0;
    unsigned b=0,t=0;for(unsigned j=0;j<16;j++){b|=i->boot_id[j];t|=i->intent_id[j];}return b&&t;
}
static int environment(const struct steer_draft_wg_identity *i,int fd){
    struct stat pinned,current;uint8_t boot[16];if(!valid(i)||fd<0)return EINVAL;
    if(fstat(fd,&pinned)||stat("/proc/thread-self/ns/net",&current))return errno;
    if(pinned.st_dev!=current.st_dev||pinned.st_ino!=current.st_ino||(uint64_t)pinned.st_dev!=i->namespace_device||(uint64_t)pinned.st_ino!=i->namespace_inode)return EXDEV;
    int rc=boot_id(boot);return rc?rc:memcmp(boot,i->boot_id,16)?ESTALE:0;
}
static uint32_t crc(const uint8_t *p,size_t n){uint32_t c=UINT32_MAX;for(size_t j=0;j<n;j++){c^=p[j];for(unsigned k=0;k<8;k++)c=(c>>1)^(0xedb88320u&(0u-(c&1u)));}return ~c;}
static void put(uint8_t *p,uint64_t v,unsigned n){for(unsigned j=0;j<n;j++)p[j]=(uint8_t)(v>>(j*8));}
static uint64_t get(const uint8_t *p,unsigned n){uint64_t v=0;for(unsigned j=0;j<n;j++)v|=(uint64_t)p[j]<<(j*8);return v;}
int steer_draft_wg_identity_prepare(int fd,uint64_t generation,uint64_t token,const char *kind,uint64_t deadline,const atomic_uint *cancel,struct steer_draft_wg_identity *out){
    struct stat pinned,current;uint8_t random[33];static const char alphabet[]="abcdefghijklmnopqrstuvwxyz234567";
    if(!out||!generation||!token||!kind||(strcmp(kind,"wireguard")&&strcmp(kind,"amneziawg")))return EINVAL;
    memset(out,0,sizeof *out);
    int stopped=interrupted(deadline,cancel);if(stopped)return stopped;
    if(fstat(fd,&pinned)||stat("/proc/thread-self/ns/net",&current))return errno;
    if(pinned.st_dev!=current.st_dev||pinned.st_ino!=current.st_ino)return EXDEV;
    out->namespace_device=(uint64_t)pinned.st_dev;out->namespace_inode=(uint64_t)pinned.st_ino;
    int rc=boot_id(out->boot_id);if(rc)return rc;
    ssize_t n=getrandom(random,sizeof random,GRND_NONBLOCK);if(n!=(ssize_t)sizeof random)return n<0?errno:EAGAIN;
    memcpy(out->physical_name,"sw",2);for(unsigned j=0;j<13;j++)out->physical_name[j+2]=alphabet[random[j]&31];
    out->group=(uint32_t)get(random+13,4);memcpy(out->intent_id,random+17,16);
    out->generation=generation;out->instance_token=token;memcpy(out->kind,kind,strlen(kind)+1);
    /* Reject the astronomically unlikely all-zero group/intent rather than
     * replace it with a predictable fixed marker. Caller may retry boundedly. */
    int done=interrupted(deadline,cancel);if(!done&&!valid(out))done=EAGAIN;
    if(done)memset(out,0,sizeof *out);
    return done;
}
int steer_draft_wg_identity_encode(const struct steer_draft_wg_identity *i,uint8_t out[STEER_DRAFT_WG_RECORD_BYTES]){
    if(!out||!valid(i))return EINVAL;
    memset(out,0,STEER_DRAFT_WG_RECORD_BYTES);memcpy(out,"SWGW0001",8);
    put(out+8,i->generation,8);put(out+16,i->instance_token,8);put(out+24,i->namespace_device,8);put(out+32,i->namespace_inode,8);
    memcpy(out+40,i->boot_id,16);memcpy(out+56,i->intent_id,16);memcpy(out+72,i->physical_name,16);memcpy(out+88,i->kind,16);put(out+104,i->group,4);put(out+124,crc(out,124),4);return 0;
}
int steer_draft_wg_identity_decode(const uint8_t *p,size_t n,struct steer_draft_wg_identity *out){
    if(out)memset(out,0,sizeof *out);
    if(!p||!out||n!=STEER_DRAFT_WG_RECORD_BYTES||memcmp(p,"SWGW0001",8)||get(p+124,4)!=crc(p,124))return EINVAL;
    for(unsigned j=108;j<124;j++)if(p[j])return EINVAL;
    struct steer_draft_wg_identity i={0};i.generation=get(p+8,8);i.instance_token=get(p+16,8);i.namespace_device=get(p+24,8);i.namespace_inode=get(p+32,8);
    memcpy(i.boot_id,p+40,16);memcpy(i.intent_id,p+56,16);memcpy(i.physical_name,p+72,16);memcpy(i.kind,p+88,16);i.group=(uint32_t)get(p+104,4);
    if(!valid(&i))return EINVAL;
    *out=i;return 0;
}
static int observed_error(struct steer_draft_wg_observation *o,int rc){o->error=rc;return rc;}
int steer_draft_wg_identity_reconcile(const struct steer_draft_wg_identity *i,int fd,uint64_t deadline,struct steer_draft_wg_observation *o){
    if(!o)return EINVAL;
    *o=(struct steer_draft_wg_observation){STEER_DRAFT_WG_UNKNOWN,STEER_PV1_DEVICE_UNCHANGED,0,0};
    int rc=interrupted(deadline,NULL);if(!rc)rc=environment(i,fd);if(rc)return observed_error(o,rc);
    char kind[32];uint32_t group=0;int index=0;
    rc=awg_dev_link_query_owned_until(i->physical_name,kind,sizeof kind,&index,&group,deadline);
    if(rc==ENODEV){o->state=STEER_DRAFT_WG_ABSENT;return observed_error(o,interrupted(deadline,NULL));}
    if(rc)return observed_error(o,rc);
    o->index=index;
    if(group!=i->group||strcmp(kind,i->kind)){o->state=STEER_DRAFT_WG_FOREIGN;return observed_error(o,ESTALE);}
    o->state=STEER_DRAFT_WG_OWNED;return observed_error(o,interrupted(deadline,NULL));
}
int steer_draft_wg_identity_create(const struct steer_draft_wg_identity *i,int fd,int mtu,uint64_t deadline,const atomic_uint *cancel,struct steer_draft_wg_observation *o){
    if(!o)return EINVAL;
    *o=(struct steer_draft_wg_observation){STEER_DRAFT_WG_UNKNOWN,STEER_PV1_DEVICE_UNCHANGED,0,0};
    int rc=interrupted(deadline,cancel);if(!rc)rc=environment(i,fd);if(!rc)rc=interrupted(deadline,cancel);if(rc)return observed_error(o,rc);
    if(mtu<576||mtu>65535)return observed_error(o,EINVAL);
    rc=awg_dev_link_create_owned_until(i->physical_name,i->kind,mtu,i->group,&o->index,deadline);
    if(rc){o->effect=rc==EEXIST?STEER_PV1_DEVICE_UNCHANGED:STEER_PV1_DEVICE_EFFECT_UNCERTAIN;return observed_error(o,rc);}
    o->effect=STEER_PV1_DEVICE_CHANGED;o->state=STEER_DRAFT_WG_OWNED;
    return observed_error(o,interrupted(deadline,cancel));
}
int steer_draft_wg_identity_retire(const struct steer_draft_wg_identity *i,int fd,uint64_t deadline,const atomic_uint *cancel,struct steer_draft_wg_observation *o){
    if(!o)return EINVAL;
    *o=(struct steer_draft_wg_observation){STEER_DRAFT_WG_UNKNOWN,STEER_PV1_DEVICE_UNCHANGED,0,0};
    int rc=interrupted(deadline,cancel);if(rc)return observed_error(o,rc);
    rc=steer_draft_wg_identity_reconcile(i,fd,deadline,o);if(rc||o->state==STEER_DRAFT_WG_ABSENT)return rc;
    rc=interrupted(deadline,cancel);if(rc)return observed_error(o,rc);
    rc=awg_dev_link_down_owned_until(i->physical_name,i->kind,o->index,i->group,deadline);
    if(rc){o->state=STEER_DRAFT_WG_UNKNOWN;o->effect=STEER_PV1_DEVICE_EFFECT_UNCERTAIN;return observed_error(o,rc);}
    o->effect=STEER_PV1_DEVICE_CHANGED;
    rc=interrupted(deadline,cancel);if(rc)return observed_error(o,rc);
    rc=awg_dev_link_delete_owned_until(i->physical_name,i->kind,o->index,i->group,deadline);
    if(rc){o->state=STEER_DRAFT_WG_UNKNOWN;o->effect=STEER_PV1_DEVICE_EFFECT_UNCERTAIN;return observed_error(o,rc);}
    o->state=STEER_DRAFT_WG_ABSENT;o->index=0;
    return observed_error(o,interrupted(deadline,cancel));
}
