#define _GNU_SOURCE
#include "kernel_wg.h"
#include "awgdev.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#define CONFIG_BYTES 16384u
struct steer_draft_kernel_wg {
    char inbound[65],device[16];
    uint64_t generation;
    uint32_t fwmark;
    uint16_t mtu;
    int secret_fd,index,activated;
    dev_t ns_device;
    ino_t ns_inode;
    size_t address_count,peer_count;
    struct awg_prefix addresses[STEER_DRAFT_WG_PREFIXES];
};
static struct steer_pv1_error error(uint32_t code){
    struct steer_pv1_error e={
        code,0
    };
    return e;
}
static void wipe(void *memory,size_t n){
    volatile unsigned char*p=memory;
    while(n--)*p++=0;
}
static int nonzero_key(const uint8_t key[32]){
    unsigned i,value=0;
    for(i=0;i<32;i++)value|=key[i];
    return value!=0;
}
static int text(const char*s,size_t cap){
    return s&&memchr(s,0,cap)!=NULL;
}
static int identifier(const char*s,size_t cap){
    size_t i;
    if(!text(s,cap)||!*s)return 0;
    for(i=0;s[i];i++){
        unsigned c=(unsigned char)s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.'))return 0;
    }
    return 1;
}
static int reference(const char*s,size_t cap){
    size_t i;
    if(!text(s,cap)||strncmp(s,"env:",4)||!s[4])return 0;
    for(i=4;s[i];i++){
        unsigned c=(unsigned char)s[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||c=='_'||(i>4&&c>='0'&&c<='9')))return 0;
    }
    return 1;
}
static int key_valid(const uint8_t*p){
    unsigned i;
    for(i=0;i<43;i++){
        unsigned c=p[i];
        if(!((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='+'||c=='/'))return 0;
    }
    return p[43]=='=';
}
static int prefix_valid(const char*s){
    char addr[64],*slash,*p;
    uint8_t bytes[16];
    unsigned bits=0;
    int family;
    if(!text(s,64))return 0;
    snprintf(addr,sizeof(addr),"%s",s);
    slash=strchr(addr,'/');
    if(!slash)return 0;
    *slash++=0;
    if(!*slash)return 0;
    for(p=slash;*p;p++){
        if(*p<'0'||*p>'9'||bits>128)return 0;
        bits=bits*10u+(unsigned)(*p-'0');
    }
    family=inet_pton(AF_INET,addr,bytes)==1?4:inet_pton(AF_INET6,addr,bytes)==1?6:0;
    return family&&bits<=(family==4?32u:128u);
}
static int namespace_same(const struct steer_draft_kernel_wg*h){
    struct stat st;
    return !stat("/proc/self/ns/net",&st)&&st.st_dev==h->ns_device&&st.st_ino==h->ns_inode;
}
static int secret_line(FILE*f,const char*name,const char*ref,steer_draft_kernel_wg_secret resolve,void*context){
    uint8_t key[44]={
        0
    };
    struct steer_pv1_span reference_span={
        (const uint8_t*)ref,(uint32_t)strlen(ref)
    };
    struct steer_pv1_error e=resolve(context,reference_span,key);
    int ok=!e.code&&key_valid(key);
    if(ok){
        fprintf(f,"%s = ",name);
        fwrite(key,1,sizeof(key),f);
        fputc('\n',f);
    }
    wipe(key,sizeof(key));
    return ok;
}
struct steer_pv1_error steer_draft_kernel_wg_prepare(const struct steer_draft_kernel_wg_config*c,steer_draft_kernel_wg_secret resolve,void*context,struct steer_draft_kernel_wg**out){
    struct steer_draft_kernel_wg*h=NULL;
    struct stat ns;
    struct awg_conf parsed;
    struct awg_secrets secrets;
    char diagnostic[256],*buffer=NULL;
    FILE*f=NULL;
    uint32_t i,j;
    long length;
    int rc;
    struct steer_pv1_error e=error(STEER_PV1_INVALID);
    if(out)*out=NULL;
    if(!c||!out||!resolve||!c->generation||!identifier(c->inbound_id,sizeof(c->inbound_id))||!identifier(c->device,sizeof(c->device))||!strcmp(c->device,".")||!strcmp(c->device,"..")||awg_ifname_conspicuous(c->device)||!reference(c->private_key_ref,sizeof(c->private_key_ref))||!c->listen_port||!c->address_count||c->address_count>STEER_DRAFT_WG_PREFIXES||!c->peer_count||c->peer_count>STEER_DRAFT_WG_PEERS||(c->mtu&&(c->mtu<1280||c->mtu>9000)))return e;
    for(i=0;i<c->address_count;i++)if(!prefix_valid(c->addresses[i]))return e;
    for(i=0;i<c->peer_count;i++){
        const struct steer_draft_kernel_wg_peer*p=&c->peers[i];
        if(!text(p->public_key,sizeof(p->public_key))||strlen(p->public_key)!=44||!key_valid((const uint8_t*)p->public_key)||!p->allowed_count||p->allowed_count>STEER_DRAFT_WG_PREFIXES||!text(p->preshared_key_ref,sizeof(p->preshared_key_ref))||(*p->preshared_key_ref&&!reference(p->preshared_key_ref,sizeof(p->preshared_key_ref))))return e;
        for(j=0;j<p->allowed_count;j++)if(!prefix_valid(p->allowed_ips[j]))return e;
    }
    if(stat("/proc/self/ns/net",&ns))return error(STEER_PV1_IO);
    rc=awg_dev_link_query(c->device,NULL,0,NULL);
    if(rc==0)return error(STEER_PV1_POLICY_DENIED);
    if(rc!=ENODEV)return error(STEER_PV1_IO);
    h=calloc(1,sizeof(*h));
    if(h)h->secret_fd=-1;
    buffer=calloc(1,CONFIG_BYTES);
    if(!h||!buffer){
        e=error(STEER_PV1_RESOURCE_EXHAUSTED);
        goto fail;
    }
    h->secret_fd=-1;
    f=fmemopen(buffer,CONFIG_BYTES,"w");
    if(!f){
        e=error(STEER_PV1_RESOURCE_EXHAUSTED);
        goto fail;
    }
    fputs("[Interface]\n",f);
    if(!secret_line(f,"PrivateKey",c->private_key_ref,resolve,context))goto fail;
    fprintf(f,"ListenPort = %u\nMTU = %u\nAddress = ",c->listen_port,c->mtu?c->mtu:1420);
    for(i=0;i<c->address_count;i++)fprintf(f,"%s%s",i?", ":"",c->addresses[i]);
    fputc('\n',f);
    for(i=0;i<c->peer_count;i++){
        const struct steer_draft_kernel_wg_peer*p=&c->peers[i];
        fprintf(f,"[Peer]\nPublicKey = %s\n",p->public_key);
        if(*p->preshared_key_ref&&!secret_line(f,"PresharedKey",p->preshared_key_ref,resolve,context))goto fail;
        fputs("AllowedIPs = ",f);
        for(j=0;j<p->allowed_count;j++)fprintf(f,"%s%s",j?", ":"",p->allowed_ips[j]);
        fputc('\n',f);
    }
    if(fflush(f)||ferror(f))goto fail;
    length=ftell(f);
    fclose(f);
    f=NULL;
    if(length<=0||(size_t)length>=CONFIG_BYTES)goto fail;
    memset(&parsed,0,sizeof(parsed));
    memset(&secrets,0,sizeof(secrets));
    rc=awg_conf_parse(buffer,(size_t)length,&parsed,&secrets,diagnostic,sizeof(diagnostic));
    if(!rc){
        if(!secrets.has_priv||!nonzero_key(secrets.priv))rc=-1;
        for(i=0;i<parsed.peer_n;i++){
            if(!nonzero_key(parsed.peer[i].pub)||
                (parsed.peer[i].has_psk&&!nonzero_key(secrets.psk[i])))rc=-1;
            for(j=0;j<i;j++)if(!memcmp(parsed.peer[i].pub,parsed.peer[j].pub,32))rc=-1;
        }
    }
    awg_secrets_wipe(&secrets);
    if(rc){
        awg_conf_free(&parsed);
        goto fail;
    }
    if(awg_conf_needs_awg(&parsed)){
        awg_conf_free(&parsed);
        goto fail;
    }
    h->address_count=parsed.addr_n;
    h->peer_count=parsed.peer_n;
    memcpy(h->addresses,parsed.addr,parsed.addr_n*sizeof(parsed.addr[0]));
    awg_conf_free(&parsed);
    h->secret_fd=memfd_create("steer-wg-secret",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    if(h->secret_fd<0){
        e=error(STEER_PV1_IO);
        goto fail;
    }
    if(fchmod(h->secret_fd,0600)){
        e=error(STEER_PV1_IO);
        goto fail;
    }
    {
        size_t used=0;
        while(used<(size_t)length){
            ssize_t n=write(h->secret_fd,buffer+used,(size_t)length-used);
            if(n<0&&errno==EINTR)continue;
            if(n<=0){
                e=error(STEER_PV1_IO);
                goto fail;
            }
            used+=(size_t)n;
        }
    }
    if(fcntl(h->secret_fd,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL)){
        e=error(STEER_PV1_IO);
        goto fail;
    }
    snprintf(h->inbound,sizeof(h->inbound),"%s",c->inbound_id);
    snprintf(h->device,sizeof(h->device),"%s",c->device);
    h->generation=c->generation;
    h->fwmark=c->fwmark;
    h->mtu=c->mtu?c->mtu:1420;
    h->ns_device=ns.st_dev;
    h->ns_inode=ns.st_ino;
    wipe(buffer,CONFIG_BYTES);
    free(buffer);
    *out=h;
    return error(STEER_PV1_OK);
    fail:if(f)fclose(f);
    if(buffer){
        wipe(buffer,CONFIG_BYTES);
        free(buffer);
    }
    if(h){
        if(h->secret_fd>=0)close(h->secret_fd);
        free(h);
    }
    return e;
}
static int ownership(const struct steer_draft_kernel_wg*h){
    char kind[32];
    int index,rc;
    if(!namespace_same(h))return EPERM;
    rc=awg_dev_link_query(h->device,kind,sizeof(kind),&index);
    if(rc)return rc;
    return index==h->index&&!strcmp(kind,"wireguard")?0:ESTALE;
}
static int addresses_ready(const struct steer_draft_kernel_wg*h){
    struct ifaddrs*all=NULL,*a;
    size_t i;
    int ok=1;
    if(getifaddrs(&all))return 0;
    for(i=0;i<h->address_count;i++){
        const struct awg_prefix*p=&h->addresses[i];
        int found=0;
        for(a=all;a;a=a->ifa_next){
            const uint8_t*bytes,*mask;
            size_t length,j;
            if(!a->ifa_addr||!a->ifa_netmask||strcmp(a->ifa_name,h->device)||!(a->ifa_flags&IFF_UP)||a->ifa_addr->sa_family!=p->family)continue;
            if(p->family==AF_INET){
                bytes=(const uint8_t*)&((const struct sockaddr_in*)a->ifa_addr)->sin_addr;
                mask=(const uint8_t*)&((const struct sockaddr_in*)a->ifa_netmask)->sin_addr;
                length=4;
            }
            else{
                bytes=(const uint8_t*)&((const struct sockaddr_in6*)a->ifa_addr)->sin6_addr;
                mask=(const uint8_t*)&((const struct sockaddr_in6*)a->ifa_netmask)->sin6_addr;
                length=16;
            }
            if(memcmp(bytes,p->addr,length))continue;
            for(j=0;j<length*8;j++)if(!!(mask[j/8]&(0x80u>>(j%8)))!=(j<p->cidr))break;
            if(j==length*8){
                found=1;
                break;
            }
        }
        if(!found){
            ok=0;
            break;
        }
    }
    freeifaddrs(all);
    return ok;
}
struct steer_pv1_error steer_draft_kernel_wg_rollback(struct steer_draft_kernel_wg*h){
    int rc;
    if(!h)return error(STEER_PV1_INVALID);
    if(!namespace_same(h))return error(STEER_PV1_POLICY_DENIED);
    if(!h->index){
        h->activated=0;
        return error(STEER_PV1_OK);
    }
    rc=awg_dev_link_delete_owned(h->device,"wireguard",h->index);
    if(rc&&rc!=ENODEV)return error(rc==ESTALE||rc==EPERM?STEER_PV1_POLICY_DENIED:STEER_PV1_IO);
    awg_dev_state_drop(h->device);
    h->index=0;
    h->activated=0;
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_kernel_wg_retire(struct steer_draft_kernel_wg*h){
    return steer_draft_kernel_wg_rollback(h);
}
struct steer_pv1_error steer_draft_kernel_wg_activate_guarded(struct steer_draft_kernel_wg*h,
    steer_draft_kernel_wg_before_up before_up,void *context){
    char path[64];
    struct awg_live live;
    int rc;
    struct steer_pv1_error cleanup;
    if(!h)return error(STEER_PV1_INVALID);
    if(!namespace_same(h)||h->index||h->activated)return error(STEER_PV1_POLICY_DENIED);
    rc=awg_dev_link_create_exclusive(h->device,"wireguard",h->mtu,&h->index);
    if(rc){
        if(h->index)(void)steer_draft_kernel_wg_rollback(h);
        return error(rc==EEXIST?STEER_PV1_POLICY_DENIED:STEER_PV1_IO);
    }
    if(ownership(h)){
        (void)steer_draft_kernel_wg_rollback(h);
        return error(STEER_PV1_POLICY_DENIED);
    }
    if(before_up){
        struct steer_pv1_error guarded=before_up(context,h->device,h->index);
        if(guarded.code){
            (void)steer_draft_kernel_wg_rollback(h);
            return guarded;
        }
    }
    snprintf(path,sizeof(path),"/proc/self/fd/%d",h->secret_fd);
    rc=awg_dev_configure(h->inbound,h->device,path,h->fwmark,NULL,0,1,NULL,0);
    if(rc||ownership(h)||!addresses_ready(h)||awg_dev_live_read(h->device,"wireguard",&live)||live.peer_n!=h->peer_count){
        cleanup=steer_draft_kernel_wg_rollback(h);
        return cleanup.code?cleanup:error(STEER_PV1_IO);
    }
    h->activated=1;
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_kernel_wg_destroy(struct steer_draft_kernel_wg*h){
    if(!h)return error(STEER_PV1_INVALID);
    if(h->index||h->activated){
        int rc=ownership(h);
        if(rc!=ENODEV&&rc!=ESTALE)return error(STEER_PV1_POLICY_DENIED);
        /* Identity is gone/replaced. Discard only our userspace resources,
         * never mutate or remove the replacement interface. */
    }
    close(h->secret_fd);
    wipe(h,sizeof(*h));
    free(h);
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_draft_kernel_wg_activate(struct steer_draft_kernel_wg*h){
    return steer_draft_kernel_wg_activate_guarded(h,NULL,NULL);
}
int steer_draft_kernel_wg_index(const struct steer_draft_kernel_wg*h){
    return h?h->index:0;
}
