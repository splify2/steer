#define _GNU_SOURCE
#include "kernel_wg_ownership.h"
#include "awgdev.h"
#include <steer/draft/device_v1.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
static atomic_uint cancel_flag;
static int create_mode,delete_mode;
int __real_awg_dev_link_create_owned_until(const char *,const char *,int,uint32_t,int *,uint64_t);
int __wrap_awg_dev_link_create_owned_until(const char *n,const char *k,int mtu,uint32_t g,int *i,uint64_t d){
    int rc=__real_awg_dev_link_create_owned_until(n,k,mtu,g,i,d);
    if(!rc&&create_mode==1){*i=0;return ETIMEDOUT;}
    if(!rc&&create_mode==2)atomic_store(&cancel_flag,1);
    return rc;
}
int __real_awg_dev_link_delete_owned_until(const char *,const char *,int,uint32_t,uint64_t);
int __wrap_awg_dev_link_delete_owned_until(const char *n,const char *k,int i,uint32_t g,uint64_t d){
    int rc=__real_awg_dev_link_delete_owned_until(n,k,i,g,d);return !rc&&delete_mode?ETIMEDOUT:rc;
}
static uint64_t deadline(void){struct timespec t;assert(!clock_gettime(CLOCK_MONOTONIC,&t));return (uint64_t)t.tv_sec*1000000000u+t.tv_nsec+2000000000u;}
static void ip(char *const a[]){pid_t p=fork();assert(p>=0);if(!p){execvp("ip",a);_exit(127);}int s;assert(waitpid(p,&s,0)==p&&WIFEXITED(s)&&!WEXITSTATUS(s));}
static void checksum(uint8_t p[STEER_DRAFT_WG_RECORD_BYTES]){
    uint32_t value=UINT32_MAX;
    for(size_t j=0;j<124;j++){value^=p[j];for(unsigned k=0;k<8;k++)value=(value>>1)^((value&1)?0xedb88320u:0);}
    value=~value;for(unsigned j=0;j<4;j++)p[124+j]=(uint8_t)(value>>(8*j));
}
static void check_record(struct steer_draft_wg_identity *id,uint8_t record[STEER_DRAFT_WG_RECORD_BYTES]){
    assert(!steer_draft_wg_identity_encode(id,record));struct steer_draft_wg_identity decoded;
    assert(!steer_draft_wg_identity_decode(record,STEER_DRAFT_WG_RECORD_BYTES,&decoded));
    uint8_t again[STEER_DRAFT_WG_RECORD_BYTES];assert(!steer_draft_wg_identity_encode(&decoded,again)&&!memcmp(record,again,sizeof again));
    for(size_t n=0;n<sizeof again;n++)assert(steer_draft_wg_identity_decode(record,n,&decoded)==EINVAL&&!decoded.generation);
    for(size_t n=0;n<sizeof again;n++){memcpy(again,record,sizeof again);again[n]^=1;assert(steer_draft_wg_identity_decode(again,sizeof again,&decoded)==EINVAL&&!decoded.generation);}
    /* Correct checksum deliberately reaches semantic validation, not CRC. */
    const struct {unsigned offset,length,value;} malformed[]={
        {104,4,0},{16,8,0},{8,8,0},{32,8,0},{40,16,0},{56,16,0},
        {72,1,'x'},{87,1,'x'},{88,1,'x'},{100,1,1},{108,1,1},{7,1,'2'}
    };
    for(size_t j=0;j<sizeof malformed/sizeof malformed[0];j++){
        memcpy(again,record,sizeof again);memset(again+malformed[j].offset,malformed[j].value,malformed[j].length);checksum(again);
        assert(steer_draft_wg_identity_decode(again,sizeof again,&decoded)==EINVAL&&!decoded.generation);
    }
    uint8_t big[STEER_DRAFT_WG_RECORD_BYTES+1]={0};memcpy(big,record,sizeof again);assert(steer_draft_wg_identity_decode(big,sizeof big,&decoded)==EINVAL);
}
static int other_namespace(void){
    int pair[2];assert(!socketpair(AF_UNIX,SOCK_STREAM|SOCK_CLOEXEC,0,pair));
    pid_t child=fork();assert(child>=0);
    if(!child){close(pair[0]);if(unshare(CLONE_NEWNET))_exit(2);char byte='R';if(write(pair[1],&byte,1)!=1)_exit(2);if(read(pair[1],&byte,1)!=1)_exit(2);close(pair[1]);_exit(0);}
    close(pair[1]);struct pollfd pfd={pair[0],POLLIN,0};assert(poll(&pfd,1,2000)==1);char byte;assert(read(pair[0],&byte,1)==1&&byte=='R');
    char path[80];snprintf(path,sizeof path,"/proc/%ld/ns/net",(long)child);int fd=open(path,O_RDONLY|O_CLOEXEC);assert(fd>=0);
    assert(write(pair[0],"X",1)==1);close(pair[0]);int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));return fd;
}
static void *owner_worker(void *arg){
    uintptr_t owner=(uintptr_t)arg;if(unshare(CLONE_NEWNET))return (void *)1;
    int fd=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);if(fd<0)return (void *)1;
    struct stat current,leader;if(fstat(fd,&current)||stat("/proc/self/ns/net",&leader)||(current.st_dev==leader.st_dev&&current.st_ino==leader.st_ino)){close(fd);return (void *)1;}
    atomic_uint canceled=0;int failed=0;
    for(unsigned j=0;j<6&&!failed;j++){
        struct steer_draft_wg_identity id;struct steer_draft_wg_observation o;
        failed=steer_draft_wg_identity_prepare(fd,11,100+owner*10+j,"wireguard",deadline(),&canceled,&id)!=0;
        if(!failed)failed=steer_draft_wg_identity_create(&id,fd,1420,deadline(),&canceled,&o)!=0;
        if(!failed&&owner==0){struct steer_draft_wg_identity wrong=id;wrong.boot_id[0]^=1;
            failed=steer_draft_wg_identity_retire(&wrong,fd,deadline(),&canceled,&o)!=ESTALE||o.effect!=STEER_PV1_DEVICE_UNCHANGED;}
        if(!failed)failed=steer_draft_wg_identity_retire(&id,fd,deadline(),&canceled,&o)!=0||o.state!=STEER_DRAFT_WG_ABSENT;
    }
    close(fd);return failed?(void *)1:NULL;
}
static void workers(void){
    pthread_t threads[4];for(uintptr_t j=0;j<4;j++)assert(!pthread_create(threads+j,NULL,owner_worker,(void *)j));
    for(unsigned j=0;j<4;j++){void *result;assert(!pthread_join(threads[j],&result)&&!result);}
    puts("WG ownership four actual thread namespaces: isolated failed owner check + healthy create/reconcile/retire PASS");
}
int main(int argc,char **argv){
    int ns=open("/proc/thread-self/ns/net",O_RDONLY|O_CLOEXEC);assert(ns>=0);
    struct steer_draft_wg_identity id;uint8_t record[STEER_DRAFT_WG_RECORD_BYTES];
    assert(!steer_draft_wg_identity_prepare(ns,7,91,"wireguard",deadline(),&cancel_flag,&id));check_record(&id,record);
    struct steer_draft_wg_identity rejected;
    assert(steer_draft_wg_identity_prepare(ns,7,90,"wireguard",0,&cancel_flag,&rejected)==EINVAL&&!rejected.generation);
    assert(steer_draft_wg_identity_prepare(ns,7,90,"wireguard",1,&cancel_flag,&rejected)==ETIMEDOUT&&!rejected.generation);
    atomic_store(&cancel_flag,1);assert(steer_draft_wg_identity_prepare(ns,7,90,"wireguard",deadline(),&cancel_flag,&rejected)==ECANCELED&&!rejected.generation);atomic_store(&cancel_flag,0);
    if(argc==2&&!strcmp(argv[1],"--record")){close(ns);puts("WG recovery record bounds/corruption PASS");return 0;}
    struct stat current,initial;assert(!fstat(ns,&current)&&!stat("/proc/1/ns/net",&initial));
    if(!getenv("STEER_TEST_OWNED_NETNS")||(current.st_dev==initial.st_dev&&current.st_ino==initial.st_ino)){fputs("isolated namespace required\n",stderr);return 2;}
    if(argc==2&&!strcmp(argv[1],"--workers")){workers();close(ns);return 0;}
    /* Lab coordinator fixture persists exact opaque intent BEFORE kernel create.
     * No production/private provider journal is implemented here. */
    char dir[]="/tmp/steer-wg-intent-XXXXXX",path[128];assert(mkdtemp(dir));snprintf(path,sizeof path,"%s/intent",dir);
    int file=open(path,O_CREAT|O_EXCL|O_WRONLY|O_CLOEXEC,0600);assert(file>=0&&write(file,record,sizeof record)==sizeof record&&!fsync(file)&&!close(file));
    int directory=open(dir,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0&&!fsync(directory)&&!close(directory));
    pid_t child=fork();assert(child>=0);
    if(!child){create_mode=1;struct steer_draft_wg_observation o;int rc=steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel_flag,&o);_exit(rc==ETIMEDOUT&&o.effect==STEER_PV1_DEVICE_EFFECT_UNCERTAIN?0:1);}
    int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&!WEXITSTATUS(status));
    memset(&id,0,sizeof id);file=open(path,O_RDONLY|O_CLOEXEC);assert(file>=0&&read(file,record,sizeof record)==sizeof record&&!close(file));
    assert(!steer_draft_wg_identity_decode(record,sizeof record,&id));
    struct steer_draft_wg_observation o;assert(!steer_draft_wg_identity_reconcile(&id,ns,deadline(),&o)&&o.state==STEER_DRAFT_WG_OWNED&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    struct steer_draft_wg_identity wrong=id;wrong.boot_id[0]^=1;
    assert(steer_draft_wg_identity_retire(&wrong,ns,deadline(),&cancel_flag,&o)==ESTALE&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    int mnt=open("/proc/thread-self/ns/mnt",O_RDONLY|O_CLOEXEC);assert(mnt>=0);
    assert(steer_draft_wg_identity_retire(&id,mnt,deadline(),&cancel_flag,&o)==EXDEV&&o.effect==STEER_PV1_DEVICE_UNCHANGED);close(mnt);
    int other=other_namespace();struct stat other_stat;assert(!fstat(other,&other_stat));
    wrong=id;wrong.namespace_device=(uint64_t)other_stat.st_dev;wrong.namespace_inode=(uint64_t)other_stat.st_ino;
    /* Pinned FD and record agree, but the calling worker is in a different
     * actual network namespace: /proc/thread-self identity must reject it. */
    assert(steer_draft_wg_identity_retire(&wrong,other,deadline(),&cancel_flag,&o)==EXDEV&&o.effect==STEER_PV1_DEVICE_UNCHANGED);close(other);
    atomic_store(&cancel_flag,1);assert(steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)==ECANCELED&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    atomic_store(&cancel_flag,0);delete_mode=1;
    assert(steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)==ETIMEDOUT&&o.effect==STEER_PV1_DEVICE_EFFECT_UNCERTAIN);
    delete_mode=0;assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)&&o.state==STEER_DRAFT_WG_ABSENT&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    assert(!steer_draft_wg_identity_prepare(ns,7,92,"wireguard",deadline(),&cancel_flag,&id));
    atomic_store(&cancel_flag,1);
    assert(steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel_flag,&o)==ECANCELED&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    assert(awg_dev_link_query(id.physical_name,NULL,0,NULL)==ENODEV);
    atomic_store(&cancel_flag,0);create_mode=2;
    assert(steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel_flag,&o)==ECANCELED&&o.effect==STEER_PV1_DEVICE_CHANGED&&o.state==STEER_DRAFT_WG_OWNED);
    atomic_store(&cancel_flag,0);create_mode=0;
    assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)&&o.effect==STEER_PV1_DEVICE_CHANGED);
    assert(!steer_draft_wg_identity_prepare(ns,7,93,"wireguard",deadline(),&cancel_flag,&id));
    assert(!steer_draft_wg_identity_create(&id,ns,1420,deadline(),&cancel_flag,&o));
    char group[16];snprintf(group,sizeof group,"%u",id.group==1?2u:1u);
    char *set[]={"ip","link","set","dev",id.physical_name,"group",group,NULL};ip(set);
    assert(steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)==ESTALE&&o.state==STEER_DRAFT_WG_FOREIGN&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    assert(!awg_dev_link_query(id.physical_name,NULL,0,NULL));
    char *remove[]={"ip","link","del","dev",id.physical_name,NULL};ip(remove);
    assert(!steer_draft_wg_identity_retire(&id,ns,deadline(),&cancel_flag,&o)&&o.state==STEER_DRAFT_WG_ABSENT&&o.effect==STEER_PV1_DEVICE_UNCHANGED);
    assert(!unlink(path)&&!rmdir(dir)&&!close(ns));
    puts("WG recovery: durable intent/lost create result, lost delete result, boot/ns refusal, cancellation effect, foreign marker preservation PASS");return 0;
}
