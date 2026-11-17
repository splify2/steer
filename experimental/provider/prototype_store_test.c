#define _GNU_SOURCE
#include "prototype_store.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <unistd.h>
static int file_sync_failure,directory_sync_failure,rename_failure;
static int force_random_collision;
static ssize_t store_test_getrandom(void *out,size_t length,unsigned flags){
    if(force_random_collision){
        uint64_t value=1;
        assert(length==sizeof(value));
        memcpy(out,&value,length);
        return (ssize_t)length;
    }
    return getrandom(out,length,flags);
}
static int store_test_fsync(int fd){
    struct stat st;
    assert(!fstat(fd,&st));
    if((S_ISDIR(st.st_mode)&&directory_sync_failure)||(!S_ISDIR(st.st_mode)&&file_sync_failure)){
        errno=ENOSPC;
        return -1;
    }
    return fsync(fd);
}
static int store_test_renameat(int oldfd,const char*oldpath,int newfd,const char*newpath){
    if(rename_failure){
        errno=EIO;
        return -1;
    }
    return renameat(oldfd,oldpath,newfd,newpath);
}
#define fsync store_test_fsync
#define renameat store_test_renameat
#define getrandom store_test_getrandom
#include "prototype_store.c"
#undef fsync
#undef renameat
#undef getrandom
static const char document[]="{\"prototype\":\"steer-linux-v1\",\"listeners\":[],\"routing\":{\"default\":\"block\",\"rules\":[]}}";
static unsigned temporary_count(const char*path){
    DIR*d=opendir(path);
    struct dirent*entry;
    unsigned n=0;
    assert(d);
    while((entry=readdir(d)))if(!strncmp(entry->d_name,".config.tmp.",12))n++;
    closedir(d);
    return n;
}
static void loaded(struct steer_prototype_store*s,uint64_t generation){
    struct steer_prototype_config*c=NULL;
    assert(!steer_prototype_store_load(s,&c).code);
    assert(c&&c->generation==generation&&!strcmp(c->document_json,document));
    steer_prototype_config_destroy(c);
}
int main(void){
    char path[]="/tmp/steer-store-test-XXXXXX",name[256],link[256];
    struct steer_prototype_store*s=NULL,*other=NULL;
    struct steer_prototype_store_transaction*t=NULL;
    struct steer_prototype_config*c=NULL,*readback=NULL;
    struct steer_prototype_store_result result;
    struct stat st;
    int fd;
    assert(mkdtemp(path));
    assert(!steer_prototype_config_parse(document,strlen(document),1,&c).code);
    assert(!steer_prototype_store_open(path,&s).code);
    assert(steer_prototype_store_open(path,&other).code==STEER_PV1_POLICY_DENIED&&!other);
    assert(steer_prototype_store_load(s,&readback).code==STEER_PV1_UNSUPPORTED&&!readback);
    assert(!steer_prototype_store_prepare(s,c,&t).code);
    assert(temporary_count(path)==1);
    assert(steer_prototype_store_close(s).code==STEER_PV1_POLICY_DENIED);
    assert(!steer_prototype_store_abort(t).code);
    assert(!temporary_count(path));
    /* Collision exhaustion must not unlink a temp this transaction did not own. */
    snprintf(link,sizeof(link),"%s/.config.tmp.%ld.%016llx",path,(long)getpid(),1ull);
    fd=open(link,O_WRONLY|O_CREAT|O_EXCL,0600);
    assert(fd>=0);
    close(fd);
    force_random_collision=1;
    assert(steer_prototype_store_prepare(s,c,&t).code==STEER_PV1_IO&&!t);
    force_random_collision=0;
    assert(!stat(link,&st)&&temporary_count(path)==1);
    assert(!unlink(link));
    assert(steer_prototype_store_load(s,&readback).code==STEER_PV1_UNSUPPORTED);
    assert(!steer_prototype_store_prepare(s,c,&t).code);
    result=steer_prototype_store_commit(t);
    assert(!result.error.code&&result.phase==STEER_PROTOTYPE_STORE_SYNCED);
    assert(steer_prototype_store_commit(t).phase==STEER_PROTOTYPE_STORE_SYNCED);
    assert(!steer_prototype_store_abort(t).code);
    loaded(s,1);
    snprintf(name,sizeof(name),"%s/config.json",path);
    assert(!stat(name,&st)&&(st.st_mode&0777)==0600);
    c->generation=2;
    file_sync_failure=1;
    assert(steer_prototype_store_prepare(s,c,&t).code==STEER_PV1_IO&&!t);
    file_sync_failure=0;
    loaded(s,1);
    assert(!temporary_count(path));
    assert(!steer_prototype_store_prepare(s,c,&t).code);
    rename_failure=1;
    result=steer_prototype_store_commit(t);
    assert(result.error.code==STEER_PV1_IO&&result.phase==STEER_PROTOTYPE_STORE_NOT_RENAMED);
    rename_failure=0;
    loaded(s,1);
    assert(!steer_prototype_store_abort(t).code);
    assert(!temporary_count(path));
    assert(!steer_prototype_store_prepare(s,c,&t).code);
    directory_sync_failure=1;
    result=steer_prototype_store_commit(t);
    assert(result.error.code==STEER_PV1_IO&&result.phase==STEER_PROTOTYPE_STORE_RENAMED);
    directory_sync_failure=0;
    loaded(s,2);
    assert(steer_prototype_store_commit(t).phase==STEER_PROTOTYPE_STORE_RENAMED);
    assert(!steer_prototype_store_abort(t).code);
    loaded(s,2);
    assert(!temporary_count(path));
    assert(!steer_prototype_store_close(s).code);
    assert(!chmod(path,0755));
    assert(steer_prototype_store_open(path,&s).code==STEER_PV1_INVALID&&!s);
    assert(!chmod(path,0700));
    snprintf(link,sizeof(link),"%s.link",path);
    assert(!symlink(path,link));
    assert(steer_prototype_store_open(link,&s).code&&!s);
    assert(!unlink(link));
    assert(!steer_prototype_store_open(path,&s).code);
    fd=open(name,O_WRONLY|O_TRUNC);
    assert(fd>=0&&write(fd,"corrupt",7)==7);
    close(fd);
    assert(steer_prototype_store_load(s,&readback).code&&!readback);
    assert(!unlink(name));
    assert(!symlink("/etc/passwd",name));
    assert(steer_prototype_store_load(s,&readback).code==STEER_PV1_INVALID&&!readback);
    assert(!unlink(name));
    assert(!steer_prototype_store_close(s).code);
    snprintf(name,sizeof(name),"%s/.writer.lock",path);
    assert(!unlink(name)&&!rmdir(path));
    steer_prototype_config_destroy(c);
    puts("prototype store tests passed");
    return 0;
}
