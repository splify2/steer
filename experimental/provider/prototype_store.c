#define _GNU_SOURCE
#include "prototype_store.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>
struct steer_prototype_store {
    int directory,lock;
    struct steer_prototype_store_transaction *transaction;
};
struct steer_prototype_store_transaction {
    struct steer_prototype_store *store;
    char temporary[96];
    int attempted;
    struct steer_prototype_store_result result;
};
static struct steer_pv1_error error(uint32_t c){
    struct steer_pv1_error e={
        c,0
    };
    return e;
}
static int private_file(int fd){
    struct stat st;
    return !fstat(fd,&st)&&S_ISREG(st.st_mode)&&st.st_uid==geteuid()&&!(st.st_mode&0077)&&st.st_nlink==1;
}
static int write_all(int fd,const char *p,size_t n){
    while(n){
        ssize_t written=write(fd,p,n);
        if(written<0&&errno==EINTR)continue;
        if(written<=0)return -1;
        p+=written;
        n-=(size_t)written;
    }
    return 0;
}
struct steer_pv1_error steer_prototype_store_open(const char *path,struct steer_prototype_store **out){
    struct steer_prototype_store*s;
    struct stat st;
    if(out)*out=NULL;
    if(!path||!*path||!out)return error(STEER_PV1_INVALID);
    s=calloc(1,sizeof(*s));
    if(!s)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    s->directory=-1;
    s->lock=-1;
    s->directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    if(s->directory<0)goto io;
    if(fstat(s->directory,&st)||!S_ISDIR(st.st_mode)||st.st_uid!=geteuid()||(st.st_mode&0077))goto invalid;
    s->lock=openat(s->directory,".writer.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
    if(s->lock<0)goto io;
    if(!private_file(s->lock))goto invalid;
    if(flock(s->lock,LOCK_EX|LOCK_NB)){
        if(errno==EWOULDBLOCK){
            close(s->lock);
            close(s->directory);
            free(s);
            return error(STEER_PV1_POLICY_DENIED);
        }
        goto io;
    }
    *out=s;
    return error(STEER_PV1_OK);
    invalid:if(s->lock>=0)close(s->lock);
    close(s->directory);
    free(s);
    return error(STEER_PV1_INVALID);
    io:if(s->lock>=0)close(s->lock);
    if(s->directory>=0)close(s->directory);
    free(s);
    return error(STEER_PV1_IO);
}
struct steer_pv1_error steer_prototype_store_close(struct steer_prototype_store*s){
    if(!s)return error(STEER_PV1_INVALID);
    if(s->transaction)return error(STEER_PV1_POLICY_DENIED);
    close(s->lock);
    close(s->directory);
    free(s);
    return error(STEER_PV1_OK);
}
struct steer_pv1_error steer_prototype_store_prepare_document(struct steer_prototype_store*s,const struct steer_store_document*c,struct steer_prototype_store_transaction**out){
    struct steer_prototype_store_transaction*t;
    char prefix[96];
    unsigned attempt;
    int fd=-1,created=0;
    size_t prefix_length;
    if(out)*out=NULL;
    if(!s||!c||!out||!c->generation||!c->document||!c->length||c->length>(c->format==STEER_STORE_FORMAT_PROTOTYPE?STEER_PROTOTYPE_CONFIG_MAX_BYTES:STEER_STORE_DOCUMENT_MAX)||(c->format!=STEER_STORE_FORMAT_PROTOTYPE&&c->format!=STEER_STORE_FORMAT_SPEC_V3)||c->document[0]!='{'||c->document[c->length-1]!='}'||memchr(c->document,0,c->length))return error(STEER_PV1_INVALID);
    if(s->transaction)return error(STEER_PV1_POLICY_DENIED);
    t=calloc(1,sizeof(*t));
    if(!t)return error(STEER_PV1_RESOURCE_EXHAUSTED);
    t->store=s;
    for(attempt=0;attempt<16;attempt++){
        uint64_t random;
        ssize_t got;
        do{
            got=getrandom(&random,sizeof(random),0);
        }
        while(got<0&&errno==EINTR);
        if(got!=(ssize_t)sizeof(random))goto fail;
        snprintf(t->temporary,sizeof(t->temporary),".config.tmp.%ld.%016llx",(long)getpid(),(unsigned long long)random);
        fd=openat(s->directory,t->temporary,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
        if(fd>=0){
            created=1;
            break;
        }
        if(errno!=EEXIST)goto fail;
    }
    if(fd<0||fchmod(fd,0600))goto fail;
    prefix_length=(size_t)snprintf(prefix,sizeof(prefix),c->format==STEER_STORE_FORMAT_PROTOTYPE?"{\"revision\":%llu,\"document\":":"{\"revision\":%llu,\"format\":\"steer-spec-v3\",\"document\":",(unsigned long long)c->generation);
    if(prefix_length>=sizeof(prefix))goto fail;
    if(write_all(fd,prefix,prefix_length)||write_all(fd,c->document,c->length)||write_all(fd,"}\n",2)||fsync(fd))goto fail;
    if(close(fd)){
        fd=-1;
        goto fail;
    }
    fd=-1;
    s->transaction=t;
    *out=t;
    return error(STEER_PV1_OK);
    fail:if(fd>=0)close(fd);
    if(created)unlinkat(s->directory,t->temporary,0);
    free(t);
    return error(STEER_PV1_IO);
}
struct steer_pv1_error steer_prototype_store_prepare(struct steer_prototype_store *s,const struct steer_prototype_config *c,struct steer_prototype_store_transaction **out){
    if(!c){if(out)*out=NULL;return error(STEER_PV1_INVALID);}
    struct steer_store_document document={c->generation,STEER_STORE_FORMAT_PROTOTYPE,c->document_json,c->document_length};
    return steer_prototype_store_prepare_document(s,&document,out);
}
struct steer_prototype_store_result steer_prototype_store_commit(struct steer_prototype_store_transaction*t){
    struct steer_prototype_store_result invalid={
        {
            STEER_PV1_INVALID,0
        },STEER_PROTOTYPE_STORE_NOT_RENAMED
    };
    if(!t)return invalid;
    if(t->attempted)return t->result;
    t->attempted=1;
    t->result.error=error(STEER_PV1_IO);
    if(renameat(t->store->directory,t->temporary,t->store->directory,"config.json"))return t->result;
    t->result.phase=STEER_PROTOTYPE_STORE_RENAMED;
    if(fsync(t->store->directory))return t->result;
    t->result.phase=STEER_PROTOTYPE_STORE_SYNCED;
    t->result.error=error(STEER_PV1_OK);
    return t->result;
}
struct steer_pv1_error steer_prototype_store_abort(struct steer_prototype_store_transaction*t){
    struct steer_pv1_error e=error(STEER_PV1_OK);
    if(!t)return error(STEER_PV1_INVALID);
    if(t->result.phase==STEER_PROTOTYPE_STORE_NOT_RENAMED&&unlinkat(t->store->directory,t->temporary,0)&&errno!=ENOENT)e=error(STEER_PV1_IO);
    t->store->transaction=NULL;
    free(t);
    return e;
}
struct steer_pv1_error steer_prototype_store_load_document(struct steer_prototype_store*s,struct steer_store_document**out){
    int fd;
    struct stat st;
    char *data,*p,*document;
    size_t used=0,length;
    uint64_t revision=0;
    uint32_t format=STEER_STORE_FORMAT_PROTOTYPE;
    struct steer_pv1_error e=error(STEER_PV1_INVALID);
    if(out)*out=NULL;
    if(!s||!out)return e;
    fd=openat(s->directory,"config.json",O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);
    if(fd<0)return error(errno==ENOENT?STEER_PV1_UNSUPPORTED:errno==ELOOP?STEER_PV1_INVALID:STEER_PV1_IO);
    if(!private_file(fd)||fstat(fd,&st)){
        close(fd);
        return e;
    }
    if(st.st_size<=0||(uint64_t)st.st_size>STEER_STORE_DOCUMENT_MAX+128u){
        close(fd);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    length=(size_t)st.st_size;
    data=malloc(length+1);
    if(!data){
        close(fd);
        return error(STEER_PV1_RESOURCE_EXHAUSTED);
    }
    while(used<length){
        ssize_t n=read(fd,data+used,length-used);
        if(n<0&&errno==EINTR)continue;
        if(n<=0){
            e=error(STEER_PV1_IO);
            goto done;
        }
        used+=(size_t)n;
    }
    char extra;ssize_t extra_size;
    do{extra_size=read(fd,&extra,1);}while(extra_size<0&&errno==EINTR);
    if(extra_size!=0){e=error(extra_size<0?STEER_PV1_IO:STEER_PV1_INVALID);goto done;}
    data[length]=0;
    if(memchr(data,0,length)||length<30||memcmp(data,"{\"revision\":",12))goto done;
    p=data+12;
    if(*p<'1'||*p>'9')goto done;
    while(*p>='0'&&*p<='9'){
        unsigned digit=(unsigned)(*p++-'0');
        if(revision>(UINT64_MAX-digit)/10u)goto done;
        revision=revision*10u+digit;
    }
    static const char format_tag[]=",\"format\":\"steer-spec-v3\"";
    if(!strncmp(p,format_tag,sizeof(format_tag)-1)){format=STEER_STORE_FORMAT_SPEC_V3;p+=sizeof(format_tag)-1;}
    if(strncmp(p,",\"document\":",12))goto done;
    document=p+12;
    if(data[length-1]!='\n'||data[length-2]!='}')goto done;
    length=(size_t)((data+length-2)-document);
    if(!length||length>(format==STEER_STORE_FORMAT_PROTOTYPE?STEER_PROTOTYPE_CONFIG_MAX_BYTES:STEER_STORE_DOCUMENT_MAX)||document[0]!='{'||document[length-1]!='}')goto done;
    struct steer_store_document *snapshot=calloc(1,sizeof(*snapshot));
    if(!snapshot){e=error(STEER_PV1_RESOURCE_EXHAUSTED);goto done;}
    memmove(data,document,length);data[length]=0;
    *snapshot=(struct steer_store_document){revision,format,data,length};*out=snapshot;data=NULL;e=error(0);
    done:close(fd);
    free(data);
    return e;
}

void steer_store_document_destroy(struct steer_store_document *document){if(document){free(document->document);free(document);}}
struct steer_pv1_error steer_prototype_store_load(struct steer_prototype_store *s,struct steer_prototype_config **out){
    if(out)*out=NULL;
    if(!out)return error(STEER_PV1_INVALID);
    struct steer_store_document *document=NULL;struct steer_pv1_error result=steer_prototype_store_load_document(s,&document);
    if(result.code)return result;
    if(document->format!=STEER_STORE_FORMAT_PROTOTYPE)result=error(STEER_PV1_INVALID);
    else result=steer_prototype_config_parse(document->document,document->length,document->generation,out);
    steer_store_document_destroy(document);return result;
}
