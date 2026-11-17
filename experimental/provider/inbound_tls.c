/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "inbound_tls.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void erase(void *memory,size_t length) { volatile uint8_t *p=memory;while(length--)*p++=0; }
static int read_file(const char *path,size_t limit,uint8_t **out,size_t *length) {
    struct stat st;int fd;size_t done=0;uint8_t *data=NULL,extra;
    if(!path||!*path)return -1;
    fd=open(path,O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NONBLOCK);if(fd<0)return -1;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_size<=0||(uint64_t)st.st_size>limit)goto fail;
    data=malloc((size_t)st.st_size);if(!data)goto fail;
    while(done<(size_t)st.st_size) {
        ssize_t n=read(fd,data+done,(size_t)st.st_size-done);
        if(n<0&&errno==EINTR)continue;
        if(n<=0)goto fail;
        done+=(size_t)n;
    }
    ssize_t n;do { n=read(fd,&extra,1); } while(n<0&&errno==EINTR);
    if(n!=0)goto fail;
    close(fd);*out=data;*length=done;return 0;
fail:
    if(data) { erase(data,(size_t)st.st_size);free(data); }
    close(fd);return -1;
}
void steer_draft_tls_material_clear(struct steer_draft_tls_material *m) {
    if(!m)return;
    if(m->private_key) { erase(m->private_key,m->private_key_length);free(m->private_key); }
    free(m->certificate);memset(m,0,sizeof *m);
}
int steer_draft_tls_material_load(const char *certificate,const char *key,struct steer_draft_tls_material *out) {
    if(!out)return -1;
    memset(out,0,sizeof *out);
    if(read_file(certificate,1048576,&out->certificate,&out->certificate_length)||
       read_file(key,65536,&out->private_key,&out->private_key_length)) {
        steer_draft_tls_material_clear(out);return -1;
    }
    return 0;
}
