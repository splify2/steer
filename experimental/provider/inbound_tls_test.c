/* SPDX-License-Identifier: GPL-3.0-only */
#define _GNU_SOURCE
#include "inbound_tls.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static void write_file(const char *path,const char *data) {
    int fd=open(path,O_CREAT|O_TRUNC|O_WRONLY,0600);assert(fd>=0);
    assert(write(fd,data,strlen(data))==(ssize_t)strlen(data));assert(!close(fd));
}
int main(void) {
    char directory[]="/tmp/steer-inbound-tls-XXXXXX",cert[256],key[256],link[256],fifo[256];
    assert(mkdtemp(directory));snprintf(cert,sizeof cert,"%s/cert",directory);snprintf(key,sizeof key,"%s/key",directory);
    snprintf(link,sizeof link,"%s/link",directory);snprintf(fifo,sizeof fifo,"%s/fifo",directory);
    write_file(cert,"public fixture certificate");write_file(key,"public disposable key fixture");
    struct steer_draft_tls_material material;
    assert(!steer_draft_tls_material_load(cert,key,&material));
    assert(material.certificate_length==26&&material.private_key_length==29);
    assert(!memcmp(material.certificate,"public fixture certificate",26));
    steer_draft_tls_material_clear(&material);steer_draft_tls_material_clear(&material);
    assert(!symlink(cert,link));assert(!steer_draft_tls_material_load(link,key,&material));steer_draft_tls_material_clear(&material);
    assert(!mkfifo(fifo,0600));assert(steer_draft_tls_material_load(fifo,key,&material)==-1&&!material.certificate&&!material.private_key);
    assert(steer_draft_tls_material_load(directory,key,&material)==-1);
    assert(steer_draft_tls_material_load(cert,NULL,&material)==-1&&!material.certificate&&!material.private_key);
    write_file(key,"");assert(steer_draft_tls_material_load(cert,key,&material)==-1);
    int fd=open(key,O_WRONLY);assert(fd>=0&&!ftruncate(fd,65537)&&!close(fd));
    assert(steer_draft_tls_material_load(cert,key,&material)==-1&&!material.certificate&&!material.private_key);
    fd=open(cert,O_WRONLY);assert(fd>=0&&!ftruncate(fd,1048577)&&!close(fd));
    assert(steer_draft_tls_material_load(cert,key,&material)==-1);
    assert(!unlink(link)&&!unlink(fifo)&&!unlink(cert)&&!unlink(key)&&!rmdir(directory));
    puts("inbound TLS material: bounded regular files, FIFO/directory/oversize rejection, cleanup PASS");return 0;
}
