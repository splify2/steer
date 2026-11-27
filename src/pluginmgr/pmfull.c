/* A manager request, never a second filesystem writer. A prior successful
 * check is deliberately not an argument to this API. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>
#include "full_remove.h"
#include "scrypto.h"

int pm_binding_sha(const void *buf,size_t n,char out[65]) {
    struct sc_hash_ctx h;
    unsigned char digest[32];
    if (sc_hash_init(&h,SC_SHA256)) return -1;
    int bad=sc_hash_update(&h,buf,n) || sc_hash_final(&h,digest);
    sc_hash_free(&h);
    if (bad) return -1;
    for (unsigned i=0;i<32;i++) snprintf(out+2*i,3,"%02x",digest[i]);
    return 0;
}

static int hex(const char *s,size_t n) {
    return strlen(s)==n && strspn(s,"0123456789abcdef")==n;
}

/* This narrow version requires a matching manager/supervisor executable.
 * Check the connected peer before sending any operation. */
static int peer(int sock,int lock) {
    struct ucred u;
    socklen_t n=sizeof(u);
    struct flock l={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    if (getsockopt(sock,SOL_SOCKET,SO_PEERCRED,&u,&n) || u.uid!=getuid() || u.pid<=0 ||
        fcntl(lock,F_GETLK,&l) || l.l_type!=F_WRLCK || l.l_whence!=SEEK_SET ||
        l.l_start || l.l_len || l.l_pid!=u.pid) return -1;
    char path[64];
    struct stat a,b;
    snprintf(path,sizeof(path),"/proc/%ld/exe",(long)u.pid);
    return stat(path,&a) || stat("/proc/self/exe",&b) || a.st_dev!=b.st_dev || a.st_ino!=b.st_ino ? -1 : 0;
}

enum { RETRY_PENDING=4 };
static int one_request(const char *p,const char *op,const char *g,const char *b,const char *tx,int retry) {
    int lock=full_manager_view(p,g,b,NULL), s=-1, rc=1;
    if (lock<0) goto done;
    struct sockaddr_un a={.sun_family=AF_UNIX};
    int al=snprintf(a.sun_path+1,sizeof(a.sun_path)-1,"steer-supd2-%s",g);
    s=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_CLOEXEC,0);
    struct timeval timeout={3,0};
    if (s<0 || setsockopt(s,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout)) ||
        setsockopt(s,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout)) ||
        connect(s,(struct sockaddr *)&a,(socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+al)) ||
        peer(s,lock)) goto done;
    char nonce[33], req[256], reply[320], prefix[300];
    if (recv(s,nonce,32,MSG_TRUNC)!=32) goto done;
    nonce[32]=0;
    if (!hex(nonce,32)) goto done;
    int len=snprintf(req,sizeof(req),"%s %s %s %s %s",op,g,b,tx,nonce);
    if (send(s,req,(size_t)len,MSG_NOSIGNAL)!=len) goto done;
    ssize_t n=recv(s,reply,sizeof(reply)-1,MSG_TRUNC);
    len=snprintf(prefix,sizeof(prefix),FULL_TYPE2 " %s ",req);
    if (n<=len || n>=(ssize_t)sizeof(reply) || memchr(reply,0,(size_t)n) ||
        memcmp(reply,prefix,(size_t)len)) goto done;
    reply[n]=0;
    const char *result=reply+len;
    if (!strcmp(result,"removed")) {
        int witness=full_manager_view(p,g,b,tx);
        if (witness<0) goto done;
        close(witness);
        rc=0;
    } else if (!strcmp(result,"pending") && retry) {
        rc=RETRY_PENDING;
        goto done;
    } else if (!strcmp(result,"pending") || !strcmp(result,"active") ||
               !strcmp(result,"intent") || !strcmp(result,"quarantined")) rc=3;
    else {
        fprintf(stderr,"supd-full: %s\n",result);
        goto done;
    }
    printf("{\"state\":\"%s\",\"generation\":\"%s\",\"binding\":\"%s\",\"tx\":\"%s\"}\n",result,g,b,tx);
done:
    if (rc==1) fputs("supd-full: removal not confirmed\n",stderr);
    if (s>=0) close(s);
    if (lock>=0) close(lock);
    return rc;
}

int pm_full_main(const char *p,const char *action,const char *g,const char *b,const char *tx) {
    const char *op=!strcmp(action,"remove-exact")?"remove":!strcmp(action,"recover-exact")?"recover":
                   !strcmp(action,"inspect-exact")?"inspect":NULL;
    if (!op || !hex(g,32) || !hex(b,64) || !hex(tx,32)) {
        fputs("supd-full: expected {remove,recover,inspect}-exact G BINDING TX\n",stderr);
        return 2;
    }
    /* Let the normal supervisor loop reap a terminating UI. Only retry an
     * authenticated pending response, never infer a decision from EOF. */
    for (int i=0;;i++) {
        int rc=one_request(p,op,g,b,tx,i<4 && strcmp(op,"inspect"));
        if (rc!=RETRY_PENDING) return rc;
        usleep(50000);
        op="recover";
    }
}
