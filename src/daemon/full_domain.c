/* Fixed, non-root, one-generation supd domain. Provisioning is offline;
 * this process is the sole writer after publication. No registry lookup. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/epoll.h>
#include "full_domain.h"
#include "helpers.h"
#include "loop.h"
#include "plugin.h"

#if defined(__linux__) && defined(__x86_64__) && !defined(__ANDROID__) && defined(STATX_MNT_ID)
#include <sys/xattr.h>
#include <sys/random.h>
#include <stddef.h>

/* Static/compatible builds without the verifier must refuse this profile. */
extern int pm_file_sha256(const char *, unsigned char [32], unsigned long long *) __attribute__((weak));
#define BIND "user.steer.supd1.binding"
#define PHASE "user.steer.supd1.phase"
#define TYPE "supd-full/1"
#define ELF "tree/bin/steer-ui-service"
struct full_domain {
    char path[256], g[33], ticket[33];
    char binding[4096];
    ssize_t binding_n;
    int history, lock, server;
    struct supd *sup;
};

/* Inventory order is part of binding v1. A dir is checked before its
 * descendants. Counts reject extra entries (including legacy manifests). */
static const struct entry { const char *name; int children; } layout[] = {
    {".",5},{"owner.lock",-1},{"child.lock",-1},{"history",-1},{"type",-1},
    {"tree",7},{"tree/bin",1},{"tree/assets",5},{"tree/assets/fonts",3},{"tree/licenses",1},
    {"tree/LICENSE",-1},{"tree/MANIFEST",-1},{"tree/MANIFEST.sig",-1},{"tree/plugin.json",-1},
    {ELF,-1},{"tree/licenses/libyaml.txt",-1},{"tree/assets/index.html",-1},
    {"tree/assets/app.css",-1},{"tree/assets/app.js",-1},{"tree/assets/config-model.js",-1},
    {"tree/assets/fonts/Onest-OFL.txt",-1},{"tree/assets/fonts/onest-cyrillic.woff2",-1},
    {"tree/assets/fonts/onest-latin.woff2",-1}
};

static int count_entries(const char *path) {
    DIR *d = opendir(path);
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    errno = 0;
    while ((e = readdir(d))) if (strcmp(e->d_name,".") && strcmp(e->d_name,"..")) n++;
    if (errno) n = -1;
    closedir(d);
    return n;
}

static int disk_binding(struct full_domain *f) {
    char actual[4096], expected[sizeof(actual)], path[512];
    size_t used = 0;
    struct statx base;
    snprintf(path,sizeof(path),"%s/..",f->path);
    if (statx(AT_FDCWD,path,0,STATX_MNT_ID,&base) || !(base.stx_mask & STATX_MNT_ID)) return -1;
    for (size_t i=0; i<sizeof(layout)/sizeof(layout[0]); i++) {
        const struct entry *e = &layout[i];
        snprintf(path,sizeof(path),"%s/%s",f->path,e->name);
        struct stat st;
        struct statx sx;
        if (lstat(path,&st) || st.st_uid != getuid() ||
            statx(AT_FDCWD,path,AT_SYMLINK_NOFOLLOW,STATX_MNT_ID,&sx) || sx.stx_mnt_id != base.stx_mnt_id)
            return -1;
        char hex[65] = "-";
        if (e->children >= 0) {
            if (!S_ISDIR(st.st_mode) || (st.st_mode & 07022) || count_entries(path) != e->children) return -1;
        } else {
            if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return -1;
            if (!strcmp(e->name,"type") || !strncmp(e->name,"tree/",5)) {
                unsigned char hash[32];
                unsigned long long size;
                if (st.st_size > 8*1024*1024 || !pm_file_sha256 || pm_file_sha256(path,hash,&size)) return -1;
                for (unsigned j=0;j<32;j++) snprintf(hex+2*j,3,"%02x",hash[j]);
            } else if (strcmp(e->name,"history") && st.st_size != 0) return -1;
        }
        int n = snprintf(actual+used,sizeof(actual)-used,"%s %llu %llu %o %s\n",e->name,
                         (unsigned long long)st.st_dev,(unsigned long long)st.st_ino,(unsigned)st.st_mode,hex);
        if (n < 0 || (size_t)n >= sizeof(actual)-used) return -1;
        used += (size_t)n;
    }
    ssize_t n = lgetxattr(f->path,BIND,expected,sizeof(expected));
    return n == (ssize_t)used && n == f->binding_n && !memcmp(f->binding,expected,used) &&
           !memcmp(actual,expected,used) ? 0 : -1;
}

static int hex32(const char *s) {
    return strlen(s)==32 && strspn(s,"0123456789abcdef")==32;
}

/* An intact prepared fence plus A is already non-launchable; only a
 * matching fence request can finish sealing it. A missing sealed tail is
 * damage, not an undo. owner.lock is NEVER re-opened by this process. */
static int state(struct full_domain *f) {
    char buf[128], want[128], phase, real[4096], parent[256];
    struct stat st;
    if (!realpath(f->path,real) || strcmp(real,f->path)) return -1;
    strcpy(parent,f->path);
    *strrchr(parent,'/') = 0;
    if (stat(parent,&st) || st.st_mode!=(S_IFDIR|0700) || st.st_uid!=getuid() || disk_binding(f)) return -1;
    if (fgetxattr(f->history,PHASE,&phase,1)!=1) return -1;
    int a = snprintf(want,sizeof(want),"start %s\n",f->g);
    int b = snprintf(want+a,sizeof(want)-(size_t)a,"fence %s\n",f->g);
    ssize_t n = pread(f->history,buf,sizeof(buf),0);
    if (n == a && phase=='A' && !memcmp(buf,want,(size_t)a)) return 1;
    if (n == a+b && !memcmp(buf,want,(size_t)n)) return phase=='F' ? 0 : phase=='A' ? 2 : -1;
    return -1;
}
int full_active(struct full_domain *f) { return state(f); }

static int lease(struct full_domain *f) {
    char path[300];
    snprintf(path,sizeof(path),"%s/child.lock",f->path);
    int fd = open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd < 0) return -1;
    if (fd <= 3) {
        int high = fcntl(fd,F_DUPFD_CLOEXEC,4);
        close(fd);
        fd = high;
    }
    if (fd >= 0 && flock(fd,LOCK_EX|LOCK_NB)) { close(fd); return -1; }
    return fd;
}
int full_launch_lease(struct full_domain *f) { return state(f)==1 ? lease(f) : -1; }

int full_plan(struct full_domain *f, struct helper *h) {
    char prog[300], assets[300], core[300];
    snprintf(prog,sizeof(prog),"%s/%s",f->path,ELF);
    snprintf(assets,sizeof(assets),"%s/tree/assets",f->path);
    snprintf(core,sizeof(core),"%s-v3.sock",f->path);
    char *args[] = {"--port","0","--assets",assets,"--core-control",core};
    struct kind_helper hp = {.cmd="service", .prog=prog, .arg=args, .arg_n=6};
    memset(h,0,sizeof(*h));
    h->service=1; h->evfd=-1; h->delay_ms=HELPERS_DELAY_MS;
    strcpy(h->name,"full-ui"); strcpy(h->plugin,"steer-ui");
    return helper_launch_set(h,&hp);
}

static const char *fence(struct full_domain *f, int phase) {
    if (phase == 1) {
        char line[48];
        int n = snprintf(line,sizeof(line),"fence %s\n",f->g);
        if (write(f->history,line,(size_t)n)!=n) return "damaged";
    }
    if (phase && (fsync(f->history) || fsetxattr(f->history,PHASE,"F",1,XATTR_REPLACE))) return "damaged";
    if (fsync(f->history) || state(f)!=0) return "damaged";
    supd_spec_changed(f->sup,NULL,0); /* gone, SIGTERM; wait asynchronously via child_cb */
    if (supd_full_pid(f->sup)) return "pending";
    int fd = lease(f);
    if (fd < 0) return "pending";
    close(fd);
    return "excluded";
}

static void answer(struct full_domain *f,int c) {
    char q[200], op[10], g[33], challenge[33], ticket[33], extra, reply[256];
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(c,SOL_SOCKET,SO_PEERCRED,&cred,&len) || cred.uid!=getuid()) return;
    ssize_t n = recv(c,q,sizeof(q)-1,MSG_TRUNC);
    if (n<=0 || n>=(ssize_t)sizeof(q) || memchr(q,0,(size_t)n)) return;
    q[n]=0;
    if (sscanf(q,"%9s %32s %32s %32s %c",op,g,challenge,ticket,&extra)!=4 ||
        !hex32(g) || !hex32(challenge)) return;
    const char *result="refused", *proof="-";
    if (!strcmp(g,f->g)) {
        int phase = state(f);
        if (phase<0) result="damaged";
        else if (!strcmp(op,"status") && !strcmp(ticket,"-"))
            result=phase==1?"active":phase==0?"fenced":"pending";
        else if ((!strcmp(op,"fence") && !strcmp(ticket,"-")) ||
                 (!strcmp(op,"check") && !strcmp(ticket,f->ticket) && phase==0)) {
            result=fence(f,phase);
            if (!strcmp(result,"excluded")) proof=f->ticket;
        }
    }
    n=snprintf(reply,sizeof(reply),"%s %s %s %s %s %s %ld %d",TYPE,op,g,challenge,result,proof,
               (long)getpid(),supd_full_pid(f->sup));
    send(c,reply,(size_t)n,MSG_NOSIGNAL);
}

static void incoming(struct loop *l,int fd,uint32_t events,void *arg) {
    (void)l; (void)events;
    int c=accept4(fd,NULL,NULL,SOCK_CLOEXEC);
    if (c<0) return;
    struct timeval limit={0,250000};
    if (!setsockopt(c,SOL_SOCKET,SO_RCVTIMEO,&limit,sizeof(limit))) answer(arg,c);
    close(c);
}
static void sig_cb(struct loop *l,int sig,void *arg) {
    struct full_domain *f=arg;
    if (sig==SIGHUP) supd_spec_changed(f->sup,NULL,0);
    else loop_stop(l,0);
}

static int open_domain(struct full_domain *f,const char *prefix) {
    char path[300], meta[512], expected[512], archive[65], key[65], real[4096];
    const char *base="/tmp/e4-lab-";
    if (!getuid() || geteuid()!=getuid() || getegid()!=getgid() ||
        strlen(prefix)>80 || strncmp(prefix,base,strlen(base)) ||
        !realpath(prefix,real) || strcmp(real,prefix)) return -1;
    const char *slash=strchr(prefix+strlen(base),'/');
    if (!slash || slash==prefix+strlen(base) || !slash[1] ||
        strspn(slash+1,"abcdefghijklmnopqrstuvwxyz0123456789-")!=strlen(slash+1)) return -1;
    strcpy(f->path,prefix);
    f->binding_n=lgetxattr(prefix,BIND,f->binding,sizeof(f->binding));
    if (disk_binding(f)) return -1;
    snprintf(path,sizeof(path),"%s/type",prefix);
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t n=read(fd,meta,sizeof(meta)-1);
    close(fd);
    if (n<=0 || n>=(ssize_t)sizeof(meta)-1) return -1;
    meta[n]=0;
    if (sscanf(meta,TYPE " %*s %32s %64s %64s",f->g,archive,key)!=3 || !hex32(f->g) ||
        strspn(archive,"0123456789abcdef")!=64 || strspn(key,"0123456789abcdef")!=64) return -1;
    int want=snprintf(expected,sizeof(expected),TYPE "\n%s\n%s\n%s\n%s\n",prefix,f->g,archive,key);
    if (want!=n || memcmp(meta,expected,(size_t)n)) return -1;
    snprintf(path,sizeof(path),"%s/owner.lock",prefix);
    f->lock=open(path,O_RDWR|O_CLOEXEC|O_NOFOLLOW);
    struct flock lk={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    if (f->lock<0 || fcntl(f->lock,F_SETLK,&lk)) return -1;
    snprintf(path,sizeof(path),"%s/history",prefix);
    f->history=open(path,O_RDWR|O_APPEND|O_CLOEXEC|O_NOFOLLOW);
    if (f->history<0 || state(f)<0) return -1;
    unsigned char random[16];
    if (getrandom(random,sizeof(random),0)!=sizeof(random)) return -1;
    for (unsigned i=0;i<sizeof(random);i++) snprintf(f->ticket+2*i,3,"%02x",random[i]);
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    int al=snprintf(addr.sun_path+1,sizeof(addr.sun_path)-1,"steer-supd1-%s",f->g);
    f->server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    return f->server<0 || bind(f->server,(struct sockaddr *)&addr,
             (socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+al)) || listen(f->server,8) ? -1 : 0;
}

int supd_full_main(const char *prefix) {
    struct full_domain f={0};
    if (open_domain(&f,prefix)) { fputs("supd-full: owner/history/binding unavailable\n",stderr); return 1; }
    struct loop *l=loop_new();
    if (!l || loop_fd_add(l,f.server,EPOLLIN,incoming,&f) || loop_signal(l,SIGHUP,sig_cb,&f) ||
        loop_signal(l,SIGTERM,sig_cb,&f) || loop_signal(l,SIGINT,sig_cb,&f) || !(f.sup=supd_full_open(l,&f)))
        return 1;
    int rc=loop_run(l);
    supd_stop(f.sup);
    return rc; /* standalone process exits, releasing owner.lock last */
}
#else
int supd_full_main(const char *p) { (void)p; fputs("supd-full: unsupported build\n",stderr); return 2; }
int full_active(struct full_domain *f) { (void)f; return -1; }
int full_launch_lease(struct full_domain *f) { (void)f; return -1; }
int full_plan(struct full_domain *f,struct helper *h) { (void)f; (void)h; return -1; }
#endif
