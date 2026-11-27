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
#include "full_remove.h"
#include "full_install.h"
#include "helpers.h"
#include "loop.h"
#include "plugin.h"

#if defined(__linux__) && defined(__x86_64__) && !defined(__ANDROID__)
#include <sys/time.h>
#include <sys/xattr.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <linux/fs.h>
#include <stddef.h>

/* Static/compatible builds without the verifier must refuse this profile. */
extern int pm_file_sha256(const char *, unsigned char [32], unsigned long long *) __attribute__((weak));
extern int pm_binding_sha(const void *,size_t,char [65]) __attribute__((weak));
extern int pm_statx_mount_id(const char *,uint64_t *) __attribute__((weak));
#define BIND "user.steer.supd1.binding"
#define PHASE "user.steer.supd1.phase"
#define TYPE "supd-full/1"
#define ELF "tree/bin/steer-ui-service"
struct full_domain {
    char path[256], g[33], ticket[33];
    char binding[4096];
    ssize_t binding_n;
    int v2, retired;
    char digest[65];
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
    {"tree/assets/fonts/onest-latin.woff2",-1},{".lock",0} /* /2 legacy writer barrier */
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

static int walk_binding(struct full_domain *f,const struct full_package *pkg,const char *host,
                        const char *type_hash,char actual[4096]) {
    char path[512];
    size_t used = 0;
    uint64_t base;
    snprintf(path,sizeof(path),"%s/..",f->path);
    if (!pm_statx_mount_id || pm_statx_mount_id(path,&base) || !base) return -1;
    f->retired=0;
    if (f->v2) {
        struct stat st;
        snprintf(path,sizeof(path),"%s/tree",f->path);
        if (lstat(path,&st)) {
            if (errno!=ENOENT) return -1;
            f->retired=1;
        }
    }
    for (size_t i=0; i<sizeof(layout)/sizeof(layout[0])-(f->v2?0:1); i++) {
        const struct entry *e = &layout[i];
        if (f->retired && !strncmp(e->name,"tree",4))
            snprintf(path,sizeof(path),"%s/retired-%s%s",f->path,f->g,e->name+4);
        else snprintf(path,sizeof(path),"%s/%s",f->path,e->name);
        struct stat st;
        uint64_t mount;
        if (lstat(path,&st) || st.st_uid != getuid() ||
            pm_statx_mount_id(path,&mount) || mount!=base)
            return -1;
        char hex[65] = "-";
        if (e->children >= 0) {
            if (!S_ISDIR(st.st_mode) || (st.st_mode & 07022) ||
                count_entries(path) != e->children+(i==0 && f->v2)) return -1;
        } else {
            if (!S_ISREG(st.st_mode) || st.st_nlink != 1) return -1;
            if (!strcmp(e->name,"type") || !strncmp(e->name,"tree/",5)) {
                unsigned char hash[32];
                unsigned long long size;
                if (st.st_size > 8*1024*1024 || !pm_file_sha256 || pm_file_sha256(path,hash,&size)) return -1;
                for (unsigned j=0;j<32;j++) snprintf(hex+2*j,3,"%02x",hash[j]);
            } else if (strcmp(e->name,"history") && st.st_size != 0) return -1;
        }
        if (pkg) {
            int tree=!strncmp(e->name,"tree",4);
            mode_t mode=e->children>=0 ? (tree?0755:0700) : !tree?0600:!strcmp(e->name,ELF)?0755:0644;
            if (f->retired || (st.st_mode & 07777)!=mode ||
                (!strcmp(e->name,"tree") && (st.st_dev!=pkg->dev || st.st_ino!=pkg->ino)) ||
                (!strcmp(e->name,"type") && strcmp(type_hash,hex))) return -1;
            if (tree && e->children<0) {
                unsigned j=0;
                while (j<pkg->n && strcmp(pkg->files[j].name,e->name+5)) j++;
                if (j==pkg->n || pkg->files[j].dev!=st.st_dev || pkg->files[j].ino!=st.st_ino) return -1;
                char signed_hex[65];
                for (unsigned k=0;k<32;k++) snprintf(signed_hex+2*k,3,"%02x",pkg->files[j].hash[k]);
                if (strcmp(hex,signed_hex) || (!strcmp(e->name,ELF) && strcmp(hex,host))) return -1;
            }
            int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW);
            if (fd<0) return -1;
            int rc=fsync(fd);
            close(fd);
            if (rc) return -1;
        }
        int n = snprintf(actual+used,sizeof(f->binding)-used,"%s %llu %llu %o %s\n",e->name,
                         (unsigned long long)st.st_dev,(unsigned long long)st.st_ino,(unsigned)st.st_mode,hex);
        if (n < 0 || (size_t)n >= sizeof(f->binding)-used) return -1;
        used += (size_t)n;
    }
    return (int)used;
}

static int disk_binding(struct full_domain *f) {
    char actual[4096],expected[4096];
    int used=walk_binding(f,NULL,NULL,NULL,actual);
    if (used<0) return -1;
    ssize_t n=lgetxattr(f->path,f->v2?FULL_BIND2:BIND,expected,sizeof(expected));
    return n == (ssize_t)used && n == f->binding_n && !memcmp(f->binding,expected,used) &&
           !memcmp(actual,expected,used) ? 0 : -1;
}

int full_first_capable(void) { return pm_file_sha256 && pm_binding_sha && pm_statx_mount_id; }

int full_seal_new(const char *stage,const struct full_package *pkg,const char *host,
                  const char *type_hash,char binding[65]) {
    struct full_domain f={.v2=1};
    if (!full_first_capable() || strlen(stage)>=sizeof(f.path) || pkg->n!=FULL_FILES) return -1;
    strcpy(f.path,stage);
    int n=walk_binding(&f,pkg,host,type_hash,f.binding);
    return n<0 || lsetxattr(stage,FULL_BIND2,f.binding,(size_t)n,XATTR_CREATE) ||
           pm_binding_sha(f.binding,(size_t)n,binding) ? -1 : 0;
}

static int hex32(const char *s) {
    return strlen(s)==32 && strspn(s,"0123456789abcdef")==32;
}

/* Never re-open owner.lock in the owner process: closing even an unrelated
 * fd on that inode would release the process-owned write lock. */
static int domain_ok(struct full_domain *f) {
    char real[4096], parent[256];
    struct stat st;
    if (!realpath(f->path,real) || strcmp(real,f->path)) return -1;
    strcpy(parent,f->path);
    *strrchr(parent,'/') = 0;
    return stat(parent,&st) || st.st_mode!=(S_IFDIR|0700) || st.st_uid!=getuid() || disk_binding(f) ? -1 : 0;
}

/* /2: immutable decision and commit records, independent monotonic seal.
 * Check intent BEFORE every fork, including the window before seal I. */
enum tx_state { BAD=-1, REMOVED=0, ACTIVE=1, INTENT, MOVED, COMMITTING };
static int decision(char record[256],const char *g,const char *binding,const char *tx) {
    int n=snprintf(record,256,"%s %s %s",g,binding,tx);
    char hash[65];
    if (!pm_binding_sha || pm_binding_sha(record,(size_t)n,hash)) return -1;
    return n+snprintf(record+n,256-(size_t)n," %s",hash);
}

static int seal_tx(int fd,char state,const char *tx) {
    char s[33];
    s[0]=state; memcpy(s+1,tx,32);
    return fsetxattr(fd,FULL_PHASE2,s,33,XATTR_REPLACE);
}

static int tx_state(struct full_domain *f, char tx[33], char *seal) {
    char initial[64], buf[256], intent[256], commit[256], canonical[256], s[34];
    int n=snprintf(initial,sizeof(initial),"start %s\n",f->g);
    if (domain_ok(f) || pread(f->history,buf,sizeof(buf),0)!=n || memcmp(buf,initial,(size_t)n)) return BAD;
    ssize_t sn=fgetxattr(f->history,FULL_PHASE2,s,sizeof(s));
    if (sn!=1 && sn!=33) return BAD;
    *seal=s[0];
    if ((*seal=='A')!=(sn==1)) return BAD;
    ssize_t i=fgetxattr(f->history,FULL_INTENT,intent,sizeof(intent)-1);
    if (i<0 && errno!=ENODATA) return BAD;
    ssize_t c=fgetxattr(f->history,FULL_COMMIT,commit,sizeof(commit));
    if (c<0 && errno!=ENODATA) return BAD;
    if (i<0) return !f->retired && *seal=='A' && c<0 ? ACTIVE : BAD;
    intent[i]=0;
    if (sscanf(intent,"%*s %*s %32s",tx)!=1 || !hex32(tx)) return BAD;
    n=decision(canonical,f->g,f->digest,tx);
    if (n<0 || i!=n || memcmp(canonical,intent,(size_t)n) || (sn==33 && memcmp(s+1,tx,32))) return BAD;
    if (!f->retired) return (*seal=='I' || *seal=='A') && c<0 ? INTENT : BAD;
    if (c<0) return *seal=='I' ? MOVED : BAD;
    if (c!=n || memcmp(commit,canonical,(size_t)n)) return BAD;
    return *seal=='I' ? COMMITTING : *seal=='C' ? REMOVED : BAD;
}

static int state(struct full_domain *f) {
    char buf[128], want[128], phase;
    if (f->v2) {
        char tx[33];
        return tx_state(f,tx,&phase);
    }
    if (domain_ok(f)) return -1;
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

/* Only this owner writes. It never returns to helpers_due or another request
 * between the under-lease compare, rename and commit. Never accepts a path. */
static const char *remove_exact(struct full_domain *f,const char *op,const char *g,const char *b,const char *tx) {
    if (strcmp(g,f->g) || strcmp(b,f->digest) || !hex32(tx)) return "conflict";
    char prior[33], seal, record[256], dst[64];
    int st=tx_state(f,prior,&seal);
    if (st==BAD) return "damaged";
    int begin=!strcmp(op,"remove");
    if (strcmp(op,"inspect") && strcmp(op,"recover") && !begin) return "refused";
    if (st!=ACTIVE && strcmp(tx,prior)) return "conflict";
    if (!strcmp(op,"inspect")) {
        if (st==REMOVED && fsync(f->history)) return "unconfirmed";
        return st==ACTIVE?"active":st==REMOVED?"removed":st==INTENT?"intent":"quarantined";
    }
    if (begin!=(st==ACTIVE)) return "conflict";
    int len=decision(record,g,b,tx);
    if (len<0) return "unconfirmed";
    if (begin && fsetxattr(f->history,FULL_INTENT,record,(size_t)len,XATTR_CREATE)) return "unconfirmed";
    if (st==REMOVED) return fsync(f->history) ? "unconfirmed" : "removed";
    if (seal=='A' && (fsync(f->history) || seal_tx(f->history,'I',tx))) return "unconfirmed";
    if (fsync(f->history)) return "unconfirmed";
    supd_spec_changed(f->sup,NULL,0);
    if (supd_full_pid(f->sup)) return "pending";
    int fd=lease(f);
    if (fd<0) return "pending";
    const char *result="unconfirmed";
    int root=open(f->path,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    st=tx_state(f,prior,&seal);
    if (root<0 || (st!=INTENT && st!=MOVED && st!=COMMITTING) || strcmp(prior,tx) || seal!='I') goto out;
    snprintf(dst,sizeof(dst),"retired-%s",g);
    if (st==INTENT && syscall(SYS_renameat2,root,"tree",root,dst,RENAME_NOREPLACE)) goto out;
    if (fsync(root)) goto out;
    st=tx_state(f,prior,&seal);
    if ((st!=MOVED && st!=COMMITTING) || strcmp(prior,tx)) goto out;
    if (st==MOVED && fsetxattr(f->history,FULL_COMMIT,record,(size_t)len,XATTR_CREATE)) goto out;
    if (!fsync(f->history) && !seal_tx(f->history,'C',tx) &&
        !fsync(f->history) && tx_state(f,prior,&seal)==REMOVED && !strcmp(prior,tx)) result="removed";
out:
    if (root>=0) close(root);
    close(fd);
    return result;
}

static int full_nonce(char out[33]) {
    unsigned char random[16];
    if (getrandom(random,sizeof(random),0)!=sizeof(random)) return -1;
    for (unsigned i=0;i<sizeof(random);i++) snprintf(out+2*i,3,"%02x",random[i]);
    return 0;
}

static void answer_remove(struct full_domain *f,int c) {
    char nonce[33],q[256],op[12],g[33],b[65],tx[33],echo[33],extra,reply[320];
    if (full_nonce(nonce) || send(c,nonce,32,MSG_NOSIGNAL)!=32) return;
    ssize_t n=recv(c,q,sizeof(q)-1,MSG_TRUNC);
    if (n<=0 || n>=(ssize_t)sizeof(q) || memchr(q,0,(size_t)n)) return;
    q[n]=0;
    if (sscanf(q,"%11s %32s %64s %32s %32s %c",op,g,b,tx,echo,&extra)!=5 || strcmp(echo,nonce)) return;
    const char *result=remove_exact(f,op,g,b,tx);
    n=snprintf(reply,sizeof(reply),FULL_TYPE2 " %s %s %s %s %s %s",op,g,b,tx,nonce,result);
    send(c,reply,(size_t)n,MSG_NOSIGNAL);
}

static void answer(struct full_domain *f,int c) {
    char q[200], op[10], g[33], challenge[33], ticket[33], extra, reply[256];
    struct ucred cred;
    socklen_t len = sizeof(cred);
    if (getsockopt(c,SOL_SOCKET,SO_PEERCRED,&cred,&len) || cred.uid!=getuid()) return;
    if (f->v2) { answer_remove(f,c); return; }
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

static int read_domain(struct full_domain *f,const char *prefix,const char *location,int writer) {
    char path[300], meta[512], expected[512], archive[65], key[65], real[4096];
    const char *base="/tmp/e4-lab-";
    if (!getuid() || geteuid()!=getuid() || getegid()!=getgid() ||
        strlen(prefix)>80 || strncmp(prefix,base,strlen(base)) ||
        strlen(location)>=sizeof(f->path) || !realpath(location,real) || strcmp(real,location)) return -1;
    const char *slash=strchr(prefix+strlen(base),'/');
    if (!slash || slash==prefix+strlen(base) || !slash[1] ||
        strspn(slash+1,"abcdefghijklmnopqrstuvwxyz0123456789-")!=strlen(slash+1)) return -1;
    strcpy(f->path,location);
    f->binding_n=lgetxattr(location,FULL_BIND2,f->binding,sizeof(f->binding));
    if (f->binding_n>=0) f->v2=1;
#ifdef STATX_MNT_ID
    /* /1 retains its original libc/build boundary. /2 can get the exact
     * same mount-ID evidence from the stock Linux UAPI helper on musl. */
    else if (errno==ENODATA) f->binding_n=lgetxattr(location,BIND,f->binding,sizeof(f->binding));
#endif
    if (f->binding_n<=0) return -1;
    snprintf(path,sizeof(path),"%s/type",location);
    struct stat st;
    if (lstat(path,&st) || st.st_mode!=(S_IFREG|0600) || st.st_nlink!=1 || st.st_uid!=getuid()) return -1;
    int fd=open(path,O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t n=read(fd,meta,sizeof(meta)-1);
    close(fd);
    if (n<=0 || n>=(ssize_t)sizeof(meta)-1) return -1;
    meta[n]=0;
    if (sscanf(meta,"%*s %*s %32s %64s %64s",f->g,archive,key)!=3 || !hex32(f->g) ||
        strspn(archive,"0123456789abcdef")!=64 || strspn(key,"0123456789abcdef")!=64) return -1;
    int want=snprintf(expected,sizeof(expected),"%s\n%s\n%s\n%s\n%s\n",f->v2?FULL_TYPE2:TYPE,prefix,f->g,archive,key);
    if (want!=n || memcmp(meta,expected,(size_t)n) || domain_ok(f)) return -1;
    if (f->v2 && (!pm_binding_sha || pm_binding_sha(f->binding,(size_t)f->binding_n,f->digest))) return -1;
    snprintf(path,sizeof(path),"%s/owner.lock",location);
    f->lock=open(path,(writer?O_RDWR:O_RDONLY)|O_CLOEXEC|O_NOFOLLOW);
    struct flock lk={.l_type=F_WRLCK,.l_whence=SEEK_SET};
    if (f->lock<0 || (writer && fcntl(f->lock,F_SETLK,&lk))) return -1;
    snprintf(path,sizeof(path),"%s/history",location);
    f->history=open(path,(writer?(O_RDWR|O_APPEND):O_RDONLY)|O_CLOEXEC|O_NOFOLLOW);
    if (f->history<0 || state(f)<0) return -1;
    return 0;
}

static int open_domain(struct full_domain *f,const char *prefix) {
    if (read_domain(f,prefix,prefix,1)) return -1;
    if (full_nonce(f->ticket)) return -1;
    struct sockaddr_un addr={.sun_family=AF_UNIX};
    int al=snprintf(addr.sun_path+1,sizeof(addr.sun_path)-1,"steer-supd%d-%s",f->v2?2:1,f->g);
    f->server=socket(AF_UNIX,SOCK_SEQPACKET|SOCK_NONBLOCK|SOCK_CLOEXEC,0);
    return f->server<0 || bind(f->server,(struct sockaddr *)&addr,
             (socklen_t)(offsetof(struct sockaddr_un,sun_path)+1+al)) || listen(f->server,8) ? -1 : 0;
}

int full_manager_view(const char *prefix,const char *g,const char *binding,const char *committed) {
    struct full_domain f={.history=-1,.lock=-1};
    char tx[33], seal;
    int ok=!read_domain(&f,prefix,prefix,0) && f.v2 && !strcmp(f.g,g) && !strcmp(f.digest,binding) &&
           (!committed || (tx_state(&f,tx,&seal)==REMOVED && !strcmp(tx,committed)));
    if (f.history>=0) close(f.history);
    if (ok) return f.lock;
    if (f.lock>=0) close(f.lock);
    return -1;
}

int full_first_check(const char *stage,const char *prefix,const char *g,const char *binding) {
    struct full_domain f={.history=-1,.lock=-1};
    int ok=!read_domain(&f,prefix,stage,0) && f.v2 && !strcmp(f.g,g) &&
           !strcmp(f.digest,binding) && state(&f)==ACTIVE;
    if (f.history>=0) close(f.history);
    if (f.lock>=0) close(f.lock);
    return ok ? 0 : -1;
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
int full_first_capable(void) { return 0; }
int full_seal_new(const char *s,const struct full_package *p,const char *h,const char *t,char b[65]) {
    (void)s;(void)p;(void)h;(void)t;(void)b;return -1;
}
int full_first_check(const char *s,const char *p,const char *g,const char *b) {
    (void)s;(void)p;(void)g;(void)b;return -1;
}
int full_manager_view(const char *p,const char *g,const char *b,const char *c) {
    (void)p; (void)g; (void)b; (void)c; return -1;
}
int supd_full_main(const char *p) { (void)p; fputs("supd-full: unsupported build\n",stderr); return 2; }
int full_active(struct full_domain *f) { (void)f; return -1; }
int full_launch_lease(struct full_domain *f) { (void)f; return -1; }
int full_plan(struct full_domain *f,struct helper *h) { (void)f; (void)h; return -1; }
#endif
