/* Offline first publication. Never write into an existing full-domain prefix. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fs.h>
#include <linux/memfd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/xattr.h>
#include <unistd.h>
#include "pm.h"
#include "full_install.h"
#include "full_remove.h"

static int hex(const char *s,size_t n) {
    return strlen(s)==n && strspn(s,"0123456789abcdef")==n;
}

/* The trusted key path is policy, not archive data. Walk its ancestry on
 * pinned fds so a different uid cannot redirect this lookup. */
static int open_key(const char *absolute) {
    char path[PATH_MAX];
    strcpy(path,absolute+1); /* already canonical, realpath succeeded */
    int dir=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    char *name=path,*slash;
    while (dir>=0 && (slash=strchr(name,'/'))) {
        *slash=0;
        int next=openat(dir,name,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        close(dir);
        struct stat st;
        if (next<0) return -1;
        if (fstat(next,&st) || (st.st_uid && st.st_uid!=getuid()) ||
            ((st.st_mode&022) && !(st.st_mode&S_ISVTX))) { close(next); return -1; }
        dir=next; name=slash+1;
    }
    if (dir<0) return -1;
    int fd=openat(dir,name,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    close(dir);
    return fd;
}

/* Inputs are bounded snapshots. The verifier reads the same archive whose
 * digest the caller selected, even if the input path is replaced. */
static unsigned char *input(const char *path,size_t limit,size_t *n,int key) {
    char resolved[PATH_MAX];
    if (path[0]!='/' || !realpath(path,resolved) || strcmp(path,resolved)) return NULL;
    int fd=key?open_key(path):open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
    struct stat st;
    unsigned char *buf=NULL;
    if (fd>=0 && !fstat(fd,&st) && S_ISREG(st.st_mode) && st.st_size>0 &&
        (unsigned long long)st.st_size<=limit && (!key || (!(st.st_mode&022) &&
        (!st.st_uid || st.st_uid==getuid())))) {
        *n=(size_t)st.st_size;
        buf=malloc(*n);
        char tail;
        if (buf && (read(fd,buf,*n)!=(ssize_t)*n || read(fd,&tail,1)!=0)) { free(buf); buf=NULL; }
    }
    if (fd>=0) close(fd);
    return buf;
}

static int new_file(int dir,const char *name,const char *data,int history) {
    int fd=openat(dir,name,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
    if (fd<0) return -1;
    size_t n=strlen(data);
    int bad=write(fd,data,n)!=(ssize_t)n ||
            (history && fsetxattr(fd,FULL_PHASE2,"A",1,XATTR_CREATE)) || fsync(fd);
    if (close(fd)) bad=1;
    return bad ? -1 : 0;
}

static int private_dir(int at,const char *path) {
    int fd=openat(at,path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
    struct stat st;
    if (fd>=0 && !fstat(fd,&st) && st.st_uid==getuid() && st.st_mode==(S_IFDIR|0700)) return fd;
    if (fd>=0) close(fd);
    return -1;
}

/* The receipt is a prepared witness, never a standalone success record.
 * Confirm joins it to the durable publication and the current active inode. */
static int confirm(int parent,int work,const char *prefix,const char *tx) {
    char record[256],canonical[256],g[33],b[65];
    int fd=openat(work,"receipt",O_RDONLY|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC);
    struct stat st;
    if (fd<0) return -1;
    ssize_t n=-1;
    if (!fstat(fd,&st) && st.st_mode==(S_IFREG|0600) && st.st_uid==getuid() && st.st_nlink==1)
        n=read(fd,record,sizeof(record)-1);
    close(fd);
    if (n<=0 || n>=(ssize_t)sizeof(record)-1) return -1;
    record[n]=0;
    if (sscanf(record,"%32s %64s",g,b)!=2 || !hex(g,32) || !hex(b,64)) return -1;
    int len=snprintf(canonical,sizeof(canonical),"%s %s %s %s\n",g,b,tx,prefix);
    if (len!=n || memcmp(canonical,record,(size_t)n) || fsync(work) || fsync(parent) ||
        full_first_check(prefix,prefix,g,b)) return -1;
    return printf("{\"state\":\"installed\",\"generation\":\"%s\",\"binding\":\"%s\",\"tx\":\"%s\"}\n",g,b,tx)<0 ||
           fflush(stdout) ? -1 : 0;
}

static int prepare(int parent,int work,const char *stage,const char *prefix,const char *base,
                   const char *tx,char **args) {
    /* args: absolute .s2p, archive SHA, trusted public key, approved host SHA */
    char g[33],b[65],sha[65],keysha[65],type[320],typehash[65],start[48],record[256],blob[64];
    struct sigv_key key;
    size_t n=0;
    unsigned char *bytes=input(args[2],8192,&n,1), random[16];
    int bad=!bytes || pm_binding_sha(bytes,n,keysha) || sigv_parse_key((char *)bytes,n,&key);
    free(bytes);
    if (bad || getrandom(random,sizeof(random),0)!=sizeof(random)) return -1;
    for (unsigned i=0;i<sizeof(random);i++) snprintf(g+2*i,3,"%02x",random[i]);
    bytes=input(args[0],16u<<20,&n,0);
    if (!bytes) return -1;
    int mem=(int)syscall(SYS_memfd_create,"full-s2p",MFD_CLOEXEC|MFD_ALLOW_SEALING);
    bad=mem<0 || pm_binding_sha(bytes,n,sha) || strcmp(sha,args[1]) ||
        write(mem,bytes,n)!=(ssize_t)n || fcntl(mem,F_ADD_SEALS,F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL);
    free(bytes);
    int dir=-1,rc=-1;
    if (bad || mkdirat(work,"new",0700) || (dir=private_dir(work,"new"))<0) goto out;
    snprintf(blob,sizeof(blob),"/proc/self/fd/%d",mem);
    char *tree=pm_path(stage,"tree");
    struct full_package pkg={0};
    struct pm_err err={0};
    /* The stock error formatter consults keys/revoked on unknown key.
     * Scope that diagnostic to the new private domain too. */
    bad=setenv("STEER_PLUGIN_KEYS",stage,1) || pm_full_unpack(blob,tree,&key,&pkg,&err);
    free(tree);
    if (bad) {
        fprintf(stderr,"supd-full: проверка архива: %s %s\n",err.code,err.msg);
        goto out;
    }
    snprintf(type,sizeof(type),FULL_TYPE2 "\n%s\n%s\n%s\n%s\n",prefix,g,sha,keysha);
    snprintf(start,sizeof(start),"start %s\n",g);
    if (mkdirat(dir,".lock",0700) || new_file(dir,"owner.lock","",0) || new_file(dir,"child.lock","",0) ||
        new_file(dir,"type",type,0) || new_file(dir,"history",start,1) ||
        pm_binding_sha(type,strlen(type),typehash) || full_seal_new(stage,&pkg,args[3],typehash,b) ||
        fsync(dir)) goto out;
    snprintf(record,sizeof(record),"%s %s %s %s\n",g,b,tx,prefix);
    if (new_file(work,"receipt",record,0) || fsync(work) || fsync(parent) ||
        full_first_check(stage,prefix,g,b) ||
        syscall(SYS_renameat2,work,"new",parent,base,RENAME_NOREPLACE)) goto out;
    rc=confirm(parent,work,prefix,tx);
out:
    if (mem>=0) close(mem);
    if (dir>=0) close(dir);
    return rc;
}

int pm_first_main(const char *prefix,int argc,char **argv) {
    int first=argc==6 && !strcmp(argv[0],"install-first");
    if ((!first && !(argc==2 && !strcmp(argv[0],"confirm-first"))) || !hex(argv[1],32) ||
        (first && (!hex(argv[3],64) || !hex(argv[5],64)))) return 2;
    char parentpath[81],real[PATH_MAX],attempt[48];
    const char *slash=strrchr(prefix,'/');
    if (!full_first_capable()) { fputs("supd-full: unsupported build\n",stderr); return 1; }
    if (!getuid() || getuid()!=geteuid() || getgid()!=getegid() ||
        strlen(prefix)>80 || strncmp(prefix,"/tmp/e4-lab-",12) || !slash || slash<=prefix+12 ||
        strchr(prefix+12,'/')!=slash || strpbrk(prefix," \t\r\n") || !slash[1] ||
        strspn(slash+1,"abcdefghijklmnopqrstuvwxyz0123456789-")!=strlen(slash+1)) return 1;
    memcpy(parentpath,prefix,(size_t)(slash-prefix));
    parentpath[slash-prefix]=0;
    if (!realpath(parentpath,real) || strcmp(real,parentpath)) return 1;
    int parent=private_dir(AT_FDCWD,parentpath),work=-1,rc=1;
    if (parent<0 || flock(parent,LOCK_EX|LOCK_NB)) goto out;
    snprintf(attempt,sizeof(attempt),".first-%s",argv[1]);
    struct stat st;
    static const char *const reserved[]={"installed","etc","type","history",".lock"};
    for (size_t i=0;i<sizeof(reserved)/sizeof(*reserved);i++) {
        if (!strcmp(slash+1,reserved[i]) || !fstatat(parent,reserved[i],&st,AT_SYMLINK_NOFOLLOW) ||
            errno!=ENOENT) goto out;
    }
    umask(022);
    if (first && (!fstatat(parent,slash+1,&st,AT_SYMLINK_NOFOLLOW) || errno!=ENOENT ||
        mkdirat(parent,attempt,0700))) goto out;
    work=private_dir(parent,attempt);
    if (work<0) goto out;
    if (first) {
        char *stage=pm_fmt("%s/%s/new",parentpath,attempt);
        rc=prepare(parent,work,stage,prefix,slash+1,argv[1],argv+2)!=0;
        free(stage);
    } else rc=confirm(parent,work,prefix,argv[1])!=0;
out:
    if (work>=0) close(work);
    if (parent>=0) close(parent);
    if (rc) fputs("supd-full: первичная установка не подтверждена\n",stderr);
    return rc;
}
