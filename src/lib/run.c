#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <time.h>
#include <spawn.h>
#include <limits.h>
#include <paths.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "run.h"

/* One spawn authority; no post-fork application code in a multithreaded host. */
extern char **environ;
#define RUN_DEADLINE_MS 60000L
static uint64_t run_now_ns(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t)||t.tv_sec<0)return 0;return (uint64_t)t.tv_sec*1000000000ULL+(uint64_t)t.tv_nsec;}
static int run_expired(uint64_t deadline){uint64_t now=run_now_ns();if(!now){errno=EIO;return 1;}if(now>=deadline){errno=ETIMEDOUT;return 1;}return 0;}
static int run_spawn_at(const char *file,const char *const argv[],int output_fd,pid_t *child,int search){
    posix_spawnattr_t attr;posix_spawn_file_actions_t actions;int rc,have_attr=0,have_actions=0;sigset_t defaults;
    if(!argv||!argv[0]||!file){errno=EINVAL;return -1;}
    rc=posix_spawnattr_init(&attr);if(rc)goto out;have_attr=1;
    rc=posix_spawn_file_actions_init(&actions);if(rc)goto out;have_actions=1;
    sigemptyset(&defaults);sigaddset(&defaults,SIGPIPE);
    rc=posix_spawnattr_setsigdefault(&attr,&defaults);if(rc)goto out;
    rc=posix_spawnattr_setpgroup(&attr,0);if(rc)goto out;
    rc=posix_spawnattr_setflags(&attr,POSIX_SPAWN_SETPGROUP|POSIX_SPAWN_SETSIGDEF);if(rc)goto out;
    rc=output_fd>=0?posix_spawn_file_actions_adddup2(&actions,output_fd,STDOUT_FILENO):posix_spawn_file_actions_addopen(&actions,STDOUT_FILENO,"/dev/null",O_WRONLY,0);if(rc)goto out;
    if(output_fd>STDERR_FILENO){rc=posix_spawn_file_actions_addclose(&actions,output_fd);if(rc)goto out;}
    rc=posix_spawn_file_actions_addopen(&actions,STDERR_FILENO,"/dev/null",O_WRONLY,0);if(rc)goto out;
    rc=search?posix_spawnp(child,file,&actions,&attr,(char *const *)argv,environ):posix_spawn(child,file,&actions,&attr,(char *const *)argv,environ);
 out:
    if(have_actions)posix_spawn_file_actions_destroy(&actions);
    if(have_attr)posix_spawnattr_destroy(&attr);
    if(rc){errno=rc;return -1;}return 0;
}
static int run_spawn(const char *const argv[],int fd,pid_t *child){if(!argv||!argv[0]){errno=EINVAL;return -1;}return run_spawn_at(argv[0],argv,fd,child,1);}
/* Caller owns child reaping. No global SIGCHLD disposition is changed. */
static int run_child_state(pid_t child,int *exited){
    siginfo_t status;memset(&status,0,sizeof status);
    if(waitid(P_PID,(id_t)child,&status,WEXITED|WNOHANG|WNOWAIT)<0)return errno==EINTR?0:-1;
    if(status.si_pid==child)*exited=1;return 0;
}
static int run_poll_ms(uint64_t deadline,int fallback){
    uint64_t now=run_now_ns();if(!now||now>=deadline)return 0;
    uint64_t ms=(deadline-now)/1000000ULL+((deadline-now)%1000000ULL!=0);
    if(fallback&&ms>20)ms=20;return ms>INT_MAX?INT_MAX:(int)ms;
}
static int run_forward(int fd,const unsigned char *p,size_t n,uint64_t deadline){
    while(n){if(run_expired(deadline))return -1;ssize_t wrote=write(fd,p,n);if(wrote<0){if(errno==EINTR)continue;return -1;}if(!wrote){errno=EIO;return -1;}p+=(size_t)wrote;n-=(size_t)wrote;}return 0;
}
static int run_wait(pid_t child,int capture_fd,int output_fd,uint64_t max_bytes,uint64_t deadline){
    int pfd=-1,exited=0,eof=capture_fd<0,result=-1;uint64_t total=0;unsigned char data[4096];
#ifdef SYS_pidfd_open
    pfd=(int)syscall(SYS_pidfd_open,child,0);
#endif
    for(;;){
        if(run_expired(deadline))break;
        if(!exited&&run_child_state(child,&exited)<0)break;
        if(exited&&eof){result=0;break;}
        if(!eof){ssize_t got=read(capture_fd,data,sizeof data);
            if(got>0){if((uint64_t)got>max_bytes-total){errno=EFBIG;break;}total+=(uint64_t)got;if(run_forward(output_fd,data,(size_t)got,deadline))break;continue;}
            if(!got){eof=1;continue;}
            if(errno==EINTR)continue;
            if(errno!=EAGAIN&&errno!=EWOULDBLOCK)break;
        }
        struct pollfd fds[2]={{eof?-1:capture_fd,POLLIN,0},{exited?-1:pfd,POLLIN,0}};
        int ready=poll(fds,2,run_poll_ms(deadline,pfd<0&&!exited));
        if(ready<0&&errno!=EINTR)break;
    }
    int saved=errno;if(pfd>=0)close(pfd);errno=saved;return result;
}
/* Do not reap other jobs. If host is a subreaper, also collect adopted children
 * in this job's process group. Kernel-uninterruptible exits remain unbounded. */
static int run_reap(pid_t child,int group,int terminate,int *status){
    if(terminate){(void)kill(-child,SIGKILL);(void)kill(child,SIGKILL);}
    int have=0;
    if(group){for(;;){int st;pid_t got=waitpid(-child,&st,0);if(got>0){if(got==child){*status=st;have=1;}continue;}if(got<0&&errno==EINTR)continue;break;}}
    if(!have){pid_t got;do{got=waitpid(child,status,0);}while(got<0&&errno==EINTR);if(got!=child)return -1;}
    return 0;
}
static uint64_t run_legacy_deadline(void){
    long limit=RUN_DEADLINE_MS;const char *value=getenv("STEER_RUN_DEADLINE_MS");
    if(value){char *end;errno=0;long parsed=strtol(value,&end,10);if(end!=value&&errno!=ERANGE&&parsed>0)limit=parsed;}
    uint64_t now=run_now_ns();if(!now)return 0;
    uint64_t delay=(uint64_t)limit>UINT64_MAX/1000000ULL?UINT64_MAX:(uint64_t)limit*1000000ULL;
    return delay>UINT64_MAX-now?UINT64_MAX:now+delay;
}
static int run_legacy_candidate(const char *path,const char *const argv[],int fd,pid_t *child){
    if(!run_spawn_at(path,argv,fd,child,0))return 0;
    if(errno!=ENOEXEC)return -1;
    size_t n=0;while(argv[n]){if(n>SIZE_MAX/sizeof(char *)-3){errno=E2BIG;return -1;}n++;}
    char **shell=malloc((n+2)*sizeof *shell);if(!shell)return -1;
    shell[0]=(char *)_PATH_BSHELL;shell[1]=(char *)path;for(size_t j=1;j<n;j++)shell[j+1]=(char *)argv[j];shell[n+1]=NULL;
    int rc=run_spawn_at(_PATH_BSHELL,(const char *const *)shell,fd,child,0),saved=errno;free(shell);errno=saved;return rc;
}
static int run_spawn_legacy(const char *const argv[],int fd,pid_t *child){
    if(!argv||!argv[0]){errno=EINVAL;return -1;}if(!argv[0][0]){errno=ENOENT;return -1;}
    if(strchr(argv[0],'/'))return run_legacy_candidate(argv[0],argv,fd,child);
    const char *path=getenv("PATH");char *default_path=NULL;
    if(!path){size_t n=confstr(_CS_PATH,NULL,0);if(!n){errno=ENOENT;return -1;}default_path=malloc(n);if(!default_path)return -1;if(confstr(_CS_PATH,default_path,n)!=n){free(default_path);errno=EIO;return -1;}path=default_path;}
    size_t path_n=strlen(path),file_n=strlen(argv[0]);if(path_n>SIZE_MAX-file_n-2){free(default_path);errno=ENAMETOOLONG;return -1;}
    char *candidate=malloc(path_n+file_n+2);if(!candidate){free(default_path);return -1;}
    int denied=0,rc=-1,saved=ENOENT;const char *part=path;
    for(;;){const char *end=strchr(part,':');size_t n=end?(size_t)(end-part):strlen(part);
        if(n){memcpy(candidate,part,n);candidate[n++]='/';}memcpy(candidate+n,argv[0],file_n+1);
        rc=run_legacy_candidate(candidate,argv,fd,child);saved=errno;if(!rc)break;
        if(saved==EACCES)denied=1;
        else if(saved!=ENOENT&&saved!=ENOTDIR&&saved!=ESTALE&&saved!=ENODEV&&saved!=ETIMEDOUT)break;
        if(!end){saved=denied?EACCES:ENOENT;break;}part=end+1;
    }
    free(candidate);free(default_path);errno=saved;return rc;
}
static int run_exec_error(void){return errno==ENOENT||errno==ENOEXEC||errno==EACCES||errno==ENOTDIR||errno==ELOOP||errno==ENAMETOOLONG||errno==ETXTBSY;}
static int run_with_output(const char *const argv[],int output_fd){
    uint64_t deadline=run_legacy_deadline();if(!deadline){errno=EIO;return -1;}if(run_expired(deadline))return -1;
    pid_t child;if(run_spawn_legacy(argv,output_fd,&child))return run_exec_error()?127:-1;
    int result=run_wait(child,-1,-1,0,deadline),saved=errno,status=0;
    if(result&&saved==ECHILD){errno=saved;return -1;}
    if(result&&saved==ETIMEDOUT)fprintf(stderr,"steer[warn] команда «%s» не ответила в срок — снята\n",argv[0]);
    if(run_reap(child,result!=0,result!=0,&status)){if(!result)saved=errno;result=-1;}
    if(!result&&run_expired(deadline)){saved=errno;result=-1;}
    if(result){errno=saved;return -1;}return WIFEXITED(status)?WEXITSTATUS(status):-1;
}
int run(const char *const argv[]){return run_with_output(argv,-1);}
int run_output(const char *const argv[],int output_fd){if(output_fd<0){errno=EINVAL;return -1;}return run_with_output(argv,output_fd);}
int run_quiet(const char *const argv[]){return run(argv);}
int run_output_until(const char *const argv[],int output_fd,uint64_t deadline,uint64_t max_bytes){
    if(!deadline){errno=EINVAL;return -1;}if(run_expired(deadline))return -1;
    struct stat st;int flags=fcntl(output_fd,F_GETFL);if(flags<0||fstat(output_fd,&st))return -1;
    if(!S_ISREG(st.st_mode)||(flags&O_ACCMODE)==O_RDONLY){errno=EINVAL;return -1;}
    if(lseek(output_fd,0,SEEK_CUR)<0)return -1;
    struct sigaction action;if(sigaction(SIGCHLD,NULL,&action))return -1;
    if(action.sa_handler!=SIG_DFL||(action.sa_flags&SA_NOCLDWAIT)){errno=EINVAL;return -1;}
    int pipefd[2];if(pipe2(pipefd,O_CLOEXEC))return -1;
    flags=fcntl(pipefd[0],F_GETFL);if(flags<0||fcntl(pipefd[0],F_SETFL,flags|O_NONBLOCK)<0){int saved=errno;close(pipefd[0]);close(pipefd[1]);errno=saved;return -1;}
    if(run_expired(deadline)){int saved=errno;close(pipefd[0]);close(pipefd[1]);errno=saved;return -1;}
    pid_t child;if(run_spawn(argv,pipefd[1],&child)){int saved=errno;close(pipefd[0]);close(pipefd[1]);errno=saved;return -1;}
    close(pipefd[1]);int result=run_wait(child,pipefd[0],output_fd,max_bytes,deadline),saved=errno,status=0;close(pipefd[0]);
    if(result&&saved==ECHILD){errno=saved;return -1;}
    /* The until path is for finite host tools, never background services. */
    if(run_reap(child,1,1,&status)){if(!result)saved=errno;result=-1;}
    if(!result&&run_expired(deadline)){saved=errno;result=-1;}
    if(result){errno=saved;return -1;}if(!WIFEXITED(status)){errno=EIO;return -1;}return WEXITSTATUS(status);
}
