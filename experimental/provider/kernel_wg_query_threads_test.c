#define _GNU_SOURCE
#include "awgdev.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
static pthread_barrier_t barrier;
static int isolated;
struct worker {unsigned id;dev_t device;ino_t inode;};
static void *run(void *user){
 struct worker *w=user;struct stat namespace;
 if(isolated)assert(!unshare(CLONE_NEWNET));
 assert(!stat("/proc/thread-self/ns/net",&namespace));w->device=namespace.st_dev;w->inode=namespace.st_ino;
 pthread_barrier_wait(&barrier);
 for(unsigned i=0;i<200;i++){
  char kind[32];int index=0;
  int missing=(i+w->id)%2;
  int result=awg_dev_link_query(missing?"steerAbsent0":"lo",kind,sizeof kind,&index);
  if(missing)assert(result==ENODEV);else assert(!result&&index==1&&!kind[0]);
 }
 return NULL;
}
int main(int argc,char **argv){
 isolated=argc==2&&!strcmp(argv[1],"--isolated-owners");alarm(15);
 pthread_t threads[4];struct worker workers[4]={0};assert(!pthread_barrier_init(&barrier,NULL,4));
 for(unsigned i=0;i<4;i++){workers[i].id=i;assert(!pthread_create(&threads[i],NULL,run,&workers[i]));}
 for(unsigned i=0;i<4;i++)assert(!pthread_join(threads[i],NULL));
 if(isolated)for(unsigned i=0;i<4;i++)for(unsigned j=0;j<i;j++)assert(workers[i].device!=workers[j].device||workers[i].inode!=workers[j].inode);
 assert(!pthread_barrier_destroy(&barrier));alarm(0);
 puts("netlink query: four concurrent owners, mixed existing/absent replies PASS");return 0;
}
