#define _GNU_SOURCE
#include "execution_journal.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
static int fail_directory_sync,exit_before_rename;
int __real_fsync(int);
long __real_syscall(long,...);
int __wrap_fsync(int fd){struct stat s;assert(!fstat(fd,&s));if(fail_directory_sync&&S_ISDIR(s.st_mode)){fail_directory_sync=0;errno=EIO;return -1;}return __real_fsync(fd);}
long __wrap_syscall(long number,...){
 assert(number==SYS_renameat2);va_list args;va_start(args,number);int oldfd=va_arg(args,int);const char *old=va_arg(args,const char *);int newfd=va_arg(args,int);const char *name=va_arg(args,const char *);unsigned flags=va_arg(args,unsigned);va_end(args);
 if(exit_before_rename)_exit(0);
 return __real_syscall(number,oldfd,old,newfd,name,flags);
}
static struct steer_spec_journal_record record(uint64_t txn,uint64_t instance){
 struct steer_spec_journal_record r={.key={txn,instance,1,STEER_SPEC_JOURNAL_INTENT},.generation=7,.operation=1,.phase=1,.length=7};
 strcpy(r.provider,"fixture.kernel.device");strcpy(r.provider_version,"1");memcpy(r.plan_digest,"plan",4);memcpy(r.data,"opaque!",7);return r;
}
struct seen {struct steer_spec_journal *journal;struct steer_spec_journal_record records[8];unsigned count;};
static struct steer_pv1_error visit(void *arg,const struct steer_spec_journal_record *r){
 struct seen *s=arg;assert(s->count<8);s->records[s->count++]=*r;
 assert(steer_spec_journal_close(s->journal).code==STEER_PV1_POLICY_DENIED);
 assert(steer_spec_journal_append(s->journal,r).error.code==STEER_PV1_POLICY_DENIED);
 return (struct steer_pv1_error){0,0};
}
static void cleanup(const char *path){DIR *d=opendir(path);assert(d);struct dirent *e;int fd=dirfd(d);while((e=readdir(d)))if(strcmp(e->d_name,".")&&strcmp(e->d_name,".."))assert(!unlinkat(fd,e->d_name,0));closedir(d);assert(!rmdir(path));}
int main(void){
 alarm(20);char path[]="/tmp/steer-journal-test-XXXXXX";assert(mkdtemp(path));assert(!chmod(path,0700));struct steer_spec_journal *j=NULL,*other=NULL;
 assert(!steer_spec_journal_open(path,8,4,&j).code);assert(steer_spec_journal_open(path,8,4,&other).code==STEER_PV1_IO&&!other);
 struct steer_spec_journal_record first=record(1,10),copy;
 struct steer_spec_journal_result result=steer_spec_journal_append(j,&first);assert(!result.error.code&&result.durability==STEER_SPEC_JOURNAL_SYNCED);
 result=steer_spec_journal_append(j,&first);assert(result.error.code==STEER_PV1_POLICY_DENIED&&result.durability==STEER_SPEC_JOURNAL_NOT_RENAMED);
 assert(!steer_spec_journal_read(j,&first.key,&copy).code&&!memcmp(copy.data,"opaque!",7));
 struct steer_spec_journal_record second=record(1,11);assert(!steer_spec_journal_append(j,&second).error.code);
 struct steer_spec_journal_record outcome=first;outcome.key.kind=STEER_SPEC_JOURNAL_OUTCOME;outcome.key.sequence=2;outcome.intent_sequence=1;outcome.effect=2;outcome.phase=4;
 assert(!steer_spec_journal_append(j,&outcome).error.code);outcome.key.sequence=3;
 assert(steer_spec_journal_append(j,&outcome).error.code==STEER_PV1_POLICY_DENIED);
 outcome.key.kind=STEER_SPEC_JOURNAL_RECONCILE;outcome.effect=0;outcome.phase=5;assert(!steer_spec_journal_append(j,&outcome).error.code);
 outcome=second;outcome.key.kind=STEER_SPEC_JOURNAL_OUTCOME;outcome.key.sequence=2;outcome.intent_sequence=1;assert(steer_spec_journal_append(j,&outcome).error.code==STEER_PV1_RESOURCE_EXHAUSTED);
 struct steer_spec_journal_record uncertain=record(2,20);fail_directory_sync=1;result=steer_spec_journal_append(j,&uncertain);
 assert(result.error.code==STEER_PV1_IO&&result.durability==STEER_SPEC_JOURNAL_RENAMED&&!fail_directory_sync);
 assert(!steer_spec_journal_read(j,&uncertain.key,&copy).code&&copy.key.transaction==2);
 pid_t child=fork();assert(child>=0);if(!child){exit_before_rename=1;struct steer_spec_journal_record crash=record(3,30);steer_spec_journal_append(j,&crash);_exit(90);}
 int status;assert(waitpid(child,&status,0)==child&&WIFEXITED(status)&&WEXITSTATUS(status)==0);assert(!steer_spec_journal_close(j).code);
 assert(!steer_spec_journal_open(path,8,4,&j).code);struct seen s={.journal=j};struct steer_spec_journal_scan_report report;
 assert(!steer_spec_journal_scan(j,visit,&s,&report).code&&s.count==5&&report.records==5&&report.orphan_temporaries==1);
 unsigned unresolved=0;
 for(unsigned i=0;i<s.count;i++)if(s.records[i].key.kind==STEER_SPEC_JOURNAL_INTENT){
  unsigned retired=0;for(unsigned k=0;k<s.count;k++)if(s.records[k].key.transaction==s.records[i].key.transaction&&s.records[k].key.instance==s.records[i].key.instance&&s.records[k].intent_sequence==s.records[i].key.sequence&&s.records[k].phase==5)retired=1;
  if(!retired)unresolved++;
 }
 assert(unresolved==2); /* lost outcome => UNCERTAIN, not guessed QUIESCENT */
 assert(!steer_spec_journal_close(j).code);assert(!steer_spec_journal_open(path,6,4,&j).code);s.journal=j; /* five records + orphan */
 struct steer_spec_journal_record full=record(4,40);assert(steer_spec_journal_append(j,&full).error.code==STEER_PV1_RESOURCE_EXHAUSTED);
 char filename[256];snprintf(filename,sizeof(filename),"%s/foreign",path);int fd=open(filename,O_WRONLY|O_CREAT|O_EXCL,0600);assert(fd>=0);close(fd);s.count=0;
 assert(steer_spec_journal_scan(j,visit,&s,&report).code);assert(!unlink(filename));
 struct steer_spec_journal_key fifo={5,50,1,1};snprintf(filename,sizeof(filename),"%s/r-0000000000000005-0000000000000032-00000001-1",path);assert(!mkfifo(filename,0600));
 assert(steer_spec_journal_read(j,&fifo,&copy).code==STEER_PV1_INVALID);assert(!unlink(filename));
 snprintf(filename,sizeof(filename),"%s/r-0000000000000001-000000000000000a-00000001-1",path);fd=open(filename,O_WRONLY|O_TRUNC);assert(fd>=0&&write(fd,"bad",3)==3);close(fd);
 assert(steer_spec_journal_read(j,&first.key,&copy).code==STEER_PV1_INVALID);s.count=0;assert(steer_spec_journal_scan(j,visit,&s,&report).code==STEER_PV1_INVALID);
 assert(!steer_spec_journal_close(j).code);assert(!chmod(path,0755));assert(steer_spec_journal_open(path,8,4,&j).code==STEER_PV1_INVALID&&!j);assert(!chmod(path,0700));cleanup(path);
 assert(steer_spec_journal_open("/tmp/steer-journal-no-such-directory",8,4,&j).code==STEER_PV1_IO&&!j);
 puts("execution-journal: immutable multi-instance records/restart/lost-result/rename-uncertainty/crash-temp/FIFO/bounds/corruption PASS");return 0;
}
