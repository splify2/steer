#define _GNU_SOURCE
#include "execution_journal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef RENAME_NOREPLACE
#define RENAME_NOREPLACE 1u
#endif
struct transaction_count {uint64_t id;uint32_t count;};
struct steer_spec_journal {int directory,lock,scanning;uint32_t maximum,per_transaction;};
static struct steer_pv1_error error(uint32_t c){return (struct steer_pv1_error){c,0};}
static int private_file(int fd){struct stat s;return !fstat(fd,&s)&&S_ISREG(s.st_mode)&&s.st_uid==geteuid()&&!(s.st_mode&0077)&&s.st_nlink==1;}
static int key_valid(const struct steer_spec_journal_key *k){return k&&k->transaction&&k->instance&&k->sequence&&k->kind>=1&&k->kind<=5;}
static int text_valid(const char *s,size_t maximum){size_t n=strnlen(s,maximum);if(!n||n==maximum)return 0;for(size_t i=0;i<n;i++)if((unsigned char)s[i]<33||(unsigned char)s[i]>126)return 0;return 1;}
static int record_valid(const struct steer_spec_journal_record *r){
 if(!key_valid(&r->key)||!r->generation||!text_valid(r->provider,sizeof(r->provider))||!text_valid(r->provider_version,sizeof(r->provider_version))||r->length>STEER_SPEC_JOURNAL_DATA_MAX)return 0;
 if(r->key.kind==STEER_SPEC_JOURNAL_ANCHOR)return !r->anchor_transaction&&!r->anchor_sequence&&r->credits&&r->credits<=4096&&r->cleanup_floor>=2&&r->cleanup_floor<=r->credits&&r->grant_id&&!r->operation&&!r->intent_sequence&&!r->phase&&!r->effect;
 if(r->key.kind==STEER_SPEC_JOURNAL_GRANT)return r->anchor_transaction&&r->anchor_sequence&&r->credits&&r->credits<=4096&&!r->cleanup_floor&&r->grant_id&&!r->operation&&!r->intent_sequence&&!r->phase&&!r->effect;
 return r->operation>=1&&r->operation<=4&&r->effect<=2&&r->phase>=1&&r->phase<=5&&!r->credits&&!r->cleanup_floor&&!r->grant_id&&
  ((!r->anchor_transaction&&!r->anchor_sequence)||(r->anchor_transaction&&r->anchor_sequence))&&
  (r->key.kind==STEER_SPEC_JOURNAL_INTENT?!r->intent_sequence:r->intent_sequence&&r->intent_sequence<r->key.sequence);
}
static void filename(const struct steer_spec_journal_key *k,char out[80]){snprintf(out,80,"r-%016" PRIx64 "-%016" PRIx64 "-%08" PRIx32 "-%u",k->transaction,k->instance,k->sequence,k->kind);}
static uint32_t crc(const unsigned char *p,size_t n){uint32_t c=~0u;while(n--){c^=*p++;for(unsigned b=0;b<8;b++)c=(c>>1)^(0xedb88320u&(uint32_t)-(int32_t)(c&1));}return ~c;}
static void put32(unsigned char **p,uint32_t n){for(unsigned i=0;i<4;i++){*(*p)++=(unsigned char)n;n>>=8;}}
static void put64(unsigned char **p,uint64_t n){for(unsigned i=0;i<8;i++){*(*p)++=(unsigned char)n;n>>=8;}}
static uint32_t get32(const unsigned char **p){uint32_t n=0;for(unsigned i=0;i<4;i++)n|=(uint32_t)*(*p)++<<(8*i);return n;}
static uint64_t get64(const unsigned char **p){uint64_t n=0;for(unsigned i=0;i<8;i++)n|=(uint64_t)*(*p)++<<(8*i);return n;}
static size_t encode(const struct steer_spec_journal_record *r,unsigned char bytes[8192]){
 unsigned char *p=bytes;memcpy(p,"STJRNL2",8);p+=8;
 put64(&p,r->key.transaction);put64(&p,r->key.instance);put32(&p,r->key.sequence);put32(&p,r->key.kind);put64(&p,r->generation);
 put32(&p,r->intent_sequence);put32(&p,r->operation);put32(&p,r->effect);put32(&p,r->phase);
 put64(&p,r->anchor_transaction);put64(&p,r->grant_id);put32(&p,r->anchor_sequence);put32(&p,r->credits);put32(&p,r->cleanup_floor);
 uint32_t pn=(uint32_t)strlen(r->provider),vn=(uint32_t)strlen(r->provider_version);
 put32(&p,pn);put32(&p,vn);put32(&p,r->length);memcpy(p,r->plan_digest,32);p+=32;
 memcpy(p,r->provider,pn);p+=pn;memcpy(p,r->provider_version,vn);p+=vn;memcpy(p,r->data,r->length);p+=r->length;
 uint32_t checksum=crc(bytes,(size_t)(p-bytes));put32(&p,checksum);return (size_t)(p-bytes);
}
static int decode(const unsigned char *bytes,size_t size,struct steer_spec_journal_record *r){
 if(size<132||memcmp(bytes,"STJRNL2",8))return -1;
 const unsigned char *last=bytes+size-4;if(get32(&last)!=crc(bytes,size-4))return -1;
 const unsigned char *p=bytes+8;memset(r,0,sizeof(*r));r->key.transaction=get64(&p);r->key.instance=get64(&p);r->key.sequence=get32(&p);r->key.kind=get32(&p);r->generation=get64(&p);
 r->intent_sequence=get32(&p);r->operation=get32(&p);r->effect=get32(&p);r->phase=get32(&p);
 r->anchor_transaction=get64(&p);r->grant_id=get64(&p);r->anchor_sequence=get32(&p);r->credits=get32(&p);r->cleanup_floor=get32(&p);
 uint32_t pn=get32(&p),vn=get32(&p);r->length=get32(&p);
 if(pn>=sizeof(r->provider)||vn>=sizeof(r->provider_version)||r->length>sizeof(r->data)||size!=132u+pn+vn+r->length)return -1;
 memcpy(r->plan_digest,p,32);p+=32;memcpy(r->provider,p,pn);p+=pn;memcpy(r->provider_version,p,vn);p+=vn;memcpy(r->data,p,r->length);
 if(memchr(r->provider,0,pn)||memchr(r->provider_version,0,vn)||!record_valid(r))return -1;
 return 0;
}
struct steer_pv1_error steer_spec_journal_open(const char *path,uint32_t maximum,uint32_t per_transaction,struct steer_spec_journal **out){
 if(out)*out=NULL;
 if(!path||!*path||!out||!maximum||maximum>4096||!per_transaction||per_transaction>128||per_transaction>maximum)return error(STEER_PV1_INVALID);
 struct steer_spec_journal *j=calloc(1,sizeof(*j));if(!j)return error(STEER_PV1_RESOURCE_EXHAUSTED);j->directory=j->lock=-1;j->maximum=maximum;j->per_transaction=per_transaction;
 j->directory=open(path,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);if(j->directory<0)goto io;
 struct stat s;if(fstat(j->directory,&s)||!S_ISDIR(s.st_mode)||s.st_uid!=geteuid()||(s.st_mode&0077))goto invalid;
 j->lock=openat(j->directory,".writer.lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);if(j->lock<0)goto io;
 if(!private_file(j->lock))goto invalid;
 if(flock(j->lock,LOCK_EX|LOCK_NB))goto io;
 *out=j;return error(0);
invalid:
 if(j->lock>=0)close(j->lock);
 if(j->directory>=0)close(j->directory);
 free(j);return error(STEER_PV1_INVALID);
io:
 if(j->lock>=0)close(j->lock);
 if(j->directory>=0)close(j->directory);
 free(j);return error(STEER_PV1_IO);
}
struct steer_pv1_error steer_spec_journal_close(struct steer_spec_journal *j){if(!j)return error(STEER_PV1_INVALID);if(j->scanning)return error(STEER_PV1_POLICY_DENIED);close(j->lock);close(j->directory);free(j);return error(0);}
struct steer_pv1_error steer_spec_journal_read(struct steer_spec_journal *j,const struct steer_spec_journal_key *key,struct steer_spec_journal_record *out){
 if(!j||!out||!key_valid(key))return error(STEER_PV1_INVALID);
 char name[80];filename(key,name);int fd=openat(j->directory,name,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW);if(fd<0)return error(errno==ENOENT?STEER_PV1_UNSUPPORTED:STEER_PV1_IO);
 if(!private_file(fd)){close(fd);return error(STEER_PV1_INVALID);}
 unsigned char bytes[8192];size_t have=0;int bad=0;
 for(;;){ssize_t n=read(fd,bytes+have,sizeof(bytes)-have);if(n<0&&errno==EINTR)continue;if(n<0){bad=1;break;}if(!n)break;have+=(size_t)n;if(have==sizeof(bytes)){bad=1;break;}}
 close(fd);if(bad)return error(STEER_PV1_IO);
 if(decode(bytes,have,out)||out->key.transaction!=key->transaction||out->key.instance!=key->instance||out->key.sequence!=key->sequence||out->key.kind!=key->kind){memset(out,0,sizeof(*out));return error(STEER_PV1_INVALID);}return error(0);
}
static int parse_name(const char *name,struct steer_spec_journal_key *key){
 int end=0;unsigned kind;
 if(strlen(name)!=46||sscanf(name,"r-%16" SCNx64 "-%16" SCNx64 "-%8" SCNx32 "-%u%n",&key->transaction,&key->instance,&key->sequence,&kind,&end)!=4||end!=46)return -1;
 key->kind=kind;char canonical[80];filename(key,canonical);return !key_valid(key)||strcmp(name,canonical)?-1:0;
}
struct steer_pv1_error steer_spec_journal_scan(struct steer_spec_journal *j,struct steer_pv1_error (*visit)(void *,const struct steer_spec_journal_record *),void *context,struct steer_spec_journal_scan_report *report){
 if(report)memset(report,0,sizeof(*report));
 if(!j||!visit)return error(STEER_PV1_INVALID);
 if(j->scanning)return error(STEER_PV1_POLICY_DENIED);
 int fd=openat(j->directory,".",O_RDONLY|O_DIRECTORY|O_CLOEXEC);if(fd<0)return error(STEER_PV1_IO);
 DIR *directory=fdopendir(fd);if(!directory){close(fd);return error(STEER_PV1_IO);}
 struct transaction_count *workspace=calloc(j->maximum,sizeof(*workspace));if(!workspace){closedir(directory);return error(STEER_PV1_RESOURCE_EXHAUSTED);}
 struct steer_pv1_error result=error(0);uint32_t count=0,orphans=0,transactions=0;j->scanning=1;
 for(;;){
  errno=0;struct dirent *entry=readdir(directory);if(!entry){if(errno)result=error(STEER_PV1_IO);break;}
  if(!strcmp(entry->d_name,".")||!strcmp(entry->d_name,"..")||!strcmp(entry->d_name,".writer.lock"))continue;
  if(++count>j->maximum){result=error(STEER_PV1_RESOURCE_EXHAUSTED);break;}
  if(!strncmp(entry->d_name,".tmp-",5)){
   int valid=strlen(entry->d_name)==21;for(size_t i=5;valid&&i<21;i++)if(!((entry->d_name[i]>='0'&&entry->d_name[i]<='9')||(entry->d_name[i]>='a'&&entry->d_name[i]<='f')))valid=0;
   int temporary=valid?openat(j->directory,entry->d_name,O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOFOLLOW):-1;struct stat st;
   if(temporary<0){result=error(STEER_PV1_INVALID);break;}
   valid=private_file(temporary)&&!fstat(temporary,&st)&&st.st_size>=0&&st.st_size<=8192;close(temporary);
   if(!valid){result=error(STEER_PV1_INVALID);break;}
   orphans++;continue;
  }
  struct steer_spec_journal_key key;if(parse_name(entry->d_name,&key)){result=error(STEER_PV1_INVALID);break;}
  uint32_t index=0;while(index<transactions&&workspace[index].id!=key.transaction)index++;
  if(index==transactions)workspace[transactions++].id=key.transaction;
  if(++workspace[index].count>j->per_transaction){result=error(STEER_PV1_RESOURCE_EXHAUSTED);break;}
  struct steer_spec_journal_record record;result=steer_spec_journal_read(j,&key,&record);if(result.code)break;
  if((record.key.kind==STEER_SPEC_JOURNAL_OUTCOME||record.key.kind==STEER_SPEC_JOURNAL_RECONCILE)){
   struct steer_spec_journal_key intent_key={record.key.transaction,record.key.instance,record.intent_sequence,STEER_SPEC_JOURNAL_INTENT};struct steer_spec_journal_record intent;
   result=steer_spec_journal_read(j,&intent_key,&intent);if(result.code)break;
   if(intent.generation!=record.generation||intent.operation!=record.operation||strcmp(intent.provider,record.provider)||strcmp(intent.provider_version,record.provider_version)||memcmp(intent.plan_digest,record.plan_digest,32)){result=error(STEER_PV1_INVALID);break;}
  }
  result=visit(context,&record);if(result.code||result.transient)break;
 }
 j->scanning=0;closedir(directory);free(workspace);if(!result.code&&report){report->records=count-orphans;report->orphan_temporaries=orphans;}return result;
}
struct count_context {const struct steer_spec_journal_record *candidate;uint64_t transaction;uint32_t total,transaction_count;};
static struct steer_pv1_error count_record(void *arg,const struct steer_spec_journal_record *r){
 struct count_context *c=arg;c->total++;if(r->key.transaction==c->transaction)c->transaction_count++;
 const struct steer_spec_journal_record *n=c->candidate;
 if(n->key.kind==STEER_SPEC_JOURNAL_OUTCOME&&r->key.kind==STEER_SPEC_JOURNAL_OUTCOME&&r->key.transaction==n->key.transaction&&r->key.instance==n->key.instance&&r->intent_sequence==n->intent_sequence)return error(STEER_PV1_POLICY_DENIED);
 return error(0);
}
static int write_all(int fd,const unsigned char *bytes,size_t length){while(length){ssize_t n=write(fd,bytes,length);if(n<0&&errno==EINTR)continue;if(n<=0)return -1;bytes+=n;length-=(size_t)n;}return 0;}
struct steer_spec_journal_result steer_spec_journal_append(struct steer_spec_journal *j,const struct steer_spec_journal_record *r){
 struct steer_spec_journal_result result={error(STEER_PV1_INVALID),STEER_SPEC_JOURNAL_NOT_RENAMED};
 if(!j||!r||!record_valid(r))return result;
 if(j->scanning){result.error=error(STEER_PV1_POLICY_DENIED);return result;}
 struct stat status;if(fstat(j->directory,&status)||status.st_uid!=geteuid()||(status.st_mode&0077))return result;
 struct count_context counts={r,r->key.transaction,0,0};struct steer_spec_journal_scan_report report;result.error=steer_spec_journal_scan(j,count_record,&counts,&report);if(result.error.code)return result;
 if(counts.total+report.orphan_temporaries>=j->maximum||counts.transaction_count>=j->per_transaction){result.error=error(STEER_PV1_RESOURCE_EXHAUSTED);return result;}
 if((r->key.kind==STEER_SPEC_JOURNAL_OUTCOME||r->key.kind==STEER_SPEC_JOURNAL_RECONCILE)){
  struct steer_spec_journal_key intent_key={r->key.transaction,r->key.instance,r->intent_sequence,STEER_SPEC_JOURNAL_INTENT};struct steer_spec_journal_record intent;
  result.error=steer_spec_journal_read(j,&intent_key,&intent);if(result.error.code)return result;
  if(intent.generation!=r->generation||intent.operation!=r->operation||strcmp(intent.provider,r->provider)||strcmp(intent.provider_version,r->provider_version)||memcmp(intent.plan_digest,r->plan_digest,32)){result.error=error(STEER_PV1_INVALID);return result;}
 }
 unsigned char bytes[8192];size_t length=encode(r,bytes);char name[80],temporary[48];filename(&r->key,name);
 int fd=-1;for(unsigned i=0;i<8;i++){
  uint64_t random;ssize_t n;do n=getrandom(&random,sizeof(random),0);while(n<0&&errno==EINTR);
  if(n!=(ssize_t)sizeof(random)){result.error=error(STEER_PV1_IO);return result;}
  snprintf(temporary,sizeof(temporary),".tmp-%016" PRIx64,random);fd=openat(j->directory,temporary,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
  if(fd>=0)break;
  if(errno!=EEXIST){result.error=error(STEER_PV1_IO);return result;}
 }
 if(fd<0){result.error=error(STEER_PV1_RESOURCE_EXHAUSTED);return result;}
 int failed=write_all(fd,bytes,length)||fsync(fd);if(close(fd))failed=1;
 if(failed){unlinkat(j->directory,temporary,0);result.error=error(STEER_PV1_IO);return result;}
 int renamed;
#ifdef SYS_renameat2
 renamed=(int)syscall(SYS_renameat2,j->directory,temporary,j->directory,name,RENAME_NOREPLACE);
#else
 errno=ENOSYS;renamed=-1;
#endif
 if(renamed){int saved=errno;unlinkat(j->directory,temporary,0);result.error=error(saved==ENOSYS||saved==EINVAL?STEER_PV1_UNSUPPORTED:saved==EEXIST?STEER_PV1_POLICY_DENIED:STEER_PV1_IO);return result;}
 result.durability=STEER_SPEC_JOURNAL_RENAMED;
 if(fsync(j->directory)){result.error=error(STEER_PV1_IO);return result;}
 result.durability=STEER_SPEC_JOURNAL_SYNCED;result.error=error(0);return result;
}

int steer_spec_journal_record_valid(const struct steer_spec_journal_record *r){return r&&record_valid(r);}

struct steer_pv1_error steer_spec_journal_sync_existing(struct steer_spec_journal *j){if(!j)return error(STEER_PV1_INVALID);if(j->scanning)return error(STEER_PV1_POLICY_DENIED);struct stat s;if(fstat(j->directory,&s)||s.st_uid!=geteuid()||(s.st_mode&0077))return error(STEER_PV1_INVALID);return error(fsync(j->directory)?STEER_PV1_IO:0);}
