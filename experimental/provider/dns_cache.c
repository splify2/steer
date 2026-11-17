#include "dns_cache.h"
#include <stdlib.h>
#include <string.h>
#define RECORD 618u
#define HEADER 20u
struct entry {struct steer_dns_cache_key key;struct steer_dns_answer answer;uint64_t expires,used;};
struct steer_dns_cache {uint32_t max;uint64_t serial;struct entry entries[];};
static void put32(uint8_t *p,uint32_t x){p[0]=(uint8_t)(x>>24);p[1]=(uint8_t)(x>>16);p[2]=(uint8_t)(x>>8);p[3]=(uint8_t)x;}
static uint32_t get32(const uint8_t *p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static void put64(uint8_t *p,uint64_t x){put32(p,(uint32_t)(x>>32));put32(p+4,(uint32_t)x);}
static uint64_t get64(const uint8_t *p){return ((uint64_t)get32(p)<<32)|get32(p+4);}
static int keyvalid(const struct steer_dns_cache_key *k){uint8_t packet[4096];size_t n;struct steer_dns_question q;return k&&memchr(k->name,0,sizeof(k->name))&&(k->type==1||k->type==28)&&!steer_dns_query(k->name,k->type,0,packet,sizeof(packet),&n)&&!steer_dns_question_read(packet,n,&q)&&!strcmp(q.name,k->name);}
static int same(const struct steer_dns_cache_key *a,const struct steer_dns_cache_key *b){return a->type==b->type&&!memcmp(a->identity,b->identity,32)&&!strcmp(a->name,b->name);}
struct steer_dns_cache *steer_dns_cache_create(uint32_t max){struct steer_dns_cache *c;if(!max||max>1024)return NULL;c=calloc(1,sizeof(*c)+(size_t)max*sizeof(c->entries[0]));if(c)c->max=max;return c;}
void steer_dns_cache_free(struct steer_dns_cache *c){free(c);}
int steer_dns_cache_put(struct steer_dns_cache *c,const struct steer_dns_cache_key *k,const struct steer_dns_answer *a,uint64_t now){uint32_t i,slot=0,ttl;if(!c||!keyvalid(k)||!a||a->rcode||!a->count||a->count>16||!a->ttl)return -1;ttl=a->ttl>86400?86400:a->ttl;
    for(i=0;i<a->count;i++){if(a->addresses[i].family!=(k->type==1?4:6)||!a->addresses[i].ttl)return -1;if(a->addresses[i].ttl<ttl)ttl=a->addresses[i].ttl;}
    if(now>UINT64_MAX-(uint64_t)ttl*1000)return -1;
    for(i=0;i<c->max;i++)if(same(&c->entries[i].key,k)){slot=i;break;}
    if(i==c->max)for(i=0;i<c->max;i++){if(c->entries[i].expires<=now){slot=i;break;}if(c->entries[i].used<c->entries[slot].used)slot=i;}
    c->entries[slot].key=*k;c->entries[slot].answer=*a;c->entries[slot].expires=now+(uint64_t)ttl*1000;c->entries[slot].used=++c->serial;return 0;
}
int steer_dns_cache_get(struct steer_dns_cache *c,const struct steer_dns_cache_key *k,uint64_t now,struct steer_dns_answer *out){uint32_t i,j;if(!c||!keyvalid(k)||!out)return 0;for(i=0;i<c->max;i++)if(c->entries[i].expires>now&&same(&c->entries[i].key,k)){*out=c->entries[i].answer;out->ttl=(uint32_t)((c->entries[i].expires-now)/1000);if(!out->ttl)return 0;for(j=0;j<out->count;j++)out->addresses[j].ttl=out->ttl;c->entries[i].used=++c->serial;return 1;}return 0;}
int steer_dns_cache_reverse(struct steer_dns_cache *c,const uint8_t identity[32],uint8_t family,const uint8_t *ip,uint64_t now,char name[254]){uint32_t i,j;if(!c||!identity||!ip||!name||(family!=4&&family!=6))return 0;for(i=0;i<c->max;i++)if(c->entries[i].expires>now&&!memcmp(identity,c->entries[i].key.identity,32))for(j=0;j<c->entries[i].answer.count;j++)if(c->entries[i].answer.addresses[j].family==family&&!memcmp(ip,c->entries[i].answer.addresses[j].bytes,family==4?4:16)){strcpy(name,c->entries[i].key.name);return 1;}return 0;}
size_t steer_dns_cache_snapshot_max(const struct steer_dns_cache *c){return c?HEADER+(size_t)c->max*RECORD:0;}
int steer_dns_cache_export(const struct steer_dns_cache *c,uint64_t mono,uint64_t wall,uint8_t *p,size_t cap,size_t *out){uint32_t i,j,count=0;size_t at=HEADER;if(out)*out=0;if(!c||!p||!out||cap<HEADER)return -1;memset(p,0,HEADER);memcpy(p,"SDNS",4);put32(p+4,1);put64(p+8,wall);
    for(i=0;i<c->max;i++){const struct entry *e=&c->entries[i];uint64_t seconds;if(e->expires<=mono||(seconds=(e->expires-mono)/1000)==0)continue;if(cap-at<RECORD)return -1;memset(p+at,0,RECORD);memcpy(p+at,e->key.identity,32);memcpy(p+at+32,e->key.name,strlen(e->key.name));p[at+286]=(uint8_t)e->key.type;put32(p+at+287,(uint32_t)seconds);p[at+291]=(uint8_t)e->answer.count;for(j=0;j<e->answer.count;j++){p[at+292+j*20]=e->answer.addresses[j].family;memcpy(p+at+293+j*20,e->answer.addresses[j].bytes,16);}at+=RECORD;count++;}put32(p+16,count);*out=at;return 0;
}
int steer_dns_cache_import(struct steer_dns_cache *c,const uint8_t identity[32],uint64_t mono,uint64_t wall,const uint8_t *p,size_t n){struct steer_dns_cache *temp;uint32_t count,i,j;uint64_t saved,age;if(!c||!identity||!p||n<HEADER||memcmp(p,"SDNS",4)||get32(p+4)!=1)return -1;saved=get64(p+8);if(wall<saved)return -1;age=wall-saved;count=get32(p+16);if(count>c->max||n!=HEADER+(size_t)count*RECORD)return -1;temp=steer_dns_cache_create(c->max);if(!temp)return -1;
    for(i=0;i<count;i++){size_t at=HEADER+(size_t)i*RECORD;struct steer_dns_cache_key key;struct steer_dns_answer a={0};uint32_t ttl=get32(p+at+287);memcpy(key.identity,p+at,32);memcpy(key.name,p+at+32,254);key.type=p[at+286];a.count=p[at+291];if(!keyvalid(&key)||!a.count||a.count>16||!ttl||ttl>86400)goto invalid;
        for(j=0;j<a.count;j++){a.addresses[j].family=p[at+292+j*20];memcpy(a.addresses[j].bytes,p+at+293+j*20,16);if(a.addresses[j].family!=(key.type==1?4:6))goto invalid;}
        if(memcmp(identity,key.identity,32)||age>=ttl)continue;
        a.ttl=ttl-(uint32_t)age;for(j=0;j<a.count;j++)a.addresses[j].ttl=a.ttl;if(steer_dns_cache_put(temp,&key,&a,mono))goto invalid;
    }memcpy(c->entries,temp->entries,(size_t)c->max*sizeof(c->entries[0]));c->serial=temp->serial;steer_dns_cache_free(temp);return 0;
invalid:steer_dns_cache_free(temp);return -1;
}
