#include "dns_runtime.h"
#include "loop.h"
#include <stdlib.h>
#include <string.h>
#include <limits.h>
struct steer_dns_job {
    struct steer_dns_runtime *runtime;struct loop_timer *timer;void *operation;
    struct steer_dns_question question;struct steer_dns_answer answer;
    steer_dns_done done;void *userdata;uint32_t state,code,cancelled;int ipv4;
    uint64_t deadline;size_t size;uint8_t packet[STEER_DNS_PACKET_MAX];
};
struct steer_dns_runtime {struct loop *loop;struct steer_dns_exchange exchange;uint32_t max,jobs,stopped,dispatching;struct steer_dns_job slots[];};
static void terminal(void *arg,uint32_t code,const uint8_t *packet,size_t size){
    struct steer_dns_job *j=arg;
    j->operation=NULL;j->code=j->cancelled?j->cancelled:code;j->size=0;
    if(!j->code){if(!packet||size>sizeof(j->packet)||steer_dns_answer_read(packet,size,&j->question,j->ipv4,&j->answer))j->code=STEER_PV1_IO;else {memcpy(j->packet,packet,size);j->size=size;}}
    j->state=2;loop_timer_set(j->timer,0);
}
static void timer(struct loop *l,struct loop_timer *t,void *arg){
    struct steer_dns_job *j=arg;struct steer_dns_runtime *r=j->runtime;(void)l;(void)t;
    if(j->state==1){uint64_t now=(uint64_t)loop_now_ms()*1000000;
        if(now<j->deadline){uint64_t diff=j->deadline-now,ms=diff/1000000+(diff%1000000!=0);loop_timer_set(j->timer,ms>(uint64_t)LONG_MAX?LONG_MAX:(long)ms);return;}
        j->cancelled=STEER_PV1_TIMEOUT;r->exchange.cancel(r->exchange.context,j->operation);return;}
    if(j->state==2){steer_dns_done done=j->done;void *ctx=j->userdata;uint32_t code=j->code;size_t size=j->size;
        if(!code&&(uint64_t)loop_now_ms()*1000000>=j->deadline){code=STEER_PV1_TIMEOUT;size=0;}
        /* Keep slot occupied across callback: reentrant admission cannot overwrite
         * borrowed response. Destroy is refused inside any terminal callback. */
        j->state=3;r->dispatching++;done(ctx,code,code?NULL:j->packet,size,code?NULL:&j->answer);r->dispatching--;j->state=0;j->done=NULL;j->userdata=NULL;r->jobs--;}
}
uint32_t steer_dns_runtime_create(struct loop *l,uint32_t max,const struct steer_dns_exchange *e,struct steer_dns_runtime **out){
    struct steer_dns_runtime *r;uint32_t i;if(out)*out=NULL;if(!out||!l||!e||!e->start||!e->cancel||!max||max>256)return STEER_PV1_INVALID;
    r=calloc(1,sizeof(*r)+(size_t)max*sizeof(r->slots[0]));if(!r)return STEER_PV1_RESOURCE_EXHAUSTED;r->loop=l;r->exchange=*e;r->max=max;
    for(i=0;i<max;i++){r->slots[i].runtime=r;r->slots[i].timer=loop_timer_new(l,timer,&r->slots[i]);if(!r->slots[i].timer){while(i)loop_timer_free(r->slots[--i].timer);free(r);return STEER_PV1_RESOURCE_EXHAUSTED;}}
    *out=r;return 0;
}
uint32_t steer_dns_submit(struct steer_dns_runtime *r,uint32_t binding,const uint8_t *p,size_t n,uint64_t deadline,int ipv4,steer_dns_done done,void *ctx,struct steer_dns_job **out){
    uint32_t i,code;uint64_t now=(uint64_t)loop_now_ms()*1000000,ms;struct steer_dns_question q;struct steer_dns_job *j;
    if(out)*out=NULL;
    if(!r||!out||!done||steer_dns_question_read(p,n,&q)||(p[2]&0xf8)||p[3]||p[6]||p[7]||p[8]||p[9])return STEER_PV1_INVALID;
    if(deadline<=now)return STEER_PV1_TIMEOUT;
    if(r->stopped)return STEER_PV1_CANCELLED;
    for(i=0;i<r->max;i++)if(!r->slots[i].state)break;
    if(i==r->max)return STEER_PV1_RESOURCE_EXHAUSTED;
    j=&r->slots[i];j->question=q;j->done=done;j->userdata=ctx;j->cancelled=0;j->ipv4=ipv4;j->state=1;j->size=0;j->deadline=deadline;
    if(ipv4&&q.type==28){
        if(steer_dns_empty(p,n,j->packet,sizeof(j->packet),&j->size)){j->state=0;return STEER_PV1_INVALID;}
        memset(&j->answer,0,sizeof(j->answer));j->code=0;j->state=2;r->jobs++;*out=j;loop_timer_set(j->timer,0);return 0;
    }
    code=r->exchange.start(r->exchange.context,binding,p,n,deadline,terminal,j,&j->operation);
    if(code){j->state=0;j->done=NULL;return code;}r->jobs++;*out=j;ms=(deadline-now)/1000000+((deadline-now)%1000000!=0);loop_timer_set(j->timer,ms>(uint64_t)LONG_MAX?LONG_MAX:(long)ms);return 0;
}
void steer_dns_cancel(struct steer_dns_job *j){if(!j||j->state!=1||j->cancelled)return;j->cancelled=STEER_PV1_CANCELLED;loop_timer_stop(j->timer);j->runtime->exchange.cancel(j->runtime->exchange.context,j->operation);}
void steer_dns_quiesce(struct steer_dns_runtime *r){uint32_t i;if(!r)return;r->stopped=1;for(i=0;i<r->max;i++)steer_dns_cancel(&r->slots[i]);}
uint32_t steer_dns_runtime_jobs(const struct steer_dns_runtime *r){return r?r->jobs:0;}
uint32_t steer_dns_runtime_destroy(struct steer_dns_runtime *r){uint32_t i;if(!r)return STEER_PV1_INVALID;if(r->jobs||r->dispatching)return STEER_PV1_POLICY_DENIED;for(i=0;i<r->max;i++)loop_timer_free(r->slots[i].timer);free(r);return 0;}
