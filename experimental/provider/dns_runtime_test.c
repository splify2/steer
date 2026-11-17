#include "dns_runtime.h"
#include "loop.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>
static int64_t clock_offset;
int64_t __real_loop_now_ms(void);
int64_t __wrap_loop_now_ms(void){return __real_loop_now_ms()+clock_offset;}
struct fixture {struct loop *loop;struct loop_timer *timer;steer_dns_exchange_done done;void *arg;uint8_t packet[4096];size_t size;unsigned callbacks,cancels;uint32_t expected;int late;struct steer_dns_runtime *runtime;};
static void deliver(struct loop *l,struct loop_timer *t,void *arg){struct fixture *f=arg;(void)l;(void)t;if(f->late)clock_offset=2000;f->done(f->arg,f->cancels?STEER_PV1_CANCELLED:0,f->packet,f->size);}
static uint32_t start(void *arg,uint32_t binding,const uint8_t *p,size_t n,uint64_t deadline,steer_dns_exchange_done done,void *ctx,void **op){struct fixture *f=arg;assert(binding==7&&deadline);memcpy(f->packet,p,n);f->size=n;f->packet[2]=0x81;f->packet[3]=0x80;f->done=done;f->arg=ctx;*op=f;loop_timer_set(f->timer,0);return 0;}
static void cancel(void *arg,void *op){struct fixture *f=arg;assert(op==f);f->cancels++;loop_timer_set(f->timer,0);}
static void done(void *arg,uint32_t code,const uint8_t *p,size_t n,const struct steer_dns_answer *a){struct fixture *f=arg;assert(code==f->expected);assert(steer_dns_runtime_destroy(f->runtime)==STEER_PV1_POLICY_DENIED);if(!code)assert(p&&n&&a&&!a->count);else assert(!p&&!n&&!a);f->callbacks++;loop_stop(f->loop,0);}
int main(void){struct fixture f={0};struct steer_dns_exchange e={&f,start,cancel};struct steer_dns_job *job,*other;uint8_t q[4096],reply[4096];size_t n,rn;struct steer_dns_question question;struct steer_dns_answer answer;
    assert(!steer_dns_query("Example.COM",1,123,q,sizeof(q),&n));assert(!steer_dns_question_read(q,n,&question));assert(!strcmp(question.name,"example.com"));assert(!steer_dns_empty(q,n,reply,sizeof(reply),&rn));assert(!steer_dns_answer_read(reply,rn,&question,1,&answer));reply[0]^=1;assert(steer_dns_answer_read(reply,rn,&question,1,&answer));
    /* Compression cycles and truncated RR bodies cannot enter cache/runtime. */
    q[12]=0xc0;q[13]=12;assert(steer_dns_question_read(q,n,&question));assert(!steer_dns_query("example.com",1,123,q,sizeof(q),&n));
    f.loop=loop_new();assert(f.loop);f.timer=loop_timer_new(f.loop,deliver,&f);assert(f.timer);assert(!steer_dns_runtime_create(f.loop,1,&e,&f.runtime));
    assert(!steer_dns_submit(f.runtime,7,q,n,((uint64_t)loop_now_ms()+1000)*1000000,1,done,&f,&job));assert(!f.callbacks);assert(steer_dns_submit(f.runtime,7,q,n,((uint64_t)loop_now_ms()+1000)*1000000,1,done,&f,&other)==STEER_PV1_RESOURCE_EXHAUSTED);assert(!other);assert(!loop_run(f.loop));assert(f.callbacks==1&&!steer_dns_runtime_jobs(f.runtime));
    assert(!steer_dns_runtime_destroy(f.runtime));loop_timer_free(f.timer);loop_free(f.loop);
    f.loop=loop_new();assert(f.loop);f.timer=loop_timer_new(f.loop,deliver,&f);assert(f.timer);assert(!steer_dns_runtime_create(f.loop,1,&e,&f.runtime));
    f.expected=STEER_PV1_CANCELLED;assert(!steer_dns_submit(f.runtime,7,q,n,((uint64_t)loop_now_ms()+1000)*1000000,1,done,&f,&job));steer_dns_quiesce(f.runtime);assert(f.callbacks==1);assert(steer_dns_runtime_destroy(f.runtime)==STEER_PV1_POLICY_DENIED);assert(!loop_run(f.loop));assert(f.callbacks==2&&f.cancels==1);assert(!steer_dns_runtime_destroy(f.runtime));loop_timer_free(f.timer);loop_free(f.loop);
    f.loop=loop_new();assert(f.loop);f.timer=loop_timer_new(f.loop,deliver,&f);assert(f.timer);assert(!steer_dns_runtime_create(f.loop,1,&e,&f.runtime));f.cancels=0;f.late=1;f.expected=STEER_PV1_TIMEOUT;
    assert(!steer_dns_submit(f.runtime,7,q,n,((uint64_t)loop_now_ms()+1000)*1000000,1,done,&f,&job));assert(!loop_run(f.loop));assert(f.callbacks==3&&!f.cancels);assert(!steer_dns_runtime_destroy(f.runtime));loop_timer_free(f.timer);loop_free(f.loop);puts("dns runtime: ok");return 0;
}
