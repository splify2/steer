#define _GNU_SOURCE
#include "loop.h"
#include <assert.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/wait.h>
#include <unistd.h>
struct state {int fd, calls, completed, bad;struct loop_timer *neighbor,*rescheduled;};
static void spinning(struct loop *l,struct loop_timer *timer,void *arg) {
    (void)l;struct state *s=arg;s->calls++;
    if(s->calls==1){uint64_t one=1;assert(write(s->fd,&one,sizeof(one))==sizeof(one));}
    loop_timer_set(timer,0);
}
static void readable(struct loop *l,int fd,uint32_t events,void *arg) {
    (void)events;struct state *s=arg;uint64_t value;
    assert(read(fd,&value,sizeof(value))==sizeof(value));
    assert(s->calls>0&&s->calls<=64);loop_stop(l,0);
}
static void stopping(struct loop *l,struct loop_timer *timer,void *arg) {
    struct state *s=arg;s->calls++;loop_timer_set(timer,0);loop_stop(l,19);
}
static void forbidden(struct loop *l,struct loop_timer *timer,void *arg) {
    (void)l;(void)timer;((struct state *)arg)->bad++;
}
static void completed(struct loop *l,struct loop_timer *timer,void *arg) {
    struct state *s=arg;s->completed++;loop_timer_free(timer);
    if(s->completed==2)loop_stop(l,0);
}
static void mutating(struct loop *l,struct loop_timer *timer,void *arg) {
    struct state *s=arg;
    loop_timer_free(s->neighbor);s->neighbor=NULL;
    loop_timer_stop(s->rescheduled);loop_timer_set(s->rescheduled,0);
    struct loop_timer *created=loop_timer_new(l,completed,s);assert(created);loop_timer_set(created,0);
    loop_timer_free(timer);
}
static void bulk_timer(struct loop *l,struct loop_timer *timer,void *arg) {
    struct state *s=arg;s->calls++;loop_timer_free(timer);
    if(s->calls==1){uint64_t one=1;assert(write(s->fd,&one,sizeof(one))==sizeof(one));}
    if(s->calls==130&&s->completed)loop_stop(l,0);
}
static void bulk_readable(struct loop *l,int fd,uint32_t events,void *arg) {
    (void)events;struct state *s=arg;uint64_t value;
    assert(read(fd,&value,sizeof(value))==sizeof(value));
    assert(s->calls>0&&s->calls<=128);s->completed=1;
    if(s->calls==130)loop_stop(l,0);
}
static void run_case(int which) {
    alarm(2);
    struct loop *loop=loop_new();assert(loop);
    struct state s={.fd=-1};
    if(which==0){
        s.fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(s.fd>=0);
        assert(!loop_fd_add(loop,s.fd,EPOLLIN,readable,&s));
        struct loop_timer *timer=loop_timer_new(loop,spinning,&s);assert(timer);loop_timer_set(timer,0);
        assert(loop_run(loop)==0);loop_fd_del(loop,s.fd);close(s.fd);
    }else if(which==1){
        struct loop_timer *timer=loop_timer_new(loop,stopping,&s);assert(timer);loop_timer_set(timer,0);
        assert(loop_run(loop)==19&&s.calls==1);
    }else if(which==2){
        s.neighbor=loop_timer_new(loop,forbidden,&s);
        s.rescheduled=loop_timer_new(loop,completed,&s);
        struct loop_timer *first=loop_timer_new(loop,mutating,&s);
        assert(s.neighbor&&s.rescheduled&&first);
        loop_timer_set(first,0);loop_timer_set(s.neighbor,0);loop_timer_set(s.rescheduled,0);
        assert(loop_run(loop)==0&&s.completed==2&&!s.bad);
    }else{
        s.fd=eventfd(0,EFD_NONBLOCK|EFD_CLOEXEC);assert(s.fd>=0);
        assert(!loop_fd_add(loop,s.fd,EPOLLIN,bulk_readable,&s));
        for(int i=0;i<130;i++){
            struct loop_timer *timer=loop_timer_new(loop,bulk_timer,&s);assert(timer);loop_timer_set(timer,0);
        }
        assert(loop_run(loop)==0&&s.calls==130&&s.completed);
        loop_fd_del(loop,s.fd);close(s.fd);
    }
    loop_free(loop);alarm(0);
}
int main(void) {
    const char *names[]={"ready fd survives zero-delay timer chain","stop is honored inside rearming timer","timer callbacks safely delete/rearm/create neighbors","large due batch yields and remaining timers complete"};
    int failures=0;
    for(int i=0;i<4;i++){
        fflush(NULL);
        pid_t child=fork();assert(child>=0);
        if(!child){run_case(i);exit(0);}
        int status;assert(waitpid(child,&status,0)==child);
        int ok=WIFEXITED(status)&&WEXITSTATUS(status)==0;
        printf("%s %s\n",ok?"PASS":"FAIL",names[i]);failures+=!ok;
    }
    return failures?1:0;
}
