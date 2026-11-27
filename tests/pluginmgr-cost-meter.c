/* Linux-only test wrapper. Manager stdout/stderr pass through untouched. */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/statvfs.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static pid_t manager;
static atomic_int done;
static long long disk_peak, rss_sum_peak, samples, max_gap;
static long long ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)) abort();
    return (long long)t.tv_sec*1000000000+t.tv_nsec;
}
static long long used(void) {
    struct statvfs v;
    if (statvfs("/run/volume",&v)) abort();
    return (v.f_blocks-v.f_bfree)*(long long)v.f_frsize;
}
static long long rss(pid_t pid) {
    char path[100];
    long pages = 0, child;
    snprintf(path,sizeof path,"/proc/%d/statm",pid);
    FILE *f = fopen(path,"r");
    if (!f) return 0;
    if (fscanf(f,"%*d %ld",&pages) != 1) pages = 0;
    fclose(f);
    long long total = pages*(sysconf(_SC_PAGESIZE)/1024);
    snprintf(path,sizeof path,"/proc/%d/task/%d/children",pid,pid);
    f = fopen(path,"r");
    if (f) {
        while (fscanf(f,"%ld",&child) == 1) total += rss((pid_t)child);
        fclose(f);
    }
    return total;
}
static void *monitor(void *unused) {
    (void)unused;
    long long last = ns();
    do {
        long long now = ns(), d = used(), r = rss(manager);
        if (d > disk_peak) disk_peak = d;
        if (r > rss_sum_peak) rss_sum_peak = r;
        if (now-last > max_gap) max_gap = now-last;
        last = now;
        samples++;
        nanosleep(&(struct timespec){0,250000},NULL);
    } while (!atomic_load(&done));
    return NULL;
}
static void pin(int cpu) {
    cpu_set_t mask;
    CPU_ZERO(&mask); CPU_SET(cpu,&mask);
    if (sched_setaffinity(0,sizeof mask,&mask)) abort();
}
int main(int argc,char **argv) {
    if (argc < 3) return 2; /* metrics file, executable, arguments */
    pin(0);
    int gate[2];
    if (pipe(gate)) abort();
    manager = fork();
    if (manager < 0) abort();
    if (!manager) {
        close(gate[1]); pin(1);
        char b;
        if (read(gate[0],&b,1) != 1) _exit(126);
        close(gate[0]); execv(argv[2],argv+2); _exit(127);
    }
    close(gate[0]);
    long long start_bytes = disk_peak = used();
    pthread_t watcher;
    if (pthread_create(&watcher,NULL,monitor,NULL)) abort();
    long long start = ns();
    if (write(gate[1],"x",1) != 1) abort();
    close(gate[1]);
    siginfo_t si;
    while (waitid(P_PID,manager,&si,WEXITED|WNOWAIT)) if (errno != EINTR) abort();
    long long elapsed = ns()-start;
    atomic_store(&done,1);
    pthread_join(watcher,NULL);
    long long rd = -1, wr = -1;
    char path[100];
    snprintf(path,sizeof path,"/proc/%d/io",manager);
    FILE *f = fopen(path,"r");
    if (f) {
        if (fscanf(f,"rchar: %lld\nwchar: %lld",&rd,&wr) != 2) abort();
        fclose(f);
    }
    struct rusage ru; int status;
    if (wait4(manager,&status,0,&ru) != manager) abort();
    long long end = used();
    if (end > disk_peak) disk_peak = end;
    f = fopen(argv[1],"w");
    if (!f) abort();
    fprintf(f,"{\"us\":%lld,\"rss_kib\":%ld,\"tree_kib\":%lld,\"before\":%lld,\"peak\":%lld,"
            "\"after\":%lld,\"rchar\":%lld,\"wchar\":%lld,\"samples\":%lld,\"gap_us\":%lld}\n",
            elapsed/1000,ru.ru_maxrss,rss_sum_peak,start_bytes,disk_peak,end,rd,wr,samples,max_gap/1000);
    if (fclose(f)) abort();
    return WIFEXITED(status) ? WEXITSTATUS(status) : 128+WTERMSIG(status);
}
