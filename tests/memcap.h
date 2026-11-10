/* Пик памяти и время разбора враждебного входа — для стендов, которые проверяют, что маленький
 * файл не раздувается в гигабайты (подписка hysteria2 «[}», пины сертификатов, дерево .srs).
 *
 * Проверка идёт в дочернем процессе: если правка сломана, раздувание не должно уронить сам стенд
 * или машину сборки. Ребёнку ставится потолок адресного пространства (RLIMIT_AS) — он упирается
 * в отказ malloc, а не в OOM-killer, — и срок (alarm). Под ASan потолок не ставится: теневая
 * память санитайзера резервирует терабайты адресов, и любой RLIMIT_AS валит его на старте;
 * остаётся срок.
 *
 * memcap_run возвращает прирост пикового RSS ребёнка над RSS родителя в КиБ (wait4 даёт пик
 * ребёнка, а страницы родителя ребёнок наследует), или -1, если ребёнок не вернул 0: упал, убит
 * сроком или fn сказала «не то». */
#ifndef STEER_TESTS_MEMCAP_H
#define STEER_TESTS_MEMCAP_H

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__SANITIZE_ADDRESS__)
#define MEMCAP_ASAN 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define MEMCAP_ASAN 1
#endif
#endif

/* Текущие RSS и размер адресного пространства процесса в КиБ (/proc/self/statm, в страницах). */
static inline void memcap_self(long *rss_kb, long *vm_kb) {
    long vm = 0, rss = 0;
    FILE *f = fopen("/proc/self/statm", "r");
    if (f) { if (fscanf(f, "%ld %ld", &vm, &rss) != 2) vm = rss = 0; fclose(f); }
    long pk = sysconf(_SC_PAGESIZE) / 1024;
    if (rss_kb) *rss_kb = rss * pk;
    if (vm_kb) *vm_kb = vm * pk;
}

static inline long memcap_run(int (*fn)(void *), void *arg, long cap_mb, int sec) {
    long rss0 = 0, vm0 = 0;
    memcap_self(&rss0, &vm0);
    fflush(NULL);
    pid_t pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
#ifndef MEMCAP_ASAN
        struct rlimit rl = { .rlim_cur = (rlim_t)(vm0 + cap_mb * 1024) * 1024,
                             .rlim_max = (rlim_t)(vm0 + cap_mb * 1024) * 1024 };
        setrlimit(RLIMIT_AS, &rl);
#else
        (void)cap_mb;
#endif
        alarm((unsigned)sec);
        _exit(fn(arg) == 0 ? 0 : 3);
    }
    int st = 0;
    struct rusage ru;
    if (wait4(pid, &st, 0, &ru) != pid) return -1;
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) return -1;
    long d = ru.ru_maxrss - rss0;
    return d < 0 ? 0 : d;
}

#endif
