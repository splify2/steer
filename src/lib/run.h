#ifndef STEER_RUN_H
#define STEER_RUN_H
#include <stdint.h>

/* Запуск внешней команды с выброшенным выводом (src/lib/run.c). Объявление одно на всё
 * дерево: раньше его копировал extern-строкой в свою шапку каждый файл, который зовёт
 * run_quiet (failover.c, obfs.c, awg.c, xsclient.c, xshub.c, subfetch.c, tunnel.c — восемь
 * копий одной и той же строки), и это ровно тот вид повтора, который ничего не проверяет:
 * поменяйся сигнатура в run.c, каждая копия продолжила бы молча компилироваться со старой. */

int run(const char *const argv[]);
int run_quiet(const char *const argv[]);
/* Same deadline/process-group semantics as run. Stdout goes to caller-owned
 * fd (caller bounds/validates result); stderr remains suppressed. */
int run_output(const char *const argv[], int output_fd);
/* Bounded capture with the caller's absolute CLOCK_MONOTONIC deadline. */
int run_output_until(const char *const argv[],int output_fd,uint64_t deadline_ns,uint64_t max_bytes);

#endif
