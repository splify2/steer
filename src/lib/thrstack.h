/* Размер стека потока: сколько нужно самому потоку плюс статическая TLS, если её берут из стека.
 *
 * ЗАЧЕМ. glibc кладёт статическую TLS всех загруженных модулей (у libsteer.so — thread-local буферы,
 * 558 КБ на 2.0.4) в тот же блок, что и стек, и потоку с pthread_attr_setstacksize меньше этой суммы
 * отказывает: pthread_create → EINVAL. Так молча не запускались слежка за узлами пула (512 КБ, pool.c)
 * и слежка hysteria2 (512 КБ) — на стендах хоста, где glibc, а не на роутере: «поток слежки за узлами
 * не создался (Invalid argument)» в каждом прогоне run-tunnel. Размер TLS растёт вместе с кодом
 * (под 300 КБ, когда ставили запас у установщиков, — 558 КБ теперь), поэтому число здесь не
 * угадывается, а считается по заголовкам загруженных модулей (PT_TLS).
 *
 * musl и bionic отводят TLS сверх запрошенного стека сами — там добавлять нечего, и стек остаётся
 * ровно тем, что просили (на роутере виртуальная память тоже не бесплатна). */
#ifndef STEER_THRSTACK_H
#define STEER_THRSTACK_H
#include <stddef.h>

#ifdef __GLIBC__
#include <link.h>

static int thr_tls_add(struct dl_phdr_info *info, size_t size, void *arg) {
    (void)size;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_TLS)
            *(size_t *)arg += info->dlpi_phdr[i].p_memsz + info->dlpi_phdr[i].p_align;
    return 0;
}
#endif

static inline size_t thread_stack(size_t need) {
#ifdef __GLIBC__
    size_t tls = 0;
    dl_iterate_phdr(thr_tls_add, &tls);
    return need + tls;
#else
    return need;
#endif
}

#endif
