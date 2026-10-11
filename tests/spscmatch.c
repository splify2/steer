/* Кольцо «один производитель — один потребитель» (src/tunnel/spsc.h): порядок, содержимое, потеря
 * при переполнении и побудка спящего потребителя.
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. Кольцо — единственное место, где читатель TUN и рабочий поток стека
 * делят память без замка (R-146). Ошибка здесь не падает: пакет, прочитанный раньше, чем записан,
 * или потерянная побудка выглядят снаружи как «иногда тормозит» и «иногда соединение зависло».
 * Поэтому каждое свойство проверяется отдельно и по числам:
 *   - порядок и целость: потребитель видит пакеты в порядке записи, а байты каждого совпадают с
 *     тем, что положил производитель (длина и содержимое выводятся из номера, чужую запись не
 *     спутать);
 *   - переполнение: производитель не блокируется, отброшенное считается, и «принято + отброшено =
 *     отправлено» сходится ровно, без дыр и повторов;
 *   - выход через границу 2^32: счётчики голова/хвост бегут по кругу без остановки, и место, где они
 *     переходят через ноль, — классическое место ошибки в разности без знака;
 *   - ожидание места: производитель на полном кольце спит до побудки потребителя (spsc_room) или до
 *     срока, ничего не теряя (t_prodwait);
 *   - побудка: потребитель спит по протоколу (spsc_sleep_begin, poll по eventfd), производитель
 *     будит спящего и никого более. Потерянная побудка — это poll, вернувшийся по таймауту при
 *     непустом кольце; допускается ноль таких случаев.
 *
 * Стенд собирается дважды: обычно и под -fsanitize=thread (цель spscmatch-tsan в Makefile), и второй
 * раз проверяет не результат, а ПРАВИЛА ПАМЯТИ: тот же код без единого предупреждения о гонке —
 * значит, release/acquire и seq_cst расставлены так, как заявлено в шапке spsc.h.
 *
 * Ни сети, ни прав: входит в обычный make test. */
#define _GNU_SOURCE
#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "../src/tunnel/spsc.h"
#include "unit.h"

#define CAP 120u          /* данные слота; с заголовком слот в 128 байт */

/* Содержимое пакета номер i: длина и байты выводятся из номера. */
static uint32_t len_of(uint64_t i) { return 4 + (uint32_t)((i * 2654435761u) % (CAP - 3)); }
static void fill(unsigned char *p, uint64_t i) {
    uint32_t n = len_of(i);
    uint32_t id = (uint32_t)i;
    memcpy(p, &id, 4);
    for (uint32_t k = 4; k < n; k++) p[k] = (unsigned char)(i * 31 + k);
}
static int verify(const unsigned char *p, uint32_t n, uint64_t i) {
    if (n != len_of(i)) return 0;
    uint32_t id;
    memcpy(&id, p, 4);
    if (id != (uint32_t)i) return 0;
    for (uint32_t k = 4; k < n; k++)
        if (p[k] != (unsigned char)(i * 31 + k)) return 0;
    return 1;
}

/* ---- один поток: границы ---- */
static void t_single(void) {
    struct spsc r;
    check("число слотов не степень двойки — отказ", -1, spsc_init(&r, 6, CAP));
    check("слот один — отказ", -1, spsc_init(&r, 1, CAP));
    check("инициализация на 8 слотов", 0, spsc_init(&r, 8, CAP));

    uint32_t n = 0;
    check("пустое кольцо: peek даёт NULL", 1, spsc_peek(&r, &n) == NULL);
    check("пустое кольцо: pending ложь", 0, spsc_pending(&r));

    int took = 0;
    for (int i = 0; i < 20; i++) {
        unsigned char *s = spsc_reserve(&r);
        if (!s) break;
        fill(s, (uint64_t)i);
        spsc_commit(&r, len_of((uint64_t)i));
        took++;
    }
    check("кольцо на 8 слотов принимает ровно 8", 8, took);
    check("девятый слот не выдаётся", 1, spsc_reserve(&r) == NULL);

    int ok = 1;
    for (int i = 0; i < 8; i++) {
        const unsigned char *p = spsc_peek(&r, &n);
        if (!p || !verify(p, n, (uint64_t)i)) ok = 0;
        spsc_pop(&r);
    }
    check("все 8 прочитаны по порядку и без искажений", 1, ok);
    check("после чтения пусто", 1, spsc_peek(&r, &n) == NULL);

    /* Пробег через 2^32: ставим счётчики перед самым переходом и гоняем кольцо. Разность без
     * знака обязана остаться верной, а заполненность — считаться правильно. */
    r.head = r.tail = r.tail_seen = r.head_seen = 0xFFFFFFFEu;
    ok = 1;
    uint64_t seq = 0, want = 0;
    for (int round = 0; round < 40; round++) {
        int put = 0;
        for (int k = 0; k < 8; k++) {
            unsigned char *s = spsc_reserve(&r);
            if (!s) break;
            fill(s, seq);
            spsc_commit(&r, len_of(seq));
            seq++;
            put++;
        }
        if (put != 8) ok = 0;
        if (spsc_reserve(&r) != NULL) ok = 0;
        for (int k = 0; k < put; k++) {
            const unsigned char *p = spsc_peek(&r, &n);
            if (!p || !verify(p, n, want)) ok = 0;
            want++;
            spsc_pop(&r);
        }
    }
    check("через границу 2^32 порядок и ёмкость верны (320 пакетов)", 1, ok);
    check("счётчики действительно перешли через ноль", 1, r.head < 0x1000u);
    spsc_free(&r);
}

/* ---- два потока, переполнение ---- */
struct ov {
    struct spsc r;
    uint64_t total;
    uint64_t sent, dropped;     /* пишет производитель */
    uint64_t got, bad, gaps;    /* пишет потребитель */
    int done;
};

static void *ov_prod(void *a) {
    struct ov *o = a;
    for (uint64_t i = 0; i < o->total; i++) {
        unsigned char *s = spsc_reserve(&o->r);
        if (!s) { o->dropped++; continue; }
        fill(s, i);
        spsc_commit(&o->r, len_of(i));
        o->sent++;
    }
    __atomic_store_n(&o->done, 1, __ATOMIC_RELEASE);
    return NULL;
}

static void *ov_cons(void *a) {
    struct ov *o = a;
    int64_t last = -1;
    for (;;) {
        uint32_t n;
        const unsigned char *p = spsc_peek(&o->r, &n);
        if (!p) {
            if (__atomic_load_n(&o->done, __ATOMIC_ACQUIRE) && !spsc_pending(&o->r)) break;
            continue;
        }
        uint32_t id;
        memcpy(&id, p, 4);
        /* Номера идут строго по возрастанию (пропуски — отброшенное при переполнении, а не
         * переставленное). */
        if ((int64_t)id <= last) o->bad++;
        else if ((int64_t)id != last + 1) o->gaps++;
        if (!verify(p, n, id)) o->bad++;
        last = id;
        spsc_pop(&o->r);
        o->got++;
        /* Потребитель нарочно медленнее производителя: без этого малое кольцо не переполнится. */
        if ((o->got & 0x1FF) == 0) { struct timespec ts = { 0, 20000 }; nanosleep(&ts, NULL); }
    }
    return NULL;
}

static void t_overflow(void) {
    static struct ov o;
    memset(&o, 0, sizeof(o));
    o.total = 600000;
    spsc_init(&o.r, 16, CAP);
    pthread_t a, b;
    pthread_create(&b, NULL, ov_cons, &o);
    pthread_create(&a, NULL, ov_prod, &o);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    check("переполнение: часть пакетов отброшена (кольцо в 16 слотов)", 1, o.dropped > 0);
    check("переполнение: принятое + отброшенное = отправленному", (long)o.total, (long)(o.got + o.dropped));
    check("переполнение: принято столько, сколько записано", (long)o.sent, (long)o.got);
    check("переполнение: порядок не нарушен, содержимое целое", 0, (long)o.bad);
    printf("     отправлено %llu, принято %llu, отброшено %llu (разрывов в нумерации %llu)\n",
           (unsigned long long)o.total, (unsigned long long)o.got, (unsigned long long)o.dropped,
           (unsigned long long)o.gaps);
    spsc_free(&o.r);
}

/* ---- побудка ---- */
struct wk {
    struct spsc r;
    uint64_t total;
    uint64_t got, bad;
    uint64_t begins, sleeps, lost;  /* потребитель: попыток уснуть, засыпаний, потерянных побудок */
    uint64_t wakes;             /* производитель: сколько раз пришлось будить */
};

static void *wk_prod(void *a) {
    struct wk *w = a;
    unsigned x = 12345;
    for (uint64_t i = 0; i < w->total; i++) {
        unsigned char *s;
        /* Ждать место здесь можно: это стенд побудки, потерь в нём быть не должно. */
        while (!(s = spsc_reserve(&w->r))) sched_yield();
        fill(s, i);
        w->wakes += (uint64_t)spsc_commit(&w->r, len_of(i));
        /* Пачки и паузы вперемешку: пауза даёт потребителю заснуть, пачка — гонку с засыпанием. */
        x = x * 1103515245u + 12345u;
        if ((x >> 16) % 50 == 0) { struct timespec ts = { 0, 200000 + (long)((x >> 8) % 300000) }; nanosleep(&ts, NULL); }
    }
    return NULL;
}

static void *wk_cons(void *a) {
    struct wk *w = a;
    uint64_t want = 0;
    while (want < w->total) {
        uint32_t n;
        const unsigned char *p;
        while ((p = spsc_peek(&w->r, &n)) != NULL) {
            if (!verify(p, n, want)) w->bad++;
            want++;
            spsc_pop(&w->r);
            w->got++;
        }
        if (want >= w->total) break;
        w->begins++;
        if (!spsc_sleep_begin(&w->r)) continue;     /* пакет успел прийти: не спим */
        w->sleeps++;
        struct pollfd pf = { .fd = w->r.efd, .events = POLLIN };
        /* Три секунды — «никогда» для стенда, где пакеты идут каждые доли миллисекунды. */
        int rc = poll(&pf, 1, 3000);
        spsc_sleep_end(&w->r);
        if (rc == 0 && spsc_pending(&w->r)) { w->lost++; }
        if (rc > 0) { uint64_t d; ssize_t rd = read(w->r.efd, &d, sizeof(d)); (void)rd; }
        if (rc == 0 && !spsc_pending(&w->r)) { w->lost += 1000; break; }  /* производитель встал — тоже провал */
    }
    return NULL;
}

static void t_wake(void) {
    static struct wk w;
    memset(&w, 0, sizeof(w));
    w.total = 200000;
    spsc_init(&w.r, 64, CAP);
    w.r.efd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    pthread_t a, b;
    pthread_create(&b, NULL, wk_cons, &w);
    pthread_create(&a, NULL, wk_prod, &w);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    check("побудка: принято всё", (long)w.total, (long)w.got);
    check("побудка: байты и порядок целы", 0, (long)w.bad);
    check("побудка: потерянных побудок нет", 0, (long)w.lost);
    /* Будят ТОЛЬКО объявившего сон: побудок не больше, чем попыток уснуть (попытка, отменённая
     * пришедшим пакетом, тоже могла быть замечена производителем). Побудка на каждый пакет была бы
     * системным вызовом на пакет — тем, от чего кольцо избавляет. */
    check("побудок не больше, чем попыток уснуть", 1, w.wakes <= w.begins);
    check("побудок заметно меньше пакетов (не на каждый)", 1, w.wakes < w.total / 4);
    printf("     пакетов %llu, засыпаний %llu, побудок %llu\n", (unsigned long long)w.total,
           (unsigned long long)w.sleeps, (unsigned long long)w.wakes);
    close(w.r.efd);
    spsc_free(&w.r);
}

/* ---- ожидание места: производитель спит на полном кольце (spsc_reserve_wait, spsc_room) ----
 *
 * Читатель TUN на полном кольце не бросает пакет, а ждёт место (R-146: без этого при двух рабочих
 * 830–1253 брошенных пакета на стенде run-tunnel-mt). Проверяется: (1) ожидание с побудкой не теряет
 * ни пакета и не уходит в срок, хотя потребитель разбирает порциями с паузами — побудка от spsc_room
 * доходит; (2) производитель спит, а не крутится — будит его потребитель, и побудок не больше, чем
 * порций; (3) зависший потребитель — срок соблюдается: NULL не раньше срока и без вечного сна. */
struct pw {
    struct spsc r;
    uint64_t total, got, bad, timeouts, waits;
};

static void *pw_prod(void *a) {
    struct pw *w = a;
    for (uint64_t i = 0; i < w->total; i++) {
        unsigned char *s = spsc_reserve(&w->r);
        if (!s) {
            w->waits++;
            /* Секунда — «никогда» для потребителя, разбирающего каждые доли миллисекунды. */
            s = spsc_reserve_wait(&w->r, 1000000000ull);
        }
        if (!s) { w->timeouts++; continue; }
        fill(s, i);
        spsc_commit(&w->r, len_of(i));
    }
    return NULL;
}

static void *pw_cons(void *a) {
    struct pw *w = a;
    uint64_t want = 0;
    unsigned x = 777;
    while (want < w->total - w->timeouts) {
        uint32_t n;
        const unsigned char *p;
        int k = 0;
        while (k < 8 && (p = spsc_peek(&w->r, &n)) != NULL) {
            if (!verify(p, n, want)) w->bad++;
            want++;
            spsc_pop(&w->r);
            w->got++;
            k++;
        }
        if (k) spsc_room(&w->r);
        /* Пауза после порции: производитель успевает заполнить кольцо и уснуть. */
        x = x * 1103515245u + 12345u;
        if ((x >> 16) % 4 == 0) { struct timespec ts = { 0, 50000 }; nanosleep(&ts, NULL); }
        if (!k) sched_yield();
    }
    return NULL;
}

static long ms_since(const struct timespec *t0) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (t.tv_sec - t0->tv_sec) * 1000L + (t.tv_nsec - t0->tv_nsec) / 1000000L;
}

static void t_prodwait(void) {
    static struct pw w;
    memset(&w, 0, sizeof(w));
    w.total = 100000;
    spsc_init(&w.r, 16, CAP);
    pthread_t a, b;
    pthread_create(&b, NULL, pw_cons, &w);
    pthread_create(&a, NULL, pw_prod, &w);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    check("ожидание места: принято всё", (long)w.total, (long)w.got);
    check("ожидание места: байты и порядок целы", 0, (long)w.bad);
    check("ожидание места: ни одного ухода в срок", 0, (long)w.timeouts);
    check("ожидание места: производитель ждал (кольцо заполнялось)", 1, w.waits > 0);
    printf("     пакетов %llu, ожиданий места %llu\n", (unsigned long long)w.total,
           (unsigned long long)w.waits);
    spsc_free(&w.r);

    /* Потребитель завис: кольцо полно, никто не разбирает — ждём срок и получаем NULL. */
    struct spsc r;
    spsc_init(&r, 4, CAP);
    for (int i = 0; i < 4; i++) { unsigned char *s = spsc_reserve(&r); fill(s, (uint64_t)i); spsc_commit(&r, len_of((uint64_t)i)); }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    unsigned char *s = spsc_reserve_wait(&r, 30000000ull);   /* 30 мс */
    long ms = ms_since(&t0);
    check("зависший потребитель: места нет — NULL", 1, s == NULL);
    check("зависший потребитель: срок выдержан (≥ 29 мс)", 1, ms >= 29);
    check("зависший потребитель: и не дольше (< 500 мс)", 1, ms < 500);
    check("после срока флаг ожидания снят", 0, (long)r.prod_waiting);
    spsc_free(&r);
}

int main(void) {
    t_single();
    t_overflow();
    t_wake();
    t_prodwait();
    return unit_done("spscmatch");
}
