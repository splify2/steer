/* Кольцо «один производитель — один потребитель» без замков: передача пакетов от потока,
 * читающего TUN, рабочему потоку стека (stack.c, R-146).
 *
 * ЗАЧЕМ ЭТО НУЖНО. Потоки стека держат соединение целиком — таблицу, шифр, сокет узла, запись
 * клиенту, — и общих изменяемых данных между ними нет. Чтобы ядра работали, пакеты клиента надо
 * доставить тому потоку, который владеет соединением. Раскладку по очередям устройства ядро
 * гарантировать не умеет (12 против 292 Мбит/с на роутере, см. stack.c), поэтому пакеты читает один
 * поток и раздаёт по хэшу соединения. Между читателем и рабочим — это кольцо: на пакет ни замка, ни
 * системного вызова, ни malloc, одна запись счётчика с release и одно чтение с acquire.
 *
 * КАК УСТРОЕНО.
 *  - Слоты фиксированного размера лежат одним блоком; пакет копируется в слот (до ~1500 байт — это
 *    дешевле, чем отдельный блок на пакет и счёт ссылок). Счётчики голова/хвост бегут по кругу
 *    без остановки, место берётся по маске: разность беззнаковых чисел верна и при переходе
 *    через ноль, а 32-битных атомиков хватает всем целям, включая mips (64-битных без libatomic
 *    там нет, поэтому их здесь нет).
 *  - Голова и хвост — на разных строках кэша: производитель и потребитель пишут каждый свою и
 *    только читают чужую, и «чужая» в кэше сменяется лишь когда ею воспользовались (производитель
 *    помнит последний виденный хвост и перечитывает его, только когда кольцо кажется полным;
 *    потребитель так же помнит голову).
 *  - Переполнение не блокирует производителя: spsc_reserve вернёт NULL, пакет отбрасывается со
 *    счётчиком у вызывающего. TCP повторит, UDP потеря не в новинку; ждать здесь значило бы
 *    остановить чтение TUN для ВСЕХ рабочих из-за одного медленного.
 *
 * ПОБУДКА. Спящий рабочий ждёт в epoll, и будить его на каждый пакет — системный вызов на
 * пакет, то есть ровно то, от чего кольцо избавляет. Поэтому будят только спящего, и это решает
 * флаг waiting по схеме Деккера:
 *    потребитель:   waiting = 1;  затем проверить кольцо — пусто, тогда спать;
 *    производитель: head = h + 1; затем прочитать waiting — 1, тогда обменять его на 0 и
 *                   записать в eventfd.
 * Обе пары операций — seq_cst, и это не перестраховка: при release/acquire оба могли бы не увидеть
 * записи друг друга (запись и чтение разных ячеек можно переставить), и рабочий уснул бы при
 * непустом кольце до следующего пакета. Отдельных заграждений (atomic_thread_fence) здесь нет
 * сознательно: sanitize=thread их не понимает, а упорядоченные операции он проверяет полностью.
 * Обмен waiting на 0 даёт ровно одну запись в eventfd на пробуждение, сколько бы пакетов ни
 * пришло, пока рабочий вставал.
 *
 * ОЖИДАНИЕ МЕСТА (spsc_reserve_wait, spsc_room). Полное кольцо — это рабочий, который отстал, и бросать
 * пакет сразу — значит отдать повтору TCP то, что рабочий разобрал бы через сотню микросекунд (стенд
 * run-tunnel-mt: при 2 рабочих без ожидания 830–1253 брошенных пакета и втрое дольше). Производитель
 * засыпает на самом хвосте (futex): ядро сравнит хвост с виденным и не даст уснуть, если тот уже ушёл.
 * Будить его потребитель обязан, только если тот спит, — флаг prod_waiting, та же схема Деккера, что
 * у waiting, но проверяется он раз в порцию разбора (spsc_room), а не на каждый пакет: пакет так и
 * стоит одного release. Сон ограничен сроком — потребитель, не освободивший места за срок, завис.
 *
 * Слоты — одно отображение (calloc): страницы, которых не коснулись, памяти не занимают. Но кольцо
 * ходит по кругу, и под нагрузкой тронутся все: см. SPSC_BYTES. */
#ifndef STEER_SPSC_H
#define STEER_SPSC_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <linux/futex.h>
#include <sys/syscall.h>

#define SPSC_LINE 64

struct spsc {
    /* Производитель: пишет head, читает tail. */
    _Alignas(SPSC_LINE) uint32_t head;
    uint32_t tail_seen;           /* хвост, каким его видел производитель; только он его трогает */
    uint32_t prod_waiting;        /* производитель спит на полном кольце (spsc_reserve_wait) */
    /* Потребитель: пишет tail и waiting, читает head. */
    _Alignas(SPSC_LINE) uint32_t tail;
    uint32_t head_seen;
    uint32_t waiting;
    /* Не меняется после spsc_init (efd ставит потребитель ДО того, как производитель начнёт). */
    _Alignas(SPSC_LINE) unsigned char *buf;
    uint32_t mask;                /* число слотов - 1; число слотов — степень двойки */
    uint32_t stride;              /* байт на слот, с заголовком */
    int efd;                      /* eventfd потребителя; -1 — будить нечем */
};

/* Заголовок слота: длина пакета. Данные идут сразу за ним; 8 байт, чтобы данные оставались
 * выровненными на 8 (IP-заголовок читается как есть, без копии в выровненный буфер). */
#define SPSC_HDR 8u

/* Сколько байт занимает кольцо из nslots слотов с данными до cap байт. */
#define SPSC_BYTES(nslots, cap) ((size_t)(nslots) * (((cap) + SPSC_HDR + 63u) & ~63u))

/* nslots — степень двойки, не меньше двух. Данные слота — до cap байт. 0 или -1 при нехватке памяти. */
static inline int spsc_init(struct spsc *r, uint32_t nslots, uint32_t cap) {
    memset(r, 0, sizeof(*r));
    if (nslots < 2 || (nslots & (nslots - 1))) return -1;
    r->stride = (cap + SPSC_HDR + 63u) & ~63u;
    /* Выровнено по строке кэша: слот не делит строку с соседом, а значит запись производителя в
     * следующий слот не отнимает строку у потребителя, читающего предыдущий. */
    void *m = NULL;
    if (posix_memalign(&m, SPSC_LINE, (size_t)nslots * r->stride) != 0) return -1;
    r->buf = m;
    r->mask = nslots - 1;
    r->efd = -1;
    return 0;
}

static inline void spsc_free(struct spsc *r) {
    free(r->buf);
    r->buf = NULL;
}

static inline uint32_t spsc_cap(const struct spsc *r) { return r->stride - SPSC_HDR; }

/* ---- производитель ---- */

/* Место под следующий пакет, или NULL — кольцо полно. Данные записать и сообщить длину в
 * spsc_commit; до него потребитель слот не видит. */
static inline unsigned char *spsc_reserve(struct spsc *r) {
    uint32_t h = __atomic_load_n(&r->head, __ATOMIC_RELAXED);   /* пишет только производитель */
    if (h - r->tail_seen > r->mask) {
        r->tail_seen = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
        if (h - r->tail_seen > r->mask) return NULL;
    }
    return r->buf + (size_t)(h & r->mask) * r->stride + SPSC_HDR;
}

/* Опубликовать слот, взятый spsc_reserve, и разбудить потребителя, если он спит. Возвращает 1,
 * если пришлось будить. */
static inline int spsc_commit(struct spsc *r, uint32_t len) {
    uint32_t h = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    *(uint32_t *)(void *)(r->buf + (size_t)(h & r->mask) * r->stride) = len;
    /* seq_cst: часть пары с флагом waiting (см. шапку). */
    __atomic_store_n(&r->head, h + 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&r->waiting, __ATOMIC_SEQ_CST) &&
        __atomic_exchange_n(&r->waiting, 0, __ATOMIC_SEQ_CST)) {
        if (r->efd >= 0) {
            uint64_t one = 1;
            ssize_t wr = write(r->efd, &one, sizeof(one));
            (void)wr;   /* счётчик eventfd переполнен — рабочий и так разбужен */
        }
        return 1;
    }
    return 0;
}

/* Как spsc_reserve, но на полном кольце ждёт места до timeout_ns, не крутясь: спит на хвосте, пока
 * потребитель его не сдвинет и не разбудит (spsc_room). NULL — места не стало за срок. */
static inline unsigned char *spsc_reserve_wait(struct spsc *r, uint64_t timeout_ns) {
    unsigned char *slot = spsc_reserve(r);
    if (slot || !timeout_ns) return slot;
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        /* seq_cst: пара с spsc_room (см. шапку). */
        __atomic_store_n(&r->prod_waiting, 1, __ATOMIC_SEQ_CST);
        uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_SEQ_CST);
        uint32_t h = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
        if (h - t > r->mask) {
            struct timespec now;
            clock_gettime(CLOCK_MONOTONIC, &now);
            int64_t left = (int64_t)timeout_ns - ((int64_t)(now.tv_sec - t0.tv_sec) * 1000000000 +
                                                  (now.tv_nsec - t0.tv_nsec));
            if (left <= 0) { __atomic_store_n(&r->prod_waiting, 0, __ATOMIC_RELAXED); return NULL; }
            struct timespec ts = { (time_t)(left / 1000000000), (long)(left % 1000000000) };
            /* Хвост уже не t — ядро вернёт сразу (EAGAIN); иначе спим до побудки или срока. */
            syscall(SYS_futex, &r->tail, FUTEX_WAIT_PRIVATE, t, &ts, NULL, 0);
        }
        __atomic_store_n(&r->prod_waiting, 0, __ATOMIC_RELAXED);
        slot = spsc_reserve(r);
        if (slot) return slot;
    }
}

/* ---- потребитель ---- */

/* После порции spsc_pop: если производитель спит на полном кольце — разбудить. Раз в порцию, а не на
 * пакет: seq_cst-запись хвоста (того же значения) и чтение флага — пара к spsc_reserve_wait. */
static inline void spsc_room(struct spsc *r) {
    uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    __atomic_store_n(&r->tail, t, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&r->prod_waiting, __ATOMIC_SEQ_CST) &&
        __atomic_exchange_n(&r->prod_waiting, 0, __ATOMIC_SEQ_CST))
        syscall(SYS_futex, &r->tail, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);
}

/* Следующий пакет, или NULL. Длина — в *len. Пакет остаётся в кольце до spsc_pop. */
static inline const unsigned char *spsc_peek(struct spsc *r, uint32_t *len) {
    uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);   /* пишет только потребитель */
    if (t == r->head_seen) {
        r->head_seen = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
        if (t == r->head_seen) return NULL;
    }
    const unsigned char *s = r->buf + (size_t)(t & r->mask) * r->stride;
    *len = *(const uint32_t *)(const void *)s;
    return s + SPSC_HDR;
}

static inline void spsc_pop(struct spsc *r) {
    uint32_t t = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    __atomic_store_n(&r->tail, t + 1, __ATOMIC_RELEASE);
}

/* Есть ли что взять (потребитель). Читает голову заново, а не из памятки head_seen. */
static inline int spsc_pending(struct spsc *r) {
    return __atomic_load_n(&r->tail, __ATOMIC_RELAXED) !=
           __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
}

/* Перед сном: объявить себя спящим и проверить кольцо ещё раз. Возвращает 1 — спать можно
 * (производитель теперь разбудит), 0 — пакет успел прийти, флаг снят, спать нельзя. */
static inline int spsc_sleep_begin(struct spsc *r) {
    __atomic_store_n(&r->waiting, 1, __ATOMIC_SEQ_CST);
    if (__atomic_load_n(&r->tail, __ATOMIC_RELAXED) !=
        __atomic_load_n(&r->head, __ATOMIC_SEQ_CST)) {
        __atomic_store_n(&r->waiting, 0, __ATOMIC_SEQ_CST);
        return 0;
    }
    return 1;
}

/* После пробуждения по любой причине. Если производитель уже обменял флаг на 0 — ничего не
 * меняется; если проснулись по другой причине (сокет, срок), флаг снимается, и следующие
 * пакеты не будят зря. */
static inline void spsc_sleep_end(struct spsc *r) {
    __atomic_store_n(&r->waiting, 0, __ATOMIC_RELAXED);
}

#endif
