/* Пакетный ввод-вывод UDP слоя QUIC (quic.c, «ПАКЕТНЫЙ ВВОД-ВЫВОД» в quic.h): чистые части —
 * какие датаграммы уходят одним вызовом с UDP_SEGMENT, какие ошибки отключают GSO, как режется
 * склеенный приём (UDP_GRO). Сами сокеты — в tests/qcloop.c (эхо на запасных путях и подсчёт
 * вызовов) и tests/run-hy2.sh.
 *
 *     cc -O2 -w -DQC_WITH_SERVER $(make -s print-inc) -Itests -o build/qcbatch tests/qcbatch.c \
 *        src/proto/quic/quic.c src/proto/quic/qcssl.c <ngtcp2.a> <wolfssl.a> -lpthread */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>

#include "quic.h"
#include "unit.h"

static size_t run(const size_t *l, size_t n) { return qc_io_gso_run(l, n); }

int main(void) {
    /* GSO: первая задаёт размер сегмента. */
    size_t a[] = { 1252, 1252, 1252, 1252 };
    check("четыре равные — одним вызовом", 4, (long)run(a, 4));
    size_t b[] = { 1252, 1252, 700 };
    check("короткая в конце входит в пачку", 3, (long)run(b, 3));
    size_t c[] = { 1252, 700, 1252 };
    check("короткая в середине закрывает пачку (после неё сегмент другого размера)", 2, (long)run(c, 3));
    size_t d[] = { 1252, 1300, 1252 };
    check("больший, чем первая, не входит", 1, (long)run(d, 3));
    size_t e[] = { 700, 1252 };
    check("первая короче следующей — пачка из одной", 1, (long)run(e, 2));
    size_t f[] = { 1252 };
    check("одна датаграмма — пачка из одной", 1, (long)run(f, 1));
    check("пусто — 0", 0, (long)run(f, 0));
    size_t z[] = { 0, 0 };
    check("нулевая длина — не склеивается", 1, (long)run(z, 2));
    size_t z2[] = { 1252, 0, 1252 };
    check("нулевая длина посередине закрывает пачку", 1, (long)run(z2, 3));

    /* Пределы ядра: 64 сегмента и 65507 байт. */
    size_t many[100];
    for (int i = 0; i < 100; i++) many[i] = 100;
    check("не больше 64 сегментов за вызов", 64, (long)run(many, 100));
    size_t big[100];
    for (int i = 0; i < 100; i++) big[i] = 9000;
    check("не больше 65507 байт за вызов (7 по 9000)", 7, (long)run(big, 100));
    size_t big2[] = { 20000, 20000, 20000, 20000 };
    check("65507 байт: три по 20000, четвёртая не влезает", 3, (long)run(big2, 4));
    size_t big3[] = { 60000, 5507 };
    check("ровно 65507 байт входит", 2, (long)run(big3, 2));
    size_t big4[] = { 60000, 5508 };
    check("65508 байт — уже нет", 1, (long)run(big4, 2));

    /* Какие ошибки отключают GSO. */
    check("EIO (нет контрольной суммы в устройстве) — отключить", 1, qc_io_gso_fatal(EIO));
    check("EINVAL (ядро без UDP_SEGMENT) — отключить", 1, qc_io_gso_fatal(EINVAL));
    check("ENOPROTOOPT — отключить", 1, qc_io_gso_fatal(ENOPROTOOPT));
    check("EOPNOTSUPP — отключить", 1, qc_io_gso_fatal(EOPNOTSUPP));
    check("EAGAIN — потеря, не отказ GSO", 0, qc_io_gso_fatal(EAGAIN));
    check("ENOBUFS — потеря, не отказ GSO", 0, qc_io_gso_fatal(ENOBUFS));
    check("ECONNREFUSED — потеря, не отказ GSO", 0, qc_io_gso_fatal(ECONNREFUSED));
    check("EMSGSIZE — потеря, не отказ GSO", 0, qc_io_gso_fatal(EMSGSIZE));

    /* GRO: нарезка склеенного приёма на датаграммы. */
    size_t off = 0, n, got[8], k = 0;
    while ((n = qc_io_gro_next(3000, 1200, off)) != 0 && k < 8) { got[k++] = n; off += n; }
    check("3000 байт по 1200: три датаграммы", 3, (long)k);
    check("  1200", 1200, (long)got[0]);
    check("  1200", 1200, (long)got[1]);
    check("  600 (последняя короче)", 600, (long)got[2]);
    check("  сумма — всё принятое", 3000, (long)off);
    check("кратно сегменту: 2400 по 1200 — две", 1200, (long)qc_io_gro_next(2400, 1200, 1200));
    check("  и конец", 0, (long)qc_io_gro_next(2400, 1200, 2400));
    check("без склейки (seg 0) — одним куском", 1252, (long)qc_io_gro_next(1252, 0, 0));
    check("  второго куска нет", 0, (long)qc_io_gro_next(1252, 0, 1252));
    check("пустая датаграмма — нечего отдавать", 0, (long)qc_io_gro_next(0, 1200, 0));
    check("сегмент больше данных — один кусок", 500, (long)qc_io_gro_next(500, 1200, 0));
    return unit_done("qcbatch");
}
