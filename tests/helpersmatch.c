/* Пауза перезапуска помощника (src/daemon/helpers.c, helpers_exited) без процессов и без ожидания.
 *
 * Помощник, который перед выходом сам сказал down с причиной (ни один узел подписки не отвечает), не
 * упал, а ждёт узла, и узнать, что узел вернулся, можно только запуском: проверка узла живёт в самом
 * помощнике. Пауза его перезапуска росла как у упавшего, 5, 10, 20 ... 300 с, и группа вернулась на
 * ожившего члена через 313 с (стенд QEMU). Теперь у такого выхода пауза не больше 30 с; упавший без
 * слов растёт по-прежнему до 300 с. */
#include <stdio.h>
#include <string.h>

#include "helpers.h"

static int g_fail;
static void check(int ok, const char *what) {
    printf("%-100s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) g_fail = 1;
}

/* Помощник вышел n раз подряд, каждый раз сразу после запуска. Возвращает паузу до следующего запуска
 * после последнего выхода, мс. */
static long exits(struct helper_set *s, int n, int said_down) {
    struct helper *h = &s->h[0];
    long wait = 0;
    for (int i = 0; i < n; i++) {
        h->pid = 1000 + i;
        h->started_ms = helpers_now_ms();
        h->st.said_down = said_down;
        helpers_exited(s, h->pid, 0);
        wait = h->next_ms - helpers_now_ms();
    }
    return wait;
}

int main(void) {
    struct helper_set s;
    memset(&s, 0, sizeof s);
    if (helpers_reserve(&s, 1) != 0) return 2;
    s.n = 1;
    struct helper *h = &s.h[0];
    memset(h, 0, sizeof *h);
    snprintf(h->cmd, sizeof h->cmd, "vless");
    snprintf(h->name, sizeof h->name, "vl");
    h->delay_ms = HELPERS_DELAY_MS;
    h->evfd = -1;

    long w = exits(&s, 1, 1);
    check(w > 4000 && w <= 5000, "вышел, сказав down: первый перезапуск через 5 с");
    w = exits(&s, 9, 1);
    check(w <= 30000 && w > 25000, "вышел, сказав down, десять раз подряд: пауза остановилась на 30 с, не на 300");

    h->delay_ms = HELPERS_DELAY_MS;
    w = exits(&s, 10, 0);
    check(w > 250000 && w <= 300000, "упал молча десять раз подряд: пауза по-прежнему растёт до 300 с");

    /* Пауза уже выросла до 300 с (упал молча), а затем помощник сообщил down и вышел: обрезается. */
    w = exits(&s, 1, 1);
    check(w <= 30000, "после роста паузы до 300 с выход со словом down обрезает её до 30 с");

    printf(g_fail ? "\nhelpersmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
