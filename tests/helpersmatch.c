/* Пауза перезапуска помощника (src/daemon/helpers.c, helpers_exited) без процессов и без ожидания.
 *
 * Помощник, который перед выходом сам сказал down с причиной (ни один узел подписки не отвечает), не
 * упал, а ждёт узла, и узнать, что узел вернулся, можно только запуском: проверка узла живёт в самом
 * помощнике. Пауза его перезапуска росла как у упавшего, 5, 10, 20 ... 300 с, и группа вернулась на
 * ожившего члена через 313 с (стенд QEMU). Теперь у такого выхода пауза не больше 30 с; упавший без
 * слов растёт по-прежнему до 300 с. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <sys/wait.h>

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

/* Остановка службы (helpers_stop): помощники, вышедшие на SIGTERM, пожинаются в тот же миг, а не на очередном шаге
 * опроса в 50 и 100 мс (I-534). Восемь процессов, умирающих по SIGTERM сразу: порядком и без порядка остановка
 * укладывается в доли шага опроса (прежде — шаг на каждого, до 400 мс). */
static long stop_ms(int ordered) {
    struct helper_set st;
    memset(&st, 0, sizeof st);
    if (helpers_reserve(&st, 8) != 0) return -1;
    st.n = 8;
    for (int i = 0; i < 8; i++) {
        memset(&st.h[i], 0, sizeof st.h[i]);
        pid_t p = fork();
        if (p == 0) { for (;;) pause(); }
        st.h[i].pid = p;
        st.h[i].evfd = -1;
    }
    usleep(20000);                       /* дети дошли до pause */
    long t0 = helpers_now_ms();
    helpers_stop(&st, ordered);
    long dt = helpers_now_ms() - t0;
    int alive = 0;
    for (int i = 0; i < 8; i++) if (st.h[i].pid) alive++;
    return alive ? -2 : dt;
}

/* Поля запуска без пределов (плагины): тысячи аргументов и переменных окружения длиной в
 * несколько КиБ, клон, запись и чтение по трубе супервизора, argv, окружение и сверка набором из
 * тысячи помощников. Прежде: prog 16 байт, два аргумента по 255, одна переменная в 31. */
static void launch_limits(void) {
    enum { NA = 3000, NE = 2000, BIG = 5000 };
    struct helper h;
    memset(&h, 0, sizeof h);
    h.cmd = strdup("plug");
    snprintf(h.name, sizeof h.name, "p1");
    h.prog = strdup("steer-plugin-with-a-very-long-program-name");
    h.arg = calloc(NA, sizeof(char *));
    h.env = calloc(NE, sizeof(char *));
    for (int i = 0; i < NA; i++) {
        h.arg[i] = malloc(BIG + 1);
        memset(h.arg[i], 'a' + i % 26, BIG);
        h.arg[i][BIG] = '\0';
        snprintf(h.arg[i], 16, "arg%d=", i);
    }
    h.arg_n = NA;
    for (int i = 0; i < NE; i++) {
        h.env[i] = malloc(BIG + 1);
        memset(h.env[i], 'x', BIG);
        h.env[i][BIG] = '\0';
        char nm[32];
        snprintf(nm, sizeof nm, "STEERPL_%d=", i);
        memcpy(h.env[i], nm, strlen(nm));
    }
    h.env_n = NE;

    struct helper c;
    check(helper_clone(&c, &h) == 0 && c.arg_n == NA && c.env_n == NE && c.arg[NA - 1] != h.arg[NA - 1] &&
          !strcmp(c.arg[NA - 1], h.arg[NA - 1]) && !strcmp(c.env[NE - 1], h.env[NE - 1]),
          "клон помощника: 3000 аргументов и 2000 переменных по 5 КиБ скопированы целиком");

    FILE *f = tmpfile();
    struct helper r;
    int ok = f && helper_write(f, &h) == 0 && helper_write(f, &c) == 0;
    if (f) rewind(f);
    ok = ok && helper_read(f, &r) == 0 && r.arg_n == NA && r.env_n == NE &&
         !strcmp(r.arg[NA - 1], h.arg[NA - 1]) && !strcmp(r.env[0], h.env[0]) &&
         !strcmp(r.prog, h.prog) && !strcmp(r.cmd, "plug") && !strcmp(r.name, "p1");
    check(ok, "запись и чтение по трубе супервизора сохраняют все строки");
    if (f) fclose(f);

    char pb[4096];
    const char **av = helper_argv(&h, "/exe", "/usr/sbin/steer", 1, "/spec", pb, sizeof pb);
    size_t n = 0;
    while (av && av[n]) n++;
    check(av && n == 3 + NA && !strcmp(av[3 + NA - 1], h.arg[NA - 1]),
          "argv помощника-программы: все 3000 аргументов, число слов не ограничено");
    free(av);

    helper_putenv(&h);
    check(getenv("STEERPL_1999") && strlen(getenv("STEERPL_1999")) == BIG - strlen("STEERPL_1999="),
          "окружение: все 2000 переменных поставлены, значение в 5 КиБ цело");

    /* Набор из тысячи помощников со своими строками: сверка берёт параметры нового состава. */
    enum { M = 1000 };
    struct helper *fresh = calloc(M, sizeof *fresh);
    struct helper_set set;
    memset(&set, 0, sizeof set);
    for (int i = 0; i < M; i++) {
        char nm[32], v[64];
        snprintf(nm, sizeof nm, "o%d", i);
        struct kind_helper kh = { .sig = KIND_SIG_INIT };
        snprintf(v, sizeof v, "ARG%d", i);
        if (kind_helper_cmd(&kh, "plug") || kind_helper_arg(&kh, v) || kind_helper_env(&kh, "K=v") ||
            kind_helper_prog(&kh, "steer-plug"))
            continue;
        helper_launch_set(&fresh[i], &kh);
        kind_helper_free(&kh);
        snprintf(fresh[i].name, sizeof fresh[i].name, "%s", nm);
        fresh[i].evfd = -1;
    }
    helpers_merge(&set, fresh, M);
    check(set.n == M && !strcmp(set.h[M - 1].arg[0], "ARG999") && !strcmp(set.h[M - 1].env[0], "K=v"),
          "набор из тысячи помощников принят сверкой без предела числа");
    helpers_launch_free(fresh, M);
    free(fresh);
    check(set.n == M && !strcmp(set.h[0].prog, "steer-plug"),
          "  и держит свои строки после освобождения плана сверки");
    helpers_launch_free(set.h, set.n);
    helper_launch_free(&h);
    helper_launch_free(&c);
    helper_launch_free(&r);
}

int main(void) {
    struct helper_set s;
    memset(&s, 0, sizeof s);
    if (helpers_reserve(&s, 1) != 0) return 2;
    s.n = 1;
    struct helper *h = &s.h[0];
    memset(h, 0, sizeof *h);
    h->cmd = strdup("vless");
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

    launch_limits();

    long u = stop_ms(0), o = stop_ms(1);
    check(u >= 0 && u < 90, "остановка без порядка: восемь помощников, вышедших на SIGTERM, убраны быстрее шага опроса (90 мс)");
    check(o >= 0 && o < 150, "остановка по порядку: восемь помощников убраны быстрее 150 мс (прежде шаг опроса на каждого)");
    if (u >= 90 || o >= 150) printf("  без порядка %ld мс, по порядку %ld мс\n", u, o);

    printf(g_fail ? "\nhelpersmatch: ПРОВАЛ\n" : "\nвсе проверки прошли\n");
    return g_fail;
}
