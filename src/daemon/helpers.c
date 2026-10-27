/* Помощники выходов: общая логика `steer supervise` и супервизора демона — см. helpers.h.
 *
 * Всё, что здесь, раньше жило в supervise.c и перенесено без изменения поведения: состав по
 * видам в порядке via, подпись параметров, пауза перезапуска, сверка по SIGHUP. Доводы — у
 * каждой функции. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <poll.h>

#include "spec.h"
#include "platform.h"
#include "helpers.h"
#include "plugin.h"

long helpers_now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* ПОДПИСЬ ПАРАМЕТРОВ ПОМОЩНИКА — то, что он читает из спеки ОДИН РАЗ, при старте.
 *
 * Состав («команда выход») SIGHUP сверял и раньше, а смену параметров оставленного выхода — нет:
 * человек выбирал другой узел подписки или другой сервер обфускации, apply проходил, а помощник
 * продолжал работать со старым до своего перезапуска, то есть до перезагрузки. Тот же открытый
 * пункт закрывает на роутере сам splify2 отпечатками vless_fingerprint и obfs_fingerprint
 * (rpcd/m-spec.sh); здесь поля те же, и по тем же доводам в подпись входит ТОЛЬКО то, что
 * помощник действительно читает при старте. Правка устройства, on_fail или каналов помощника
 * не касается, а перезапуск рвёт туннель и меняет выходной адрес — трогать его из-за неё нельзя.
 *
 * Поля по видам называет сам вид (kind_ops.helper в src/kinds): vless — файл подписки и выбор
 * узлов; xsteer — файл конфигурации и режим потока; tgws — домен точек; obfs у interface —
 * сервер и локальный адрес; модуль DPI — очередь, файл настройки и его содержимое. Содержимое остальных файлов (подписка обновилась)
 * подписью не ловится, как и на роутере: это отдельный повод со своим путём. */
static unsigned long long helper_sig(const struct spec *sp, const struct output *o,
                                     const struct kind_helper *hp) {
    unsigned long long h = hp->sig;       /* поля вида уже подмешаны его kind_ops.helper */
    /* Цель `via` помощник тоже читает при старте: метку сокета наверх он берёт один раз
     * (out_underlay_mark), и смена цели без перезапуска оставила бы туннель в прежнем выходе.
     * Только когда поле задано — подпись выхода без via остаётся прежней, и обновление движка
     * не перезапускает ни одного помощника.
     *
     * И сама МЕТКА цели, а не только её имя. Цель могли убрать из спеки и вернуть под тем же
     * именем — реестр выдаст ей другое место, то есть другую метку и таблицу, — а помощник со
     * старой меткой продолжал бы метить сокет значением, которое теперь ведёт в чужую таблицу
     * или никуда (то есть напрямую, мимо цели), до своего перезапуска. С меткой в подписи
     * сверка после такого apply перезапускает его сразу. Метку считает out_underlay_mark — ровно
     * то значение, что помощник поставит на сокет (с битом туннеля на телефоне). */
    if (o->over[0]) {
        kind_sig_mix(&h, o->over, strlen(o->over));
        uint32_t um = out_underlay_mark(sp, o);
        kind_sig_mix(&h, &um, sizeof(um));
    }
    return h;
}

size_t helpers_plan(const struct spec *sp, struct helper *out, size_t max, int *need_marks) {
    size_t k = 0;
    if (need_marks) *need_marks = 0;
    /* В порядке зависимостей via: цель поднимается раньше того, чей туннель через неё идёт, —
     * иначе первый подъём внутреннего перебирал бы узлы через ещё не созданное устройство и
     * уходил в паузу перезапуска. Гарантии готовности это не даёт (цель поднимается секунды),
     * но у спеки без via порядок прежний, спековый. */
    for (int depth = 0; depth <= MAX_OVER_DEPTH; depth++) {
        for (size_t i = 0; i < sp->out_n; i++) {
            const struct output *o = &sp->out[i];
            if (out_over_depth(sp, o) != depth) continue;
            /* Какой помощник нужен выходу, говорит вид (kind_ops.helper). Вид, чьей команды в
             * этой сборке нет, помощника не называет: vless и xsteer здесь только в расширенной
             * сборке, мост tgws — там же (kinds/tgws.c). */
            const struct kind_ops *kd = kind_of(o);
            struct kind_helper hp = { .sig = KIND_SIG_INIT };
            if (!kd->helper) continue;
            if (kd->helper(sp, o, &hp) != 0) { kind_helper_free(&hp); continue; }
            /* Помощник плагина читает {conf} (steer-api.md, 1.4): файл кладётся здесь, до запуска, при
             * каждом сборе помощников — его содержимое входит и в подпись перезапуска (plugin.c). */
            if (hp.conf_path && plugin_conf_write(sp, o) != 0)
                fprintf(stderr, "steer[warn] %s: файл настройки выхода %s не записан: %s\n", o->name,
                        hp.conf_path, strerror(errno));
            if (hp.marks && need_marks) *need_marks = 1;
            if (k >= max) { kind_helper_free(&hp); continue; }
            struct helper *h = &out[k];
            memset(h, 0, sizeof(*h));
            if (!hp.cmd || helper_launch_set(h, &hp) != 0) {
                helper_launch_free(h);
                kind_helper_free(&hp);
                continue;
            }
            k++;
            snprintf(h->name, sizeof(h->name), "%s", o->name);
            if (hp.plugin) snprintf(h->plugin, sizeof(h->plugin), "%s", hp.plugin);
            h->sig = helper_sig(sp, o, &hp);
            h->delay_ms = HELPERS_DELAY_MS;
            h->evfd = -1;
            kind_helper_free(&hp);
        }
    }
    return k;
}

/* Как назвать помощника в журнале: «obfs a»; у резолвера имени выхода нет — «dnsd». */
/* ---- поля запуска ------------------------------------------------------------------------- */

static char **vec_dup(char *const *v, size_t n) {
    if (!n) return NULL;
    char **c = calloc(n, sizeof(*c));
    if (!c) return NULL;
    for (size_t i = 0; i < n; i++)
        if (!(c[i] = strdup(v[i]))) {
            for (size_t j = 0; j < i; j++) free(c[j]);
            free(c);
            return NULL;
        }
    return c;
}

static void vec_free(char **v, size_t n) {
    for (size_t i = 0; i < n; i++) free(v[i]);
    free(v);
}

void helper_launch_free(struct helper *h) {
    free(h->cmd);
    free(h->prog);
    vec_free(h->arg, h->arg_n);
    vec_free(h->env, h->env_n);
    h->cmd = h->prog = NULL;
    h->arg = h->env = NULL;
    h->arg_n = h->env_n = 0;
}

void helpers_launch_free(struct helper *v, size_t n) {
    for (size_t i = 0; i < n; i++) helper_launch_free(&v[i]);
}

static int launch_copy(struct helper *dst, const char *cmd, const char *prog, char *const *arg,
                       size_t arg_n, char *const *env, size_t env_n) {
    char *c = cmd ? strdup(cmd) : NULL;
    char *p = prog ? strdup(prog) : NULL;
    char **a = vec_dup(arg, arg_n), **e = vec_dup(env, env_n);
    if ((cmd && !c) || (prog && !p) || (arg_n && !a) || (env_n && !e)) {
        free(c); free(p);
        if (a) vec_free(a, arg_n);
        if (e) vec_free(e, env_n);
        return -1;
    }
    helper_launch_free(dst);
    dst->cmd = c; dst->prog = p;
    dst->arg = a; dst->arg_n = arg_n;
    dst->env = e; dst->env_n = env_n;
    return 0;
}

int helper_launch_set(struct helper *h, const struct kind_helper *hp) {
    return launch_copy(h, hp->cmd, hp->prog, hp->arg, hp->arg_n, hp->env, hp->env_n);
}

int helper_set_cmd(struct helper *h, const char *cmd) {
    return launch_copy(h, cmd, NULL, NULL, 0, NULL, 0);
}

int helper_clone(struct helper *dst, const struct helper *src) {
    *dst = *src;
    dst->cmd = dst->prog = NULL;
    dst->arg = dst->env = NULL;
    dst->arg_n = dst->env_n = 0;
    if (launch_copy(dst, src->cmd, src->prog, src->arg, src->arg_n, src->env, src->env_n) != 0) {
        memset(dst, 0, sizeof(*dst));
        return -1;
    }
    return 0;
}

/* Строка по трубе: длина (size_t; ~0 — NULL) и байты. */
static int wstr(FILE *w, const char *s) {
    size_t n = s ? strlen(s) : (size_t)-1;
    if (fwrite(&n, sizeof(n), 1, w) != 1) return -1;
    return s && n && fwrite(s, 1, n, w) != n ? -1 : 0;
}

static int rstr(FILE *r, char **out) {
    size_t n;
    *out = NULL;
    if (fread(&n, sizeof(n), 1, r) != 1) return -1;
    if (n == (size_t)-1) return 0;
    char *s = malloc(n + 1);
    if (!s) return -1;
    if (n && fread(s, 1, n, r) != n) { free(s); return -1; }
    s[n] = '\0';
    *out = s;
    return 0;
}

int helper_write(FILE *w, const struct helper *h) {
    if (fwrite(h, sizeof(*h), 1, w) != 1) return -1;
    if (wstr(w, h->cmd) || wstr(w, h->prog)) return -1;
    for (size_t i = 0; i < h->arg_n; i++) if (wstr(w, h->arg[i])) return -1;
    for (size_t i = 0; i < h->env_n; i++) if (wstr(w, h->env[i])) return -1;
    return 0;
}

int helper_read(FILE *r, struct helper *h) {
    if (fread(h, sizeof(*h), 1, r) != 1) return -1;
    size_t an = h->arg_n, en = h->env_n;
    h->cmd = h->prog = NULL;
    h->arg = h->env = NULL;
    h->arg_n = h->env_n = 0;
    if (rstr(r, &h->cmd) || rstr(r, &h->prog)) goto bad;
    if (an && !(h->arg = calloc(an, sizeof(*h->arg)))) goto bad;
    h->arg_n = an;
    for (size_t i = 0; i < an; i++) if (rstr(r, &h->arg[i])) goto bad;
    if (en && !(h->env = calloc(en, sizeof(*h->env)))) goto bad;
    h->env_n = en;
    for (size_t i = 0; i < en; i++) if (rstr(r, &h->env[i])) goto bad;
    return 0;
bad:
    helper_launch_free(h);
    return -1;
}

static const char *hname(const struct helper *h, char *buf, size_t n) {
    snprintf(buf, n, "%s%s%s", h->cmd ? h->cmd : "", h->name[0] ? " " : "", h->name);
    return buf;
}

static int same_helper(const struct helper *a, const struct helper *b) {
    return !strcmp(a->cmd ? a->cmd : "", b->cmd ? b->cmd : "") && !strcmp(a->name, b->name);
}

/* Параметры запуска — из нового состава: у помощника-программы они в аргументах (очередь,
 * файл ключей zapret), и перезапуск ради новой подписи обязан взять новые. */
static void take_params(struct helper *h, const struct helper *f) {
    /* Нет памяти — параметры остаются прежними: следующая сверка возьмёт новые. */
    launch_copy(h, f->cmd, f->prog, f->arg, f->arg_n, f->env, f->env_n);
}

int helpers_reserve(struct helper_set *s, size_t n) {
    if (n <= s->cap) return 0;
    size_t nc = s->cap ? s->cap : 8;
    while (nc < n) nc *= 2;
    struct helper *np = realloc(s->h, nc * sizeof(*np));
    if (!np) return -1;
    memset(np + s->cap, 0, (nc - s->cap) * sizeof(*np));
    s->h = np;
    s->cap = nc;
    return 0;
}

void helpers_merge(struct helper_set *s, const struct helper *fresh, size_t fn) {
    /* Место сразу на всех возможных новичков: дальше элементы наборы не двигает. */
    if (helpers_reserve(s, s->n + fn) != 0) return;
    struct helper *h = s->h;
    for (size_t i = 0; i < s->n; i++) {
        int keep = 0;
        for (size_t k = 0; k < fn; k++)
            if (same_helper(&h[i], &fresh[k])) keep = 1;
        if (!keep && !h[i].gone) {
            h[i].gone = 1;
            if (h[i].pid) kill(h[i].pid, SIGTERM);
        }
    }
    /* Оставленные выходы с новыми параметрами: запомнить подпись и перезапустить живого
     * помощника. Не запущенный (ждёт паузы после падения) поднимется уже с новыми — его
     * достаточно запомнить. */
    for (size_t i = 0; i < s->n; i++) {
        if (h[i].gone) continue;
        for (size_t k = 0; k < fn; k++) {
            if (!same_helper(&h[i], &fresh[k])) continue;
            take_params(&h[i], &fresh[k]);
            if (h[i].sig == fresh[k].sig) continue;
            h[i].sig = fresh[k].sig;
            h[i].revive = 0;      /* причина перезапуска теперь — параметры */
            if (h[i].pid && !h[i].restart) {
                h[i].restart = 1;
                kill(h[i].pid, SIGTERM);
            }
        }
    }
    for (size_t k = 0; k < fn; k++) {
        int have = 0;
        for (size_t i = 0; i < s->n; i++) {
            if (!same_helper(&h[i], &fresh[k])) continue;
            /* Выход вернули в спеку, пока его прежний помощник ещё гаснет: не второй экземпляр
             * рядом, а тот же слот — перезапустится, когда прежний выйдет. */
            h[i].gone = 0;
            h[i].sig = fresh[k].sig;
            take_params(&h[i], &fresh[k]);
            have = 1;
        }
        if (!have && helper_clone(&h[s->n], &fresh[k]) == 0) s->n++;
    }
    /* Спеку исправили — упавшему незачем досиживать растущую паузу до пяти минут. */
    for (size_t i = 0; i < s->n; i++)
        if (!h[i].pid) { h[i].delay_ms = HELPERS_DELAY_MS; h[i].next_ms = 0; }
}

struct helper *helpers_exited(struct helper_set *s, pid_t pid, int st) {
    char nb[48];
    for (size_t i = 0; i < s->n; i++) {
        struct helper *h = &s->h[i];
        if (h->pid != pid) continue;
        h->pid = 0;
        /* Погашен нами ради новых параметров (или по просьбе сторожа, supd_restart) — поднять
         * сразу: это не падение, и ни пауза, ни её рост к нему не относятся. */
        if (h->restart) {
            int rv = h->revive;
            h->restart = h->revive = 0;
            h->delay_ms = HELPERS_DELAY_MS;
            h->next_ms = 0;
            if (!h->gone)
                fprintf(stderr, "steer[info] supervise: %s — %s, поднимаю заново\n",
                        hname(h, nb, sizeof(nb)),
                        rv ? "выход не отвечает" : "параметры выхода изменились");
            return h;
        }
        /* Проработал дольше минуты — пауза снова пять секунд. Эта пауза и ждётся сейчас, а
         * удваивается следующая: первый перезапуск упавшего всегда через пять секунд, как у
         * procd. */
        long now = helpers_now_ms();
        long lived = now - h->started_ms;
        long cap = h->st.said_down ? HELPERS_DELAY_DOWN_MAX_MS : HELPERS_DELAY_MAX_MS;
        if (lived >= HELPERS_STABLE_MS) h->delay_ms = HELPERS_DELAY_MS;
        if (h->delay_ms > cap) h->delay_ms = cap;
        h->next_ms = now + h->delay_ms;
        if (!h->gone)
            fprintf(stderr, "steer[warn] supervise: %s вышел (%s %d) — перезапуск "
                            "через %ld с\n", hname(h, nb, sizeof(nb)),
                    WIFEXITED(st) ? "код" : "сигнал",
                    WIFEXITED(st) ? WEXITSTATUS(st) : WTERMSIG(st),
                    h->delay_ms / 1000);
        if (lived < HELPERS_STABLE_MS && h->delay_ms < cap)
            h->delay_ms = h->delay_ms * 2 > cap ? cap : h->delay_ms * 2;
        return h;
    }
    return NULL;
}

void helpers_compact(struct helper_set *s) {
    size_t w = 0;
    for (size_t i = 0; i < s->n; i++)
        if (!(s->h[i].gone && !s->h[i].pid)) {
            if (w != i) s->h[w] = s->h[i];
            w++;
        } else {
            helper_launch_free(&s->h[i]);
        }
    s->n = w;
}

long helpers_due(struct helper_set *s, helper_start_fn start, void *arg) {
    long now = helpers_now_ms();
    long wait = -1;
    for (size_t i = 0; i < s->n; i++) {
        struct helper *h = &s->h[i];
        if (h->pid || h->gone) continue;
        if (h->next_ms <= now && start(h, arg) != 0) h->next_ms = now + h->delay_ms;
        if (!h->pid && (wait < 0 || h->next_ms - now < wait))
            wait = h->next_ms - now > 0 ? h->next_ms - now : 0;
    }
    return wait;
}

void helper_started(struct helper *h, pid_t pid) {
    h->pid = pid;
    h->started_ms = helpers_now_ms();
    char nb[48];
    fprintf(stderr, "steer[info] supervise: %s запущен (pid %d)\n", hname(h, nb, sizeof(nb)),
            (int)pid);
}

const char **helper_argv(const struct helper *h, const char *exe, const char *self, int seam,
                         const char *spec, char *progbuf, size_t pbn) {
    /* Слов: до трёх своих, аргументы программы, пять у подкоманды (--spec, --state-dir) и NULL. */
    const char **av = malloc((h->arg_n + 10) * sizeof(*av));
    if (!av) return NULL;
    size_t n = 0;
    if (h->prog && h->prog[0]) {
        /* Помощник-программа (steer-nfqws) лежит рядом с движком — как /usr/sbin у init.d.
         * Шов стенда подменяет и её, получая имя помощника и выход первыми словами. */
        if (seam) {
            av[n++] = exe;
            av[n++] = h->cmd;
            av[n++] = h->name;
        } else if (h->prog[0] == '/') {
            /* Программа плагина: реестр (kinds/plugin.c) отдаёт полный путь в каталоге плагина. */
            snprintf(progbuf, pbn, "%s", h->prog);
            av[n++] = progbuf;
        } else {
            const char *sl = strrchr(self, '/');
            int dl = sl ? (int)(sl - self) : 1;
            snprintf(progbuf, pbn, "%.*s/%s", dl, sl ? self : ".", h->prog);
            av[n++] = progbuf;
        }
        for (size_t i = 0; i < h->arg_n; i++) av[n++] = h->arg[i];
        av[n] = NULL;
        return av;
    }
    av[n++] = exe;
    av[n++] = h->cmd;
    av[n++] = h->name;
    av[n++] = "--spec";
    av[n++] = spec;
    /* Каталог состояния — тот же, что у супервизора, если его задали: помощник читает оттуда
     * реестр меток (метку цели via), и разойдись каталоги — подпись в супервизоре считалась бы
     * по одной метке, а сокет помощника ставился бы по другой. */
    if (strcmp(steer_state_dir(), plat()->state_dir) != 0) {
        av[n++] = "--state-dir";
        av[n++] = steer_state_dir();
    }
    av[n] = NULL;
    return av;
}

void helper_putenv(const struct helper *h) {
    for (size_t i = 0; i < h->env_n; i++) putenv(h->env[i]);
}

const char *helper_argv0(const char *exe, char *buf, size_t n) {
    const char *sl = strrchr(exe, '/');
    const char *base = sl ? sl + 1 : exe;
    if (strcmp(base, "steerd") != 0) return exe;
    snprintf(buf, n, "%.*ssteer", (int)(base - exe), exe);
    return buf;
}

/* Дескриптор процесса (pidfd, ядро ≥ 5.3): ждать выхода можно poll без опроса waitpid. -1 — ядро не умеет или
 * процесса уже нет. */
static int pidfd_of(pid_t pid) {
#ifdef SYS_pidfd_open
    return (int)syscall(SYS_pidfd_open, pid, 0);
#else
    (void)pid;
    errno = ENOSYS;
    return -1;
#endif
}

/* Дождаться выхода pid до срока (монотонные мс). 1 — вышел (пожат).
 *
 * По pidfd — проснуться ровно в миг выхода, а не на очередном шаге опроса в 50 мс: остановка службы с десятком
 * помощников копила эти шаги (I-534). Ядро без pidfd — прежний опрос. */
static int wait_until(pid_t pid, long deadline) {
    int pfd = pidfd_of(pid);
    for (;;) {
        pid_t w = waitpid(pid, NULL, WNOHANG);
        if (w == pid || (w < 0 && errno == ECHILD)) { if (pfd >= 0) close(pfd); return 1; }
        long left = deadline - helpers_now_ms();
        if (left <= 0) { if (pfd >= 0) close(pfd); return 0; }
        if (pfd >= 0) {
            struct pollfd p = { .fd = pfd, .events = POLLIN };
            poll(&p, 1, left > 1000 ? 1000 : (int)left);
        } else {
            struct timespec ts = { 0, 50000000L };
            nanosleep(&ts, NULL);
        }
    }
}

/* Дождаться выхода всех pid из h[0..n) до срока: один poll по всем pidfd вместо шага опроса в 100 мс на каждого.
 * У вышедших h[i].pid обнуляется. */
static void wait_all(struct helper *h, size_t n, long deadline) {
    struct pollfd *pf = calloc(n ? n : 1, sizeof(*pf));
    for (;;) {
        size_t left = 0;
        for (size_t i = 0; i < n; i++) {
            if (!h[i].pid) continue;
            if (waitpid(h[i].pid, NULL, WNOHANG) == h[i].pid) h[i].pid = 0;
            else left++;
        }
        long ms = deadline - helpers_now_ms();
        if (!left || ms <= 0) break;
        size_t k = 0;
        int ok = pf != NULL;
        for (size_t i = 0; ok && i < n; i++) {
            if (!h[i].pid) continue;
            int fd = pidfd_of(h[i].pid);
            if (fd < 0) { ok = 0; break; }
            pf[k].fd = fd;
            pf[k].events = POLLIN;
            pf[k].revents = 0;
            k++;
        }
        if (ok) poll(pf, (nfds_t)k, ms > 1000 ? 1000 : (int)ms);
        for (size_t i = 0; i < k; i++) close(pf[i].fd);
        if (!ok) {                       /* ядро без pidfd: прежний шаг опроса */
            struct timespec ts = { 0, 100000000L };
            nanosleep(&ts, NULL);
        }
    }
    free(pf);
}

void helpers_stop(struct helper_set *s, int ordered) {
    struct helper *h = s->h;
    size_t n = s->n;
    if (!ordered) {
        for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGTERM);
        /* Три секунды на уборку, дальше — SIGKILL: супервизор не выходит, оставив помощника жить без присмотра. */
        wait_all(h, n, helpers_now_ms() + 3000L);
        for (size_t i = 0; i < n; i++) if (h[i].pid) kill(h[i].pid, SIGKILL);
        wait_all(h, n, helpers_now_ms() + 1000L);
        return;
    }
    /* По одному, в обратном порядке подъёма: внешний туннель гаснет раньше того, через кого он
     * идёт, и не успевает перебрать узлы через уже снятое устройство. Каждому — три секунды на
     * уборку, всем вместе — не больше десяти: дальше оставшимся сразу SIGKILL (procd и init
     * ждут остановки службы не бесконечно). */
    long all = helpers_now_ms() + 10000L;
    for (size_t i = n; i-- > 0;) {
        if (!h[i].pid) continue;
        long now = helpers_now_ms();
        if (now < all) {
            kill(h[i].pid, SIGTERM);
            long dl = now + 3000L < all ? now + 3000L : all;
            if (wait_until(h[i].pid, dl)) { h[i].pid = 0; continue; }
        }
        kill(h[i].pid, SIGKILL);
        while (waitpid(h[i].pid, NULL, 0) < 0 && errno == EINTR) {}
        h[i].pid = 0;
    }
}
