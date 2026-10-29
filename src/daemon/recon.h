/* Apply-сверка демона: новая спека сравнивается с применённой по частям (устройство и доводы —
 * в шапке recon.c). */
#ifndef STEER_RECON_H
#define STEER_RECON_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "spec.h"

/* Выход в плане: то, что apply ставит в ядро для него, свёрнутое в подписи. */
struct recon_out {
    char name[32];
    unsigned mark;
    int table;
    int routed;                     /* у выхода есть устройство: правило и таблица */
    int awg;                        /* kind=awg: устройство настраивает apply */
    unsigned long long rsig;        /* подпись маршрутизации */
    unsigned long long wsig;        /* подпись того, что читает сторож */
};

/* План новой спеки — вывод `steer apply-plan`. */
struct recon_plan {
    int nftc;
    unsigned long long fp;          /* отпечаток текста набора правил */
    size_t ch_n, out_n;
    /* Массивы растут по числу строк плана (recon_plan_parse) и отдаются recon_plan_free:
     * выходов в плане столько, сколько в спеке (в том числе direct без метки), а не «не больше 16». */
    struct recon_out *out;
    size_t n, cap;
    struct { unsigned mark; int table; } *stale;
    size_t stale_n, stale_cap;
    /* Сводка элементов статических наборов в ядре на момент плана (строка kelems, только с
     * --kernel-elems): kel_ok 0 — не спрашивали или снять не вышло. */
    int kel_ok;
    uint64_t kel, kel_n;
};

/* Что демон знает о применённом. valid=0 — ничего: следующий apply применяет всё, как
 * подкоманда. */
struct recon_state {
    int valid;
    unsigned long long fp;
    uint64_t handle;                /* номер таблицы в ядре после нашего nft -f; 0 — ядро не даёт */
    /* Отпечаток наших таблиц в ядре сразу после нашего nft -f (nfd_table_fp: цепочки, правила,
     * заголовки наборов — без элементов и счётчиков): с ним сверяется ядро на каждом apply и на
     * каждом проходе сторожа. */
    uint64_t kfp;
    /* Сводка элементов статических наборов сразу после нашего nft -f (recon_kernel_elems): с ней
     * сверяется ядро на apply и reload (на проходе сторожа — нет). kel_ok 0 — снять не вышло,
     * элементы до следующего nft -f не сверяются. */
    int kel_ok;
    uint64_t kel, kel_n;
    struct recon_out *out;          /* куча, recon_applied растит; живёт с демоном */
    size_t n, cap;
    /* Подписи сторожа — отдельно от применённого: их сверка нужна и тогда, когда в ядро ничего
     * не шло. */
    int wvalid;
    struct { char name[32]; unsigned long long wsig; } *w;
    size_t wn, wcap;
    int nftc;                       /* раскладка из первого плана; -1 — ещё не знаем */
};

/* Решение: что применять. */
struct recon_diff {
    int ruleset;
    /* Массивы растут по числу выходов решения и отдаются recon_diff_free. */
    char (*route)[32];
    size_t route_n, route_cap;
    /* route_kern[i] — выход route[i] привязывается заново только потому, что ядро разошлось с
     * ожидаемым, а подпись его маршрутизации в спеке не менялась: такая привязка ничего не снимает
     * нарочно, и страж правил вправе возвращать правила этого выхода, пока она идёт (rulewd.c).
     * Выход с изменившейся подписью, новый и полный apply — 0: спека могла отнять у него IPv6. */
    unsigned char *route_kern;      /* параллельно route */
    struct { unsigned mark; int table; } *drop;
    size_t drop_n, drop_cap;
    int awg, masq;
    /* Сторожу внеочередной проход: в ядре нашлось расхождение, которое сверка вернула сама
     * (проход подтвердит выбор устройств и карты раздачи), или то, что возвращает только он
     * (маршрутизация выхода в отказе). */
    int watch;
};

/* Ядро сразу после нашего nft -f — как его снял ребёнок apply-commit (recon_kernel_print) и
 * передал демону строкой своего вывода. */
struct recon_kernel {
    int ok;                         /* номер и отпечаток сняты */
    uint64_t handle, kfp;
    int el_ok;                      /* сводка элементов снята */
    uint64_t el, el_n;
};

struct fo_store;
void recon_init(struct recon_state *st);
/* Отдать массивы и обнулить. Структуры несут указатели: их обнуление memset'ом без этих вызовов —
 * утечка. recon_plan_parse и recon_decide начинают с нулевой структуры (свежее соединение). */
void recon_plan_free(struct recon_plan *p);
void recon_diff_free(struct recon_diff *d);
/* Разобрать вывод плана. 0 — годный. */
int recon_plan_parse(const char *text, size_t n, struct recon_plan *p);
/* Решить по плану и применённому — и по ядру: таблица на месте и та же ли (номер), не изменены ли
 * в ней цепочки, правила и наборы (отпечаток) и элементы статических наборов (сводка из плана),
 * стоят ли правила и маршруты выходов (rtnetlink).
 * sp — спека в памяти демона (последняя применённая; NULL — нет, и маршруты по ядру не
 * сверяются), outs — память сторожа (выбор устройств и отказы; NULL — файлы каталога состояния).
 * Найденное расхождение — строкой в stderr. */
void recon_decide(const struct recon_state *st, const struct recon_plan *p, const struct spec *sp,
                  struct fo_store *outs, struct recon_diff *d);
/* Есть ли что применять в ядро (набор правил или маршрутизация). */
int recon_diff_any(const struct recon_diff *d);
/* argv для `steer apply-commit` по решению: строки — в куче, ровно по размеру (список выходов в
 * --route и меток в --drop длинный, сколько выходов, столько и байт; раньше — буфер в килобайт, и
 * хвост списка молча не привязывался), av — не меньше 20 мест. Возврат — блок для free после
 * запуска; NULL — нехватка памяти (av не годен). */
char *recon_commit_argv(const struct recon_diff *d, const char *exe, const char *spec,
                        const char *state_dir, int nftc, char **av);
/* Применение прошло: запомнить план как применённое (ruleset — ставился ли набор правил). k —
 * ядро после nft -f от apply-commit (NULL или !ok — снимает сам демон, без сводки элементов). */
void recon_applied(struct recon_state *st, const struct recon_plan *p, const struct recon_diff *d,
                   const struct recon_kernel *k);
/* Подписи сторожа по плану: 1 — изменились (или прежних нет). Запоминает новые. */
int recon_watch_changed(struct recon_state *st, const struct recon_plan *p);
/* Применённое больше не известно (движок выключен, применение не прошло). */
void recon_forget(struct recon_state *st);

/* Сверка на проходе сторожа (шапка recon.c, «СВЕРКА НА ПРОХОДЕ СТОРОЖА»): номер и отпечаток
 * наших таблиц в ядре против снятых после нашего последнего nft -f — четыре обмена netlink, без
 * элементов. 0 — всё то же; 1 — разошлось (почему — в *why); 2 — таблицы нет (движок снят:
 * `steer down`, чинить нечего); -1 — сверять не с чем (применённое неизвестно) или ядро не
 * ответило. */
int recon_kernel_drift(const struct recon_state *st, const char **why);

/* Сводка элементов статических наборов наших таблиц в ядре (шапка recon.c, «СВЕРКА ЭЛЕМЕНТОВ»):
 * *sum — свёртка, не зависящая от порядка элементов, *n — сколько элементов вошло. 0 — снята;
 * -1 — ядро не ответило или доменный набор менялся на глазах. */
int recon_kernel_elems(uint64_t *sum, uint64_t *n);
/* Ребёнок apply-commit сразу после nft -f: номер, отпечаток и сводка элементов наших таблиц —
 * строкой `recon-kernel …` в f. */
void recon_kernel_print(FILE *f);
/* Найти в выводе apply-commit строку recon-kernel, разобрать в *k и вырезать (в ответ
 * человеку она не идёт). *n — новая длина. */
void recon_kernel_take(char *text, size_t *n, struct recon_kernel *k);

/* Номер таблицы inet ИМЯ в ядре (NFT_MSG_GETTABLE по netlink, без запуска nft): 0 — есть, номер
 * в *h (0 — ядро номеров таблиц не отдаёт, до Linux 4.16); 1 — таблицы нет; -1 — не спросить. */
int recon_table_handle(const char *name, uint64_t *h);

#endif
