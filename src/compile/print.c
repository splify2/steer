/* Печать дерева набора правил (ir.h) в текст nftables — один печатник на обе раскладки.
 *
 * Печатник знает только синтаксис nft и раскладку текста: отступы в четыре пробела, пустые
 * строки там, где их поставил строитель (obj->gap), «dnat ip to» в inet и «dnat to» в
 * таблице одного семейства. Что стоит в ядре, решают генератор (generate.c) и раскладка
 * старого ядра (legacy.c). Текст обязан совпадать с тем, что печатал прежний генератор, до
 * байта: на этом держится снимок tests/golden/ruleset. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <stdlib.h>

#include "spec.h"
#include "srs.h"
#include "ir.h"

#define LOG_W "steer[warn] apply: "

/* Elements come straight from the list files: the fitter (steer-aggregate) has
 * already decided what fits, and re-parsing them here would only add a second place
 * for the two to disagree. */
/* fam — семейство набора (4 — ipv4_addr, 6 — парный ipv6_addr, docs/architecture.md, «4б»):
 * строки другого семейства из того же файла идут в другой набор, здесь они пропускаются. */
static size_t emit_elements(FILE *f, const char *path, size_t already, int fam) {
    FILE *in = fopen(path, "r");
    /* Не die: читаемость всех файлов уже проверена (check_address_lists), и попасть сюда
     * можно только гонкой — список удалили между проверкой и генерацией. Ронять из-за неё
     * весь набор правил незачем: пропадут адреса одного списка, и про это будет сказано. */
    if (!in) {
        fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", path);
        return 0;
    }
    /* 512, а не 128: строка длиннее просто обрезалась бы посередине, и в набор уехал бы
     * обломок адреса — то есть тихо не тот адрес. */
    char line[512];
    size_t n = already;
    while (fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        /* Не-адреса пропускаем молча: про них уже сказал check_address_lists, а nft на
         * них отвергает ВЕСЬ набор, а не одну строку. */
        if (spec_line_family(p) != fam) continue;
        /* fputs, а не fprintf: на списке в сотни тысяч элементов разбор
         * форматной строки на каждый — это заметная доля времени apply. */
        if (n) fputs(", ", f);
        fputs(p, f);
        n++;
    }
    fclose(in);
    return n - already;
}

/* ---- подсети набора .srs (NFT_EL_SRS) -------------------------------------------------------
 * Потоком, как адресный список: читатель отдаёт префиксы по одному (srs_walk), и в памяти не
 * лежит ничего, кроме окна распаковки. Имена набора не читаются вовсе — их берёт резолвер. */
struct srs_pr { FILE *f; size_t n; int excl; int fam; };

static int srs_pr_cb(void *ctx, const struct srs_elem *el) {
    struct srs_pr *p = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != p->fam || el->excl != p->excl) return 0;
    /* Та же запись, что у srs-read: набор, подключённый ключом, и набор, разложенный в списки,
     * дают один и тот же текст. IPv6 — каноническая запись inet_ntop. */
    char b[64];
    if (p->fam == 6) {
        char a[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, el->addr, a, sizeof(a))) return 0;
        snprintf(b, sizeof(b), "%s/%d", a, el->plen);
    } else
        snprintf(b, sizeof(b), "%u.%u.%u.%u/%d", el->addr[0], el->addr[1], el->addr[2],
                 el->addr[3], el->plen);
    if (p->n) fputs(", ", p->f);
    fputs(b, p->f);
    p->n++;
    return 0;
}

static size_t emit_srs(FILE *f, const char *path, const struct ir_srs *src, size_t already,
                       int fam) {
    struct srs_pr p = { f, already, src->excl, fam };
    struct err e = {0};
    /* Не отказ: разбор набора уже прошёл (check_address_lists), и сюда попадают только гонкой —
     * файл заменили между проверкой и печатью. Пропадут подсети одного набора, про это сказано. */
    if (srs_walk(src->set, SRS_EL_CIDR, src->sel, srs_pr_cb, &p, &e) != 0)
        fprintf(stderr, LOG_W "%s — его подсети в набор правил не попали\n",
                e.msg[0] ? e.msg : path);
    return p.n - already;
}

/* ---- составной набор (NFT_EL_MIXED) ----------------------------------------------------------
 *
 * Ключ — адрес . протокол . порты, и ядро НЕ ПРИНИМАЕТ пересекающихся элементов: `10.0.0.0/8 .
 * 17 . 1-100` и `10.1.0.0/16 . 17 . 50-60` отвергаются целиком (EEXIST), auto-merge сливает
 * только точные повторы. А пересечения здесь обычны: подсеть без сужения из собственного
 * списка канала и та же подсеть с «udp 50000-65535» из набора, два списка одного хостинга.
 *
 * Поэтому элементы собираются в память и раскладываются заново: проход по адресной оси, на
 * каждом отрезке — множество действующих сужений, и оно печатается НЕПЕРЕСЕКАЮЩИМИСЯ ящиками
 * «протокол × порты» (l4_union_alloc). Соседние отрезки с одинаковым множеством сливаются.
 * Память — 32 байта на подсеть, и только у составного набора: он бывает лишь у канала со
 * смешанным сужением, а у обычного набора элементы по-прежнему идут потоком. */
struct mx_ev { uint64_t pos; uint32_t l4; int32_t d; };
struct mx {
    struct mx_ev *ev;
    size_t n, cap;
    /* Различные сужения набора — без предела: множество действующих на отрезке — битовая
     * строка из act_words(nl4) слов (по биту на сужение), её длина известна после сбора. */
    const struct l4match **l4s;
    size_t nl4, l4cap;
    int over;                   /* нет памяти на сужение */
};

static size_t act_words(size_t nl4) { return (nl4 + 63) / 64 + 1; }
static void act_flip(uint64_t *act, const int *cnt, size_t l) {
    if (cnt[l] > 0) act[l >> 6] |= 1ULL << (l & 63); else act[l >> 6] &= ~(1ULL << (l & 63));
}
static int act_any(const uint64_t *act, size_t nw) {
    for (size_t i = 0; i < nw; i++) if (act[i]) return 1;
    return 0;
}

static int mx_l4(struct mx *m, const struct l4match *l4) {
    for (size_t i = 0; i < m->nl4; i++)
        if (m->l4s[i] == l4 || l4match_same(m->l4s[i], l4)) return (int)i;
    if (m->nl4 == m->l4cap) {
        size_t cap = m->l4cap ? m->l4cap * 2 : 16;
        const struct l4match **v = realloc(m->l4s, cap * sizeof(*v));
        if (!v) { m->over = 1; return -1; }
        m->l4s = v;
        m->l4cap = cap;
    }
    m->l4s[m->nl4] = l4;
    return (int)m->nl4++;
}

static int mx_add(struct mx *m, uint32_t lo, uint32_t hi, int l4) {
    if (l4 < 0) return 0;
    if (m->n + 2 > m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 1024;
        struct mx_ev *e = realloc(m->ev, cap * sizeof(*e));
        if (!e) return -1;
        m->ev = e;
        m->cap = cap;
    }
    m->ev[m->n++] = (struct mx_ev){ lo, (uint32_t)l4, 1 };
    m->ev[m->n++] = (struct mx_ev){ (uint64_t)hi + 1, (uint32_t)l4, -1 };
    return 0;
}

struct mx_srs { struct mx *m; const struct l4match *eff; };
static int mx_srs_cb(void *ctx, const struct srs_elem *el) {
    struct mx_srs *c = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != 4 || el->excl) return 0;
    uint32_t a = ((uint32_t)el->addr[0] << 24) | ((uint32_t)el->addr[1] << 16) |
                 ((uint32_t)el->addr[2] << 8) | el->addr[3];
    uint32_t span = el->plen >= 32 ? 0 : (el->plen <= 0 ? 0xFFFFFFFFu : (0xFFFFFFFFu >> el->plen));
    return mx_add(c->m, a, a | span, mx_l4(c->m, &c->eff[el->clause])) ? -1 : 0;
}

/* Адресная строка списка → диапазон: «a.b.c.d», «a.b.c.d/n», «a-b». 0 — не адрес. */
static int line_range(const char *p, uint32_t *lo, uint32_t *hi) {
    char buf[64];
    size_t n = strcspn(p, " \t");
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, p, n);
    buf[n] = '\0';
    char *dash = strchr(buf, '-'), *slash = strchr(buf, '/');
    struct in_addr a, b;
    if (dash) {
        *dash = '\0';
        if (inet_pton(AF_INET, buf, &a) != 1 || inet_pton(AF_INET, dash + 1, &b) != 1) return 0;
        *lo = ntohl(a.s_addr);
        *hi = ntohl(b.s_addr);
        return *lo <= *hi;
    }
    int plen = 32;
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 32) return 0;
        plen = (int)v;
    }
    if (inet_pton(AF_INET, buf, &a) != 1) return 0;
    uint32_t span = plen >= 32 ? 0 : (plen <= 0 ? 0xFFFFFFFFu : (0xFFFFFFFFu >> plen));
    *lo = ntohl(a.s_addr) & ~span;
    *hi = *lo | span;
    return 1;
}

static int ev_cmp(const void *a, const void *b) {
    const struct mx_ev *x = a, *y = b;
    return x->pos < y->pos ? -1 : x->pos > y->pos;
}

static void addr_text(uint32_t lo, uint32_t hi, char *dst, size_t n) {
    uint32_t span = hi - lo;
    int aligned = ((span + 1u) & span) == 0 && (lo & span) == 0;   /* степень двойки и выровнен */
    if (lo == 0 && hi == 0xFFFFFFFFu) aligned = 1;
    if (aligned) {
        int plen = 32;
        while (plen > 0 && (span >> (32 - plen)) != 0) plen--;
        if (lo == 0 && hi == 0xFFFFFFFFu) plen = 0;
        if (plen == 32)
            snprintf(dst, n, "%u.%u.%u.%u", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255, lo & 255);
        else
            snprintf(dst, n, "%u.%u.%u.%u/%d", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255,
                     lo & 255, plen);
        return;
    }
    snprintf(dst, n, "%u.%u.%u.%u-%u.%u.%u.%u", lo >> 24, (lo >> 16) & 255, (lo >> 8) & 255,
             lo & 255, hi >> 24, (hi >> 16) & 255, (hi >> 8) & 255, hi & 255);
}

/* Один отрезок адресов с множеством сужений act — непересекающимися ящиками. */
static void mx_print(FILE *f, const struct mx *m, uint64_t lo, uint64_t hi, const uint64_t *act,
                     size_t *written) {
    const struct l4match **ms = malloc((m->nl4 ? m->nl4 : 1) * sizeof(*ms));
    size_t k = 0, nb = 0;
    struct l4box *box = NULL;
    if (ms) {
        for (size_t b = 0; b < m->nl4; b++) if (act[b >> 6] & (1ULL << (b & 63))) ms[k++] = m->l4s[b];
        box = l4_union_alloc(ms, k, &nb);
        free(ms);
    }
    if (!box) { fprintf(stderr, LOG_W "составной набор: нет памяти на ящики сужений\n"); return; }
    char at[40], bt[48];
    addr_text((uint32_t)lo, (uint32_t)hi, at, sizeof(at));
    for (size_t j = 0; j < nb; j++) {
        l4_box_text(&box[j], bt, sizeof(bt));
        fprintf(f, (*written)++ ? ", %s . %s" : "        elements = { %s . %s", at, bt);
    }
    free(box);
}

/* ЗАСЕВ В СОСТАВНОМ НАБОРЕ (g_print_seed, ir.h). Поддельный адрес ложится событиями той же оси
 * с сужениями совпавших частей канала — их объединение и раскладку на ящики делает тот же проход,
 * что и у списков, и результат совпадает с ящиками резолвера (dch_boxes), когда список канала сам
 * этот адрес не покрывает.
 *
 * Одно отличие от списков: засеянный адрес НЕ сливается с соседними отрезками. Соседние
 * поддельные адреса одного канала — обычное дело (пул раздаётся подряд), и слитый отрезок
 * «198.18.0.1-198.18.0.3 . …» был бы для резолвера чужим элементом: снять адрес имени, ушедшего из
 * канала (dch_del, точным ключом), он бы не смог, и имя продолжало бы уходить в прежний выход до
 * следующей замены таблицы. Граница отрезков b соседствует с засеянным адресом F, когда b == F
 * (отрезок начинается с него) или b == F + 1 (отрезок им кончается). Засев отсортирован по адресу
 * (fpseed.c), поиск — бинарный. */
static uint32_t seed_a4(const struct ir_seed *s) {
    return ((uint32_t)s->a[0] << 24) | ((uint32_t)s->a[1] << 16) | ((uint32_t)s->a[2] << 8) |
           s->a[3];
}

static int seed_edge4(const struct ir_seed *s, size_t n, uint64_t b) {
    uint64_t lo_v = b ? b - 1 : 0;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (seed_a4(&s[mid]) < lo_v) lo = mid + 1;
        else hi = mid;
    }
    for (size_t i = lo; i < n && i < lo + 2; i++) {
        uint64_t a = seed_a4(&s[i]);
        if (a == b || a + 1 == b) return 1;
    }
    return 0;
}

static const struct l4match g_seed_none;

static void mx_add_seed4(struct mx *m, const struct ir_seed *seed, size_t nseed) {
    for (size_t i = 0; i < nseed; i++) {
        uint32_t a = seed_a4(&seed[i]);
        if (!seed[i].l4_n) { mx_add(m, a, a, mx_l4(m, &g_seed_none)); continue; }
        for (size_t k = 0; k < seed[i].l4_n; k++) mx_add(m, a, a, mx_l4(m, seed[i].l4[k]));
    }
}

static void emit_mixed(FILE *f, const struct ir_mixed *mix, const struct ir_seed *seed,
                       size_t nseed) {
    struct mx m;
    memset(&m, 0, sizeof(m));
    for (size_t i = 0; mix && i < mix->n; i++) {
        const struct ir_mixed_src *s = &mix->v[i];
        if (s->set) {
            struct mx_srs c = { &m, s->eff };
            struct err e = {0};
            if (srs_walk(s->set, SRS_EL_CIDR, s->sel, mx_srs_cb, &c, &e) != 0)
                fprintf(stderr, LOG_W "%s — его подсети в набор правил не попали\n",
                        e.msg[0] ? e.msg : s->path);
            continue;
        }
        FILE *in = fopen(s->path, "r");
        if (!in) {
            fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", s->path);
            continue;
        }
        int l4 = mx_l4(&m, s->l4);
        char line[512];
        while (fgets(line, sizeof(line), in)) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!*p || *p == '#' || *p == ';' || spec_line_family(p) != 4) continue;
            uint32_t lo, hi;
            if (line_range(p, &lo, &hi) && mx_add(&m, lo, hi, l4) != 0) break;
        }
        fclose(in);
    }
    mx_add_seed4(&m, seed, nseed);
    if (m.over)
        fprintf(stderr, LOG_W "составной набор: не хватило памяти на варианты сужения\n");
    qsort(m.ev, m.n, sizeof(m.ev[0]), ev_cmp);
    size_t nw = act_words(m.nl4);
    int *cnt = calloc(m.nl4 ? m.nl4 : 1, sizeof(*cnt));
    uint64_t *act = calloc(2 * nw, sizeof(*act)), *pact = act ? act + nw : NULL;
    if (!cnt || !act) {
        fprintf(stderr, LOG_W "составной набор: нет памяти — элементы не напечатаны\n");
        free(cnt); free(act); free(m.ev); free(m.l4s);
        return;
    }
    uint64_t prev = 0;
    struct { uint64_t lo, hi; int have; } pend = { 0, 0, 0 };
    size_t written = 0;
    for (size_t i = 0; i <= m.n; ) {
        uint64_t pos = i < m.n ? m.ev[i].pos : ((uint64_t)1 << 32);
        /* Отрезок [prev, pos) с множеством act — к отложенному, если продолжает его (и граница
         * между ними — не край засеянного адреса, см. seed_edge4). */
        if (pos > prev && act_any(act, nw)) {
            if (pend.have && !memcmp(pact, act, nw * sizeof(*act)) && pend.hi + 1 == prev &&
                !(nseed && seed_edge4(seed, nseed, prev))) {
                pend.hi = pos - 1;
            } else {
                if (pend.have) mx_print(f, &m, pend.lo, pend.hi, pact, &written);
                pend.lo = prev;
                pend.hi = pos - 1;
                memcpy(pact, act, nw * sizeof(*act));
                pend.have = 1;
            }
        }
        if (i == m.n) break;
        for (; i < m.n && m.ev[i].pos == pos; i++) {
            size_t l = m.ev[i].l4;
            cnt[l] += m.ev[i].d;
            act_flip(act, cnt, l);
        }
        prev = pos;
    }
    if (pend.have) mx_print(f, &m, pend.lo, pend.hi, pact, &written);
    if (written) fprintf(f, " }\n");
    free(cnt);
    free(act);
    free(m.ev);
    free(m.l4s);
}

/* ---- составной набор IPv6 (ipv6_addr . inet_proto . inet_service) ----------------------------
 *
 * Та же раскладка, что у emit_mixed выше, на 128-битной оси адресов: парный набор составной
 * группы (docs/architecture.md, «4б»). Отдельной копией, а не общим кодом с IPv4: на роутерах
 * mips и arm нет __int128, и ось IPv4 пришлось бы тоже перевести на пару слов — ради того,
 * чтобы текст IPv4 остался прежним до байта, её не трогаем. Позиция конца отрезка — hi + 1, и у
 * последнего адреса оси она «за краем» (inf). */
struct a128 { uint64_t hi, lo; };
struct mx6_ev { struct a128 pos; uint8_t inf; uint32_t l4; int32_t d; };
struct mx6 { struct mx6_ev *ev; size_t n, cap; struct mx lm; };

static int a128_cmp(struct a128 a, struct a128 b) {
    if (a.hi != b.hi) return a.hi < b.hi ? -1 : 1;
    return a.lo < b.lo ? -1 : a.lo > b.lo;
}

static struct a128 a128_from(const uint8_t *b) {
    struct a128 a = { 0, 0 };
    for (int i = 0; i < 8; i++) a.hi = (a.hi << 8) | b[i];
    for (int i = 8; i < 16; i++) a.lo = (a.lo << 8) | b[i];
    return a;
}

static void a128_bytes(struct a128 a, uint8_t *b) {
    for (int i = 7; i >= 0; i--) { b[i] = (uint8_t)a.hi; a.hi >>= 8; }
    for (int i = 15; i >= 8; i--) { b[i] = (uint8_t)a.lo; a.lo >>= 8; }
}

/* Маска хвоста префикса длины plen: биты, которые у сети — нули, а у последнего адреса — единицы. */
static struct a128 a128_span(int plen) {
    struct a128 s = { 0, 0 };
    if (plen <= 0) { s.hi = s.lo = ~0ULL; return s; }
    if (plen >= 128) return s;
    if (plen < 64) { s.hi = ~0ULL >> plen; s.lo = ~0ULL; }
    else s.lo = plen == 64 ? ~0ULL : ~0ULL >> (plen - 64);
    return s;
}

static int mx6_add(struct mx6 *m, struct a128 lo, struct a128 hi, int l4) {
    if (l4 < 0) return 0;
    if (m->n + 2 > m->cap) {
        size_t cap = m->cap ? m->cap * 2 : 256;
        struct mx6_ev *e = realloc(m->ev, cap * sizeof(*e));
        if (!e) return -1;
        m->ev = e;
        m->cap = cap;
    }
    struct a128 end = hi;
    uint8_t inf = 0;
    if (++end.lo == 0 && ++end.hi == 0) inf = 1;
    m->ev[m->n++] = (struct mx6_ev){ lo, 0, (uint32_t)l4, 1 };
    m->ev[m->n++] = (struct mx6_ev){ end, inf, (uint32_t)l4, -1 };
    return 0;
}

struct mx6_srs { struct mx6 *m; const struct l4match *eff; };
static int mx6_srs_cb(void *ctx, const struct srs_elem *el) {
    struct mx6_srs *c = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != 6 || el->excl) return 0;
    struct a128 a = a128_from(el->addr), s = a128_span(el->plen);
    a.hi &= ~s.hi;
    a.lo &= ~s.lo;
    struct a128 b = { a.hi | s.hi, a.lo | s.lo };
    return mx6_add(c->m, a, b, mx_l4(&c->m->lm, &c->eff[el->clause])) ? -1 : 0;
}

/* Строка IPv6 списка → диапазон: «адрес», «адрес/длина», «a-b». 0 — не адрес IPv6. */
static int line_range6(const char *p, struct a128 *lo, struct a128 *hi) {
    char buf[96];
    size_t n = strcspn(p, " \t");
    if (n >= sizeof(buf)) return 0;
    memcpy(buf, p, n);
    buf[n] = '\0';
    char *dash = strchr(buf, '-'), *slash = strchr(buf, '/');
    uint8_t a[16], b[16];
    if (dash) {
        *dash = '\0';
        if (inet_pton(AF_INET6, buf, a) != 1 || inet_pton(AF_INET6, dash + 1, b) != 1) return 0;
        *lo = a128_from(a);
        *hi = a128_from(b);
        return a128_cmp(*lo, *hi) <= 0;
    }
    int plen = 128;
    if (slash) {
        *slash = '\0';
        char *end = NULL;
        long v = strtol(slash + 1, &end, 10);
        if (!end || *end || v < 0 || v > 128) return 0;
        plen = (int)v;
    }
    if (inet_pton(AF_INET6, buf, a) != 1) return 0;
    struct a128 s = a128_span(plen);
    *lo = a128_from(a);
    lo->hi &= ~s.hi;
    lo->lo &= ~s.lo;
    hi->hi = lo->hi | s.hi;
    hi->lo = lo->lo | s.lo;
    return 1;
}

static int ev6_cmp(const void *x, const void *y) {
    const struct mx6_ev *a = x, *b = y;
    if (a->inf != b->inf) return a->inf ? 1 : -1;
    return a128_cmp(a->pos, b->pos);
}

/* Отрезок [lo, hi] текстом: префикс, если он выровнен, иначе «lo-hi». */
static void addr6_text(struct a128 lo, struct a128 hi, char *dst, size_t n) {
    for (int plen = 0; plen <= 128; plen++) {
        struct a128 s = a128_span(plen);
        if ((lo.hi & s.hi) || (lo.lo & s.lo)) continue;
        if ((lo.hi | s.hi) != hi.hi || (lo.lo | s.lo) != hi.lo) continue;
        uint8_t b[16];
        char t[INET6_ADDRSTRLEN];
        a128_bytes(lo, b);
        inet_ntop(AF_INET6, b, t, sizeof(t));
        if (plen == 128) snprintf(dst, n, "%s", t);
        else snprintf(dst, n, "%s/%d", t, plen);
        return;
    }
    uint8_t b1[16], b2[16];
    char t1[INET6_ADDRSTRLEN], t2[INET6_ADDRSTRLEN];
    a128_bytes(lo, b1);
    a128_bytes(hi, b2);
    inet_ntop(AF_INET6, b1, t1, sizeof(t1));
    inet_ntop(AF_INET6, b2, t2, sizeof(t2));
    snprintf(dst, n, "%s-%s", t1, t2);
}

static void mx6_print(FILE *f, const struct mx *lm, struct a128 lo, struct a128 hi,
                      const uint64_t *act, size_t *written) {
    const struct l4match **ms = malloc((lm->nl4 ? lm->nl4 : 1) * sizeof(*ms));
    size_t k = 0, nb = 0;
    struct l4box *box = NULL;
    if (ms) {
        for (size_t b = 0; b < lm->nl4; b++) if (act[b >> 6] & (1ULL << (b & 63))) ms[k++] = lm->l4s[b];
        box = l4_union_alloc(ms, k, &nb);
        free(ms);
    }
    if (!box) { fprintf(stderr, LOG_W "составной набор: нет памяти на ящики сужений\n"); return; }
    char at[2 * INET6_ADDRSTRLEN + 8], bt[48];
    addr6_text(lo, hi, at, sizeof(at));
    for (size_t j = 0; j < nb; j++) {
        l4_box_text(&box[j], bt, sizeof(bt));
        fprintf(f, (*written)++ ? ", %s . %s" : "        elements = { %s . %s", at, bt);
    }
    free(box);
}

/* Засев IPv6 — тем же приёмом, что seed_edge4 и mx_add_seed4 у IPv4: засеянный адрес не
 * сливается с соседями (граница prev соседствует с F, когда prev == F или prev == F + 1). */
static int seed_edge6(const struct ir_seed *s, size_t n, struct a128 b) {
    struct a128 bm = b;
    if (bm.lo-- == 0) bm.hi--;
    int b0 = !b.hi && !b.lo;
    size_t lo = 0, hi = n;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (!b0 && a128_cmp(a128_from(s[mid].a), bm) < 0) lo = mid + 1;
        else hi = mid;
    }
    for (size_t i = lo; i < n && i < lo + 2; i++) {
        struct a128 a = a128_from(s[i].a);
        if (!a128_cmp(a, b) || (!b0 && !a128_cmp(a, bm))) return 1;
    }
    return 0;
}

static void emit_mixed6(FILE *f, const struct ir_mixed *mix, const struct ir_seed *seed,
                        size_t nseed) {
    struct mx6 m;
    memset(&m, 0, sizeof(m));
    for (size_t i = 0; mix && i < mix->n; i++) {
        const struct ir_mixed_src *s = &mix->v[i];
        if (s->set) {
            struct mx6_srs c = { &m, s->eff };
            struct err e = {0};
            if (srs_walk(s->set, SRS_EL_CIDR, s->sel, mx6_srs_cb, &c, &e) != 0)
                fprintf(stderr, LOG_W "%s — его подсети в набор правил не попали\n",
                        e.msg[0] ? e.msg : s->path);
            continue;
        }
        FILE *in = fopen(s->path, "r");
        if (!in) {
            fprintf(stderr, LOG_W "%s: список исчез во время сборки набора правил\n", s->path);
            continue;
        }
        int l4 = mx_l4(&m.lm, s->l4);
        char line[512];
        while (fgets(line, sizeof(line), in)) {
            char *nl = strpbrk(line, "\r\n");
            if (nl) *nl = '\0';
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            if (!*p || *p == '#' || *p == ';' || spec_line_family(p) != 6) continue;
            struct a128 lo, hi;
            if (line_range6(p, &lo, &hi) && mx6_add(&m, lo, hi, l4) != 0) break;
        }
        fclose(in);
    }
    for (size_t i = 0; i < nseed; i++) {
        struct a128 a = a128_from(seed[i].a);
        if (!seed[i].l4_n) { mx6_add(&m, a, a, mx_l4(&m.lm, &g_seed_none)); continue; }
        for (size_t k = 0; k < seed[i].l4_n; k++) mx6_add(&m, a, a, mx_l4(&m.lm, seed[i].l4[k]));
    }
    if (m.lm.over)
        fprintf(stderr, LOG_W "составной набор: не хватило памяти на варианты сужения\n");
    qsort(m.ev, m.n, sizeof(m.ev[0]), ev6_cmp);
    size_t nw = act_words(m.lm.nl4);
    int *cnt = calloc(m.lm.nl4 ? m.lm.nl4 : 1, sizeof(*cnt));
    uint64_t *act = calloc(2 * nw, sizeof(*act)), *pact = act ? act + nw : NULL;
    if (!cnt || !act) {
        fprintf(stderr, LOG_W "составной набор: нет памяти — элементы не напечатаны\n");
        free(cnt); free(act); free(m.ev); free(m.lm.l4s);
        return;
    }
    struct a128 prev = { 0, 0 };
    struct { struct a128 lo, hi; int have; } pend;
    memset(&pend, 0, sizeof(pend));
    size_t written = 0;
    for (size_t i = 0; i <= m.n; ) {
        /* Позиция следующего события; за последним — край оси (inf). */
        int inf = i == m.n || m.ev[i].inf;
        struct a128 pos = i < m.n ? m.ev[i].pos : prev;
        if (act_any(act, nw) && (inf || a128_cmp(pos, prev) > 0)) {
            /* Отрезок [prev, pos) — его последний адрес pos - 1 (у края оси — все единицы). */
            struct a128 last;
            if (inf) last.hi = last.lo = ~0ULL;
            else { last = pos; if (last.lo-- == 0) last.hi--; }
            struct a128 nx = pend.hi;
            int adj = pend.have && !(++nx.lo == 0 && ++nx.hi == 0) && !a128_cmp(nx, prev);
            if (adj && nseed && seed_edge6(seed, nseed, prev)) adj = 0;
            if (pend.have && !memcmp(pact, act, nw * sizeof(*act)) && adj) {
                pend.hi = last;
            } else {
                if (pend.have) mx6_print(f, &m.lm, pend.lo, pend.hi, pact, &written);
                pend.lo = prev;
                pend.hi = last;
                memcpy(pact, act, nw * sizeof(*act));
                pend.have = 1;
            }
        }
        if (i == m.n) break;
        size_t j = i;
        for (; j < m.n && m.ev[j].inf == m.ev[i].inf && !a128_cmp(m.ev[j].pos, m.ev[i].pos); j++) {
            size_t l = m.ev[j].l4;
            cnt[l] += m.ev[j].d;
            act_flip(act, cnt, l);
        }
        if (inf) break;          /* событие на краю оси — дальше отрезков нет */
        prev = pos;
        i = j;
    }
    if (pend.have) mx6_print(f, &m.lm, pend.lo, pend.hi, pact, &written);
    if (written) fprintf(f, " }\n");
    free(cnt);
    free(act);
    free(m.ev);
    free(m.lm.l4s);
}

/* КАРТА ПОДМЕНЫ fake→real ЗАСЕВАЕТСЯ ПРЯМО В НАБОРЕ ПРАВИЛ — из файла состояния резолвера
 * (<state-dir>/fakeip.state, строки «домен\tподдельный\tнастоящий»), а не остаётся пустой до
 * перезапуска dnsd.
 *
 * ЗАЧЕМ. apply пересобирает таблицу целиком, и карта на мгновение исчезала вместе с ней; dnsd
 * восстанавливал её только при своём перезапуске, секундой позже. Запрос, пришедший в это окно,
 * не мог добавить подмену (карты нет), и dnsd по правилу fail-open отдавал клиенту НАСТОЯЩИЙ
 * адрес: сайт, который человек велел вести в туннель, уходил напрямую, а клиент запоминал этот
 * адрес на весь TTL записи. Снято с живого роутера: после «Применить» посреди просмотра YouTube
 * узел googlevideo остался в состоянии без настоящего адреса, а ролики не открывались до
 * перезапуска браузера — уже при исправном туннеле. С засеянной картой окна нет: пакеты к
 * поддельным адресам переводятся тем же набором правил, который их и метит.
 *
 * Только строки с настоящим адресом: без него подменять нечего, и dnsd такую запись тоже не
 * восстанавливает. Повтор поддельного адреса пропускается — nft отвергает набор с двойным
 * ключом целиком, а в файле повторы законны (первая раздача побеждает, как у dnsd). Файла нет —
 * карта пустая, как и раньше: так на роутере, где резолвер ещё ничего не раздал. */
/* fam 6 — карта fakeip6: поддельный IPv6 — пара поддельного IPv4 из второго поля (fakeip6_of),
 * настоящий — четвёртое поле строки (настоящий IPv6 из ответа AAAA). */
static void emit_fakeip_elements(FILE *f, const char *path, int fam) {
    FILE *s = fopen(path, "r");
    if (!s) return;
    static uint8_t seen[131072 / 8];       /* 198.18.0.0/15 — бит на адрес */
    memset(seen, 0, sizeof(seen));
    char line[1024];
    int n = 0;
    while (fgets(line, sizeof(line), s)) {
        char *t1 = strchr(line, '\t');
        if (!t1) continue;
        char *fake = t1 + 1;
        char *t2 = strchr(fake, '\t');
        if (!t2) continue;
        *t2 = '\0';
        char *real = t2 + 1;
        char *t3 = real + strcspn(real, "\t\r\n");
        char *real6 = *t3 == '\t' ? t3 + 1 : NULL;
        *t3 = '\0';
        struct in_addr a, b;
        if (inet_aton(fake, &a) == 0) continue;
        uint32_t fh = ntohl(a.s_addr);
        if ((fh & 0xfffe0000u) != 0xc6120000u) continue;   /* вне 198.18.0.0/15 — не наше */
        uint32_t idx = fh - 0xc6120000u;
        if (fam == 6) {
            if (!real6) continue;
            real6[strcspn(real6, "\t\r\n")] = '\0';
            uint8_t f6[16], r6[16];
            if (inet_pton(AF_INET6, real6, r6) != 1) continue;
            if (seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) continue;
            seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
            fakeip6_of(fh, f6);
            char fs6[INET6_ADDRSTRLEN], rs6[INET6_ADDRSTRLEN];
            if (!inet_ntop(AF_INET6, f6, fs6, sizeof(fs6)) ||
                !inet_ntop(AF_INET6, r6, rs6, sizeof(rs6))) continue;
            fprintf(f, n ? ",\n            %s : %s" : "        elements = { %s : %s", fs6, rs6);
            n++;
            continue;
        }
        if (inet_aton(real, &b) == 0 || b.s_addr == 0) continue;
        if (seen[idx >> 3] & (uint8_t)(1u << (idx & 7))) continue;
        seen[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        /* В набор едет РАЗОБРАННЫЙ адрес, а не байты строки. inet_aton принимает не только
         * точечную запись: «0xc6120009», «3323068425» и «198.18.9» — то же самое 198.18.0.9,
         * и проверку диапазона выше такая строка проходит честно. А nft такого ключа не
         * понимает и отвергает набор ЦЕЛИКОМ (`nft -f` атомарен) — то есть одна нетипичная
         * строка в файле состояния оставила бы роутер вообще без правил: ни маршрутизации,
         * ни подмены, ни меток. Раз адрес уже разобран, печатать надо его, а не то, из чего
         * он разобран.
         *
         * Два своих буфера, а не inet_ntoa дважды: inet_ntoa отдаёт статический буфер, и
         * второй вызов в том же fprintf перезаписал бы результат первого. */
        char fs[INET_ADDRSTRLEN], rs[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &a, fs, sizeof(fs)) ||
            !inet_ntop(AF_INET, &b, rs, sizeof(rs))) continue;
        fprintf(f, n ? ",\n            %s : %s" : "        elements = { %s : %s", fs, rs);
        n++;
    }
    if (n) fprintf(f, " }\n");
    fclose(s);
}

/* Элементы набора. Источник fakeip.state печатается своей раскладкой (пары по строке, и
 * строки elements нет вовсе, если пар нет); остальные — одной строкой через запятую.
 *
 * Строка elements у адресных источников печатается, даже если в файлах не нашлось ни одной
 * адресной строки: строитель кладёт файлы в набор, только когда check_address_lists насчитал
 * в них адреса, и пустым набор здесь выйдет лишь гонкой (список исчез после проверки) —
 * ровно как у прежнего генератора. */
/* ЗАСЕВ ИЗ ФАЙЛА СОСТОЯНИЯ — В ТЕКСТЕ ДЛЯ ЯДРА, НО НЕ В ОТПЕЧАТКЕ ПЛАНА.
 *
 * Apply-сверка демона (src/daemon/recon.c) решает «набор правил изменился» по отпечатку этого
 * текста. Карта fake-IP засевается из fakeip.state, а его резолвер дописывает на каждый новый
 * выданный адрес, — то есть с засевом отпечаток менялся от любого нового имени в сети, и
 * reload, reapply из init.d или apply из hotplug с той же спекой заменяли таблицу целиком:
 * транзакция nft на все списки (на больших — секунды процессора роутера), сброс и перезаливка
 * элементов, которые кладут резолвер и сторож, повторная отправка таблицы резолверу — ровно та
 * работа, от которой сверка и должна избавлять. Стенд tests/reconmatch.sh обходил это лишним
 * apply перед проверкой сверки с ядром.
 *
 * Засев от этого не нужен меньше, и снимать его из текста для ядра нельзя: он закрывает окно
 * между заменой таблицы и приходом таблицы к резолверу (почему — у emit_fakeip_elements выше;
 * docs/architecture.md, раздел 2, «Набор правил», «Порядок применения»). Но в отпечатке ему не
 * место: элементы, которые он ставит, в таблице, не заменявшейся с прошлой загрузки, уже стоят —
 * их туда при раздаче положил сам резолвер, — и заменять таблицу ради них незачем. Поэтому план
 * печатает текст без засева (g_print_state_seed = 0), а загрузка (ruleset_load, apply-commit и
 * подкоманда `steer apply`) — с ним, как прежде: как только набор правил всё же заменяется,
 * карта приходит засеянной из файла на момент замены. Сверку с ядром это не задевает: отпечаток
 * таблицы в ядре (nfd_table_fp) элементов именованных наборов не видит и так.
 *
 * ЗАСЕВ НАБОРОВ КАНАЛОВ fake-IP (перепроверка на QEMU, 2026-09-28). Карта одна закрывала только
 * половину окна: подмена после замены стоит, а набор канала, по которому пакет к поддельному
 * адресу получает метку выхода, приходил пустым до таблицы резолверу. Пакет клиента с
 * поддельным адресом в кэше разворачивался в настоящий адрес и уходил без метки — по таблице
 * main, в WAN, мимо выхода и мимо on_fail=drop (1-4 запроса на каждую замену на стенде). Теперь
 * в набор канала fake-IP тем же текстом ложатся поддельные адреса из того же файла — те, что
 * резолвер поставил бы туда после таблицы (решает его же код, fpseed.c;
 * печатник получает их по имени набора, g_print_seed), и подмена и метка появляются одной
 * транзакцией. Засев наборов идёт по тому же флагу, что засев карты, и в отпечаток плана не
 * входит по той же причине. Не собрался засев наборов — apply не засевает и карту
 * (g_print_state_seed = 0): подмена без решения о маршруте — ровно та утечка; поддельный адрес
 * без подмены до резолвера не уходит никуда (правило за dnat, generate.c, build_fakeip).
 *
 * Как элементы ложатся. Обычный набор — адресами в той же строке elements, что списки (второй
 * `elements =` в том же наборе nft молча ЗАМЕНЯЕТ первый — проверено на nftables 1.0.9).
 * auto-merge сольёт соседние поддельные адреса одного канала в отрезок; резолвер, которому потом
 * понадобится снять из набора один адрес, делит такой отрезок сам (dch_del, fakeip.c).
 * Составной — событиями той же раскладки, что списки (emit_mixed), и засеянный адрес там не
 * сливается с соседями (seed_edge4). Набор старой раскладки — hash (legacy.c, шаг 1): засев идёт в
 * динамическую половину, чьё имя — имя группы; составной hash засева не получает — ящиков
 * «протоколы × порты» hash не держит, и такой элемент отверг бы весь набор правил.
 *
 * Чего в тексте нет по-прежнему: элементов real-ip. Их память — только у резолвера (realip.c), а
 * ложиться текстом со сроком в набор с auto-merge они не могут: nft сливает соседние элементы в
 * один с timeout ПЕРВОГО (проверено: 10.0.0.4 со сроком 10 с и 10.0.0.5 со сроком час — один
 * «10.0.0.4/31 timeout 10s»), а элемент со сроком рядом с префиксом списка превращает и префикс в
 * истекающий. Их возвращает резолвер сразу после загрузки (apply.c, ruleset_load → supd_dnsd_reassert). Набор «пущен
 * напрямую» печатается пустым (метки упавших выходов ставят сторож и apply-commit по таблицам
 * выходов); карта раздачи balance — «все члены живы» по спеке, к живым её сразу после загрузки
 * приводит fog_balance_adopt. Адресные списки и наборы .srs — выбор человека, и их смена —
 * законная причина заменить набор. */
int g_print_state_seed = 1;
size_t (*g_print_seed)(const char *set, int fam, const struct ir_seed **out);

static void print_elements(FILE *f, const struct nft_set *s) {
    /* Семейство набора — по его типу: парный набор IPv6 («<группа>6», docs/architecture.md,
     * «4б») берёт из тех же файлов и наборов .srs строки IPv6, обычный — IPv4. */
    int fam = s->key && !strncmp(s->key, "ipv6_addr", 9) ? 6 : 4;
    /* Засев набора канала fake-IP (g_print_seed): спрашивается только у набора со сроками — такие
     * заводит генератор доменной группе (и динамической половине старой раскладки), — и только
     * при засеве вообще. Составной набор без интервалов (hash старой раскладки) засева не
     * получает: ящики «протоколы × порты» — интервалы. */
    int composite = s->key && strstr(s->key, " . ") != NULL;
    const struct ir_seed *seed = NULL;
    size_t nseed = 0;
    if (g_print_state_seed && g_print_seed && !s->data && (s->flags & NFT_SET_TIMEOUT) &&
        (!composite || (s->flags & NFT_SET_INTERVAL)))
        nseed = g_print_seed(s->o.name, fam, &seed);
    const struct ir_mixed *mix = NULL;
    int list = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_FAKEIP_STATE) {
            if (g_print_state_seed) emit_fakeip_elements(f, e->s, fam);
        }
        else if (e->k == NFT_EL_MIXED) mix = e->p;
        else list = 1;
    }
    /* Составной набор — одной раскладкой: и его списки (источник у него один, NFT_EL_MIXED), и
     * засев; без засева текст тот же, что прежде. */
    if (composite) {
        if (mix || nseed) {
            if (fam == 6) emit_mixed6(f, mix, seed, nseed);
            else emit_mixed(f, mix, seed, nseed);
        }
        return;
    }
    if (mix) {
        if (fam == 6) emit_mixed6(f, mix, NULL, 0);
        else emit_mixed(f, mix, NULL, 0);
    }
    if (!list && !nseed) return;
    fprintf(f, "        elements = { ");
    size_t written = 0;
    for (const struct nft_elsrc *e = s->els; e; e = e->next) {
        if (e->k == NFT_EL_ADDR_FILE) written += emit_elements(f, e->s, written, fam);
        else if (e->k == NFT_EL_SRS) written += emit_srs(f, e->s, e->p, written, fam);
        else if (e->k == NFT_EL_VALUE) {
            if (written++) fputs(", ", f);
            fputs(e->s, f);
        }
    }
    /* Засев — в ту же строку: второй `elements =` в наборе заменил бы списки, а не дополнил. */
    for (size_t i = 0; i < nseed; i++) {
        char t[INET6_ADDRSTRLEN];
        if (!inet_ntop(fam == 6 ? AF_INET6 : AF_INET, seed[i].a, t, sizeof(t))) continue;
        if (written++) fputs(", ", f);
        fputs(t, f);
    }
    fprintf(f, " }\n");
}

static void print_set(FILE *f, const struct nft_set *s) {
    fprintf(f, "%s    %s %s {\n", s->o.gap ? "\n" : "", s->data ? "map" : "set", s->o.name);
    if (s->data) fprintf(f, "        type %s : %s;\n", s->key, s->data);
    else fprintf(f, "        type %s\n", s->key);
    if (s->flags) {
        fprintf(f, "        flags ");
        const char *sep = "";
        if (s->flags & NFT_SET_INTERVAL) { fprintf(f, "%sinterval", sep); sep = ","; }
        if (s->flags & NFT_SET_TIMEOUT) fprintf(f, "%stimeout", sep);
        fprintf(f, "\n");
    }
    if (s->auto_merge) fprintf(f, "        auto-merge\n");
    print_elements(f, s);
    fprintf(f, "    }\n");
}

static void print_expr(FILE *f, const struct nft_table *t, const struct nft_rule *r,
                       const struct nft_expr *x) {
    switch (x->k) {
    case NFT_X_RAW:
    case NFT_X_MARKSET:
    case NFT_X_NOTRACK:
    case NFT_X_FRAG6:
        fputs(x->text, f);
        break;
    case NFT_X_FAMILY:
        fprintf(f, "meta nfproto ipv%d", x->fam);
        break;
    case NFT_X_SETREF:
        fprintf(f, "%s @%s", x->text, x->arg);
        break;
    case NFT_X_COUNTER:
        /* Нули — коротким `counter`: так вывод `--dry-run` на чистой машине остаётся тем же
         * текстом, что и раньше. */
        if (r->pkts || r->bytes) fprintf(f, "counter packets %lu bytes %lu", r->pkts, r->bytes);
        else fputs("counter", f);
        break;
    case NFT_X_DNAT:
        /* В таблице одного семейства семейство и так известно, и слово ip после dnat там
         * лишнее; в inet без него nft не знает, адрес какого семейства подставлять. */
        fprintf(f, "dnat %sto %s map @%s",
                t->fam != NFT_FAM_INET ? "" : r->fam == 6 ? "ip6 " : "ip ", x->text, x->arg);
        break;
    case NFT_X_JUMP:
        fprintf(f, "jump %s", x->arg);
        break;
    }
}

static void print_rule(FILE *f, const struct nft_table *t, const struct nft_rule *r) {
    fputs("        ", f);
    int first = 1;
    for (const struct nft_expr *x = r->x; x; x = x->next) {
        /* «meta nfproto ipvN» в таблице ip/ip6 ничего не сужает — семейство задала таблица. */
        if (x->k == NFT_X_FAMILY && t->fam != NFT_FAM_INET) continue;
        if (!first) fputc(' ', f);
        print_expr(f, t, r, x);
        first = 0;
    }
    if (r->comment) fprintf(f, "%scomment \"%s\"", first ? "" : " ", r->comment);
    fputc('\n', f);
}

static void print_chain(FILE *f, const struct nft_table *t, const struct nft_chain *c) {
    fprintf(f, "%s    chain %s {\n", c->o.gap ? "\n" : "", c->o.name);
    if (c->type) {
        char prio[48];
        ir_prio_str(c, prio, sizeof(prio));
        /* Устройства — между хуком и приоритетом, как их пишет и печатает nft. */
        fprintf(f, "        type %s hook %s%s%s priority %s; policy %s;\n",
                c->type, c->hook, c->devices ? " " : "", c->devices ? c->devices : "", prio,
                c->policy ? c->policy : "accept");
    }
    for (const struct nft_rule *r = c->rules; r; r = r->next) print_rule(f, t, r);
    fprintf(f, "    }\n");
}

static const char *fam_name(enum nft_family fam) {
    switch (fam) {
    case NFT_FAM_IP: return "ip";
    case NFT_FAM_IP6: return "ip6";
    case NFT_FAM_INET: break;
    }
    return "inet";
}

void nft_print(const struct nft_rs *rs, FILE *f) {
    for (const struct nft_table *t = rs->tables; t; t = t->next) {
        fprintf(f, "table %s %s {\n", fam_name(t->fam), t->name);
        for (struct nft_obj *o = t->objs; o; o = o->next) {
            if (o->k == NFT_OBJ_SET) print_set(f, (const struct nft_set *)o);
            else print_chain(f, t, (const struct nft_chain *)o);
        }
        fprintf(f, "}\n");
    }
}
