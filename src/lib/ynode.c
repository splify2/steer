/* Дерево YAML-документа поверх событийного парсера libyaml — см. ynode.h.
 *
 * ПОЧЕМУ СОБЫТИЯ, А НЕ loader.c ИЗ libyaml. Загрузчик библиотеки строит свой yaml_document_t и
 * разворачивает алиасы в ссылки на узлы — то есть ровно то место, где живёт «ямл-бомба»: девять
 * строк `a: &a [*b, *b, ...]` дают миллиард узлов у того, кто обходит дерево. Сам парсер алиасы
 * не разворачивает никогда — он отдаёт событие ALIAS с именем, — поэтому опасность только у
 * потребителя событий, и здесь она закрыта целиком: алиас — отказ. Заодно своё дерево даёт то,
 * чего нет у загрузчика: предел узлов и глубины прямо по ходу разбора (отказ наступает раньше,
 * чем память кончится), проверку повторных ключей и узлы со строкой/столбцом в нашем виде.
 *
 * ПОЧЕМУ ЗАПРЕЩЁН И ЯКОРЬ, а не только алиас. Якорь без алиаса бесполезен, а якорь с алиасом —
 * отказ; разрешить якорь значило бы отказать человеку на строке алиаса, хотя намерение («хочу
 * переиспользовать кусок») видно уже на строке якоря. Спеке v2 переиспользование не нужно: всё,
 * что повторяется, — это имена (клиенты, списки, выходы), и правила ссылаются на них по имени.
 * JSON якорей не знает вовсе, так что спеки v1 запрет не задевает.
 *
 * Пределы размера, узлов и глубины — ynode.h (YDOC_MAX_*), там же и обоснование чисел. Размер
 * проверяется ДО разбора, узлы и глубина — по событиям: libyaml держит свои стеки в куче (не
 * рекурсией), и разбор останавливается на первом событии за пределом. */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "yaml.h"
#include "ynode.h"

/* ---- арена ------------------------------------------------------------------------------ */
/* Узлы, массивы детей и строки — кусками по 64 КБ; кусок под большую строку заводится своего
 * размера. Освобождение — проходом по списку кусков, поэтому ни один узел не освобождается
 * отдельно, и ошибка разбора на полпути не оставляет утечек. */
#define YARENA_CHUNK (64u << 10)

struct ychunk {
    struct ychunk *next;
    size_t used, cap;
    max_align_t data[];
};

struct ydoc {
    struct ychunk *arena;
    struct ynode *root;
    const char *name;
    size_t nodes;
};

static void *yalloc(struct ydoc *d, size_t n) {
    size_t a = sizeof(max_align_t);
    n = (n + a - 1) / a * a;
    struct ychunk *c = d->arena;
    if (!c || c->cap - c->used < n) {
        size_t cap = n > YARENA_CHUNK ? n : YARENA_CHUNK;
        c = malloc(sizeof(*c) + cap);
        if (!c) return NULL;
        c->used = 0;
        c->cap = cap;
        c->next = d->arena;
        d->arena = c;
    }
    void *p = (unsigned char *)c->data + c->used;
    c->used += n;
    return p;
}

static char *ystrdup(struct ydoc *d, const char *s, size_t n) {
    char *p = yalloc(d, n + 1);
    if (!p) return NULL;
    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

void ydoc_free(struct ydoc *d) {
    if (!d) return;
    for (struct ychunk *c = d->arena, *nx; c; c = nx) {
        nx = c->next;
        free(c);
    }
    free(d);
}

/* ---- сообщения -------------------------------------------------------------------------- */
/* err_set берёт формат с одним %s, а здесь их больше (имя, строка, столбец, текст): сообщение
 * собирается в буфер и уходит через "%s". Буфер меньше struct err нарочно — с запасом под то,
 * что вызывающий, пробрасывая отказ, добавит спереди. */
static int yfail(struct err *e, const char *name, unsigned line, unsigned col,
                 const char *fmt, const char *a) {
    char buf[900];
    int off = line ? snprintf(buf, sizeof(buf), "%s:%u:%u: ", name, line, col)
                   : snprintf(buf, sizeof(buf), "%s: ", name);
    if (off < 0) off = 0;
    if ((size_t)off >= sizeof(buf)) off = sizeof(buf) - 1;
    snprintf(buf + off, sizeof(buf) - off, fmt, a);
    return err_set(e, "%s", buf);
}

int ynode_err(struct err *e, const struct ydoc *d, const struct ynode *n,
              const char *fmt, const char *a) {
    return yfail(e, d ? d->name : "?", n ? n->line : 0, n ? n->col : 0, fmt, a);
}

/* Строка и столбец (с единицы) по смещению в буфере — для ошибок чтения, у которых libyaml
 * даёт только смещение, а не отметку. */
static void ypos(const char *buf, size_t len, size_t off, unsigned *line, unsigned *col) {
    unsigned l = 1, c = 1;
    for (size_t i = 0; i < off && i < len; i++) {
        if (buf[i] == '\n') { l++; c = 1; }
        else if (((unsigned char)buf[i] & 0xC0) != 0x80) c++;   /* символ, а не байт UTF-8 */
    }
    *line = l;
    *col = c;
}

/* Отказ самой libyaml. Текст problem/context — английский текст библиотеки («did not find
 * expected key»): переводить его своей таблицей значило бы разойтись с ней на первом же
 * обновлении, а место (строка, столбец) и так наше. */
static int ylib_fail(struct err *e, const char *name, const yaml_parser_t *p,
                     const char *buf, size_t len) {
    char msg[600];
    unsigned line, col;
    switch (p->error) {
    case YAML_MEMORY_ERROR:
        return yfail(e, name, 0, 0, "не хватило памяти на разбор YAML", NULL);
    case YAML_READER_ERROR:
        ypos(buf, len, p->problem_offset, &line, &col);
        snprintf(msg, sizeof(msg), "текст не читается как UTF-8/UTF-16: %s",
                 p->problem ? p->problem : "?");
        return yfail(e, name, line, col, "%s", msg);
    default:
        line = (unsigned)p->problem_mark.line + 1;
        col = (unsigned)p->problem_mark.column + 1;
        if (p->context)
            snprintf(msg, sizeof(msg), "ошибка YAML: %s (%s, начало в строке %u)",
                     p->problem ? p->problem : "?", p->context,
                     (unsigned)p->context_mark.line + 1);
        else
            snprintf(msg, sizeof(msg), "ошибка YAML: %s", p->problem ? p->problem : "?");
        /* Самая частая ошибка руками — табуляция в отступе, и текст библиотеки («found character
         * that cannot start any token») её не называет. */
        if (p->error == YAML_SCANNER_ERROR && p->problem_mark.index < len &&
            buf[p->problem_mark.index] == '\t') {
            size_t m = strlen(msg);
            snprintf(msg + m, sizeof(msg) - m, "; табуляция: отступ в YAML — только пробелы");
        }
        return yfail(e, name, line, col, "%s", msg);
    }
}

/* ---- сборка дерева по событиям ------------------------------------------------------------ */
/* Кадр — открытая коллекция: сам узел и растущий массив детей (в куче, пока коллекция не
 * закрыта; на закрытии переезжает в арену точного размера). Стек кадров — массив фиксированной
 * глубины: глубже YDOC_MAX_DEPTH разбор не заходит. */
struct yframe {
    struct ynode *node;
    struct ynode **v;
    size_t n, cap;
};

struct ybuild {
    struct ydoc *d;
    struct err *e;
    struct yframe st[YDOC_MAX_DEPTH];
    int depth;
};

static struct ynode *ynew(struct ybuild *b, enum ynode_kind kind, const yaml_event_t *ev) {
    if (++b->d->nodes > YDOC_MAX_NODES) {
        char lim[24];
        snprintf(lim, sizeof(lim), "%u", YDOC_MAX_NODES);
        yfail(b->e, b->d->name, (unsigned)ev->start_mark.line + 1,
              (unsigned)ev->start_mark.column + 1, "в документе больше %s узлов", lim);
        return NULL;
    }
    struct ynode *n = yalloc(b->d, sizeof(*n));
    if (!n) { yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL); return NULL; }
    memset(n, 0, sizeof(*n));
    n->kind = kind;
    n->style = YS_PLAIN;
    n->line = (unsigned)ev->start_mark.line + 1;
    n->col = (unsigned)ev->start_mark.column + 1;
    return n;
}

/* Якорь и тег — общие для скаляра и коллекций. */
static int yanchor_tag(struct ybuild *b, struct ynode *n, const yaml_char_t *anchor,
                       const yaml_char_t *tag) {
    if (anchor)
        return yfail(b->e, b->d->name, n->line, n->col,
                     "якорь &%s: якоря и алиасы в спеке не поддерживаются — повторяющееся "
                     "задаётся именем и ссылкой на него", (const char *)anchor);
    if (tag) {
        n->tag = ystrdup(b->d, (const char *)tag, strlen((const char *)tag));
        if (!n->tag) return yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL);
    }
    return 0;
}

/* Новый узел становится ребёнком открытой коллекции (или корнем). В отображение дети идут
 * парами «ключ, значение», и на чётном месте — ключ: он обязан быть скаляром. */
static int yattach(struct ybuild *b, struct ynode *n) {
    if (b->depth == 0) {
        b->d->root = n;
        return 0;
    }
    struct yframe *f = &b->st[b->depth - 1];
    if (f->node->kind == YN_MAP && f->n % 2 == 0 && n->kind != YN_SCALAR)
        return yfail(b->e, b->d->name, n->line, n->col,
                     "ключ отображения — не строка (составные ключи не поддерживаются)", NULL);
    if (f->n == f->cap) {
        size_t cap = f->cap ? f->cap * 2 : 8;
        struct ynode **v = realloc(f->v, cap * sizeof(*v));
        if (!v) return yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL);
        f->v = v;
        f->cap = cap;
    }
    f->v[f->n++] = n;
    return 0;
}

static int ypush(struct ybuild *b, struct ynode *n) {
    if (b->depth >= YDOC_MAX_DEPTH) {
        char lim[16];
        snprintf(lim, sizeof(lim), "%d", YDOC_MAX_DEPTH);
        return yfail(b->e, b->d->name, n->line, n->col, "вложенность глубже %s уровней", lim);
    }
    struct yframe *f = &b->st[b->depth++];
    f->node = n;
    f->v = NULL;
    f->n = f->cap = 0;
    return 0;
}

static int ykey_cmp(const void *a, const void *b) {
    const struct ynode *x = *(struct ynode *const *)a, *y = *(struct ynode *const *)b;
    int c = strcmp(x->str, y->str);
    if (c) return c;
    if (x->line != y->line) return x->line < y->line ? -1 : 1;
    return x->col < y->col ? -1 : x->col > y->col;
}

/* Повторный ключ: сортировкой копии ключей, а не попарным сравнением — отображение на сотню
 * тысяч ключей (предел узлов это позволяет) попарно считалось бы минутами. Называется ВТОРОЕ по
 * тексту вхождение (к нему и идёт человек), первое — строкой в тексте сообщения. */
static int ydupkeys(struct ybuild *b, struct ynode *map) {
    size_t n = map->len;
    if (n < 2) return 0;
    struct ynode **k = malloc(n * sizeof(*k));
    if (!k) return yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL);
    for (size_t i = 0; i < n; i++) k[i] = map->items[2 * i];
    qsort(k, n, sizeof(*k), ykey_cmp);
    int rc = 0;
    for (size_t i = 1; i < n; i++) {
        if (strcmp(k[i - 1]->str, k[i]->str) != 0) continue;
        char msg[600];
        snprintf(msg, sizeof(msg), "ключ \"%.400s\" повторяется (первый раз — строка %u)",
                 k[i]->str, k[i - 1]->line);
        rc = yfail(b->e, b->d->name, k[i]->line, k[i]->col, "%s", msg);
        break;
    }
    free(k);
    return rc;
}

static int ypop(struct ybuild *b) {
    struct yframe *f = &b->st[--b->depth];
    struct ynode *n = f->node;
    int rc = 0;
    if (f->n) {
        n->items = yalloc(b->d, f->n * sizeof(*n->items));
        if (!n->items) rc = yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL);
        else memcpy(n->items, f->v, f->n * sizeof(*n->items));
    }
    n->len = n->kind == YN_MAP ? f->n / 2 : f->n;
    free(f->v);
    f->v = NULL;
    if (rc == 0 && n->kind == YN_MAP) rc = ydupkeys(b, n);
    return rc;
}

static int yscalar(struct ybuild *b, const yaml_event_t *ev) {
    struct ynode *n = ynew(b, YN_SCALAR, ev);
    if (!n) return -1;
    if (yanchor_tag(b, n, ev->data.scalar.anchor, ev->data.scalar.tag) != 0) return -1;
    const char *v = (const char *)ev->data.scalar.value;
    size_t len = ev->data.scalar.length;
    if (memchr(v, 0, len))
        return yfail(b->e, b->d->name, n->line, n->col,
                     "в строке нулевой байт — такое значение обрезалось бы молча", NULL);
    switch (ev->data.scalar.style) {
    case YAML_SINGLE_QUOTED_SCALAR_STYLE: n->style = YS_SINGLE; break;
    case YAML_DOUBLE_QUOTED_SCALAR_STYLE: n->style = YS_DOUBLE; break;
    case YAML_LITERAL_SCALAR_STYLE:       n->style = YS_LITERAL; break;
    case YAML_FOLDED_SCALAR_STYLE:        n->style = YS_FOLDED; break;
    default:                              n->style = YS_PLAIN; break;
    }
    n->str = ystrdup(b->d, v, len);
    if (!n->str) return yfail(b->e, b->d->name, 0, 0, "не хватило памяти на дерево YAML", NULL);
    n->len = len;
    return yattach(b, n);
}

static int ycoll(struct ybuild *b, const yaml_event_t *ev, enum ynode_kind kind) {
    struct ynode *n = ynew(b, kind, ev);
    if (!n) return -1;
    const yaml_char_t *anchor = kind == YN_MAP ? ev->data.mapping_start.anchor
                                               : ev->data.sequence_start.anchor;
    const yaml_char_t *tag = kind == YN_MAP ? ev->data.mapping_start.tag
                                            : ev->data.sequence_start.tag;
    if (yanchor_tag(b, n, anchor, tag) != 0) return -1;
    if (yattach(b, n) != 0) return -1;
    return ypush(b, n);
}

/* Одно событие. 1 — поток кончился, 0 — дальше, -1 — отказ (текст в b->e). */
static int yevent(struct ybuild *b, const yaml_event_t *ev, int *docs) {
    switch (ev->type) {
    case YAML_STREAM_END_EVENT:
        return 1;
    case YAML_DOCUMENT_START_EVENT:
        if ((*docs)++)
            return yfail(b->e, b->d->name, (unsigned)ev->start_mark.line + 1,
                         (unsigned)ev->start_mark.column + 1,
                         "второй документ в потоке: ожидался один документ", NULL);
        return 0;
    case YAML_ALIAS_EVENT:
        return yfail(b->e, b->d->name, (unsigned)ev->start_mark.line + 1,
                     (unsigned)ev->start_mark.column + 1,
                     "алиас *%s: якоря и алиасы в спеке не поддерживаются — повторяющееся "
                     "задаётся именем и ссылкой на него", (const char *)ev->data.alias.anchor);
    case YAML_SCALAR_EVENT:
        return yscalar(b, ev);
    case YAML_SEQUENCE_START_EVENT:
        return ycoll(b, ev, YN_SEQ);
    case YAML_MAPPING_START_EVENT:
        return ycoll(b, ev, YN_MAP);
    case YAML_SEQUENCE_END_EVENT:
    case YAML_MAPPING_END_EVENT:
        return ypop(b);
    default:            /* начало потока, конец документа, пустое событие */
        return 0;
    }
}

struct ydoc *ydoc_parse_buf(const char *buf, size_t len, const char *name, struct err *e) {
    if (!name) name = "<yaml>";
    if (len > YDOC_MAX_BYTES) {
        char lim[24];
        snprintf(lim, sizeof(lim), "%u", YDOC_MAX_BYTES);
        yfail(e, name, 0, 0, "документ больше %s байт", lim);
        return NULL;
    }
    struct ydoc *d = calloc(1, sizeof(*d));
    if (!d) { yfail(e, name, 0, 0, "не хватило памяти на разбор YAML", NULL); return NULL; }
    d->name = ystrdup(d, name, strlen(name));
    if (!d->name) {
        ydoc_free(d);
        yfail(e, name, 0, 0, "не хватило памяти на разбор YAML", NULL);
        return NULL;
    }

    yaml_parser_t p;
    if (!yaml_parser_initialize(&p)) {
        ydoc_free(d);
        yfail(e, name, 0, 0, "не хватило памяти на разбор YAML", NULL);
        return NULL;
    }
    /* Пустой буфер — законный пустой поток; libyaml указателя при нулевой длине не читает, но
     * NULL ей не отдаём. */
    yaml_parser_set_input_string(&p, (const unsigned char *)(buf ? buf : ""), len);

    struct ybuild *b = calloc(1, sizeof(*b));
    int rc = b ? 0 : yfail(e, name, 0, 0, "не хватило памяти на разбор YAML", NULL);
    int docs = 0;
    if (b) {
        b->d = d;
        b->e = e;
    }
    while (rc == 0) {
        yaml_event_t ev;
        if (!yaml_parser_parse(&p, &ev)) {
            rc = ylib_fail(e, d->name, &p, buf ? buf : "", len);
            break;
        }
        rc = yevent(b, &ev, &docs);
        yaml_event_delete(&ev);
    }
    if (b)
        for (int i = 0; i < b->depth; i++) free(b->st[i].v);
    free(b);
    yaml_parser_delete(&p);

    if (rc < 0) {
        ydoc_free(d);
        return NULL;
    }
    if (!d->root) {
        yfail(e, d->name, 0, 0, "документ пуст", NULL);
        ydoc_free(d);
        return NULL;
    }
    return d;
}

/* ---- доступ ------------------------------------------------------------------------------ */
const struct ynode *ydoc_root(const struct ydoc *d) { return d ? d->root : NULL; }
const char *ydoc_name(const struct ydoc *d) { return d ? d->name : NULL; }

size_t ynode_len(const struct ynode *n) {
    return n && n->kind != YN_SCALAR ? n->len : 0;
}

const struct ynode *ynode_at(const struct ynode *seq, size_t i) {
    return seq && seq->kind == YN_SEQ && i < seq->len ? seq->items[i] : NULL;
}

const struct ynode *ynode_key_at(const struct ynode *map, size_t i) {
    return map && map->kind == YN_MAP && i < map->len ? map->items[2 * i] : NULL;
}

const struct ynode *ynode_val_at(const struct ynode *map, size_t i) {
    return map && map->kind == YN_MAP && i < map->len ? map->items[2 * i + 1] : NULL;
}

/* Перебором: у спеки отображения на единицы и десятки ключей, а повторов нет по построению
 * (ydupkeys), так что первое совпадение — единственное. */
const struct ynode *ynode_get(const struct ynode *map, const char *key) {
    if (!map || map->kind != YN_MAP || !key) return NULL;
    for (size_t i = 0; i < map->len; i++)
        if (strcmp(map->items[2 * i]->str, key) == 0) return map->items[2 * i + 1];
    return NULL;
}

int ynode_is_null(const struct ynode *n) {
    if (!n || n->kind != YN_SCALAR || n->style != YS_PLAIN) return 0;
    const char *s = n->str;
    return !*s || !strcmp(s, "~") || !strcmp(s, "null") || !strcmp(s, "Null") || !strcmp(s, "NULL");
}

int ynode_bool(const struct ynode *n, int *out) {
    if (!n || n->kind != YN_SCALAR || n->style != YS_PLAIN) return -1;
    const char *s = n->str;
    if (!strcmp(s, "true") || !strcmp(s, "True") || !strcmp(s, "TRUE")) { *out = 1; return 0; }
    if (!strcmp(s, "false") || !strcmp(s, "False") || !strcmp(s, "FALSE")) { *out = 0; return 0; }
    return -1;
}

int ynode_long(const struct ynode *n, long *out) {
    if (!n || n->kind != YN_SCALAR || n->style != YS_PLAIN) return -1;
    const char *s = n->str, *p = s;
    if (*p == '-' || *p == '+') p++;
    if (*p < '0' || *p > '9') return -1;
    for (const char *q = p; *q; q++)
        if (*q < '0' || *q > '9') return -1;
    errno = 0;
    char *end;
    long v = strtol(s, &end, 10);
    if (errno == ERANGE || *end) return -1;
    *out = v;
    return 0;
}
