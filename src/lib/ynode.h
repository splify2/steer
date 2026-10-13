#ifndef STEER_YNODE_H
#define STEER_YNODE_H

/* Дерево YAML-документа поверх libyaml (src/third_party/libyaml): спека v2 (docs/architecture.md,
 * раздел 3; «4в») читается этим модулем, и JSON спеки v2 — им же, потому что JSON —
 * подмножество того, что понимает парсер libyaml (проверено стендом tests/yamlmatch.c).
 *
 * ПОЧЕМУ ФАЙЛ НЕ yaml.h. Заголовок libyaml называется yaml.h и подключается ею самой как
 * <yaml.h>; заголовки в дереве подключаются по имени из любого слоя (-I на все каталоги,
 * build/sources.mk), и второй yaml.h молча подменял бы первый порядком флагов. Переименовывать
 * чужой заголовок — значит править upstream, поэтому уступает наш: ynode.
 *
 * ЧТО ДАЁТ. Разбор файла или буфера в дерево узлов трёх видов — скаляр, последовательность,
 * отображение — со строкой и столбцом каждого узла (с единицы) для сообщений об ошибке. Типов
 * значений (число, логическое) дерево не знает: скаляр — это строка и стиль, в котором он записан
 * (`5` и `"5"` различимы), а толкование — дело разбора спеки; помощники ynode_long/ynode_bool
 * ниже толкуют по базовой схеме YAML 1.2, без «yes/no/on/off» из 1.1 (там `no` — это ложь, а
 * код страны Норвегии в списке превращался бы в false).
 *
 * ПАМЯТЬ. Все узлы и строки документа — в одной арене, освобождаются одним ydoc_free().
 * Указатели на узлы и строки живут, пока жив документ.
 *
 * ОТКАЗЫ (через struct err, правило 5 — модуль в src/lib процесс не завершает). Сообщение
 * начинается с «имя:строка:столбец: », где имя — путь файла или то, что передано в
 * ydoc_parse_buf. Отказом кончаются, кроме синтаксических ошибок самой libyaml:
 *   - документ больше YDOC_MAX_BYTES или узлов больше YDOC_MAX_NODES;
 *   - вложенность глубже YDOC_MAX_DEPTH;
 *   - алиас (*имя) или якорь (&имя) — запрещены оба, см. ynode.c;
 *   - больше одного документа в потоке, пустой поток;
 *   - ключ отображения не скаляр, ключ повторяется;
 *   - нулевой байт внутри скаляра ("\0" в кавычках): движок держит строки как C-строки, и
 *     такой скаляр молча обрезался бы. */

#include <stddef.h>
#include "err.h"

/* Пределы. Спека — не больше нескольких мегабайт; на роутере с 64 МБ
 * памяти дерево обязано оставаться в единицах мегабайт при любом входе. Узел — ~56 байт вместе с
 * указателем на него у родителя, так что 256 Ки узлов — это ~14 МБ в худшем случае (вход из
 * одних `[]`/`1,` на четыре мегабайта дал бы два миллиона узлов — предел отказывает раньше).
 * Глубина: спека v2 вложена на 4-5 уровней; 64 — с запасом, а обход дерева у
 * потребителей рекурсивный, и предел держит стек в границах. */
#define YDOC_MAX_BYTES (4u << 20)
#define YDOC_MAX_NODES (256u << 10)
#define YDOC_MAX_DEPTH 64

enum ynode_kind { YN_SCALAR, YN_SEQ, YN_MAP };

/* Стиль записи скаляра — как в тексте. Для последовательностей и отображений не заполняется
 * (YS_PLAIN): блочная или потоковая запись смысла не меняет. */
enum ynode_style { YS_PLAIN, YS_SINGLE, YS_DOUBLE, YS_LITERAL, YS_FOLDED };

struct ynode {
    enum ynode_kind kind;
    enum ynode_style style;
    unsigned line, col;        /* начало узла, с единицы */
    const char *tag;           /* явный тег (`!!str` → "tag:yaml.org,2002:str") или NULL */
    const char *str;           /* YN_SCALAR: значение, всегда с завершающим нулём */
    size_t len;                /* YN_SCALAR: длина str; YN_SEQ — элементов; YN_MAP — пар */
    struct ynode **items;      /* YN_SEQ: len элементов; YN_MAP: 2*len — ключ, значение, ... */
};

struct ydoc;

/* Разбор файла целиком. NULL — отказ, текст в e->msg (e зануляет вызывающий, как у load_spec). */
struct ydoc *ydoc_parse_file(const char *path, struct err *e);
/* Разбор буфера (не обязан кончаться нулём). name — для сообщений, копируется. */
struct ydoc *ydoc_parse_buf(const char *buf, size_t len, const char *name, struct err *e);
void ydoc_free(struct ydoc *d);

const struct ynode *ydoc_root(const struct ydoc *d);
const char *ydoc_name(const struct ydoc *d);

/* Доступ. Все принимают NULL и узел не того вида — и тогда отвечают NULL/0: цепочку
 * ynode_get(ynode_get(root, "dns"), "mode") можно писать без проверок на каждом шаге. */
size_t ynode_len(const struct ynode *n);                                  /* элементов или пар */
const struct ynode *ynode_at(const struct ynode *seq, size_t i);
const struct ynode *ynode_get(const struct ynode *map, const char *key);
const struct ynode *ynode_key_at(const struct ynode *map, size_t i);     /* в порядке текста */
const struct ynode *ynode_val_at(const struct ynode *map, size_t i);
const char *ynode_str(const struct ynode *n);                            /* скаляр, иначе NULL */

/* Толкование скаляра по базовой схеме YAML 1.2 — только для скаляров без кавычек (YS_PLAIN):
 * `"5"` и `'true'` — строки, так же, как в JSON.
 *   ynode_is_null: пусто, ~, null, Null, NULL.
 *   ynode_bool:    true/True/TRUE, false/False/FALSE → 0 и *out; иначе -1.
 *   ynode_long:    десятичное целое [-+]?[0-9]+ в пределах long → 0 и *out; иначе -1. */
int ynode_is_null(const struct ynode *n);
int ynode_bool(const struct ynode *n, int *out);
int ynode_long(const struct ynode *n, long *out);

/* Отказ разбора спеки по узлу: «имя:строка:столбец: » + fmt с одним %s (как err_set). n может
 * быть NULL — тогда без строки и столбца. Возвращает -1. */
int ynode_err(struct err *e, const struct ydoc *d, const struct ynode *n,
              const char *fmt, const char *a);

#endif
