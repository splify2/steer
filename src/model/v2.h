/* Спека v2 (YAML или JSON с `version: 2`) — src/model/v2.c (разбор) и src/model/v2print.c
 * (печать, `steer spec convert`). Формат — docs/spec-v2.md и раздел 3 docs/architecture.md. */
#ifndef STEER_V2_H
#define STEER_V2_H
#include <stdio.h>

struct spec;
struct err;
struct ydoc;

/* Разобрать дерево спеки v2 в модель *s (уже обнулённую load_spec и с умолчанием lan_devices).
 * 0 — разобрано; -1 — отказ, текст в e: «файл:строка:столбец: что не так». Строки путей
 * копируются — дерево можно освобождать сразу после возврата. */
int spec_parse_v2(const struct ydoc *d, struct spec *s, struct err *e);

/* Напечатать модель спекой v2 (YAML в стиле примера раздела 3). Перевод v1 → v2: модель,
 * собранная из v1, печатается так, что её разбор даёт тот же набор правил. 0 — напечатано; -1 —
 * модель не выражается спекой v2 (текст в e). */
int spec_print_v2(FILE *f, const struct spec *s, struct err *e);
/* Та же печать JSON-объектом (`steer spec convert --json`): ключи и порядок — как у spec_print_v2. */
int spec_print_v2_json(FILE *f, const struct spec *s, struct err *e);

/* Схема спеки v2 (`steer spec-schema`, docs/spec-schema.md): таблицы ключей (v2keys.c), виды ядра
 * из реестра и виды установленных плагинов. json — JSON, иначе таблица для человека. 0 — напечатано;
 * -1 — отказ, текст в e. */
int v2_schema_print(FILE *f, int json, struct err *e);

/* Каталог файла спеки для относительных путей ключей (см. определение). */
int v2_base_dir(const char *name, char *buf, size_t n);

#endif
