/* JSON для программ плагина (src/plugkit): дерево документа без пределов по длине и числу.
 *
 * Программа плагина читает JSON в трёх местах API ядра (plugin-sdk/docs/steer-api.md): файл настройки
 * выхода {conf} (1.4), вход хуков check и expand (3.2, 3.3) и событийные строки сокета. Модель спеки
 * ядра с YAML ей для этого не нужна: документ маленький, а ядро уже проверило его схемой ключей вида.
 * Разбор строгий (RFC 8259): мусор после документа, висящая запятая, управляющий байт в строке —
 * отказ с местом. Строки — UTF-8 как есть, \uXXXX раскрываются (с суррогатными парами). */
#ifndef STEER_PKJSON_H
#define STEER_PKJSON_H

#include <stddef.h>

enum pkj_type { PKJ_NULL, PKJ_BOOL, PKJ_NUM, PKJ_STR, PKJ_ARR, PKJ_OBJ };

struct pkj {
    enum pkj_type t;
    int b;                      /* PKJ_BOOL */
    double num;                 /* PKJ_NUM */
    int integer;                /* PKJ_NUM без дроби и порядка: num — целое */
    char *s;                    /* PKJ_STR — значение; PKJ_NUM — запись числа как в тексте */
    size_t n;                   /* PKJ_ARR, PKJ_OBJ — сколько элементов */
    struct pkj **v;             /* элементы */
    char **k;                   /* PKJ_OBJ — ключи */
};

/* Разобрать текст. NULL — отказ, причина с номером байта в err. */
struct pkj *pkj_parse(const char *txt, size_t len, char *err, size_t errn);
/* Прочитать файл и разобрать; "-" — stdin. */
struct pkj *pkj_load(const char *path, char *err, size_t errn);
void pkj_free(struct pkj *j);

/* Значение ключа объекта; NULL — нет ключа или j не объект. */
const struct pkj *pkj_get(const struct pkj *j, const char *key);
/* Строка или NULL (не строка, null, нет узла). */
const char *pkj_str(const struct pkj *j);
/* Целое: 0 — есть, -1 — не целое число. */
int pkj_long(const struct pkj *j, long *out);
/* Булево: 0 — есть, -1 — не true/false. */
int pkj_bool(const struct pkj *j, int *out);
/* Элемент массива; NULL — за пределами или не массив. */
const struct pkj *pkj_at(const struct pkj *j, size_t i);
/* Длина массива или объекта; 0 у остальных. */
size_t pkj_len(const struct pkj *j);

/* Значение по пути «a.b.c» от объекта j. */
const struct pkj *pkj_path(const struct pkj *j, const char *path);

#endif
