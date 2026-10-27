/* ТАБЛИЦЫ КЛЮЧЕЙ СПЕКИ v2 — одно знание о том, какие ключи есть, для разбора (v2.c) и для схемы
 * (`steer spec-schema`, v2schema.c; формат — docs/spec-schema.md).
 *
 * Разбор берёт отсюда перечни допустимых ключей каждого раздела (неизвестный ключ — отказ),
 * пределы чисел и то, кому какой ключ вида принадлежит (ключ чужого вида — отказ). Схема строится
 * из тех же строк и из реестра видов (kind_ops.caps и .keys), так что новый ключ, внесённый в
 * таблицу, появляется и в разборе, и в схеме разом. Значения ключей (разбор enum, ссылки по именам,
 * сочетания) остаются в v2.c и kinds/<вид>.c: их сверяет стенд tests/specschemamatch.sh — каждый ключ
 * схемы разбор принимает, каждое значение enum и границы чисел — тоже, неизвестный ключ — нет. */
#ifndef STEER_V2KEYS_H
#define STEER_V2KEYS_H
#include <stddef.h>

struct kind_ops;

/* Разделы спеки: у каждого свой перечень ключей. */
enum v2_scope {
    V2S_TOP,            /* корень спеки */
    V2S_LAN,
    V2S_CLIENT,         /* запись clients.<имя> */
    V2S_LIST,           /* запись lists.<имя> */
    V2S_OUT,            /* запись outputs.<имя>: общие ключи и ключи видов (кому — who) */
    V2S_OBFS,           /* outputs.<имя>.obfs */
    V2S_DNS,
    V2S_CACHE_TTL,      /* dns.cache_ttl */
    V2S_DNS_UP,         /* dns.upstreams.<имя> — сервер */
    V2S_DNS_GRP,        /* dns.upstreams.<имя> — группа серверов */
    V2S_RULE,           /* запись rules[] */
    V2S_N
};

enum v2_type {
    VT_STR, VT_INT, VT_BOOL,
    VT_STRS,            /* перечень строк: список или одно значение */
    VT_INTS,            /* перечень целых */
    VT_OBJ,             /* вложенное отображение, ключи — раздел sub */
    VT_MAP,             /* отображение «имя → запись раздела sub» */
    VT_SEQ,             /* список записей раздела sub */
    VT_STR_OBJ          /* строка (имя из ref) или запись dns-апстрима */
};

/* Кому ключ раздела V2S_OUT (проверка v2key_applies по свойствам вида — kind_ops.caps и .keys). */
enum v2_who {
    W_ALL,              /* всем (kind) */
    W_PROTOCOL,         /* только kind: tunnel */
    W_FAIL,             /* группе и виду с устройством или меткой (on_fail) */
    W_IPV6,             /* группе и виду, который несёт IPv6 */
    W_PREFIX,           /* виду, у которого бывает ipv6: routed (устройство, не туннель с завершением TCP) */
    W_OVER,             /* виду со своим сокетом наверх (подложка) */
    W_DEVICE,           /* виду с устройством, не группе */
    W_GROUP,            /* только группе */
    W_KK,               /* виду, у которого в kind_ops.keys стоит бит kk, не группе */
    W_INTERNAL          /* пишет только плагин (owner): в спеке человека его нет */
};

enum v2_flag {
    VF_REQUIRED = 1 << 0,   /* без ключа разбор отказывает (у вида — когда ключ ему принадлежит) */
    VF_SECRET   = 1 << 1,   /* значение не печатается в status, diag и журнале */
    VF_PATH     = 1 << 2,   /* строка — путь файла, относительный — от каталога спеки (x-path: etc) */
    VF_NOT_YET  = 1 << 3,   /* разбирается и проверяется, но спека отвергается «ещё не поддерживается» */
    VF_PHONE    = 1 << 4,   /* принимает только платформа с локальными каналами (телефон) */
    VF_INTERNAL = 1 << 5,   /* разбор принимает, в схему не входит: ключ пишет только плагин */
    VF_ITEM_NUM = 1 << 6,   /* элемент перечня — и число, и строка (uid 10123, порт 443) */
    VF_NOMSG    = 1 << 7,   /* не называть владельца в отказе «ключ есть только у …» */
    VF_POOL     = 1 << 8    /* ключ пула узлов туннеля (kind: tunnel) */
};

struct v2key {
    enum v2_scope scope;
    const char *key;
    enum v2_type type;
    unsigned flags;             /* enum v2_flag */
    const char *hint;           /* подсказка человеку, по-русски */
    const char *def;            /* умолчание — литерал JSON; NULL — нет или выводится (см. hint) */
    const char *ex;             /* пример годного значения — литерал JSON */
    const char *en;             /* допустимые значения через «|» (у VT_STRS — для элементов) */
    int range;                  /* lo..hi — границы числа или элементов VT_INTS */
    long lo, hi;
    int min_items, max_items;   /* VT_STRS, VT_INTS: границы длины перечня; 0 — нет */
    const char *pat;            /* регулярное выражение (ERE) строки или элемента */
    const char *ref;            /* значение — имя из раздела ref: outputs, lists, clients, dns.upstreams */
    const char *also;           /* кроме них допустимы слова через «|» (all, lan, direct) */
    const char *when;           /* ключ имеет смысл при «ключ=значение|значение» соседа */
    enum v2_scope sub;          /* VT_OBJ, VT_MAP, VT_SEQ, VT_STR_OBJ: раздел вложенной записи */
    const char *reserved;       /* VT_MAP: занятые имена через «|» */
    enum v2_who who;            /* V2S_OUT */
    unsigned kk;                /* W_KK: бит enum kind_key */
    const char *owner;          /* W_KK, W_GROUP, W_PROTOCOL: чей ключ — для отказа «есть только у …» */
    const char *protos;         /* W_KK: у каких протоколов kind: tunnel — через «,»; NULL — у всех */
    const char *needs;          /* «значение:сосед,сосед» («*» — при любом значении): без соседей разбор отказывает (scope: device — for) */
};

/* Все записи таблицы и их число (порядок — порядок показа). */
const struct v2key *v2keys_all(size_t *n);
/* Запись раздела по имени ключа; NULL — нет. Для V2S_OUT — первая (у имён, что есть у группы и
 * у туннеля, см. v2key_out_find). */
const struct v2key *v2key_find(enum v2_scope sc, const char *key);
/* Запись V2S_OUT по имени среди ключей кому who; NULL — нет. */
const struct v2key *v2key_out_find(const char *key, enum v2_who who);
/* Ключ раздела допустим (есть в таблице и не внутренний): для keys_known разбора. */
int v2key_known(enum v2_scope sc, const char *key);
/* Имя i-го ключа раздела (в порядке таблицы, без внутренних); NULL — их меньше. */
const char *v2key_name_at(enum v2_scope sc, size_t i);
/* Перечень допустимых ключей раздела через «, » — для подсказки в отказе. */
void v2keys_list(enum v2_scope sc, char *buf, size_t n);
/* Подходит ли ключ раздела V2S_OUT выходу вида kd (group — это группа). Общая для разбора и
 * схемы: где разбор отказывает «нет у kind …», схема ключа не показывает. */
int v2key_applies(const struct v2key *k, const struct kind_ops *kd, int group);
/* Подходит ли ключ протоколу kind: tunnel (proto — «vless», …; NULL — протокол не важен). */
int v2key_proto_ok(const struct v2key *k, const char *proto);
/* Границы числа ключа раздела; 0 — границ в таблице нет. Разбор берёт пределы отсюда. */
int v2key_range(enum v2_scope sc, const char *key, long *lo, long *hi);
/* Подсказка «какие ключи есть у этого выхода» для отказа разбора: общие и ключи вида. */
void v2keys_out_list(const struct kind_ops *kd, int group, int tunnel, const char *proto, char *buf, size_t n);

#endif
