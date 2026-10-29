/* Исключение узлов подписки у выхода kind: tunnel — ключи `exclude`, `exclude_name` и `only` спеки v2
 * (docs/spec-v2.md). Общее для всех протоколов туннеля: разбор спеки (model/v2.c), печать
 * (model/v2print.c), виды (kinds/vless.c, hysteria2.c, proxy.c) и модули, которые отбирают
 * кандидатов (vlmain.c, hy2main.c, pxmain.c) и печатают узлы (`*-nodes`).
 *
 * ЗАЧЕМ. `nodes` — номера среди пригодных узлов, и при обновлении подписки они уезжают; новые узлы
 * той страны, которую человек не хочет, при пустом `nodes` («любой рабочий») попадали бы в
 * кандидаты сами. Исключение называет СВОЙСТВО узла — страну по флагу или кусок имени, — поэтому
 * переживает обновление подписки.
 *
 * ИСКЛЮЧЕНИЕ ТОЛЬКО ОТБИРАЕТ КАНДИДАТОВ. Номера узлов от него не сдвигаются: они по-прежнему среди
 * всех пригодных, как печатает `*-nodes`. Вместе с `nodes` и `transport` — пересечение.
 *
 * СТРАНА УЗЛА — ПО ФЛАГУ-ЭМОДЗИ В ИМЕНИ, как у интерфейса splify2 (ccFromName в
 * ui/src/lib/nodename.ts): первая пара подряд идущих символов regional indicator (U+1F1E6…1F1FF)
 * где угодно в имени, буквы — A…Z по порядку. «🇳🇱 Амстердам» → NL. Флага нет — страны у узла нет,
 * и исключение по стране его не берёт. Названий стран словами здесь нет (их нет и у ccFromName).
 *
 * Всё — static inline: функции нужны и ядру (разбор спеки), и модулям, а заводить ради них символ
 * в списке экспорта libsteer незачем. */
#ifndef STEER_NODESEL_H
#define STEER_NODESEL_H

#include <stddef.h>

struct node_exclude {
    char (*cc)[3];              /* коды стран, две заглавные латинские буквы; арена спеки */
    size_t cc_n;
    char (*only)[3];            /* `only`: брать ТОЛЬКО узлы этих стран; арена спеки */
    size_t only_n;
    const char **names;         /* подстроки имени узла как записаны в спеке; арена спеки */
    size_t names_n;
};

/* Символ regional indicator в UTF-8: F0 9F 87 A6…BF. Проверка по байту за раз: на конце строки
 * первое несовпадение (ноль) останавливает её до чтения за пределами. */
static inline int nodesel_ri(const unsigned char *p) {
    return p[0] == 0xF0 && p[1] == 0x9F && p[2] == 0x87 && p[3] >= 0xA6 && p[3] <= 0xBF;
}

/* Код страны из флага в имени узла: 1 — найден (cc — две буквы и ноль), 0 — флага нет. */
static inline int node_cc(const char *name, char cc[3]) {
    for (const unsigned char *p = (const unsigned char *)name; p && *p; p++) {
        if (nodesel_ri(p) && nodesel_ri(p + 4)) {
            cc[0] = (char)('A' + (p[3] - 0xA6));
            cc[1] = (char)('A' + (p[7] - 0xA6));
            cc[2] = '\0';
            return 1;
        }
    }
    return 0;
}

/* Следующий символ UTF-8 со свёрткой регистра латиницы и кириллицы (А–Я, Ѐ–Џ — к строчным);
 * негодный байт — сам себе символ. Сдвигает *ps. */
static inline unsigned nodesel_cp(const unsigned char **ps) {
    const unsigned char *p = *ps;
    unsigned c = p[0];
    size_t n = 1;
    if (c >= 0xC0 && c < 0xE0 && (p[1] & 0xC0) == 0x80) {
        c = ((c & 0x1Fu) << 6) | (p[1] & 0x3Fu);
        n = 2;
    } else if (c >= 0xE0 && c < 0xF0 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80) {
        c = ((c & 0x0Fu) << 12) | ((p[1] & 0x3Fu) << 6) | (p[2] & 0x3Fu);
        n = 3;
    } else if (c >= 0xF0 && c < 0xF8 && (p[1] & 0xC0) == 0x80 && (p[2] & 0xC0) == 0x80 &&
               (p[3] & 0xC0) == 0x80) {
        c = ((c & 0x07u) << 18) | ((p[1] & 0x3Fu) << 12) | ((p[2] & 0x3Fu) << 6) | (p[3] & 0x3Fu);
        n = 4;
    }
    *ps = p + n;
    if (c >= 'A' && c <= 'Z') return c + 32;
    if (c >= 0x410 && c <= 0x42F) return c + 32;        /* А–Я → а–я */
    if (c >= 0x400 && c <= 0x40F) return c + 0x50;      /* Ѐ–Џ (Ё в их числе) → ѐ–џ */
    return c;
}

/* Есть ли needle в hay без учёта регистра (латиница и кириллица). Пустой needle разбор спеки не
 * пропускает: он исключил бы все узлы. */
static inline int node_name_has(const char *hay, const char *needle) {
    if (!hay || !needle || !*needle) return 0;
    for (const unsigned char *h = (const unsigned char *)hay; *h; nodesel_cp(&h)) {
        const unsigned char *a = h, *b = (const unsigned char *)needle;
        for (;;) {
            if (!*b) return 1;
            if (!*a || nodesel_cp(&a) != nodesel_cp(&b)) break;
        }
    }
    return 0;
}

/* Исключён ли узел с этим именем. x == NULL или пустое исключение — нет. С `only` исключён и узел
 * без флага: страну ему назвать нечем, а человек просил узлы КОНКРЕТНЫХ стран — угадывать не за что. */
static inline int node_excluded(const struct node_exclude *x, const char *name) {
    if (!x || !name) return 0;
    if (x->only_n) {
        char cc[3];
        int in = 0;
        if (node_cc(name, cc))
            for (size_t i = 0; i < x->only_n && !in; i++)
                in = x->only[i][0] == cc[0] && x->only[i][1] == cc[1];
        if (!in) return 1;
    }
    if (x->cc_n) {
        char cc[3];
        if (node_cc(name, cc))
            for (size_t i = 0; i < x->cc_n; i++)
                if (x->cc[i][0] == cc[0] && x->cc[i][1] == cc[1]) return 1;
    }
    for (size_t i = 0; i < x->names_n; i++)
        if (node_name_has(name, x->names[i])) return 1;
    return 0;
}

#endif
