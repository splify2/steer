/* {conf} → --spec/--state-dir у программ протоколов (plugconf.h). */
#define _GNU_SOURCE
#include "plugconf.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Строка JSON по ключу внутри объекта `obj` (текст от '{' объекта): только то, что пишет ядро —
 * строковое значение с экранированием \" \\ \/. Ключ ищется на верхнем уровне объекта. */
static char *jstr(const char *obj, const char *key) {
    size_t kl = strlen(key);
    int depth = 0;
    for (const char *p = obj; *p; p++) {
        if (*p == '"') {
            const char *s = ++p;
            while (*p && *p != '"') { if (*p == '\\' && p[1]) p++; p++; }
            if (!*p) return NULL;
            const char *e = p;
            if (depth != 1) continue;
            const char *q = e + 1;
            while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
            if (*q != ':' || (size_t)(e - s) != kl || strncmp(s, key, kl) != 0) continue;
            q++;
            while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
            if (*q != '"') return NULL;
            q++;
            char *out = malloc(strlen(q) + 1), *w = out;
            if (!out) return NULL;
            for (; *q && *q != '"'; q++) {
                if (*q == '\\' && q[1]) {
                    q++;
                    *w++ = *q == 'n' ? '\n' : *q == 't' ? '\t' : *q;
                } else *w++ = *q;
            }
            *w = '\0';
            return out;
        }
        if (*p == '{' || *p == '[') depth++;
        else if (*p == '}' || *p == ']') { if (--depth <= 0) return NULL; }
    }
    return NULL;
}

/* Объект по ключу верхнего уровня: указатель на его '{' в тексте. */
static const char *jobj(const char *doc, const char *key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    for (const char *p = strstr(doc, pat); p; p = strstr(p + 1, pat)) {
        const char *q = p + strlen(pat);
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q != ':') continue;
        q++;
        while (*q == ' ' || *q == '\t' || *q == '\n' || *q == '\r') q++;
        if (*q == '{') return q;
    }
    return NULL;
}

static char *slurp(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 4096, n = 0;
    char *b = malloc(cap);
    for (size_t r; b && (r = fread(b + n, 1, cap - n - 1, f)) > 0;) {
        n += r;
        if (n + 1 >= cap) { char *nb = realloc(b, cap *= 2); if (!nb) { free(b); b = NULL; } else b = nb; }
    }
    fclose(f);
    if (b) b[n] = '\0';
    return b;
}

/* Реестр плагинов ВНУТРИ помощника протокола (kinds/plugin.c) пуст. Помощник разбирает спеку своей
 * копией модели, и его собственный вид (tunnel:vless…) обязан быть встроенным видом этой копии: если бы
 * реестр прочёл каталог плагинов, вид выхода взялся бы из манифеста этого же плагина, и помощник не
 * узнал бы своего выхода («выход не vless»). Виды других плагинов в спеке помощнику не нужны — их выходы
 * в его разборе недоступны (kind_unavail), а не отказ всей спеке. Корень реестра — каталог самой
 * программы: в нём нет подкаталогов с plugin.json, и реестр выходит пустым, но «раскладка есть». */
static void registry_off(void) {
    static char dir[4096];
    ssize_t l = readlink("/proc/self/exe", dir, sizeof(dir) - 1);
    if (l <= 0) return;
    dir[l] = '\0';
    char *sl = strrchr(dir, '/');
    if (!sl || sl == dir) return;
    *sl = '\0';
    setenv("STEER_PLUGINS_ROOT", dir, 1);
    setenv("STEER_PLUGIN_DIR", dir, 1);
}

char **plugconf_argv(int *argc, char **argv) {
    registry_off();
    int at = -1;
    for (int i = 1; i + 1 < *argc; i++)
        if (!strcmp(argv[i], "--conf")) { at = i; break; }
    if (at < 0) return argv;
    const char *path = argv[at + 1];
    char *doc = slurp(path);
    const char *paths = doc ? jobj(doc, "paths") : NULL;
    char *spec = paths ? jstr(paths, "spec") : NULL;
    char *etc = paths ? jstr(paths, "etc") : NULL;
    char *state = paths ? jstr(paths, "state") : NULL;
    if (!spec && etc) {
        size_t l = strlen(etc) + 16;
        spec = malloc(l);
        if (spec) {
            snprintf(spec, l, "%s/spec.json", etc);
            char *ym = malloc(l);
            if (ym) {
                snprintf(ym, l, "%s/spec.yaml", etc);
                /* Как plat_spec_default: JSON, если он есть; иначе YAML, если есть он. */
                if (access(spec, F_OK) != 0 && access(ym, F_OK) == 0) { free(spec); spec = ym; }
                else free(ym);
            }
        }
    }
    if (!spec) {
        fprintf(stderr, "steer: %s — %s\n", path,
                doc ? "в файле настройки выхода нет paths.etc" : "файл настройки выхода не читается");
        exit(2);
    }
    char **av = calloc((size_t)*argc + 4, sizeof(*av));
    if (!av) { fprintf(stderr, "steer: нет памяти\n"); exit(2); }
    int n = 0;
    for (int i = 0; i < *argc; i++) {
        if (i == at) {
            av[n++] = "--spec";
            av[n++] = spec;
            if (state && *state) { av[n++] = "--state-dir"; av[n++] = state; }
            i++;
            continue;
        }
        av[n++] = argv[i];
    }
    av[n] = NULL;
    *argc = n;
    free(doc);
    free(etc);
    return av;
}
