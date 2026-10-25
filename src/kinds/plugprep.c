/* Шаг подготовки спеки: хуки плагинов (plugin.h; steer-api.md, раздел 3). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "spec.h"
#include "plugin.h"

int spec_prepare(const char *path, struct err *e) {
    (void)path; (void)e;
    return 0;
}

int spec_prepared_text(const char *path, const char *human, size_t human_n, char **text, size_t *n,
                       char key[65]) {
    (void)path; (void)human; (void)human_n; (void)text; (void)n; (void)key;
    return 0;
}
