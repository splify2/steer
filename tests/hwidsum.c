/* Печатает SHA-256 своего аргумента шестнадцатеричными знаками.
 *
 * Нужен ровно для одного: сверить нашу реализацию с `sha256sum` оболочки на известных
 * векторах. Проверять её выводом самого движка нельзя — там хеш уже обрезан до двадцати
 * знаков и завёрнут в приставку, то есть половина ответа не видна, а расхождение в старших
 * байтах спряталось бы. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/tools/hwid.h"

/* Only the test executable is linked with --wrap. Fail direct heap requests
 * from the linked objects, not the C library's internal stdio allocations. */
void *__wrap_malloc(size_t n) { (void)n; return NULL; }
void *__wrap_calloc(size_t n, size_t s) { (void)n; (void)s; return NULL; }
void *__wrap_realloc(void *p, size_t n) { (void)p; (void)n; return NULL; }

/* Второй режим — PBKDF2, ради известных ответов RFC 6070: через готовый идентификатор их не
 * проверить, там вывод обрезан и завёрнут в приставку. */
static int pbkdf2_mode(int argc, char **argv) {
    if (argc < 6) { fprintf(stderr, "нужно: --pbkdf2 пароль соль проходы длина\n"); return 2; }
    unsigned iters = (unsigned)strtoul(argv[4], NULL, 10);
    size_t len = (size_t)strtoul(argv[5], NULL, 10);
    if (len == 0 || len > 64) { fprintf(stderr, "длина от 1 до 64\n"); return 2; }
    unsigned char out[64];
    steer_pbkdf2_sha256((const unsigned char *)argv[2], strlen(argv[2]),
                        (const unsigned char *)argv[3], strlen(argv[3]), iters, out, len);
    for (size_t i = 0; i < len; i++) printf("%02x", out[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--dev-id")) {
        const char *fixture = getenv("STEER_SYSNET");
        return fixture && *fixture ? cmd_dev_id() : 2;
    }
    if (argc > 1 && !strcmp(argv[1], "--pbkdf2")) return pbkdf2_mode(argc, argv);
    const char *s = argc > 1 ? argv[1] : "";
    unsigned char d[32];
    steer_sha256((const unsigned char *)s, strlen(s), d);
    for (int i = 0; i < 32; i++) printf("%02x", d[i]);
    printf("\n");
    return 0;
}
