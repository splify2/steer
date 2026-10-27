/* Флаг --platform (modcmd.h). */
#include <stdio.h>
#include <string.h>

#include "modcmd.h"
#include "platform.h"

int modcmd_platform_args(int *argc, char **argv) {
    /* Платформа (src/platform/platform.h) — до всего остального: от неё зависят пути по
     * умолчанию, справка и раскладка меток. --platform понимает любая команда, в любом месте
     * строки, поэтому он вынимается из argv здесь, до разбора: у dnsd, fit и ctl свои парсеры,
     * и учить каждый из них этому флагу незачем. Выбор уходит и в окружение (plat_select) —
     * процессы, которые движок запускает сам, работают на той же платформе. */
    for (int i = 1; i < *argc; i++) {
        if (strcmp(argv[i], "--platform") != 0) continue;
        if (i + 1 >= *argc) {
            fprintf(stderr, "steer: флаг --platform остался без значения (%s)\n", plat_names());
            return 2;
        }
        if (plat_select(argv[i + 1]) != 0) {
            fprintf(stderr, "steer: --platform %s: такой платформы нет (есть %s)\n", argv[i + 1],
                    plat_names());
            return 2;
        }
        memmove(&argv[i], &argv[i + 2], (size_t)(*argc - i - 1) * sizeof *argv);
        *argc -= 2;
        i--;
    }
    return 0;
}
