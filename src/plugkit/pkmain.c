/* main программы плагина: её единственная запись PK_PROGRAM (plugkit.h). */
#include <stdio.h>

#include "plugkit.h"

int main(int argc, char **argv) {
    const struct pk_prog *p = pk_prog_find(NULL);
    if (!p) {
        fprintf(stderr, "steer: в программе нет таблицы подкоманд (PK_PROGRAM)\n");
        return 2;
    }
    return pk_prog_run(p, argc, argv);
}
