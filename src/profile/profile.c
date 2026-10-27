/* Профиль сборки (profile.h): умолчания базовой сборки и слабая ссылка на файл профиля.
 *
 * Слабая ссылка, а не сгенерированный файл, — по тем же доводам, что у реестра видов
 * (src/kinds/kind.c): одно место и та же компоновка объектов во всех трёх системах сборки. Файл
 * профиля в сборке есть — steer_profile определён, нет — адрес нулевой, и действует базовый. */
#include <stddef.h>
#include "profile.h"

extern const struct profile steer_profile __attribute__((weak));

static struct profile g_prof;
static int g_prof_ready;

const struct profile *prof(void) {
    if (!g_prof_ready) {
        if (&steer_profile) g_prof = steer_profile;
        if (!g_prof.build) g_prof.build = "базовая сборка";
        /* Полный движок берёт таблицы с 300 (300 плюс место в реестре, model/registry.c). */
        if (!g_prof.table_base) g_prof.table_base = 300;
        if (!g_prof.rt_tables_file) g_prof.rt_tables_file = "steer.conf";
        /* Слушатели TCP модулей — от 9480 (ряд 8480… занимал прежний мост tgws ядра; плагины берут порты
         * от 10480, src/kinds/plugalloc.c). */
        if (!g_prof.tcp_port_base) g_prof.tcp_port_base = 9480;
        g_prof_ready = 1;
    }
    return &g_prof;
}
