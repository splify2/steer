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
        g_prof_ready = 1;
    }
    return &g_prof;
}
