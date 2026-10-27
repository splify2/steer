/* Версия ядра этой сборки (module.h). */
#include "module.h"

/* Версию подставляет сборка (-DSTEER_VERSION) из файла VERSION; умолчание — для стендов. */
#ifndef STEER_VERSION
#define STEER_VERSION "dev"
#endif

const char *steer_engine_version(void) { return STEER_VERSION; }
