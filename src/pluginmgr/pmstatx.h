#ifndef STEER_PMSTATX_H
#define STEER_PMSTATX_H
#include <stdint.h>

/* 0 только при наличии STATX_MNT_ID в ответе ядра. Не следует по ссылке. */
int pm_statx_mount_id(const char *path, uint64_t *id);
#endif
