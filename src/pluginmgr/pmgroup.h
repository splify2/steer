/* Внутренний журнал одного legacy install --file ... --file под pm_lock. */
#ifndef STEER_PMGROUP_H
#define STEER_PMGROUP_H
#include "pm.h"
#define PM_GROUP_DIR ".group-txn"

struct group_file { char id[128], ver[128], arch[128]; };
struct pm_group {
    char *dir;
    struct group_file *v;
    size_t n;
    int preparing;
};

int pm_group_preparing(const struct pm_group *g);
int pm_group_publish(const struct pm_group *g);
int pm_group_finish(const char *marker, int accept, struct pm_ctx *x);
int pm_group_write(const struct pm_group *g, const char *name, const char *path,
                   const char *buf, size_t n);
int pm_state_save_group(const struct pm_state *s, const struct pm_group *g, struct pm_err *e);
int pm_group_bad_versions(const struct pm_result *res, const char *why);
int pm_group_reader(int writer); /* fd с flock на каталоге; -2 — каталога ещё нет */
int pm_group_pending(void);
#endif
