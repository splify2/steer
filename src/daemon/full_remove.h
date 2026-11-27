/* supd-full/2. The retained binding always uses logical names under "tree",
 * including when the exact same inode is in retired-G. */
#ifndef STEER_FULL_REMOVE_H
#define STEER_FULL_REMOVE_H
#include <stddef.h>
#define FULL_TYPE2 "supd-full/2"
#define FULL_BIND2 "user.steer.supd2.binding"
#define FULL_PHASE2 "user.steer.supd2.phase"
#define FULL_INTENT "user.steer.supd2.intent"
#define FULL_COMMIT "user.steer.supd2.commit"
/* Read-only manager view. Returns an open fd on the validated owner.lock.
 * With committed != NULL also requires a sealed commit with that TX. */
int full_manager_view(const char *prefix,const char *g,const char *binding,const char *committed);
#endif
