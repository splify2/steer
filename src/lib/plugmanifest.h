/* Legacy manifest admission. This is not provider loading or signature checking. */
#ifndef STEER_PLUGMANIFEST_H
#define STEER_PLUGMANIFEST_H

#include "ynode.h"

static inline const char *plugin_legacy_contract_why(const struct ynode *root) {
    long schema = 0;
    if (ynode_long(ynode_get(root, "schema"), &schema) != 0 || schema != 1)
        return "plugin.json: поддерживается только schema 1";
    if (ynode_get(ynode_get(root, "compat"), "steer-provider-api"))
        return "steer-provider-api не поддерживается legacy runtime";
    return NULL;
}

#endif
