/* Private handoff from the stock signed unpacker to the supd-full/2 binder.
 * The signed archive is the source of hashes; the destination is not. */
#ifndef STEER_FULL_INSTALL_H
#define STEER_FULL_INSTALL_H
#include <sys/types.h>
#define FULL_FILES 13
struct full_file {
    char name[64];
    unsigned char hash[32];
    dev_t dev;
    ino_t ino;
};
struct full_package {
    dev_t dev;
    ino_t ino;
    unsigned n;
    struct full_file files[FULL_FILES];
};
int full_first_capable(void);
int full_seal_new(const char *stage,const struct full_package *pkg,const char *host,
                  const char *type_hash,char binding[65]);
int full_first_check(const char *stage,const char *prefix,const char *g,const char *binding);
#endif
