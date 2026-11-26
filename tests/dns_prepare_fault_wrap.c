/* SPDX-License-Identifier: GPL-3.0-only
 * Linked only into the isolated fault-fixture binary, never production. */
#define _GNU_SOURCE
#include "dnsd_int.h"
#include "tabfmt.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int in_feed, in_rules;
int __real_tabfmt_feed(struct tabfmt_feed *,const char *,size_t);
int __wrap_tabfmt_feed(struct tabfmt_feed *feed,const char *data,size_t n) {
    in_feed++;
    int result=__real_tabfmt_feed(feed,data,n);
    in_feed--;
    return result;
}
int __real_dch_rules_load(const struct dchan *,struct ruleset *,struct dpart **,size_t *,int *);
int __wrap_dch_rules_load(const struct dchan *d,struct ruleset *rules,struct dpart **parts,
    size_t *n,int *composite) {
    if(in_feed)in_rules++;
    int result=__real_dch_rules_load(d,rules,parts,n,composite);
    if(in_feed)in_rules--;
    return result;
}
char *__real_strdup(const char *);
char *__wrap_strdup(const char *s) {
    const char *arm;
    if(in_rules && !strcmp(s,"switch.test") && (arm=getenv("STEER_TEST_DNS_PREPARE_ARM")) &&
       *arm && !unlink(arm)) {
        fprintf(stderr,"DNS_TEST_PREPARE_ENOMEM pid=%ld\n",(long)getpid());
        errno=ENOMEM;
        return NULL;
    }
    return __real_strdup(s);
}
