/* Private one-generation Linux Full UI profile. Not a package removal API. */
#ifndef STEER_FULL_DOMAIN_H
#define STEER_FULL_DOMAIN_H
struct full_domain;
struct helper;
struct loop;
struct supd;
int supd_full_main(const char *prefix);
int full_active(struct full_domain *f);  /* only 1 admits a launch */
int full_launch_lease(struct full_domain *f);
int full_plan(struct full_domain *f, struct helper *h);
int supd_full_pid(struct supd *s);
struct supd *supd_full_open(struct loop *l, struct full_domain *f);
#endif
