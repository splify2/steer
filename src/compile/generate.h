#ifndef STEER_GENERATE_H
#define STEER_GENERATE_H

/* Компиляция набора групп в набор правил nftables (src/compile/generate.c): дерево (ir.h) и
 * печать (print.c). */

#include <stdio.h>
#include "groups.h"
#include "ir.h"
#include "nftcompat.h"

/* Дерево современной раскладки по спеке sp и её группам gr. 0 — успех; -1 — отказ
 * (недостижимо на разобранной спеке, кроме нехватки памяти), текст в e->msg — правило 5,
 * docs/architecture.md, раздел 2. Спека и группы — параметрами, правило 6. */
int nft_build(struct nft_rs *rs, const struct spec *sp, const struct groups *gr, struct err *e);
/* Текст ruleset в f: nft_build, nft_print. На отказе в f не
 * пишется ничего. */
int generate(const struct spec *sp, const struct groups *gr, FILE *f, struct err *e);

/* Каналы на само устройство (plat()->local_channels, src/platform/platform.h): цепочки на хуке
 * output. Код — здесь, у компилятора; платформа только говорит, бывают ли такие каналы. */
int nft_emit_output_mark(struct nft_rs *rs, const struct spec *sp, const struct groups *gr,
                         struct err *e);
void nft_emit_output_dns(struct nft_rs *rs, const struct spec *sp, const struct groups *gr);

/* Замечания про IPv6 правил (docs/architecture.md, «4б») — для diag: выход без IPv6, в который
 * ведут правила (их IPv6 отвергается, а не уходит напрямую), и правило, чьих клиентов по IPv6 не
 * узнать (свой клиент из одних адресов IPv4). fn зовётся на каждое: id, приговор diag (note —
 * совет: выход без IPv6 работает, клиент уходит на IPv4; warn — находка: IPv6 клиентов уходит мимо
 * правила), что, что с этим делать. */
typedef void (*v6_note_fn)(void *ctx, const char *id, const char *verdict, const char *what,
                           const char *why);
void v6_notes(const struct spec *sp, const struct groups *gr, v6_note_fn fn, void *ctx);

void counters_load(void);
int counter_find(const char *name, int down, unsigned long *p, unsigned long *b);
void l4_describe(const struct l4match *m, char *dst, size_t n);

#endif
