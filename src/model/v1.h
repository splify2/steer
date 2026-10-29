/* Спека v1 (JSON со `schema: 1` или `2`) → модель v2 — src/model/v1.c. Только перевод при загрузке. */
#ifndef STEER_V1_H
#define STEER_V1_H

struct spec;
struct err;

/* Разобрать текст спеки v1 и перевести в модель в *s (уже обнулённую load_spec и с умолчанием
 * lan_devices). 0 — разобрано; -1 — отказ, текст в e (прежние тексты разбора v1). */
int spec_parse_v1(const char *text, struct spec *s, struct err *e);

#endif
