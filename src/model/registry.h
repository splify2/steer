#ifndef STEER_REGISTRY_H
#define STEER_REGISTRY_H

/* Из сохранённых назначений и свободных мест вычислить mark/table для свежей спеки,
 * ничего не записывая. 0 — успех, -1 — отказ с текстом в e. */
int registry_plan(struct spec *s, struct err *e);

/* Подготовить снимок уже вычисленных назначений до изменений в ядре. Строка принадлежит
 * вызывающему (free), NULL — отказ с текстом в e. Публикация, как и прежде, best effort. */
char *registry_render(const struct spec *s, struct err *e);
void registry_publish(const struct spec *s, const char *text);

/* Раздать и сразу сохранить места (прежнее поведение остальных подкоманд). */
int registry_assign(struct spec *s, struct err *e);

#endif
