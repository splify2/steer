/* Сквозные проверки спеки — общие для обоих форматов (src/model/check.c).
 *
 * Проверки, которые смотрят на МОДЕЛЬ (выходы, подложки, группы), а не на текст, живут здесь один
 * раз: разбор спеки (model/v2.c) зовёт их после того, как модель собрана. Слово для подложки
 * (`over`) приходит параметром. */
#ifndef STEER_CHECK_H
#define STEER_CHECK_H

struct spec;
struct err;
struct port_range;
struct out_obfs;

/* «443» или «50000-65535» → диапазон портов. 0 — разобрано; -1 — негодная запись (отказ
 * говорит вызывающий: только он знает, где она стоит). */
int port_range_parse(const char *s, struct port_range *r);

/* Обфускация выхода из трёх строк спеки: режим (пусто — wg-over-tcp), «адрес:порт» сервера и
 * «адрес:порт», на который смотрит Endpoint пира WireGuard. name — имя выхода для сообщений.
 * 0 — ob заполнен и ob->on = 1; -1 — отказ, текст в e. */
int obfs_set(const char *name, const char *mode, const char *server, const char *listen,
             struct out_obfs *ob, struct err *e);

/* Проверки выходов, которым нужна вся спека: выход в локальное устройство (петля), устройство
 * дважды в одном пуле, подложка (over_word — «over»: есть ли цель, годится ли,
 * нет ли круга, в том числе через устройства пула, и не длиннее ли цепочка MAX_OVER_DEPTH).
 * 0 — годится; -1 — отказ в e, а в *bad (если не NULL) — номер выхода, о котором он. */
int spec_check_outputs(const struct spec *sp, const char *over_word, int *bad, struct err *e);

/* Выходов с меткой (out_needs_mark) не больше, чем мест в поле метки (steer_mark_slots, marks.h).
 * Это единственный настоящий предел числа выходов, и он свойство раскладки: отказ называет цифры
 * раскладки — сколько мест, какие биты поля, сколько выходов в спеке. 0 — годится. */
int check_mark_slots(const struct spec *sp, struct err *e);

#endif
