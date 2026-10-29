#ifndef STEER_DAEMON_H
#define STEER_DAEMON_H

/* Общий заголовок ядра steer: объявления, которые до нарезки src/daemon/steer.c на модули
 * (docs/architecture.md, «Слои и каталоги») были видны друг другу просто потому, что жили в
 * одном файле. Формы ровно те же, только "static" снят там, где вызов теперь идёт из другого
 * файла. */

#include <stddef.h>
#include <stdio.h>

struct spec;
struct groups;

/* Уровень в журнале — см. одноимённые макросы в failover.c и obfs.c. Метка подсистемы здесь
 * «apply»: строки с ней пишутся при компиляции и применении спеки. */
#define LOG_W "steer[warn] apply: "

/* masqueraded — подмена адреса IPv4 на устройстве, masq6 — IPv6 (с 1.10 раздельно, шаг 8): у fw4
 * это два разных ключа зоны (masq и masq6) и два правила `meta nfproto ipv4|ipv6 masquerade`, а
 * прежде любое правило masquerade засчитывалось за оба семейства — зона с одним masq6 выглядела
 * «NAT есть» для IPv4. Правило без семейства (`oifname "wg0" masquerade` в таблице inet) — оба;
 * в таблице ip — только IPv4, в ip6 — только IPv6.
 *
 * zone6 — зона fw4, чей masq6 подменяет IPv6 на устройстве: имя цепочки srcnat_<зона>, куда
 * устройство уходит переходом `oifname … jump srcnat_<зона>` (fw4 собирает её из UCI firewall:
 * зона, в `network` которой есть интерфейс устройства). Пусто — masq6 не найден или подмена стоит
 * правилом на самом устройстве, не в цепочке зоны. Устройство и зона называются по-разному
 * (wg0 в зоне wan), и предупреждение «у зоны wg0 включён masq6» называло бы не то, что править. */
struct fwcheck { int in_firewall, masqueraded, masq6; char zone6[32]; };

struct fwcheck fw_check(const char *device);
/* Каким ключом ipv6 судить IPv6 устройства dev выхода o: записанным у самого выхода, а если его
 * нет (OUT_V6_KIND) — у члена группы с этим устройством (вглубь вложенных групп) или у
 * владельца устройства (out_for_device). У группы, чей член `ipv6: nat`,
 * подмену на устройство члена ставит движок (postrouting_nat6 — по выходу-члену), и судить
 * устройство по ключу группы значило бы жаловаться «нет masquerade IPv6» на исправной настройке.
 * Возврат — значение enum out_ipv6 (spec.h; здесь int: заголовок спеки сюда не включается). */
struct output;
int out_ipv6_mode_dev(const struct spec *sp, const struct output *o, const char *dev);
/* То же по готовому тексту набора правил в форме `nft -t list ruleset` — разбор, которым fw_check
 * судит текст от ядра (fwcheck.c); отдельно ради стенда tests/fwmatch.c (дампы с живого fw4). */
struct fwcheck fw_check_dump(const char *dump, const char *device);
int report_mark_overlap(void);
/* Сброс кэшей дампа ruleset (fwcheck.c): стенд tests/fwmatch.c изображает им свежий процесс на
 * каждую пробу, демон — свежий ответ на каждый status и diag. */
void fwcheck_reset_cache(void);
/* Чем объяснять совпадение адреса — доменным списком, адресным или обоими (explain.c);
 * отдельной функцией ради стенда tests/fwmatch.c, см. её шапку там же. */
const char *explain_set_phrase(const char *addr, int has_files, int has_domains);
void report_traceroute_dep(const struct spec *sp);
void report_output_deps(const struct spec *sp);
/* Глобальный адрес IPv6 на устройстве раздачи — у клиентов есть IPv6 наружу (fwcheck.c). */
int lan_has_global_v6(const struct spec *sp);

/* Путь снимка состояния status — снимает apply.c, пишет и отдаёт status.c. */
void status_snap_path(char *buf, size_t n);

/* Проверка формы адреса/имени перед подстановкой в командную строку nft — общая для main.c
 * (разбор аргумента explain) и diag.c/explain.c. */
int addr_ok(const char *a);
int looks_like_name(const char *s);

/* Ответы status и explain — в поток, по спеке и группам, которые держит вызывающий: подкоманда
 * читает спеку сама, демон отдаёт свою из памяти (src/daemon/ctl.c). status_answer пишет и
 * снимок для --fast; status_fast — запомненный ответ (-1 — снимка нет). explain_emit
 * возвращает код подкоманды explain. */
void status_answer(const struct spec *sp, const struct groups *gr, FILE *out);
int status_fast(FILE *out);
/* Свои поля объекта выхода от того, кто знает помощников по их событиям (супервизор демона,
 * supd.c): fn печатает фрагмент JSON с запятой впереди или ничего. NULL — снять. Тот же шов,
 * что probe_source у хода перебора узлов (probe.h). */
void status_extra_source(void (*fn)(FILE *out, const char *out_name));
int explain_emit(const struct spec *sp, const struct groups *gr, const char *what, FILE *out);

/* Соединения с меткой движка (дамп ctnetlink) — src/daemon/conns.c, тем же разговором с
 * ctnetlink, что у ctnl.c; журнал имён работающего резолвера отдаёт сам резолвер, dlog.c. Оба
 * печатают в поток: подкоманда — в stdout, демон — в память (src/daemon/ctl.c). */
int ctnl_conns_print(FILE *out);
/* Смена выхода правил (apply, reload): снимок правил прежней спеки — до замены её в памяти, и
 * снятие соединений, которые прежний выход изменившегося правила держал бы дальше (conns.c). */
struct rr_snap;
struct groups;
struct rr_snap *reroute_snap(const struct spec *sp);
void reroute_evict(const struct rr_snap *old, const struct spec *sp, const struct groups *gr);
void reroute_snap_free(struct rr_snap *s);
int dlog_print(FILE *out);

int cmd_apply(const char *spec, int dry);
/* Служебные подкоманды демона для apply-сверки (apply.c, recon.c): план — проверки и отпечатки
 * частей без применения; применение — только названных частей. В справке их нет. */
int cmd_apply_plan(int argc, char **argv);
int cmd_apply_commit(int argc, char **argv);
int cmd_status(const char *spec, int fast);
int cmd_diag(const char *spec);
/* Отчёт diag по готовой спеке и группам — в поток out; код подкоманды (diag.c). */
int diag_emit(const struct spec *sp, const struct groups *gr, FILE *out);
int cmd_down(void);
int cmd_supervise(const char *spec);
/* Поднимать ли резолвер (ответ needs-dnsd; supd.c) — им же решает супервизор демона (supd.c). */
int dnsd_wanted(void);
int cmd_explain(const char *spec, const char *what);
/* События сети для сторожа (watch.c): сокет netlink на RTMGRP_LINK и адреса IPv4/IPv6
 * (-1 — не открылся) и дочитать накопленное (1 — было хоть одно событие). Ими же пользуется
 * сторож демона (watchd.c). WATCH_SETTLE_S — сколько ждать после события до внеочередного
 * прохода: смена сети приходит пачкой, см. watchd.c. */
int watch_nl_open(void);
int watch_nl_drain(int fd);
#define WATCH_SETTLE_S 5
/* masquerade на телефоне сторож возвращает не на каждом проходе (watch.c, watch_masq_due). */
#define WATCH_MASQ_S 600
int watch_masq_due(long *last, int force);

int cmd_failover(const char *spec, int verbose);   /* failover.c */
void probe_rule_cleanup(void);   /* failover.c */

void iptables_masq_ensure(const struct spec *sp);   /* apply.c, plat()->iptables_masq */

#endif
