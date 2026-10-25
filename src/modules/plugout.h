/* {conf} помощника протокола глазами кода протокола (vlmain.c, hy2main.c, pxmain.c, xsclient.c).
 *
 * Реализация — src/modules/plugconf.c, он есть только в программе протокола (точка входа модуля или
 * плагина); статические сборки (телефон, стенды) его не несут, поэтому код протокола ссылается на эти
 * функции СЛАБО (#pragma weak) и без --conf ведёт себя как всегда. Заголовок отдельный от plugconf.h,
 * чтобы профили статических сборок оставались замкнутыми (tests/buildmatch.sh). */
#ifndef STEER_PLUGOUT_H
#define STEER_PLUGOUT_H

#include <stdint.h>

struct output;

/* Что из {conf} помощник берёт мимо разбора спеки. */
struct plugconf {
    int active;                 /* процесс запущен с --conf */
    uint32_t mark, sock_mark;
    int table, tcp_port;
    int sock_mark_required;
    char *status_path;          /* <state>/plugin/<id>/<выход>.status.json */
    char *fakeip_path;          /* paths.fakeip; NULL — ядро не дало */
};

/* {conf} этого процесса; active 0 — запуск без --conf (подкоманда, раскладка 2.0, стенд). */
const struct plugconf *plugconf_get(void);

/* После registry_assign: метка и таблица выхода — из {conf}; пул пишет состояние в файл плагина,
 * стек читает fake-IP из paths.fakeip. Без --conf ничего не делает. */
void plugconf_out(struct output *o);

#endif
