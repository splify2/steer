/* Соединение с узлом VLESS/Reality и проверка «нас признали». Подробности — в client.c.
 *
 * Соединение — это struct transport (proto/transport/transport.h): сокет, безопасность и
 * транспорт узла. VLESS над ним — заголовок запроса (vless_proto.h) и кадры Vision (vision.h);
 * их кладёт в поток дайлер стека туннеля (vldial.c) и проверка узла ниже. */
#ifndef STEER_CLIENT_H
#define STEER_CLIENT_H
#include "vless.h"
#include "transport.h"

/* Коды самого VLESS — поверх кодов транспорта TR_* (transport.h), с которыми они делят одно
 * пространство чисел: -30…-38 были общими и прежде. */
#define VLESS_CONN_EBADUUID  (-35)
/* Reality не признал ключ: TLS установлен, но отвечает маскировочный сайт. Отдельный код,
 * потому что это единственная ошибка, которая иначе выглядит как рабочий узел. */
#define VLESS_CONN_EREJECTED (-36)

/* Соединение с узлом: TCP, безопасность и транспорт из ссылки узла. 0 — готово. */
int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s);

int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n);

/* То же, но с замерами. Оба в миллисекундах, -1 если до этого шага не дошло:
 *
 *   handshake_ms — от начала TCP до готового транспорта (TCP + TLS + HTTP/2, если он есть).
 *                  Это цена ПОДКЛЮЧЕНИЯ к узлу, платится один раз;
 *   ttfb_ms      — от отправки запроса до первого байта ответа VLESS. Дочитывание
 *                  заголовка расходует тот же срок ожидания, но в TTFB не входит.
 *
 * Именно ttfb, а не ICMP: пинг через наш TUN не ходит вовсе (ICMP мы не пересылаем), и
 * «пинг» через туннель был бы не тем, что измеряют. Здесь измеряется ровно тот путь, по
 * которому пойдёт трафик. */
int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms);

/* Текст причины для кода VLESS или транспорта. */
const char *vless_strerror(int rc);

/* Сколько места обязан дать вызывающий при чтении: транспорты поверх HTTP/2 отдают за
 * один раз до целой записи TLS. */
#define VLESS_MIN_RECV_CAP TRANSPORT_MIN_READ_CAP

#endif
