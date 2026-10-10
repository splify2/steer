#ifndef STEER_DNSD_DOH2_H
#define STEER_DNSD_DOH2_H

/* DoH ПО HTTP/2 (RFC 8484 + RFC 9113): КАДРЫ И HPACK — БЕЗ СЕТИ.
 *
 * Как и doq.h, здесь только то, что проверяется по байтам: преамбула соединения, кадры, запрос
 * POST application/dns-message одним HEADERS+DATA и разбор статуса из блока заголовков ответа.
 * Соединение, потоки, окна и повторы — в dup.c; вынесено затем, чтобы стенд dupmatch проверял
 * кадры без TLS и сокетов.
 *
 * ЗАЧЕМ HTTP/2. RFC 8484 требует от серверов DoH поддержки HTTP/2, а HTTP/1.1 — нет. Quad9 отвечает
 * на HTTP/1.1 кодом 505 («requires HTTP/2 in accordance with section 5.2 of RFC 8484»), и клиент,
 * умеющий одно HTTP/1.1, оставался без публичного сервера, которого держатся многие. Клиент
 * предлагает в ALPN «h2, http/1.1» и ведёт соединение по выбору сервера: h2 — этим модулем,
 * http/1.1 — прежним разбором в dup.c.
 *
 * ЧЕМ ЭТО ОТЛИЧАЕТСЯ ОТ src/proto/tls/h2.c. Тот клиент — один поток на соединение (для xhttp и
 * grpc), здесь потоков много: один вопрос — один поток, поэтому кадровая часть ниже не знает про
 * поток вовсе и хранит его номер тот, кто зовёт.
 *
 * HPACK. Запрос кодируется литералами без индексации (динамической таблицы у нас нет). Чтобы и
 * ответ не потребовал динамической таблицы, в SETTINGS уходит SETTINGS_HEADER_TABLE_SIZE = 0
 * (RFC 9113, 6.5.2; RFC 7541, 4.2): сервер обязан не помещать в таблицу ничего, и индекс выше 61
 * в его блоке значит нарушение (COMPRESSION_ERROR). Тогда разбор ответа — статическая таблица и
 * литералы, а Хаффман нужен лишь цифрам статуса (h2d_status). Прочие заголовки ответа пропускаются
 * по длине: для DoH нужны статус и тело. */

#include <stddef.h>
#include <stdint.h>

#define H2D_DATA          0x0
#define H2D_HEADERS       0x1
#define H2D_RST_STREAM    0x3
#define H2D_SETTINGS      0x4
#define H2D_PUSH_PROMISE  0x5
#define H2D_PING          0x6
#define H2D_GOAWAY        0x7
#define H2D_WINDOW_UPDATE 0x8
#define H2D_CONTINUATION  0x9

#define H2D_F_END_STREAM  0x1
#define H2D_F_ACK         0x1
#define H2D_F_END_HEADERS 0x4
#define H2D_F_PADDED      0x8
#define H2D_F_PRIORITY    0x20

#define H2D_S_HEADER_TABLE_SIZE      0x1
#define H2D_S_ENABLE_PUSH            0x2
#define H2D_S_MAX_CONCURRENT_STREAMS 0x3
#define H2D_S_INITIAL_WINDOW_SIZE    0x4
#define H2D_S_MAX_FRAME_SIZE         0x5

#define H2D_E_NO_ERROR         0x0
#define H2D_E_PROTOCOL_ERROR   0x1
#define H2D_E_REFUSED_STREAM   0x7
#define H2D_E_CANCEL           0x8
#define H2D_E_COMPRESSION      0x9

/* Наибольший кадр, который принимает сервер и принимаем мы: значение по умолчанию (RFC 9113, 4.2);
 * SETTINGS_MAX_FRAME_SIZE мы не повышаем, а наши кадры (вопрос DNS ≤ 1 КиБ) всегда меньше. */
#define H2D_MAX_FRAME 16384u
#define H2D_WINDOW_DEFAULT 65535

/* Заголовок кадра, найденного в начале буфера; body указывает внутрь буфера. */
struct h2d_frame {
    uint8_t type, flags;
    uint32_t sid;
    const uint8_t *body;
    size_t len;
    size_t total;                       /* сколько байт буфера занял кадр (9 + len) */
};

/* Первый кадр буфера buf[0..n).
 *   1  — кадр целый, *f заполнен
 *   0  — ждём ещё байт
 *  -1  — длина больше H2D_MAX_FRAME: нарушение (FRAME_SIZE_ERROR) */
int h2d_next(const uint8_t *buf, size_t n, struct h2d_frame *f);

/* Кадр в dst: 9 байт заголовка и тело. Байт записано, или 0, если не поместилось. */
size_t h2d_frame_put(uint8_t *dst, size_t cap, uint8_t type, uint8_t flags, uint32_t sid,
                     const uint8_t *body, size_t n);

/* Преамбула клиента (24 байта) и SETTINGS: таблица заголовков 0, push выключен. */
size_t h2d_hello(uint8_t *dst, size_t cap);

/* Запрос вопроса q[0..qn): HEADERS (:method POST, :scheme https, :path, :authority, content-type,
 * accept, content-length) с END_HEADERS и следом DATA с END_STREAM. ID сообщения в теле — 0 (RFC 8484,
 * 4.1: так ответ кэшируется, а поток и есть номер вопроса). Байт записано, или 0, если не поместилось
 * или qn < 12. authority — уже с портом, если он нестандартный. */
size_t h2d_request(uint8_t *dst, size_t cap, uint32_t sid, const char *authority, const char *path,
                   const uint8_t *q, size_t qn);

/* Код ответа из блока заголовков (HEADERS + CONTINUATION целиком): 100..599; 0 — :status в блоке
 * нет (трейлеры); -1 — блок не разобрался или ссылается на динамическую таблицу, которой у нас нет. */
int h2d_status(const uint8_t *blk, size_t n);

/* Три цифры :status из значения поля (huff — оно закодировано Хаффманом, одинаково в HPACK и QPACK); код
 * 100..999 или -1. Общее с doh3.c. */
int h2d_status_value(const uint8_t *p, size_t n, int huff);

/* Имя кода ошибки HTTP/2 для журнала («PROTOCOL_ERROR»); неизвестный — «код N». */
const char *h2d_errname(uint32_t code, char *buf, size_t cap);

#endif
