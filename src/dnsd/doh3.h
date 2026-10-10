#ifndef STEER_DNSD_DOH3_H
#define STEER_DNSD_DOH3_H

/* DoH ПО HTTP/3 (RFC 8484 + RFC 9114 + RFC 9204): КАДРЫ И QPACK — БЕЗ СЕТИ.
 *
 * Здесь только то, что проверяется по байтам: целые переменной длины, поток управления с SETTINGS,
 * запрос вопроса (HEADERS + DATA), разбор ответа (HEADERS + DATA на потоке вопроса). Соединение QUIC,
 * потоки и сроки — в dup.c поверх шва dupq.h; вынесено отдельным файлом затем, чтобы стенд dupmatch
 * проверял кадры без ngtcp2 и без сокетов, как у DoQ (doq.h) и DoH/h2 (doh2.h).
 *
 * ЧТО ВЫБРАНО.
 *   - QPACK — только статическая таблица. Своё SETTINGS_QPACK_MAX_TABLE_CAPACITY и
 *     SETTINGS_QPACK_BLOCKED_STREAMS — 0: сервер не вправе вносить в таблицу ничего, ссылки на
 *     динамическую таблицу в его ответе — ошибка сжатия (RFC 9204, 4.5), и потоки кодировщика и
 *     декодировщика нам не нужны (RFC 9204, 4.2 разрешает их не открывать). Запрос пишется только
 *     ссылками на статическую таблицу и литералами без индексации.
 *   - Метод POST с телом: сообщение DNS идёт в DATA как есть, номер в нём 0 (RFC 8484, 4.1; кэшируемость),
 *     исходный номер возвращает тот, кто принял вопрос (dup.c).
 *   - Ответ принимается целиком, когда сервер закончил поток (FIN): код :status — 200, тело — сообщение
 *     DNS. Промежуточные 1xx пропускаются, неизвестные кадры пропускаются (RFC 9114, 9: запас
 *     расширений), трейлеры игнорируются. */

#include <stddef.h>
#include <stdint.h>

#define H3D_DATA      0x0
#define H3D_HEADERS   0x1
#define H3D_SETTINGS  0x4
#define H3D_GOAWAY    0x7

#define H3D_S_QPACK_MAX_TABLE_CAPACITY 0x1
#define H3D_S_QPACK_BLOCKED_STREAMS    0x7

#define H3D_E_NO_ERROR              0x100
#define H3D_E_GENERAL_PROTOCOL      0x101
#define H3D_E_INTERNAL              0x102
#define H3D_E_REQUEST_CANCELLED     0x10c
#define H3D_E_FRAME_UNEXPECTED      0x105
#define H3D_E_MESSAGE_ERROR         0x10e
#define H3D_E_QPACK_DECOMPRESSION   0x200

#define H3D_ALPN "h3"
#define H3D_DEFAULT_PORT 443

/* Наибольшее тело ответа: сообщение DNS в 16 бит длины (RFC 1035, 4.2.2). Предел формата, не наш. */
#define H3D_MSG_MAX 65535u
/* Наибольший буфер ответа на потоке: тело плюс заголовки и кадровая обвязка. Заголовки ответа сервера
 * (куки, политики) бывают в несколько килобайт; больше шестнадцати — сервер шлёт не ответ DNS. */
#define H3D_RX_MAX (H3D_MSG_MAX + 16384u)

/* Целое переменной длины (RFC 9000, 16): в dst, число байт или 0, если не поместилось. */
size_t h3d_varint_put(uint8_t *dst, size_t cap, uint64_t v);
/* Из buf[0..n): *v, число занятых байт; 0 — буфер оборван. */
size_t h3d_varint_get(const uint8_t *buf, size_t n, uint64_t *v);

/* Начало потока управления клиента: тип потока 0x00 и кадр SETTINGS (таблица QPACK 0, блокированных
 * потоков 0). Поток остаётся открытым до конца соединения. Байт записано или 0. */
size_t h3d_control_open(uint8_t *dst, size_t cap);

/* Запрос вопроса q[0..qn): HEADERS (:method POST, :scheme https, :authority, :path, content-type,
 * accept) и DATA с телом, номер в теле — 0. Байт записано или 0 (вопрос короче заголовка DNS или не
 * влез). Идёт на новом двунаправленном потоке с FIN. */
size_t h3d_request(uint8_t *dst, size_t cap, const char *authority, const char *path,
                   const uint8_t *q, size_t qn);

/* Ответ на потоке вопроса: rx[0..n) — всё, что пришло, fin — сервер закончил поток.
 *    0 — ещё не весь ответ (ждать);
 *    1 — ответ целый: *status — код, тело (оно передвинуто в начало rx) — *blen байт;
 *   -1 — нарушение формата: *why — короткая причина для журнала, *err — код ошибки HTTP/3 для закрытия.
 * Код, не равный 200, — тоже ответ (1): решает вызывающий. Вызывать с fin == 0 можно, но целым ответ
 * без FIN не считается: тело могло бы продолжиться. Буфер меняется только при возврате 1. */
int h3d_response(uint8_t *rx, size_t n, int fin, int *status, size_t *blen, const char **why, uint64_t *err);

/* Код :status из блока полей QPACK (без префикса кадра); 0 — :status нет, -1 — блок нарушает формат
 * или опирается на динамическую таблицу. */
int h3d_status(const uint8_t *blk, size_t n);

/* Имя кода ошибки HTTP/3 для журнала; неизвестный — «код 0x…». */
const char *h3d_errname(uint64_t code, char *buf, size_t cap);

#endif
