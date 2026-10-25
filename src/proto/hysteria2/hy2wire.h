/* Провод hysteria2: байты, без сокетов и без QUIC (модуль steer-hysteria2, docs/hysteria2.md).
 *
 * Здесь всё, что клиент пишет и читает внутри потоков и датаграмм QUIC, и ничего сверх этого: так
 * форматы проверяются стендом на векторах (tests/hy2match.c) и сверяются с настоящим сервером, не
 * поднимая соединения. Эталон — протокол apernet/hysteria (docs/PROTOCOL.md, ядро hysteria2) и
 * клиент Xray-core (transport/internet/hysteria).
 *
 * ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО: HTTP/3 целиком. Запрос авторизации — единственное, что hysteria2
 * берёт у HTTP/3, и собирается он вручную (решение владельца: nghttp3 не берём). Ниже только то,
 * что для этого нужно: QPACK без динамической таблицы (её мы не разрешаем — SETTINGS пуст) и
 * разбор ответа сервера, который эту таблицу тоже не использует, но сжимает строки Huffman. */
#ifndef STEER_HY2WIRE_H
#define STEER_HY2WIRE_H
#include <stddef.h>
#include <stdint.h>

/* ---- целые QUIC (RFC 9000, 16) ---- */
#define HY2_VARINT_MAX ((1ull << 62) - 1)
/* Записать; возвращает длину (1, 2, 4, 8) или 0, если значение больше 2^62 - 1 либо out мал. */
size_t hy2_varint_put(uint8_t *out, size_t cap, uint64_t v);
/* Прочитать; возвращает длину или 0, если байтов не хватает. */
size_t hy2_varint_get(const uint8_t *d, size_t n, uint64_t *v);
size_t hy2_varint_len(uint64_t v);

/* ---- управляющий поток HTTP/3 ----
 * Тип потока 0x00 и пустой кадр SETTINGS. Датаграммы HTTP/3 НЕ объявляются (H3_DATAGRAM): иначе
 * слой HTTP/3 сервера начинает читать очередь датаграмм QUIC наравне с приложением и уносит каждую
 * вторую (hy2wire.c). Таблицу QPACK не разрешаем (по умолчанию ноль). Возвращает длину. */
size_t hy2_h3_control(uint8_t *out, size_t cap);

/* ---- запрос авторизации ----
 * Кадр HEADERS с полями POST https://hysteria/auth, Hysteria-Auth, Hysteria-CC-RX (наша скорость
 * приёма, байт/с; 0 — не знаем), Hysteria-Padding. Возвращает длину или 0, если не влезло.
 * pad — длина набивки в знаках (эталон кладёт случайную). */
size_t hy2_auth_request(uint8_t *out, size_t cap, const char *auth, uint64_t rx_bps, size_t pad);

struct hy2_auth_resp {
    int      status;            /* :status ответа; успех — 233 */
    int      udp;               /* Hysteria-UDP: true */
    int      rx_auto;           /* Hysteria-CC-RX: auto — сервер сам определяет скорость (BBR) */
    uint64_t rx;                /* Hysteria-CC-RX числом: предел приёма сервера, байт/с; 0 — без предела */
};
#define HY2_AUTH_OK 233
/* Разобрать ответ с начала потока запроса. Возвращает: 1 — кадр HEADERS разобран, *r заполнен;
 * 0 — данных мало; -1 — ответ негоден (причина в *why, если не NULL). Кадры до HEADERS
 * (незнакомые, GREASE) пропускаются. */
int hy2_auth_response(const uint8_t *d, size_t n, struct hy2_auth_resp *r, const char **why);

/* ---- TCP ---- */
#define HY2_TCP_REQ_ID 0x401
/* TCPRequest: 0x401, адрес «хост:порт», набивка. Хост IPv6 — в скобках. Возвращает длину или 0. */
size_t hy2_tcp_request(uint8_t *out, size_t cap, const char *host, uint16_t port, size_t pad);
struct hy2_tcp_resp {
    int  ok;                    /* status 0 */
    char msg[128];              /* сообщение сервера при отказе (обрезано) */
};
/* Разобрать TCPResponse с начала потока. Возвращает: >0 — сколько байт заняла (дальше идут данные
 * потока); 0 — данных мало; -1 — негоден. */
int hy2_tcp_response(const uint8_t *d, size_t n, struct hy2_tcp_resp *r);

/* ---- UDP ---- */
struct hy2_udp_msg {
    uint32_t sid;
    uint16_t pkt;
    uint8_t  frag, nfrag;
    char     addr[264];         /* «хост:порт» */
    const uint8_t *data;
    size_t   n;
};
/* Заголовок одного сообщения: session id, packet id, frag id/count, адрес. Возвращает длину
 * заголовка (данные пишет вызывающий следом) или 0, если не влезло. */
size_t hy2_udp_header(uint8_t *out, size_t cap, uint32_t sid, uint16_t pkt, uint8_t frag,
                      uint8_t nfrag, const char *addr);
/* Сборка фрагментированных датаграмм UDP от сервера, по одной на packet id.
 *
 * Фрагменты хранятся каждый своим куском по реальной длине (сервер режет по своему MTU), слотов —
 * заявленное nfrag (u8, протокол сам ограничивает его 255). Сборок на поток столько, сколько пришло
 * разных packet id: сервер шлёт фрагменты нескольких датаграмм вперемешку, и одна сборка на поток
 * теряла бы обе. Недособранная (фрагмент потерян) живёт HY2_RASM_TTL_MS и снимается при следующем
 * фрагменте любой сборки. *head — список сборок потока (NULL — пусто). */
#define HY2_RASM_TTL_MS 5000
struct hy2_rasm;
/* Принять фрагмент (m уже разобран hy2_udp_parse, nfrag > 1). Собралась — вернуть блок malloc: pre байт
 * места под заголовок вызывающего, затем *total байт датаграммы; не собралась или брак (число
 * фрагментов, превышение 65507 байт) — NULL. now_ms — монотонные часы для срока. */
uint8_t *hy2_rasm_feed(struct hy2_rasm **head, const struct hy2_udp_msg *m, uint64_t now_ms, size_t pre,
                       size_t *total);
void hy2_rasm_free(struct hy2_rasm **head);
/* Разбор датаграммы; 0 — годна (m->data указывает внутрь d), -1 — негодна. */
int hy2_udp_parse(const uint8_t *d, size_t n, struct hy2_udp_msg *m);

/* ---- Brutal при нескольких рабочих ---- */
/* У каждого рабочего своё соединение QUIC, а заданные `up`/ответ сервера — предел на весь узел, поэтому
 * рабочие делят его. Доля одного: cap / max(1, n), но не ноль (ноль — это BBR). */
uint64_t hy2_brutal_share(uint64_t cap, unsigned n);
/* Рабочий занят вверх, если за ms миллисекунд отправил не меньше восьмой части того, что ему
 * положено при доле share_bps (бит/с). Единичные запросы и подтверждения скачивания — не занятость:
 * иначе скачивающие потоки отнимали бы долю у настоящей загрузки. */
int hy2_worker_busy(uint64_t bytes, uint64_t ms, uint64_t share_bps);

/* ---- Salamander (extras/obfs эталона) ---- */
#define HY2_SALT 8
/* BLAKE2b с 32-байтным выходом (RFC 7693, без ключа): единственное место, где он нужен. */
void hy2_blake2b256(uint8_t out[32], const uint8_t *in, size_t n);
struct hy2_salamander {
    uint8_t key[128];           /* пароль длиннее обрезается: узел с таким паролем отвергает разбор */
    size_t  keylen;
};
#define HY2_OBFS_PASS_MAX 128
void hy2_salamander_init(struct hy2_salamander *s, const char *password);
/* Датаграмма → в сеть: соль(8) + исходные байты, смешанные с BLAKE2b-256(ключ || соль). dst вмещает
 * n + 8; соль случайная. Возвращает n + 8. */
size_t hy2_salamander_tx(void *user, uint8_t *dst, const uint8_t *src, size_t n);
/* Из сети → датаграмма. dst может совпадать с src. Возвращает n - 8 или 0 (короче соли). */
size_t hy2_salamander_rx(void *user, uint8_t *dst, const uint8_t *src, size_t n);
/* То же с заданной солью — для стенда на векторах. */
size_t hy2_salamander_tx_salt(const struct hy2_salamander *s, const uint8_t salt[HY2_SALT],
                              uint8_t *dst, const uint8_t *src, size_t n);

/* ---- Gecko (extras/obfs/gecko.go эталона) ----
 * Salamander плюс форма: пакеты QUIC с длинным заголовком (рукопожатие) режутся на 2..8 кусков
 * случайной набивки и размера, короткие идут как есть. Кадр (до Salamander): байт 0x80, msgID,
 * (номер куска << 4 | число кусков), длина набивки (2 байта), набивка, кусок. Датаграмма с
 * нулевым старшим битом после снятия Salamander — обычный пакет. */
#define HY2_GECKO_MIN_DEF 512
#define HY2_GECKO_MAX_DEF 1200
#define HY2_GECKO_SLOTS 4
struct hy2_gecko_slot {
    uint8_t used, msgid, total, got;
    uint64_t at_ms;
    uint16_t len[8];
    uint8_t *buf;               /* 8 кусков по 1500 */
};
struct hy2_gecko {
    struct hy2_salamander sm;
    unsigned minp, maxp;        /* размер итоговой датаграммы UDP: наименьший и наибольший */
    uint8_t msgid;
    struct hy2_gecko_slot slot[HY2_GECKO_SLOTS];
};
/* min/max равные нулю — умолчания эталона (512, 1200). -1, если размеры негодны (эталон:
 * 0 < min <= max <= 2048). */
int hy2_gecko_init(struct hy2_gecko *g, const char *password, unsigned minp, unsigned maxp);
void hy2_gecko_free(struct hy2_gecko *g);
/* Швы фильтра QUIC (src/proto/quic/quic.h): отправка — датаграммы выдаёт out; приём — 0, пока
 * пакет не собран, иначе длина собранного в dst. */
int hy2_gecko_tx(void *user, const uint8_t *src, size_t n,
                 void (*out)(void *ctx, const uint8_t *d, size_t n), void *ctx);
size_t hy2_gecko_rx(void *user, uint8_t *dst, const uint8_t *src, size_t n);

#endif
