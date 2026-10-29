/* Модуль hysteria2 (steer-hysteria2): узел подписки и общие объявления. Устройство — docs/hysteria2.md.
 *
 * Узел — то, что нужно клиенту, чтобы пройти авторизацию у сервера hysteria2 и нести через него
 * потоки: адрес, пароль, проверка сертификата, обфускация, скорость и прыжки по портам. Формат
 * ссылки и конфига Xray-core разбирает hy2sub.c; соединение и мультиплексирование — hy2conn.c;
 * дайлер стека — hy2dial.c; команды и слежка за узлом — hy2main.c. */
#ifndef STEER_HY2_H
#define STEER_HY2_H
#include <stddef.h>
#include <stdint.h>

#include "hy2wire.h"

#define HY2_HOP_RANGES 8        /* равно QC_HOP_RANGES (проверяет hy2conn.c) */

struct hy2_node {
    char name[128];             /* человеческое имя: #фрагмент ссылки, tag/remarks конфига, иначе хост:порт */
    char host[128];             /* адрес сервера: имя или литерал IP */
    uint16_t port;              /* базовый порт (первый из списка при прыжках) */
    char auth[192];             /* содержимое Hysteria-Auth (в ссылке — вся часть userinfo) */
    char sni[128];              /* имя для SNI и проверки сертификата; пусто — хост, если это имя */
    uint8_t insecure;           /* insecure=1: сертификат не проверяется */
    uint8_t has_pin;            /* pinSHA256 задан: проверяется отпечаток листа, а не цепочка */
    uint8_t pin[32];
    uint8_t obfs;               /* 1 — Salamander, 2 — Gecko (Salamander и нарезка пакетов рукопожатия) */
    char obfs_pass[HY2_OBFS_PASS_MAX + 1];
    uint16_t gecko_min, gecko_max;      /* размер датаграммы Gecko; 0 — умолчания эталона (512, 1200) */
    uint64_t up_bps, down_bps;  /* байт/с; 0 — не задано (тогда BBR, как у эталона) */
    uint16_t hop[HY2_HOP_RANGES * 2];   /* диапазоны портов сервера для прыжков, включительно */
    unsigned hop_n;
    unsigned hop_s;             /* период смены порта, с (по умолчанию 30, не меньше 5) */
    /* Первое поле, не влезшее в свой буфер: узел с урезанным паролем или SNI выглядит исправным и не
     * авторизуется без единого слова причины. node_check отвергает такой узел с названием и шириной.
     * NULL — всё влезло; имя узла в счёт не идёт. */
    const char *trunc_what;
    uint16_t trunc_cap;         /* ширина поля без нуля */
    char skip_reason[64];       /* почему узел непригоден */
};

#define HY2_SKIP_REASONS 8
struct hy2_skip {
    char reason[64];
    char example[144];
    size_t count;
};
struct hy2_sub_stats {
    size_t skipped;             /* узлов hysteria2, непригодных к работе */
    size_t foreign;             /* ссылок и outbound'ов других протоколов */
    struct hy2_skip reasons[HY2_SKIP_REASONS];
    size_t reasons_n, reasons_dropped;
};

/* Одна ссылка hysteria2:// или hy2://. 0 — узел пригоден; 1 — разобран, но негоден (причина в
 * skip_reason); -1 — это не ссылка hysteria2. */
int hy2_parse_url(const char *url, struct hy2_node *n);

/* Подписка целиком: список ссылок по строкам либо конфиг Xray-core (объект с outbounds, массив
 * конфигов или массив outbound). Возвращает число пригодных узлов, записанных в out. */
size_t hy2_parse_sub(const char *text, struct hy2_node *out, size_t max, struct hy2_sub_stats *st);
/* Тело подписки → текст: base64 разворачивается, если это он (как у vless_sub_text); иначе то же. */
const char *hy2_sub_text(const char *raw, size_t raw_n, char *dec, size_t dec_n);
/* Подписка из файла целиком, в куче: массив узлов (free) и их число; NULL — не открылся, файл
 * больше 64 МиБ или нет памяти. Числа узлов ограничивает память, а не константа. */
struct hy2_node *hy2_load_sub(const char *path, size_t *cnt, struct hy2_sub_stats *st);

/* Скорость «100 mbps» / «100» (Мбит/с) → байт/с. 0 — не разобралось или пусто. */
uint64_t hy2_parse_bandwidth(const char *s);
/* Список портов «443», «20000-30000», «443,5000-6000»: порт узла — первый, диапазоны — для
 * прыжков (если портов больше одного). Возвращает 0; -1 — не разобралось; -2 — диапазонов
 * больше HY2_HOP_RANGES. */
int hy2_parse_ports(const char *s, uint16_t *first, uint16_t *hop, unsigned *hop_n);

#endif
