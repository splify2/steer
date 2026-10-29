/* Мост Telegram → WebSocket: перехваченное соединение с дата-центром уходит через
 * wss://kwsN.web.telegram.org/apiws. Объяснение целиком — в tgws.c. Программа плагина tgws
 * (src/modules/main_tgws.c) собирает настройку из {conf} выхода и настроек плагина и зовёт этот код. */
#ifndef STEER_TGWS_H
#define STEER_TGWS_H

#include <stddef.h>

/* Всё, что мост знает о своём выходе и о настройках плагина. Строки — чужие (живут, пока жив вызов).
 * Списки — строки по одной записи, как их пишет человек в настройках плагина (settings.schema.json):
 *   alt    — запасные домены за Cloudflare, по порядку предпочтения;
 *   route  — пути ДЦ: «2 ws домен», «2m direct» (m — медийный);
 *   dc     — дополнение таблицы адресов ДЦ: «149.154.167.220 2», «149.154.164.250 4 media»;
 *   warp   — интерфейсы туннелей WARP по порядку предпочтения. */
struct tgws_opts {
    const char *name;           /* имя выхода (журнал) */
    const char *domain;         /* ключ domain выхода; у пробы — флаг --domain */
    int port;                   /* порт моста: ресурс выхода, его выдаёт ядро ({conf}, output.ports) */
    int verbose;                /* строка на каждое соединение в журнал */
    const char *const *alt;   size_t alt_n;
    const char *const *route; size_t route_n;
    const char *const *dc;    size_t dc_n;
    const char *const *warp;  size_t warp_n;
};

/* Пути, подобранные замером (настройка плагина `pick`): строки в формате `routes` («2 ws домен»,
 * «4 direct»). Действуют только там, где настройки (`routes`) о ДЦ молчат; таблица подменяется на ходу,
 * без перезапуска моста. 1 — карта изменилась, 0 — та же, -1 — нет памяти. */
int tgws_route_pick(const char *const *v, size_t n);

/* Поднять мост выхода. Не возвращается, пока жив. */
int tgws_serve(const struct tgws_opts *o);

/* Проверить путь до Telegram целиком: TLS, апгрейд веб-сокета и настоящий обмен MTProto
 * (req_pq_multi → resPQ). 0 — дата-центр ответил. Из o берутся domain и dc.
 *
 * direct — идти НАПРЯМУЮ в дата-центр, без веб-сокета и TLS: так подбор узнаёт, какие ДЦ
 * у этого провайдера не заблокированы и перехватывать их незачем.
 * timeout_s — сколько ждать; 0 — умолчание сборки. */
int tgws_probe(const struct tgws_opts *o, int dc, int media, int direct, int timeout_s);

#endif
