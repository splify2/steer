/* QUIC-соединение движка: тонкая обёртка над ngtcp2 (шаг 7 выпуска 1.10, docs/architecture.md,
 * «Криптография»/«Туннели»: QUIC как слой).
 *
 * ЗАЧЕМ. Потребителей у слоя два, оба позже: DoQ в dnsd (1.11) и модуль hysteria2. Им нужно одно и
 * то же — клиентское соединение поверх UDP-сокета, потоки, датаграммы RFC 9221, таймеры, — и
 * ни тому, ни другому не нужны ни ngtcp2, ни wolfSSL в заголовках. Поэтому здесь ни одного типа
 * обеих библиотек: наружу торчат сокет, потоки как целые идентификаторы и колбэки с байтами.
 * Сами протоколы (DoQ, запрос авторизации HTTP/3 и кадры TCP/UDP у hysteria2) — на стороне
 * потребителя: это байты внутри потоков и датаграмм.
 *
 * МОДЕЛЬ ВЫПОЛНЕНИЯ — ОДНОПОТОЧНАЯ, ВНЕШНЯЯ ЛИНИЯ СОБЫТИЙ. Соединение владеет одним неблокирующим
 * UDP-сокетом (qc_fd) и ничего не запускает само:
 *
 *     qc_open ─► регистрируем qc_fd() в своём epoll (EPOLLIN)
 *     готов сокет  ─► qc_on_readable()    (читает все дейтаграммы, отвечает, зовёт колбэки)
 *     истёк таймер ─► qc_on_timer()       (потеря, PTO, пейсинг, idle; срок — qc_timeout_ms())
 *     хочешь писать ─► qc_stream_send / qc_datagram_send (ставят в очередь и сразу пытаются
 *                     отправить; остальное уходит по ACK и таймеру)
 *
 * Для простых потребителей и стендов — qc_run(): один проход epoll_wait по этому сокету и таймеру.
 * После любого вызова срок таймера мог измениться — его надо перечитать (qc_timeout_ms).
 *
 * КОЛБЭКИ ВЫЗЫВАЮТСЯ ТОЛЬКО ИЗ qc_on_readable, qc_on_timer и qc_run (отправка ничего не читает).
 * Из колбэка можно звать qc_stream_send, qc_datagram_send, qc_stream_open и qc_close; qc_free —
 * нельзя (объект ещё в работе у вызвавшего): закрытие сообщается on_closed, освобождает
 * потребитель после возврата.
 *
 * ПЕРЕГРУЗКА. По умолчанию CUBIC (это то, чего ждёт DoQ). cfg.brutal_bps != 0 включает Brutal —
 * наш патч к ngtcp2 (build/ngtcp2/patches): заданная скорость в БАЙТАХ в секунду, без снижения при
 * потерях, как у hysteria2.
 *
 * ЧТО ЗДЕСЬ НАМЕРЕННО ПРОСТО. Один путь (без миграции), одна пара адресов, без 0-RTT и билетов
 * сессии, без переупорядочения приёма потоков: данные передаются потребителю сразу, окно
 * приёма продлевается сразу (обратного давления на отправителя нет — потребитель, которому
 * нужно замедлить, закрывает поток).
 *
 * ПАКЕТНЫЙ ВВОД-ВЫВОД UDP. Приём — recvmmsg (до 32 датаграмм за вызов), с UDP_GRO ядро склеивает
 * подряд пришедшие датаграммы одного потока в одну, и слой режет их по размеру сегмента. Отправка —
 * пачка ngtcp2 (ngtcp2_conn_write_aggregate_pkt) уходит одним sendmsg с UDP_SEGMENT, если датаграммы
 * одного размера, иначе sendmmsg. Нет UDP_GRO или UDP_SEGMENT в ядре — слой молча остаётся на
 * recvmmsg и sendmmsg; ошибка GSO при отправке (EIO — устройство без контрольной суммы, EINVAL)
 * выключает GSO для этого сокета. Порядок, пейсинг и Brutal те же: пачку составляет ngtcp2. */
#ifndef STEER_QUIC_H
#define STEER_QUIC_H
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define QC_EINVAL   (-1)    /* неверный аргумент */
#define QC_ENOMEM   (-2)
#define QC_ESOCK    (-3)    /* сокет или адрес */
#define QC_ETLS     (-4)    /* не создался контекст TLS (roots, сертификат) */
#define QC_EQUIC    (-5)    /* ngtcp2 отказал при создании */
#define QC_EAGAIN   (-6)    /* сейчас нельзя: потоков больше нет, очередь полна, рукопожатие идёт */
#define QC_ECLOSED  (-7)    /* соединение закрыто */
#define QC_ETOOBIG  (-8)    /* датаграмма больше допустимой */
#define QC_ENOSTREAM (-9)   /* нет такого потока */

/* Причины закрытия для on_closed. */
#define QC_CLOSE_LOCAL      0   /* закрыли мы (qc_close) */
#define QC_CLOSE_PEER       1   /* закрыл сервер (CONNECTION_CLOSE, draining) */
#define QC_CLOSE_IDLE       2   /* молчание дольше max_idle */
#define QC_CLOSE_HANDSHAKE  3   /* рукопожатие не уложилось в срок или отвергнуто (TLS, ALPN) */
#define QC_CLOSE_ERROR      4   /* ошибка протокола или сокета */

#define QC_HOP_RANGES 8     /* диапазонов портов в прыжках */
/* Серверов, для которых кэш билетов 0-RTT (qc_tls_early) хранит сессию. Восемь: апстримов DoQ у человека
 * единицы (по одному на правило с dns), запись весит около полукилобайта (билет и параметры транспорта),
 * то есть кэш — четыре килобайта; больше серверов вытесняют самые старые записи по кругу. */
#define QC_SESS_MAX 8

/* Шов для обфускации: фильтр между ngtcp2 и сокетом. Нужен hysteria2 (Salamander: каждая
 * датаграмма UDP — соль в 8 байт и исходный пакет, побитово смешанный с ключом из соли), а DoQ и
 * обычный QUIC его не задают. Ни того, ни другого фильтра слой не знает: он вызывает функции
 * и берёт длину результата.
 *   tx  — из src (n байт) в dst (вмещает n + 64), вернуть длину; 0 — не отправлять;
 *   rx  — из src в dst, dst МОЖЕТ совпадать с src (обработка на месте); вернуть длину; 0 —
 *         датаграмма не наша, отбросить. */
struct qc_filter {
    size_t (*tx)(void *user, uint8_t *dst, const uint8_t *src, size_t n);
    size_t (*rx)(void *user, uint8_t *dst, const uint8_t *src, size_t n);
    void *user;
    /* Вместо tx, когда одному пакету соответствует НЕСКОЛЬКО датаграмм (Gecko режет пакеты
     * рукопожатия на куски): фильтр вызывает out(ctx, датаграмма, длина) на каждую. rx тогда
     * возвращает 0, пока пакет не собран целиком, и длину собранного — когда собран. */
    int (*tx_multi)(void *user, const uint8_t *src, size_t n,
                    void (*out)(void *ctx, const uint8_t *d, size_t n), void *ctx);
};

struct qc;          /* соединение */
struct qc_tls;      /* контекст TLS: корни проверки, при желании общий для соединений */

struct qc_ops {
    void (*on_handshake)(void *user);
    /* fin != 0 — сервер закончил передачу по этому потоку (данных в вызове может не быть). */
    void (*on_stream_data)(void *user, int64_t sid, const uint8_t *d, size_t n, int fin);
    /* Поток закрыт целиком (обе стороны). app_err — код приложения, 0 если его не было. */
    void (*on_stream_close)(void *user, int64_t sid, uint64_t app_err);
    void (*on_datagram)(void *user, const uint8_t *d, size_t n);
    /* Единственный раз. why — короткая строка для журнала (не для показа человеку). */
    void (*on_closed)(void *user, int reason, const char *why);
    /* Сервер НЕ принял 0-RTT (cfg.early_data): всё, что ушло раньше рукопожатия, потеряно вместе с
     * потоками — их номера начнутся заново. Зовётся один раз, из завершения рукопожатия, до
     * on_handshake; потребитель обязан повторить свои запросы на новых потоках. NULL — не нужно. */
    void (*on_early_rejected)(void *user);
};

struct qc_cfg {
    /* Сервер: IPv4/IPv6 в текстовом виде (имён не разбираем — резолвит потребитель). */
    const char *host;
    uint16_t    port;
    /* Имя для SNI и проверки сертификата; NULL — без SNI (и без проверки имени). */
    const char *sni;
    /* ALPN, одна строка: "h3" для hysteria2, "doq" для DNS over QUIC. */
    const char *alpn;
    /* Проверка сертификата. 1 (по умолчанию нулевая структура = проверять) — цепочка до корней
     * из ca_pem либо, если его нет, из файла ca_file (NULL — общий файл ca-bundle роутера,
     * CERTV_DEFAULT_ROOTS; на телефоне путь даёт tls_cert_roots()) и имя sni. insecure = 1 —
     * не проверять ничего (как в hysteria2 с insecure: true). */
    int         insecure;
    /* pinSHA256: 32 байта SHA-256 листового сертификата. Задан — цепочка и имя НЕ проверяются
     * (как у эталона), а после рукопожатия отпечаток сверяется, и несовпадение закрывает
     * соединение причиной QC_CLOSE_HANDSHAKE. Работает только с готовым cfg.tls == NULL. */
    const uint8_t *pin_sha256;
    const uint8_t *ca_pem;
    size_t      ca_pem_n;
    const char *ca_file;
    /* Готовый общий контекст TLS (qc_tls_new): корни разбираются один раз на процесс. NULL — свой
     * на соединение (ca_pem/ca_file/insecure выше берутся тогда). */
    struct qc_tls *tls;

    /* Brutal: целевая скорость, БАЙТ/с. 0 — обычный CUBIC. */
    uint64_t    brutal_bps;
    /* SO_MARK сокета до connect(): маршрут ядро выбирает по метке (собственный трафик туннеля идёт
     * мимо самого туннеля, «подложка» в spec.h). mark_required — отказ SO_MARK отказывает открытие
     * (иначе соединение молча ушло бы не туда), как у транспортов. */
    uint32_t    sock_mark;
    int         mark_required;
    /* Обратное давление на приём: окна потоков и соединения НЕ продлеваются сами, потребитель
     * возвращает их qc_stream_consumed по мере того, как отдал байты дальше. По умолчанию (0)
     * окно продлевается сразу, как описано в шапке. */
    int         flow_manual;
    /* BBR вместо CUBIC (при brutal_bps == 0). */
    int         bbr;
    /* Датаграммы RFC 9221: наибольшая принимаемая, 0 — датаграмм не принимаем (и не шлём). Нужны
     * hysteria2 (UDP-релей); DoQ их не использует. */
    size_t      datagram_max;
    /* 0-RTT: если для этого сервера (sni и порт) в общем контексте tls уже есть билет прошлой сессии
     * с разрешением early data, потоки можно открывать и слать в них ДО конца рукопожатия
     * (qc_early_ready), а билеты этого соединения запоминаются для следующих. Нужен tls, у которого
     * включено qc_tls_early; иначе поле ничего не значит. Безопасность 0-RTT — забота потребителя:
     * данные 0-RTT можно повторить (воспроизвести) на пути, поэтому в них годятся только идемпотентные
     * запросы (вопрос DNS, RFC 9250, раздел 5.5). */
    int         early_data;

    /* Пределы; нули — умолчания. */
    unsigned    idle_ms;            /* max_idle_timeout, по умолчанию 30000 */
    unsigned    keepalive_ms;       /* PING при молчании; 0 — не слать. После рукопожатия — не реже
                                     * трети меньшего из двух сроков простоя (свой и сервера) */
    unsigned    handshake_ms;       /* по умолчанию 10000 */
    uint64_t    max_data;           /* окно приёма соединения, по умолчанию 8 МиБ */
    uint64_t    max_stream_data;    /* окно приёма потока, по умолчанию 2 МиБ */
    uint64_t    max_streams;        /* потоков, которые открывает сервер, по умолчанию 16 */
    size_t      send_buf;           /* буфер отправки на поток (неподтверждённое + очередь), 1 МиБ */

    /* Фильтр датаграмм сокета (обфускация hysteria2, Salamander); NULL — датаграммы идут как есть.
     * Копируется при открытии. */
    const struct qc_filter *filter;
    /* Прыжки по портам сервера: hop_n диапазонов [hop[2i], hop[2i+1]] (порядок хоста, включительно),
     * смена порта не чаще чем раз в hop_ms (0 — порт выбирается один раз). cfg.port остаётся
     * «базовым» адресом сервера для ngtcp2 и SNI; отправка идёт на выбранный порт диапазона, приём
     * — с любого порта диапазона. hop_n = 0 — прыжков нет. */
    unsigned    hop_n, hop_ms;
    uint16_t    hop[QC_HOP_RANGES * 2];
};

struct qc_stats {
    uint64_t rtt_us;            /* сглаженный RTT */
    uint64_t cwnd;              /* окно перегрузки, байт */
    uint64_t in_flight;         /* байт в полёте */
    uint64_t pkt_sent, pkt_lost, pkt_recv;
    uint64_t bytes_sent, bytes_recv;
    int      handshake_done;
    int      brutal;            /* 1 — работает Brutal */
    uint64_t dg_dropped;        /* датаграмм выброшено из очереди (не влезли в пакет) */
    uint64_t tx_calls, rx_calls;    /* системных вызовов отправки и приёма UDP (sendmsg/sendmmsg/recvmsg/recvmmsg) */
};

/* Контекст TLS отдельно от соединения: разбор корней (полторы сотни сертификатов) — не то, что
 * стоит делать на каждое соединение. Потоки не защищены: контекст принадлежит потоку, где
 * создан. Освобождает потребитель, когда все соединения на нём закрыты. */
struct qc_tls *qc_tls_new(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
void qc_tls_free(struct qc_tls *t);
/* Включить в контексте билеты сессий для 0-RTT (cfg.early_data): билеты хранятся в памяти процесса,
 * по одному на сервера (sni и порт), не больше QC_SESS_MAX серверов; на диск не пишутся. Включённый
 * контекст безопасен из нескольких потоков (кэш под замком). */
void qc_tls_early(struct qc_tls *t);

/* Открыть соединение: сокет, TLS, первый пакет рукопожатия уходит сразу. 0 — успех, *out —
 * соединение; иначе QC_E*. ops копируется; user возвращается в колбэках. */
int  qc_open(const struct qc_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out);
/* Закрыть: CONNECTION_CLOSE(app_err) серверу, затем on_closed(LOCAL). Память освобождает qc_free. */
void qc_close(struct qc *q, uint64_t app_err);
void qc_free(struct qc *q);

int  qc_fd(const struct qc *q);
/* Мс до следующего срока: 0 — пора, -1 — сроков нет (соединение закрыто). Округляется вверх. */
int  qc_timeout_ms(struct qc *q);
/* Оба возвращают 0, пока соединение живо, и QC_ECLOSED после on_closed. */
int  qc_on_readable(struct qc *q);
int  qc_on_timer(struct qc *q);
/* Проход epoll_wait(timeout_ms) по сокету и таймеру (-1 — ждать срока таймера сколько нужно). */
int  qc_run(struct qc *q, int timeout_ms);

int  qc_handshake_done(const struct qc *q);
/* 0-RTT возможен: рукопожатие ещё идёт, но потоки открывать и слать в них уже можно (cfg.early_data и
 * билет с разрешением early data). После рукопожатия — 0. */
int  qc_early_ready(const struct qc *q);
/* Двунаправленный поток. QC_EAGAIN — рукопожатие не завершено (и 0-RTT не разрешён) или у сервера
 * нет разрешения. */
int  qc_stream_open(struct qc *q, int64_t *sid);
/* Однонаправленный поток (наша передача, приёма нет): управляющий поток HTTP/3 у hysteria2. Те же
 * QC_EAGAIN и qc_stream_send. */
int  qc_stream_open_uni(struct qc *q, int64_t *sid);
/* Поставить n байт в очередь потока; fin — после них закрыть передачу. Возвращает принятое число
 * байт (0..n; меньше n — буфер потока полон, повторить после освобождения по ACK) или QC_E*. */
ssize_t qc_stream_send(struct qc *q, int64_t sid, const uint8_t *d, size_t n, int fin);
/* Не отправленное и не подтверждённое в потоке, байт. */
size_t qc_stream_buffered(const struct qc *q, int64_t sid);
/* Отменить поток (RESET_STREAM и STOP_SENDING с кодом). */
int  qc_stream_reset(struct qc *q, int64_t sid, uint64_t app_err);
/* Датаграмма: 0 — в очереди; QC_ETOOBIG — больше qc_datagram_max; QC_EAGAIN — очередь полна (64).
 * Датаграммы ненадёжны: отправленную можно потерять, повторять их — дело потребителя. */
int  qc_datagram_send(struct qc *q, const uint8_t *d, size_t n);
/* Наибольшая датаграмма, что влезает сейчас (0 — сервер датаграмм не принимает). */
size_t qc_datagram_max(const struct qc *q);

/* Вернуть окна приёма (только при cfg.flow_manual): n байт потока sid отданы дальше. Ставит
 * обновление окна в очередь; пакет с ним уходит при следующей отправке или после qc_flush_credit. */
void qc_stream_consumed(struct qc *q, int64_t sid, size_t n);
/* Отправить обновления окон, которые поставил qc_stream_consumed, если они ещё не ушли. Зовёт
 * потребитель из своей линии событий (не из колбэка: там она ничего не делает — обновление уйдёт
 * концом qc_on_readable) — один раз за проход, а не после каждого куска. */
void qc_flush_credit(struct qc *q);
/* Сменить перегрузку на ходу: brutal_bps != 0 — Brutal с этой скоростью (байт/с), 0 — BBR. Так
 * hysteria2 применяет ответ сервера на авторизацию, когда соединение уже открыто. 0 — успех;
 * QC_EINVAL — смена не поддержана. */
int  qc_set_cc(struct qc *q, uint64_t brutal_bps);

void qc_stats_get(struct qc *q, struct qc_stats *st);

/* Внутреннее, для стендов (в libsteer.map нет): включить и выключить пакетные пути сокета —
 * gso: отправка одним вызовом с UDP_SEGMENT; gro: приём склеенных датаграмм (иначе recvmmsg). */
void qc_io_force(struct qc *q, int gso, int gro);
/* Сколько датаграмм из начала списка длин уходит одним вызовом с UDP_SEGMENT: первая задаёт размер
 * сегмента, следующие — того же размера, меньшая — только последней; не больше 64 сегментов и
 * 65507 байт. n == 0 — 0, иначе не меньше 1. */
size_t qc_io_gso_run(const size_t *len, size_t n);
/* Ошибка errno отправки с UDP_SEGMENT, после которой GSO для сокета выключается (ядро без него,
 * устройство без контрольной суммы), а не обычная потеря (буфер полон). */
int qc_io_gso_fatal(int err);
/* Длина следующего куска склеенного приёма (UDP_GRO) длиной total и размером сегмента seg
 * (0 — не склеен) начиная со смещения off; 0 — конец. */
size_t qc_io_gro_next(size_t total, size_t seg, size_t off);

#ifdef QC_WITH_SERVER
/* Сервер ДЛЯ СТЕНДОВ (ключ QC_WITH_SERVER задают tests/qcloop.c и tests/qcserver.c, в libsteer его
 * нет): одно соединение на сокет, сертификат и ключ — DER. Те же колбэки, те же qc_on_readable,
 * qc_on_timer, qc_run, qc_stream_send, qc_datagram_send, что у клиента — это и делает эхо-сервер
 * стенда одним экраном кода. Соединение создаётся по первому пакету Initial. */
struct qc_srv_cfg {
    const char *bind_host;
    uint16_t    port;               /* 0 — любой свободный; узнать: qc_local_port */
    const char *alpn;
    const uint8_t *cert_der; size_t cert_n;
    const uint8_t *key_der;  size_t key_n;
    uint64_t    brutal_bps;
    size_t      datagram_max;
    unsigned    idle_ms;
    uint64_t    max_data, max_stream_data, max_streams;
    size_t      send_buf;
};
int qc_listen(const struct qc_srv_cfg *cfg, const struct qc_ops *ops, void *user, struct qc **out);
uint16_t qc_local_port(const struct qc *q);
#endif

#endif
