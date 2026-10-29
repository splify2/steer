/* Соединение с узлом VLESS/Reality: от TCP до проверки «нас признали».
 *
 * Ключевая мысль этого файла: у Reality нет отрицательного ответа. Сервер, не узнавший
 * клиента, не отвечает отказом — он проксирует соединение на настоящий сайт, которым
 * прикрывается. Значит рукопожатие может пройти полностью, ключи сойтись, TLS
 * установиться, и всё равно это будет чужой сайт, а не туннель.
 *
 * Отличить одно от другого можно только по первому байту ответа VLESS: сервер отвечает
 * версией 0, а настоящий сайт пришлёт что угодно другое — HTTP, HTML, редирект. Поэтому
 * vless_probe() ниже и есть единственная честная проверка узла, и именно её использует
 * сторож вместо пинга.
 *
 * Установление соединения (TCP по всем адресам, security, транспорты) — в proto/transport: от
 * VLESS в нём не зависит ничего. Здесь то, что знает про VLESS: узел подписки как параметры
 * транспорта и проверка узла запросом VLESS.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <time.h>

#include "vless.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"
/* Узел глазами транспорта (sl_tr_node) — общий с модулем steer-proxy. */
#include "sublink.h"

/* Полное установление: TCP + безопасность + транспорт. Возвращает 0 и заполняет conn. */
int vless_connect(const struct vless_node *node, struct transport *conn, int timeout_s) {
    struct tr_node tn;
    sl_tr_node(node, &tn);
    return transport_open(conn, &tn, timeout_s);
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Проверка узла: единственный способ узнать, признал ли нас Reality.
 *
 * Просим у сервера соединение с заведомо живым адресом и смотрим на ПЕРВЫЙ БАЙТ ответа.
 * Версия 0 — это ответ VLESS, то есть сервер наш. Что угодно другое означает, что нас не
 * признали и мы разговариваем с настоящим сайтом: соединение при этом рабочее, страница
 * откроется, и без этой проверки узел выглядел бы полностью здоровым.
 *
 * Обращаемся к чужому адресу и ждём хоть какой-то ответ: цель не проверить интернет, а
 * получить от СЕРВЕРА подтверждение, что он понял запрос VLESS. Побочно это и есть
 * измерение задержки — тот же путь, по которому пойдёт настоящий трафик. */

/* КУДА ПРОСИТЬСЯ — ДВА АДРЕСА, А НЕ ОДИН, И ЭТО НЕ ПЕРЕСТРАХОВКА.
 *
 * Здесь была единственная зашитая цель 1.1.1.1:80. Узел, который её не пропускает —
 * провайдер сервера её блокирует, у хостера свой DNS на этом адресе, у самого сервера
 * правило на 1.1.1.1, — не отвечал ничем, проба возвращала «сервер не прислал данных»,
 * и узел браковался ЦЕЛИКОМ. Дальше по цепочке это стоило дорого: автоматический режим
 * вызывает пробу для каждого узла и негодный пропускает, cmd_vless возвращает 1, при
 * on_fail=drop (умолчание) канал просто стоит. Тот же самый узел, выбранный номером
 * вручную, берётся без пробы и работает — отсюда дословное «с автоматическим режимом
 * ничего не загружается, приходится выбирать вручную».
 *
 * У сторожа выходов рядом (failover.c) две цели с того самого дня, и причина там записана
 * теми же словами: один адрес может быть недоступен именно в этом туннеле, и тогда
 * здоровый путь выглядит мёртвым. Здесь ровно тот же случай, только цена выше — сторож
 * переключает выход, а проба вычёркивает узел из подбора.
 *
 * Вторая цель пробуется ТОЛЬКО тогда, когда виновата может быть цель: соединение с
 * сервером состоялось, а данных в ответ не пришло. Отказ рукопожатия и отказ Reality
 * (маскировочный сайт вместо туннеля) — свойства узла, повторять их со второй целью
 * значило бы удваивать время подбора на всех мёртвых узлах подписки. */
struct probe_target { unsigned char ip[4]; const char *host; };
static const struct probe_target PROBE_TARGETS[] = {
    { { 1, 1, 1, 1 }, "1.1.1.1" },
    { { 8, 8, 8, 8 }, "8.8.8.8" },
};

static int probe_once(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms,
                      const struct probe_target *tg, int *connected);

int vless_probe(const struct vless_node *node, int timeout_s, char *why, size_t why_n) {
    return vless_probe_timed(node, timeout_s, why, why_n, NULL, NULL);
}

int vless_probe_timed(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms) {
    int rc = TR_EIO;
    for (size_t i = 0; i < sizeof(PROBE_TARGETS) / sizeof(PROBE_TARGETS[0]); i++) {
        int connected = 0;
        rc = probe_once(node, timeout_s, why, why_n, handshake_ms, ttfb_ms,
                        &PROBE_TARGETS[i], &connected);
        if (rc == 0) return 0;
        /* До сервера не дошли, либо он нас не признал — цель ни при чём. */
        if (!connected || rc == VLESS_CONN_EREJECTED || rc == VLESS_CONN_EBADUUID)
            return rc;
    }
    return rc;
}

static int probe_once(const struct vless_node *node, int timeout_s, char *why, size_t why_n,
                      int *handshake_ms, int *ttfb_ms,
                      const struct probe_target *tg, int *connected) {
    if (handshake_ms) *handshake_ms = -1;
    if (ttfb_ms) *ttfb_ms = -1;
    *connected = 0;

    struct transport c;
    int64_t t0 = now_ms();
    int rc = vless_connect(node, &c, timeout_s);
    if (rc) {
        snprintf(why, why_n, "%s", vless_strerror(rc));
        return rc;
    }
    if (handshake_ms) *handshake_ms = (int)(now_ms() - t0);
    *connected = 1;

    unsigned char uuid[16];
    if (vless_uuid_parse(node->uuid, uuid) != 0) {
        transport_close(&c);
        snprintf(why, why_n, "UUID неразборчив");
        return VLESS_CONN_EBADUUID;
    }

    unsigned char req[512];
    size_t req_n = vless_build_request(uuid, VLESS_CMD_TCP, NULL, tg->ip, 80,
                                       node->flow, req, sizeof(req));
    if (!req_n) { transport_close(&c); snprintf(why, why_n, "заголовок не собрался"); return TR_EIO; }

    /* Минимальный HTTP-запрос вместе с заголовком: сервер не отвечает, пока не получит
     * данные для пересылки, и без них проверка ждала бы до таймаута. */
    char http[128];
    int http_n = snprintf(http, sizeof(http),
                          "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", tg->host);
    /* Сколько данных реально уехало за заголовком. Отдельной переменной, а не sizeof:
     * ниже Vision вычитает ровно это число, чтобы отделить заголовок VLESS от данных, и
     * при не влезшем запросе прежняя формула вычла бы длину того, чего в буфере нет. */
    size_t http_used = 0;
    if (http_n > 0 && req_n + (size_t)http_n <= sizeof(req)) {
        memcpy(req + req_n, http, (size_t)http_n);
        req_n += (size_t)http_n;
        http_used = (size_t)http_n;
    }

    /* Заголовок VLESS и данные с Vision — РАЗНЫЕ вещи, и порядок здесь не произволен.
     *
     * Заголовок уходит сырым, сразу за ним первый кадр Vision с данными. В Xray это видно
     * по XtlsPadding: обёртка применяется к буферам ДАННЫХ, а комментарий «we do a long
     * padding to hide vless header» означает, что заголовок прячет набивка СЛЕДУЮЩЕГО
     * кадра, попадая с ним в одну TLS-запись — а не что заголовок лежит внутри кадра.
     *
     * Первая версия заворачивала заголовок внутрь кадра. Сервер тогда читал UUID (он
     * совпадал), брал следующие 5 байт как команду и длины — а там была версия VLESS и
     * начало UUID из заголовка. Длины выходили бессмысленные, и сервер закрывал
     * соединение: read возвращал -11, то есть выглядело как отказ по ключу. */
    if (node->flow[0]) {
        struct vision vis;
        vless_uuid_parse(node->uuid, uuid);
        vision_init(&vis, uuid);
        static __thread unsigned char framed[8192];
        /* Заголовок VLESS занимает первые header_n байт req — остальное это HTTP-данные. */
        size_t header_n = req_n - http_used;
        size_t fn = vision_wrap(&vis, req + header_n, req_n - header_n,
                                framed, sizeof(framed));
        if (!fn) { transport_close(&c); snprintf(why, why_n, "кадр Vision не собрался"); return TR_EIO; }
        /* Одной записью: заголовок и кадр должны уехать вместе, иначе их разделение по
         * записям само становится признаком. */
        static __thread unsigned char together[8704];
        if (header_n + fn > sizeof(together)) { transport_close(&c); snprintf(why, why_n, "не влезло"); return TR_EIO; }
        memcpy(together, req, header_n);
        memcpy(together + header_n, framed, fn);
        rc = transport_write(&c, together, header_n + fn);
    } else {
        rc = transport_write(&c, req, req_n);
    }
    if (rc) { transport_close(&c); snprintf(why, why_n, "запрос не ушёл: %s", vless_strerror(rc)); return rc; }
    int64_t t_sent = now_ms();

    /* Буфер по мерке транспорта, а не «с запасом»: поверх HTTP/2 за один раз приезжает до
     * целой записи TLS, и меньший буфер дал бы ошибку на совершенно законном кадре. */
    static __thread unsigned char buf[VLESS_MIN_RECV_CAP];
    size_t got = 0;
    /* Ждём данных ПО ЧАСАМ, а не заданным числом попыток.
     *
     * Ноль байт от чтения означает «пока нечего», и причин тому две: служебный кадр
     * HTTP/2 (SETTINGS, WINDOW_UPDATE) или запись, которая ещё не приехала целиком. Чтение
     * записей неблокирующее — оно обязано таким быть, потому что в туннеле один цикл на все
     * соединения, — поэтому восемь попыток подряд проходили за микросекунды, ещё до того
     * как ответ вообще успевал прийти по сети.
     *
     * Стоило это дорого: проба объявляла «сервер не прислал данных» на полностью рабочем
     * узле. Туннель при этом работал, потому что при заданном номере узла он пробу не
     * вызывает вовсе, — и расхождение между «узел не проходит проверку» и «через узел идёт
     * трафик» выглядело как что угодно, кроме ошибки в самой проверке. Проверено на своём
     * Reality-сервере (tests/run-reality.sh): сервер отвечал, в его логе видно и разбор
     * нашего кадра Vision, и отправленный нам ответ.
     *
     * Ждём на сокете, а не в холостом цикле: иначе это те же микросекунды, только дороже. */
    int64_t rx_deadline = now_ms() + (int64_t)(timeout_s > 0 ? timeout_s : 8) * 1000;
    for (;;) {
        rc = transport_read(&c, buf, sizeof(buf), &got);
        if (rc) { transport_close(&c); snprintf(why, why_n, "ответа нет: %s", vless_strerror(rc)); return rc; }
        if (got) break;
        if (now_ms() >= rx_deadline) break;
        struct pollfd pw = { .fd = transport_fd(&c), .events = POLLIN, .revents = 0 };
        poll(&pw, 1, 200);
    }
    if (!got) { transport_close(&c); snprintf(why, why_n, "сервер не прислал данных"); return TR_EIO; }
    /* Первый байт пришёл. Замер сделан ДО разбора ответа: разбор ничего не ждёт, а
     * включать его в задержку значило бы мерить свою же работу. */
    if (ttfb_ms) *ttfb_ms = (int)(now_ms() - t_sent);

    /* Заголовок ответа VLESS идёт ДО кадров Vision и обёрткой не покрыт — разбирается из буфера как
     * есть, тем же порядком, что у туннеля (vl_deliver: сначала заголовок, потом кадры). Прежде здесь
     * сперва разворачивался кадр Vision — состоянием, объявленным внутри блока и обнулённым вместо UUID
     * узла, — и разбор читал заголовок из rx_pre этого состояния уже после выхода из блока: чтение стека
     * вне области видимости (ASan: stack-use-after-scope на первой же пробе узла с flow). Работало это
     * случайно: нулевой «UUID» расходился с ответом сразу за «00 00», и в rx_pre лежали ровно байты
     * заголовка. */
    size_t skip = 0;
    int pr = vless_parse_response(buf, got, &skip);
    transport_close(&c);

    if (pr == VLESS_EPROTO) {
        /* Вот он, тихий отказ Reality. Говорим прямо, потому что иначе это неотличимо
         * от рабочего узла: TLS установлен, ответ пришёл, но он от чужого сайта. */
        snprintf(why, why_n,
                 "сервер не признал ключ — отвечает маскировочный сайт, а не туннель "
                 "(проверьте pbk, sid и sni)");
        return VLESS_CONN_EREJECTED;
    }
    if (pr == VLESS_EAGAIN) {
        snprintf(why, why_n, "ответ слишком короткий (%zu байт)", got);
        return TR_EIO;
    }
    snprintf(why, why_n, "ok, ответ VLESS (%zu байт)", got);
    return 0;
}

const char *vless_strerror(int rc) {
    switch (rc) {
        case VLESS_CONN_EBADUUID: return "UUID неразборчив";
        case VLESS_CONN_EREJECTED: return "сервер не признал ключ";
        default: return transport_strerror(rc);
    }
}
