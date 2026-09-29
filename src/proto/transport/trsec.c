/* Безопасность связи: security=none, tls и reality — рукопожатие поверх сокета к узлу.
 *
 * Средний ярус транспорта (transport.h). Переехал из клиента VLESS (client.c), где одно и то же
 * рукопожатие было написано дважды — у основной связи и у второй связи xhttp, — и копии уже
 * различались мелочами (где живёт состояние Reality, какой ALPN просить). Теперь рукопожатие
 * одно, а различие — в параметре alpn, который приносит транспорт.
 *
 * Ключевая мысль, ради которой здесь так мало кода: у Reality нет отрицательного ответа.
 * Сервер, не узнавший клиента, не отвечает отказом — он проксирует соединение на настоящий
 * сайт, которым прикрывается. Рукопожатие может пройти целиком, и всё равно это будет чужой
 * сайт. Отличить одно от другого может только протокол над транспортом (vless_probe в
 * proto/vless/client.c), поэтому здесь «рукопожатие прошло» и означает ровно это, не больше.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include "transport.h"
#include "reality.h"
#include "roots.h"

/* security=none — голый поток, без TLS вообще. Полезен в доверенной сети, и именно поэтому он
 * не «частный случай reality», а отдельная ветка: ставить TLS там, где его нет, значило бы
 * просто не соединиться. Без TLS согласовывать ALPN нечем, поэтому транспорт поверх HTTP/2
 * начинает его сразу: голый h2 по TCP («h2c») сервер либо примет, либо ответит мусором, и это
 * увидит проверка. */
static int sec_none(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    (void)n; (void)alpn;
    l->plain = 1;
    return 0;
}

/* security=tls — обычный TLS, без Reality, и security=reality.
 *
 * Отличий между ними ровно три, и все три обязательны. ClientHello без аутентификатора (иначе
 * сервер увидел бы в session_id мусор — безвредный, но бессмысленный). ИМЯ обязано быть: у
 * Reality пустой SNI законен (сервер ждёт Hello без расширения), а обычному TLS без имени нечего
 * предъявить и нечем проверить сертификат. И сама проверка сертификата — единственное, что здесь
 * доказывает подлинность сервера.
 *
 * Имя берётся из sni, а host — только запасным: sni это то, что мы просим у сервера, и
 * проверять сертификат надо против него же. Узел, объявленный одним адресом без имени,
 * проверяется против адреса — и не пройдёт, если сертификат выдан не на него. Это
 * правильный отказ, а не наша строгость: ровно так же поступает Xray.
 *
 * Состояние Reality (наш эфемерный ключ и ключ аутентификатора) живёт на стеке этой функции, а
 * не в соединении: после рукопожатия оно не нужно никому, и держать приватный ключ в памяти
 * соединения до его закрытия было незачем. */
static int sec_tls_like(struct tr_link *l, const struct tr_node *n, const char *alpn,
                        int is_tls) {
    const char *verify_host = n->sni[0] ? n->sni : n->host;
    struct reality_cfg cfg = {
        .sni = is_tls ? verify_host : n->sni,
        .pbk = n->pbk, .sid = n->sid, .fp = n->fp,
        /* ALPN просим ровно тогда, когда он нужен транспорту. Для tcp его нет — и Hello
         * остаётся тем самым, который проверен на живых узлах. */
        .alpn = alpn,
        .plain = is_tls,
    };
    struct reality_state rst;
    unsigned char hello[2048];
    size_t hello_n = 0;
    /* ws и httpupgrade просят в ALPN ТОЛЬКО http/1.1 — как Xray (WebsocketHandshakeContext у
     * uTLS переписывает ALPN отпечатка на один http/1.1) и как сам Chrome на соединении
     * веб-сокета. С обычной парой «h2, http/1.1» сервер за TLS вправе выбрать h2, и наш запрос
     * Upgrade по HTTP/1.1 уйдёт в соединение HTTP/2 мусором.
     *
     * Xray-core 26.9.8+ отвергает Reality ClientHello, если гибридный key_share
     * X25519MLKEM768 не стоит перед обычным X25519. Секрет Reality по-прежнему выводится из
     * X25519 (сервер делает так же); гибридная доля — часть современного облика Chrome и
     * обязательная проверка свежести клиента на сервере. Поэтому pq включён у каждого
     * TLS-подобного транспорта VLESS, включая ws/httpupgrade. */
    struct reality_carrier car = { .pq = 1, .alpn_http11 = 1 };
    const int h11 = alpn && !strcmp(alpn, "http/1.1");
    if (!h11) car.alpn_http11 = 0;
    int rc = reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof(hello), &hello_n);
    if (rc) return rc;

    size_t sent = 0;
    while (sent < hello_n) {
        ssize_t w = write(l->fd, hello + sent, hello_n - sent);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            return TR_EIO;
        }
        sent += (size_t)w;
    }

    /* Передаётся наш ПРИВАТНЫЙ ключ, а не готовый секрет: TLS-расписание строится на
     * обмене с эфемерным ключом сервера, который приедет только в ServerHello. */
    /* Чем доказывать подлинность — решается видом узла, и вариант всегда ровно один.
     * У обычного TLS это цепочка и имя, у Reality — HMAC в поле подписи временного
     * сертификата на ключе, который есть только у владельца постоянной пары. */
    struct tls13_auth auth = { 0 };
    if (is_tls) { auth.host = verify_host; auth.roots = tls_cert_roots(); }
    else        auth.reality_key = rst.authkey;

    return tls13_handshake_auth(&l->tls, l->fd, hello, hello_n, rst.priv, &auth);
}

static int sec_tls(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    return sec_tls_like(l, n, alpn, 1);
}

static int sec_reality(struct tr_link *l, const struct tr_node *n, const char *alpn) {
    return sec_tls_like(l, n, alpn, 0);
}

const struct security_ops tr_sec_none    = { .name = "none",    .handshake = sec_none };
const struct security_ops tr_sec_tls     = { .name = "tls",     .handshake = sec_tls };
const struct security_ops tr_sec_reality = { .name = "reality", .handshake = sec_reality };

/* Всё, что не none и не tls, — reality: так было всегда, а неподдержанное значение отсеивает
 * разбор подписки (sub.c) раньше, чем узел доходит сюда. */
const struct security_ops *tr_security(const char *name) {
    if (!strcmp(name, "none")) return &tr_sec_none;
    if (!strcmp(name, "tls")) return &tr_sec_tls;
    return &tr_sec_reality;
}

int tr_link_open(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s) {
    l->fd = -1;
    int fd = tr_dial(n->host, n->port, timeout_s);
    if (fd < 0) return fd;
    l->fd = fd;
    /* На отказе рукопожатия — один close, а не tr_link_close, как было и прежде: за собой в
     * куче на отказе убирает сам tls13_handshake_auth, и это держит стенд vlessmatch под
     * AddressSanitizer — по отдельной проверке кучи на каждую ветвь отказа. */
    int rc = tr_security(n->security)->handshake(l, n, alpn);
    if (rc) { close(fd); l->fd = -1; return rc; }
    return 0;
}
