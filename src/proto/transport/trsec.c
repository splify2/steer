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
#include <stdlib.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>

#include "transport.h"
#include "reality.h"
#include "roots.h"
#include "certverify.h"
#include "ech.h"

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
        /* Гибрид X25519MLKEM768 в ClientHello — как у Chrome 131+, uTLS HelloChrome_Auto и Go 1.24+,
         * то есть у любого клиента Xray с fp=chrome и без fp. Без него наш Hello — «Chrome позапрошлого
         * года» и по размеру (537 байт вместо около 1760), и по составу supported_groups. Выключатель
         * STEER_NOPQ=1 — для разбора: посредник, роняющий Hello больше одного сегмента.
         * Посредник, который роняет такой Hello молча, ловит tr_link_open: таймаут длинного Hello —
         * одна повторная попытка коротким, и узел запоминается (l->nopq). */
        .pq = !getenv("STEER_NOPQ") && !l->nopq,
    };
    /* pqv: ключ ML-DSA-65, base64url. Разбирается ДО отправки Hello: испорченный ключ — отказ узла, а не
     * повод отправить Hello и потом молча не проверять подпись. Разбор подписки (sub.c) такой ключ
     * отсеивает раньше, так что сюда он не доходит; это вторая линия. */
    unsigned char pqv[SC_MLDSA65_PK];
    const int have_pqv = !is_tls && n->pqv && n->pqv[0];
    if (have_pqv && xc_b64url_decode(n->pqv, pqv, sizeof pqv) != SC_MLDSA65_PK) return REALITY_EBADKEY;
    struct reality_state rst;
    unsigned char hello[2560];
    size_t hello_n = 0;
    /* ws и httpupgrade просят в ALPN ТОЛЬКО http/1.1 — как Xray (WebsocketHandshakeContext у
     * uTLS переписывает ALPN отпечатка на один http/1.1) и как сам Chrome на соединении
     * веб-сокета. С обычной парой «h2, http/1.1» сервер за TLS вправе выбрать h2, и наш запрос
     * Upgrade по HTTP/1.1 уйдёт в соединение HTTP/2 мусором. У остальных транспортов Hello не
     * меняется ни на бит (tests/hellofreeze.c): носитель зовётся только ради этих двух. */
    struct reality_carrier car = { .alpn_http11 = 1 };
    const int h11 = alpn && !strcmp(alpn, "http/1.1");
    int rc = h11 ? reality_build_hello_carry(&cfg, &rst, &car, hello, sizeof(hello), &hello_n)
                 : reality_build_hello(&cfg, &rst, hello, sizeof(hello), &hello_n);
    if (rc) return rc;

    /* ECH (security=tls, `ech=` узла): собранный выше Hello с настоящим SNI становится внутренним, по
     * проводу идёт внешний с public_name из ECHConfig (ech.h). Буферы — в куче: внешний Hello вмещает
     * зашифрованную копию внутреннего, то есть вдвое больше обычного, а стек рабочих потоков мал. */
    struct ech_heap {
        struct ech_cfg cfg;
        struct ech_state st;
        unsigned char list[1100];
        unsigned char outer[6144];
        size_t outer_n;
    } *eh = NULL;
    struct tls13_ech te = { 0 };
    const unsigned char *send_hello = hello;
    size_t send_n = hello_n;
    if (is_tls && n->ech && n->ech[0]) {
        eh = calloc(1, sizeof *eh);
        if (!eh) return TR_EIO;
        int ln = ech_b64_decode(n->ech, eh->list, sizeof eh->list);
        int er = ln <= 0 ? ECH_EPARSE : ech_pick(eh->list, (size_t)ln, &eh->cfg);
        if (er == 0) er = ech_wrap(&eh->cfg, hello, hello_n, eh->outer, sizeof eh->outer, &eh->outer_n, &eh->st);
        if (er != 0) {
            free(eh);
            return er;                              /* причина — ECH_E* (transport.c, tr_strerror) */
        }
        send_hello = eh->outer;
        send_n = eh->outer_n;
        te.inner = eh->st.inner;
        te.inner_n = eh->st.inner_n;
        te.random = eh->st.random;
    }

    size_t sent = 0;
    while (sent < send_n) {
        /* MSG_NOSIGNAL: узел, закрывший соединение до ClientHello, — отказ записи, а не сигнал. */
        ssize_t w = send(l->fd, send_hello + sent, send_n - sent, MSG_NOSIGNAL);
        if (w <= 0) {
            if (w < 0 && errno == EINTR) continue;
            free(eh);
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
    /* Закрепления, имена проверки и явный отказ от проверки — из узла и выхода (certverify.h). Без
     * них указатель остаётся NULL, и проверка идёт прежним путём: цепочка до корней и SNI. */
    struct cert_policy pol = { .pcs = n->pcs, .pks = n->pks, .vcn = n->vcn, .insecure = n->insecure };
    if (is_tls) {
        auth.host = verify_host;
        auth.roots = tls_cert_roots();
        if (pol.pcs || pol.pks || pol.vcn || pol.insecure) auth.policy = &pol;
    } else auth.reality_key = rst.authkey;
    if (rst.pq) auth.mlkem_dk = rst.mlkem_dk;
    auth.mldsa_pk = have_pqv ? pqv : NULL;

    if (eh) auth.ech = &te;
    int hrc = tls13_handshake_auth(&l->tls, l->fd, send_hello, send_n, rst.priv, &auth);
    free(eh);
    return hrc;
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

/* ---- память «этому узлу нужен короткий Hello» ------------------------------------------------
 *
 * Известно, что часть российских посредников (ТСПУ) роняет или душит TLS-соединения, чей ClientHello
 * несёт постквантовый обмен и не влезает в один сегмент (около 1760 байт против 537). Сервер такого
 * Hello не видит, и рукопожатие кончается TLS13_ETIMEOUT без единого байта ответа. Поэтому: таймаут
 * Hello с гибридом — ОДНА повторная попытка на новом соединении с коротким Hello, и, если она удалась,
 * узел (хост:порт) запоминается — следующие соединения не платят таймаут каждый раз.
 *
 * Запоминается только после удавшейся короткой попытки: мёртвый узел молчит на любой Hello, и «длинный
 * не прошёл» про него ничего не доказывает. Срок памяти — час, а не до перезапуска: правила посредника
 * меняются (и снимаются), а постквантовый Hello — облик Chrome, который мы хотим держать там, где он
 * проходит. Цена пересмотра раз в час — одно соединение с таймаутом на узел. Предела на число узлов
 * нет: запись — хост и срок, их ровно столько, сколько узлов с таким посредником на пути. */
/* Срок памяти, секунды. Не static — шов стенда tests/pqfallbackmatch.c (0 — не помнить). */
long tr_nopq_ttl_s = 3600;
static pthread_mutex_t g_nopq_mu = PTHREAD_MUTEX_INITIALIZER;
struct nopq_ent {
    char *host;
    uint16_t port;
    long until;                /* CLOCK_MONOTONIC, секунды */
    int logged;                /* о решении по этому узлу уже сказано в журнале */
};
static struct nopq_ent *g_nopq;
static size_t g_nopq_n;

static long nopq_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long)ts.tv_sec;
}

static struct nopq_ent *nopq_find(const char *host, uint16_t port) {
    for (size_t i = 0; i < g_nopq_n; i++)
        if (g_nopq[i].port == port && !strcmp(g_nopq[i].host, host)) return &g_nopq[i];
    return NULL;
}

static int nopq_known(const struct tr_node *n) {
    pthread_mutex_lock(&g_nopq_mu);
    struct nopq_ent *e = nopq_find(n->host, n->port);
    int r = e && e->until > nopq_now();
    pthread_mutex_unlock(&g_nopq_mu);
    return r;
}

static void nopq_remember(const struct tr_node *n) {
    pthread_mutex_lock(&g_nopq_mu);
    struct nopq_ent *e = nopq_find(n->host, n->port);
    if (!e) {
        struct nopq_ent *g = realloc(g_nopq, (g_nopq_n + 1) * sizeof *g);
        char *h = g ? strdup(n->host) : NULL;
        if (!h) { if (g) g_nopq = g; pthread_mutex_unlock(&g_nopq_mu); return; }
        g_nopq = g;
        e = &g_nopq[g_nopq_n++];
        e->host = h; e->port = n->port; e->logged = 0;
    }
    e->until = nopq_now() + tr_nopq_ttl_s;
    if (!e->logged) {
        e->logged = 1;
        fprintf(stderr, "steer[warn] узел %s:%u не ответил на длинный ClientHello — дальше короткий, "
                "без постквантового обмена (раз в %ld мин пробуем снова)\n",
                n->host, (unsigned)n->port, tr_nopq_ttl_s / 60);
    }
    pthread_mutex_unlock(&g_nopq_mu);
}

static int link_try(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s, int nopq) {
    l->fd = -1;
    l->nopq = nopq;
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

int tr_link_open(struct tr_link *l, const struct tr_node *n, const char *alpn, int timeout_s) {
    /* Гибрид предлагается только у tls и reality и только если его не выключили (STEER_NOPQ). */
    const int pq_able = strcmp(n->security, "none") != 0 && !getenv("STEER_NOPQ");
    const int known = pq_able && nopq_known(n);
    int rc = link_try(l, n, alpn, timeout_s, known || !pq_able);
    if (rc == TLS13_ETIMEOUT && pq_able && !known) {
        /* Одна повторная попытка, не цикл: короткий Hello тоже без ответа — узел мёртв, и дальше
         * это дело вызывающего (сторож, пул), а не ещё одного круга здесь. */
        const int rc2 = link_try(l, n, alpn, timeout_s, 1);
        if (rc2 == 0) { nopq_remember(n); return 0; }
        /* Причина — первая: сервер Reality 26.9 отдаёт Hello без гибрида на маскировочный сайт, и
         * ответом коротким был бы «не признал ключ», тогда как корень беды — потерянный длинный Hello. */
    }
    return rc;
}
