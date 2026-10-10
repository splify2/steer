/* Транспорт xhttp: поток протокола в теле запросов HTTP/2 — одним запросом или двумя связями.
 *
 * Верхний ярус транспорта (transport.h). Переехал из клиента VLESS (client.c) без изменений в
 * поведении; вторая связь под выгрузку поднимается теперь тем же tr_link_open, что и основная,
 * — прежде рукопожатие было скопировано в неё отдельной функцией.
 *
 * xhttp в режиме stream-one не оборачивает ничего: тело запроса — это поток наверх, тело
 * ответа — поток вниз. Зато он требует набивки: сервер проверяет длину x_padding в
 * Referer и без неё отвечает 400 (см. hub.go в Xray). Это не украшение — это условие.
 * Режимы stream-up и packet-up — в transport.h у enum xhttp_mode.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/random.h>

#include "transport.h"

/* Путь xhttp: с ведущим и завершающим слэшем.
 *
 * Завершающий слэш — не косметика. Сервер вычисляет идентификатор сессии как остаток
 * пути после своего, и режим stream-one опознаётся именно по ПУСТОМУ остатку. Путь без
 * завершающего слэша даёт непустой остаток, сервер уходит в режим packet-up и отвечает
 * 400 — а выглядит это как «узел не работает». */
static void xhttp_path(const struct tr_node *n, char *out, size_t cap) {
    const char *p = n->path[0] ? n->path : "/";
    size_t len = strlen(p);
    snprintf(out, cap, "%s%s%s", p[0] == '/' ? "" : "/", p,
             len && p[len - 1] == '/' ? "" : "/");
}

/* Режим xhttp узла. Пусто и «auto» решаются как у клиента Xray (splithttp/dialer.go): stream-one
 * при reality, иначе (tls, none) packet-up. Сервер вправе принимать только тот режим, на который
 * настроен, и сервер packet-up отвечает на stream-one 400, поэтому auto обязан выбрать то, что
 * выбрал бы клиент Xray. Всё остальное названо в ссылке явно, и разбор подписки уже отсеял то, чего
 * мы не умеем (sub.c), так что сюда доходят только эти три. */
static enum xhttp_mode xhttp_mode_of(const struct tr_node *n) {
    if (!strcmp(n->mode, "packet-up")) return XH_PACKET_UP;
    if (!strcmp(n->mode, "stream-up")) return XH_STREAM_UP;
    if (!strcmp(n->mode, "stream-one")) return XH_STREAM_ONE;
    return n->security && !strcmp(n->security, "reality") ? XH_STREAM_ONE : XH_PACKET_UP;
}

/* Идентификатор сессии. Ровно им сервер связывает запрос выгрузки с запросом загрузки, и
 * поэтому он обязан быть непредсказуемым: угадав его, посторонний влил бы свои байты в чужую
 * сессию. Форма — как у Xray по умолчанию, строка UUID: она же встречается в путях обычных
 * приложений и ничем не выделяется. */
static void session_id(char *out, size_t cap) {
    unsigned char r[16];
    if (getrandom(r, sizeof r, 0) != (ssize_t)sizeof r) {
        /* Источник случайности отказал. Нули здесь были бы ХУЖЕ отказа: сессия стала бы
         * предсказуемой, оставаясь на вид рабочей. Пусть будет заведомо негодная строка —
         * сервер её примет, но такой узел не поднимется, и это заметят. */
        snprintf(out, cap, "00000000-0000-0000-0000-000000000000");
        return;
    }
    r[6] = (unsigned char)((r[6] & 0x0F) | 0x40);   /* версия 4 */
    r[8] = (unsigned char)((r[8] & 0x3F) | 0x80);   /* вариант   */
    snprintf(out, cap,
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7],
             r[8], r[9], r[10], r[11], r[12], r[13], r[14], r[15]);
}

/* Referer с набивкой для одного запроса.
 *
 * Своя длина у КАЖДОГО запроса, а не одна на соединение: у packet-up запросов череда, и
 * одинаковая длина набивки во всех превратила бы саму набивку в признак — то есть в ровно
 * то, против чего она заведена. Диапазон 100..1000 знаков задан сервером Xray
 * (GetNormalizedXPaddingBytes), и выйти за него значит получить отказ. */
static int xhttp_referer(char *out, size_t cap, const char *authority, const char *path,
                         uint16_t pf, uint16_t pt) {
    /* ДЛИНУ ЗАДАЁТ СЕРВЕР, А НЕ МЫ. Она приезжает в ссылке полем `xPaddingBytes` (см.
     * pad_range в sub.c), и сервер её ПРОВЕРЯЕТ: не попал в диапазон — 400 и всё.
     *
     * Прежде здесь стояло жёсткое 150…660. Оно укладывается в умолчание Xray (100…1000) и
     * потому работало почти везде — а на подписке, где продавец объявил «50-150», отвечали
     * отказом ВСЕ его узлы xhttp. Выглядело это как «узлы мёртвые»: TLS проходит, Reality
     * признаёт, и только потом 400.
     *
     * Пусто — умолчание Xray 100…1000 (GetNormalizedXPaddingBytes), а не прежние 150…660:
     * повторяем upstream, чтобы у нас и у него совпадали не только границы, но и середина. */
    size_t lo = pt ? pf : 100;
    size_t hi = pt ? pt : 1000;
    unsigned char r = 0;
    if (getrandom(&r, 1, 0) != 1) r = 128;
    size_t pad = lo + (size_t)r * (hi - lo + 1) / 256;
    if (pad < lo) pad = lo;
    if (pad > hi) pad = hi;
    int k = snprintf(out, cap, "https://%s%s?x_padding=", authority, path);
    if (k < 0 || (size_t)k + pad + 1 > cap) return H2_ETOOBIG;
    memset(out + k, 'X', pad);
    out[k + pad] = '\0';
    return 0;
}

/* ---- вторая связь: под выгрузку ------------------------------------------------------- */

static int up_write(void *ctx, const unsigned char *d, size_t n) {
    struct xh_up *u = ctx;
    return tr_link_write(&u->link, d, n);
}

static int up_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct xh_up *u = ctx;
    /* Прямого копирования здесь не бывает: Vision живёт на потоке ЗАГРУЗКИ, а эта связь
     * только пишет. Ответы сервера на выгрузку — пустые 200, и читаются они лишь затем,
     * чтобы разобрать служебные кадры HTTP/2 и не переполнить окно.
     *
     * ЖДАТЬ ЗДЕСЬ НЕЛЬЗЯ. Слив ответов делается попутно с отправкой, и блокирующее чтение
     * остановило бы выгрузку до прихода ответа — то есть превратило бы поток в череду
     * «отправил и жду». Поверх TLS ожидания и нет: tls13_read опрашивает сокет с нулевым
     * сроком и отдаёт ноль байт, когда записи ещё нет. На голом сокете (security=none)
     * такого поведения нет, и опрос приходится ставить самим — поэтому чтение этой связи
     * своё, а не tr_link_read основной. */
    if (u->link.plain) {
        struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
        if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN)) { *got = 0; return 0; }
        ssize_t r = read(u->link.fd, d, cap);
        if (r == 0) return TR_ECLOSED;
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) { *got = 0; return 0; }
            return TR_EIO;
        }
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&u->link.tls, d, cap, got);
}

/* Слить то, что сервер ответил на выгрузку.
 *
 * ЗАЧЕМ ЭТО ВООБЩЕ НАДО. На каждый кусок packet-up сервер отвечает пустым 200: заголовки,
 * пустой DATA, END_STREAM — десятки байт. Не читать их значит копить в приёмном буфере
 * сокета; когда он заполнится, сервер перестанет писать, а следом застрянет и разбор его
 * стороны — выгрузка встанет, причём тем позже, чем больше буфер, то есть «иногда и на
 * больших файлах». Заодно этот же вызов забирает служебные кадры HTTP/2 (SETTINGS,
 * WINDOW_UPDATE, PING) — без них окно соединения не пополнялось бы вовсе.
 *
 * Ничего не ждёт и данных не отдаёт: прочитанное выбрасывается. Отдаёт ОТКАЗ: сервер xhttp
 * отвечает не-200 на кусок, который не принял (например, 400 на набивку не той длины), и
 * этот кусок потерян — поток за ним цел уже не будет. Прежде код выбрасывался вместе с
 * телом, отправка возвращала успех, и узел выглядел живым, а трафик не шёл (I-219). Прочие
 * коды h2_read здесь не отказ: H2_ERESET у packet-up — это законный конец ответа на кусок,
 * а обрыв связи назовёт следующая запись. */
static int up_drain(struct xh_up *u) {
    if (!u->started) return 0;
    static __thread unsigned char sink[H2_MIN_READ_CAP];
    /* Пока связь не опустеет, но с пределом, чтобы один вызов не крутился вечно. НЕ пока чтение не
     * вернёт данных: на этой связи оно не вернёт их никогда (ответы — пустые 200), и остановка
     * по этому признаку брала по одной записи за вызов, а ответ на кусок лежал за WINDOW_UPDATE и
     * SETTINGS. */
    for (int i = 0; i < 64; i++) {
        /* packet-up: ответ на ТЕКУЩИЙ кусок (done) ничего не говорит о старых, ответы на которые
         * ещё в пути: сервер отвечает в любом порядке. h2_read отказался бы читать, раз done стоит,
         * и ответ на самый старый кусок никогда не прочитался бы: его окно оставалось полным, и
         * выгрузка вставала навсегда (нового куска нет, значит нет и h2_next, который сбросил бы
         * done). */
        if (u->h2.done && !u->h2.pend_err && h2_open_streams(&u->h2) > 0) u->h2.done = 0;
        int more = !u->link.plain && tls13_has_record(&u->link.tls);
        if (!more) {
            struct pollfd p = { .fd = u->link.fd, .events = POLLIN };
            more = poll(&p, 1, 0) > 0 && (p.revents & POLLIN);
        }
        if (!more) return 0;
        size_t got = 0;
        int rc = h2_read(&u->h2, sink, sizeof(sink), &got);
        if (rc == H2_ESTATUS) return rc;
        if (rc) return 0;
    }
    return 0;
}

/* Поднять вторую связь. Тот же путь установления, что и у основной: TCP, и дальше либо
 * ничего (security=none), либо Reality, либо обычный TLS с проверкой. ALPN — всегда h2. */
static int up_connect(struct transport *t, const struct tr_node *n, int timeout_s) {
    struct xh_up *u = &t->xh.up;
    memset(u, 0, sizeof(*u));
    int rc = tr_link_open(&u->link, n, "h2", timeout_s);
    if (rc) return rc;
    if (!u->link.plain && u->link.tls.alpn[0] && strcmp(u->link.tls.alpn, "h2") != 0) {
        tls13_free(&u->link.tls); close(u->link.fd); u->link.fd = -1;
        return TR_ENOH2;
    }
    return 0;
}

/* Открыть очередной запрос выгрузки. seq < 0 — постоянный поток stream-up (номера у него
 * нет), иначе номер куска packet-up. */
static int up_request(struct transport *t, long long seq) {
    struct xh_state *x = &t->xh;
    struct xh_up *u = &x->up;
    struct h2_io io = { .ctx = u, .write = up_write, .read = up_read };
    char path[320];
    if (seq < 0) snprintf(path, sizeof(path), "%s", x->up_path);
    else         snprintf(path, sizeof(path), "%s/%lld", x->up_path, seq);

    static __thread char ref[1400];
    if (xhttp_referer(ref, sizeof(ref), x->authority, path, x->pad_from, x->pad_to))
        return H2_ETOOBIG;

    /* Content-Type: application/grpc только у запроса stream-up. Xray ставит его на запросы потока
     * (stream-up, stream-one), на куски packet-up — никогда; сервер его не проверяет, но кусок с
     * ним не похож на кусок Xray. */
    const char *ctype = seq < 0 ? "application/grpc" : NULL;
    if (!u->started) {
        int rc = h2_start_ex(&u->h2, &io, x->authority, path, ctype, ref, H2_POST, 0, 1);
        if (rc) return rc;
        u->started = 1;
        return 0;
    }
    return h2_next(&u->h2, x->authority, path, ctype, ref, H2_POST);
}

/* Поднять выгрузку, если она нужна этому режиму. Для stream-one не делает ничего: там
 * выгрузка идёт телом того же единственного запроса. */
static int up_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    if (t->xh.mode == XH_STREAM_ONE) return 0;

    int rc = up_connect(t, n, timeout_s);
    if (rc) return rc;

    /* stream-up открывает свой POST сразу и держит его открытым до конца соединения: тело
     * этого запроса и есть канал наверх.
     *
     * packet-up НЕ открывает ничего заранее. Запрос там живёт ровно один кусок, и открыть
     * его до того, как кусок появился, значило бы держать на сервере пустую выгрузку —
     * причём с номером 0, который потом пришлось бы пропустить. Первый запрос откроется в
     * первой же отправке. */
    if (t->xh.mode == XH_STREAM_UP) return up_request(t, -1);
    t->xh.seq = 0;
    return 0;
}

/* ---- транспорт ------------------------------------------------------------------------ */

/* scMaxEachPostBytes, когда узел его не объявил: умолчание Xray и клиента, и сервера. */
#define XH_POST_DEFAULT 1000000u

static int xhttp_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    struct xh_state *x = &t->xh;
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    /* :authority так, как клиент Xray собирает URL: настройка host узла, иначе SNI (маскировочный
     * домен, которым прикрывается сервер), иначе адрес. Сервер с заданным host сравнивает его с
     * :authority и на любое другое имя отвечает 404 (hub.go). */
    const char *authority = n->http_host && n->http_host[0] ? n->http_host
                          : n->sni[0] ? n->sni : n->host;
    char path[320];

    /* Режим определяется ЗДЕСЬ, один раз: дальше он читается и при открытии потоков, и при
     * каждой отправке, и три независимых разбора строки разошлись бы. */
    x->mode = xhttp_mode_of(n);
    xhttp_path(n, path, sizeof(path));
    snprintf(x->authority, sizeof(x->authority), "%s", authority);
    x->pad_from = n->pad_from;
    x->pad_to = n->pad_to;
    /* Предел тела POST: диапазон scMaxEachPostBytes узла; не объявлен — умолчание Xray, 1000000
     * (сервер на тело больше своего предела отвечает 413). Размер каждого POST выбирается при его
     * отправке (post_pick). */
    x->post_min = n->post_to ? n->post_from : XH_POST_DEFAULT;
    x->post_max = n->post_to ? n->post_to : XH_POST_DEFAULT;
    if (getrandom(&x->post_rng, sizeof x->post_rng, 0) != (ssize_t)sizeof x->post_rng)
        x->post_rng = (uint64_t)(uintptr_t)t ^ 0x9E3779B97F4A7C15ull;

    /* __thread: буфер живёт между вызовами, но потоков теперь несколько, и один общий
     * массив они переписывали бы друг под другом. Своя копия на поток — 1,4 КБ. */
    static __thread char ref[1400];

    if (x->mode == XH_STREAM_ONE) {
        if (xhttp_referer(ref, sizeof(ref), authority, path, n->pad_from, n->pad_to))
            return H2_ETOOBIG;
        /* Content-Type: application/grpc и здесь — так делает Xray (FillStreamRequest ставит
         * его на любой запрос С ТЕЛОМ), и посредники по нему не пытаются буферизовать поток.
         * Всё остальное в заголовках — облик БРАУЗЕРА, а не gRPC: см. put_headers в h2.c. */
        return h2_start_ex(&t->h2, &io, authority, path, "application/grpc", ref,
                           H2_POST, 0, 1);
    }

    /* Два оставшихся режима начинаются одинаково: сессия получает имя, и по этому имени
     * сервер потом свяжет с ней запросы выгрузки. Имя дописывается к пути — так у Xray
     * задано по умолчанию (session placement = path), и так его читает hub.go. */
    char sid[40];
    session_id(sid, sizeof(sid));
    if (snprintf(x->up_path, sizeof(x->up_path), "%s%s", path, sid) >= (int)sizeof(x->up_path))
        return H2_ETOOBIG;

    /* ЭТА связь — за загрузкой, и запрос у неё GET без тела. Метод здесь не украшение:
     * сервер отличает выгрузку от загрузки именно им (hub.go: GET без номера куска — это
     * stream-down). POST без тела сервер счёл бы выгрузкой и стал бы ждать байт, которых
     * не будет, а вниз не отдал бы ничего. */
    if (xhttp_referer(ref, sizeof(ref), authority, x->up_path, n->pad_from, n->pad_to))
        return H2_ETOOBIG;
    int rc = h2_start_ex(&t->h2, &io, authority, x->up_path, NULL, ref, H2_GET, 1, 1);
    if (rc) return rc;
    return up_open(t, n, timeout_s);
}

/* packet-up: нижняя граница размера POST — меньшее из post_min и окна потока (окно каждого нового
 * потока — peer_init_win, и POST больше него не уйдёт), см. post_pick. До первого запроса окно —
 * умолчательные 65535. 0 — предела нет. */
static size_t post_floor(const struct xh_state *x) {
    if (!x->post_max) return 0;
    size_t lo = x->post_min && x->post_min < x->post_max ? x->post_min : x->post_max;
    long win = x->up.started ? x->up.h2.peer_init_win : 65535;
    if (win > 0 && (size_t)win < lo) lo = (size_t)win;
    return lo;
}

/* packet-up: размер очередного POST — равномерно в [post_min, post_max], как делает клиент Xray
 * (RandomRange на каждый запрос), но не больше окна потока. xorshift64*: на каждый POST системный
 * вызов getrandom не нужен, а случайность здесь — не секрет, а форма трафика. 0 — предела нет. */
static size_t post_pick(struct xh_state *x) {
    if (!x->post_max) return 0;
    size_t lo = post_floor(x);
    size_t hi = x->post_max;
    long win = x->up.started ? x->up.h2.peer_init_win : 65535;
    if (win > 0 && (size_t)win < hi) hi = (size_t)win;
    if (hi <= lo) return lo;
    uint64_t r = x->post_rng ? x->post_rng : 0x9E3779B97F4A7C15ull;
    r ^= r >> 12; r ^= r << 25; r ^= r >> 27;
    x->post_rng = r;
    return lo + (size_t)((r * 0x2545F4914F6CDD1Dull) >> 11) % (hi - lo + 1);
}

/* packet-up: сколько все куски записи могут нести вместе (окно соединения). */
static long packet_conn_room(const struct xh_up *u) {
    if (!u->started) return 65535;
    return u->h2.send_win_conn > 0 ? u->h2.send_win_conn : 0;
}

/* packet-up: насколько вперёд от самого старого неотвеченного куска может уйти новый, в кусках.
 * Сервер берёт каждый POST в своей горутине и ставит куски по порядку seq, держа не больше
 * scMaxBufferedPosts (умолчание 30) за пропавшим; сверх этого он рвёт соединение без ошибки HTTP
 * («packet queue is too large», upload_queue.go), и поток просто кончается. Посланные вплотную,
 * наши куски под нагрузкой туда доходили: одна медленная горутина — это дыра, и всё, что ушло
 * тем временем, копится за ней. Ограничить число неотвеченных кусков мало: поздние отвечаются и
 * освобождают места, а дыра остаётся. Поэтому предел — окно по seq, как в TCP: ни один кусок не
 * дальше PACKET_INFLIGHT от самого старого неотвеченного. Восемь — с большим запасом до умолчания
 * сервера и ниже даже сниженного. */
#define PACKET_INFLIGHT 16

/* Сколько кусков ещё можно послать, пока окно по seq не заполнено (см. PACKET_INFLIGHT). Номера
 * потоков растут на два за кусок. */
static long packet_slots(const struct xh_up *u) {
    if (!u->started) return PACKET_INFLIGHT;
    uint32_t oldest = h2_oldest_open(&u->h2);
    if (!oldest) return PACKET_INFLIGHT;
    long ahead = (long)(u->h2.sid - oldest) / 2 + 1;   /* кусков от самого старого до последнего */
    return ahead >= PACKET_INFLIGHT ? 0 : PACKET_INFLIGHT - ahead;
}

/* packet-up: сколько несёт запрос следующего куска. До первого запроса окна — умолчательные
 * 65535. */
static long packet_room(const struct xh_up *u) {
    if (!u->started) return 65535;
    if (packet_slots(u) <= 0) return 0;
    const struct h2 *h = &u->h2;
    int32_t r = h->send_win_conn < h->peer_init_win ? h->send_win_conn : h->peer_init_win;
    return r > 0 ? r : 0;
}

static int xhttp_write(struct transport *t, const unsigned char *d, size_t n) {
    struct xh_state *x = &t->xh;
    /* Отказ, прочитанный слежкой за второй связью: кусок потерян, и поток за ним цел уже не
     * будет (I-219) — тот же ответ, что дал бы слив внутри этой отправки. */
    if (x->drain_err) { int e = x->drain_err; x->drain_err = 0; return e; }
    switch (x->mode) {
        case XH_STREAM_ONE:
            return h2_write(&t->h2, d, n);
        case XH_STREAM_UP: {
            /* Один длинный POST на всё соединение: пишем в него и попутно забираем то, что
             * сервер успел ответить. Закрытое окно может значить лишь непрочитанный
             * WINDOW_UPDATE: слить и попробовать ещё раз, прежде чем отказывать. */
            int rc = h2_write(&x->up.h2, d, n);
            if (rc == H2_EWINDOW && up_drain(&x->up) == 0) rc = h2_write(&x->up.h2, d, n);
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
        case XH_PACKET_UP: {
            /* Кусок = отдельный запрос: открыть, записать, закрыть свою половину.
             *
             * БЕЗ НАКОПЛЕНИЯ. Xray собирает мелкие записи в куски до мегабайта и
             * прямо пишет, что без этого полоса «крайне ограничена». У нас копить
             * нечем: накопитель требует срока сброса, то есть таймера или своего
             * потока на каждое соединение, — а туннель зовёт отправку сам и о
             * времени ничего не знает. Поэтому один запрос на один вызов, и это
             * честная плата за режим, который выбирают тогда, когда другие не
             * проходят вовсе.
             *
             * Сервер отвечает 413 на тело POST больше своего scMaxEachPostBytes: запись уходит кусками,
             * каждый — случайного размера в [post_min, post_max] узла (post_pick), как у клиента Xray.
             * «Всё или ничего» по-прежнему верно (контракт h2_write, на который опирается Vision
             * выше): окна проверяются для всей записи до открытия первого куска, окно соединения —
             * для суммы, окно каждого нового потока — для одного куска. Число кусков заранее
             * неизвестно (размеры случайны), поэтому места считаются по худшему: все куски
             * наименьшего размера. */
            size_t floor_sz = post_floor(x);
            size_t piece = floor_sz && floor_sz < n ? floor_sz : n;
            /* Куски этой записи обязаны уместиться среди неотвеченных; запись, которой одной нужно
             * больше PACKET_INFLIGHT (крошечный scMaxEachPostBytes), никого не ждёт. */
            int pieces = (int)((n + piece - 1) / piece);
#define PACKET_FITS() ((long)piece <= packet_room(&x->up) && (long)n <= packet_conn_room(&x->up) && \
                       (packet_slots(&x->up) >= pieces || \
                        (pieces > PACKET_INFLIGHT && !h2_open_streams(&x->up.h2))))
            if (!PACKET_FITS()) up_drain(&x->up);
            if (!PACKET_FITS()) return H2_EWINDOW;
#undef PACKET_FITS
            int rc = 0;
            for (size_t off = 0; off < n && !rc; ) {
                size_t m = post_pick(x);
                if (!m || m > n - off) m = n - off;
                rc = up_request(t, (long long)x->seq);
                if (!rc) rc = h2_write(&x->up.h2, d + off, m);
                if (!rc) rc = h2_end_stream(&x->up.h2);
                if (!rc) x->seq++;
                off += m;
            }
            int dr = up_drain(&x->up);
            return rc ? rc : dr;
        }
    }
    return h2_write(&t->h2, d, n);
}

static int xhttp_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    return h2_read(&t->h2, d, cap, got);
}

/* Самоуказателей ДВА: у загрузки (h2.io.ctx — основная связь) и у выгрузки (up.h2.io.ctx —
 * вторая связь; для stream-up он ставится ещё до переезда, внутри открытия). Пока чинился
 * только первый, выгрузка соединения, взятого из пула запасных, уезжала через вторую связь
 * чужой запасной сессии, которая тут же заводилась в том же слоте. */
static void xhttp_moved(struct transport *t) {
    t->h2.io.ctx = &t->link;
    t->xh.up.h2.io.ctx = &t->xh.up;
}

/* Вторая связь. Существует она только у stream-up и packet-up; у stream-one её fd равен
 * нулю после memset, поэтому проверка на «больше нуля», а не «не -1». */
static void xhttp_close(struct transport *t) {
    struct xh_up *u = &t->xh.up;
    if (u->link.fd > 0) close(u->link.fd);
    u->link.fd = -1;
    if (!u->link.plain) tls13_free(&u->link.tls);
    u->link.tls.ready = 0;
    u->started = 0;
}

/* Конец ответа уже известен, а сказать о нём можно только следующим чтением (причина — у grpc_pending в
 * trgrpc.c): иначе цикл туннеля не звал бы его, пока сокет молчит. Смотрим на поток ЗАГРУЗКИ (t->h2):
 * ответы на куски выгрузки (up.h2) законно кончаются на каждом куске. */
static int xhttp_pending(const struct transport *t) { return t->h2.done || t->h2.pend_err; }

/* Что примет xhttp_write сейчас, по режимам: те же окна, которые он проверяет.
 *
 * stream-up и packet-up выгружают по своей связи, которую цикл туннеля не наблюдает: он читает
 * только связь загрузки. WINDOW_UPDATE сервера для выгрузки читал лишь up_drain после записи, и
 * когда окно клиента стало выбираться по месту (dialer_ops.room), закрытое место значило «нет
 * записей», то есть «нет чтений», и место оставалось закрытым: выгрузка stream-up падала с 3 ГБ до
 * 14 МБ за 20 с. Поэтому низкое место сначала сливает связь выгрузки, а потом сообщается. */
#define UP_ROOM_LOW 65536
static long xhttp_room(struct transport *t) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE: return h2_room(&t->h2);
        case XH_STREAM_UP:
            if (h2_room(&x->up.h2) < UP_ROOM_LOW) up_drain(&x->up);
            return h2_room(&x->up.h2);
        case XH_PACKET_UP: {
            /* В БАЙТАХ, которые несут свободные места под куски, а не окно HTTP/2: окно бывает в
             * мегабайты, а неотвеченных кусков может быть лишь PACKET_INFLIGHT. Получив окно, клиент
             * слал куда больше, чем брали места, и каждый отказанный сегмент ждал таймаута повторной
             * передачи (11 МБ выгружено за 20 с). Место считается по наименьшему куску диапазона
             * (post_floor): запись не больше места занимает не больше свободных мест, как бы ни
             * выпали случайные размеры; без предела у узла — по 64 КБ, окну по умолчанию. */
            if (packet_room(&x->up) < UP_ROOM_LOW || packet_slots(&x->up) <= PACKET_INFLIGHT / 2)
                up_drain(&x->up);
            long r = packet_room(&x->up);
            long slots = packet_slots(&x->up);
            size_t fl = post_floor(x);
            long per = fl ? (long)fl : 65536;
            if (slots < 0) slots = 0;
            if (r > slots * per) r = slots * per;
            if (r > packet_conn_room(&x->up)) r = packet_conn_room(&x->up);
            return r;
        }
    }
    return h2_room(&t->h2);
}

/* Вторая связь под наблюдение цикла туннеля.
 *
 * Ответы на выгрузку приходят по ней, а цикл ждёт события только основного сокета. Освободившееся
 * место (ответ на кусок packet-up, WINDOW_UPDATE stream-up) без этого замечалось, лишь когда цикл
 * просыпался по чужому поводу — пакету клиента, — а клиент, которому отказано в окне, молчит до
 * своего таймера: выгрузка packet-up шла кусками «окно, пауза» (8-10 Мбит/с при 150 у stream-up).
 * Теперь ответ будит цикл сам: он сливает связь и, если место выросло, шлёт клиенту окно. */
static int xhttp_aux_fd(const struct transport *t) {
    const struct xh_state *x = &t->xh;
    if (x->mode == XH_STREAM_ONE || !x->up.started || x->up.link.fd <= 0) return -1;
    return x->up.link.fd;
}

static int xhttp_aux_drain(struct transport *t) {
    struct xh_state *x = &t->xh;
    int rc = up_drain(&x->up);
    /* Отказ не теряем: он останется записи. Читать эту связь дальше незачем — сломанная, она
     * иначе будила бы цикл на каждом витке. */
    if (rc && !x->drain_err) x->drain_err = rc;
    if (rc) return rc;
    /* Закрытая сервером связь читается всегда (конец потока): будить цикл ею бесконечно нельзя. */
    struct pollfd p = { .fd = x->up.link.fd, .events = POLLIN | POLLRDHUP };
    if (poll(&p, 1, 0) > 0 && (p.revents & (POLLRDHUP | POLLHUP | POLLERR))) return -1;
    return 0;
}

/* Одним вызовом принимает любую запись только packet-up: режет её на POST сам. У stream-up и
 * stream-one запись — это DATA в одном потоке с окном, и стек собирает для них не больше записи TLS.
 * Vision (flow) сюда не доходит: узел xhttp с flow отсеивается при разборе ссылки, а у дайлера
 * VLESS узел с flow большой записи не получает в любом случае (vl_up_max). */
static int xhttp_big_write(const struct transport *t) { return t->xh.mode == XH_PACKET_UP; }

const struct transport_ops tr_xhttp = {
    .name = "xhttp", .alpn = "h2", .zc = 0,
    .open = xhttp_open, .write = xhttp_write, .read = xhttp_read,
    .moved = xhttp_moved, .close = xhttp_close, .pending = xhttp_pending,
    .room = xhttp_room,
    .aux_fd = xhttp_aux_fd, .aux_drain = xhttp_aux_drain,
    .big_write = xhttp_big_write,
};
