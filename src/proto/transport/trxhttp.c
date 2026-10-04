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

/* Режим xhttp узла. Пусто и «auto» — stream-one: его же выбирает Xray при reality, и он
 * дешевле всех. Всё остальное названо в ссылке явно, и разбор подписки уже отсеял то, чего
 * мы не умеем (sub.c), так что сюда доходят только эти три. */
static enum xhttp_mode xhttp_mode_of(const struct tr_node *n) {
    if (!strcmp(n->mode, "packet-up")) return XH_PACKET_UP;
    if (!strcmp(n->mode, "stream-up")) return XH_STREAM_UP;
    return XH_STREAM_ONE;
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
    for (int i = 0; i < 4; i++) {
        size_t got = 0;
        int rc = h2_read(&u->h2, sink, sizeof(sink), &got);
        if (rc == H2_ESTATUS) return rc;
        if (rc) return 0;
        if (!got) return 0;
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

    if (!u->started) {
        int rc = h2_start_ex(&u->h2, &io, x->authority, path, "application/grpc", ref,
                             H2_POST, 0, 1);
        if (rc) return rc;
        u->started = 1;
        return 0;
    }
    return h2_next(&u->h2, x->authority, path, "application/grpc", ref, H2_POST);
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

static int xhttp_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    struct xh_state *x = &t->xh;
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    /* Имя хоста в :authority — маскировочный домен, как и в SNI: сервер прикрывается им,
     * и запрос к другому имени выдал бы нас сразу. */
    const char *authority = n->sni[0] ? n->sni : n->host;
    char path[320];

    /* Режим определяется ЗДЕСЬ, один раз: дальше он читается и при открытии потоков, и при
     * каждой отправке, и три независимых разбора строки разошлись бы. */
    x->mode = xhttp_mode_of(n);
    xhttp_path(n, path, sizeof(path));
    snprintf(x->authority, sizeof(x->authority), "%s", authority);
    x->pad_from = n->pad_from;
    x->pad_to = n->pad_to;

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

static int xhttp_write(struct transport *t, const unsigned char *d, size_t n) {
    struct xh_state *x = &t->xh;
    switch (x->mode) {
        case XH_STREAM_ONE:
            return h2_write(&t->h2, d, n);
        case XH_STREAM_UP: {
            /* Один длинный POST на всё соединение: пишем в него и попутно забираем то, что
             * сервер успел ответить. */
            int rc = h2_write(&x->up.h2, d, n);
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
             * проходят вовсе. */
            int rc = up_request(t, (long long)x->seq);
            if (rc) return rc;
            rc = h2_write(&x->up.h2, d, n);
            if (rc) return rc;
            rc = h2_end_stream(&x->up.h2);
            x->seq++;
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

const struct transport_ops tr_xhttp = {
    .name = "xhttp", .alpn = "h2", .zc = 0,
    .open = xhttp_open, .write = xhttp_write, .read = xhttp_read,
    .moved = xhttp_moved, .close = xhttp_close, .pending = xhttp_pending,
};
