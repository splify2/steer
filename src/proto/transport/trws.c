/* Транспорт ws: поток протокола в кадрах WebSocket (RFC 6455) после запроса Upgrade.
 *
 * Верхний ярус транспорта (transport.h), шаг 5 выпуска 1.10. Запрос Upgrade и ответ 101 — общие с
 * httpupgrade (trupgrade.c); здесь — только кадры.
 *
 * ОТПРАВКА — КАК У XRAY. Клиент Xray пишет в gorilla/websocket одним WriteMessage(BinaryMessage)
 * на каждую свою запись, а буфер записи у него 4096 байт (websocket/dialer.go: WriteBufferSize), и
 * сообщение длиннее буфера gorilla режет на кадры по 4096: первый — binary без FIN, дальше
 * continuation, последний — с FIN (messageWriter.flushFrame в conn.go). Перехват Xray 26.3.27 на
 * выгрузке 30 КБ так и показал: 4096 без FIN, 4096 с FIN, 34 с FIN, … Каждый кадр уходит своей
 * записью в сокет — у TLS это своя запись TLS. Мы режем так же и пишем так же, по кадру на запись:
 * размеры записей на проводе тогда совпадают с клиентом Xray, а не выдают «другую реализацию»
 * одним своим видом. (Правило Go о малых записях TLS в начале соединения — dynamic record
 * sizing — этим не повторено: у нашего TLS своя раскладка, общая для всех транспортов.)
 *
 * Маска — у каждого кадра своя, из случайности ядра (RFC 6455, 5.3: клиент обязан маскировать,
 * ключ обязан быть непредсказуем, иначе посредник-кеш можно отравить подобранными байтами).
 * Ключи берутся пачкой, по 64 кадра на один getrandom: вызов ядра на каждые 4 КБ выгрузки на
 * роутере заметен, а пачка на поток ничем не хуже по непредсказуемости.
 *
 * ПРИЁМ — потоком (tr_ws_parse): сервер (у Xray — WriteMessage без буфера) шлёт сообщение одним
 * незамаскированным кадром, но RFC разрешает и фрагменты, и служебные кадры посреди них, и кадр
 * любой длины до 2^63 — поэтому разбор ничего не предполагает о границах и копит только
 * заголовок кадра и тело служебного. Нарушения RFC — маска от сервера, биты RSV без
 * согласованных расширений, служебный кадр длиннее 125 байт или разрезанный, continuation вне
 * сообщения и новое сообщение внутри неразрезанного, неизвестный опкод — рвут соединение
 * (TR_EWSFRAME), как у gorilla: поток после такого кадра уже не понять. Текстовые кадры
 * читаются как двоичные: Xray сам поступает так же (connection.go читает NextReader, не глядя на
 * тип), а проверять UTF-8 у байтов VLESS бессмысленно.
 *
 * ping — ответ pong с тем же телом; pong — ничего; close — ответный close с тем же кодом (так
 * отвечает gorilla по умолчанию) и конец потока. Данные, приехавшие в одном куске ДО close,
 * отдаются, а конец потока — следующим чтением.
 *
 * При закрытии соединения уходит свой close 1000, как у Xray (connection.Close) — неблокирующей
 * записью, см. ws_close.
 *
 * РАННИЕ ДАННЫЕ (Ed > 0, `?ed=N` в пути) — как у Xray, байт в байт на проводе: запрос Upgrade
 * откладывается до первой записи; она, если не длиннее Ed, уезжает в Sec-WebSocket-Protocol
 * (base64url без выравнивания), иначе — кадрами после ответа 101. Пока ответа нет, записи копятся
 * в очереди и уходят сразу за ним (ws_write, ws_read): у Xray запись в это время ждёт ответа в
 * своей горутине, а цикл туннеля ждать не вправе. Сервер Xray ранние данные принимает всегда,
 * какой бы Ed ни стоял у него самого (hub.go читает Sec-WebSocket-Protocol безусловно). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include "transport.h"

#define WS_FRAG 4096               /* кадр отправки: как буфер записи gorilla у Xray */

size_t tr_ws_frame(unsigned char *out, size_t cap, int opcode, int fin, const unsigned char key[4],
                   const unsigned char *d, size_t n) {
    size_t h = n > 65535 ? 10 : n > 125 ? 4 : 2;
    if (h + 4 + n > cap || h + 4 + n < n) return 0;
    out[0] = (unsigned char)((fin ? 0x80 : 0) | (opcode & 0x0f));
    if (n > 65535) {
        out[1] = 0x80 | 127;
        for (int i = 0; i < 8; i++) out[2 + i] = (unsigned char)((uint64_t)n >> (56 - 8 * i));
    } else if (n > 125) {
        out[1] = 0x80 | 126;
        out[2] = (unsigned char)(n >> 8);
        out[3] = (unsigned char)n;
    } else {
        out[1] = (unsigned char)(0x80 | n);
    }
    memcpy(out + h, key, 4);
    unsigned char *p = out + h + 4;
    for (size_t i = 0; i < n; i++) p[i] = (unsigned char)(d[i] ^ key[i & 3]);
    return h + 4 + n;
}

/* Служебный кадр дочитан. */
static int ws_ctl(struct ws_rx *r) {
    switch (r->op) {
    case 9:                                    /* ping */
        r->pong_due = 1;
        r->pong_n = r->ctl_n;
        memcpy(r->pong, r->ctl, r->ctl_n);
        return 0;
    case 10:                                   /* pong — ответ на наш ping; мы их не шлём */
        return 0;
    case 8:                                    /* close */
        /* Тело close — либо пусто, либо код (2 байта) и причина. Один байт — нарушение
         * (RFC 6455, 5.5.1). */
        if (r->ctl_n == 1) return TR_EWSFRAME;
        r->closed = 1;
        r->close_code = r->ctl_n >= 2 ? (uint16_t)((r->ctl[0] << 8) | r->ctl[1]) : 1005;
        return 0;
    default:
        return TR_EWSFRAME;
    }
}

int tr_ws_parse(struct ws_rx *r, const unsigned char *in, size_t n,
                unsigned char *out, size_t cap, size_t *out_n) {
    size_t i = 0, o = 0;
    *out_n = 0;
    while (i < n && !r->closed) {
        if (!r->in_payload) {
            r->hdr[r->hdr_n++] = in[i++];
            if (r->hdr_n < 2) continue;
            unsigned b0 = r->hdr[0], b1 = r->hdr[1];
            /* Кадр сервера маскироваться не вправе (RFC 6455, 5.1): клиент обязан закрыть
             * соединение. Проверяется до длины — дальше этот кадр читать незачем. */
            if (b1 & 0x80) return TR_EWSFRAME;
            unsigned l7 = b1 & 0x7f;
            size_t need = 2 + (l7 == 126 ? 2 : l7 == 127 ? 8 : 0);
            if (r->hdr_n < need) continue;
            uint64_t len = l7;
            if (l7 == 126) {
                len = ((uint64_t)r->hdr[2] << 8) | r->hdr[3];
            } else if (l7 == 127) {
                len = 0;
                for (int k = 2; k < 10; k++) len = (len << 8) | r->hdr[k];
                if (len >> 63) return TR_EWSFRAME;     /* старший бит длины обязан быть 0 */
            }
            r->hdr_n = 0;
            if (b0 & 0x70) return TR_EWSFRAME;         /* RSV: расширений не согласовывали */
            unsigned op = b0 & 0x0f, fin = b0 >> 7;
            if (op & 8) {
                if (op > 10 || !fin || len > 125) return TR_EWSFRAME;
            } else if (op == 0) {
                if (!r->in_msg) return TR_EWSFRAME;
                r->in_msg = (uint8_t)!fin;
            } else if (op == 1 || op == 2) {
                if (r->in_msg) return TR_EWSFRAME;
                r->in_msg = (uint8_t)!fin;
            } else {
                return TR_EWSFRAME;
            }
            r->op = (uint8_t)op;
            r->left = len;
            r->ctl_n = 0;
            if (len) { r->in_payload = 1; continue; }
            if (op & 8) {
                int rc = ws_ctl(r);
                if (rc) return rc;
            }
            continue;
        }
        size_t take = n - i;
        if (take > r->left) take = (size_t)r->left;
        if (r->op & 8) {
            memcpy(r->ctl + r->ctl_n, in + i, take);
            r->ctl_n = (uint8_t)(r->ctl_n + take);
        } else {
            if (o + take > cap) return H2_ETOOBIG;
            memmove(out + o, in + i, take);
            o += take;
        }
        i += take;
        r->left -= take;
        if (!r->left) {
            r->in_payload = 0;
            if (r->op & 8) {
                int rc = ws_ctl(r);
                if (rc) return rc;
            }
        }
    }
    *out_n = o;
    return 0;
}

/* Ключ маски: пачка случайности на поток. */
static int mask_key(unsigned char key[4]) {
    static __thread unsigned char pool[256];
    static __thread unsigned left;
    if (left < 4) {
        if (tr_h1_random(pool, sizeof(pool)) != 0) return -1;
        left = sizeof(pool);
    }
    memcpy(key, pool + sizeof(pool) - left, 4);
    left -= 4;
    return 0;
}

static int ws_control(struct transport *t, int op, const unsigned char *d, size_t n) {
    unsigned char key[4], f[2 + 4 + 125];
    if (mask_key(key) != 0) return TR_EIO;
    size_t fl = tr_ws_frame(f, sizeof(f), op, 1, key, d, n);
    return fl ? tr_link_write(&t->link, f, fl) : TR_EWSFRAME;
}

/* Ответить на служебное, что накопил разбор: pong на ping, ответный close на close. */
static int ws_answer(struct transport *t) {
    struct ws_rx *r = &t->h1.rx;
    int rc = 0;
    if (r->pong_due && !r->closed) {
        r->pong_due = 0;
        rc = ws_control(t, 10, r->pong, r->pong_n);
    }
    if (r->closed && !r->close_sent) {
        r->close_sent = 1;
        unsigned char c[2] = { (unsigned char)(r->close_code >> 8), (unsigned char)r->close_code };
        /* Ошибка ответного close не важна: соединение и так кончается. */
        (void)ws_control(t, 8, c, r->close_code == 1005 ? 0 : 2);
    }
    return rc;
}

static int ws_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    return tr_h1_upgrade(t, n, 1, timeout_s);
}

/* Одна запись — одно сообщение, кадрами по WS_FRAG (WriteMessage у gorilla). */
static int ws_frames(struct transport *t, const unsigned char *d, size_t n) {
    static __thread unsigned char fb[WS_FRAG + 14];
    size_t off = 0;
    int op = 2;                                /* binary, дальше — continuation */
    while (off < n) {
        size_t take = n - off > WS_FRAG ? WS_FRAG : n - off;
        unsigned char key[4];
        if (mask_key(key) != 0) return TR_EIO;
        size_t fl = tr_ws_frame(fb, sizeof(fb), op, off + take == n, key, d + off, take);
        int rc = tr_link_write(&t->link, fb, fl);
        if (rc) return rc;
        off += take;
        op = 0;
    }
    return 0;
}

/* Предел очереди до ответа 101. Сверх него запись не принимается ЦЕЛИКОМ (H2_EWINDOW: дайлер
 * понимает это как «ничего не ушло, повторить», как закрытое окно HTTP/2), а не частично. */
#define WS_QMAX (256 * 1024)

static int q_push(struct h1_state *s, const unsigned char *d, size_t n) {
    size_t need = (size_t)s->q_n + 4 + n;
    if (need > WS_QMAX) return H2_EWINDOW;
    if (need > s->q_cap) {
        size_t cap = s->q_cap ? s->q_cap : 8192;
        while (cap < need) cap *= 2;
        unsigned char *q = realloc(s->q, cap);
        if (!q) return TR_EIO;
        s->q = q;
        s->q_cap = (uint32_t)cap;
    }
    unsigned char *p = s->q + s->q_n;
    p[0] = (unsigned char)(n >> 24); p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8);  p[3] = (unsigned char)n;
    memcpy(p + 4, d, n);
    s->q_n = (uint32_t)need;
    return 0;
}

/* Очередь — кадрами, запись за записью, как их писал бы Xray после ответа 101. */
static int q_flush(struct transport *t) {
    struct h1_state *s = &t->h1;
    size_t off = 0;
    int rc = 0;
    while (!rc && off + 4 <= s->q_n) {
        const unsigned char *p = s->q + off;
        size_t n = ((size_t)p[0] << 24) | ((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3];
        rc = ws_frames(t, p + 4, n);
        off += 4 + n;
    }
    free(s->q);
    s->q = NULL;
    s->q_n = s->q_cap = 0;
    return rc;
}

/* Запись по фазе (h1_state):
 *
 *   H1_DEFER  первая запись при Ed > 0 — у Xray это delayDialConn.Write: запись не длиннее Ed
 *             уезжает ранними данными в самом запросе и считается записанной, длиннее — запрос без
 *             них, а запись — кадрами после ответа 101 (здесь — в очередь);
 *   H1_WAIT   ответа 101 ещё нет: у Xray запись ждёт его внутри dialWebSocket, у нас — в очереди,
 *             которую чтение отправит сразу за принятым ответом. Байты на проводе те же: запрос,
 *             ответ, кадры; отправлять кадры раньше ответа нельзя — gorilla на той стороне
 *             рвёт соединение («client sent data before handshake is complete»);
 *   H1_OPEN   кадры сразу. */
static int ws_write(struct transport *t, const unsigned char *d, size_t n) {
    struct h1_state *s = &t->h1;
    if (s->phase == H1_OPEN) return ws_frames(t, d, n);
    if (s->phase == H1_WAIT) return q_push(s, d, n);
    /* H1_DEFER: первая запись. */
    int early = n <= s->ed;
    int rc = early ? 0 : q_push(s, d, n);
    if (rc) return rc;
    s->resp = calloc(1, sizeof(*s->resp));
    if (!s->resp) return TR_EIO;
    rc = tr_h1_send(t, 1, early ? d : NULL, n);
    if (rc) return rc;
    s->phase = H1_WAIT;
    return 0;
}

/* Кусок входа — целиком в разбор, тела кадров — в d. Выход не длиннее входа (заголовки кадров
 * только убывают), поэтому запись TLS, влезающая в d, влезает и разобранной.
 *
 * В H1_WAIT сперва дочитывается ответ 101 (tr_h1_lazy): ответ не тот — отказ его кодом, принят —
 * очередь записей уходит кадрами, а то, что приехало за ответом тем же куском, — уже кадры. В
 * H1_DEFER сервер молчать обязан: запроса ещё не было. */
static int ws_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    struct h1_state *s = &t->h1;
    struct ws_rx *r = &s->rx;
    if (r->closed) return TR_ECLOSED;
    size_t on = 0;
    int rc;
    if (s->phase != H1_OPEN) {
        const unsigned char *in = d;
        size_t n = 0;
        if (t->link.plain) {
            rc = tr_sock_read(t->link.fd, d, cap, &n);
            if (rc) return rc;
        } else {
            rc = tls13_read_ref(&t->link.tls, &in, &n);
            if (rc) return rc;
        }
        if (!n) return 0;
        if (s->phase == H1_DEFER) return TR_EWSFRAME;
        size_t used = 0;
        rc = tr_h1_lazy(t, 1, in, n, &used);
        if (rc <= 0) return rc;
        rc = q_flush(t);
        if (rc) return rc;
        rc = tr_ws_parse(r, in + used, n - used, d, cap, &on);
    } else if (s->stash) {
        /* Сначала то, что приехало вместе с ответом 101. */
        size_t left = s->stash_n - s->stash_off;
        size_t take = left < cap ? left : cap;
        rc = tr_ws_parse(r, s->stash + s->stash_off, take, d, cap, &on);
        s->stash_off += (uint32_t)take;
        if (s->stash_off >= s->stash_n) tr_h1_free(t);
    } else if (!t->link.plain) {
        const unsigned char *in = NULL;
        size_t n = 0;
        rc = tls13_read_ref(&t->link.tls, &in, &n);
        if (rc) return rc;
        if (!n) return 0;
        rc = tr_ws_parse(r, in, n, d, cap, &on);
    } else {
        /* Голый сокет: читаем прямо в d и разбираем на месте. */
        size_t k = 0;
        rc = tr_sock_read(t->link.fd, d, cap, &k);
        if (rc) return rc;
        if (!k) return 0;
        rc = tr_ws_parse(r, d, k, d, cap, &on);
    }
    if (rc) return rc;
    rc = ws_answer(t);
    *got = on;
    if (rc) return rc;
    if (r->closed && !on) return TR_ECLOSED;
    return 0;
}

/* Остаток после 101 и отложенный конец потока: и то, и другое цикл туннеля обязан забрать
 * чтением, хотя сокет может молчать. */
static int ws_pending(const struct transport *t) {
    return t->h1.stash != NULL || t->h1.rx.closed;
}

/* Закрытие — как connection.Close у Xray: close с кодом 1000 и пустой причиной, затем сокет. Только
 * после принятого 101 (до него кадров не было) и если close ещё не уходил (ответ на close сервера).
 *
 * Сокет на эту запись — неблокирующий. Закрытие идёт из цикла туннеля, и соединение может быть
 * уже мёртвым с полным буфером отправки: блокирующая запись стояла бы там до срока сокета (у Xray
 * — до 5 секунд, но горутина соединения своя). Кадр в 8 байт в исправное соединение уходит всегда;
 * не ушёл — значит и доставлять его было некому. */
static void ws_close(struct transport *t) {
    struct h1_state *s = &t->h1;
    if (s->upgraded && !s->rx.close_sent && t->link.fd >= 0) {
        s->rx.close_sent = 1;
        int fl = fcntl(t->link.fd, F_GETFL, 0);
        if (fl >= 0 && fcntl(t->link.fd, F_SETFL, fl | O_NONBLOCK) == 0) {
            static const unsigned char c[2] = { 0x03, 0xE8 };
            (void)ws_control(t, 8, c, 2);
        }
    }
    tr_h1_free(t);
}

const struct transport_ops tr_ws = {
    .name = "ws", .alpn = "http/1.1", .zc = 0,
    .open = ws_open, .write = ws_write, .read = ws_read,
    .moved = NULL, .close = ws_close, .pending = ws_pending,
};
