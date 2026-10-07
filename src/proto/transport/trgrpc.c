/* Транспорт grpc: поток протокола в сообщениях gRPC внутри одного потока HTTP/2.
 *
 * Верхний ярус транспорта (transport.h). Переехал из клиента VLESS (client.c) без изменений.
 *
 * grpc и xhttp — это HTTP/2, а не «другой формат кадров». Разница между ними меньше, чем
 * кажется: оба открывают один поток запросом POST и гоняют байты в его теле. Отличаются
 * ровно двумя вещами — путём и тем, обёрнуты ли данные в сообщения gRPC.
 *
 * Формат сообщения gRPC (RFC на gRPC over HTTP/2 плюс schema Xray из stream.proto):
 *
 *   признак сжатия  1 байт  (0 — не сжато; сжатие мы не предлагаем и не принимаем)
 *   длина           4 байта big-endian
 *   тело            protobuf-сообщение Hunk { bytes data = 1 } — то есть 0x0A, длина, байты
 *
 * MultiHunk (mode=multi) отличается только тем, что поле 1 может повторяться. На отправку
 * это неотличимо от Hunk — одно поле и есть законный MultiHunk, — а на приём разбор
 * повторов получается сам, потому что мы читаем поля до конца сообщения.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>

#include "transport.h"

/* Путь запроса для gRPC.
 *
 * Обычная форма: serviceName без ведущего слэша, тогда путь — /<service>/Tun. Новая форма
 * из Xray: serviceName начинается со слэша и УЖЕ содержит имя метода целиком, тогда путь
 * это он сам. Различать обязательно: перепутав, мы попадём в несуществующий метод, и
 * сервер ответит 404 — то есть узел будет выглядеть неисправным. */
static void grpc_path(const struct tr_node *n, char *out, size_t cap) {
    int multi = !strcmp(n->mode, "multi");
    if (n->service[0] == '/') {
        /* Форма «/a/b/MyTun» или «/a/b/MyTun|MyTunMulti»: берём нужную половину. */
        const char *bar = strchr(n->service, '|');
        size_t len = bar ? (size_t)(bar - n->service) : strlen(n->service);
        if (multi && bar) {
            const char *slash = strrchr(n->service, '/');
            size_t head = slash ? (size_t)(slash - n->service) : 0;
            snprintf(out, cap, "%.*s/%s", (int)head, n->service, bar + 1);
            return;
        }
        snprintf(out, cap, "%.*s", (int)len, n->service);
        return;
    }
    snprintf(out, cap, "/%s/%s", n->service, multi ? "TunMulti" : "Tun");
}

/* Обернуть данные в сообщение gRPC. */
static size_t grpc_wrap(const unsigned char *d, size_t n, unsigned char *out, size_t cap) {
    unsigned char pb[8];
    size_t pb_n = 0;
    pb[pb_n++] = 0x0A;                    /* поле 1, wire type 2 (bytes) */
    size_t v = n;
    while (v >= 128) { pb[pb_n++] = (unsigned char)((v & 0x7F) | 0x80); v >>= 7; }
    pb[pb_n++] = (unsigned char)v;

    size_t msg = pb_n + n;
    if (5 + msg > cap) return 0;
    out[0] = 0;                            /* не сжато */
    out[1] = (unsigned char)(msg >> 24); out[2] = (unsigned char)(msg >> 16);
    out[3] = (unsigned char)(msg >> 8);    out[4] = (unsigned char)msg;
    memcpy(out + 5, pb, pb_n);
    memcpy(out + 5 + pb_n, d, n);
    return 5 + msg;
}

/* Вынуть данные из потока сообщений gRPC. Работает по кускам любого размера: состояние
 * живёт в struct grpc_de, потому что границы сообщения и записи не совпадают. */
static int grpc_unwrap(struct grpc_de *de, const unsigned char *in, size_t n,
                       unsigned char *out, size_t cap, size_t *out_n) {
    *out_n = 0;
    size_t i = 0;
    while (i < n) {
        if (de->msg_left == 0) {
            /* Заголовок сообщения: признак сжатия и длина. */
            while (de->hdr_n < 5 && i < n) de->hdr[de->hdr_n++] = in[i++];
            if (de->hdr_n < 5) break;
            if (de->hdr[0] != 0) return TR_EGRPC;   /* сжатие не предлагали */
            de->msg_left = ((uint32_t)de->hdr[1] << 24) | ((uint32_t)de->hdr[2] << 16) |
                           ((uint32_t)de->hdr[3] << 8) | de->hdr[4];
            de->hdr_n = 0;
            de->pb_n = 0;
            de->field_left = 0;
            /* Пустое сообщение — законно: сервер так проверяет живость потока. */
            continue;
        }
        if (de->field_left == 0) {
            /* Тег и длина поля protobuf внутри сообщения. Собираем побайтно: тег и varint
             * могут разъехаться по записям так же, как всё остальное. */
            int complete = 0;
            while (i < n && de->msg_left > 0) {
                unsigned char b = in[i++];
                de->msg_left--;
                if (de->pb_n >= sizeof(de->pb)) return TR_EGRPC;  /* varint длиннее пяти байт не бывает */
                if (de->pb_n == 0 && b != 0x0A) return TR_EGRPC;  /* ждём только поле 1 */
                de->pb[de->pb_n++] = b;
                if (de->pb_n > 1 && !(b & 0x80)) { complete = 1; break; }
            }
            if (!complete) break;                  /* дочитаем в следующий раз */
            uint32_t v = 0;
            unsigned shift = 0;
            for (unsigned k = 1; k < de->pb_n; k++) {
                v |= (uint32_t)(de->pb[k] & 0x7F) << shift;
                shift += 7;
            }
            de->field_left = v;
            de->pb_n = 0;
            /* Пустое поле — законно, просто нечего отдавать. */
            if (de->field_left == 0) continue;
        }
        size_t take = de->field_left;
        if (take > n - i) take = n - i;
        if (take > de->msg_left) take = de->msg_left;
        if (*out_n + take > cap) return H2_ETOOBIG;
        memcpy(out + *out_n, in + i, take);
        *out_n += take;
        i += take;
        de->field_left -= (uint32_t)take;
        de->msg_left -= (uint32_t)take;
    }
    return 0;
}

static int grpc_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    (void)timeout_s;
    struct h2_io io = { .ctx = &t->link, .write = tr_link_write, .read = tr_link_read };
    /* Имя хоста в :authority — маскировочный домен, как и в SNI: сервер прикрывается им,
     * и запрос к другому имени выдал бы нас сразу. */
    const char *authority = n->sni[0] ? n->sni : n->host;
    char path[320];
    grpc_path(n, path, sizeof(path));
    memset(&t->de, 0, sizeof(t->de));
    return h2_start(&t->h2, &io, authority, path, "application/grpc", NULL);
}

static int grpc_write(struct transport *t, const unsigned char *d, size_t n) {
    static __thread unsigned char msg[H2_MIN_READ_CAP + 16];
    size_t mn = grpc_wrap(d, n, msg, sizeof(msg));
    if (!mn) return H2_ETOOBIG;
    return h2_write(&t->h2, msg, mn);
}

static int grpc_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    /* Один буфер на ПОТОК, а не на соединение: по 16 КБ на каждое соединение
     * это мегабайт на коробке с пятнадцатью, а потоков всего несколько. Общим он
     * был, пока поток был один; теперь общий массив потоки переписывали бы друг под
     * другом — и это не «иногда мусор», а перепутанные куски чужого соединения. */
    static __thread unsigned char raw[H2_MIN_READ_CAP];
    size_t rn = 0;
    int rc = h2_read(&t->h2, raw, sizeof(raw), &rn);
    if (rc) return rc;
    if (!rn) return 0;
    return grpc_unwrap(&t->de, raw, rn, d, cap, got);
}

/* h2 держит указатель на связь того же соединения (io.ctx) — после переезда структуры он
 * указывал бы в брошенное место. */
static void grpc_moved(struct transport *t) { t->h2.io.ctx = &t->link; }

/* Конец потока уже известен (END_STREAM пришёл вместе с последними данными или отказ отложен до
 * следующего чтения, h2.h: pend_err), а сказать о нём можно только следующим h2_read. Сокет при этом
 * молчит — сервер всё отправил, — и без этого признака цикл туннеля, отдав клиенту данные, не звал бы
 * чтение снова: соединение клиента висело бы без FIN до уборки по простою (120 с). Тот же случай — ответ
 * из одних концевых HEADERS (сервер gRPC отказал в методе): данных нет вовсе, а поток закончен. */
static int grpc_pending(const struct transport *t) { return t->h2.done || t->h2.pend_err; }

/* Сообщение gRPC добавляет к каждой записи 5 байт заголовка и до 4 байт тега и длины protobuf. */
static long grpc_room(const struct transport *t) {
    long r = h2_room(&t->h2) - 9;
    return r > 0 ? r : 0;
}

const struct transport_ops tr_grpc = {
    .name = "grpc", .alpn = "h2", .zc = 0,
    .open = grpc_open, .write = grpc_write, .read = grpc_read,
    .moved = grpc_moved, .close = NULL, .pending = grpc_pending,
    .room = grpc_room,
};
