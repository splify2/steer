/* Дайлер VLESS: как стек туннеля (stack.c) везёт потоки клиента к узлу VLESS.
 *
 * Всё, что здесь, жило прямо в цикле туннеля (tunnel.c) — в upstream_send, downstream_pump,
 * udp_downstream и в заводе соединения на SYN, — пока цикл был сварен с VLESS. При выделении
 * стека (шаг 2 выпуска 1.10) оно переехало сюда без изменений в поведении: те же байты на
 * проводе, те же строки журнала, тот же порядок. Стек видит только таблицу vless_dialer.
 *
 * Сессия — struct vl_sess (vldial.h): состояние потока (заголовок, Vision, сборка датаграммы) и
 * связь с узлом (struct transport). Связь можно установить заранее — адрес назначения в VLESS
 * едет в заголовке запроса вместе с первыми данными, а до того связь ничья (DC_PRECONNECT), —
 * поэтому у стека есть пул запасных связей, и take переселяет из запасной только связь.
 *
 * При выпуске 1.10 (шаг 4) этот файл уходит в бинарник модуля steer-vless.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/random.h>

#include "vless.h"
#include "vless_proto.h"
#include "vision.h"
#include "client.h"
#include "vldial.h"
#include "pool.h"
#include "stack.h"

#define LOG_W  "steer[warn] tunnel: "

/* Буфер стека обязан вмещать целую запись транспорта и запас на заголовок и набивку Vision
 * (см. TUNNEL_BUF в dialer.h). Число там записано числом, а проверяется — здесь. */
_Static_assert(TUNNEL_BUF >= VLESS_MIN_RECV_CAP + 2048,
               "TUNNEL_BUF меньше записи транспорта с запасом под заголовок VLESS и Vision");

static int g_trace;
#define TR(...) do { if (g_trace) fprintf(stderr, "tun: " __VA_ARGS__); } while (0)

void vl_set_trace(int on) { g_trace = on; }

/* ---- узел ------------------------------------------------------------------------------ */

static const char *vl_peer(const void *ctx) {
    const struct vless_node *node = ctx;
    return node->host;
}

static void vl_describe(const void *ctx, char *out, size_t n) {
    const struct vless_node *node = ctx;
    snprintf(out, n, "%s (%s:%u %s%s)", node->name, node->host, node->port, node->type,
             node->flow[0] ? " +vision" : "");
}

/* ---- связь ----------------------------------------------------------------------------- */

/* Исход установления слежке за узлом докладывает пул узлов (src/tunnel/pool.c): он знает, к какому
 * из активных узлов шло соединение. */
static int vl_connect(const void *ctx, void *sess, int timeout_s) {
    struct vl_sess *s = sess;
    return vless_connect(ctx, &s->t, timeout_s);
}

/* Связь из запасной сессии — в сессию соединения. Копируется только struct transport: UUID и
 * Vision потока в dst уже заведены (flow_open), и затереть их значило бы потерять поток.
 *
 * h2 держит указатель на своё же соединение (io.ctx) — после переезда структуры он указывает в
 * брошенный слот пула; таких самоуказателей ДВА (см. xhttp_moved в trxhttp.c), и чинит их
 * транспорт, а не мы. */
static void vl_take(void *dst, void *src) {
    struct vl_sess *d = dst;
    struct vl_sess *s = src;
    memcpy(&d->t, &s->t, sizeof(d->t));
    transport_moved(&d->t);
}

static void vl_close(void *sess) {
    struct vl_sess *s = sess;
    transport_close(&s->t);
}

/* Толстую половину НЕ трём целиком: 40 КБ memset на каждое закрытие это 40 КБ, прогнанных
 * через кэш ради нулей, которые всё равно перепишет открытие связи (transport_open начинается
 * с memset своей структуры). Здесь достаточно обнулить то, что читаем сами.
 *
 * Счётчики сборки датаграммы — но НЕ сам буфер: 4 КБ нулей на каждое закрытие это те же 4 КБ
 * через кэш ради данных, которые всё равно перепишет следующая датаграмма. Всё тронутое здесь
 * лежит в начале сессии (порядок полей — в vldial.h). */
static void vl_clear(void *sess) {
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    s->t.link.fd = -1;
    memset(&s->vis, 0, sizeof(s->vis));
    s->dg_want = s->dg_have = 0;
    s->dg_skip = 0;
    s->lenb_n = 0;
    s->xs = 0;
    s->xdiscard = 0;
    free(s->dgbig);
    s->dgbig = NULL;
}

static int vl_fd(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_fd(&s->t);
}

static int vl_has_data(const void *sess) {
    const struct vl_sess *s = sess;
    return transport_has_data(&s->t);
}

/* ---- поток ----------------------------------------------------------------------------- */

/* Идентификатор узла не разобрался, и соединение закрывается. Причина известна здесь и
 * обязана быть сказана: молчаливое закрытие снаружи выглядит как «трафика нет», и ровно так
 * выглядел бы следующий похожий случай (I-097). Сегодня сюда не попасть — узел с негодным
 * UUID отсеивается при разборе подписки, а vless_tunnel_run проверяет его до подъёма
 * устройства, — поэтому строка через ограничитель, а не на каждый пакет. Сам UUID не
 * печатается: это ключ доступа к узлу. */
static void node_id_refused(const struct vless_node *node, const char *what) {
    static __thread time_t said;
    time_t now = stack_now_s();
    if (now - said < 5) return;
    said = now;
    fprintf(stderr, LOG_W "у узла %s не разбирается UUID — %s отклонено; "
                    "проверьте ссылку узла\n", node->name, what);
}

static int vl_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    (void)k;
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    s->header_sent = 0;
    s->established = 0;
    if (vless_uuid_parse(node->uuid, s->uuid) != 0) {
        node_id_refused(node, udp ? "соединение UDP" : "соединение TCP");
        return -1;
    }
    /* У UDP Vision заводим только для узла с flow: там UDP идёт командой Mux с рамками XUDP поверх
     * потока Vision (vl_send). Без flow в запросе UDP flow не объявлен, кадров не будет ни в ту, ни
     * в другую сторону. */
    if (!udp || node->flow[0]) vision_init(&s->vis, s->uuid);
    return 0;
}

/* ---- XUDP: UDP по vision-записи (Mux.Cool, как клиент Xray) ---------------------------------------
 *
 * Сервер не принимает UDP-запрос (команда 2) к учётной записи с flow=xtls-rprx-vision: Xray-core
 * отвечает «doesn't support UDP», sing-box сверяет flow с записью для любой команды и отвергает и
 * пустой, и vision. Собственный клиент Xray ходит иначе (proxy/vless/outbound/outbound.go: при
 * vision команда UDP заменяется на Mux со службой v1.mux.cool:666): поток Mux.Cool с рамками XUDP
 * (common/xudp), а весь поток обёрнут Vision, как у TCP. Так и здесь, для узлов с flow.
 * Узлы без flow остаются на команде 2: она проще, короче на проводе и принимается всеми серверами.
 *
 * Рамка (общий вид у Mux.Cool, common/mux/frame.go):
 *   [длина метаданных u16][идентификатор сессии u16 = 0][статус u8][опции u8][...]  [длина данных u16][данные]
 *   статус: 1 New, 2 Keep, 3 End, 4 KeepAlive. Опции: бит 0 — есть данные, бит 1 — ошибка.
 * Первая датаграмма потока — New: после опций сеть (2 = UDP), порт, тип адреса и адрес назначения, затем
 * GlobalID (8 байт; сервер Xray по нему возвращает один и тот же UDP-сокет при новом потоке —
 * «full cone»). Дальше — Keep без адреса: назначение потока не меняется, а по Keep без адреса
 * сервер использует назначение New (sing-box: длина метаданных 4 — адреса нет). Один поток — одно
 * назначение, как и у команды 2 (см. docs/vless.md): сессия mux одна, мультиплекса адресатов нет.
 *
 * ЧЕГО ЗДЕСЬ НЕТ: мультиплекса нескольких сессий в одном потоке и Mux для TCP (concurrency): для
 * TCP они нужны только чтобы экономить рукопожатия, а у стека для этого есть пул запасных связей. */
enum { XS_LEN = 0, XS_META, XS_DLEN, XS_DATA, XS_SKIP };

/* GlobalID: непрозрачный 8-байтовый ключ «этот источник», по которому сервер подбирает сокет. От
 * источника клиента и случайного ключа процесса: одинаков у всех потоков одного источника, разный у
 * разных и непредсказуем снаружи. Криптостойкость не нужна — это не секрет, а ключ таблицы сервера. */
static unsigned char g_xudp_key[16];
static pthread_once_t g_xudp_once = PTHREAD_ONCE_INIT;
static void xudp_key_init(void) {
    if (getrandom(g_xudp_key, sizeof g_xudp_key, 0) != (ssize_t)sizeof g_xudp_key) {
        struct timespec t;
        clock_gettime(CLOCK_REALTIME, &t);
        memcpy(g_xudp_key, &t, sizeof t < sizeof g_xudp_key ? sizeof t : sizeof g_xudp_key);
    }
}

static void xudp_gid(const struct flow_key *k, unsigned char gid[8]) {
    pthread_once(&g_xudp_once, xudp_key_init);
    uint64_t h = 1469598103934665603ULL;               /* FNV-1a, 64 бита */
    unsigned char in[16 + 6];
    memcpy(in, g_xudp_key, 16);
    memcpy(in + 16, &k->src, 4);
    in[20] = (unsigned char)(k->sport >> 8);
    in[21] = (unsigned char)k->sport;
    for (size_t i = 0; i < sizeof in; i++) { h ^= in[i]; h *= 1099511628211ULL; }
    h ^= h >> 32;
    for (int i = 0; i < 8; i++) gid[i] = (unsigned char)(h >> (56 - 8 * i));
}

/* Датаграммы [длина u16][данные] (так их обрамляет dgram_frame) → рамки XUDP. first — первая рамка
 * потока (New с адресом), остальные — Keep. Возвращает длину результата, 0 — не влезло или брак. */
static size_t xudp_frames(const struct flow_key *k, int first, const unsigned char *in, size_t n,
                          unsigned char *out, size_t cap) {
    size_t o = 0;
    while (n) {
        if (n < 2) return 0;
        size_t dl = ((size_t)in[0] << 8) | in[1];
        in += 2;
        n -= 2;
        if (dl > n) return 0;
        unsigned char meta[40];
        size_t m = 0;
        meta[m++] = 0; meta[m++] = 0;                  /* идентификатор сессии: одна, нулевая */
        if (first) {
            meta[m++] = 1;                             /* New */
            meta[m++] = 1;                             /* опции: есть данные */
            meta[m++] = 2;                             /* сеть: UDP */
            meta[m++] = (unsigned char)(k->dport >> 8);
            meta[m++] = (unsigned char)k->dport;       /* порт, затем тип адреса и адрес */
            meta[m++] = VLESS_ADDR_IPV4;
            memcpy(meta + m, &k->dst, 4);
            m += 4;
            xudp_gid(k, meta + m);
            m += 8;
            first = 0;
        } else {
            meta[m++] = 2;                             /* Keep */
            meta[m++] = 1;
        }
        if (o + 2 + m + 2 + dl > cap) return 0;
        out[o++] = (unsigned char)(m >> 8);
        out[o++] = (unsigned char)m;
        memcpy(out + o, meta, m);
        o += m;
        out[o++] = (unsigned char)(dl >> 8);
        out[o++] = (unsigned char)dl;
        memcpy(out + o, in, dl);
        o += dl;
        in += dl;
        n -= dl;
    }
    return o;
}

/* Самая большая датаграмма клиента, которую мы несём узлу. Отправка склеивает заголовок запроса,
 * кадр Vision или рамку XUDP и саму датаграмму в ОДИН буфер записи TUNNEL_BUF — одним куском
 * обязательно, окно h2 принимает либо всё, либо ничего, — и обёртки не должны его переполнить:
 * иначе датаграмма крупнее ломала бы поток (SEND_FATAL), а не терялась. Запас тот же, что у
 * TCP (TUNNEL_BUF - 2048 в стеке: заголовок и обёртка Vision), и ещё 512 под рамку XUDP и длину.
 * В обратную сторону предел шире — UDP_DGRAM_ABS: приём собирает датаграмму в куче по её длине. */
#define VL_DGRAM_UP (TUNNEL_BUF - 2048 - 512)

/* Куда собирать датаграмму длиной want: в dg, а крупнее — в кучу. NULL — памяти нет; вызывающий
 * тогда выбрасывает датаграмму по длине, как слишком крупную (поток остаётся). Размер кучи —
 * всегда UDP_DGRAM_ABS, чтобы следующая крупная датаграмма не перевыделяла. */
static unsigned char *dg_reserve(struct vl_sess *s, size_t want) {
    if (want <= sizeof s->dg) return s->dg;
    if (!s->dgbig) s->dgbig = malloc(UDP_DGRAM_ABS);
    return s->dgbig;
}

/* Буфер текущей датаграммы: тот же выбор, что сделал dg_reserve, когда длина стала известна. */
static unsigned char *dg_cur(struct vl_sess *s) {
    return s->dg_want <= sizeof s->dg ? s->dg : s->dgbig;
}

/* Разобрать поток рамок XUDP от узла (после снятия Vision) и отдать датаграммы клиенту. Потоковый,
 * как udp_downstream: границы рамок, кадров Vision и записей TLS не совпадают. 0 или -1.
 *
 * Правила — по PacketReader из common/xudp: Keep с данными — датаграмма; KeepAlive — служебная,
 * данные (если есть) выбрасываются; End, New и всё прочее — конец потока. Адрес отправителя в Keep
 * пропускается: назначение потока фиксировано, и ответ отдаётся клиенту от него, как у команды 2. */
static int xudp_downstream(struct vl_sess *s, const unsigned char *d, size_t n,
                           dialer_emit_fn emit, void *arg) {
    while (n) {
        switch (s->xs) {
        case XS_LEN:
        case XS_DLEN: {
            unsigned v;
            if (!s->lenb_n && n >= 2) { v = (unsigned)(d[0] << 8 | d[1]); d += 2; n -= 2; }
            else if (!s->lenb_n) { s->lenb = d[0]; s->lenb_n = 1; return 0; }
            else { v = (unsigned)(s->lenb << 8 | d[0]); s->lenb_n = 0; d++; n--; }
            if (s->xs == XS_LEN) {
                if (v < 4 || v > 512) return -1;        /* Xray: короче 4 — конец; длиннее 512 — брак */
                s->xneed = (uint16_t)v;
                s->dg_have = 0;
                s->xs = XS_META;
            } else if (!v) {
                s->xs = XS_LEN;
            } else if (v > UDP_DGRAM_ABS || !dg_reserve(s, v)) {
                s->dg_skip = v;                          /* выбросить ровно по длине, см. udp_downstream */
                s->xdiscard = 1;
                s->xs = XS_SKIP;
            } else {
                s->dg_want = (uint16_t)v;
                s->dg_have = 0;
                s->xs = XS_DATA;
            }
            break;
        }
        case XS_META: {
            size_t take = (size_t)s->xneed - s->dg_have;
            if (take > n) take = n;
            memcpy(s->dg + s->dg_have, d, take);
            s->dg_have = (uint16_t)(s->dg_have + take);
            d += take;
            n -= take;
            if (s->dg_have < s->xneed) return 0;
            unsigned status = s->dg[2], opt = s->dg[3];
            if (status != 2 && status != 4) return -1;   /* End, New, чужое: конец потока */
            if (opt & 2) return -1;                      /* опция «ошибка» */
            s->xdiscard = status == 4;
            s->xs = (opt & 1) ? XS_DLEN : XS_LEN;
            break;
        }
        case XS_DATA: {
            size_t take = (size_t)s->dg_want - s->dg_have;
            if (take > n) take = n;
            memcpy(dg_cur(s) + s->dg_have, d, take);
            s->dg_have = (uint16_t)(s->dg_have + take);
            d += take;
            n -= take;
            if (s->dg_have < s->dg_want) return 0;
            s->xs = XS_LEN;
            if (!s->xdiscard && emit(arg, dg_cur(s), s->dg_want) != 0) return -1;
            s->dg_want = 0;
            s->dg_have = 0;
            break;
        }
        default: {                                       /* XS_SKIP */
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take;
            n -= take;
            s->dg_skip -= take;
            if (!s->dg_skip) { s->xs = XS_LEN; s->xdiscard = 0; }
            break;
        }
        }
    }
    return 0;
}

/* Отправить узлу данные в правильной форме: с заголовком VLESS на первом кадре и в обёртке
 * Vision, если узел её требует. */
static int vl_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* Буфер нужен ТОЛЬКО чтобы приклеить заголовок или кадр Vision к данным одной записью.
     * Когда клеить нечего — а это обычный случай, потому что заголовок уходит один раз на
     * соединение, а Vision заканчивает набивку первым же кадром, — данные отдаются прямо из
     * пакета, без копии вовсе. */
    static __thread unsigned char out[TUNNEL_BUF];
    const unsigned char *body = data;
    size_t len = 0;

    /* UDP к узлу с flow: рамки XUDP вместо датаграмм с длиной, см. блок XUDP выше. Данные, которые
     * пришли обрамлёнными dgram_frame, переупаковываются в xb; дальше путь общий с TCP — Vision, запись. */
    const int xudp = udp && node->flow[0];
    if (xudp) {
        static __thread unsigned char xb[TUNNEL_BUF];
        size_t xn = xudp_frames(k, !s->header_sent, data, n, xb, sizeof xb);
        if (!xn) return SEND_FATAL;
        data = xb;
        n = xn;
        body = xb;
        if (!s->header_sent) {
            /* У Mux в заголовке нет ни порта, ни адреса (vless_build_request): служба v1.mux.cool:666
             * подразумевается командой. */
            len = vless_build_request(s->uuid, VLESS_CMD_MUX, NULL, NULL, 0, node->flow,
                                      out, sizeof(out));
            if (!len) return SEND_FATAL;
        }
    } else if (!s->header_sent) {
        /* Адрес назначения берём из пакета: имени у нас нет, клиент уже разрешил его сам
         * (или через наш резолвер, который вернул fake-IP и подменит адрес в DNAT). */
        unsigned char ip4[4];
        memcpy(ip4, &k->dst, 4);
        /* Поток UDP объявляется командой 2 и БЕЗ flow.
         *
         * Vision (xtls-rprx-vision) — это про TCP: он подменяет копирование потока после
         * рукопожатия, а у датаграмм такого потока нет. Xray это и требует: аккаунту с
         * flow=xtls-rprx-vision он запрещает vision на TCP-запросе без flow, но UDP-запрос
         * с пустым flow принимает — именно так ходит UDP у самого Xray. Прислать здесь flow
         * значило бы получить закрытый поток без внятной причины.
         *
         * dport уже в хостовом порядке — см. комментарий в tun.h. */
        len = vless_build_request(s->uuid, udp ? VLESS_CMD_UDP : VLESS_CMD_TCP,
                                  NULL, ip4, k->dport,
                                  udp ? NULL : node->flow, out, sizeof(out));
        if (!len) return SEND_FATAL;
    }

    /* n == 0 (вызов стека для молчащего клиента, dialer.h): один заголовок, как клиент Xray
     * отправляет его через 100 мс без данных. Vision начинается с первых настоящих данных. */
    if (!n && !len) return SEND_OK;

    /* Оборачивать нужно только пока Vision не закончил набивку. После кадра end vision_wrap
     * сводится к копированию данных на месте — а копию мы делали ДВАЖДЫ: сначала в framed,
     * потом из него в out. То есть каждый байт выгрузки проходил по памяти трижды (третий
     * раз — внутри tls13_write, где он обязателен: шифрование идёт на месте в записи).
     * Теперь до шифрования копий ноль или одна. */
    /* Состояние Vision снимается ДО обёртки и возвращается, если отправка не удалась.
     *
     * Иначе первый кадр терялся безвозвратно при закрытом окне HTTP/2: vision_wrap уже
     * пометил бы UUID отправленным и набивку законченной, а h2_write не отправил НИЧЕГО
     * (он либо всё, либо ничего). Клиент повторяет тот же пакет, мы отправляем его уже без
     * кадра и без UUID — сервер такого не ждёт и закрывает поток. Снаружи это выглядело бы
     * как «узел с vision и grpc иногда не работает», причём «иногда» означало бы «когда
     * сервер не успел принять», то есть на быстром канале чаще.
     *
     * Шестьдесят четыре байта копии против невоспроизводимой поломки протокола. */
    struct vision vis_before = s->vis;
    if (node->flow[0] && !s->vis.sent_end && n) {
        size_t fn = vision_wrap(&s->vis, data, n, out + len, sizeof(out) - len);
        if (!fn) return SEND_FATAL;
        len += fn;
        body = out;
    } else if (len) {
        /* Заголовок уже лежит в out — данные приклеиваем к нему. */
        if (len + n > sizeof(out)) return SEND_FATAL;
        memcpy(out + len, data, n);
        len += n;
        body = out;
    } else {
        len = n;
    }

    /* Через транспорт: упаковку (tcp, grpc, xhttp) знает он, а не дайлер. */
    int rc = transport_write(&s->t, body, len);
    if (rc == H2_EWINDOW) {
        /* Окно HTTP/2 закрыто: сервер не успевает принимать. Это НЕ отказ — это то, для
         * чего управление потоком и существует. Ничего не ушло (h2_write либо отправляет
         * всё, либо ничего), поэтому достаточно не подтверждать пакет: клиент повторит
         * его сам, как при потере, и повторит уже тогда, когда окно откроется.
         *
         * Первая версия считала это ошибкой и разрывала соединение. Выглядело как
         * «выгрузка обрывается на случайном месте» — месте, где сервер впервые не успел. */
        s->vis = vis_before;                /* кадр не ушёл — обёртка как бы не делалась */
        return SEND_AGAIN;
    }
    if (rc == H2_ESTATUS) {
        /* Сервер xhttp ответил отказом на выгрузку (stream-up, packet-up): кусок не принят, и
         * поток за ним цел не будет. Закрываем, как любую неудачу отправки, но причину
         * называем — иначе узел, отказывающий каждому куску, выглядит живым (I-219). */
        static __thread time_t said;
        time_t now = stack_now_s();
        if (now - said >= 5) {
            said = now;
            fprintf(stderr, LOG_W "узел %s не принял данные: %s — соединение закрыто; "
                            "проверьте настройки xhttp узла\n", node->name, vless_strerror(rc));
        }
    }
    if (rc) return SEND_FATAL;
    /* Заголовок отмечаем отправленным только теперь: пометить раньше значило бы, что
     * повторная попытка уйдёт без него, и сервер не поймёт, куда соединять. */
    s->header_sent = 1;
    return SEND_OK;
}

/* Датаграмма узлу: двухбайтовая длина и данные ОДНИМ куском.
 *
 * Одним обязательно: h2_write отправляет либо всё, либо ничего, и датаграмма, разрезанная
 * на два вызова, при закрытом окне уехала бы половиной — сервер прочитал бы длину и стал
 * ждать хвост, которого нет, а следующая датаграмма приехала бы внутрь предыдущей. */
static size_t vl_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > VL_DGRAM_UP || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8);
    out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

/* Через транспорт, а не tls13_read напрямую: у grpc и xhttp между TLS и VLESS лежит HTTP/2, и
 * чтение мимо него отдавало бы кадры вместо данных. Прямой вызов работал, пока транспорт был
 * единственный, и это ровно тот случай, когда «работает» и «правильно» разошлись молча.
 *
 * Вариант _zc отдаёт указатель на расшифрованную запись там, где копия не нужна: на голом tcp
 * данные так и остаются в буфере соединения. Буфер стека при этом всё равно нужен — под
 * транспорты поверх HTTP/2, где кадр собирается из нескольких записей. */
static int vl_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data,
                   size_t *got) {
    struct vl_sess *s = sess;
    return transport_read_zc(&s->t, buf, cap, data, got);
}

/* Разобрать поток датаграмм от узла и отдать их клиенту.
 *
 * Состояние сборки живёт в сессии между вызовами: границы датаграммы, кадра HTTP/2 и записи
 * TLS не совпадают ни в одном месте, и «дочитать до конца датаграммы» здесь нельзя — чтение
 * заблокировалось бы и остановило весь цикл. Возвращает 0 или -1. */
static int udp_downstream(struct vl_sess *s, const unsigned char *d, size_t n,
                          dialer_emit_fn emit, void *arg) {
    while (n) {
        /* Слишком крупная датаграмма выбрасывается РОВНО ПО ДЛИНЕ. Оборвать отсчёт нельзя:
         * её хвост тут же был бы прочитан как длина следующей, и поток разъехался бы
         * навсегда — то есть одна такая датаграмма убивала бы соединение. */
        if (s->dg_skip) {
            uint32_t take = s->dg_skip < n ? s->dg_skip : (uint32_t)n;
            d += take;
            n -= take;
            s->dg_skip -= take;
            continue;
        }
        if (!s->dg_want) {
            if (s->lenb_n) {                        /* первый байт длины приехал раньше */
                s->dg_want = (uint16_t)((s->lenb << 8) | d[0]);
                s->lenb_n = 0;
                d++;
                n--;
            } else if (n == 1) {
                /* Запись кончилась ровно между двумя байтами длины. Случай редкий, и
                 * именно поэтому его надо обработать: потерянный байт длины — это не
                 * потерянная датаграмма, а сдвиг всего потока после неё. */
                s->lenb = d[0];
                s->lenb_n = 1;
                return 0;
            } else {
                s->dg_want = (uint16_t)((d[0] << 8) | d[1]);
                d += 2;
                n -= 2;
            }
            if (!s->dg_want) continue;              /* длина 0: отдавать нечего */
            if (s->dg_want > UDP_DGRAM_ABS || !dg_reserve(s, s->dg_want)) {
                /* Строка — слово в слово прежняя, вместе с повтором «tunnel:» после
                 * приставки: по ней журнал уже читают. */
                static __thread time_t said;
                time_t now = stack_now_s();
                if (now - said >= 10) {
                    said = now;
                    fprintf(stderr, LOG_W "tunnel: датаграмма %u байт не принята (предел %d, "
                            "или нет памяти) — выброшена\n", s->dg_want, UDP_DGRAM_ABS);
                }
                s->dg_skip = s->dg_want;
                s->dg_want = 0;
                continue;
            }
            s->dg_have = 0;
        }
        size_t need = (size_t)s->dg_want - s->dg_have;
        size_t take = n < need ? n : need;
        memcpy(dg_cur(s) + s->dg_have, d, take);
        s->dg_have = (uint16_t)(s->dg_have + take);
        d += take;
        n -= take;
        if (s->dg_have < s->dg_want) return 0;      /* хвост приедет следующей записью */

        /* Датаграмма целиком — клиенту. Метку времени соединения стек двигает сам, на КАЖДОЙ
         * отданной датаграмме: поток, по которому идёт только приём, иначе убрали бы по простою
         * прямо во время работы. */
        if (emit(arg, dg_cur(s), s->dg_want) != 0) return -1;
        s->dg_want = 0;
        s->dg_have = 0;
    }
    return 0;
}

static int vl_deliver(const void *ctx, void *sess, int udp, const unsigned char *rx, size_t got,
                      dialer_emit_fn emit, void *arg) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    /* Порядок разбора: сначала заголовок ОТВЕТА VLESS, потом кадры Vision.
     *
     * Сервер отвечает так: [версия|длина_доп|доп] и только ДАЛЬШЕ поток в кадрах Vision.
     * Заголовок ответа обёрткой не покрыт, и первая версия пыталась развернуть его как
     * кадр: получала «00 00 96 67 ad» (версия 0, длина 0, начало данных), длины кадра
     * выходили бессмысленные, unwrap возвращал EAGAIN, и ответ терялся целиком.
     *
     * Это зеркало ошибки на отправке: там заголовок ЗАПРОСА тоже идёт до кадра, а не
     * внутри него. Один и тот же принцип, который я дважды прочитал наоборот. */
    const unsigned char *cur = rx;
    size_t left = got;

    if (!s->established) {
        size_t skip = 0;
        if (vless_parse_response(cur, left, &skip) != 0) {
            TR("ответ VLESS не разобран (%zu байт)\n", left);
            return -1;
        }
        cur += skip;
        left -= skip;
        s->established = 1;
        TR("заголовок ответа снят (%zu байт), осталось %zu\n", skip, left);
    }

    /* UDP к узлу с flow: кадры Vision, а в них рамки XUDP. */
    if (udp && node->flow[0]) {
        while (left) {
            size_t used = 0, pl_n = 0;
            const unsigned char *pl = NULL;
            int ur = vision_unwrap(&s->vis, cur, left, &used, &pl, &pl_n);
            if (ur == VISION_EPROTO) return -1;
            if (ur != 0 || (!used && !pl_n)) break;
            cur += used;
            left -= used;
            if (pl_n && xudp_downstream(s, pl, pl_n, emit, arg) != 0) return -1;
        }
        return 0;
    }
    /* Дальше пути расходятся: у TCP это поток в кадрах Vision, у UDP без flow — датаграммы с
     * двухбайтовой длиной и без всякого Vision (его в запросе UDP мы не объявляли). */
    if (udp)
        return left ? udp_downstream(s, cur, left, emit, arg) : 0;

    while (left) {
        const unsigned char *p = cur;
        size_t pn = left;

        if (node->flow[0]) {
            size_t used = 0;
            const unsigned char *pl = NULL;
            size_t pl_n = 0;
            int ur = vision_unwrap(&s->vis, cur, left, &used, &pl, &pl_n);
            /* Недопустимая команда в кадре — это КОНЕЦ соединения, а не пауза.
             *
             * Разбор возвращает EPROTO, не сбросив накопленный заголовок, поэтому каждый
             * следующий вызов перечитывает тот же испорченный кадр и потребляет ноль
             * байт. Прежний `break` при этом отдавал неотрицательный итог, то есть
             * соединение считалось живым: одного байта команды 3 от сервера хватало,
             * чтобы туннель до бесконечности читал записи, расшифровывал их (самая
             * дорогая работа на этом железе) и выбрасывал целиком, а клиент ждал ответа,
             * которого не будет, пока слот не уберут по простою в 120 секунд. */
            if (ur == VISION_EPROTO) {
                TR("недопустимый кадр Vision: рвём соединение, осталось %zu\n", left);
                return -1;
            }
            if (ur != 0 || (!used && !pl_n)) {
                /* Нехватка данных ошибкой больше не считается: разбор потоковый и копит
                 * начало потока сам (см. rx_pre в vision.h). Ноль потреблённых байт при
                 * нулевой выдаче означает, что двигаться некуда. */
                TR("кадр не разобран: ur=%d осталось %zu\n", ur, left);
                break;
            }
            p = pl;
            pn = pl_n;
            cur += used;
            left -= used;

        } else {
            cur += left;
            left = 0;
        }

        /* Отдаём кадр сразу, а не складываем в общий буфер: складывать было незачем — всё
         * равно потом нарезали, — а стоило это копии всего трафика и предела «не влезло». */
        if (pn && emit(arg, p, pn) != 0) return -1;
    }

    /* Сервер объявил прямое копирование — сообщаем об этом связи, чтобы следующее чтение шло
     * мимо расшифровки. Ставится ЗДЕСЬ, потому что команда живёт в кадрах Vision, а про них
     * знает только этот код. */
    /* Под VLESS encryption прямого копирования не бывает: записи слоя шифрования остаются записями
     * до конца соединения (у Xray там CanSpliceCopy = 3, и сервер команду не шлёт). */
    if (s->vis.recv_direct && !s->t.link.rx_direct && !s->t.enc) {
        transport_direct(&s->t);
        TR("сервер перешёл на прямое копирование — читаем сокет как есть\n");
    }
    return 0;
}

/* ---- подъём ---------------------------------------------------------------------------- */

int vless_tunnel_run(struct output *o, const struct pool_cfg *pc,
                     void (*ready)(void *arg, const char *dev), void *arg) {
    /* Идентификатор узла — ДО устройства и потоков, пока узел ещё можно назвать. Дальше он
     * разбирается заново на каждое соединение (vl_flow_open), и отказ там означал бы туннель,
     * который поднят, но закрывает всё подряд (I-097). */
    const struct vless_node *node = (const struct vless_node *)pc->nodes + pc->first;
    unsigned char id[16];
    if (vless_uuid_parse(node->uuid, id) != 0) {
        fprintf(stderr, "steer[warn]: у узла %s не разбирается UUID — туннель %s не поднят; "
                        "проверьте ссылку узла\n", node->name, o->device);
        return 1;
    }
    g_trace = getenv("STEER_TUN_TRACE") != NULL;
    /* Узлы соединений выбирает пул (src/tunnel/pool.c): активных может быть несколько, у каждого
     * соединения свой, и замена умершего — без перезапуска процесса. */
    return pool_run(o, pc, ready, arg);
}

/* Что примет vl_send сейчас (dialer_ops.room): место у транспорта без того, что vl_send ставит
 * перед данными, — заголовка запроса, пока он не отправлен, и кадра Vision (набивка до
 * примерно 1400 байт), пока Vision не закончил набивку. */
static long vl_room(const void *ctx, void *sess) {
    const struct vless_node *node = ctx;
    struct vl_sess *s = sess;
    long r = transport_room(&s->t);
    if (r < 0) return -1;
    if (!s->header_sent) r -= 64;
    if (node->flow[0] && !s->vis.sent_end) r -= 2048;
    return r > 0 ? r : 0;
}

const struct dialer_ops vless_dialer = {
    .name = "vless",
    .caps = DC_PRECONNECT,
    .sess_size = sizeof(struct vl_sess),
    .peer = vl_peer,
    .describe = vl_describe,
    .strerror = vless_strerror,
    .connect = vl_connect,
    .take = vl_take,
    .close = vl_close,
    .clear = vl_clear,
    .fd = vl_fd,
    .has_data = vl_has_data,
    .flow_open = vl_flow_open,
    .send = vl_send,
    .room = vl_room,
    .dgram_frame = vl_dgram_frame,
    .dgram_max = VL_DGRAM_UP,
    .read = vl_read,
    .deliver = vl_deliver,
};
