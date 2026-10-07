/* Транспорт до узла: сборка ярусов, ввод-вывод связи и транспорт tcp. Ярусы — в transport.h.
 *
 * Переехало из клиента VLESS (client.c) при выделении стека туннеля из протокола (шаг 2
 * выпуска 1.10): прежде соединение с узлом было `struct vless_conn`, и транспорт в нём решался
 * перечислением `enum vless_transport { VT_RAW, VT_GRPC, VT_XHTTP }` с разбором по switch в
 * каждой функции обмена. Теперь транспорт — таблица (struct transport_ops), и новый (ws,
 * httpupgrade) — это новая таблица, а не ещё одна ветка в каждом switch.
 *
 * Поведение не менялось ни в чём: порядок шагов установления, кто и чем закрывается на каждом
 * отказе, ALPN, нулевая копия на tcp — те же. Держат это стенды vlessmatch (ветви отказа под
 * AddressSanitizer), xhupmatch (ответы на выгрузку xhttp) и ext-test на настоящей библиотеке.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>

#include "transport.h"
#include "reality.h"
#include "ech.h"

/* ---- ввод-вывод связи ----------------------------------------------------------------- */

int tr_link_write(void *ctx, const unsigned char *d, size_t n) {
    struct tr_link *l = ctx;
    if (l->plain) {
        size_t sent = 0;
        while (sent < n) {
            /* send с MSG_NOSIGNAL, а не write: закрытый узлом сокет — отказ записи (EPIPE), а не
             * SIGPIPE, даже у процесса, который его не выключал (проба узла, стенды). Поверх TLS
             * ту же роль для tls13_write играет выключенный SIGPIPE модульных команд
             * (cli/modcmd.c): tls13.c защищён от правок, и флага там не поставить. */
            ssize_t w = send(l->fd, d + sent, n - sent, MSG_NOSIGNAL);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return TR_EIO;
            }
            sent += (size_t)w;
        }
        return 0;
    }
    return tls13_write(&l->tls, d, n);
}

int tr_link_read(void *ctx, unsigned char *d, size_t cap, size_t *got) {
    struct tr_link *l = ctx;
    /* Прямое копирование: сервер перестал шифровать в нашу сторону, и расшифровывать
     * теперь нечего — в сокете лежит поток целевого соединения. Читаем как есть.
     *
     * Но СНАЧАЛА отдаём то, что уже прочитано у сокета в буфер записей: переход в прямой
     * режим случается посреди потока, и начало сырых данных к этому моменту обычно уже у
     * нас. Прочитать сокет, не отдав их, значит выбросить кусок и разъехаться с сервером —
     * узлы с Vision отдавали ровно ноль байт. */
    if (l->rx_direct && !l->plain) {
        size_t pending = tls13_take_pending(&l->tls, d, cap);
        if (pending) { *got = pending; return 0; }
    }
    if (l->plain || l->rx_direct) {
        ssize_t r = read(l->fd, d, cap);
        if (r <= 0) return r == 0 ? TR_ECLOSED : TR_EIO;
        *got = (size_t)r;
        return 0;
    }
    return tls13_read(&l->tls, d, cap, got);
}

void tr_link_close(struct tr_link *l) {
    if (l->fd >= 0) close(l->fd);
    l->fd = -1;
    /* Контексты шифров живут в куче: без освобождения туннель за час работы утекает на
     * тысячах соединений. Зовётся и для связи, до TLS не дошедшей: освобождение пустого
     * состояния безвредно, а знать здесь, докуда дошло рукопожатие, незачем. */
    if (!l->plain) tls13_free(&l->tls);
    l->tls.ready = 0;
}

/* ---- транспорт tcp: поток протокола прямо в связи ------------------------------------- */

static int tcp_write(struct transport *t, const unsigned char *d, size_t n) {
    return tr_link_write(&t->link, d, n);
}

static int tcp_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    return tr_link_read(&t->link, d, cap, got);
}

const struct transport_ops tr_tcp = {
    .name = "tcp", .alpn = NULL, .zc = 1,
    .open = NULL, .write = tcp_write, .read = tcp_read, .moved = NULL, .close = NULL,
};

/* Транспорт по полю ссылки. Неподдержанное отсеивает разбор подписки (sub.c), поэтому сюда
 * доходят только эти пять; всё прочее — tcp, как было всегда. */
static const struct transport_ops *transport_of(const char *type) {
    if (!strcmp(type, "grpc")) return &tr_grpc;
    if (!strcmp(type, "xhttp")) return &tr_xhttp;
    if (!strcmp(type, "ws")) return &tr_ws;
    if (!strcmp(type, "httpupgrade")) return &tr_httpupgrade;
    return &tr_tcp;
}

/* Лежит ли у транспорта своё непрочитанное (transport_ops.pending). */
static int fr_pending(const struct transport *t) {
    return t->fr && t->fr->pending && t->fr->pending(t);
}

/* Разбирает ли транспорт ещё своё поверх записей TLS (transport_ops.busy). */
static int fr_busy(const struct transport *t) {
    return t->fr && t->fr->busy && t->fr->busy(t);
}

/* Шифрование VLESS (encryption узла) — последний ярус: поверх готового транспорта, до запроса VLESS. */
static int tr_venc_after(struct transport *t, const struct tr_node *n, int timeout_s) {
    if (!n->encryption || !n->encryption[0]) return 0;
    int rc = tr_venc_open(t, n, timeout_s);
    if (rc) transport_close(t);
    return rc;
}

/* ---- сборка ярусов -------------------------------------------------------------------- */

int transport_open(struct transport *t, const struct tr_node *n, int timeout_s) {
    memset(t, 0, sizeof(*t));
    /* Транспорт определяется ЗДЕСЬ, один раз: дальше он читается и при открытии, и при каждой
     * отправке, и независимые разборы строки разошлись бы. */
    t->fr = transport_of(n->type);
    int rc = tr_link_open(&t->link, n, t->fr->alpn, timeout_s);
    if (rc) return rc;
    if (!t->fr->open) return tr_venc_after(t, n, timeout_s);

    /* ALPN здесь НЕ обязателен, и это важно понять правильно.
     *
     * Сервер Reality, признавший клиента, обслуживает соединение сам — с
     * `NextProtos: nil` (так и написано в config.go Xray), то есть ALPN не выбирает
     * вовсе и присылает пустые EncryptedExtensions. Признаком «h2 согласован» служит
     * не ответ, а сама конфигурация узла: Xray для reality решает версию HTTP тем же
     * способом — decideHTTPVersion возвращает «2» при reality, ни на что не глядя.
     *
     * Проверено на живом узле: openssl с -alpn h2 получает «h2», потому что его
     * НЕ признали и проксировали на настоящий сайт. Наше соединение ALPN не получает
     * именно потому, что признали. Требование ALPN отвергало бы ровно те узлы,
     * которые работают, — и первая версия этой проверки так и делала.
     *
     * Поэтому ошибка остаётся только на противоречие: сервер назвал протокол, и это
     * не тот, что просили. Тогда мы точно знаем, что говорить по нему бессмысленно.
     *
     * Отказы ПОСЛЕ удавшегося рукопожатия закрываются через transport_close, а не одним
     * close(fd), и это не стилистика. К этому месту ключи уже развёрнуты, и контексты
     * шифров живут в КУЧЕ. Дескриптор их не держит, вызывающие тоже не убирают: проверка узла
     * возвращается сразу, пул запасных сессий лишь помечает слот пустым.
     *
     * Стреляет это на узле grpc/xhttp с security=reality, которого Reality не признал:
     * маскировочный сайт выбирает ALPN http/1.1, ENOH2 приходит на КАЖДОЙ попытке, а пул
     * пополняется на каждый SYN. Процесс живёт неделями — RSS растёт до OOM-killer, и в
     * журнале при этом только «поток к узлу не открылся». */
    if (!t->link.plain && t->fr->alpn && t->link.tls.alpn[0] &&
        strcmp(t->link.tls.alpn, t->fr->alpn) != 0) {
        transport_close(t);
        /* Код — по тому, ЧТО просили: ws и httpupgrade просят только http/1.1, и «не согласился
         * на HTTP/2» у них было бы неправдой, отправляющей человека не туда. */
        return strcmp(t->fr->alpn, "h2") ? TR_ENOH1 : TR_ENOH2;
    }
    /* security=none с транспортом поверх HTTP/2: прежде единственная ветка отказа, которая
     * дескриптор НЕ закрывала. Узел, который не отвечает по h2, за сутки опроса упирал
     * процесс в RLIMIT_NOFILE. Теперь отказ открытия закрывается одним путём при любой
     * безопасности. */
    rc = t->fr->open(t, n, timeout_s);
    if (rc) { transport_close(t); return rc; }
    return tr_venc_after(t, n, timeout_s);
}

int transport_write(struct transport *t, const unsigned char *d, size_t n) {
    if (t->enc) return tr_venc_write(t, d, n);
    return t->fr->write(t, d, n);
}

long transport_room(const struct transport *t) {
    if (!t->fr || !t->fr->room) return -1;
    long r = t->fr->room(t);
    /* Шифрование VLESS оборачивает каждую запись в запись AEAD: длина и метка. Берём запас, а не
     * точную надбавку: она зависит от того, как данные разбиты на записи. */
    if (t->enc) r -= r / 32 + 64;
    return r > 0 ? r : 0;
}

int transport_read(struct transport *t, unsigned char *d, size_t cap, size_t *got) {
    *got = 0;
    if (t->enc) return tr_venc_read(t, d, cap, got);
    return t->fr->read(t, d, cap, got);
}

int transport_read_zc(struct transport *t, unsigned char *buf, size_t cap,
                      const unsigned char **data, size_t *got) {
    *got = 0;
    *data = buf;
    /* Без копии — только там, где данные лежат в записях TLS как есть (transport_ops.zc).
     * Прямое копирование (rx_direct) и security=none читают сокет сами. Своё непрочитанное у
     * транспорта (остаток после ответа 101 у httpupgrade) — раньше записей TLS: оно раньше
     * их и приехало. */
    if (!t->enc && t->fr->zc && !t->link.plain && !t->link.rx_direct && !fr_pending(t) && !fr_busy(t))
        return tls13_read_ref(&t->link.tls, data, got);
    return transport_read(t, buf, cap, got);
}

/* Есть ли у нас непрочитанное, о чём ядро не расскажет.
 *
 * Спрашивает туннель, прежде чем уйти ждать событий: данные, уже вынутые из сокета в буфер
 * записей, для epoll не существуют. Зачем это важно — в tls13.h у tls13_has_record.
 *
 * Три режима, а не один. Без TLS буфера нет вовсе. В прямом копировании нет и границ
 * записей — значимо просто «есть байты». В обычном режиме — только ЦЕЛАЯ запись: по части
 * записи мы всё равно ничего не сможем отдать, и считать её готовностью значило бы крутить
 * цикл впустую до прихода остатка.
 *
 * И четвёртое, раньше всех: своё непрочитанное у транспорта (transport_ops.pending) — остаток
 * после ответа 101 и конец потока ws, о котором сокет уже ничего не скажет. */
int transport_has_data(const struct transport *t) {
    /* Шифрованный поток: расшифрованное и целая запись во входе слоя (trvenc.c) — раньше всего. */
    if (t->enc && tr_venc_pending(t)) return 1;
    if (fr_pending(t)) return 1;
    if (t->link.plain) return 0;
    if (t->link.rx_direct) return tls13_buffered(&t->link.tls) > 0;
    return tls13_has_record(&t->link.tls);
}

void transport_direct(struct transport *t) { t->link.rx_direct = 1; }

void transport_moved(struct transport *t) {
    if (t->fr && t->fr->moved) t->fr->moved(t);
}

void transport_close(struct transport *t) {
    /* Своё транспорт закрывает ПЕРВЫМ, пока связь жива: ws шлёт при закрытии кадр close, как
     * Xray, и шифровать его после tr_link_close было бы нечем. Вторая связь xhttp закрывается
     * ЗДЕСЬ ЖЕ и по тому же доводу (transport_ops.close). Забыть её значило бы утечку ровно вдвое
     * злее обычной: на соединение приходится и лишний дескриптор, и лишний набор контекстов
     * шифра. fr пуст, если открытие не дошло до выбора транспорта — тогда и второй связи не было. */
    if (t->enc) tr_venc_close(t);
    if (t->fr && t->fr->close) t->fr->close(t);
    tr_link_close(&t->link);
}

const char *transport_strerror(int rc) {
    switch (rc) {
        case 0: return "ok";
        case TR_EDNS: return "имя не разрешилось";
        case TR_ESOCK: return "нет сокета";
        case TR_ECONNECT: return "TCP не соединился";
        case TR_EIO: return "обрыв ввода-вывода";
        case TR_ECLOSED: return "сервер закрыл соединение";
        case TR_ENOH2: return "сервер не согласился на HTTP/2 (нужен для grpc и xhttp)";
        case TR_EGRPC: return "поток gRPC в неожиданной форме";
        case TR_ENOH1: return "сервер выбрал не HTTP/1.1 (нужен для ws и httpupgrade)";
        /* Код ответа — в тексте: 404 и 400 почти всегда значат не тот path или host (сервер Xray
         * так отвечает на чужой путь), 403 и 5xx — посредника или CDN перед сервером. */
        case TR_EUPSTATUS: {
            static __thread char why[96];
            snprintf(why, sizeof why, "сервер ответил %d вместо 101 (проверьте path и host)",
                     tr_h1_last_status());
            return why;
        }
        case TR_ENOUPGRADE: return "ответ 101 без Upgrade: websocket";
        case TR_EWSACCEPT: return "ответ 101 с неверным Sec-WebSocket-Accept";
        case TR_EUPTIMEOUT: return "сервер не ответил на запрос Upgrade (таймаут)";
        case TR_EUPTOOBIG: return "ответ на запрос Upgrade не разобрался";
        case TR_EWSFRAME: return "кадр WebSocket не по RFC 6455";
        case TR_EVENC: {
            static __thread char why[128];
            snprintf(why, sizeof why, "VLESS encryption: %s", tr_venc_reason());
            return why;
        }
        case TR_EVENCAUTH: return "VLESS encryption: ключи разошлись с сервером (проверьте строку encryption)";
        case TR_EVENC0RTT: return "VLESS encryption: сервер отклонил билет 0-RTT";
        case H2_EIO: case H2_EPROTO: case H2_ESTATUS:
        case H2_ERESET: case H2_ETOOBIG: case H2_EWINDOW: return h2_strerror(rc);
        case REALITY_EBADKEY: return "pbk или sid не разобрались";
        case REALITY_ECRYPTO: return "сбой криптографии";
        case REALITY_ETOOBIG: return "ClientHello не влез";
        case TLS13_EAUTH: return "AEAD не сошёлся (ключи разъехались)";
        case TLS13_EFINISHED: return "Finished не совпал";
        case TLS13_ENOKEYSHARE: return "ServerHello без key_share";
        case TLS13_EBADSUITE: return "сервер выбрал неподдержанный шифр";
        case TLS13_EBADREC: return "испорченная TLS-запись";
        case TLS13_EECH: return "сервер не принял ECH (ключ ECH в ссылке устарел или сервер его не знает)";
        case ECH_EPARSE: return "ECH: ECHConfigList из ссылки не разобрался";
        case ECH_ENOCONFIG: return "ECH: в ECHConfigList нет записи, которую мы умеем (нужен X25519, HKDF-SHA256, AES-128-GCM или ChaCha20)";
        case ECH_ECRYPTO: return "ECH: сбой криптографии";
        case ECH_ETOOBIG: return "ECH: ClientHello не влез";
        case TLS13_ECLOSED: return "TLS закрыт сервером";
        case TLS13_EIO: return "ошибка чтения TLS";
        /* «Молчит», а не «ошибка»: соединение TCP встало, а на ClientHello ответа нет. Так
         * выглядит блокировка по имени в SNI, лежачий узел и потерянный пакет — то есть
         * причина снаружи движка, и текст обязан отправлять смотреть туда. */
        case TLS13_ETIMEOUT: return "узел не ответил на ClientHello (таймаут)";
        /* Причина у отказа проверки одна на код, но РАЗНАЯ по сути — «нечем проверить» это
         * не то же самое, что «проверили и не сошлось». Точный текст приносит tls13.c, и
         * общее слово добавляется здесь, чтобы человек видел, о чём вообще речь. */
        case TLS13_ECERT: {
            static __thread char why[128];
            const char *d = tls13_verify_reason();
            snprintf(why, sizeof why, "сервер не доказал подлинность%s%s",
                     d && d[0] ? ": " : "", d && d[0] ? d : "");
            return why;
        }
        default: return "неизвестная ошибка";
    }
}
