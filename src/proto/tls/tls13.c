/* Слой записей TLS 1.3 поверх готового рукопожатия Reality.
 *
 * Что здесь есть и чего сознательно нет.
 *
 * Reality — это настоящий TLS 1.3 с той единственной особенностью, что подлинность
 * сервера доказана аутентификатором в session_id, а не сертификатом. Всё остальное —
 * обычный обмен по RFC 8446: ServerHello приносит серверную половину key_share, из
 * общего секрета выводятся ключи трафика, дальше записи шифруются AEAD.
 *
 * Сертификат сервера Reality мы НЕ проверяем цепочкой, и это не небрежность: сертификат
 * подлинный, но принадлежит чужому сайту, которым сервер прикрывается. Проверять его
 * бессмысленно — подлинность уже доказана иначе (аутентификатор и HMAC в поле подписи, см.
 * certverify.h). Именно поэтому здесь нет TLS-стека библиотеки: он настаивал бы на проверке
 * цепочки, собирал бы свой ClientHello, а облик Hello у нас — браузерный и свой (reality.c).
 * От криптобиблиотеки здесь нужны только примитивы, и берутся они через слой scrypto.
 *
 * Реализована только та часть рукопожатия, которая нужна: разобрать ServerHello, вывести
 * ключи, проверить Finished. Возобновление сессий, client cert, HelloRetryRequest и
 * post-handshake authentication не поддержаны. После Finished ограниченно разбираются
 * NewSessionTicket (без возобновления) и KeyUpdate; close_notify закрывает только направление.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "scrypto.h"
#include "certverify.h"
#include "tls13.h"
#include "tls13_offered.h"
#include "tls13_engine.h"
#include "wipe.h"

/* Из reality.c: тот же X25519, но со вторым множителем из ServerHello. Общая функция, а
 * не копия, потому что копия крипто-кода — это два места, где может разойтись прижатие
 * скаляра или порядок байт. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

/* ---- HKDF-Expand-Label из RFC 8446 §7.1 ------------------------------------ */
/* Своя обёртка, потому что метка склеивается по строгому формату: длина вывода,
 * "tls13 "+label, контекст. Ошибка в одном байте здесь даёт ключи, отличные от
 * серверных, и проявляется как «расшифровка не выходит» уже после рукопожатия. */
static int expand_label(enum sc_hash md,
                        const unsigned char *secret, size_t secret_n,
                        const char *label,
                        const unsigned char *ctx, size_t ctx_n,
                        unsigned char *out, size_t out_n) {
    unsigned char info[512];
    size_t i = 0;
    size_t llen = strlen(label);
    if (6 + llen > 255 || ctx_n > 255 || 4 + 6 + llen + ctx_n > sizeof(info)) return -1;
    info[i++] = (unsigned char)(out_n >> 8);
    info[i++] = (unsigned char)out_n;
    info[i++] = (unsigned char)(6 + llen);
    memcpy(info + i, "tls13 ", 6); i += 6;
    memcpy(info + i, label, llen); i += llen;
    info[i++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + i, ctx, ctx_n); i += ctx_n; }
    return sc_hkdf_expand(md, secret, secret_n, info, i, out, out_n);
}

static int derive_secret(enum sc_hash md, const unsigned char *secret,
                         const char *label, const unsigned char *thash, size_t hash_n,
                         unsigned char *out) {
    return expand_label(md, secret, hash_n, label, thash, hash_n, out, hash_n);
}

/* ---- транскрипт ------------------------------------------------------------ */
/* Хеш всех сообщений рукопожатия по порядку. Он входит в вывод каждого ключа, поэтому
 * любое расхождение с сервером (лишний байт, пропущенное сообщение) ломает не транскрипт,
 * а ключи — и обнаруживается как неверный Finished. */
/* Internal failures are terminal; never substitute a synthetic transcript. */
static int tr_init(struct tls13 *t) {
    if (sc_hash_init(&t->tr, SC_SHA256) || sc_hash_init(&t->tr384, SC_SHA384)) return TLS13_ECRYPTO;
    return 0;
}
static int tr_add(struct tls13 *t, const unsigned char *d, size_t n) {
    if (sc_hash_update(&t->tr, d, n) || sc_hash_update(&t->tr384, d, n)) return TLS13_ECRYPTO;
    return 0;
}
static int tr_hash(const struct tls13 *t, unsigned char *out) {
    struct sc_hash_ctx c;
    size_t length = t->hash_n == 48 ? 48 : 32;
    if (sc_hash_clone(&c, t->hash_n == 48 ? &t->tr384 : &t->tr)) {
        memset(out, 0, length); return TLS13_ECRYPTO;
    }
    int rc = sc_hash_final(&c, out); sc_hash_free(&c);
    if (rc) { steer_wipe(out, length); return TLS13_ECRYPTO; }
    return 0;
}

/* ---- чтение записей -------------------------------------------------------- */
/* Чтение по дескриптору — только для рукопожатия: у него ещё нет struct tls13 с буфером,
 * и оно по своей природе синхронное. */
static int read_full(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r == 0) return TLS13_ECLOSED;
        if (r < 0) {
            if (errno == EINTR) continue;
            /* Сокет рукопожатия блокирующий и со сроком (SO_RCVTIMEO), поэтому EAGAIN здесь
             * значит ровно одно: срок вышел, а узел не ответил. Это не ошибка ввода-вывода,
             * и называть её так — уводить в сторону: искать надо снаружи. */
            if (errno == EAGAIN || errno == EWOULDBLOCK) return TLS13_ETIMEOUT;
            return TLS13_EIO;
        }
        got += (size_t)r;
    }
    return 0;
}

/* Одна TLS-запись, собранная из буфера соединения.
 *
 * Читаем у сокета КРУПНО и редко: один read() берёт всё, что накопилось (до 16 КБ), а
 * записи выдаются из буфера без новых вызовов. Прежняя версия спрашивала FIONREAD,
 * подглядывала заголовок и ждала дособирания записи на каждой итерации — это давало
 * 16 000 чтений в секунду по 600 байт и 80% времени цикла внутри чтения.
 *
 * may_wait разделяет два режима: рукопожатие ЖДЁТ (оно синхронное, продолжить с середины
 * некому), поток данных не ждёт — недособранную запись оставляем в буфере и уходим к
 * другим соединениям. */
/* Сдвигать остаток к началу буфера стоит только когда хвост кончился: при
 * записях среднего размера (4-8 КБ — обычное дело у Xray и норма в режиме
 * rx_direct) безусловный сдвиг гонял memmove на каждое чтение, перенося
 * килобайты ради места, которое и так было. Порог — чтобы одно чтение могло
 * взять осмысленный кусок, а не дочитывать буфер по сотне байт. */
#define RBUF_MIN_FILL 4096

static int rbuf_fill(struct tls13 *t, int may_wait) {
    /* Компактим, когда непрерывного места под чтение осталось мало. Порядок
     * важен: сначала сдвиг, потом проверка переполнения — полный буфер со
     * сдвинутым началом это не переполнение, а повод освободить место. */
    if (t->rbuf_off && sizeof(t->rbuf) - t->rbuf_n < RBUF_MIN_FILL) {
        if (t->rbuf_n > t->rbuf_off)
            memmove(t->rbuf, t->rbuf + t->rbuf_off, t->rbuf_n - t->rbuf_off);
        t->rbuf_n -= t->rbuf_off;
        t->rbuf_off = 0;
    }
    if (t->rbuf_n >= sizeof(t->rbuf)) return TLS13_ETOOBIG;

    /* Поток данных не ждёт — и спрашивает не poll перед чтением, а само чтение: recv с MSG_DONTWAIT
     * на пустом сокете сразу даёт EAGAIN. Прежде здесь стоял poll(…, 0) перед каждым read — второй
     * системный вызов на каждое чтение: 66–115 вызовов poll на МБ у gRPC и Vision (замер R-148),
     * а сокет узла блокирующий и со сроком, так что read без проверки ждал бы до его конца. Рукопожатие
     * (may_wait) читает как раньше — ждёт. */
    ssize_t r = may_wait ? read(t->fd, t->rbuf + t->rbuf_n, sizeof(t->rbuf) - t->rbuf_n)
                         : recv(t->fd, t->rbuf + t->rbuf_n, sizeof(t->rbuf) - t->rbuf_n, MSG_DONTWAIT);
    if (r == 0) return TLS13_ECLOSED;
    if (r < 0) {
        if (errno == EINTR) return 0;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return TLS13_EAGAIN;
        return TLS13_EIO;
    }
    t->rbuf_n += (size_t)r;
    return 0;
}

/* Для рукопожатия: своего буфера у него ещё нет, а ждать он обязан. */
static int read_record_fd(int fd, unsigned char *type, unsigned char *body, size_t cap,
                          size_t *body_n) {
    unsigned char h[5];
    int rc = read_full(fd, h, 5);
    if (rc) return rc;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return TLS13_ETOOBIG;
    rc = read_full(fd, body, len);
    if (rc) return rc;
    *type = h[0];
    *body_n = len;
    return 0;
}

static int read_record(struct tls13 *t, unsigned char *type, unsigned char **body,
                       size_t *body_n, int may_wait) {
    for (int guard = 0; guard < 64; guard++) {
        size_t have = t->rbuf_n - t->rbuf_off;
        if (have >= 5) {
            const unsigned char *h = t->rbuf + t->rbuf_off;
            size_t len = ((size_t)h[3] << 8) | h[4];
            if (len > TLS13_MAX_REC) return TLS13_EBADREC;
            if (have >= 5 + len) {
                *type = h[0];
                *body = t->rbuf + t->rbuf_off + 5;
                *body_n = len;
                t->rbuf_off += 5 + len;
                return 0;
            }
        }
        int rc = rbuf_fill(t, may_wait);
        if (rc) return rc;
    }
    return TLS13_EAGAIN;
}

/* ---- AEAD ------------------------------------------------------------------ */
/* Nonce в TLS 1.3: iv XOR порядковый номер, выровненный вправо. Счётчик свой на каждое
 * направление и НЕ сбрасывается — сброс означал бы повтор nonce, то есть полную потерю
 * защиты AEAD. */
static void aead_nonce(const unsigned char iv[12], uint64_t seq, unsigned char out[12]) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++)
        out[11 - i] ^= (unsigned char)(seq >> (8 * i));
}

/* Развернуть ключ в контекст шифра. Вызывается один раз на направление, когда ключи
 * трафика готовы; дальше каждая запись пользуется готовым контекстом. */
int tls13_keys_setup(struct tls13_keys *k) {
    if (k->ctx_ready) return 0;
    enum sc_aead_alg a;
    /* Длина ключа сверяется с алгоритмом: key_n заполняет вызывающий (рукопожатие, xsteer), и
     * расхождение означало бы ключ AES-256, развёрнутый из шестнадцати байт с мусором. */
    switch (k->aead) {
        case TLS13_AEAD_AES128: a = SC_AES128_GCM; break;
        case TLS13_AEAD_AES256: a = SC_AES256_GCM; break;
        case TLS13_AEAD_CHACHA: a = SC_CHACHA20_POLY1305; break;
        default: return TLS13_ECRYPTO;
    }
    if (k->key_n != sc_aead_key_len(a)) return TLS13_ECRYPTO;
    if (sc_aead_setkey(&k->ctx, a, k->key) != 0) return TLS13_ECRYPTO;
    k->ctx_ready = 1;
    return 0;
}

void tls13_keys_free(struct tls13_keys *k) {
    if (!k->ctx_ready) return;
    sc_aead_free(&k->ctx);
    k->ctx_ready = 0;
}

/* Безопасна на ОБНУЛЁННОЙ структуре и при повторном вызове — это контракт, а не удобство:
 * её зовёт transport_close на любой связи, в том числе при security=none, где
 * tls13_init не звали вовсе. Держится на том, что у каждого контекста слоя нулевой «алгоритм» или
 * флаг готовности значит «пусто» (sc_hash_free, sc_aead_free ничего не делают), а освобождение
 * этот признак снова обнуляет. */
static int post_active(const struct tls13 *t) { return t->post.phase == TLS13_POST_PHASE; }
static void post_init(struct tls13 *t, const unsigned char *client, const unsigned char *server) {
    sc_hash_free(&t->tr);
    sc_hash_free(&t->tr384);
    steer_wipe(t->phase_storage, sizeof(t->phase_storage));
    t->post.phase = TLS13_POST_PHASE;
    memcpy(t->post.app_wr_secret, client, t->hash_n);
    memcpy(t->post.app_rd_secret, server, t->hash_n);
}
void tls13_free(struct tls13 *t) {
    int post = post_active(t);
    outq_free(&t->oq);
    t->live = 0;
    tls13_keys_free(&t->rd);
    tls13_keys_free(&t->wr);
    /* Ключ и iv трафика — секреты на всё время соединения; освободить контекст шифра мало: массивы
     * остаются в структуре, которую вызывающий часто отдаёт в free/кучу без обнуления. */
    steer_wipe(t->rd.key, sizeof(t->rd.key));
    steer_wipe(t->wr.key, sizeof(t->wr.key));
    steer_wipe(t->rd.iv, sizeof(t->rd.iv));
    steer_wipe(t->wr.iv, sizeof(t->wr.iv));
    if (!post) { sc_hash_free(&t->tr); sc_hash_free(&t->tr384); }
    steer_wipe(t->phase_storage, sizeof(t->phase_storage));
    t->ready = 0;
}

int tls13_aead_open(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n) {
    if (n < 16) return TLS13_EBADREC;
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    size_t ct = n - 16;
    /* Тег КОПИРУЕТСЯ, а не читается из того же буфера. Расшифровка идёт на месте, и тег
     * лежит сразу за шифротекстом — то есть в области, которую реализация вправе задеть,
     * дописывая последний неполный блок. tests/scryptomatch.c проверяет, что wolfCrypt так не
     * делает ни на одном размере записи, — но зависеть от внутреннего устройства библиотеки
     * незачем, а копия в шестнадцать байт стоит ничего. */
    unsigned char tag[16];
    memcpy(tag, buf + ct, 16);
    int rc = sc_aead_open(&k->ctx, nonce, aad, aad_n, buf, ct, tag);
    return rc == 0 ? 0 : TLS13_EAUTH;
}

int tls13_aead_seal(struct tls13_keys *k, uint64_t seq,
                     const unsigned char *aad, size_t aad_n,
                     unsigned char *buf, size_t n, unsigned char *tag) {
    if (!k->ctx_ready) return TLS13_ESTATE;
    unsigned char nonce[12];
    aead_nonce(k->iv, seq, nonce);
    int rc = sc_aead_seal(&k->ctx, nonce, aad, aad_n, buf, n, tag);
    return rc == 0 ? 0 : TLS13_ECRYPTO;
}

/* Те же две операции, но с одноразовым контекстом — для РУКОПОЖАТИЯ.
 *
 * Оно проходит по три-четыре записи на соединение, поэтому цена разворота ключа здесь не
 * значит ничего, а взамен не приходится освобождать контексты на десятке путей выхода по
 * ошибке. Постоянные контексты стоят там, где идёт поток, — и только там. */
static int aead_open_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = tls13_keys_setup(&k);
    if (rc == 0) rc = tls13_aead_open(&k, seq, aad, aad_n, buf, n);
    tls13_keys_free(&k);
    steer_wipe(&k, sizeof(k));              /* копия ключа рукопожатия на стеке */
    return rc;
}

static int aead_seal_once(const struct tls13_keys *src, uint64_t seq,
                          const unsigned char *aad, size_t aad_n,
                          unsigned char *buf, size_t n, unsigned char *tag) {
    struct tls13_keys k = *src;
    k.ctx_ready = 0;
    int rc = tls13_keys_setup(&k);
    if (rc == 0) rc = tls13_aead_seal(&k, seq, aad, aad_n, buf, n, tag);
    tls13_keys_free(&k);
    steer_wipe(&k, sizeof(k));
    return rc;
}

/* ---- рукопожатие ----------------------------------------------------------- */

/* Почему отказ проверки лежит В ПОТОКЕ, а не в struct tls13. К моменту, когда вызывающий
 * захочет назвать причину, соединение уже закрыто и структура очищена: путь отказа в
 * client.c — vless_close, а он обнуляет всё. Поток же переживает и закрытие, и следующую
 * попытку того же соединителя, а разные соединители своих причин друг другу не портят. */
static __thread char g_verify_reason[96];

const char *tls13_verify_reason(void) { return g_verify_reason; }

/* Секреты расписания ключей одним куском. Раньше лежали отдельными массивами на стеке handshake(), и
 * ни один из многочисленных выходов (return на каждой ошибке разбора) их не стирал: после рукопожатия
 * в стеке оставались handshake-секреты, мастер-секрет, секреты трафика и общий секрет ECDHE (в т.ч.
 * ML-KEM) — читаются из дампа памяти или чужого вызова, севшего на тот же стек. Собраны в структуру,
 * чтобы обёртка handshake() стёрла их ОДИН раз на любом выходе, а не по return в полусотне мест. */
struct hs_secrets {
    unsigned char early[48], derived[48], hs_secret[48];
    unsigned char ecdhe[SC_MLKEM768_SS + 32];
    unsigned char c_hs[48], s_hs[48];
    unsigned char master[48], c_ap[48], s_ap[48];
    unsigned char fkey[48], cfkey[48];
    struct tls13_keys c_hk, s_hk;           /* ключи рукопожатия — копии с ключом и iv */
};

static int write_all_fd(int fd, const unsigned char *p, size_t n);

/* Sans-IO negotiation state: only public transcript metadata; no socket,
 * borrowed auth retention or crypto-context ownership transfer. Shared helper
 * for the legacy handshake and forthcoming incremental engine. */
struct hs_negotiated {
    enum sc_hash md;
    size_t hash_n, server_hello_n;
    unsigned char empty_hash[48], server_hello[TLS13_SH_KEEP];
};
/* Bound work as well as bytes: real TLS1.3 ServerHello has only a few
 * extensions. Retain a small ID set instead of an 8KiB bitmap or an unbounded
 * quadratic duplicate scan over peer-controlled empty extensions. */
#define TLS13_SH_EXTENSIONS_MAX 64u
static int validate_server_hello(const unsigned char *rec, size_t n) {
    uint16_t seen[TLS13_SH_EXTENSIONS_MAX];
    size_t count = 0;
    int selected_version = 0;
    if (!rec || n < 44 || rec[0] != 2 || rec[4] != 3 || rec[5] != 3) return TLS13_EBADREC;
    size_t declared = ((size_t)rec[1] << 16) | ((size_t)rec[2] << 8) | rec[3];
    if (declared != n - 4 || rec[38] > 32) return TLS13_EBADREC;
    size_t offset = 39 + rec[38];
    if (offset > n || n - offset < 5 || rec[offset + 2] != 0) return TLS13_EBADREC;
    offset += 3; /* selected cipher and legacy compression */
    size_t length = ((size_t)rec[offset] << 8) | rec[offset + 1];
    offset += 2;
    if (length != n - offset) return TLS13_EBADREC;
    while (offset < n) {
        if (n - offset < 4 || count == TLS13_SH_EXTENSIONS_MAX) return TLS13_EBADREC;
        uint16_t type = (uint16_t)((unsigned)rec[offset] << 8 | rec[offset + 1]);
        length = ((size_t)rec[offset + 2] << 8) | rec[offset + 3];
        offset += 4;
        if (length > n - offset) return TLS13_EBADREC;
        for (size_t i = 0; i < count; i++) if (seen[i] == type) return TLS13_EBADREC;
        seen[count++] = type;
        if (type == 0x33) {
            if (length < 4 || ((((size_t)rec[offset + 2] << 8) | rec[offset + 3]) != length - 4))
                return TLS13_EBADREC;
        } else if (type == 0x2b) {
            if (length != 2 || rec[offset] != 3 || rec[offset + 1] != 4) return TLS13_EBADREC;
            selected_version = 1;
        }
        offset += length;
    }
    return selected_version ? 0 : TLS13_EBADREC;
}
#ifdef STEER_TLS13_TEST
int tls13_test_server_hello_validate(const unsigned char *record, size_t length) {
    return validate_server_hello(record, length);
}
#endif
static int negotiate_server_hello(struct hs_secrets *sec, struct tls13 *t,
    const unsigned char *rec, size_t n, const unsigned char *our_priv,
    const struct tls13_auth *auth, const struct tls13_offered *offered, struct hs_negotiated *negotiated) {
    enum sc_hash md = SC_SHA256;
    size_t H = 0;
    int valid = validate_server_hello(rec, n);
    if (valid) return valid;
    valid = match_server_offer(offered, rec, n);
    if (valid) return valid;
    /* Серверная половина key_share — в расширениях. Ищем по типу 0x33, а не по
     * смещению: длина session_id и набор расширений меняются от сервера к серверу.
     *
     * HS_HDR = 4: тип сообщения(1) + длина(3). Первая версия начинала разбор сразу с
     * версии, съедая заголовок как данные — session_id читался как 22 вместо 32, а
     * длина расширений выходила 14973 при записи в 122 байта. Проявлялось это как
     * «испорченная TLS-запись», то есть виноватым выглядел сервер. */
    const size_t HS_HDR = 4;
    unsigned char server_pub[32];
    /* Гибрид X25519MLKEM768: ответ сервера — шифротекст ML-KEM (1088) и его X25519-половина (32). */
    unsigned char kem_ct[SC_MLKEM768_CT];
    int have_pub = 0, have_kem = 0;
    {
        size_t p = HS_HDR + 2 + 32;             /* заголовок + version + random */
        if (p >= n) return TLS13_EBADREC;
        size_t sid_n = rec[p++];
        p += sid_n;
        p += 2;                                 /* cipher_suite */
        p += 1;                                 /* compression */
        if (p + 2 > n) return TLS13_EBADREC;
        size_t exts_n = ((size_t)rec[p] << 8) | rec[p + 1];
        p += 2;
        size_t end = p + exts_n;
        if (end > n) return TLS13_EBADREC;
        while (p + 4 <= end) {
            unsigned etype = ((unsigned)rec[p] << 8) | rec[p + 1];
            size_t elen = ((size_t)rec[p + 2] << 8) | rec[p + 3];
            p += 4;
            if (p + elen > end) break;
            if (etype == 0x0033 && elen >= 4) {
                /* group(2) + length(2) + key. Группу читаем, а не гадаем по длине: X25519 — 32 байта,
                 * гибрид — 1120, и принять шифротекст за открытый ключ значило бы дойти до Finished
                 * с чужим секретом (видно как «AEAD не сошёлся»). */
                unsigned grp = ((unsigned)rec[p] << 8) | rec[p + 1];
                size_t klen = ((size_t)rec[p + 2] << 8) | rec[p + 3];
                if (4 + klen > elen) return TLS13_EBADREC;
                if (grp == 0x001D && klen == 32) {
                    memcpy(server_pub, rec + p + 4, 32);
                    have_pub = 1;
                } else if (grp == 0x11EC && klen == SC_MLKEM768_CT + 32 && auth && auth->mlkem_dk) {
                    memcpy(kem_ct, rec + p + 4, SC_MLKEM768_CT);
                    memcpy(server_pub, rec + p + 4 + SC_MLKEM768_CT, 32);
                    have_pub = have_kem = 1;
                } else return TLS13_ENOKEYSHARE;
            }
            p += elen;
        }
    }
    if (!have_pub) return TLS13_ENOKEYSHARE;
    /* Копия ServerHello для проверки ML-DSA: rec ниже переиспользуется под следующие записи, а подпись
     * считается и над ним тоже. Копируем только когда проверка включена. */
    unsigned char *sh_copy = negotiated->server_hello;
    size_t sh_copy_n = 0;
    if (auth && auth->mldsa_pk) {
        if (n > TLS13_SH_KEEP) return TLS13_ETOOBIG;
        memcpy(sh_copy, rec, n);
        sh_copy_n = n;
    }

    /* Выбранный шифр определяет AEAD. Берём из ServerHello, а не догадываемся. */
    {
        size_t p = HS_HDR + 2 + 32;
        size_t sid_n = rec[p++];
        p += sid_n;
        unsigned suite = ((unsigned)rec[p] << 8) | rec[p + 1];
        switch (suite) {
            case 0x1301: t->rd.aead = t->wr.aead = TLS13_AEAD_AES128;
                         t->rd.key_n = t->wr.key_n = 16; t->hash_n = 32; break;
            case 0x1302: t->rd.aead = t->wr.aead = TLS13_AEAD_AES256;
                         t->rd.key_n = t->wr.key_n = 32; t->hash_n = 48; break;
            case 0x1303: t->rd.aead = t->wr.aead = TLS13_AEAD_CHACHA;
                         t->rd.key_n = t->wr.key_n = 32; t->hash_n = 32; break;
            default: return TLS13_EBADSUITE;
        }
    }
    /* Только теперь известно, на каком хеше стоит всё расписание ключей. */
    H = t->hash_n;
    md = H == 48 ? SC_SHA384 : SC_SHA256;

    /* ECH: сервер принял внутренний Hello или нет (RFC 9849, 7.2). Подтверждение — восемь последних байт
     * ServerHello.random: HKDF-Expand-Label(HKDF-Extract(0, random Inner), "ech accept confirmation",
     * Hash(Inner ‖ ServerHello с обнулёнными этими восемью байтами), 8). Принял — транскрипт с этой минуты
     * строится от Inner, а не от отправленного Outer (и ключи, и Finished считаются по нему). Не принял —
     * рукопожатие обрывается (TLS13_EECH, см. tls13.h). Сравнение без раннего выхода: подтверждение не
     * секрет, но привычка дешевле исключения. */
    if (auth && auth->ech) {
        struct sc_hash_ctx ic;
        unsigned char ch[48], prk[48], conf[8], zero8[8] = { 0 };
        if (n < 38) return TLS13_EBADREC;
        if (sc_hash_init(&ic, md) != 0) return TLS13_ECRYPTO;
        sc_hash_update(&ic, auth->ech->inner, auth->ech->inner_n);
        sc_hash_update(&ic, rec, 30);
        sc_hash_update(&ic, zero8, 8);
        sc_hash_update(&ic, rec + 38, n - 38);
        int hr = sc_hash_final(&ic, ch);
        sc_hash_free(&ic);
        if (hr != 0 || sc_hkdf_extract(md, NULL, 0, auth->ech->random, 32, prk) != 0 ||
            expand_label(md, prk, H, "ech accept confirmation", ch, H, conf, 8) != 0)
            return TLS13_ECRYPTO;
        unsigned char diff = 0;
        for (int i = 0; i < 8; i++) diff |= (unsigned char)(conf[i] ^ rec[30 + i]);
        if (diff) return TLS13_EECH;
        /* Транскрипт заново: Inner, затем настоящий ServerHello. */
        sc_hash_free(&t->tr);
        sc_hash_free(&t->tr384);
        if (tr_init(t) || tr_add(t, auth->ech->inner, auth->ech->inner_n) || tr_add(t, rec, n))
            return TLS13_ECRYPTO;
    }

    /* Расписание ключей RFC 8446 §7.1. Каждый шаг обязателен и порядок его строг:
     * early -> handshake -> master, с derive-secret между ними. */
    unsigned char zeros[48] = {0};
    unsigned char *empty_hash = negotiated->empty_hash;
    if (sc_hash(md, zeros, 0, empty_hash) != 0) return TLS13_ECRYPTO;

    if (sc_hkdf_extract(md, NULL, 0, zeros, H, sec->early) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->early, H, "derived", empty_hash, H, sec->derived, H) != 0) return TLS13_ECRYPTO;

    /* ECDHE-вход расписания — секрет с ЭФЕМЕРНЫМ ключом сервера из ServerHello, а не
     * тот, что посчитан в reality.c.
     *
     * Это разные величины, и путать их — ровно та ошибка, из-за которой рукопожатие
     * доходило до конца, а AEAD не сходился:
     *
     *   Reality-секрет = наш эфемерный x постоянный ключ сервера (pbk из ссылки).
     *                    Он нужен ТОЛЬКО для аутентификатора в session_id;
     *   TLS-секрет     = наш эфемерный x эфемерный ключ сервера (key_share в ServerHello).
     *                    На нём стоит всё расписание ключей.
     *
     * Сервер, обслуживая нас как VLESS, всё равно проводит обычный TLS 1.3 со своим
     * эфемерным ключом — иначе поток не был бы неотличим от настоящего HTTPS. */
    /* Секрет гибрида — mlkem_ss ‖ x25519_ss (draft-ietf-tls-ecdhe-mlkem: у X25519MLKEM768 ML-KEM
     * первый; тот же порядок у Go и BoringSSL). Обычный X25519 — просто 32 байта. */
    size_t ecdhe_n = 32;
    if (have_kem) {
        if (getenv("STEER_PQ_TRACE")) fprintf(stderr, "steer[pq]: сервер выбрал X25519MLKEM768\n");
        if (sc_mlkem768_decaps(sec->ecdhe, auth->mlkem_dk, kem_ct) != 0) return TLS13_ECRYPTO;
        if (x25519_shared_ext(our_priv, server_pub, sec->ecdhe + SC_MLKEM768_SS) != 0) return TLS13_ECRYPTO;
        ecdhe_n = sizeof(sec->ecdhe);
    } else if (x25519_shared_ext(our_priv, server_pub, sec->ecdhe) != 0) return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, sec->derived, H, sec->ecdhe, ecdhe_n, sec->hs_secret) != 0)
        return TLS13_ECRYPTO;

    unsigned char th[48];
    if (tr_hash(t, th)) return TLS13_ECRYPTO;
    if (derive_secret(md, sec->hs_secret, "c hs traffic", th, H, sec->c_hs) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, sec->hs_secret, "s hs traffic", th, H, sec->s_hs) != 0) return TLS13_ECRYPTO;

    /* Transfer only key parameters, never a shallow crypto-context copy. */
    if (sec->c_hk.ctx_ready || sec->s_hk.ctx_ready || t->wr.ctx_ready || t->rd.ctx_ready)
        return TLS13_ESTATE;
    sec->c_hk.aead = t->wr.aead; sec->c_hk.key_n = t->wr.key_n;
    sec->s_hk.aead = t->rd.aead; sec->s_hk.key_n = t->rd.key_n;
    if (expand_label(md, sec->c_hs, H, "key", NULL, 0, sec->c_hk.key, sec->c_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->c_hs, H, "iv", NULL, 0, sec->c_hk.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->s_hs, H, "key", NULL, 0, sec->s_hk.key, sec->s_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->s_hs, H, "iv", NULL, 0, sec->s_hk.iv, 12) != 0) return TLS13_ECRYPTO;

    negotiated->md = md; negotiated->hash_n = H;
    negotiated->server_hello_n = sh_copy_n;
    return 0;
}

/* Принимает уже отправленный ClientHello (для транскрипта) и общий секрет.
 * host != NULL включает проверку сертификата (security=tls); Reality использует
 * собственное доказательство. Возвращается с готовыми ключами трафика. */
/* Caller-owned assembly: legacy worker scratch or a private bounded arena.
 * No IO, retained auth pointer, roots lookup or crypto-context copying. */
enum hs_message_phase { HS_EXPECT_EE, HS_EXPECT_CERT, HS_EXPECT_CV, HS_EXPECT_FINISHED, HS_FINISHED };
struct hs_messages {
    unsigned char *buffer, *certificate;
    size_t capacity, certificate_capacity, have, certificate_n;
    unsigned char verify[1024], transcript[48], server_finished[48];
    size_t verify_n, transcript_n;
    int finished;
    enum hs_message_phase phase;
    const struct tls13_offered *offered;
    char *reason; size_t reason_capacity;
    uint32_t count, max_count;
};
static int parse_encrypted_extensions(struct tls13 *t, const struct tls13_offered *offered, const unsigned char *data, size_t length) {
    if (length < 2) return TLS13_EBADREC;
    size_t total = ((size_t)data[0] << 8) | data[1], offset = 2, count = 0;
    uint16_t seen[TLS13_SH_EXTENSIONS_MAX]; char alpn[sizeof(t->alpn)] = {0};
    if (total != length - 2) return TLS13_EBADREC;
    while (offset < length) {
        if (length - offset < 4 || count == TLS13_SH_EXTENSIONS_MAX) return TLS13_EBADREC;
        uint16_t type = (uint16_t)((unsigned)data[offset] << 8 | data[offset + 1]);
        size_t n = ((size_t)data[offset + 2] << 8) | data[offset + 3]; offset += 4;
        if (n > length - offset) return TLS13_EBADREC;
        for (size_t i = 0; i < count; i++) if (seen[i] == type) return TLS13_EBADREC;
        seen[count++] = type;
        if (type == 16) {
            if (n < 4 || (((size_t)data[offset] << 8) | data[offset + 1]) != n - 2)
                return TLS13_EBADREC;
            size_t protocol = data[offset + 2];
            if (!protocol || protocol >= sizeof(alpn) || protocol != n - 3 ||
                !offer_has_alpn(offered, data + offset + 3, protocol) ||
                memchr(data + offset + 3, 0, protocol)) return TLS13_EBADREC;
            memcpy(alpn, data + offset + 3, protocol);
        }
        offset += n;
    }
    memcpy(t->alpn, alpn, sizeof(alpn)); return 0;
}
static int consume_handshake_messages(struct hs_secrets *sec, struct tls13 *t,
    struct hs_messages *messages, const struct tls13_auth *auth,
    const unsigned char *rec, size_t pt) {
    const char *host = auth ? auth->host : NULL;
    const unsigned char *rkey = auth ? auth->reality_key : NULL;
    const int want_cert = host != NULL || rkey != NULL;
    size_t H = t->hash_n;
    enum sc_hash md = H == 48 ? SC_SHA384 : SC_SHA256;
    /* Приклеиваем к тому, что осталось от предыдущих записей. */
    if (!pt || messages->finished) return TLS13_EBADREC;
    if (messages->have > messages->capacity || pt > messages->capacity - messages->have) return TLS13_ETOOBIG;
    memcpy(messages->buffer + messages->have, rec, pt);
    messages->have += pt;

    /* В буфере может лежать несколько сообщений, а последнее — не целиком. */
    size_t p = 0;
    while (p + 4 <= messages->have) {
        unsigned char msg = messages->buffer[p];
        size_t mlen = ((size_t)messages->buffer[p + 1] << 16) | ((size_t)messages->buffer[p + 2] << 8) | messages->buffer[p + 3];
        if (messages->capacity < 4 || mlen > messages->capacity - 4) return TLS13_ETOOBIG;
        if (p + 4 + mlen > messages->have) break;  /* остаток придёт следующей записью */
        if (messages->max_count && ++messages->count > messages->max_count) return TLS13_ETOOBIG;
        switch (msg) {
            case 8:
                if (messages->phase != HS_EXPECT_EE) return TLS13_EBADREC;
                { int rc = parse_encrypted_extensions(t, messages->offered, messages->buffer + p + 4, mlen);
                  if (rc) return rc; }
                messages->phase = HS_EXPECT_CERT;
                break;
            case 11:
                if (messages->phase != HS_EXPECT_CERT || mlen < 4) return TLS13_EBADREC;
                messages->phase = HS_EXPECT_CV;
                break;
            case 15:
                if (messages->phase != HS_EXPECT_CV || mlen < 5 ||
                    (((size_t)messages->buffer[p + 6] << 8) | messages->buffer[p + 7]) != mlen - 4)
                    return TLS13_EBADREC;
                /* Pinned REALITY mandates Ed25519 independently of the mimicked
                 * browser offer (upstream 4bb46b2afd8b, hs.sigAlg = Ed25519).
                 * This selects the authenticated profile, not an auth bypass:
                 * cert_reality_check + cert_reality_verify still require its
                 * HMAC-authenticated public key and actual exact0807 proof. */
                unsigned signature = (unsigned)offer_u16(messages->buffer + p + 4);
                if (!(rkey && signature == 0x0807) &&
                    !offer_has_u16(messages->offered->signatures, messages->offered->signatures_n, signature)) {
                    snprintf(messages->reason, messages->reason_capacity, "%s", cert_verify_strerror(CERTV_EALG));
                    return TLS13_ECERT;
                }
                messages->phase = HS_EXPECT_FINISHED;
                break;
            case 20:
                if (messages->phase == HS_EXPECT_EE || messages->phase == HS_FINISHED ||
                    p + 4 + mlen != messages->have) return TLS13_EBADREC;
                break;
            case 25:
                if (messages->phase != HS_EXPECT_CERT || !want_cert) return TLS13_EBADREC;
                break;
            default: return TLS13_EBADREC;
        }
        if (want_cert && msg == 0x19) {     /* CompressedCertificate (RFC 8879) */
            /* Смысл у этого сообщения разный, и сказать надо разное.
             *
             * У security=tls расширение compress_certificate не посылается вовсе (см.
             * reality.c), поэтому сжатый сертификат означает сервер, который сжал без
             * спроса — так и говорим.
             *
             * У Reality расширение посылается: облик Chrome без него неполон. Но сервер
             * Reality, ПРИЗНАВШИЙ клиента, отвечает своим временным сертификатом и не
             * сжимает его. Сжатый — значит отвечает не он, а маскировочный сайт, куда
             * нас передали; это ровно «не признал ключ», и незачем пугать человека
             * словом про сжатие, к которому он не имеет отношения. */
            snprintf(messages->reason, messages->reason_capacity, "%s",
                     rkey ? cert_verify_strerror(CERTV_ENOTREALITY)
                          : "сервер сжал сертификат, о чём его не просили");
            return TLS13_ECERT;
        }
        if (want_cert && msg == 0x0B && messages->certificate_n == 0) {   /* Certificate */
            if (mlen > messages->certificate_capacity) return TLS13_ETOOBIG;
            memcpy(messages->certificate, messages->buffer + p + 4, mlen);
            messages->certificate_n = mlen;
        }
        if (want_cert && msg == 0x0F && messages->verify_n == 0) {     /* CertificateVerify */
            /* Хеш снимается ЗДЕСЬ, до tr_add этого же сообщения: сервер подписывал
             * транскрипт по Certificate включительно, и ни байтом больше. Снять его
             * позже нельзя — транскрипт необратим. */
            if (mlen > sizeof(messages->verify)) return TLS13_ETOOBIG;
            if (tr_hash(t, messages->transcript)) return TLS13_ECRYPTO;
            messages->transcript_n = H;
            memcpy(messages->verify, messages->buffer + p + 4, mlen);
            messages->verify_n = mlen;
        }
        if (msg == 0x14) {                  /* Finished */
            /* Проверяем ДО добавления в транскрипт: сервер считал его от хеша
             * предыдущих сообщений. */
            unsigned char hash[48], want[48];
            if (tr_hash(t, hash)) return TLS13_ECRYPTO;
            if (expand_label(md, sec->s_hs, H, "finished", NULL, 0, sec->fkey, H) != 0)
                return TLS13_ECRYPTO;
            if (sc_hmac(md, sec->fkey, H, hash, H, want) != 0) return TLS13_ECRYPTO;
            if (mlen != H || memcmp(messages->buffer + p + 4, want, H) != 0) return TLS13_EFINISHED;
            if (messages->phase != HS_EXPECT_FINISHED) {
                snprintf(messages->reason, messages->reason_capacity, "сервер не прислал %s",
                         messages->phase == HS_EXPECT_CERT ? "сертификат" : "подпись");
                return want_cert ? TLS13_ECERT : TLS13_EBADREC;
            }
            memcpy(messages->server_finished, want, H);
            messages->phase = HS_FINISHED;
            messages->finished = 1;
        }
        if (tr_add(t, messages->buffer + p, 4 + mlen)) return TLS13_ECRYPTO;
        p += 4 + mlen;
    }
    /* Разобранное выбрасываем, недоразобранное сдвигаем к началу. */
    if (p) {
        if (messages->have > p) memmove(messages->buffer, messages->buffer + p, messages->have - p);
        messages->have -= p;
    }
    return 0;
}

/* Socket-free final-flight construction. The transcript still ends with the
 * verified server Finished; no application-key ownership is transferred here. */
static int encode_client_finished(struct hs_secrets *sec, struct tls13 *t,
                                  unsigned char *out, size_t capacity, size_t *length) {
    size_t H = t->hash_n; enum sc_hash md = H == 48 ? SC_SHA384 : SC_SHA256;
    unsigned char hash[48], finished[48];
    *length = 0;
    if ((H != 32 && H != 48) || capacity < H + 32) return TLS13_ETOOBIG;
    int rc = TLS13_ECRYPTO;
    if (tr_hash(t, hash)) goto done;
    if (expand_label(md, sec->c_hs, H, "finished", NULL, 0, sec->cfkey, H) != 0 ||
        sc_hmac(md, sec->cfkey, H, hash, H, finished) != 0) goto done;
    static const unsigned char ccs[6] = {0x14,3,3,0,1,1};
    memcpy(out, ccs, sizeof(ccs)); unsigned char *record = out + sizeof(ccs);
    size_t plaintext = 4 + H + 1, total = plaintext + 16;
    record[0] = 0x17; record[1] = 3; record[2] = 3;
    record[3] = (unsigned char)(total >> 8); record[4] = (unsigned char)total;
    record[5] = 20; record[6] = 0; record[7] = 0; record[8] = (unsigned char)H;
    memcpy(record + 9, finished, H); record[9 + H] = 22;
    rc = aead_seal_once(&sec->c_hk, 0, record, 5, record + 5, plaintext, record + 5 + plaintext);
    if (rc) { steer_wipe(out, H + 32); rc = TLS13_ECRYPTO; }
    else *length = H + 32;
done:
    steer_wipe(hash, sizeof(hash)); steer_wipe(finished, sizeof(finished)); return rc;
}

/* Exclusive borrowed TLS ownership remains unchanged. This destroys transcript
 * contexts only after all derived material has been obtained, then activates
 * the ABI-preserving post-handshake overlay. READY publication is caller-owned. */
static int install_application_keys(struct hs_secrets *sec, struct tls13 *t,
                                     const struct hs_negotiated *negotiated) {
    enum sc_hash md = negotiated->md; size_t H = negotiated->hash_n;
    const unsigned char *empty_hash = negotiated->empty_hash;
    unsigned char zeros[48] = {0}, th2[48];
    /* Ключи трафика приложения — от master secret и полного транскрипта. */
    if (expand_label(md, sec->hs_secret, H, "derived", empty_hash, H, sec->derived, H) != 0)
        return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, sec->derived, H, zeros, H, sec->master) != 0) return TLS13_ECRYPTO;
    if (tr_hash(t, th2)) return TLS13_ECRYPTO;
    if (derive_secret(md, sec->master, "c ap traffic", th2, H, sec->c_ap) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, sec->master, "s ap traffic", th2, H, sec->s_ap) != 0) return TLS13_ECRYPTO;

    if (expand_label(md, sec->c_ap, H, "key", NULL, 0, t->wr.key, t->wr.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->c_ap, H, "iv", NULL, 0, t->wr.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->s_ap, H, "key", NULL, 0, t->rd.key, t->rd.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, sec->s_ap, H, "iv", NULL, 0, t->rd.iv, 12) != 0) return TLS13_ECRYPTO;
    /* Keep directional secrets for post-handshake KeyUpdate; old generations
     * are erased on rotation, all secrets on close/failure. */
    if (tls13_keys_setup(&t->wr) != 0 || tls13_keys_setup(&t->rd) != 0) return TLS13_ECRYPTO;
    post_init(t, sec->c_ap, sec->s_ap);
    t->wr_seq = t->rd_seq = 0;
    return 0;
}

static int handshake_run(struct hs_secrets *sec, struct tls13 *t, int fd,
                     const unsigned char *client_hello, size_t hello_n,
                     const unsigned char *our_priv,
                     const struct tls13_auth *auth) {
    const char *host = auth ? auth->host : NULL;
    const unsigned char *rkey = auth ? auth->reality_key : NULL;
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    struct tls13_offered offered;
    if (!client_hello || hello_n < 5 || client_hello[0] != 22 ||
        offer_u16(client_hello + 3) != hello_n - 5) return TLS13_EBADREC;
    const unsigned char *offer_hello = auth && auth->ech ? auth->ech->inner : client_hello + 5;
    size_t offer_n = auth && auth->ech ? auth->ech->inner_n : hello_n - 5;
    int offer_rc = parse_client_offer(offer_hello, offer_n, &offered);
    if (offer_rc) return offer_rc;

    if (tr_init(t)) return TLS13_ECRYPTO;
    /* В транскрипт идёт handshake-сообщение без заголовка записи. */
    if (tr_add(t, client_hello + 5, hello_n - 5)) return TLS13_ECRYPTO;

    unsigned char rec[TLS13_MAX_REC];
    unsigned char type;
    size_t n;

    /* ServerHello. */
    int rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
    if (rc) return rc;
    if (type != 0x16 || n < 44 || rec[0] != 0x02) return TLS13_EBADREC;
    if (tr_add(t, rec, n)) return TLS13_ECRYPTO;

    struct hs_negotiated negotiated = {0};
    rc = negotiate_server_hello(sec, t, rec, n, our_priv, auth, &offered, &negotiated);
    if (rc) return rc;
    const unsigned char *sh_copy = negotiated.server_hello;
    size_t sh_copy_n = negotiated.server_hello_n;

    /* Дальше сервер шлёт зашифрованные сообщения. Читаем до Finished, попутно добавляя
     * их в транскрипт: Certificate и CertificateVerify нам не нужны по содержанию, но
     * нужны в хеше — иначе Finished не сойдётся. */
    uint64_t s_seq = 0;

    /* Сообщения рукопожатия собираются ЧЕРЕЗ ГРАНИЦЫ ЗАПИСЕЙ.
     *
     * Это не запас на будущее, а починка. Прежний разбор искал сообщения внутри одной
     * записи, и сообщение, продолжающееся в следующей, терялось молча: транскрипт расходился
     * с серверным, наш Finished не сходился, и сервер закрывал соединение. Снаружи это
     * выглядело как «узел перестал признавать клиент» — при верном аутентификаторе, что и
     * сбивало с толку сильнее всего.
     *
     * Наступает это на длинных цепочках сертификатов. Найдено на своём Reality-сервере
     * (sing-box с trace): маскировочный сайт отдавал Certificate в 8273 байта, и в трассировке
     * сервера было видно, что он признал нас — расшифровал версию, время и shortId, — а
     * рукопожатие всё равно не завершилось.
     *
     * Буфер один на поток: рукопожатия внутри потока идут по одному, а держать по 40 КБ на
     * каждое соединение значило бы 2,5 МБ там, где нужно 40 КБ. */
    static __thread unsigned char hsbuf[40960];

    /* Сообщения, нужные проверке подлинности. Копируются, а не запоминаются указателем:
     * hsbuf сдвигается по мере разбора, и к моменту проверки на прежнем месте лежало бы
     * начало следующего сообщения. Цепочка бывает и восьмикилобайтной (см. выше про
     * маскировочный сайт с Certificate в 8273 байта), поэтому буфер тех же размеров, что и
     * hsbuf, но выделяется ТОЛЬКО когда проверка включена: у Reality он был бы 40 КБ на
     * поток, которые никто не читает. */
    static __thread unsigned char certbuf[40960];
    struct hs_messages messages = {0};
    messages.offered = &offered;
    messages.buffer = hsbuf; messages.capacity = sizeof(hsbuf);
    messages.certificate = certbuf; messages.certificate_capacity = sizeof(certbuf);
    messages.reason = g_verify_reason; messages.reason_capacity = sizeof(g_verify_reason);
    g_verify_reason[0] = '\0';

    /* Проходов больше шестнадцати: одна запись — не одно сообщение, и длинная цепочка
     * сертификатов приезжает несколькими записями. */
    for (int guard = 0; guard < 64 && !messages.finished; guard++) {
        rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
        if (rc) return rc;
        if (type == 0x14) {
            if (messages.have || n != 1 || rec[0] != 1) return TLS13_EBADREC;
            continue;
        }
        if (type != 0x17) return TLS13_EBADREC;

        unsigned char aad[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char)(n >> 8), (unsigned char)n };
        rc = aead_open_once(&sec->s_hk, s_seq++, aad, 5, rec, n);
        if (rc) return rc;
        size_t pt = n - 16;
        /* Последний непустой байт — настоящий тип записи (RFC 8446 §5.4). */
        while (pt > 0 && rec[pt - 1] == 0) pt--;
        if (pt == 0) return TLS13_EBADREC;
        unsigned char inner = rec[--pt];
        if (inner != 0x16) return TLS13_EBADREC;

        rc = consume_handshake_messages(sec, t, &messages, auth, rec, pt);
        if (rc) return rc;
    }
    if (!messages.finished) return TLS13_EFINISHED;

    /* Проверка подлинности — ПОСЛЕ серверного Finished и ДО нашего.
     *
     * После: Finished доказывает, что транскрипт у нас с сервером один, а значит и та его
     * часть, которую подписал CertificateVerify, не подменена по дороге. Проверять подпись
     * над транскриптом, в котором мы ещё не уверены, значит проверять не то.
     *
     * До: свой Finished — это первое, что уходит на сервер под ключами сессии, и отправлять
     * его тому, кто подлинности не доказал, незачем. */
    /* Reality: доказательством служит поле подписи временного сертификата, и цепочка тут ни
     * при чём. Проверка стоит ДО ветки security=tls, а не вместо неё: настроек, где заданы
     * оба доказательства, не бывает, но порядок в коде должен быть определён однозначно. */
    if (rkey) {
        if (!messages.certificate_n) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "сервер не прислал сертификат");
            return TLS13_ECERT;
        }
        int rrc = cert_reality_check(messages.certificate, messages.certificate_n, rkey);
        if (rrc == 0 && auth->mldsa_pk)
            rrc = cert_reality_check_pq(messages.certificate, messages.certificate_n, rkey, auth->mldsa_pk,
                                        client_hello + 5, hello_n - 5, sh_copy, sh_copy_n);
        if (rrc == 0 && !messages.verify_n) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "сервер не прислал подпись");
            return TLS13_ECERT;
        }
        if (rrc == 0) rrc = cert_reality_verify(messages.certificate, messages.certificate_n,
            messages.verify, messages.verify_n, messages.transcript, messages.transcript_n);
        if (rrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s", cert_verify_strerror(rrc));
            return TLS13_ECERT;
        }
    }

    if (host) {
        if (!messages.certificate_n || !messages.verify_n) {
            /* Рукопожатие сошлось, а доказательства не было. Так отвечает сервер, который
             * ждал сертификат ОТ НАС (client auth) или возобновил сессию — ни того, ни
             * другого мы не умеем и не просили. Причина названа отдельно: «сертификата не
             * прислали» и «сертификат не сошёлся» — не одно и то же. */
            snprintf(g_verify_reason, sizeof(g_verify_reason),
                     "сервер не прислал %s", messages.certificate_n ? "подпись" : "сертификат");
            return TLS13_ECERT;
        }
        int vrc = cert_verify_server_ex(messages.certificate, messages.certificate_n, messages.verify, messages.verify_n,
                                        messages.transcript, messages.transcript_n, host, auth->roots, auth->policy);
        if (vrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s",
                     cert_verify_strerror(vrc));
            return TLS13_ECERT;
        }
    }

    /* Preserve the single CCS+Finished flight and the legacy write-before-key
     * publication order. Incremental callers can retain the same encoded flight
     * across arbitrary lower-write backpressure without re-encryption. */
    unsigned char final_flight[80]; size_t final_length = 0;
    rc = encode_client_finished(sec, t, final_flight, sizeof(final_flight), &final_length);
    if (rc) return rc;
    rc = write_all_fd(fd, final_flight, final_length);
    steer_wipe(final_flight, sizeof(final_flight));
    if (rc) return rc;
    rc = install_application_keys(sec, t, &negotiated);
    if (rc) return rc;
    t->ready = 1;
    return 0;
}


/* Обёртка: все выходы handshake_run проходят здесь, поэтому стирание одно. На ошибке стираются и ключи
 * трафика в t (могли быть выведены до отказа): вызывающий вызовет tls13_free, но ключи в массивах он
 * не обнуляет за рамками нашей зачистки, а рукопожатие, не доведённое до ready, их не использует. */
static int handshake(struct tls13 *t, int fd,
                     const unsigned char *client_hello, size_t hello_n,
                     const unsigned char *our_priv,
                     const struct tls13_auth *auth) {
    struct hs_secrets sec;
    memset(&sec, 0, sizeof(sec));
    int rc = handshake_run(&sec, t, fd, client_hello, hello_n, our_priv, auth);
    steer_wipe(&sec, sizeof(sec));
    if (rc != 0) {
        tls13_free(t);
    }
    return rc;
}

int tls13_handshake(struct tls13 *t, int fd,
                    const unsigned char *client_hello, size_t hello_n,
                    const unsigned char *our_priv) {
    return handshake(t, fd, client_hello, hello_n, our_priv, NULL);
}

int tls13_handshake_auth(struct tls13 *t, int fd,
                         const unsigned char *client_hello, size_t hello_n,
                         const unsigned char *our_priv,
                         const struct tls13_auth *auth) {
    /* Пустое имя при заданной проверке по сертификату — это НЕ «проверять нечем», это ошибка
     * вызывающего: проверка без имени пропустила бы любой действительный сертификат на
     * свете, то есть выглядела бы работой, ничего не проверяя. */
    if (auth && auth->host && !auth->host[0]) return TLS13_ECERT;
    return handshake(t, fd, client_hello, hello_n, our_priv, auth);
}

int tls13_has_record(const struct tls13 *t) {
    size_t have = t->rbuf_n - t->rbuf_off;
    if (have < 5) return 0;
    const unsigned char *h = t->rbuf + t->rbuf_off;
    size_t len = ((size_t)h[3] << 8) | h[4];
    return have >= 5 + len;
}

size_t tls13_buffered(const struct tls13 *t) {
    return t->rbuf_n - t->rbuf_off;
}

size_t tls13_take_pending(struct tls13 *t, unsigned char *out, size_t cap) {
    size_t have = t->rbuf_n - t->rbuf_off;
    if (!have) return 0;
    if (have > cap) have = cap;
    memcpy(out, t->rbuf + t->rbuf_off, have);
    t->rbuf_off += have;
    return have;
}

/* Incremental companion storage is private; struct tls13 and its published
 * offsets remain unchanged. Handshake workspace is independently admitted and
 * returned to the owner only after all derived secrets have been erased. */
struct engine_handshake {
    struct hs_secrets secrets;
    struct hs_negotiated negotiated;
    struct hs_messages messages;
    struct tls13_offered offered;
    struct tls13_engine_limits limits;
    uint64_t read_sequence;
    uint32_t records;
    unsigned char private_key[32];
    char reason[192];
};
struct tls13_engine {
    struct tls13 *tls;
    struct engine_handshake *handshake;
    void *workspace;
    size_t workspace_length;
    enum tls13_engine_state state;
    int error,finish_requested;
    unsigned char output[TLS13_MAX_REC + 5], header[5];
    size_t output_length, output_offset, header_length, record_length, record_have;
    size_t plaintext_length, plaintext_offset;
};
size_t tls13_engine_storage_size(void) { return sizeof(struct tls13_engine); }
int tls13_engine_workspace_size(const struct tls13_engine_options *o, size_t *length) {
    if (!length) return TLS13_ESTATE;
    *length = 0;
    if (!o || !o->client_hello || !o->x25519_private || o->client_hello_length < 48 ||
        o->client_hello_length > TLS13_MAX_REC + 5 ||
        !o->limits.max_records || o->limits.max_records > 64 ||
        !o->limits.max_messages || o->limits.max_messages > 64 ||
        o->limits.max_handshake_message < 4 || o->limits.max_handshake_message > 40960 ||
        o->limits.max_certificate < 4 || o->limits.max_certificate > 40960)
        return TLS13_ESTATE;
    /* Every summand has a small explicit maximum, including on ILP32. */
    *length = sizeof(struct engine_handshake) + o->client_hello_length +
              o->limits.max_handshake_message + o->limits.max_certificate;
    return 0;
}
static int engine_overlaps(const void *a, size_t an, const void *b, size_t bn) {
    uintptr_t av = (uintptr_t)a, bv = (uintptr_t)b;
    if (an > UINTPTR_MAX - av || bn > UINTPTR_MAX - bv) return 1;
    return av < bv + bn && bv < av + an;
}
static void engine_release_workspace(struct tls13_engine *e) {
    if (e->workspace) steer_wipe(e->workspace, e->workspace_length);
    e->workspace = NULL; e->workspace_length = 0; e->handshake = NULL;
}
static int engine_failure(struct tls13_engine *e, int error) {
    tls13_free(e->tls);
    steer_wipe(e->tls->rbuf, sizeof(e->tls->rbuf));
    steer_wipe(e->output, sizeof(e->output));
    engine_release_workspace(e);
    e->output_length = e->output_offset = e->plaintext_length = e->plaintext_offset = 0;
    e->state = TLS13_ENGINE_FAILED; e->error = error;
    return error;
}
int tls13_engine_init(void *storage, size_t storage_length, struct tls13 *tls,
                      void *workspace, size_t workspace_length,
                      const struct tls13_engine_options *options, struct tls13_engine **out) {
    if (!out) return TLS13_ESTATE;
    *out = NULL; size_t needed = 0;
    int rc = tls13_engine_workspace_size(options, &needed);
    if (rc) return rc;
    if (!storage || !tls || !workspace || storage_length < sizeof(struct tls13_engine) ||
        workspace_length < needed || (uintptr_t)storage % _Alignof(struct tls13_engine) ||
        (uintptr_t)workspace % _Alignof(struct engine_handshake) ||
        engine_overlaps(storage, sizeof(struct tls13_engine), workspace, needed) ||
        engine_overlaps(storage, sizeof(struct tls13_engine), tls, sizeof(*tls)) ||
        engine_overlaps(workspace, needed, tls, sizeof(*tls)) ||
        engine_overlaps(storage, sizeof(struct tls13_engine), options->client_hello, options->client_hello_length) ||
        engine_overlaps(workspace, needed, options->client_hello, options->client_hello_length) ||
        engine_overlaps(tls, sizeof(*tls), options->client_hello, options->client_hello_length) ||
        engine_overlaps(storage, sizeof(struct tls13_engine), options->x25519_private, 32) ||
        engine_overlaps(workspace, needed, options->x25519_private, 32) ||
        engine_overlaps(tls, sizeof(*tls), options->x25519_private, 32)) return TLS13_ESTATE;
    struct tls13_engine_options o = *options;
    if (o.client_hello[0] != 22 || offer_u16(o.client_hello + 3) != o.client_hello_length - 5)
        return TLS13_EBADREC;
    struct tls13_offered offered;
    rc = parse_client_offer(o.client_hello + 5, o.client_hello_length - 5, &offered);
    if (rc) return rc;
    /* This first capability is explicitly X25519. A prepared profile must not
     * offer another real group whose private state this engine does not own. */
    int x25519 = 0;
    for (size_t at = 0; at < offered.shares_n; at += 4 + offer_u16(offered.shares + at + 2)) {
        unsigned group = (unsigned)offer_u16(offered.shares + at);
        if (group == 29) {
            static const unsigned char basepoint[32] = {9};
            unsigned char public_key[32];
            if (offer_u16(offered.shares + at + 2) != 32 ||
                x25519_shared_ext(o.x25519_private, basepoint, public_key) ||
                memcmp(public_key, offered.shares + at + 4, 32)) return TLS13_ESTATE;
            x25519 = 1;
        } else if ((group >> 8) != (group & 255) || (group & 0x0f0f) != 0x0a0a)
            return TLS13_ENOKEYSHARE;
    }
    if (!x25519) return TLS13_ENOKEYSHARE;
    struct tls13_engine *e = storage;
    memset(e, 0, sizeof(*e)); memset(workspace, 0, needed); memset(tls, 0, sizeof(*tls));
    e->tls = tls; tls->fd = -1;
    e->workspace = workspace; e->workspace_length = needed; e->handshake = workspace;
    struct engine_handshake *h = e->handshake;
    h->limits = o.limits; memcpy(h->private_key, o.x25519_private, 32);
    unsigned char *hello = (unsigned char *)(h + 1);
    memcpy(hello, o.client_hello, o.client_hello_length);
    rc = parse_client_offer(hello + 5, o.client_hello_length - 5, &h->offered);
    if (rc) { engine_failure(e, rc); return rc; }
    h->messages.offered = &h->offered;
    h->messages.buffer = hello + o.client_hello_length;
    h->messages.capacity = o.limits.max_handshake_message;
    h->messages.certificate = h->messages.buffer + h->messages.capacity;
    h->messages.certificate_capacity = o.limits.max_certificate;
    h->messages.reason = h->reason; h->messages.reason_capacity = sizeof(h->reason);
    h->messages.max_count = o.limits.max_messages;
    if (tr_init(tls) || tr_add(tls, hello + 5, o.client_hello_length - 5))
        return engine_failure(e, TLS13_ECRYPTO);
    memcpy(e->output, hello, o.client_hello_length); e->output_length = o.client_hello_length;
    e->state = TLS13_ENGINE_HANDSHAKE; *out = e; return 0;
}
enum tls13_engine_state tls13_engine_state(const struct tls13_engine *e) { return e->state; }
int tls13_engine_error(const struct tls13_engine *e) { return e->error; }
int tls13_engine_workspace_in_use(const struct tls13_engine *e) { return e && e->workspace != NULL; }

/* ---- обмен данными --------------------------------------------------------- */
static int tls12_write(struct tls13 *t, const unsigned char *data, size_t n);

static int traffic_update(struct tls13 *t, int writing) {
    struct tls13_keys *keys = writing ? &t->wr : &t->rd;
    unsigned char *secret = writing ? t->post.app_wr_secret : t->post.app_rd_secret;
    unsigned char next[48] = {0}, key[32] = {0}, iv[12] = {0};
    enum sc_hash hash = t->hash_n == 48 ? SC_SHA384 : SC_SHA256;
    int result = TLS13_ECRYPTO;
    if (!post_active(t) || (t->hash_n != 32 && t->hash_n != 48) || (keys->key_n != 16 && keys->key_n != 32)) return TLS13_ESTATE;
    if (expand_label(hash, secret, t->hash_n, "traffic upd", NULL, 0, next, t->hash_n) ||
        expand_label(hash, next, t->hash_n, "key", NULL, 0, key, keys->key_n) ||
        expand_label(hash, next, t->hash_n, "iv", NULL, 0, iv, sizeof(iv))) goto done;
    /* Never copy an initialized AEAD context. Derive first, then rebuild this
     * direction in place; a setup failure is terminal. */
    tls13_keys_free(keys);
    steer_wipe(secret, 48); memcpy(secret, next, t->hash_n);
    steer_wipe(keys->key, sizeof(keys->key)); memcpy(keys->key, key, keys->key_n);
    memcpy(keys->iv, iv, sizeof(iv));
    if (tls13_keys_setup(keys)) goto done;
    if (writing) t->wr_seq = 0; else t->rd_seq = 0;
    result = 0;
done:
    steer_wipe(next, sizeof(next)); steer_wipe(key, sizeof(key)); steer_wipe(iv, sizeof(iv));
    return result;
}
static int post_failure(struct tls13 *t, int error) {
    tls13_free(t); t->post.phase = TLS13_POST_PHASE; t->post.error = error; return error;
}
#ifdef STEER_TLS13_TEST
/* Test-only entry into the post-Finished phase; never exported by production. */
void tls13_test_post_init(struct tls13 *t, const unsigned char *client, const unsigned char *server) {
    post_init(t, client, server);
}
int tls13_test_traffic_update(struct tls13 *t, int writing) { return traffic_update(t, writing); }
#endif
/* Encodes one complete immutable application-epoch record, no IO/queues. */
static int encode_cipher_record(struct tls13 *t, unsigned char type,
                                 const unsigned char *data, size_t n,
                                 unsigned char *record, size_t capacity, size_t *length) {
    *length = 0;
    if (n > TLS13_MAX_PLAIN || capacity < n + 22) return TLS13_ETOOBIG;
    if (t->wr_seq == UINT64_MAX) return post_failure(t, TLS13_ESTATE);
    record[0] = 23; record[1] = 3; record[2] = 3;
    size_t total = n + 17; record[3] = (unsigned char)(total >> 8); record[4] = (unsigned char)total;
    if (n) memcpy(record + 5, data, n);
    record[5 + n] = type;
    if (tls13_aead_seal(&t->wr, t->wr_seq, record, 5, record + 5, n + 1, record + 6 + n))
        return post_failure(t, TLS13_ECRYPTO);
    t->wr_seq++; *length = n + 22; return 0;
}
static int encode_key_update_reply(struct tls13 *t, unsigned char *record,
                                    size_t capacity, size_t *length) {
    *length = 0;
    if (!post_active(t) || !t->post.key_update_pending) return 0;
    if (t->post.write_closed) { t->post.key_update_pending = 0; return 0; }
    static const unsigned char update[5] = {24,0,0,1,0};
    int rc = encode_cipher_record(t, 22, update, sizeof(update), record, capacity, length);
    if (rc) return rc;
    /* Caller now owns the ENTIRE old-key ciphertext. No later record may be
     * queued before these bytes; only subsequent records use the new key. */
    if (traffic_update(t, 1)) return post_failure(t, TLS13_ECRYPTO);
    t->post.key_update_pending = 0; return 0;
}
static int encode_close_notify(struct tls13 *t, unsigned char *record,
                                size_t capacity, size_t *length) {
    *length = 0;
    if (t->post.write_closed) return 0;
    static const unsigned char alert[2] = {1,0};
    int rc = encode_cipher_record(t, 21, alert, sizeof(alert), record, capacity, length);
    if (!rc) t->post.write_closed = 1;
    return rc;
}
static int key_update_reply(struct tls13 *t) {
    unsigned char record[27]; size_t length = 0;
    int rc = encode_key_update_reply(t, record, sizeof(record), &length);
    if (rc) return rc;
    if (length && outq_send(t->fd, &t->oq, record, length)) return post_failure(t, TLS13_EIO);
    return 0;
}
int tls13_flush(struct tls13 *t) {
    int rc;
    if (post_active(t) && t->post.error) return t->post.error;
    rc = outq_flush(t->fd, &t->oq);
    if (rc) return rc < 0 ? post_failure(t, TLS13_EIO) : rc;
    if (post_active(t) && t->post.key_update_pending) {
        rc = key_update_reply(t);
        if (rc) return rc;
        rc = outq_flush(t->fd, &t->oq);
        if (rc < 0) return post_failure(t, TLS13_EIO);
    }
    return rc;
}
int tls13_shutdown_write(struct tls13 *t) {
    if(t->v12 || !post_active(t))return 2;
    if(t->post.error)return t->post.error;
    if(!t->ready)return TLS13_ESTATE;
    if(t->post.write_closed==2)return 0;
    if(!t->post.write_closed) {
        int rc=key_update_reply(t);if(rc)return rc;
        unsigned char record[24]; size_t length = 0;
        rc = encode_close_notify(t, record, sizeof(record), &length); if (rc) return rc;
        if(outq_send(t->fd,&t->oq,record,length))return post_failure(t,TLS13_EIO);
    }
    int rc=tls13_flush(t);if(rc)return rc;
    do {rc=shutdown(t->fd,SHUT_WR);} while(rc<0 && errno==EINTR);
    if(rc<0)return post_failure(t,TLS13_EIO);
    t->post.write_closed=2;return 0;
}
static int parse_post_handshake(struct tls13 *t, const unsigned char *data, size_t length) {
    size_t offset = 0;
    if (!post_active(t)) return post_failure(t, TLS13_ESTATE);
    if (!length) return post_failure(t, TLS13_EBADREC);
    while (offset < length) {
        if (!t->post.left) {
            while (t->post.header_n < 4 && offset < length) t->post.header[t->post.header_n++] = data[offset++];
            if (t->post.header_n < 4) break;
            t->post.type = t->post.header[0];
            t->post.left = ((uint32_t)t->post.header[1] << 16) | ((uint32_t)t->post.header[2] << 8) | t->post.header[3];
            t->post.header_n = 0;
            if ((t->post.type == 24 && t->post.left != 1) ||
                (t->post.type == 4 && (t->post.left < 14 || t->post.left > 131338u)) ||
                (t->post.type != 4 && t->post.type != 24)) return post_failure(t, TLS13_EBADREC);
        }
        if (t->post.type == 24 && offset < length) {
            unsigned request = data[offset++];
            /* Key changes must end at a record boundary, including when its
             * header/body was fragmented across preceding Handshake records. */
            if (request > 1 || offset != length) return post_failure(t, TLS13_EBADREC);
            t->post.left = 0;
            if (traffic_update(t, 0)) return post_failure(t, TLS13_ECRYPTO);
            if (request && !t->post.write_closed) t->post.key_update_pending = 1;
        } else {
            size_t take = length - offset;
            if (take > t->post.left) take = t->post.left;
            offset += take; t->post.left -= (uint32_t)take;
        }
    }
    return 0;
}
static int post_handshake(struct tls13 *t, const unsigned char *data, size_t length) {
    int rc = parse_post_handshake(t, data, length);
    if (rc) return rc;
    /* Legacy IO adapter only. The pure parser never writes or allocates. */
    if (t->post.key_update_pending && !outq_pending(&t->oq)) return key_update_reply(t);
    return 0;
}

int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) {
    int control;
    if (post_active(t) && t->post.error) return t->post.error;
    if (!t->ready) return TLS13_ESTATE;
    if (post_active(t) && t->post.write_closed) return TLS13_ESTATE;
    if (t->v12) return tls12_write(t, data, n);
    control = key_update_reply(t);
    if (control) return control;
    if (!t->live && outq_pending(&t->oq)) {
        control = write_all_fd(t->fd, t->oq.p + t->oq.off, outq_pending(&t->oq));
        if (control) return post_failure(t, control);
        outq_free(&t->oq);
    }
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t want = 0, sent = 0;
        int rc = encode_cipher_record(t, 23, data, chunk, out, sizeof(out), &want);
        if (rc) return rc;
        if (t->live) {
            /* Живая связь: сокет не ждём (outq_send), непринятое — в очередь (I-534). */
            if (outq_send(t->fd, &t->oq, out, want) != 0) return post_failure(t, TLS13_EIO);
            data += chunk;
            n -= chunk;
            continue;
        }
        while (sent < want) {
            ssize_t w = write(t->fd, out + sent, want - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return post_failure(t, TLS13_EIO);
            }
            sent += (size_t)w;
        }
        data += chunk;
        n -= chunk;
    }
    return 0;
}

/* Прочитать РОВНО ОДНУ запись. Данных в ней может не оказаться — тогда ноль байт с
 * кодом 0, и это успех, а не отказ.
 *
 * «Ровно одну» здесь дороже, чем выглядит. Прежняя версия крутила цикл, пока не получит
 * данные, и на записи без данных немедленно бралась читать следующую. А записей без
 * данных в этом потоке хватает: ChangeCipherSpec, NewSessionTicket и пустые записи,
 * которыми пользуется Vision. Второе чтение упиралось в SO_RCVTIMEO, через восемь секунд
 * возвращало EAGAIN — и вызывающий получал ошибку ввода-вывода на полностью исправном
 * соединении.
 *
 * Наблюдалось как «выгрузка встаёт на 130–260 КБ и обрывается»: пустая запись приезжала
 * посреди передачи, соединение умирало, и место обрыва каждый раз было другим. На коротких
 * ответах не проявлялось никогда, потому что пустая запись просто не успевала прийти.
 *
 * Ждать, пока сокет станет читаемым, — дело вызывающего: у него есть poll, у нас его нет
 * и быть не должно. */
/* Общее тело обоих чтений: разобрать одну запись и оставить открытый текст ТАМ, ГДЕ ОН
 * ЛЕЖИТ — в буфере соединения. Копию делает только tls13_read, и только потому, что его
 * вызывающему нужен свой буфер. */
static int tls12_read_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          const unsigned char **body, size_t *body_n);

/* Socket-free application-epoch record consumer. Input is mutable ciphertext;
 * authenticated plaintext remains borrowed in that same caller-owned buffer. */
static int decode_cipher_record(struct tls13 *t, unsigned char type,
                                 unsigned char *rec, size_t n,
                                 const unsigned char **body, size_t *body_n, int legacy_io) {
    *body = NULL; *body_n = 0; int rc;
    if (!rec || n > TLS13_MAX_REC) return post_failure(t, TLS13_EBADREC);
    if (type == 0x14) {
        if (n != 1 || rec[0] != 1) return post_failure(t, TLS13_EBADREC);
        if (post_active(t) && (t->post.header_n || t->post.left)) return post_failure(t, TLS13_EBADREC);
        return 0; /* compatibility CCS cannot interleave a fragmented message */
    }
    if (type != 0x17 || n < 17) return post_failure(t, TLS13_EBADREC);

    unsigned char aad[5] = { 0x17, 0x03, 0x03,
                             (unsigned char)(n >> 8), (unsigned char)n };
    if (t->rd_seq == UINT64_MAX) return post_failure(t, TLS13_ESTATE);
    rc = tls13_aead_open(&t->rd, t->rd_seq++, aad, 5, rec, n);
    if (rc) return post_failure(t, rc);
    size_t pt = n - 16;
    while (pt > 0 && rec[pt - 1] == 0) pt--;
    if (pt == 0) return post_failure(t, TLS13_EBADREC);
    unsigned char inner = rec[--pt];

    if (inner == 0x16) return legacy_io ? post_handshake(t, rec, pt) : parse_post_handshake(t, rec, pt);
    if (post_active(t) && (t->post.header_n || t->post.left)) return post_failure(t, TLS13_EBADREC);
    if (inner == 0x15) {
        if(pt!=2 || (rec[0]!=1 && rec[0]!=2) || rec[1]!=0)return post_failure(t,TLS13_EBADREC);
        if(post_active(t))t->post.read_closed=1;
        return TLS13_ECLOSED;
    }
    if (inner != 0x17) return post_failure(t, TLS13_EBADREC);
    if (pt == 0) return 0;                     /* пустая запись — законная набивка Vision */

    *body = rec;
    *body_n = pt;
    return 0;
}

#ifdef STEER_TLS13_TEST
int tls13_test_decode_bounds(struct tls13 *t, unsigned char *record, size_t length) {
    const unsigned char *body; size_t body_length;
    return decode_cipher_record(t, 23, record, length, &body, &body_length, 0);
}
#endif

static int engine_emit_control(struct tls13_engine *e) {
    if (e->output_length != e->output_offset) return 0;
    e->output_length = e->output_offset = 0;
    if (e->state != TLS13_ENGINE_READY) return 0;
    size_t length = 0;
    int rc;
    if (e->finish_requested) {
        /* No later Application Data is permitted. A KU reply is therefore not
         * required before closing; a peer cannot starve accepted finish by
         * continually requesting another reply behind held ciphertext. */
        e->tls->post.key_update_pending = 0;
        rc = encode_close_notify(e->tls, e->output, sizeof(e->output), &length);
    } else rc = encode_key_update_reply(e->tls, e->output, sizeof(e->output), &length);
    if (rc) return engine_failure(e, rc);
    e->output_length = length; return 0;
}
static int engine_handshake_record(struct tls13_engine *e, unsigned char type, size_t n) {
    struct engine_handshake *h = e->handshake; struct tls13 *t = e->tls;
    unsigned char *record = t->rbuf;
    if (++h->records > h->limits.max_records) return TLS13_ETOOBIG;
    if (type == 20) {
        if (n != 1 || record[0] != 1 || h->messages.have) return TLS13_EBADREC;
        return 0;
    }
    if (!h->negotiated.hash_n) {
        if (type != 22 || !n) return TLS13_EBADREC;
        if (h->messages.have > h->messages.capacity ||
            n > h->messages.capacity - h->messages.have) return TLS13_ETOOBIG;
        memcpy(h->messages.buffer + h->messages.have, record, n); h->messages.have += n;
        if (h->messages.have < 4) return 0;
        unsigned char *hello = h->messages.buffer;
        size_t length = ((size_t)hello[1] << 16) | ((size_t)hello[2] << 8) | hello[3];
        if (length > h->messages.capacity - 4) return TLS13_ETOOBIG;
        if (h->messages.have < length + 4) return 0;
        if (h->messages.have != length + 4) return TLS13_EBADREC;
        if (tr_add(t, hello, h->messages.have)) return TLS13_ECRYPTO;
        int rc = negotiate_server_hello(&h->secrets, t, hello, h->messages.have,
                                        h->private_key, NULL, &h->offered, &h->negotiated);
        if (rc) return rc;
        h->messages.have = 0; return 0;
    }
    if (type != 23 || n < 17 || h->read_sequence == UINT64_MAX) return TLS13_EBADREC;
    int rc = aead_open_once(&h->secrets.s_hk, h->read_sequence++, e->header, 5, record, n);
    if (rc) return rc;
    size_t plaintext = n - 16;
    while (plaintext && !record[plaintext - 1]) plaintext--;
    if (!plaintext || record[--plaintext] != 22) return TLS13_EBADREC;
    if (plaintext > TLS13_MAX_PLAIN) return TLS13_ETOOBIG;
    /* Standard TLS always requires a certificate proof, even if the external
     * prepared policy deliberately omits chain verification in a lab. */
    static const struct tls13_auth standard = {.host = "engine"};
    rc = consume_handshake_messages(&h->secrets, t, &h->messages, &standard, record, plaintext);
    if (!rc && h->messages.finished) e->state = TLS13_ENGINE_AUTH_PENDING;
    return rc;
}
int tls13_engine_feed(struct tls13_engine *e, const unsigned char *data, size_t length, size_t *consumed) {
    if (!consumed) return TLS13_ESTATE;
    *consumed = 0;
    if (!e || !e->tls || (length && !data)) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->state == TLS13_ENGINE_AUTH_PENDING || e->state == TLS13_ENGINE_FINISH_DRAIN ||
        (e->state == TLS13_ENGINE_HANDSHAKE && e->output_length != e->output_offset) ||
        e->plaintext_length != e->plaintext_offset) return TLS13_EAGAIN;
    if (e->state == TLS13_ENGINE_READY && e->tls->post.read_closed) return TLS13_ESTATE;
    if (!length) return TLS13_EAGAIN;
    if (e->header_length < 5) {
        size_t take = 5 - e->header_length; if (take > length) take = length;
        memcpy(e->header + e->header_length, data, take);
        e->header_length += take; data += take; length -= take; *consumed += take;
        if (e->header_length != 5) return 0;
        e->record_length = offer_u16(e->header + 3);
        if (e->header[1] != 3 || e->header[2] != 3 || !e->record_length ||
            e->record_length > TLS13_MAX_REC) return engine_failure(e, TLS13_EBADREC);
    }
    size_t take = e->record_length - e->record_have; if (take > length) take = length;
    if (take) memcpy(e->tls->rbuf + e->record_have, data, take);
    e->record_have += take; *consumed += take;
    if (e->record_have != e->record_length) return 0;
    int rc;
    if (e->state == TLS13_ENGINE_HANDSHAKE)
        rc = engine_handshake_record(e, e->header[0], e->record_length);
    else {
        const unsigned char *body = NULL; size_t body_length = 0;
        if (e->header[0] != 23) return engine_failure(e, TLS13_EBADREC);
        rc = decode_cipher_record(e->tls, 23, e->tls->rbuf, e->record_length, &body, &body_length, 0);
        if (rc == TLS13_ECLOSED) rc = 0;
        if (!rc && body_length > TLS13_MAX_PLAIN) rc = TLS13_ETOOBIG;
        if (!rc && body_length) { e->plaintext_offset = 0; e->plaintext_length = body_length; }
    }
    if (rc) return engine_failure(e, rc);
    e->header_length = e->record_length = e->record_have = 0;
    return engine_emit_control(e);
}
int tls13_engine_output(const struct tls13_engine *e, const unsigned char **data, size_t *length) {
    if (!data || !length) return TLS13_ESTATE;
    *data = NULL; *length = 0;
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->output_length != e->output_offset) {
        *data = e->output + e->output_offset; *length = e->output_length - e->output_offset;
    }
    return 0;
}
int tls13_engine_output_consume(struct tls13_engine *e, size_t length) {
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (length > e->output_length - e->output_offset) return TLS13_ESTATE;
    e->output_offset += length;
    if (e->output_length != e->output_offset) return 0;
    steer_wipe(e->output, e->output_length); e->output_length = e->output_offset = 0;
    if (e->state == TLS13_ENGINE_FINISH_DRAIN) {
        e->tls->ready = 1; e->state = TLS13_ENGINE_READY; engine_release_workspace(e);
    }
    return engine_emit_control(e);
}
int tls13_engine_auth_snapshot(const struct tls13_engine *e, struct tls13_engine_auth *out) {
    if (!out) return TLS13_ESTATE;
    memset(out, 0, sizeof(*out));
    if (!e || e->state != TLS13_ENGINE_AUTH_PENDING || !e->handshake) return TLS13_ESTATE;
    const struct hs_messages *m = &e->handshake->messages;
    out->certificate = m->certificate; out->certificate_length = m->certificate_n;
    out->certificate_verify = m->verify; out->certificate_verify_length = m->verify_n;
    out->transcript = m->transcript; out->transcript_length = m->transcript_n;
    return 0;
}
int tls13_engine_auth_complete(struct tls13_engine *e, int verification_error) {
    if (!e || e->state != TLS13_ENGINE_AUTH_PENDING || !e->handshake) return TLS13_ESTATE;
    if (verification_error) return engine_failure(e, TLS13_ECERT);
    struct engine_handshake *h = e->handshake;
    int rc = encode_client_finished(&h->secrets, e->tls, e->output, sizeof(e->output), &e->output_length);
    if (rc) return engine_failure(e, rc);
    rc = install_application_keys(&h->secrets, e->tls, &h->negotiated);
    if (rc) return engine_failure(e, rc);
    e->output_offset = 0; e->state = TLS13_ENGINE_FINISH_DRAIN; return 0;
}
int tls13_engine_plaintext(const struct tls13_engine *e, const unsigned char **data, size_t *length) {
    if (!data || !length) return TLS13_ESTATE;
    *data = NULL; *length = 0;
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->state != TLS13_ENGINE_READY) return TLS13_EAGAIN;
    if (e->plaintext_length != e->plaintext_offset) {
        *data = e->tls->rbuf + e->plaintext_offset; *length = e->plaintext_length - e->plaintext_offset;
    }
    return 0;
}
int tls13_engine_plaintext_consume(struct tls13_engine *e, size_t length) {
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->state != TLS13_ENGINE_READY) return TLS13_ESTATE;
    if (length > e->plaintext_length - e->plaintext_offset) return TLS13_ESTATE;
    if (length) steer_wipe(e->tls->rbuf + e->plaintext_offset, length);
    e->plaintext_offset += length;
    if (e->plaintext_offset == e->plaintext_length) e->plaintext_offset = e->plaintext_length = 0;
    return 0;
}
int tls13_engine_write(struct tls13_engine *e, const unsigned char *data, size_t length, size_t *accepted) {
    if (!accepted) return TLS13_ESTATE;
    *accepted = 0;
    if (!e || !e->tls || (length && !data)) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->state != TLS13_ENGINE_READY || e->finish_requested || e->tls->post.write_closed) return TLS13_ESTATE;
    if (e->output_length != e->output_offset) return TLS13_EAGAIN;
    int rc = engine_emit_control(e); if (rc) return rc;
    if (e->output_length) return TLS13_EAGAIN;
    if (!length) return 0;
    if (length > TLS13_MAX_PLAIN) length = TLS13_MAX_PLAIN;
    rc = encode_cipher_record(e->tls, 23, data, length, e->output, sizeof(e->output), &e->output_length);
    if (rc) return engine_failure(e, rc);
    *accepted = length; return 0;
}
int tls13_engine_finish_write(struct tls13_engine *e) {
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->state != TLS13_ENGINE_READY) return TLS13_ESTATE;
    e->finish_requested = 1;
    return engine_emit_control(e);
}
int tls13_engine_local_finished(const struct tls13_engine *e) {
    return e && e->state == TLS13_ENGINE_READY && e->finish_requested &&
           e->tls->post.write_closed && e->output_length == e->output_offset;
}
int tls13_engine_peer_finished(const struct tls13_engine *e) {
    return e && e->state == TLS13_ENGINE_READY && e->tls->post.read_closed;
}
int tls13_engine_eof(struct tls13_engine *e) {
    if (!e || !e->tls) return TLS13_ESTATE;
    if (e->error) return e->error;
    if (e->plaintext_length != e->plaintext_offset) return TLS13_EAGAIN;
    if (e->header_length || e->record_have || !tls13_engine_peer_finished(e))
        return engine_failure(e, TLS13_EIO);
    return 0;
}
void tls13_engine_destroy(struct tls13_engine *e) {
    if (!e || !e->tls) return;
    tls13_free(e->tls); steer_wipe(e->tls->rbuf, sizeof(e->tls->rbuf));
    engine_release_workspace(e); steer_wipe(e, sizeof(*e));
}
#ifdef STEER_TLS13_TEST
/* Deliberate test-only entry into an already seeded post-handshake AEAD epoch.
 * Production cannot bypass authentication/Finished through this seam. */
struct tls13_engine *tls13_test_engine_post(void *storage,size_t length,struct tls13 *tls) {
    if(!storage||length<sizeof(struct tls13_engine)||!tls||!tls->ready||!post_active(tls))return NULL;
    struct tls13_engine *e=storage;memset(e,0,sizeof(*e));e->tls=tls;e->state=TLS13_ENGINE_READY;return e;
}
#endif
static int read_one(struct tls13 *t, const unsigned char **body, size_t *body_n) {
    *body = NULL;
    *body_n = 0;
    if (post_active(t) && t->post.error) return t->post.error;
    if (post_active(t) && t->post.read_closed) return TLS13_ECLOSED;
    if (!t->ready) return TLS13_ESTATE;

    /* Запись расшифровывается НА МЕСТЕ в буфере соединения: копировать её ещё раз значило
     * бы гонять по памяти лишние 16 КБ на каждую запись. */
    unsigned char *rec = NULL;
    unsigned char type;
    size_t n = 0;
    int rc = read_record(t, &type, &rec, &n, 0);
    /* Записи целиком нет — это «пока нечего», а не сбой: вызывающий просто придёт снова. */
    if (rc == TLS13_EAGAIN) return 0;
    if (rc) {
        if (rc == TLS13_ECLOSED && post_active(t) && (t->post.header_n || t->post.left)) return post_failure(t, TLS13_EBADREC);
        if (rc == TLS13_ECLOSED && post_active(t)) return post_failure(t, TLS13_EIO); /* TLS truncation */
        return rc;
    }
    if (t->v12) return tls12_read_rec(t, type, rec, n, body, body_n);
    return decode_cipher_record(t, type, rec, n, body, body_n, 1);
}

int tls13_read(struct tls13 *t, unsigned char *out, size_t cap, size_t *got) {
    const unsigned char *body = NULL;
    size_t n = 0;
    int rc = read_one(t, &body, &n);
    *got = 0;
    if (rc || !n) return rc;
    if (n > cap) return TLS13_ETOOBIG;
    memcpy(out, body, n);
    *got = n;
    return 0;
}

int tls13_read_ref(struct tls13 *t, const unsigned char **body, size_t *body_n) {
    return read_one(t, body, body_n);
}


/* ==== TLS 1.2 ============================================================================
 *
 * Ровно столько, сколько нужно точке веб-клиента Telegram (см. tls12_handshake в tls13.h):
 * ECDHE_RSA с X25519, AES_128_GCM_SHA256 или CHACHA20_POLY1305_SHA256, без возобновления,
 * без расширенного мастер-секрета (мы его не предлагаем), без проверки сертификата.
 *
 * Nonce совпадает по устройству с 1.3, если держать iv правильно: у GCM iv = salt(4) и
 * восемь нулей, и тогда aead_nonce(iv, n) = salt || n — ровно salt || явная часть, когда
 * явная часть равна номеру записи (так пишем мы). У ChaCha iv — все двенадцать байт, и
 * nonce = iv XOR номер, как и в 1.3. Читая, явную часть GCM берём из записи: сервер вправе
 * выбирать её сам. */

#define TLS12_GCM      0xC02F   /* TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 */
#define TLS12_CHACHA   0xCCA8   /* TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 */

int xc_random(unsigned char *out, size_t n);
int xc_x25519_keypair(unsigned char priv[32], unsigned char pub[32]);

/* PRF TLS 1.2 (RFC 5246 §5): P_SHA256(secret, label || seed). */
static int tls12_prf(const unsigned char *secret, size_t secret_n, const char *label,
                     const unsigned char *seed, size_t seed_n, unsigned char *out, size_t out_n) {
    unsigned char ls[128], a[32], tmp[32];
    size_t ll = strlen(label);
    if (ll + seed_n > sizeof(ls)) return TLS13_ECRYPTO;
    memcpy(ls, label, ll);
    memcpy(ls + ll, seed, seed_n);
    size_t lsn = ll + seed_n;
    /* A(1) = HMAC(secret, label||seed), дальше A(i) = HMAC(secret, A(i-1)). */
    if (sc_hmac(SC_SHA256, secret, secret_n, ls, lsn, a)) return TLS13_ECRYPTO;
    size_t off = 0;
    while (off < out_n) {
        /* HMAC(secret, A(i) || label || seed) — двумя кусками, без склейки в буфер. */
        if (sc_hmac2(SC_SHA256, secret, secret_n, a, 32, ls, lsn, tmp)) return TLS13_ECRYPTO;
        size_t take = out_n - off < 32 ? out_n - off : 32;
        memcpy(out + off, tmp, take);
        off += take;
        if (sc_hmac(SC_SHA256, secret, secret_n, a, 32, a)) return TLS13_ECRYPTO;
    }
    return 0;
}

static void put16(unsigned char *p, size_t v) { p[0] = (unsigned char)(v >> 8); p[1] = (unsigned char)v; }
static void put24(unsigned char *p, size_t v) {
    p[0] = (unsigned char)(v >> 16); p[1] = (unsigned char)(v >> 8); p[2] = (unsigned char)v;
}

static void tls12_aad(unsigned char aad[13], uint64_t seq, unsigned char type, size_t len) {
    for (int i = 0; i < 8; i++) aad[i] = (unsigned char)(seq >> (56 - 8 * i));
    aad[8] = type; aad[9] = 0x03; aad[10] = 0x03;
    put16(aad + 11, len);
}

static int write_all_fd(int fd, const unsigned char *p, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, p + sent, n - sent);
        if (w <= 0) { if (w < 0 && errno == EINTR) continue; return TLS13_EIO; }
        sent += (size_t)w;
    }
    return 0;
}

/* Одна зашифрованная запись: тип, открытый текст. Ключ — постоянный контекст t->wr. */
static int tls12_seal_rec(struct tls13 *t, unsigned char type, const unsigned char *data,
                          size_t chunk, unsigned char *out, size_t *out_n) {
    int gcm = t->wr.aead != TLS13_AEAD_CHACHA;
    size_t ex = gcm ? 8 : 0;
    size_t total = ex + chunk + 16;
    uint64_t seq = t->wr_seq++;
    out[0] = type; out[1] = 0x03; out[2] = 0x03;
    put16(out + 3, total);
    if (gcm) for (int i = 0; i < 8; i++) out[5 + i] = (unsigned char)(seq >> (56 - 8 * i));
    memcpy(out + 5 + ex, data, chunk);
    unsigned char aad[13];
    tls12_aad(aad, seq, type, chunk);
    if (tls13_aead_seal(&t->wr, seq, aad, 13, out + 5 + ex, chunk, out + 5 + ex + chunk) != 0)
        return TLS13_ECRYPTO;
    *out_n = 5 + total;
    return 0;
}

static int tls12_write(struct tls13 *t, const unsigned char *data, size_t n) {
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t on = 0;
        int rc = tls12_seal_rec(t, 0x17, data, chunk, out, &on);
        if (rc) return rc;
        rc = write_all_fd(t->fd, out, on);
        if (rc) return rc;
        data += chunk;
        n -= chunk;
    }
    return 0;
}

/* Расшифровать запись на месте. Открытый текст — body/body_n; тип — снаружи записи. */
static int tls12_open_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          unsigned char **pt, size_t *pt_n) {
    int gcm = t->rd.aead != TLS13_AEAD_CHACHA;
    size_t ex = gcm ? 8 : 0;
    if (n < ex + 16) return TLS13_EBADREC;
    uint64_t nonce_seq = t->rd_seq;
    if (gcm) {
        nonce_seq = 0;
        for (int i = 0; i < 8; i++) nonce_seq = (nonce_seq << 8) | rec[i];
    }
    size_t len = n - ex - 16;
    unsigned char aad[13];
    tls12_aad(aad, t->rd_seq, type, len);
    int rc = tls13_aead_open(&t->rd, nonce_seq, aad, 13, rec + ex, n - ex);
    if (rc) return rc;
    t->rd_seq++;
    *pt = rec + ex;
    *pt_n = len;
    return 0;
}

static int tls12_read_rec(struct tls13 *t, unsigned char type, unsigned char *rec, size_t n,
                          const unsigned char **body, size_t *body_n) {
    unsigned char *pt;
    size_t pt_n;
    if (type != 0x17 && type != 0x15 && type != 0x16) return TLS13_EBADREC;
    int rc = tls12_open_rec(t, type, rec, n, &pt, &pt_n);
    if (rc) return rc;
    if (type == 0x15) return TLS13_ECLOSED;     /* alert — в том числе close_notify */
    if (type == 0x16) return 0;                 /* HelloRequest и прочее — не просили, молчим */
    if (!pt_n) return 0;
    *body = pt;
    *body_n = pt_n;
    return 0;
}

int tls12_handshake(struct tls13 *t, int fd, const char *sni) {
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    t->v12 = 1;
    struct sc_hash_ctx tr;
    if (sc_hash_init(&tr, SC_SHA256) != 0) return TLS13_ECRYPTO;
    int rc = TLS13_ESTATE;

    unsigned char cr[32], sr[32], priv[32], pub[32], sid[32];
    if (xc_random(cr, 32) || xc_random(sid, 32) || xc_x25519_keypair(priv, pub))
        { rc = TLS13_ECRYPTO; goto out; }

    /* ---- ClientHello ---- */
    static __thread unsigned char buf[16384];
    size_t sl = strlen(sni);
    if (sl > 200) { rc = TLS13_ETOOBIG; goto out; }
    unsigned char *h = buf + 5, *p = h + 4;
    *p++ = 0x03; *p++ = 0x03;
    memcpy(p, cr, 32); p += 32;
    *p++ = 32; memcpy(p, sid, 32); p += 32;
    /* ChaCha первым: на роутере без ускорения AES он заметно быстрее; сервер всё равно
     * выбирает по своему порядку. */
    put16(p, 4); p += 2;
    put16(p, TLS12_CHACHA); p += 2;
    put16(p, TLS12_GCM); p += 2;
    *p++ = 1; *p++ = 0;                             /* без сжатия */
    unsigned char *ext = p; p += 2;
    /* server_name */
    put16(p, 0x0000); put16(p + 2, sl + 5); put16(p + 4, sl + 3); p[6] = 0; put16(p + 7, sl);
    memcpy(p + 9, sni, sl); p += 9 + sl;
    /* supported_groups: только X25519 */
    put16(p, 0x000a); put16(p + 2, 4); put16(p + 4, 2); put16(p + 6, 0x001d); p += 8;
    /* ec_point_formats: uncompressed */
    put16(p, 0x000b); put16(p + 2, 2); p[4] = 1; p[5] = 0; p += 6;
    /* signature_algorithms: RSA-PSS и PKCS#1 — подпись мы не проверяем, но без списка
     * сервер вправе отказать. */
    static const unsigned char sa[] = { 0x08,0x04, 0x08,0x05, 0x08,0x06, 0x04,0x01, 0x05,0x01, 0x06,0x01 };
    put16(p, 0x000d); put16(p + 2, sizeof(sa) + 2); put16(p + 4, sizeof(sa));
    memcpy(p + 6, sa, sizeof(sa)); p += 6 + sizeof(sa);
    /* ALPN: только http/1.1 — поверх идёт апгрейд веб-сокета по HTTP/1.1 */
    put16(p, 0x0010); put16(p + 2, 11); put16(p + 4, 9); p[6] = 8; memcpy(p + 7, "http/1.1", 8); p += 15;
    /* renegotiation_info: пустое, как у всех современных клиентов */
    put16(p, 0xff01); put16(p + 2, 1); p[4] = 0; p += 5;
    put16(ext, (size_t)(p - ext - 2));
    size_t hl = (size_t)(p - h);
    h[0] = 0x01; put24(h + 1, hl - 4);
    buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x01; put16(buf + 3, hl);
    sc_hash_update(&tr, h, hl);
    if ((rc = write_all_fd(fd, buf, 5 + hl))) goto out;

    /* ---- ответ сервера: ServerHello … ServerHelloDone ---- */
    static __thread unsigned char hs[40960];
    size_t hs_n = 0, off = 0;
    unsigned suite = 0;
    unsigned char spub[32];
    int have_ske = 0, done = 0;
    for (int guard = 0; guard < 64 && !done; guard++) {
        unsigned char type;
        size_t n;
        rc = read_record_fd(fd, &type, buf, sizeof(buf), &n);
        if (rc) goto out;
        if (type == 0x15) { rc = TLS13_ECLOSED; goto out; }
        if (type != 0x16) { rc = TLS13_EBADREC; goto out; }
        if (hs_n + n > sizeof(hs)) { rc = TLS13_ETOOBIG; goto out; }
        memcpy(hs + hs_n, buf, n);
        hs_n += n;
        while (off + 4 <= hs_n) {
            unsigned char mt = hs[off];
            size_t ml = ((size_t)hs[off + 1] << 16) | ((size_t)hs[off + 2] << 8) | hs[off + 3];
            if (off + 4 + ml > hs_n) break;
            const unsigned char *m = hs + off + 4;
            if (mt == 0x02) {                               /* ServerHello */
                if (ml < 38 || m[0] != 3 || m[1] != 3) { rc = TLS13_EBADREC; goto out; }
                memcpy(sr, m + 2, 32);
                size_t q = 34 + 1 + m[34];
                if (q + 3 > ml) { rc = TLS13_EBADREC; goto out; }
                suite = ((unsigned)m[q] << 8) | m[q + 1];
                if (suite != TLS12_GCM && suite != TLS12_CHACHA) { rc = TLS13_EBADSUITE; goto out; }
            } else if (mt == 0x0c) {                        /* ServerKeyExchange */
                if (ml < 4 + 32 || m[0] != 3 || m[1] != 0x00 || m[2] != 0x1d || m[3] != 32)
                    { rc = TLS13_ENOKEYSHARE; goto out; }
                memcpy(spub, m + 4, 32);
                have_ske = 1;
            } else if (mt == 0x0d) {                        /* CertificateRequest — не наш случай */
                rc = TLS13_EBADREC; goto out;
            } else if (mt == 0x0e) {                        /* ServerHelloDone */
                done = 1;
            }
            /* Certificate (0x0b) и прочее — только в транскрипт. */
            sc_hash_update(&tr, hs + off, 4 + ml);
            off += 4 + ml;
            if (done) break;
        }
    }
    if (!done || !suite || !have_ske) { rc = TLS13_EBADREC; goto out; }

    /* ---- ключи ---- */
    unsigned char pms[32], ms[48], seed[64], kb[88];
    if (x25519_shared_ext(priv, spub, pms)) { rc = TLS13_ECRYPTO; goto out; }
    memcpy(seed, cr, 32); memcpy(seed + 32, sr, 32);
    if ((rc = tls12_prf(pms, 32, "master secret", seed, 64, ms, 48))) goto out;
    memcpy(seed, sr, 32); memcpy(seed + 32, cr, 32);
    int chacha = suite == TLS12_CHACHA;
    size_t kn = chacha ? 32 : 16, ivn = chacha ? 12 : 4;
    if ((rc = tls12_prf(ms, 48, "key expansion", seed, 64, kb, 2 * kn + 2 * ivn))) goto out;
    t->wr.aead = t->rd.aead = chacha ? TLS13_AEAD_CHACHA : TLS13_AEAD_AES128;
    t->wr.key_n = t->rd.key_n = kn;
    memcpy(t->wr.key, kb, kn);
    memcpy(t->rd.key, kb + kn, kn);
    memcpy(t->wr.iv, kb + 2 * kn, ivn);         /* у GCM остальные восемь — нули (см. выше) */
    memcpy(t->rd.iv, kb + 2 * kn + ivn, ivn);
    if ((rc = tls13_keys_setup(&t->wr)) || (rc = tls13_keys_setup(&t->rd))) goto out;

    /* ---- ClientKeyExchange, ChangeCipherSpec, Finished ---- */
    unsigned char cke[4 + 33];
    cke[0] = 0x10; put24(cke + 1, 33); cke[4] = 32; memcpy(cke + 5, pub, 32);
    sc_hash_update(&tr, cke, sizeof(cke));
    buf[0] = 0x16; buf[1] = 0x03; buf[2] = 0x03; put16(buf + 3, sizeof(cke));
    memcpy(buf + 5, cke, sizeof(cke));
    size_t bn = 5 + sizeof(cke);
    static const unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    memcpy(buf + bn, ccs, 6); bn += 6;

    unsigned char th[32], fin[16];
    struct sc_hash_ctx tc;
    if (sc_hash_clone(&tc, &tr) != 0) { rc = TLS13_ECRYPTO; goto out; }
    sc_hash_final(&tc, th);
    sc_hash_free(&tc);
    fin[0] = 0x14; put24(fin + 1, 12);
    if ((rc = tls12_prf(ms, 48, "client finished", th, 32, fin + 4, 12))) goto out;
    sc_hash_update(&tr, fin, 16);
    size_t fn = 0;
    if ((rc = tls12_seal_rec(t, 0x16, fin, 16, buf + bn, &fn))) goto out;
    bn += fn;
    if ((rc = write_all_fd(fd, buf, bn))) goto out;

    /* ---- ChangeCipherSpec и Finished сервера ---- */
    unsigned char want[12];
    if (sc_hash_clone(&tc, &tr) != 0) { rc = TLS13_ECRYPTO; goto out; }
    sc_hash_final(&tc, th);
    sc_hash_free(&tc);
    if ((rc = tls12_prf(ms, 48, "server finished", th, 32, want, 12))) goto out;
    int got_ccs = 0;
    for (int guard = 0; guard < 8; guard++) {
        unsigned char type;
        size_t n;
        rc = read_record_fd(fd, &type, buf, sizeof(buf), &n);
        if (rc) goto out;
        if (type == 0x15) { rc = TLS13_ECLOSED; goto out; }
        if (type == 0x14) { got_ccs = 1; continue; }
        if (type != 0x16 || !got_ccs) { rc = TLS13_EBADREC; goto out; }
        unsigned char *pt;
        size_t pn;
        if ((rc = tls12_open_rec(t, 0x16, buf, n, &pt, &pn))) goto out;
        if (pn != 16 || pt[0] != 0x14 || memcmp(pt + 4, want, 12)) { rc = TLS13_EFINISHED; goto out; }
        t->ready = 1;
        rc = 0;
        goto out;
    }
    rc = TLS13_EBADREC;
out:
    sc_hash_free(&tr);
    if (rc) { tls13_keys_free(&t->wr); tls13_keys_free(&t->rd); t->ready = 0; }
    return rc;
}
