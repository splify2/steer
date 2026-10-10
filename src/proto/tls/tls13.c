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
 * post-handshake сообщения не поддержаны — на них не приходит ни один узел подписки, а
 * каждое было бы кодом, который никогда не исполняется и потому не проверен.
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
/* Отказ хеша здесь не возвращается, а ломает транскрипт: у заведённого контекста SHA-2 отказать
 * нечему (ни выделений, ни устройств), а если это всё-таки случилось, хеш выйдет не тем, и
 * Finished не сойдётся — рукопожатие упадёт с TLS13_EFINISHED, а не пройдёт с чужими ключами.
 * Отказ init оставляет контекст незаведённым (alg == 0), и остальные вызовы на нём — тоже отказ. */
static void tr_init(struct tls13 *t) {
    sc_hash_init(&t->tr, SC_SHA256);
    sc_hash_init(&t->tr384, SC_SHA384);
}
static void tr_add(struct tls13 *t, const unsigned char *d, size_t n) {
    sc_hash_update(&t->tr, d, n);
    sc_hash_update(&t->tr384, d, n);
}
/* Хеш транскрипта тем алгоритмом, который выбрал сервер. Копия контекста: транскрипт
 * продолжается после каждого вывода ключей. */
static void tr_hash(const struct tls13 *t, unsigned char *out) {
    struct sc_hash_ctx c;
    if (sc_hash_clone(&c, t->hash_n == 48 ? &t->tr384 : &t->tr) != 0) {
        memset(out, 0, t->hash_n == 48 ? 48 : 32);
        return;
    }
    sc_hash_final(&c, out);
    sc_hash_free(&c);
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

/* Безопасна на ОБНУЛЁННОЙ структуре и при повторном вызове — это контракт, а не удобство: с шага 2
 * выпуска 1.10 её зовёт transport_close на любой связи, в том числе при security=none, где
 * tls13_init не звали вовсе. Держится на том, что у каждого контекста слоя нулевой «алгоритм» или
 * флаг готовности значит «пусто» (sc_hash_free, sc_aead_free ничего не делают), а освобождение
 * этот признак снова обнуляет. */
void tls13_free(struct tls13 *t) {
    tls13_keys_free(&t->rd);
    tls13_keys_free(&t->wr);
    sc_hash_free(&t->tr);
    sc_hash_free(&t->tr384);
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
    return rc;
}

/* ---- рукопожатие ----------------------------------------------------------- */

/* Почему отказ проверки лежит В ПОТОКЕ, а не в struct tls13. К моменту, когда вызывающий
 * захочет назвать причину, соединение уже закрыто и структура очищена: путь отказа в
 * client.c — vless_close, а он обнуляет всё. Поток же переживает и закрытие, и следующую
 * попытку того же соединителя, а разные соединители своих причин друг другу не портят. */
static __thread char g_verify_reason[96];

const char *tls13_verify_reason(void) { return g_verify_reason; }

/* Принимает уже отправленный ClientHello (для транскрипта) и общий секрет.
 *
 * host != NULL включает проверку подлинности сервера по сертификату (security=tls). При
 * host == NULL сообщения Certificate и CertificateVerify по-прежнему попадают в транскрипт,
 * но не разбираются — это путь Reality, и объяснение, почему там проверять нечего, стоит в
 * заголовке reality.c.
 *
 * Возвращается с готовыми ключами трафика. */
static int handshake(struct tls13 *t, int fd,
                     const unsigned char *client_hello, size_t hello_n,
                     const unsigned char *our_priv,
                     const struct tls13_auth *auth) {
    /* Нужен ли нам сертификат вообще. Считается один раз: дальше признак стоит в трёх
     * местах горячего разбора, и три разных условия там разошлись бы. */
    const char *host = auth ? auth->host : NULL;
    const unsigned char *rkey = auth ? auth->reality_key : NULL;
    const int want_cert = (host != NULL) || (rkey != NULL);
    memset(t, 0, sizeof(*t));
    t->fd = fd;
    /* md и H заполняются после разбора ServerHello: они зависят от набора шифров. */
    enum sc_hash md = SC_SHA256;
    size_t H = 0;

    tr_init(t);
    /* В транскрипт идёт handshake-сообщение без заголовка записи. */
    tr_add(t, client_hello + 5, hello_n - 5);

    unsigned char rec[TLS13_MAX_REC];
    unsigned char type;
    size_t n;

    /* ServerHello. */
    int rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
    if (rc) return rc;
    if (type != 0x16 || n < 44 || rec[0] != 0x02) return TLS13_EBADREC;
    tr_add(t, rec, n);

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
    unsigned char sh_copy[TLS13_SH_KEEP];
    size_t sh_copy_n = 0;
    if (auth && auth->mldsa_pk) {
        if (n > sizeof(sh_copy)) return TLS13_ETOOBIG;
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
        tr_init(t);
        tr_add(t, auth->ech->inner, auth->ech->inner_n);
        tr_add(t, rec, n);
    }

    /* Расписание ключей RFC 8446 §7.1. Каждый шаг обязателен и порядок его строг:
     * early -> handshake -> master, с derive-secret между ними. */
    unsigned char zeros[48] = {0};
    unsigned char early[48], derived[48], hs_secret[48], empty_hash[48];
    if (sc_hash(md, zeros, 0, empty_hash) != 0) return TLS13_ECRYPTO;

    if (sc_hkdf_extract(md, NULL, 0, zeros, H, early) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, early, H, "derived", empty_hash, H, derived, H) != 0) return TLS13_ECRYPTO;

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
    unsigned char ecdhe[SC_MLKEM768_SS + 32];
    size_t ecdhe_n = 32;
    if (have_kem) {
        if (getenv("STEER_PQ_TRACE")) fprintf(stderr, "steer[pq]: сервер выбрал X25519MLKEM768\n");
        if (sc_mlkem768_decaps(ecdhe, auth->mlkem_dk, kem_ct) != 0) return TLS13_ECRYPTO;
        if (x25519_shared_ext(our_priv, server_pub, ecdhe + SC_MLKEM768_SS) != 0) return TLS13_ECRYPTO;
        ecdhe_n = sizeof(ecdhe);
    } else if (x25519_shared_ext(our_priv, server_pub, ecdhe) != 0) return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, derived, H, ecdhe, ecdhe_n, hs_secret) != 0)
        return TLS13_ECRYPTO;

    unsigned char th[48];
    tr_hash(t, th);
    unsigned char c_hs[48], s_hs[48];
    if (derive_secret(md, hs_secret, "c hs traffic", th, H, c_hs) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, hs_secret, "s hs traffic", th, H, s_hs) != 0) return TLS13_ECRYPTO;

    struct tls13_keys c_hk = t->wr, s_hk = t->rd;
    if (expand_label(md, c_hs, H, "key", NULL, 0, c_hk.key, c_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_hs, H, "iv", NULL, 0, c_hk.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "key", NULL, 0, s_hk.key, s_hk.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_hs, H, "iv", NULL, 0, s_hk.iv, 12) != 0) return TLS13_ECRYPTO;

    /* Дальше сервер шлёт зашифрованные сообщения. Читаем до Finished, попутно добавляя
     * их в транскрипт: Certificate и CertificateVerify нам не нужны по содержанию, но
     * нужны в хеше — иначе Finished не сойдётся. */
    uint64_t s_seq = 0;
    int got_finished = 0;
    unsigned char server_finished[48];

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
    size_t hs_have = 0;

    /* Сообщения, нужные проверке подлинности. Копируются, а не запоминаются указателем:
     * hsbuf сдвигается по мере разбора, и к моменту проверки на прежнем месте лежало бы
     * начало следующего сообщения. Цепочка бывает и восьмикилобайтной (см. выше про
     * маскировочный сайт с Certificate в 8273 байта), поэтому буфер тех же размеров, что и
     * hsbuf, но выделяется ТОЛЬКО когда проверка включена: у Reality он был бы 40 КБ на
     * поток, которые никто не читает. */
    static __thread unsigned char certbuf[40960];
    size_t cert_n = 0;
    unsigned char cv_buf[1024];
    size_t cv_n = 0;
    unsigned char cv_transcript[48];
    size_t cv_thash_n = 0;
    g_verify_reason[0] = '\0';

    /* Проходов больше шестнадцати: одна запись — не одно сообщение, и длинная цепочка
     * сертификатов приезжает несколькими записями. */
    for (int guard = 0; guard < 64 && !got_finished; guard++) {
        rc = read_record_fd(fd, &type, rec, sizeof(rec), &n);
        if (rc) return rc;
        if (type == 0x14) continue;             /* ChangeCipherSpec: игнор в 1.3 */
        if (type != 0x17) return TLS13_EBADREC;

        unsigned char aad[5] = { 0x17, 0x03, 0x03,
                                 (unsigned char)(n >> 8), (unsigned char)n };
        rc = aead_open_once(&s_hk, s_seq++, aad, 5, rec, n);
        if (rc) return rc;
        size_t pt = n - 16;
        /* Последний непустой байт — настоящий тип записи (RFC 8446 §5.4). */
        while (pt > 0 && rec[pt - 1] == 0) pt--;
        if (pt == 0) return TLS13_EBADREC;
        unsigned char inner = rec[--pt];
        if (inner != 0x16) continue;            /* не handshake — пропускаем */

        /* Приклеиваем к тому, что осталось от предыдущих записей. */
        if (hs_have + pt > sizeof(hsbuf)) return TLS13_ETOOBIG;
        memcpy(hsbuf + hs_have, rec, pt);
        hs_have += pt;

        /* В буфере может лежать несколько сообщений, а последнее — не целиком. */
        size_t p = 0;
        while (p + 4 <= hs_have) {
            unsigned char msg = hsbuf[p];
            size_t mlen = ((size_t)hsbuf[p + 1] << 16) | ((size_t)hsbuf[p + 2] << 8) | hsbuf[p + 3];
            if (p + 4 + mlen > hs_have) break;  /* остаток придёт следующей записью */
            if (msg == 0x08) {                  /* EncryptedExtensions */
                /* Достаём только ALPN. Разбирать остальные расширения нечем и незачем:
                 * ни одно из них на нас не влияет, а лишний разбор недоверенных байт —
                 * лишнее место для ошибки. Тело: длина списка(2), затем расширения
                 * тип(2)+длина(2)+тело, а внутри ALPN — длина списка(2), длина(1), имя. */
                const unsigned char *e = hsbuf + p + 4;
                if (mlen >= 2) {
                    size_t total = ((size_t)e[0] << 8) | e[1];
                    if (total + 2 <= mlen) {
                        size_t q = 2;
                        while (q + 4 <= total + 2) {
                            unsigned etype = ((unsigned)e[q] << 8) | e[q + 1];
                            size_t ebody = ((size_t)e[q + 2] << 8) | e[q + 3];
                            if (q + 4 + ebody > total + 2) break;
                            if (etype == 0x0010 && ebody >= 4) {
                                size_t pl = e[q + 6];
                                if (pl && pl < sizeof(t->alpn) && 3 + pl <= ebody) {
                                    memcpy(t->alpn, e + q + 7, pl);
                                    t->alpn[pl] = '\0';
                                }
                            }
                            q += 4 + ebody;
                        }
                    }
                }
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
                snprintf(g_verify_reason, sizeof(g_verify_reason), "%s",
                         rkey ? cert_verify_strerror(CERTV_ENOTREALITY)
                              : "сервер сжал сертификат, о чём его не просили");
                return TLS13_ECERT;
            }
            if (want_cert && msg == 0x0B && cert_n == 0) {   /* Certificate */
                if (mlen > sizeof(certbuf)) return TLS13_ETOOBIG;
                memcpy(certbuf, hsbuf + p + 4, mlen);
                cert_n = mlen;
            }
            if (host && msg == 0x0F && cv_n == 0) {     /* CertificateVerify */
                /* Хеш снимается ЗДЕСЬ, до tr_add этого же сообщения: сервер подписывал
                 * транскрипт по Certificate включительно, и ни байтом больше. Снять его
                 * позже нельзя — транскрипт необратим. */
                if (mlen > sizeof(cv_buf)) return TLS13_ETOOBIG;
                tr_hash(t, cv_transcript);
                cv_thash_n = H;
                memcpy(cv_buf, hsbuf + p + 4, mlen);
                cv_n = mlen;
            }
            if (msg == 0x14) {                  /* Finished */
                /* Проверяем ДО добавления в транскрипт: сервер считал его от хеша
                 * предыдущих сообщений. */
                unsigned char fkey[48], hash[48], want[48];
                tr_hash(t, hash);
                if (expand_label(md, s_hs, H, "finished", NULL, 0, fkey, H) != 0)
                    return TLS13_ECRYPTO;
                if (sc_hmac(md, fkey, H, hash, H, want) != 0) return TLS13_ECRYPTO;
                if (mlen != H || memcmp(hsbuf + p + 4, want, H) != 0) return TLS13_EFINISHED;
                memcpy(server_finished, want, H);
                got_finished = 1;
            }
            tr_add(t, hsbuf + p, 4 + mlen);
            p += 4 + mlen;
        }
        /* Разобранное выбрасываем, недоразобранное сдвигаем к началу. */
        if (p) {
            if (hs_have > p) memmove(hsbuf, hsbuf + p, hs_have - p);
            hs_have -= p;
        }
    }
    if (!got_finished) return TLS13_EFINISHED;

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
        if (!cert_n) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "сервер не прислал сертификат");
            return TLS13_ECERT;
        }
        int rrc = cert_reality_check(certbuf, cert_n, rkey);
        if (rrc == 0 && auth->mldsa_pk)
            rrc = cert_reality_check_pq(certbuf, cert_n, rkey, auth->mldsa_pk,
                                        client_hello + 5, hello_n - 5, sh_copy, sh_copy_n);
        if (rrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s", cert_verify_strerror(rrc));
            return TLS13_ECERT;
        }
    }

    if (host) {
        if (!cert_n || !cv_n) {
            /* Рукопожатие сошлось, а доказательства не было. Так отвечает сервер, который
             * ждал сертификат ОТ НАС (client auth) или возобновил сессию — ни того, ни
             * другого мы не умеем и не просили. Причина названа отдельно: «сертификата не
             * прислали» и «сертификат не сошёлся» — не одно и то же. */
            snprintf(g_verify_reason, sizeof(g_verify_reason),
                     "сервер не прислал %s", cert_n ? "подпись" : "сертификат");
            return TLS13_ECERT;
        }
        int vrc = cert_verify_server_ex(certbuf, cert_n, cv_buf, cv_n,
                                        cv_transcript, cv_thash_n, host, auth->roots, auth->policy);
        if (vrc != 0) {
            snprintf(g_verify_reason, sizeof(g_verify_reason), "%s",
                     cert_verify_strerror(vrc));
            return TLS13_ECERT;
        }
    }

    /* Свой Finished — от транскрипта, включающего серверный. */
    unsigned char th2[48], cfkey[48], chash[48], cfin[48];
    tr_hash(t, th2);
    if (expand_label(md, c_hs, H, "finished", NULL, 0, cfkey, H) != 0) return TLS13_ECRYPTO;
    memcpy(chash, th2, H);
    if (sc_hmac(md, cfkey, H, chash, H, cfin) != 0) return TLS13_ECRYPTO;

    /* Отправляем: ChangeCipherSpec (совместимость с middlebox, как браузер) и
     * зашифрованный Finished. */
    {
        unsigned char ccs[6] = { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
        if (write(fd, ccs, 6) != 6) return TLS13_EIO;

        unsigned char pt[96];
        size_t pl = 0;
        pt[pl++] = 0x14;
        pt[pl++] = 0; pt[pl++] = 0; pt[pl++] = (unsigned char)H;
        memcpy(pt + pl, cfin, H); pl += H;
        pt[pl++] = 0x16;                        /* inner type */

        unsigned char out[160];
        size_t total = pl + 16;
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, pt, pl);
        if (aead_seal_once(&c_hk, 0, out, 5, out + 5, pl, out + 5 + pl) != 0) return TLS13_ECRYPTO;
        if (write(fd, out, 5 + total) != (ssize_t)(5 + total)) return TLS13_EIO;
    }

    /* Ключи трафика приложения — от master secret и полного транскрипта. */
    unsigned char master[48], c_ap[48], s_ap[48];
    if (expand_label(md, hs_secret, H, "derived", empty_hash, H, derived, H) != 0)
        return TLS13_ECRYPTO;
    if (sc_hkdf_extract(md, derived, H, zeros, H, master) != 0) return TLS13_ECRYPTO;
    tr_hash(t, th2);
    if (derive_secret(md, master, "c ap traffic", th2, H, c_ap) != 0) return TLS13_ECRYPTO;
    if (derive_secret(md, master, "s ap traffic", th2, H, s_ap) != 0) return TLS13_ECRYPTO;

    if (expand_label(md, c_ap, H, "key", NULL, 0, t->wr.key, t->wr.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, c_ap, H, "iv", NULL, 0, t->wr.iv, 12) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "key", NULL, 0, t->rd.key, t->rd.key_n) != 0) return TLS13_ECRYPTO;
    if (expand_label(md, s_ap, H, "iv", NULL, 0, t->rd.iv, 12) != 0) return TLS13_ECRYPTO;
    /* Ключи трафика больше не меняются — разворачиваем их в контексты шифров здесь, и
     * дальше поток идёт без единого setkey. */
    if (tls13_keys_setup(&t->wr) != 0 || tls13_keys_setup(&t->rd) != 0) return TLS13_ECRYPTO;
    t->wr_seq = t->rd_seq = 0;
    t->ready = 1;
    return 0;
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

/* ---- обмен данными --------------------------------------------------------- */
static int tls12_write(struct tls13 *t, const unsigned char *data, size_t n);

int tls13_write(struct tls13 *t, const unsigned char *data, size_t n) {
    if (!t->ready) return TLS13_ESTATE;
    if (t->v12) return tls12_write(t, data, n);
    while (n) {
        size_t chunk = n > TLS13_MAX_PLAIN ? TLS13_MAX_PLAIN : n;
        unsigned char out[TLS13_MAX_REC + 5];
        size_t total = chunk + 1 + 16;          /* + inner type + tag */
        out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
        out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
        memcpy(out + 5, data, chunk);
        out[5 + chunk] = 0x17;                  /* inner type: application_data */
        if (tls13_aead_seal(&t->wr, t->wr_seq++, out, 5, out + 5, chunk + 1,
                      out + 5 + chunk + 1) != 0)
            return TLS13_ECRYPTO;
        size_t want = 5 + total, sent = 0;
        while (sent < want) {
            ssize_t w = write(t->fd, out + sent, want - sent);
            if (w <= 0) {
                if (w < 0 && errno == EINTR) continue;
                return TLS13_EIO;
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

static int read_one(struct tls13 *t, const unsigned char **body, size_t *body_n) {
    if (!t->ready) return TLS13_ESTATE;
    *body = NULL;
    *body_n = 0;

    /* Запись расшифровывается НА МЕСТЕ в буфере соединения: копировать её ещё раз значило
     * бы гонять по памяти лишние 16 КБ на каждую запись. */
    unsigned char *rec = NULL;
    unsigned char type;
    size_t n = 0;
    int rc = read_record(t, &type, &rec, &n, 0);
    /* Записи целиком нет — это «пока нечего», а не сбой: вызывающий просто придёт снова. */
    if (rc == TLS13_EAGAIN) return 0;
    if (rc) return rc;
    if (t->v12) return tls12_read_rec(t, type, rec, n, body, body_n);
    if (type == 0x14) return 0;                /* ChangeCipherSpec: в 1.3 смысла не несёт */
    if (type != 0x17) return TLS13_EBADREC;

    unsigned char aad[5] = { 0x17, 0x03, 0x03,
                             (unsigned char)(n >> 8), (unsigned char)n };
    rc = tls13_aead_open(&t->rd, t->rd_seq++, aad, 5, rec, n);
    if (rc) return rc;
    size_t pt = n - 16;
    while (pt > 0 && rec[pt - 1] == 0) pt--;
    if (pt == 0) return TLS13_EBADREC;
    unsigned char inner = rec[--pt];

    /* NewSessionTicket и прочие post-handshake сообщения приходят как handshake и нас не
     * интересуют: возобновление не поддержано. Пропускаем, а не считаем ошибкой — иначе
     * соединение падало бы через минуту после установки. */
    if (inner == 0x16) return 0;
    if (inner == 0x15) return TLS13_ECLOSED;   /* alert */
    if (inner != 0x17) return 0;
    if (pt == 0) return 0;                     /* пустая запись — законная набивка Vision */

    *body = rec;
    *body_n = pt;
    return 0;
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
