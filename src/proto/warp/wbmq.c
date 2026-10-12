/* Туннель MASQUE к Cloudflare WARP — этап 2 модуля steer-warpbox (WARPBOX.md в хабе, «Протокол»).
 *
 * ЧТО НА ПРОВОДЕ. QUIC v1 к точке Cloudflare (эникаст 162.159.198.1:443 по умолчанию), SNI
 * consumer-masque.cloudflareclient.com, ALPN h3, клиентский сертификат — самоподписанный ключом P-256,
 * выданным при регистрации (wbx509.c): по нему Cloudflare узнаёт устройство. Сервер проверяется
 * ровно так же — его ключ сверяется с тем, что API отдал при включении MASQUE (цепочку и имя никто не
 * проверяет: их и у официального клиента нет). Поверх — HTTP/3: SETTINGS с H3_DATAGRAM (0x33) и меткой
 * Cloudflare 0x276, затем на первом двустороннем потоке Extended CONNECT с `:protocol cf-connect-ip`
 * к cloudflareaccess.com. После ответа 2xx IP-пакеты идут датаграммами QUIC: Quarter Stream ID потока
 * запроса, Context ID 0 и сам пакет (RFC 9297, RFC 9484). Капсул Cloudflare не шлёт: адреса туннеля —
 * из регистрации, MTU 1280.
 *
 * ГДЕ ЖИВЁТ. Туннель члена — свой поток модуля (wb_mq_start): TUN с именем устройства члена, сокет
 * QUIC и epoll на обоих. Пакет из TUN — датаграмма, датаграмма — пакет в TUN; ни стека TCP, ни
 * разбора пакетов: туннель пакетный, как xsteer. Маршрут, метки, таблица и подмена адресов — ядро
 * steer, как у любого выхода с устройством. Обрыв — переподключение с паузой (1 с, вдвое до 30 с);
 * новая точка (wb_mq_retarget) — переподключение сразу. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <linux/ipv6.h>

#include "quic.h"
#include "scrypto.h"
#include "wbmq.h"
#include "wbx509.h"

#define MQ_SNI   "consumer-masque.cloudflareclient.com"
#define MQ_AUTH  "cloudflareaccess.com"
#define MQ_PROTO "cf-connect-ip"

#define LOG(...) fprintf(stderr, "steer-warpbox: " __VA_ARGS__)

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000L + t.tv_nsec / 1000000L;
}

/* ---- целые QUIC (RFC 9000, 16) ---------------------------------------------------------------- */

static size_t vput(uint8_t *p, uint64_t v) {
    if (v < 64) { p[0] = (uint8_t)v; return 1; }
    if (v < 16384) { p[0] = (uint8_t)(0x40 | (v >> 8)); p[1] = (uint8_t)v; return 2; }
    if (v < (1u << 30)) {
        p[0] = (uint8_t)(0x80 | (v >> 24)); p[1] = (uint8_t)(v >> 16); p[2] = (uint8_t)(v >> 8); p[3] = (uint8_t)v;
        return 4;
    }
    for (int i = 7; i >= 0; i--) p[7 - i] = (uint8_t)(v >> (8 * i));
    p[0] |= 0xc0;
    return 8;
}

/* 0 — ошибка (не хватает байт), иначе длина. */
static size_t vget(const uint8_t *p, size_t n, uint64_t *v) {
    if (!n) return 0;
    size_t l = (size_t)1 << (p[0] >> 6);
    if (n < l) return 0;
    uint64_t x = p[0] & 0x3f;
    for (size_t i = 1; i < l; i++) x = (x << 8) | p[i];
    *v = x;
    return l;
}

/* ---- QPACK: только то, что нужно запросу CONNECT и чтению :status (RFC 9204) ------------------- */

/* Целое с префиксом N бит; first — старшие биты первого байта. */
static size_t qint(uint8_t *p, uint8_t first, int nbits, uint64_t v) {
    uint64_t max = (1u << nbits) - 1;
    if (v < max) { p[0] = (uint8_t)(first | v); return 1; }
    p[0] = (uint8_t)(first | max);
    v -= max;
    size_t n = 1;
    while (v >= 128) { p[n++] = (uint8_t)(0x80 | (v & 0x7f)); v >>= 7; }
    p[n++] = (uint8_t)v;
    return n;
}

static size_t qint_get(const uint8_t *p, size_t n, int nbits, uint64_t *v) {
    if (!n) return 0;
    uint64_t max = (1u << nbits) - 1, x = p[0] & max;
    if (x < max) { *v = x; return 1; }
    size_t i = 1;
    int sh = 0;
    for (; i < n && i < 9; i++) {
        x += (uint64_t)(p[i] & 0x7f) << sh;
        sh += 7;
        if (!(p[i] & 0x80)) { *v = x; return i + 1; }
    }
    return 0;
}

/* Строка без Хаффмана: H=0 и длина с префиксом prefix_bits. */
static size_t qstr(uint8_t *p, uint8_t first, int prefix_bits, const char *s) {
    size_t l = strlen(s), h = qint(p, first, prefix_bits, l);
    memcpy(p + h, s, l);
    return h + l;
}

/* Поле с именем из статической таблицы (индекс idx) и своим значением. */
static size_t qf_nameref(uint8_t *p, unsigned idx, const char *val) {
    size_t n = qint(p, 0x50, 4, idx);            /* 01 N=0 T=1 */
    return n + qstr(p + n, 0x00, 7, val);
}

/* Поле с именем и значением строками. */
static size_t qf_literal(uint8_t *p, const char *name, const char *val) {
    size_t n = qstr(p, 0x20, 3, name);           /* 001 N=0 H=0 */
    return n + qstr(p + n, 0x00, 7, val);
}

/* Блок полей запроса CONNECT. */
static size_t connect_fields(uint8_t *p) {
    size_t n = 0;
    p[n++] = 0x00;                                /* Required Insert Count 0 */
    p[n++] = 0x00;                                /* Delta Base 0 */
    p[n++] = 0xc0 | 15;                           /* :method CONNECT (статическая 15) */
    n += qf_literal(p + n, ":protocol", MQ_PROTO);
    p[n++] = 0xc0 | 23;                           /* :scheme https */
    n += qf_nameref(p + n, 0, MQ_AUTH);           /* :authority */
    p[n++] = 0xc0 | 1;                            /* :path / */
    n += qf_literal(p + n, "capsule-protocol", "?1");
    n += qf_nameref(p + n, 95, "");               /* user-agent — пустой, как у клиента Cloudflare */
    return n;
}

/* :status из статической таблицы. */
static int status_static(uint64_t idx) {
    static const struct { unsigned idx; int st; } T[] = {
        { 24, 103 }, { 25, 200 }, { 26, 304 }, { 27, 404 }, { 28, 503 }, { 63, 100 }, { 64, 204 },
        { 65, 206 }, { 66, 302 }, { 67, 400 }, { 68, 403 }, { 69, 421 }, { 70, 425 }, { 71, 500 },
    };
    for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++)
        if (T[i].idx == idx) return T[i].st;
    return -1;
}

/* Цифры кодом Хаффмана HPACK (RFC 7541, приложение B): 0-2 — пять бит 00000..00010, 3-9 — шесть бит
 * 011001..011111. Только цифры: :status — три цифры, остальное не нужно. */
static int huff_digits(const uint8_t *p, size_t n, char *out, size_t cap) {
    size_t o = 0, bits = 0;
    uint32_t acc = 0;
    for (size_t i = 0; i < n; i++) {
        acc = (acc << 8) | p[i];
        bits += 8;
        while (bits >= 5 && o + 1 < cap) {
            unsigned c5 = (acc >> (bits - 5)) & 0x1f;
            if (c5 <= 2) { out[o++] = (char)('0' + c5); bits -= 5; continue; }
            if (bits < 6) break;
            unsigned c6 = (acc >> (bits - 6)) & 0x3f;
            if (c6 >= 0x19 && c6 <= 0x1f) { out[o++] = (char)('3' + (c6 - 0x19)); bits -= 6; continue; }
            if (c5 == 0x1f) break;                  /* набивка единицами — конец */
            return -1;
        }
    }
    out[o] = '\0';
    return (int)o;
}

/* Код ответа из блока полей HEADERS; -1 — не разобран. */
static int resp_status(const uint8_t *p, size_t n) {
    uint64_t v;
    size_t k;
    if (!(k = qint_get(p, n, 8, &v))) return -1;
    p += k; n -= k;
    if (!(k = qint_get(p, n, 7, &v))) return -1;
    p += k; n -= k;
    while (n) {
        if ((p[0] & 0xc0) == 0xc0) {               /* индексированное поле, статическая таблица */
            if (!(k = qint_get(p, n, 6, &v))) return -1;
            int st = status_static(v);
            if (st > 0) return st;
            p += k; n -= k;
            continue;
        }
        if ((p[0] & 0xc0) == 0x40) {               /* имя по ссылке */
            int stat = p[0] & 0x10;
            if (!(k = qint_get(p, n, 4, &v))) return -1;
            int is_status = stat && ((v >= 24 && v <= 28) || (v >= 63 && v <= 71));
            p += k; n -= k;
            if (!n) return -1;
            int huff = p[0] & 0x80;
            uint64_t l;
            if (!(k = qint_get(p, n, 7, &l)) || n - k < l) return -1;
            if (is_status) {
                char d[8];
                if (huff) { if (huff_digits(p + k, (size_t)l, d, sizeof(d)) != 3) return -1; }
                else { if (l != 3) return -1; memcpy(d, p + k, 3); d[3] = '\0'; }
                return atoi(d);
            }
            p += k + l; n -= k + l;
            continue;
        }
        return -1;                                  /* прочие формы до :status не ждём */
    }
    return -1;
}

/* ---- соединение ----------------------------------------------------------------------------- */

struct mq {
    struct qc *q;
    int state;                  /* 0 рукопожатие, 1 запрос ушёл, 2 принят, -1 закрыто */
    int64_t req;
    uint64_t qsid;
    const unsigned char *spki;
    char why[160];
    uint8_t hb[2048];
    size_t hn;
    void (*on_ip)(void *u, const uint8_t *p, size_t n);
    void *u;
};

static int send_all(struct qc *q, int64_t sid, const uint8_t *d, size_t n, int fin) {
    ssize_t w = qc_stream_send(q, sid, d, n, fin);
    return w == (ssize_t)n ? 0 : -1;
}

static void mq_on_handshake(void *user) {
    struct mq *m = user;
    uint8_t cert[4096];
    int cn = qc_peer_cert(m->q, cert, sizeof(cert));
    const unsigned char *spki;
    size_t sn;
    if (cn <= 0 || wb_cert_spki(cert, (size_t)cn, &spki, &sn) != 0 || sn != WB_SPKI_P256 ||
        memcmp(spki, m->spki, WB_SPKI_P256) != 0) {
        snprintf(m->why, sizeof(m->why), "ключ сервера не совпал с выданным при регистрации");
        m->state = -1;
        qc_close(m->q, 0);
        return;
    }
    /* Управляющий поток: тип 0x00 и SETTINGS {H3_DATAGRAM=1, 0x276=1}; потоки QPACK — пустые. */
    int64_t sid;
    uint8_t b[64];
    size_t n = 0, sl = 0;
    uint8_t set[32];
    sl += vput(set + sl, 0x33); sl += vput(set + sl, 1);
    sl += vput(set + sl, 0x276); sl += vput(set + sl, 1);
    b[n++] = 0x00;
    n += vput(b + n, 0x04);
    n += vput(b + n, sl);
    memcpy(b + n, set, sl); n += sl;
    if (qc_stream_open_uni(m->q, &sid) != 0 || send_all(m->q, sid, b, n, 0) != 0) goto fail;
    static const uint8_t enc = 0x02, dec = 0x03;
    if (qc_stream_open_uni(m->q, &sid) != 0 || send_all(m->q, sid, &enc, 1, 0) != 0) goto fail;
    if (qc_stream_open_uni(m->q, &sid) != 0 || send_all(m->q, sid, &dec, 1, 0) != 0) goto fail;
    /* Запрос CONNECT: кадр HEADERS на первом двустороннем потоке, без FIN — поток живёт с туннелем. */
    uint8_t fl[256], fr[300];
    size_t fn = connect_fields(fl), rn = 0;
    rn += vput(fr + rn, 0x01);
    rn += vput(fr + rn, fn);
    memcpy(fr + rn, fl, fn); rn += fn;
    if (qc_stream_open(m->q, &m->req) != 0 || send_all(m->q, m->req, fr, rn, 0) != 0) goto fail;
    m->qsid = (uint64_t)m->req / 4;
    m->state = 1;
    return;
fail:
    snprintf(m->why, sizeof(m->why), "запрос HTTP/3 не отправился");
    m->state = -1;
    qc_close(m->q, 0x0102);                        /* H3_INTERNAL_ERROR */
}

static void mq_on_stream_data(void *user, int64_t sid, const uint8_t *d, size_t n, int fin) {
    struct mq *m = user;
    if (sid != m->req || m->state < 1) return;      /* управляющий поток сервера и QPACK — мимо */
    if (m->state == 1) {
        if (m->hn + n > sizeof(m->hb)) n = sizeof(m->hb) - m->hn;
        memcpy(m->hb + m->hn, d, n);
        m->hn += n;
        /* Кадры до HEADERS: зарезервированные типы (GREASE, RFC 9114, 7.2.8 — Cloudflare их шлёт)
         * пропускаются, DATA до заголовков — нарушение. */
        uint64_t type, len;
        size_t a, b;
        for (;;) {
            a = vget(m->hb, m->hn, &type);
            if (!a || !(b = vget(m->hb + a, m->hn - a, &len)) || m->hn - a - b < len) {
                if (fin) { snprintf(m->why, sizeof(m->why), "поток запроса закрыт без ответа"); m->state = -1; }
                return;
            }
            if (type == 0x01) break;
            if (type == 0x00) {
                snprintf(m->why, sizeof(m->why), "DATA раньше заголовков ответа");
                m->state = -1;
                qc_close(m->q, 0x0105);            /* H3_FRAME_UNEXPECTED */
                return;
            }
            size_t used = a + b + (size_t)len;
            memmove(m->hb, m->hb + used, m->hn - used);
            m->hn -= used;
        }
        int st = resp_status(m->hb + a + b, (size_t)len);
        if (st / 100 != 2) {
            if (st > 0) snprintf(m->why, sizeof(m->why), "CONNECT: ответ %d", st);
            else snprintf(m->why, sizeof(m->why), "CONNECT: код ответа не разобран");
            m->state = -1;
            qc_close(m->q, 0x0100);                /* H3_NO_ERROR */
            return;
        }
        m->state = 2;
        m->why[0] = '\0';
        return;                                     /* дальше в потоке — капсулы: не нужны */
    }
    if (fin) { snprintf(m->why, sizeof(m->why), "сервер закрыл поток туннеля"); m->state = -1; }
}

static void mq_on_datagram(void *user, const uint8_t *d, size_t n) {
    struct mq *m = user;
    uint64_t qs, ctx;
    size_t a = vget(d, n, &qs), b;
    if (!a || qs != m->qsid || !(b = vget(d + a, n - a, &ctx)) || ctx != 0 || m->state != 2) return;
    if (m->on_ip) m->on_ip(m->u, d + a + b, n - a - b);
}

static void mq_on_closed(void *user, int reason, const char *why) {
    struct mq *m = user;
    if (!m->why[0] || m->state >= 0)
        snprintf(m->why, sizeof(m->why), "%s", reason == QC_CLOSE_HANDSHAKE ? "рукопожатие QUIC не прошло"
                                             : reason == QC_CLOSE_IDLE ? "сервер молчит"
                                             : why && why[0] ? why : "соединение закрыто");
    m->state = -1;
}

static const struct qc_ops MQ_OPS = {
    .on_handshake = mq_on_handshake,
    .on_stream_data = mq_on_stream_data,
    .on_datagram = mq_on_datagram,
    .on_closed = mq_on_closed,
};

static int mq_open(struct mq *m, const struct wb_mq_cfg *c, char *why, size_t wn) {
    unsigned char cert[512], key[WB_SEC1_P256], pub[65];
    size_t cn = 0;
    if (wb_mq_cert(c->priv, cert, sizeof(cert), &cn) != 0 || sc_p256_public(c->priv, pub) != 0) {
        snprintf(why, wn, "сертификат клиента не собрался");
        return -1;
    }
    size_t kn = wb_p256_sec1(c->priv, pub, key);
    struct qc_cfg cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.host = c->ep;
    cfg.port = (uint16_t)(c->port ? c->port : 443);
    cfg.sni = MQ_SNI;
    cfg.alpn = "h3";
    cfg.insecure = 1;                               /* ключ сервера сверяем сами (mq_on_handshake) */
    cfg.client_cert = cert;
    cfg.client_cert_n = cn;
    cfg.client_key = key;
    cfg.client_key_n = kn;
    cfg.sock_mark = c->mark;
    cfg.mark_required = c->mark != 0;
    cfg.datagram_max = 65535;
    cfg.idle_ms = 30000;
    cfg.keepalive_ms = 25000;
    cfg.handshake_ms = 8000;
    cfg.max_streams = 4;
    void (*on_ip)(void *, const uint8_t *, size_t) = m->on_ip;
    void *u = m->u;
    memset(m, 0, sizeof(*m));
    m->on_ip = on_ip;
    m->u = u;
    m->spki = c->spki;
    m->req = -1;
    int rc = qc_open(&cfg, &MQ_OPS, m, &m->q);
    memset(key, 0, sizeof(key));
    if (rc != 0) { snprintf(why, wn, "QUIC не открылся (%d)", rc); m->q = NULL; return -1; }
    return 0;
}

/* ---- проба точки -------------------------------------------------------------------------- */

static uint16_t csum16(const uint8_t *p, size_t n) {
    uint32_t s = 0;
    for (size_t i = 0; i + 1 < n; i += 2) s += (uint32_t)(p[i] << 8 | p[i + 1]);
    if (n & 1) s += (uint32_t)p[n - 1] << 8;
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)~s;
}

struct probe { long sent_at; int got; uint16_t id; };

static void probe_ip(void *u, const uint8_t *p, size_t n) {
    struct probe *pr = u;
    if (n < 28 || (p[0] >> 4) != 4) return;
    size_t hl = (size_t)(p[0] & 0x0f) * 4;
    if (n < hl + 8 || p[9] != 1 || p[hl] != 0) return;         /* ICMP echo reply */
    if (((uint16_t)p[hl + 4] << 8 | p[hl + 5]) != pr->id) return;
    if (!pr->got) pr->got = (int)(mono_ms() - pr->sent_at) + 1;
}

int wb_mq_probe(const struct wb_mq_cfg *c, int timeout_ms, int *rtt_ms, char *why, size_t wn) {
    struct mq m;
    struct probe pr = { 0, 0, (uint16_t)(getpid() ^ mono_ms()) };
    m.on_ip = probe_ip;
    m.u = &pr;
    if (mq_open(&m, c, why, wn) != 0) return -1;
    long end = mono_ms() + timeout_ms;
    int sent = 0, rc = -1;
    while (mono_ms() < end && m.state >= 0 && !pr.got) {
        if (m.state == 2 && !sent) {
            /* IPv4 + ICMP echo к 1.1.1.1 от адреса туннеля — прямо в датаграмму, без TUN. */
            uint8_t dg[2 + 20 + 8 + 32];
            uint8_t *ip = dg + 2;
            memset(dg, 0, sizeof(dg));
            dg[0] = (uint8_t)m.qsid;                /* поток 0: Quarter Stream ID — один байт */
            dg[1] = 0x00;
            ip[0] = 0x45; ip[2] = 0; ip[3] = 60; ip[8] = 64; ip[9] = 1;
            struct in_addr src, dst;
            char v4[48];
            snprintf(v4, sizeof(v4), "%s", c->v4);
            v4[strcspn(v4, "/")] = '\0';
            if (inet_pton(AF_INET, v4, &src) != 1) { snprintf(why, wn, "адрес туннеля IPv4 не разобран"); break; }
            inet_pton(AF_INET, "1.1.1.1", &dst);
            memcpy(ip + 12, &src, 4);
            memcpy(ip + 16, &dst, 4);
            uint16_t s = csum16(ip, 20);
            ip[10] = (uint8_t)(s >> 8); ip[11] = (uint8_t)s;
            uint8_t *ic = ip + 20;
            ic[0] = 8;
            ic[4] = (uint8_t)(pr.id >> 8); ic[5] = (uint8_t)pr.id;
            ic[7] = 1;
            s = csum16(ic, 40);
            ic[2] = (uint8_t)(s >> 8); ic[3] = (uint8_t)s;
            pr.sent_at = mono_ms();
            if (qc_datagram_send(m.q, dg, sizeof(dg)) == 0) sent = 1;
        }
        long left = end - mono_ms();
        int t = qc_timeout_ms(m.q);
        if (t < 0 || t > left) t = (int)left;
        if (t > 200) t = 200;
        qc_run(m.q, t < 0 ? 0 : t);
    }
    if (pr.got) { *rtt_ms = pr.got - 1; rc = 0; }
    else if (m.state == 2) { snprintf(why, wn, "CONNECT принят, но эхо через туннель не вернулось"); rc = 1; }
    else if (m.why[0]) snprintf(why, wn, "%s", m.why);
    else if (!why[0]) snprintf(why, wn, "срок вышел");
    qc_close(m.q, 0x0100);
    qc_free(m.q);
    return rc;
}

/* ---- туннель члена: TUN и поток ---------------------------------------------------------- */

struct wb_mq {
    pthread_t th;
    pthread_mutex_t mu;
    struct wb_mq_cfg cfg;
    int ev;                     /* eventfd: остановка и новая точка */
    int tun;
    volatile int stop, retarget, up;
    char why[160];
    struct mq m;
};

static int ifreq_sock(int fam) { return socket(fam, SOCK_DGRAM | SOCK_CLOEXEC, 0); }

/* TUN: создать, MTU, адреса /32 и /128, поднять. */
static int tun_open(const struct wb_mq_cfg *c, char *why, size_t wn) {
    int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) { snprintf(why, wn, "/dev/net/tun: %s", strerror(errno)); return -1; }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    snprintf(ifr.ifr_name, IFNAMSIZ, "%.15s", c->dev);
    if (ioctl(fd, TUNSETIFF, &ifr) != 0) {
        snprintf(why, wn, "TUN %s не создан: %s", c->dev, strerror(errno));
        close(fd);
        return -1;
    }
    int s = ifreq_sock(AF_INET);
    if (s < 0) { close(fd); return -1; }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%.15s", c->dev);
    ifr.ifr_mtu = WB_MQ_MTU;
    ioctl(s, SIOCSIFMTU, &ifr);
    char a[48];
    snprintf(a, sizeof(a), "%s", c->v4);
    a[strcspn(a, "/")] = '\0';
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    sin->sin_family = AF_INET;
    if (inet_pton(AF_INET, a, &sin->sin_addr) == 1) {
        ioctl(s, SIOCSIFADDR, &ifr);
        inet_pton(AF_INET, "255.255.255.255", &sin->sin_addr);
        ioctl(s, SIOCSIFNETMASK, &ifr);
    }
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%.15s", c->dev);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    int idx = (int)if_nametoindex(c->dev);
    close(s);
    char a6[64];
    snprintf(a6, sizeof(a6), "%s", c->v6);
    a6[strcspn(a6, "/")] = '\0';
    struct in6_ifreq r6;
    memset(&r6, 0, sizeof(r6));
    if (a6[0] && idx > 0 && inet_pton(AF_INET6, a6, &r6.ifr6_addr) == 1 && (s = ifreq_sock(AF_INET6)) >= 0) {
        r6.ifr6_prefixlen = 128;
        r6.ifr6_ifindex = idx;
        ioctl(s, SIOCSIFADDR, &r6);
        close(s);
    }
    return fd;
}

static void tun_ip(void *u, const uint8_t *p, size_t n) {
    struct wb_mq *t = u;
    if (write(t->tun, p, n) < 0) { /* очередь TUN полна — пакет теряется, как на любой линии */ }
}

static void *mq_thread(void *arg) {
    struct wb_mq *t = arg;
    long delay = 1000;
    uint8_t pkt[2 + 65536];
    while (!t->stop) {
        struct wb_mq_cfg c;
        pthread_mutex_lock(&t->mu);
        c = t->cfg;
        t->retarget = 0;
        pthread_mutex_unlock(&t->mu);
        char why[160] = "";
        t->m.on_ip = tun_ip;
        t->m.u = t;
        if (mq_open(&t->m, &c, why, sizeof(why)) != 0) {
            pthread_mutex_lock(&t->mu);
            snprintf(t->why, sizeof(t->why), "%s", why);
            pthread_mutex_unlock(&t->mu);
        } else {
            int ep = epoll_create1(EPOLL_CLOEXEC);
            struct epoll_event e = { .events = EPOLLIN };
            e.data.u32 = 1; epoll_ctl(ep, EPOLL_CTL_ADD, qc_fd(t->m.q), &e);
            e.data.u32 = 2; epoll_ctl(ep, EPOLL_CTL_ADD, t->tun, &e);
            e.data.u32 = 3; epoll_ctl(ep, EPOLL_CTL_ADD, t->ev, &e);
            long up_at = 0;
            while (!t->stop && !t->retarget && t->m.state >= 0) {
                int was = t->m.state;
                struct epoll_event ev[8];
                int to = qc_timeout_ms(t->m.q);
                int n = epoll_wait(ep, ev, 8, to < 0 ? 1000 : to);
                if (n < 0 && errno != EINTR) break;
                if (n == 0) qc_on_timer(t->m.q);
                for (int i = 0; i < n; i++) {
                    if (ev[i].data.u32 == 1) qc_on_readable(t->m.q);
                    else if (ev[i].data.u32 == 3) { uint64_t x; if (read(t->ev, &x, sizeof(x)) < 0) {} }
                    else if (ev[i].data.u32 == 2) {
                        /* Пакеты из TUN — до 64 за раз; до приёма CONNECT — выбрасываются. */
                        for (int k = 0; k < 64; k++) {
                            ssize_t r = read(t->tun, pkt + 2, sizeof(pkt) - 2);
                            if (r <= 0) break;
                            if (t->m.state != 2) continue;
                            pkt[0] = (uint8_t)t->m.qsid;
                            pkt[1] = 0x00;
                            qc_datagram_send(t->m.q, pkt, (size_t)r + 2);
                        }
                    }
                }
                if (t->m.state == 2 && was != 2) {
                    up_at = mono_ms();
                    t->up = 1;
                    pthread_mutex_lock(&t->mu);
                    t->why[0] = '\0';
                    pthread_mutex_unlock(&t->mu);
                }
            }
            t->up = 0;
            pthread_mutex_lock(&t->mu);
            if (t->m.why[0]) snprintf(t->why, sizeof(t->why), "%s", t->m.why);
            pthread_mutex_unlock(&t->mu);
            close(ep);
            if (t->m.state >= 0) qc_close(t->m.q, 0x0100);
            qc_free(t->m.q);
            t->m.q = NULL;
            if (up_at && mono_ms() - up_at > 60000) delay = 1000;   /* держался минуту — пауза с начала */
        }
        if (t->stop) break;
        if (t->retarget) { delay = 1000; continue; }
        /* Пауза переподключения — с пробуждением по остановке и новой точке. */
        struct pollfd p = { t->ev, POLLIN, 0 };
        if (poll(&p, 1, (int)delay) > 0) { uint64_t x; if (read(t->ev, &x, sizeof(x)) < 0) {} }
        delay = delay * 2 > 30000 ? 30000 : delay * 2;
    }
    return NULL;
}

int wb_mq_start(const struct wb_mq_cfg *c, struct wb_mq **out, char *why, size_t wn) {
    struct wb_mq *t = calloc(1, sizeof(*t));
    if (!t) { snprintf(why, wn, "нет памяти"); return -1; }
    t->cfg = *c;
    pthread_mutex_init(&t->mu, NULL);
    t->ev = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    t->tun = t->ev >= 0 ? tun_open(c, why, wn) : -1;
    if (t->tun < 0) {
        if (t->ev >= 0) close(t->ev);
        free(t);
        return -1;
    }
    if (pthread_create(&t->th, NULL, mq_thread, t) != 0) {
        snprintf(why, wn, "поток туннеля не запустился");
        close(t->tun);
        close(t->ev);
        free(t);
        return -1;
    }
    *out = t;
    return 0;
}

static void kick(struct wb_mq *t) {
    uint64_t one = 1;
    if (write(t->ev, &one, sizeof(one)) < 0) {}
}

void wb_mq_retarget(struct wb_mq *t, const char *ep, unsigned port) {
    pthread_mutex_lock(&t->mu);
    snprintf(t->cfg.ep, sizeof(t->cfg.ep), "%s", ep);
    t->cfg.port = port;
    t->retarget = 1;
    pthread_mutex_unlock(&t->mu);
    kick(t);
}

int wb_mq_up(struct wb_mq *t, char *why, size_t wn) {
    pthread_mutex_lock(&t->mu);
    if (why && wn) snprintf(why, wn, "%s", t->why);
    pthread_mutex_unlock(&t->mu);
    return t->up;
}

void wb_mq_stop(struct wb_mq *t) {
    if (!t) return;
    t->stop = 1;
    kick(t);
    pthread_join(t->th, NULL);
    close(t->tun);
    close(t->ev);
    pthread_mutex_destroy(&t->mu);
    memset(t->cfg.priv, 0, sizeof(t->cfg.priv));
    free(t);
}
