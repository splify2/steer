/* Дайлер vmess (AEAD-заголовок, alterId 0). Эталон — v2fly/v2ray-core (proxy/vmess, common/crypto).
 * Поток и UDP поверх того же транспорта, что vless (TLS + tcp/ws/grpc/xhttp/httpupgrade).
 *
 * Запрос: AuthID(16) ‖ зашифрованная длина заголовка(2+16) ‖ nonce соединения(8) ‖ зашифрованный
 * заголовок (ключ/IV тела, команда, адрес, FNV1a). Тело — ChunkStream с ChunkMasking: каждый кусок
 * [длина(2) XOR маска SHAKE128(IV)][нагрузка+тег AEAD], nonce = счётчик(2) ‖ IV[2:12]. Ответ —
 * свой AEAD-заголовок (проверяем эхо байта V) и такие же куски на ключах SHA256(ключ/IV тела).
 * UDP (команда 2): каждая датаграмма — один кусок. Шифр тела — aes-128-gcm или chacha20-poly1305
 * (auto = aes-128-gcm); none/zero не поддержаны (pxsub). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/random.h>

#include "pxdial.h"
#include "pxwire.h"
#include "stack.h"
#include "scrypto.h"

#define VM_CHUNK 0x3FEF                  /* нагрузки в куске: < 0x3FFF - 16 */
enum { RH_LEN = 0, RH_HDR, RH_BODY };

struct vmess_sess {
    uint8_t header_sent;
    uint8_t udp;
    uint8_t sec;                         /* 3 aes-128-gcm, 4 chacha20-poly1305 */
    uint8_t respv;
    uint8_t rx;
    uint8_t has_benc, has_bdec, has_smask, has_rmask;
    uint16_t send_count, recv_count;
    uint32_t dst; uint16_t dport;
    unsigned char biv[16], riv[16];
    struct sc_aead benc, bdec;
    struct sc_shake smask, rmask;
    unsigned char rkey_len[16], riv_len[12], rkey[16], riv_k[12];
    size_t acc_n, want;
    struct transport t;
    unsigned char acc[0x4000 + 32];
};

static const char *vm_peer(const void *ctx) { return ((const struct px_node *)ctx)->vn.host; }
static void vm_describe(const void *ctx, char *out, size_t n) {
    const struct px_node *nd = ctx;
    snprintf(out, n, "%s (%s:%u vmess %s/%s)", nd->name, nd->vn.host, nd->vn.port,
             nd->vn.security, nd->vn.type);
}

static enum sc_aead_alg vm_alg(uint8_t sec) {
    return sec == 4 ? SC_CHACHA20_POLY1305 : SC_AES128_GCM;
}

/* Ключ тела: aes — 16 байт как есть; chacha — MD5(k) ‖ MD5(MD5(k)) = 32. */
static void vm_bodykey(uint8_t sec, const unsigned char k16[16], unsigned char out[32], size_t *n) {
    if (sec == 4) {
        sc_hash(SC_MD5, k16, 16, out);
        sc_hash(SC_MD5, out, 16, out + 16);
        *n = 32;
    } else {
        memcpy(out, k16, 16);
        *n = 16;
    }
}

static void vm_clear(void *sess) {
    struct vmess_sess *s = sess;
    s->header_sent = 0;
    s->rx = RH_LEN;
    s->send_count = s->recv_count = 0;
    s->has_benc = s->has_bdec = s->has_smask = s->has_rmask = 0;
    s->acc_n = 0; s->want = 2 + 16;
    s->t.link.fd = -1;
}

static int vm_flow_open(const void *ctx, void *sess, const struct flow_key *k, int udp) {
    const struct px_node *n = ctx;
    struct vmess_sess *s = sess;
    s->udp = (uint8_t)udp;
    s->dst = k->dst; s->dport = k->dport;
    s->sec = n->vmess_sec == VMESS_CHACHA20_POLY1305 ? 4 : 3;   /* auto и aes → 3 */
    return 0;
}

static int vm_connect(const void *ctx, void *sess, int timeout_s) {
    struct vmess_sess *s = sess;
    int rc = px_stream_open(ctx, &s->t, timeout_s);
    return rc;
}
static void vm_take(void *dst, void *src) {
    struct vmess_sess *d = dst, *s = src;
    memcpy(&d->t, &s->t, sizeof(d->t));
    transport_moved(&d->t);
}
static void vm_close(void *sess) {
    struct vmess_sess *s = sess;
    transport_close(&s->t);
    if (s->has_benc) { sc_aead_free(&s->benc); s->has_benc = 0; }
    if (s->has_bdec) { sc_aead_free(&s->bdec); s->has_bdec = 0; }
    if (s->has_smask) { sc_shake128_free(&s->smask); s->has_smask = 0; }
    if (s->has_rmask) { sc_shake128_free(&s->rmask); s->has_rmask = 0; }
}
static int vm_fd(const void *sess) { return transport_fd(&((const struct vmess_sess *)sess)->t); }
static int vm_has_data(const void *sess) { return transport_has_data(&((const struct vmess_sess *)sess)->t); }

/* Собрать заголовок запроса; настроить ключи тела и разбора ответа. Возвращает длину wire. */
static size_t vm_build_request(const struct px_node *n, struct vmess_sess *s,
                               unsigned char *out, size_t cap) {
    /* Повтор после закрытого окна HTTP/2: освободить прежние контексты, иначе setkey ниже их теряет. */
    if (s->has_benc) { sc_aead_free(&s->benc); s->has_benc = 0; }
    if (s->has_bdec) { sc_aead_free(&s->bdec); s->has_bdec = 0; }
    if (s->has_smask) { sc_shake128_free(&s->smask); s->has_smask = 0; }
    if (s->has_rmask) { sc_shake128_free(&s->rmask); s->has_rmask = 0; }
    s->send_count = s->recv_count = 0;
    s->rx = RH_LEN; s->acc_n = 0; s->want = 2 + 16;
    unsigned char cmdkey[16], bodykey[16], bodyiv[16], rnd[4 + 8 + 1];
    if (getrandom(rnd, sizeof rnd, 0) != (ssize_t)sizeof rnd) return 0;
    if (getrandom(bodykey, 16, 0) != 16 || getrandom(bodyiv, 16, 0) != 16) return 0;
    const unsigned char *rand4 = rnd, *connnonce = rnd + 4;
    s->respv = rnd[12];
    px_vmess_cmdkey(n->vmess_id, cmdkey);

    unsigned char H[49];
    H[0] = 1;
    memcpy(H + 1, bodyiv, 16);
    memcpy(H + 17, bodykey, 16);
    H[33] = s->respv;
    H[34] = 0x05;                        /* ChunkStream | ChunkMasking */
    H[35] = (unsigned char)s->sec;       /* paddingLen 0 | security */
    H[36] = 0;
    H[37] = s->udp ? 2 : 1;
    H[38] = (unsigned char)(s->dport >> 8); H[39] = (unsigned char)s->dport;
    H[40] = 1;                            /* ATYP IPv4 */
    memcpy(H + 41, &s->dst, 4);
    uint32_t f = px_fnv1a(H, 45);
    H[45] = (unsigned char)(f >> 24); H[46] = (unsigned char)(f >> 16);
    H[47] = (unsigned char)(f >> 8); H[48] = (unsigned char)f;

    unsigned char authid[16];
    px_vmess_authid(cmdkey, (uint64_t)time(NULL), rand4, authid);

    struct px_kdf_path pl[3] = { { NULL, 0 }, { authid, 16 }, { connnonce, 8 } };
    unsigned char lenkey[16], lennonce[12], hdrkey[16], hdrnonce[12];
    pl[0].p = (const unsigned char *)"VMess Header AEAD Key_Length"; pl[0].n = 28;
    px_vmess_kdf(cmdkey, pl, 3, lenkey, 16);
    pl[0].p = (const unsigned char *)"VMess Header AEAD Nonce_Length"; pl[0].n = 30;
    px_vmess_kdf(cmdkey, pl, 3, lennonce, 12);
    pl[0].p = (const unsigned char *)"VMess Header AEAD Key"; pl[0].n = 21;
    px_vmess_kdf(cmdkey, pl, 3, hdrkey, 16);
    pl[0].p = (const unsigned char *)"VMess Header AEAD Nonce"; pl[0].n = 23;
    px_vmess_kdf(cmdkey, pl, 3, hdrnonce, 12);

    if (cap < 16u + 18u + 8u + sizeof(H) + 16u) return 0;
    size_t o = 0;
    memcpy(out + o, authid, 16); o += 16;
    /* зашифрованная длина заголовка */
    /* Каждый отказ слоя (ключ не развернулся, SHAKE не завёлся) — отказ запроса (0 → SEND_FATAL):
     * дальше на провод ушли бы байты под неинициализированным ключом или маской длины. */
    struct sc_aead a;
    unsigned char lenpt[2] = { (unsigned char)(sizeof(H) >> 8), (unsigned char)sizeof(H) };
    if (sc_aead_setkey(&a, SC_AES128_GCM, lenkey) != 0) return 0;
    int sr = sc_aead_seal(&a, lennonce, authid, 16, lenpt, 2, out + o + 2);
    sc_aead_free(&a);
    if (sr != 0) return 0;
    memcpy(out + o, lenpt, 2); o += 2 + 16;
    memcpy(out + o, connnonce, 8); o += 8;
    /* зашифрованный заголовок */
    if (sc_aead_setkey(&a, SC_AES128_GCM, hdrkey) != 0) return 0;
    memcpy(out + o, H, sizeof H);
    sr = sc_aead_seal(&a, hdrnonce, authid, 16, out + o, sizeof H, out + o + sizeof H);
    sc_aead_free(&a);
    if (sr != 0) return 0;
    o += sizeof(H) + 16;

    /* Ключи тела (send) и ответа (recv). */
    unsigned char bk[32]; size_t bkn;
    vm_bodykey(s->sec, bodykey, bk, &bkn);
    if (sc_aead_setkey(&s->benc, vm_alg(s->sec), bk) != 0) return 0;
    s->has_benc = 1;
    memcpy(s->biv, bodyiv, 16);
    if (sc_shake128_init(&s->smask, bodyiv, 16) != 0) return 0;
    s->has_smask = 1;

    unsigned char rbk[16], rbiv[16], rbk32[32], full[32]; size_t rbkn;
    sc_hash(SC_SHA256, bodykey, 16, full); memcpy(rbk, full, 16);   /* respBodyKey = SHA256(bodyKey)[:16] */
    sc_hash(SC_SHA256, bodyiv, 16, full); memcpy(rbiv, full, 16);   /* respBodyIV  = SHA256(bodyIV)[:16] */
    vm_bodykey(s->sec, rbk, rbk32, &rbkn);
    if (sc_aead_setkey(&s->bdec, vm_alg(s->sec), rbk32) != 0) return 0;
    s->has_bdec = 1;
    memcpy(s->riv, rbiv, 16);
    if (sc_shake128_init(&s->rmask, rbiv, 16) != 0) return 0;
    s->has_rmask = 1;

    struct px_kdf_path rp[1];
    rp[0].p = (const unsigned char *)"AEAD Resp Header Len Key"; rp[0].n = 24;
    px_vmess_kdf(rbk, rp, 1, s->rkey_len, 16);
    rp[0].p = (const unsigned char *)"AEAD Resp Header Len IV"; rp[0].n = 23;
    px_vmess_kdf(rbiv, rp, 1, s->riv_len, 12);
    rp[0].p = (const unsigned char *)"AEAD Resp Header Key"; rp[0].n = 20;
    px_vmess_kdf(rbk, rp, 1, s->rkey, 16);
    rp[0].p = (const unsigned char *)"AEAD Resp Header IV"; rp[0].n = 19;
    px_vmess_kdf(rbiv, rp, 1, s->riv_k, 12);
    (void)rbkn;
    return o;
}

/* Один кусок тела в out. nonce = счётчик(2 BE) ‖ IV[2:12], длина XOR маска SHAKE. */
static size_t vm_seal_chunk(struct vmess_sess *s, const unsigned char *p, size_t n,
                            unsigned char *out) {
    unsigned char nonce[12];
    nonce[0] = (unsigned char)(s->send_count >> 8); nonce[1] = (unsigned char)s->send_count;
    memcpy(nonce + 2, s->biv + 2, 10);
    size_t L = n + 16;
    unsigned char mask[2];
    sc_shake128_read(&s->smask, mask, 2);
    out[0] = (unsigned char)((L >> 8) ^ mask[0]);
    out[1] = (unsigned char)(L ^ mask[1]);
    memcpy(out + 2, p, n);
    sc_aead_seal(&s->benc, nonce, NULL, 0, out + 2, n, out + 2 + n);
    s->send_count++;
    return 2 + L;
}

static int vm_send(const void *ctx, void *sess, const struct flow_key *k, int udp,
                   const unsigned char *data, size_t n) {
    (void)k;
    struct vmess_sess *s = sess;
    static __thread unsigned char out[TUNNEL_BUF];
    size_t o = 0;
    if (!s->header_sent) {
        o = vm_build_request(ctx, s, out, sizeof out);
        if (!o) return SEND_FATAL;
    }
    if (udp) {
        /* data — [длина(2)][датаграмма]… — каждая отдельным куском. */
        const unsigned char *p = data; size_t left = n;
        while (left >= 2) {
            size_t dl = ((size_t)p[0] << 8) | p[1];
            p += 2; left -= 2;
            if (dl > left || dl > VM_CHUNK) return SEND_FATAL;
            if (o + 2 + dl + 16 > sizeof out) {
                if (transport_write(&s->t, out, o)) return SEND_FATAL;
                o = 0;
            }
            o += vm_seal_chunk(s, p, dl, out + o);
            p += dl; left -= dl;
        }
        if (left) return SEND_FATAL;
    } else {
        while (n) {
            size_t t = n > VM_CHUNK ? VM_CHUNK : n;
            if (o + 2 + t + 16 > sizeof out) {
                if (transport_write(&s->t, out, o)) return SEND_FATAL;
                o = 0;
            }
            o += vm_seal_chunk(s, data, t, out + o);
            data += t; n -= t;
        }
    }
    int rc = o ? transport_write(&s->t, out, o) : 0;
    if (rc == H2_EWINDOW) { if (!s->header_sent) return SEND_AGAIN; return SEND_AGAIN; }
    if (rc) return SEND_FATAL;
    s->header_sent = 1;
    return SEND_OK;
}

static size_t vm_dgram_frame(const unsigned char *p, size_t n, unsigned char *out, size_t cap) {
    if (n > UDP_DGRAM_MAX || 2 + n > cap) return 0;
    out[0] = (unsigned char)(n >> 8); out[1] = (unsigned char)n;
    memcpy(out + 2, p, n);
    return 2 + n;
}

/* Вход режется так, чтобы за проход стеку ушло не больше cap байт: расшифровка отдаёт недобранный
 * кусок прошлого прохода (acc_n) плюс всё прочитанное сейчас, а место в кольце повтора стек
 * проверяет ровно под cap. Подробнее — ss_take_limit в pxss.c. Кусок vmess не больше 0x4000 —
 * сам в cap помещается, держать остаток незачем. */
static int vm_read(void *sess, unsigned char *buf, size_t cap, const unsigned char **data, size_t *got) {
    struct vmess_sess *s = sess;
    *data = buf;
    size_t lim = cap > s->acc_n ? cap - s->acc_n : 1;
    return transport_read(&s->t, buf, lim, got);
}

static int vm_deliver(const void *ctx, void *sess, int udp, const unsigned char *d, size_t len,
                      dialer_emit_fn emit, void *arg) {
    (void)ctx; (void)udp;
    struct vmess_sess *s = sess;
    while (len) {
        size_t need = s->want - s->acc_n;
        size_t take = len < need ? len : need;
        if (s->acc_n + take > sizeof s->acc) return -1;
        memcpy(s->acc + s->acc_n, d, take);
        s->acc_n += take; d += take; len -= take;
        if (s->acc_n < s->want) return 0;
        if (s->rx == RH_LEN) {
            struct sc_aead a;
            sc_aead_setkey(&a, SC_AES128_GCM, s->rkey_len);
            int rc = sc_aead_open(&a, s->riv_len, NULL, 0, s->acc, 2, s->acc + 2);
            sc_aead_free(&a);
            if (rc) return -1;
            s->want = (((size_t)s->acc[0] << 8) | s->acc[1]) + 16;
            s->acc_n = 0;
            s->rx = RH_HDR;
        } else if (s->rx == RH_HDR) {
            struct sc_aead a;
            size_t hl = s->want - 16;
            sc_aead_setkey(&a, SC_AES128_GCM, s->rkey);
            int rc = sc_aead_open(&a, s->riv_k, NULL, 0, s->acc, hl, s->acc + hl);
            sc_aead_free(&a);
            if (rc || hl < 1 || s->acc[0] != s->respv) return -1;
            s->acc_n = 0;
            s->rx = RH_BODY;
            s->want = 2;                 /* длина первого куска */
        } else if (s->want == 2) {       /* RH_BODY: длина куска */
            unsigned char mask[2];
            sc_shake128_read(&s->rmask, mask, 2);
            size_t L = (((size_t)(s->acc[0] ^ mask[0])) << 8) | (s->acc[1] ^ mask[1]);
            if (L < 16 || L > sizeof s->acc) return -1;
            s->acc_n = 0;
            s->want = L;
        } else {                         /* RH_BODY: нагрузка куска */
            unsigned char nonce[12];
            nonce[0] = (unsigned char)(s->recv_count >> 8); nonce[1] = (unsigned char)s->recv_count;
            memcpy(nonce + 2, s->riv + 2, 10);
            size_t pl = s->want - 16;
            if (sc_aead_open(&s->bdec, nonce, NULL, 0, s->acc, pl, s->acc + pl) != 0) return -1;
            s->recv_count++;
            if (pl && emit(arg, s->acc, pl) != 0) return -1;
            s->acc_n = 0;
            s->want = 2;
        }
    }
    return 0;
}

const struct dialer_ops proxy_vmess_dialer = {
    .name = "vmess",
    .caps = DC_PRECONNECT,
    .sess_size = sizeof(struct vmess_sess),
    .peer = vm_peer, .describe = vm_describe, .strerror = px_strerror,
    .connect = vm_connect, .take = vm_take, .close = vm_close, .clear = vm_clear,
    .fd = vm_fd, .has_data = vm_has_data,
    .flow_open = vm_flow_open, .send = vm_send, .dgram_frame = vm_dgram_frame,
    .read = vm_read, .deliver = vm_deliver,
};
