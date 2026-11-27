#ifndef STEER_TLS13_OFFERED_H
#define STEER_TLS13_OFFERED_H

/* Private, borrowed views into the exact unmodified ClientHello transcript.
 * The caller keeps that byte array alive through negotiation/authentication.
 * No crypto state, allocation or public TLS ABI storage is involved. */
struct tls13_offered {
    const unsigned char *session, *suites, *shares, *alpn, *signatures;
    size_t session_n, suites_n, shares_n, alpn_n, signatures_n;
};
static size_t offer_u16(const unsigned char *p) { return (size_t)p[0] << 8 | p[1]; }
static int offer_has_u16(const unsigned char *p, size_t n, unsigned value) {
    for (size_t i = 0; i + 1 < n; i += 2) if (offer_u16(p + i) == value) return 1;
    return 0;
}
static int offer_has_alpn(const struct tls13_offered *o, const unsigned char *p, size_t n) {
    size_t at = 0;
    while (at < o->alpn_n) {
        size_t length = o->alpn[at++];
        if (length == n && !memcmp(o->alpn + at, p, n)) return 1;
        at += length;
    }
    return 0;
}
static int parse_client_offer(const unsigned char *p, size_t n, struct tls13_offered *out) {
    struct tls13_offered o = {0}; uint16_t seen[64]; size_t count = 0, at;
    int version13 = 0;
    if (!p || n < 43 || p[0] != 1 || p[4] != 3 || p[5] != 3 ||
        (((size_t)p[1] << 16) | ((size_t)p[2] << 8) | p[3]) != n - 4 || p[38] > 32)
        return TLS13_EBADREC;
    o.session_n = p[38]; o.session = p + 39; at = 39 + o.session_n;
    if (at > n || n - at < 2) return TLS13_EBADREC;
    o.suites_n = offer_u16(p + at); at += 2;
    if (!o.suites_n || (o.suites_n & 1) || o.suites_n > n - at) return TLS13_EBADREC;
    o.suites = p + at; at += o.suites_n;
    if (n - at < 4 || p[at] != 1 || p[at + 1] != 0) return TLS13_EBADREC;
    at += 2; size_t extensions = offer_u16(p + at); at += 2;
    if (extensions != n - at) return TLS13_EBADREC;
    while (at < n) {
        if (n - at < 4 || count == 64) return TLS13_EBADREC;
        unsigned type = (unsigned)offer_u16(p + at); size_t length = offer_u16(p + at + 2); at += 4;
        if (length > n - at) return TLS13_EBADREC;
        for (size_t i = 0; i < count; i++) if (seen[i] == type) return TLS13_EBADREC;
        seen[count++] = (uint16_t)type;
        const unsigned char *body = p + at;
        if (type == 43) {
            if (length < 3 || body[0] != length - 1 || ((length - 1) & 1)) return TLS13_EBADREC;
            version13 = offer_has_u16(body + 1, length - 1, 0x0304);
        } else if (type == 51) {
            if (length < 6 || offer_u16(body) != length - 2) return TLS13_EBADREC;
            size_t cursor = 2, keys = 0;
            while (cursor < length) {
                if (length - cursor < 4 || ++keys > 64) return TLS13_EBADREC;
                size_t key_n = offer_u16(body + cursor + 2);
                if (!key_n || key_n > length - cursor - 4) return TLS13_EBADREC;
                for (size_t previous = 2; previous < cursor; previous += 4 + offer_u16(body + previous + 2))
                    if (offer_u16(body + previous) == offer_u16(body + cursor)) return TLS13_EBADREC;
                cursor += 4 + key_n;
            }
            o.shares = body + 2; o.shares_n = length - 2;
        } else if (type == 16) {
            if (length < 4 || offer_u16(body) != length - 2) return TLS13_EBADREC;
            size_t cursor = 2;
            while (cursor < length) {
                size_t protocol = body[cursor++];
                if (!protocol || protocol > length - cursor) return TLS13_EBADREC;
                cursor += protocol;
            }
            o.alpn = body + 2; o.alpn_n = length - 2;
        } else if (type == 13) {
            if (length < 4 || offer_u16(body) != length - 2 || ((length - 2) & 1)) return TLS13_EBADREC;
            o.signatures = body + 2; o.signatures_n = length - 2;
        }
        at += length;
    }
    if (!version13 || !o.shares_n || !o.signatures_n) return TLS13_EBADREC;
    *out = o; return 0;
}
static int match_server_offer(const struct tls13_offered *o, const unsigned char *p, size_t n) {
    /* ServerHello structural bounds have already been checked. */
    size_t sid = p[38], at = 39 + sid;
    if (sid != o->session_n || memcmp(p + 39, o->session, sid) ||
        !offer_has_u16(o->suites, o->suites_n, (unsigned)offer_u16(p + at))) return TLS13_EBADREC;
    at += 5;
    while (at < n) {
        unsigned type = (unsigned)offer_u16(p + at); size_t length = offer_u16(p + at + 2); at += 4;
        if (type == 51) {
            unsigned group = (unsigned)offer_u16(p + at); int found = 0;
            for (size_t share = 0; share < o->shares_n; share += 4 + offer_u16(o->shares + share + 2))
                if (offer_u16(o->shares + share) == group) found = 1;
            if (!found) return TLS13_EBADREC;
        } else if (type != 43) return TLS13_EBADREC; /* no resumption/unsolicited SH extension */
        at += length;
    }
    return 0;
}
#endif
