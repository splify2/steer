#include "dnsd_int.h"

/* ---------------------------------------------------------------------- */
/* DNS wire-format parsing (read-only; never mutates the packet)          */
/* ---------------------------------------------------------------------- */

/* Decodes a (possibly compressed) name starting at pos into out (dot-joined,
 * NUL terminated), and returns via *next the stream position right after the
 * name (following RFC1035 compression-pointer semantics: only the FIRST
 * pointer counts toward the caller's next-field offset). */
static int parse_name_adv(const uint8_t *pkt, size_t len, size_t pos, char *out,
                           size_t outlen, size_t *next) {
    size_t start = pos;
    size_t opos = 0;
    int jumps = 0;
    size_t cursor = pos;
    size_t advance_to = 0;
    int pointer_taken = 0;

    for (;;) {
        if (cursor >= len) return -1;
        uint8_t lbl = pkt[cursor];
        if (lbl == 0) {
            if (!pointer_taken) advance_to = cursor + 1;
            break;
        }
        if ((lbl & 0xC0) == 0xC0) {
            if (cursor + 1 >= len) return -1;
            size_t target = ((size_t)(lbl & 0x3F) << 8) | pkt[cursor + 1];
            if (!pointer_taken) {
                advance_to = cursor + 2;
                pointer_taken = 1;
            }
            if (++jumps > 32) return -1;
            cursor = target;
            continue;
        }
        if ((lbl & 0xC0) != 0) return -1;
        size_t label_len = lbl;
        cursor++;
        if (cursor + label_len > len) return -1;
        if (opos + label_len + 1 >= outlen) return -1;
        if (opos > 0) out[opos++] = '.';
        memcpy(out + opos, pkt + cursor, label_len);
        opos += label_len;
        cursor += label_len;
    }
    out[opos] = '\0';
    (void)start;
    *next = advance_to;
    return 0;
}

/* Parses a DNS response: extracts the question name (out_qname), question
 * type (out_qtype), the stream offset right after the question section
 * (out_qend — the header[0,12) + question[12,*out_qend) prefix is byte-
 * identical between the real response and anything we build to replace it,
 * so callers can reuse it verbatim), and every A-record (class IN) answer
 * IP+TTL, up to max_ips entries. Only correct for qdcount==1 (universally
 * true for a resolver's own queries) — anything else is treated as
 * unparseable. Returns the number of A-record IPs found, or -1 on a
 * malformed/short/multi-question packet (caller must still relay the raw
 * bytes to the client regardless). */
/* Записи AAAA (класс IN) — в ips6, до max_ips6, их число — в *n6 (fake-IP v6 и real-ip v6,
 * docs/architecture.md, «4б»); ips6 == NULL — не собираются. Возвращаемое значение по-прежнему
 * считает только A. */
int parse_response(const uint8_t *pkt, size_t len, char *out_qname,
                    size_t qname_len, uint16_t *out_qtype,
                    size_t *out_qend, struct answer_ip *ips,
                    int max_ips, struct answer_ip6 *ips6, int max_ips6, int *n6) {
    if (n6) *n6 = 0;
    if (len < 12) return -1;
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    uint16_t ancount = (pkt[6] << 8) | pkt[7];

    size_t pos = 12;
    if (qdcount != 1) return -1;

    size_t next = 0;
    if (parse_name_adv(pkt, len, pos, out_qname, qname_len, &next) != 0)
        return -1;
    pos = next;
    if (pos + 4 > len) return -1;
    *out_qtype = (uint16_t)((pkt[pos] << 8) | pkt[pos + 1]);
    pos += 4; /* qtype + qclass */
    *out_qend = pos;

    int found = 0;
    for (uint16_t a = 0; a < ancount && pos < len; a++) {
        char rrname[MAX_HOSTNAME];
        if (parse_name_adv(pkt, len, pos, rrname, sizeof(rrname), &next) != 0)
            break;
        pos = next;
        if (pos + 10 > len) break;
        uint16_t rtype = (pkt[pos] << 8) | pkt[pos + 1];
        uint16_t rclass = (pkt[pos + 2] << 8) | pkt[pos + 3];
        uint32_t ttl = ((uint32_t)pkt[pos + 4] << 24) | ((uint32_t)pkt[pos + 5] << 16) |
                       ((uint32_t)pkt[pos + 6] << 8) | pkt[pos + 7];
        uint16_t rdlen = (pkt[pos + 8] << 8) | pkt[pos + 9];
        pos += 10;
        if (pos + rdlen > len) break;
        if (rtype == DNS_TYPE_A && rclass == 1 /* IN */ && rdlen == 4 &&
            found < max_ips) {
            uint32_t addr;
            memcpy(&addr, pkt + pos, 4);
            ips[found].addr = addr;
            ips[found].ttl = ttl;
            found++;
        }
        if (rtype == DNS_TYPE_AAAA && rclass == 1 && rdlen == 16 && ips6 && n6 &&
            *n6 < max_ips6) {
            memcpy(ips6[*n6].addr, pkt + pos, 16);
            ips6[*n6].ttl = ttl;
            (*n6)++;
        }
        pos += rdlen;
    }
    return found;
}

/* Разбор ВОПРОСА клиентского запроса: имя, тип, конец секции вопроса. Той же
 * механикой, что parse_response, но на пути «клиент → upstream», где ответа ещё
 * нет. Не-запрос (QR=1), не один вопрос или мусор — -1: вызывающий пересылает
 * пакет наверх как раньше, быстрый путь просто не срабатывает. */
int parse_query(const uint8_t *pkt, size_t len, char *out_qname,
                 size_t qname_len, uint16_t *out_qtype, size_t *out_qend) {
    if (len < 12) return -1;
    if (pkt[2] & 0x80) return -1;               /* QR: это уже ответ */
    uint16_t qdcount = (pkt[4] << 8) | pkt[5];
    if (qdcount != 1) return -1;
    size_t next = 0;
    if (parse_name_adv(pkt, len, 12, out_qname, qname_len, &next) != 0) return -1;
    if (next + 4 > len) return -1;
    *out_qtype = (uint16_t)((pkt[next] << 8) | pkt[next + 1]);
    *out_qend = next + 4;
    return 0;
}

/* Есть ли в запросе опция EDNS «не пересылать» (DNSD_OPT_NOFORWARD, dnsd_int.h). Ищется в записи
 * OPT дополнительной секции — сразу за вопросом (qend): в запросе секций ответа и полномочий нет.
 * Испорченная запись — «нет»: тогда вопрос идёт прежним путём. */
int query_noforward(const uint8_t *pkt, size_t len, size_t qend) {
    if (len < 12 || ((pkt[6] | pkt[7] | pkt[8] | pkt[9]) != 0)) return 0;
    unsigned ar = (unsigned)((pkt[10] << 8) | pkt[11]);
    size_t p = qend;
    for (unsigned i = 0; i < ar; i++) {
        if (p + 11 > len) return 0;
        if (pkt[p] != 0) return 0;                      /* имя OPT — корень */
        uint16_t type = (uint16_t)((pkt[p + 1] << 8) | pkt[p + 2]);
        uint16_t rdlen = (uint16_t)((pkt[p + 9] << 8) | pkt[p + 10]);
        size_t rd = p + 11;
        if (rd + rdlen > len) return 0;
        if (type == 41) {
            for (size_t o = rd; o + 4 <= rd + rdlen;) {
                uint16_t code = (uint16_t)((pkt[o] << 8) | pkt[o + 1]);
                uint16_t ol = (uint16_t)((pkt[o + 2] << 8) | pkt[o + 3]);
                if (code == DNSD_OPT_NOFORWARD) return 1;
                o += 4 + ol;
            }
        }
        p = rd + rdlen;
    }
    return 0;
}

/* Ответ, собранный из ЗАПРОСА, обязан сам выставить флаги ответа — в отличие от
 * ответа, собранного из ответа upstream, где они уже стоят. QR — это ответ; opcode
 * и RD переносятся из запроса; RA — рекурсию даёт upstream, и мы отвечаем за него;
 * AA/TC/RCODE — нули. */
void make_response_flags(uint8_t *pkt) {
    pkt[2] = (uint8_t)(0x80 | (pkt[2] & 0x79));
    pkt[3] = 0x80;
}

/* Builds a reply reusing the original response's header+question bytes
 * verbatim ([0, qend) — same transaction ID, same echoed question), with
 * ancount/nscount/arcount patched and (if with_answer) exactly one A record
 * appended pointing at fake_addr_host. nscount/arcount are always zeroed:
 * dropping any authority/additional section (e.g. an upstream EDNS OPT
 * record) is fine, our substitute answer is tiny and needs neither. Returns
 * the built length, or 0 if it wouldn't fit (defensive only — qend is
 * bounded by MAX_HOSTNAME and the answer is a fixed 16 bytes, so this never
 * actually happens with out_cap sized as callers use it below). */
size_t build_rewritten_response(const uint8_t *orig, size_t qend,
                                 uint8_t *out, size_t out_cap,
                                 int with_answer, uint32_t fake_addr_host) {
    if (qend > out_cap) return 0;
    memcpy(out, orig, qend);
    /* Флаги — здесь, в единственном сборщике: путь из ответа upstream копировал их как есть,
     * и клиент видел TC (переспрашивал по TCP:53 мимо заворота — реальный адрес мимо туннеля)
     * и AD на неподписанном синтетическом ответе. */
    make_response_flags(out);
    out[6] = 0; out[7] = with_answer ? 1 : 0;               /* ancount */
    out[8] = 0; out[9] = 0; out[10] = 0; out[11] = 0;       /* nscount, arcount */

    size_t pos = qend;
    if (with_answer) {
        if (pos + 16 > out_cap) return 0;
        out[pos++] = 0xC0; out[pos++] = 0x0C; /* name: pointer to question @ offset 12 */
        out[pos++] = 0x00; out[pos++] = 0x01; /* type A */
        out[pos++] = 0x00; out[pos++] = 0x01; /* class IN */
        out[pos++] = 0x00; out[pos++] = 0x00;
        out[pos++] = 0x00; out[pos++] = FAKEIP_ANSWER_TTL;  /* ttl (fits in one byte) */
        out[pos++] = 0x00; out[pos++] = 0x04;               /* rdlength */
        uint32_t addr_net = htonl(fake_addr_host);
        memcpy(out + pos, &addr_net, 4);
        pos += 4;
    }
    return pos;
}

/* Убрать из адресов ответа пустые (0.0.0.0, ::): так отвечает апстрим, блокирующий имя. Возврат —
 * сколько адресов осталось; 0 — ответ состоял из одних пустых. */
int answer_drop_empty4(struct answer_ip *ips, int n) {
    int w = 0;
    for (int k = 0; k < n; k++)
        if (ips[k].addr) ips[w++] = ips[k];
    return w;
}

int answer_drop_empty6(struct answer_ip6 *ips, int n) {
    static const uint8_t zero6[16];
    int w = 0;
    for (int k = 0; k < n; k++)
        if (memcmp(ips[k].addr, zero6, 16)) ips[w++] = ips[k];
    return w;
}

/* То же с одной записью AAAA — поддельным адресом IPv6 (fake-IP v6). Голова и вопрос — как у
 * build_rewritten_response, запись — 28 байт. */
size_t build_rewritten_response6(const uint8_t *orig, size_t qend,
                                  uint8_t *out, size_t out_cap, const uint8_t fake6[16]) {
    size_t pos = build_rewritten_response(orig, qend, out, out_cap, 0, 0);
    if (!pos || pos + 28 > out_cap) return 0;
    out[7] = 1;                                              /* ancount */
    out[pos++] = 0xC0; out[pos++] = 0x0C;
    out[pos++] = 0x00; out[pos++] = DNS_TYPE_AAAA;
    out[pos++] = 0x00; out[pos++] = 0x01;
    out[pos++] = 0x00; out[pos++] = 0x00;
    out[pos++] = 0x00; out[pos++] = FAKEIP_ANSWER_TTL;
    out[pos++] = 0x00; out[pos++] = 0x10;                    /* rdlength 16 */
    memcpy(out + pos, fake6, 16);
    pos += 16;
    return pos;
}
