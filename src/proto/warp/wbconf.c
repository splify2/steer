/* Файл туннеля WARP в формате awg-quick и маски первого пакета AmneziaWG.
 *
 * Параметры обфускации — те, с которыми WARP проходит у провайдеров России (апстрим Zapret Manager,
 * MIXOMO_AWG_*): Jc=4 Jmin=40 Jmax=70, S1=S2=0, H1..H4=1..4 — заголовки сообщений WireGuard
 * остаются стандартными (их Cloudflare и ждёт), меняется только мусор перед рукопожатием и первый
 * пакет I1, похожий на QUIC/DNS/STUN/SIP. MTU 1280 — WARP шире не пропускает.
 *
 * Нет AmneziaWG в ядре — файл без этих полей, обычный WireGuard (awg_kernel_has_awg): туннель
 * поднимется, а пройдёт ли он DPI — скажет подбор. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/random.h>

#include "wbconf.h"
#include "wbmask.h"

static unsigned rnd(unsigned lo, unsigned hi) {
    unsigned v = 0;
    if (getrandom(&v, sizeof(v), 0) != sizeof(v)) v = (unsigned)getpid() * 2654435761u;
    return lo + v % (hi - lo + 1);
}

static void rnd_str(char *dst, size_t n) {
    static const char A[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    for (size_t i = 0; i < n; i++) dst[i] = A[rnd(0, sizeof(A) - 2)];
    dst[n] = '\0';
}

static void hex(char *dst, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) sprintf(dst + 2 * i, "%02x", (unsigned char)s[i]);
    dst[2 * n] = '\0';
}

static const char *const HOSTS[] = { "www.apple.com", "www.google.com", "www.microsoft.com", "cdn.jsdelivr.net" };

/* DNS-запрос A с EDNS и случайным хвостом. */
static void mask_dns(char *buf, size_t n) {
    const char *h = HOSTS[rnd(0, 3)];
    char q[256] = "", lab[64], hx[130];
    for (const char *s = h; *s;) {
        size_t l = strcspn(s, ".");
        snprintf(lab, sizeof(lab), "%.*s", (int)l, s);
        hex(hx, lab, l);
        snprintf(q + strlen(q), sizeof(q) - strlen(q), "%02zx%s", l, hx);
        s += l;
        if (*s == '.') s++;
    }
    unsigned p = rnd(60, 180);
    snprintf(buf, n, "<r 2><b 0x01000001000000000001%s0000010001000029100000000000%04x000c%04x><r %u>", q, p + 4, p, p);
}

/* STUN Binding Request с атрибутом SOFTWARE случайной длины. */
static void mask_stun(char *buf, size_t n) {
    unsigned s = rnd(4, 8) * 4;
    char str[40], hx[81];
    rnd_str(str, s);
    hex(hx, str, s);
    snprintf(buf, n, "<b 0x0001%04x2112a442><r 12><b 0x8022%04x%s>", s + 4, s, hx);
}

/* SIP OPTIONS. */
static void mask_sip(char *buf, size_t n) {
    const char *h = HOSTS[rnd(0, 3)];
    char br[11], from[9], cid[17], msg[600];
    rnd_str(br, 10);
    rnd_str(from, 8);
    rnd_str(cid, 16);
    int m = snprintf(msg, sizeof(msg),
                     "OPTIONS sip:%s SIP/2.0\r\nVia: SIP/2.0/UDP 192.168.%u.%u:5060;branch=z9hG4bK%s\r\n"
                     "From: <sip:%s@%s>;tag=%u\r\nTo: <sip:%s>\r\nCall-ID: %s@%s\r\nCSeq: %u OPTIONS\r\n"
                     "Max-Forwards: 70\r\nUser-Agent: PJSIP/2.13\r\nContent-Length: 0\r\n\r\n",
                     h, rnd(0, 255), rnd(2, 254), br, from, h, rnd(100000, 999999), h, cid, h, rnd(1000, 9999));
    if (m < 0 || (size_t)m >= sizeof(msg) || n < 8 + 2 * (size_t)m) { buf[0] = '\0'; return; }
    strcpy(buf, "<b 0x");
    hex(buf + 5, msg, (size_t)m);
    strcat(buf, ">");
}

const char *wb_mask_name(int k) {
    static const char *const N[WB_MASKS] = { "QUIC", "QUIC-2", "DNS", "STUN", "iCloud-DNS", "SIP" };
    return k >= 0 && k < WB_MASKS ? N[k] : "?";
}

const char *wb_mask(int k, char *buf, size_t n, const char **name) {
    /* Порядок апстрима: основная (QUIC), затем quic2 dns stun icloud sip. */
    switch (k) {
    case 0: *name = "QUIC"; snprintf(buf, n, "%s", WB_I1_QUIC); break;
    case 1: *name = "QUIC-2"; snprintf(buf, n, "%s", WB_I1_QUIC2); break;
    case 2: *name = "DNS"; mask_dns(buf, n); break;
    case 3: *name = "STUN"; mask_stun(buf, n); break;
    case 4: *name = "iCloud-DNS"; snprintf(buf, n, "%s", WB_I1_ICLOUD); break;
    case 5: *name = "SIP"; mask_sip(buf, n); break;
    default: *name = "?"; buf[0] = '\0'; return NULL;
    }
    return buf[0] ? buf : NULL;
}

int wb_conf_write(const char *path, const struct wb_conf *c) {
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    FILE *f = fdopen(fd, "w");
    if (!f) { close(fd); unlink(tmp); return -1; }
    const struct wb_reg *r = c->reg;
    fprintf(f, "[Interface]\nPrivateKey = %s\n", r->priv);
    if (c->addr) {
        fprintf(f, "Address = %s/32", r->v4);
        if (r->v6[0]) fprintf(f, ", %s/128", r->v6);
        fputc('\n', f);
    }
    fprintf(f, "MTU = 1280\n");
    if (c->obfs) {
        fprintf(f, "Jc = 4\nJmin = 40\nJmax = 70\nS1 = 0\nS2 = 0\nH1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\n");
        if (c->i1 && c->i1[0]) fprintf(f, "I1 = %s\n", c->i1);
    }
    fprintf(f, "\n[Peer]\nPublicKey = %s\nAllowedIPs = 0.0.0.0/0%s\nEndpoint = %s\n", r->peer_pub,
            c->addr && r->v6[0] ? ", ::/0" : "", c->endpoint);
    if (c->keepalive > 0) fprintf(f, "PersistentKeepalive = %d\n", c->keepalive);
    int bad = fflush(f) != 0 || fsync(fileno(f)) != 0;
    bad |= fclose(f) != 0;
    if (bad || rename(tmp, path) != 0) { unlink(tmp); return -1; }
    return 0;
}

int wb_conf_endpoint(const char *path, char *ep, size_t n) {
    ep[0] = '\0';
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "Endpoint", 8)) continue;
        char *v = strchr(line, '=');
        if (!v) continue;
        v += strspn(v + 1, " \t") + 1;
        v[strcspn(v, " \t\r\n")] = '\0';
        snprintf(ep, n, "%s", v);
    }
    fclose(f);
    return ep[0] ? 0 : -1;
}
