/* ClientHello в две записи TLS у апстрима DoT и DoH (`fragment: true`): разрез, заголовки записей,
 * отправка двумя записями с паузой, ключ спеки и седьмое поле таблицы. Без сети: сокет — пара
 * SOCK_SEQPACKET, она хранит границы отправок, так что видно, сколько раз и по сколько байт писали.
 * Рукопожатие с настоящим сервером — tests/dnsfrag.sh. Устройство проверяемого — src/dnsd/dupdial.c. */
#include "dnsd_int.h"
#include "dupint.h"
#include "tabfmt.h"
#include "unit.h"
#include <sys/stat.h>
#include <time.h>

/* Hello по байтам: запись, рукопожатие, версия, random, session_id, шифры, сжатие, расширения
 * (supported_versions до SNI и после — чтобы разбор не считал SNI первым расширением). */
static size_t mk_hello(unsigned char *b, const char *sni) {
    size_t o = 5, nl = strlen(sni);
    b[o++] = 0x01; o += 3;
    b[o++] = 0x03; b[o++] = 0x03;
    for (int i = 0; i < 32; i++) b[o++] = (unsigned char)(0x40 + i);
    b[o++] = 32;
    for (int i = 0; i < 32; i++) b[o++] = (unsigned char)(0x80 + i);
    b[o++] = 0; b[o++] = 4; b[o++] = 0x13; b[o++] = 0x01; b[o++] = 0x13; b[o++] = 0x02;
    b[o++] = 1; b[o++] = 0;
    size_t extl = o; o += 2;
    b[o++] = 0; b[o++] = 43; b[o++] = 0; b[o++] = 3; b[o++] = 2; b[o++] = 3; b[o++] = 4;       /* versions */
    b[o++] = 0; b[o++] = 0; b[o++] = (unsigned char)((nl + 5) >> 8); b[o++] = (unsigned char)(nl + 5);
    b[o++] = (unsigned char)((nl + 3) >> 8); b[o++] = (unsigned char)(nl + 3); b[o++] = 0;
    b[o++] = (unsigned char)(nl >> 8); b[o++] = (unsigned char)nl;
    memcpy(b + o, sni, nl); o += nl;
    for (int i = 0; i < 300; i++) b[o++] = 0;                                                  /* добавка */
    size_t el = o - extl - 2;
    b[extl] = (unsigned char)(el >> 8); b[extl + 1] = (unsigned char)el;
    size_t hl = o - 5 - 4;
    b[6] = (unsigned char)(hl >> 16); b[7] = (unsigned char)(hl >> 8); b[8] = (unsigned char)hl;
    size_t rl = o - 5;
    b[0] = 0x16; b[1] = 0x03; b[2] = 0x01; b[3] = (unsigned char)(rl >> 8); b[4] = (unsigned char)rl;
    return o;
}

static long mono_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (long)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Отправить и собрать, что вышло, по отправкам. */
static int sent(const unsigned char *h, size_t n, int frag, unsigned char msg[2][4096], ssize_t len[2],
                long *gap_ms) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv) != 0) return -1;
    int rc = dup_hello_send(sv[0], h, n, frag);
    len[0] = recv(sv[1], msg[0], 4096, MSG_DONTWAIT);
    long t1 = mono_ms();
    (void)t1;
    len[1] = recv(sv[1], msg[1], 4096, MSG_DONTWAIT);
    *gap_ms = 0;
    close(sv[0]); close(sv[1]);
    return rc;
}

int main(void) {
    unsigned char h[2048], msg[2][4096];
    ssize_t len[2];
    long gap;
    size_t n = mk_hello(h, "cloudflare-dns.com");
    size_t nl = strlen("cloudflare-dns.com"), sni_at = 0;
    for (size_t i = 0; i + nl <= n; i++) if (!memcmp(h + i, "cloudflare-dns.com", nl)) { sni_at = i; break; }

    /* ---- разрез ---- */
    int inside = 1, distinct = 0;
    size_t first = 0;
    for (unsigned r = 0; r < 200; r++) {
        size_t at = dup_hello_split(h, n, r);
        if (at <= sni_at || at >= sni_at + nl) inside = 0;      /* обе части имени непусты */
        if (r == 0) first = at;
        if (at != first) distinct = 1;
    }
    check("разрез всегда внутри имени SNI (200 значений rnd)", 1, inside);
    check("  точка разреза зависит от rnd", 1, distinct);
    check("  первая запись короче всего Hello", 1, first > 5 && first < n);

    /* ---- без разреза: одна отправка, байты те же ---- */
    check("fragment выключен: отправка успешна", 0, sent(h, n, 0, msg, len, &gap));
    check("  одна отправка во всю длину", (long)n, (long)len[0]);
    check("  вторых нет", 1, len[1] < 0);
    check("  байты те же", 0, memcmp(msg[0], h, n));

    /* ---- две записи ---- */
    int ok_all = 1, split_in = 1, hdr_ok = 1, payload_ok = 1, two = 1;
    for (int k = 0; k < 40; k++) {
        if (sent(h, n, 1, msg, len, &gap) != 0) { ok_all = 0; continue; }
        if (len[0] <= 5 || len[1] <= 5) { two = 0; continue; }
        /* каждая отправка — ровно одна запись: заголовок, длина, тело */
        for (int i = 0; i < 2; i++)
            if (msg[i][0] != 0x16 || msg[i][1] != 0x03 || msg[i][2] != 0x01 ||
                (size_t)(((msg[i][3] << 8) | msg[i][4]) + 5) != (size_t)len[i]) hdr_ok = 0;
        unsigned char cat[4096];
        size_t l1 = (size_t)len[0] - 5, l2 = (size_t)len[1] - 5;
        memcpy(cat, msg[0] + 5, l1);
        memcpy(cat + l1, msg[1] + 5, l2);
        if (l1 + l2 != n - 5 || memcmp(cat, h + 5, n - 5)) payload_ok = 0;
        if (5 + l1 <= sni_at || 5 + l1 >= sni_at + nl) split_in = 0;
    }
    check("fragment: отправки успешны", 1, ok_all);
    check("  ровно две отправки", 1, two);
    check("  у каждой заголовок записи, длина сходится с телом", 1, hdr_ok);
    check("  склеенное тело равно исходному Hello", 1, payload_ok);
    check("  разрез внутри имени SNI", 1, split_in);

    /* ---- пауза между отправками ---- */
    {
        int sv[2];
        socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sv);
        long t0 = mono_ms();
        dup_hello_send(sv[0], h, n, 1);
        long took = mono_ms() - t0;
        check("  между отправками пауза не меньше 1 мс (ушло за >= 1 мс, не за 100)", 1, took >= 1 && took < 100);
        close(sv[0]); close(sv[1]);
    }

    /* ---- Hello без SNI: 30-80 байт сообщения; короткая запись не режется ---- */
    {
        unsigned char g[2048];
        size_t gn = mk_hello(g, "ab");
        /* затираем тип расширения SNI: остаётся Hello без server_name */
        for (size_t i = 5; i + 4 < gn; i++)
            if (g[i] == 0 && g[i + 1] == 0 && g[i + 2] == 0 && g[i + 3] == 7 && g[i + 4] == 0 && g[i + 5] == 5) {
                g[i + 1] = 0x77; break;
            }
        int rng = 1;
        for (unsigned r = 0; r < 200; r++) {
            size_t at = dup_hello_split(g, gn, r);
            if (at < 5 + 30 || at > 5 + 80) rng = 0;
        }
        check("без SNI разрез на 30..80 байтах сообщения", 1, rng);
        check("запись не Hello (не 0x16) — не режется", 0, (int)dup_hello_split((const unsigned char *)"GET / HTTP/1.1\r\n", 16, 1));
        unsigned char s[40] = { 0x16, 3, 1, 0, 35, 1 };
        check("короткая запись — не режется", 0, (int)dup_hello_split(s, 40, 3));
        check("fragment на такой — одна отправка", 1, sent(s, 40, 1, msg, len, &gap) == 0 && len[0] == 40 && len[1] < 0);
    }

    /* ---- спека: ключ fragment ---- */
    char dir[] = "/tmp/dupfragXXXXXX";
    if (!mkdtemp(dir)) return 2;
    char sp[200];
    snprintf(sp, sizeof(sp), "%s/s.yaml", dir);
    static struct spec cfg;
    struct err e = {0};
    FILE *f = fopen(sp, "w");
    fputs("version: 2\nlan: { devices: [br-lan] }\noutputs:\n  vpn: { kind: interface, device: wg0 }\n"
          "dns:\n  other: g\n  upstreams:\n    g: { servers: [d, t, p, o], mode: race }\n"
          "    d: { url: 'https://cloudflare-dns.com/dns-query', ips: [1.1.1.1], fragment: true }\n"
          "    t: { url: 'tls://dns.google', ips: [8.8.8.8], fragment: true }\n"
          "    p: { url: 'tls://dns.test', ips: [192.0.2.1] }\n"
          "    o: { url: 'tls://dns.test', ips: [192.0.2.1], fragment: false }\n", f);
    fclose(f);
    check("спека с fragment читается", 0, load_spec(sp, &cfg, &e) < 0);
    check("  DoH fragment: true", 1, cfg.dns.up[1].frag);
    check("  DoT fragment: true", 1, cfg.dns.up[2].frag);
    check("  без ключа — выключено", 0, cfg.dns.up[3].frag);
    check("  fragment: false — выключено", 0, cfg.dns.up[4].frag);

    /* ---- таблица: седьмое поле ---- */
    char *txt = NULL;
    size_t tn = 0;
    FILE *m = open_memstream(&txt, &tn);
    tabfmt_build(&cfg, m);
    fclose(m);
    check("таблица: у d и t поле frag", 1,
          strstr(txt, "|1.1.1.1|-|frag\n") != NULL && strstr(txt, "|8.8.8.8|-|frag\n") != NULL);
    check("  у p и o поля нет (прежний формат до байта)", 1, strstr(txt, "|192.0.2.1|-\n") != NULL);
    for (size_t i = 0; i < g_dch_n; i++) free(g_dch[i].rules_path);
    memset(g_dch, 0, g_dch_cap * sizeof(*g_dch));
    g_dch_n = 0;
    check("  таблица разбирается", 0, tabfmt_parse(txt, tn));
    int fr[4] = {0}, nfr = 0;
    for (size_t i = 0; i < g_dup_cfg_n; i++) { fr[i < 4 ? i : 3] = g_dup_cfg[i].u.frag; nfr += g_dup_cfg[i].u.frag; }
    check("  frag дошёл до резолвера у двух из четырёх", 2, nfr);
    check("  и у первого (d)", 1, fr[0]);
    free(txt);

    /* ---- отказы ---- */
    static const char *const bad[] = {
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1', fragment: true } } }",                /* нет TLS */
        "dns: { upstreams: { a: { url: 'quic://dns.test', ips: [1.1.1.1], fragment: true } } }",  /* QUIC */
        "dns: { upstreams: { a: { url: 'tls://dns.test', ips: [1.1.1.1], fragment: 1 } } }",   /* не bool */
        "dns: { upstreams: { a: { url: 'udp://1.1.1.1' }, g: { servers: [a], fragment: true } } }",  /* у группы */
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        f = fopen(sp, "w");
        fprintf(f, "version: 2\nlan: { devices: [br-lan] }\noutputs:\n  vpn: { kind: interface, device: wg0 }\n%s\n", bad[i]);
        fclose(f);
        static struct spec c3;
        spec_release(&c3);
        struct err e3 = {0};
        char nm[80];
        snprintf(nm, sizeof(nm), "отказ спеки №%zu", i + 1);
        check(nm, 1, load_spec(sp, &c3, &e3) < 0);
    }
    return unit_done("dupfragmatch");
}
