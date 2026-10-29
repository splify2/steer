/* Провод и вывод ключей steer-proxy (src/proto/proxy/pxwire.c, pxsub.c) против векторов и своих
 * инвариантов. Крипто здесь настоящее (scrypto на wolfSSL), поэтому стенд — в `make ext-test`.
 *
 * НЕЗАВИСИМЫЕ ВЕКТОРЫ (Python hashlib/hmac/zlib, см. комментарии): EVP_BytesToKey на MD5, подключ
 * HKDF-SHA1, CRC32, FNV1a, адрес SOCKS5. Полную правильность 2022 (BLAKE3), vmess KDF и заголовков
 * проверяет сквозной стенд против Xray (tests/run-proxy.sh): если рукопожатие сошлось — ключи верны.
 * Здесь для них — инварианты формы (длины, детерминизм) и разбор ссылок (pxsub). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "pxwire.h"
#include "proxy.h"
#include "unit.h"

static void hx(const char *what, const char *want, const unsigned char *g, size_t n) {
    char b[160];
    for (size_t i = 0; i < n && 2 * i + 1 < sizeof b; i++) snprintf(b + 2 * i, 3, "%02x", g[i]);
    check_str(what, want, b);
}

static void test_ss(void) {
    unsigned char k[32], sub[32];
    px_ss_evp_key("sspass", k, 16);
    hx("EVP MD5 16 байт (sspass)", "447189abd7a5b4bdc89e98f6e6fa9ea8", k, 16);
    px_ss_evp_key("sspass", k, 32);
    hx("EVP MD5 32 байта", "447189abd7a5b4bdc89e98f6e6fa9ea8f4363ee90a2d9b952def20c747ebb704", k, 32);
    unsigned char salt[32];
    for (int i = 0; i < 32; i++) salt[i] = (unsigned char)i;
    px_ss_subkey(k, 32, salt, sub);
    hx("HKDF-SHA1 ss-subkey", "b269811641eec4d14d2c4d1b9439173edea93e900dea75f9f94cb88ff43b4aa5", sub, 32);
    /* 2022: подключ детерминирован и той же длины, EIH 16 байт и детерминирован (значения — Xray). */
    unsigned char psk[32], s2[32], s2b[32], eih[16], eih2[16];
    for (int i = 0; i < 32; i++) psk[i] = (unsigned char)(0x40 + i);
    px_ss2022_subkey(psk, 32, salt, s2);
    px_ss2022_subkey(psk, 32, salt, s2b);
    check_mem("2022 session subkey детерминирован", s2, s2b, 32);
    unsigned char ipsk[16], upsk[16];
    for (int i = 0; i < 16; i++) { ipsk[i] = (unsigned char)i; upsk[i] = (unsigned char)(0x80 + i); }
    check("2022 EIH", 0, px_ss2022_eih(ipsk, 16, upsk, salt, eih));
    px_ss2022_eih(ipsk, 16, upsk, salt, eih2);
    check_mem("2022 EIH детерминирован", eih, eih2, 16);
}

static void test_vmess(void) {
    unsigned char uuid[16], cmdkey[16], ck2[16], out[16], a1[16], a2[16];
    for (int i = 0; i < 16; i++) uuid[i] = (unsigned char)i;
    px_vmess_cmdkey(uuid, cmdkey);
    px_vmess_cmdkey(uuid, ck2);
    check_mem("vmess cmdKey детерминирован", cmdkey, ck2, 16);
    /* KDF: детерминизм и разная длина пути дают разный ключ (вложенный HMAC работает). */
    struct px_kdf_path p1[1] = { { (const unsigned char *)"A", 1 } };
    struct px_kdf_path p2[2] = { { (const unsigned char *)"A", 1 }, { (const unsigned char *)"B", 1 } };
    px_vmess_kdf(cmdkey, p1, 1, out, 16);
    px_vmess_kdf(cmdkey, p1, 1, ck2, 16);
    check_mem("vmess KDF детерминирован", out, ck2, 16);
    px_vmess_kdf(cmdkey, p2, 2, ck2, 16);
    check("vmess KDF разной глубины — разный ключ", 1, memcmp(out, ck2, 16) != 0);
    unsigned char r4[4] = { 1, 2, 3, 4 };
    px_vmess_authid(cmdkey, 0x1122334455667788ull, r4, a1);
    px_vmess_authid(cmdkey, 0x1122334455667788ull, r4, a2);
    check_mem("vmess AuthID детерминирован при тех же входах", a1, a2, 16);
    (void)out;
}

static void test_wire(void) {
    unsigned char a[PX_ADDR_MAX];
    unsigned char ipb[4] = { 1, 2, 3, 4 };     /* 1.2.3.4 в сетевом порядке */
    size_t n = px_socks_addr(a, 0, ipb, 443);
    check("socks addr длина", 7, (long)n);
    hx("socks addr 1.2.3.4:443", "010102030401bb", a, 7);
    /* IPv6: ATYP 4, шестнадцать байт, порт (RFC 1928) */
    unsigned char ip6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    n = px_socks_addr(a, 1, ip6, 443);
    check("socks addr IPv6 длина", 19, (long)n);
    hx("socks addr [2001:db8::1]:443", "0420010db800000000000000000000000101bb", a, 19);
    check("CRC32(00..0b)", (long)0x9270c965u, (long)px_crc32((const unsigned char[]){0,1,2,3,4,5,6,7,8,9,10,11}, 12));
    unsigned char ten[10]; for (int i = 0; i < 10; i++) ten[i] = (unsigned char)i;
    check("FNV1a(00..09)", (long)0x2f854072u, (long)px_fnv1a(ten, 10));
}

static void test_parse(void) {
    struct px_node n;
    check("trojan ссылка", 0, px_parse_url("trojan://pass@h.example:443?security=tls&sni=s.example", &n, 0));
    check_str("trojan protocol", "trojan", px_proto_name(n.proto));
    check_str("trojan password", "pass", n.pass);
    check_str("trojan security", "tls", n.vn.security);
    check("trojan без TLS — негоден", 1, px_parse_url("trojan://pass@h.example:443?security=none", &n, 0));

    check("ss SIP002 method:pass", 0, px_parse_url("ss://aes-256-gcm:secret@h.example:8388", &n, 0));
    check("ss method aes-256-gcm", (long)SS_AES256_GCM, (long)n.ss_method);
    check("ss plugin= отвергается", 1, px_parse_url("ss://aes-128-gcm:p@h.example:1?plugin=obfs", &n, 0));
    /* ss base64(userinfo) */
    check("ss base64 userinfo", 0, px_parse_url("ss://YWVzLTEyOC1nY206cGFzcw==@h.example:1234", &n, 0));
    check("ss base64 method", (long)SS_AES128_GCM, (long)n.ss_method);

    check("socks5 user:pass", 0, px_parse_url("socks5://u:p@h.example:1080", &n, 0));
    check("socks5 ver", 5, n.socks_ver);
    check("socks4", 0, px_parse_url("socks4://h.example:1080", &n, 0));
    check("socks4 ver", 4, n.socks_ver);

    check("http basic", 0, px_parse_url("http://u:p@h.example:3128", &n, 0));
    check_str("http proto", "http", px_proto_name(n.proto));

    /* vmess base64 JSON */
    const char *vm = "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6ImguZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidGxzIjoidGxzIiwic25pIjoicy5leGFtcGxlIn0=";
    check("vmess v2rayN", 0, px_parse_url(vm, &n, 0));
    check_str("vmess proto", "vmess", px_proto_name(n.proto));
    check("vmess sec auto", (long)VMESS_AUTO, (long)n.vmess_sec);
    /* want-фильтр: ss-ссылка при want=vmess — не наша. */
    check("want фильтр", -1, px_parse_url("ss://aes-128-gcm:p@h.example:1", &n, PX_VMESS));

    /* подписка: список и base64, чужое считается */
    struct px_sub_stats st;
    struct px_node out[8];
    const char *sub = "trojan://p@h1.example:443?security=tls&sni=a\nvless://x@h2:443\nss://aes-128-gcm:q@h3.example:1234\n";
    size_t got = px_parse_sub(sub, out, 8, 0, &st);
    check("подписка: пригодных 2 (trojan, ss)", 2, (long)got);
    check("подписка: чужих 1 (vless)", 1, (long)st.foreign);
}

int main(void) {
    test_ss();
    test_vmess();
    test_wire();
    test_parse();
    return unit_done("pxmatch");
}
