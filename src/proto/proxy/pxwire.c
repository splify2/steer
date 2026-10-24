/* Провод steer-proxy: адрес SOCKS5, вывод ключей ss и vmess (pxwire.h). Крипто — через scrypto.h,
 * ни байта мимо слоя. Эталоны: shadowsocks-libev (EVP_BytesToKey, HKDF-SHA1), spec SIP022
 * (BLAKE3), v2ray vmess AEAD (KDF на вложенном HMAC-SHA256). */
#define _GNU_SOURCE
#include <string.h>
#include "pxwire.h"
#include "scrypto.h"

size_t px_socks_addr(unsigned char *out, uint32_t dst_net, uint16_t dport_host) {
    out[0] = 0x01;                       /* ATYP IPv4 */
    memcpy(out + 1, &dst_net, 4);        /* уже сетевой порядок (flow_key, tun.h) */
    out[5] = (unsigned char)(dport_host >> 8);
    out[6] = (unsigned char)dport_host;
    return 7;
}

/* ---- shadowsocks ---------------------------------------------------------------------------- */

int px_ss_evp_key(const char *pass, unsigned char *key, size_t key_n) {
    /* EVP_BytesToKey(MD5, пароль, без соли, 1 итерация): key = MD5(pass) ‖ MD5(MD5(pass) ‖ pass) ‖ …
     * до key_n байт. Так shadowsocks выводит ключ из пароля с первых версий. */
    unsigned char prev[16];
    size_t have = 0, pl = strlen(pass);
    while (have < key_n) {
        struct sc_hash_ctx h;
        /* Отказ слоя (в сборке нет MD5, нет памяти) — отказ вывода ключа: прежде ключ тихо оставался
         * мусором, и узел «не отвечал» без единой причины (I-416). */
        if (sc_hash_init(&h, SC_MD5) != 0) return -1;
        int rc = 0;
        if (have) rc |= sc_hash_update(&h, prev, 16);
        rc |= sc_hash_update(&h, pass, pl);
        rc |= sc_hash_final(&h, prev);
        sc_hash_free(&h);
        if (rc) return -1;
        size_t take = key_n - have < 16 ? key_n - have : 16;
        memcpy(key + have, prev, take);
        have += take;
    }
    return 0;
}

int px_ss_subkey(const unsigned char *key, size_t key_n, const unsigned char *salt,
                 unsigned char *subkey) {
    /* HKDF-SHA1(ikm=key, salt=salt, info="ss-subkey", L=key_n) — shadowsocks AEAD. */
    return sc_hkdf(SC_SHA1, salt, key_n, key, key_n, "ss-subkey", 9, subkey, key_n);
}

void px_ss2022_subkey(const unsigned char *psk, size_t key_n, const unsigned char *salt,
                      unsigned char *subkey) {
    unsigned char material[64];          /* key_n*2, key_n ≤ 32 */
    memcpy(material, psk, key_n);
    memcpy(material + key_n, salt, key_n);
    sc_blake3_derive_key(subkey, key_n, "shadowsocks 2022 session subkey", 31,
                         material, key_n * 2);
}

int px_ss2022_eih(const unsigned char *ipsk, size_t key_n, const unsigned char *upsk,
                  const unsigned char *salt, unsigned char out[16]) {
    unsigned char subkey[32], uhash[32], material[64];
    memcpy(material, ipsk, key_n);
    memcpy(material + key_n, salt, key_n);
    sc_blake3_derive_key(subkey, key_n, "shadowsocks 2022 identity subkey", 32,
                         material, key_n * 2);
    sc_blake3_hash(uhash, upsk, key_n);
    return sc_aes_block(subkey, key_n, 0, uhash, out);
}

/* ---- vmess ---------------------------------------------------------------------------------- */

void px_vmess_cmdkey(const unsigned char uuid[16], unsigned char cmdkey[16]) {
    static const char magic[] = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
    struct sc_hash_ctx h;
    sc_hash_init(&h, SC_MD5);
    sc_hash_update(&h, uuid, 16);
    sc_hash_update(&h, magic, sizeof(magic) - 1);
    sc_hash_final(&h, cmdkey);
    sc_hash_free(&h);
}

/* Вложенный HMAC-SHA256 KDF v2ray (pxwire.h). H(level) — хеш этого уровня над сообщением; база
 * (level < 0) — HMAC с ключом «VMess AEAD KDF». Блок HMAC — 64 байта (SHA-256). */
static void vmess_h(const struct px_kdf_path *path, int level, const unsigned char *msg, size_t mn,
                    unsigned char out[32]) {
    if (level < 0) {
        sc_hmac(SC_SHA256, "VMess AEAD KDF", 14, msg, mn, out);
        return;
    }
    unsigned char keyb[64] = { 0 }, ipad[64], opad[64];
    const unsigned char *k = path[level].p;
    size_t kn = path[level].n;
    if (kn > 64) vmess_h(path, level - 1, k, kn, keyb);  /* key → H(key) */
    else memcpy(keyb, k, kn);
    for (int i = 0; i < 64; i++) { ipad[i] = keyb[i] ^ 0x36; opad[i] = keyb[i] ^ 0x5c; }
    unsigned char buf[512], inner[32];   /* сообщение растёт на 64 (блок) на каждый уровень; 4 пути ≤ 288 */
    memcpy(buf, ipad, 64);
    memcpy(buf + 64, msg, mn);
    vmess_h(path, level - 1, buf, 64 + mn, inner);
    memcpy(buf, opad, 64);
    memcpy(buf + 64, inner, 32);
    vmess_h(path, level - 1, buf, 96, out);
}

void px_vmess_kdf(const unsigned char key[16], const struct px_kdf_path *paths, size_t npaths,
                  unsigned char *out, size_t out_n) {
    unsigned char full[32];
    vmess_h(paths, (int)npaths - 1, key, 16, full);
    memcpy(out, full, out_n > 32 ? 32 : out_n);
}

uint32_t px_fnv1a(const unsigned char *p, size_t n) {
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
    return h;
}

uint32_t px_crc32(const unsigned char *p, size_t n) {
    uint32_t c = 0xffffffffu;
    for (size_t i = 0; i < n; i++) {
        c ^= p[i];
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & (uint32_t)(-(int)(c & 1)));
    }
    return c ^ 0xffffffffu;
}

void px_vmess_authid(const unsigned char cmdkey[16], uint64_t ts, const unsigned char rand4[4],
                     unsigned char out[16]) {
    unsigned char plain[16], key[16];
    struct px_kdf_path p[] = { { (const unsigned char *)"AES Auth ID Encryption", 22 } };
    for (int i = 0; i < 8; i++) plain[i] = (unsigned char)(ts >> (56 - 8 * i));
    memcpy(plain + 8, rand4, 4);
    uint32_t crc = px_crc32(plain, 12);
    for (int i = 0; i < 4; i++) plain[12 + i] = (unsigned char)(crc >> (24 - 8 * i));
    px_vmess_kdf(cmdkey, p, 1, key, 16);
    sc_aes_block(key, 16, 0, plain, out);
}
