/* Провод протоколов steer-proxy: адрес SOCKS5, вывод ключей и заголовки — то, что держит байты на
 * проводе и ломается молча (неверный ключ — сервер не отвечает, кривой заголовок — закрывает поток).
 * Поэтому всё проверяется векторами (tests/pxmatch.c) и сквозным стендом против Xray (tests/run-proxy.sh).
 *
 * Крипто здесь — через слой src/lib/scrypto.h (MD5, SHA-1/HKDF, BLAKE3, HMAC-SHA256, AES-ECB,
 * SHAKE128): protocols зашили их в формат, своей криптографии в этом нет. Чистая раскладка байт
 * (адрес SOCKS5, CRC32, FNV1a) библиотеки не требует. */
#ifndef STEER_PXWIRE_H
#define STEER_PXWIRE_H
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "proxy.h"

/* ---- адрес SOCKS5 (ATYP+ADDR+PORT) --------------------------------------------------------- */

/* Адрес назначения в форме SOCKS5: 0x01 + IPv4(4) + порт(2 BE). Имён клиент не передаёт — адрес
 * клиента уже разрешён (резолвер steer вернул fake-IP, DNAT подменит на настоящий). Пишет из
 * сетевого порядка dst и хостового dport (как во flow_key, tun.h). Возвращает длину (7). */
size_t px_socks_addr(unsigned char *out, uint32_t dst_net, uint16_t dport_host);

/* ---- shadowsocks: вывод ключей ------------------------------------------------------------- */

/* Ключ из пароля (AEAD не-2022): EVP_BytesToKey на MD5, как в shadowsocks-libev. key_n — 16 или 32. 0 — готово, -1 — отказ слоя хеширования. */
int  px_ss_evp_key(const char *pass, unsigned char *key, size_t key_n);
/* Подключ сессии (AEAD не-2022): HKDF-SHA1(key, salt, "ss-subkey"), длина — key_n. */
int  px_ss_subkey(const unsigned char *key, size_t key_n, const unsigned char *salt,
                  unsigned char *subkey);
/* Подключ сессии 2022 (SIP022): BLAKE3 derive_key(контекст, PSK ‖ salt), длина — key_n. Для
 * многопользовательского — PSK здесь uPSK (последний), реле снимается до вывода. */
void px_ss2022_subkey(const unsigned char *psk, size_t key_n, const unsigned char *salt,
                      unsigned char *subkey);
/* EIH (SIP022, многопользовательский, как у sing-box writeExtendedIdentityHeaders): 16 байт
 * идентичности. Подключ идентичности — BLAKE3 derive_key(«shadowsocks 2022 identity subkey», iPSK ‖
 * salt) длиной key_n; out = AES-ECB(подключ, BLAKE3(uPSK)[:16]). 0 — успех. */
int  px_ss2022_eih(const unsigned char *ipsk, size_t key_n, const unsigned char *upsk,
                   const unsigned char *salt, unsigned char out[16]);

/* ---- vmess (AEAD, alterId 0) --------------------------------------------------------------- */

/* cmdKey: MD5(UUID ‖ "c48619fe-8f02-49e0-b9e9-edf763e17e21"). */
void px_vmess_cmdkey(const unsigned char uuid[16], unsigned char cmdkey[16]);
/* KDF vmess: HMAC-SHA256 цепочкой с меткой «VMess AEAD KDF» и путями (RFC нет, это код v2ray).
 * Пути бинарные (AuthID, nonce — не строки), поэтому с длиной. out_n — до 32, npaths — до 4. */
struct px_kdf_path { const unsigned char *p; size_t n; };
void px_vmess_kdf(const unsigned char key[16], const struct px_kdf_path *paths, size_t npaths,
                  unsigned char *out, size_t out_n);
/* AuthID (16): [timestamp u64 BE][rand(4)][CRC32(первые 12)], шифруется AES-128-ECB одним блоком
 * ключом KDF(cmdKey, "AES Auth ID Encryption")[:16]. ts — unix-время, rand — 4 байта вызывающего. */
void px_vmess_authid(const unsigned char cmdkey[16], uint64_t ts, const unsigned char rand4[4],
                     unsigned char out[16]);
/* FNV1a-32 (контрольная сумма заголовка запроса vmess до AEAD-обёртки — у старого формата, здесь
 * ради совместимости структуры; AEAD-заголовок её не проверяет, но v2ray кладёт). */
uint32_t px_fnv1a(const unsigned char *p, size_t n);
uint32_t px_crc32(const unsigned char *p, size_t n);

/* Буфер потока цикла под крупную датаграмму UDP (до UDP_DGRAM_ABS): на стеке 64 КБ не держат, а malloc
 * на каждую датаграмму в цикле лишний. Растёт по требованию и живёт, пока жив поток. Слотов два: 0 — приём,
 * 1 — сборка или разбор, чтобы одно не затирало другое. Буферы свои у каждого файла протокола (static
 * inline): общему файлу они не нужны, а стенды дайлеров линкуются без pxwire.c. NULL — памяти нет. */
static inline unsigned char *px_scratch(int slot, size_t n) {
    static __thread struct { unsigned char *p; size_t cap; } sc[2];
    if (slot < 0 || slot > 1) return NULL;
    if (sc[slot].cap < n) {
        size_t nc = n < 2048 ? 2048 : n;
        unsigned char *np = realloc(sc[slot].p, nc);
        if (!np) return NULL;
        sc[slot].p = np;
        sc[slot].cap = nc;
    }
    return sc[slot].p;
}

#endif
