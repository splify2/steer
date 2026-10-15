/* TLS 1.3 для QUIC: единственный, кроме src/lib/scrypto.c, файл движка, который видит wolfSSL.
 *
 * ПОЧЕМУ ВТОРОЙ ФАЙЛ, А НЕ ЕЩЁ ОДНА ФУНКЦИЯ В scrypto.c. Слой примитивов (scrypto.h) — это
 * хеши, шифры и проверка подписей без единого типа библиотеки в заголовке: его подключают стенды
 * `make test`, которые wolfSSL не видят вовсе. QUIC устроен иначе. ngtcp2 не берёт примитивы —
 * он берёт сам TLS-стек (рукопожатие TLS 1.3 внутри CRYPTO-кадров, wolfSSL_quic_*), и типы
 * WOLFSSL_CTX и WOLFSSL сквозные: их принимает ngtcp2_crypto_wolfssl, их держит соединение.
 * Этот файл прячет их за указателями void *, чтобы quic.c (ngtcp2, сокеты, потоки) их не
 * видел — ровно как остальной движок не видит wolfSSL. Стенд tests/buildmatch.sh сторожит
 * список файлов, которым заголовки wolfSSL разрешены: их два.
 *
 * Свой TLS 1.3 движка (src/proto/tls/tls13.c) для QUIC не годится: ngtcp2 отдаёт ключи по
 * уровням шифрования (Initial, Handshake, 1-RTT) и ждёт тех же от TLS-стека.
 */
#ifndef STEER_QCSSL_H
#define STEER_QCSSL_H
#include <stddef.h>
#include <stdint.h>

/* Клиентский контекст. insecure — не проверять сертификат; иначе корни из ca_pem либо из ca_file
 * (файл PEM). NULL — не создалось. */
void *qcssl_ctx_client(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file);
#ifdef QC_WITH_SERVER
/* Серверный контекст стенда: сертификат и ключ — DER. */
void *qcssl_ctx_server(const uint8_t *cert_der, size_t cert_n, const uint8_t *key_der, size_t key_n);
#endif
void  qcssl_ctx_free(void *ctx);

/* Соединение TLS. conn_ref — struct ngtcp2_crypto_conn_ref *, кладётся в прикладные данные (так
 * его достаёт ngtcp2_crypto_wolfssl). sni может быть NULL; при sni != NULL и verify != 0 имя в
 * сертификате сверяется. NULL — не создалось. */
void *qcssl_new(void *ctx, void *conn_ref, const char *sni, const char *alpn, int server, int verify_name);
void  qcssl_free(void *ssl);
/* SHA-256 листового сертификата сервера (DER) — для pinSHA256 у hysteria2. 0 — есть, -1 — нет. */
int   qcssl_peer_sha256(void *ssl, uint8_t out[32]);
/* Листовой сертификат сервера (DER) в out[cap]: длина или -1 (нет или не уместился). */
int   qcssl_peer_der(void *ssl, uint8_t *out, size_t cap);
/* Клиентский сертификат (DER) и ключ (SEC1 ECPrivateKey, DER) — для серверов, которые узнают клиента
 * по ключу (MASQUE у WARP). 0 — поставлены. */
int   qcssl_ctx_client_cert(void *ctx, const uint8_t *cert, size_t cert_n, const uint8_t *key, size_t key_n);

/* ---- сессии и 0-RTT (клиент) ---------------------------------------------------------------------
 *
 * Билет сессии, присланный сервером после рукопожатия, wolfSSL отдаёт колбэку; колбэк отдаёт его
 * DER-запись обёртке через qc_session_new (quic.c) — она и хранит билеты, здесь только TLS. Со
 * следующим соединением к тому же серверу билет ставится в TLS до отправки ClientHello (qcssl_set_session):
 * рукопожатие идёт по PSK, а если билет разрешает early data (max_early_data), первые запросы уходят в
 * пакетах 0-RTT, не дожидаясь ответа сервера. */

/* Включить в контексте билеты сессий и колбэк нового билета. Без вызова билеты не запрашиваются. */
void  qcssl_ctx_sessions(void *ctx);
/* Поставить в соединение сессию из DER-записи. 1 — сессия установлена и разрешает 0-RTT (early data
 * включён), 0 — установлена, но 0-RTT она не разрешает, -1 — запись не годится. */
int   qcssl_set_session(void *ssl, const uint8_t *der, size_t n);
/* Сервер принял 0-RTT? Спрашивать после рукопожатия. */
int   qcssl_early_accepted(void *ssl);

/* Реализует quic.c: пришёл новый билет соединения user (то, что лежит в ngtcp2_crypto_conn_ref.user_data). */
void  qc_session_new(void *user, const uint8_t *der, size_t n);

#endif
