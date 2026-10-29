/* TLS 1.3 для QUIC поверх wolfSSL — см. qcssl.h (зачем отдельный файл и почему void *). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#include <wolfssl/ssl.h>
#include <wolfssl/quic.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include "qcssl.h"
#include "certverify.h"

/* Потолок размера файла корней — то же рассуждение, что у certverify.c (roots_load): путь может
 * оказаться /dev/zero, и «прочесть всё» не должно значить «съесть память роутера». ca-bundle весит
 * около 200 КБ. */
#define QCSSL_ROOTS_MAX (1024 * 1024)

static unsigned char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char *buf = malloc(QCSSL_ROOTS_MAX + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, QCSSL_ROOTS_MAX + 1, f);
    fclose(f);
    if (got == 0 || got > QCSSL_ROOTS_MAX) { free(buf); return NULL; }
    *n = got;
    return buf;
}

void *qcssl_ctx_client(int insecure, const uint8_t *ca_pem, size_t ca_pem_n, const char *ca_file) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) return NULL;
    /* Версии, билеты сессии и кодовая точка параметров транспорта выставляет ngtcp2. */
    if (ngtcp2_crypto_wolfssl_configure_client_context(ctx) != 0) goto fail;
    if (insecure) {
        wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);
        return ctx;
    }
    unsigned char *own = NULL;
    if (!ca_pem) {
        size_t n = 0;
        own = read_file(ca_file && ca_file[0] ? ca_file : CERTV_DEFAULT_ROOTS, &n);
        if (!own) goto fail;              /* нет хранилища корней: проверить нечем — отказ, а не «без проверки» */
        ca_pem = own;
        ca_pem_n = n;
    }
    int rc = wolfSSL_CTX_load_verify_buffer(ctx, ca_pem, (long)ca_pem_n, WOLFSSL_FILETYPE_PEM);
    free(own);
    if (rc != WOLFSSL_SUCCESS) goto fail;
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, NULL);
    return ctx;
fail:
    wolfSSL_CTX_free(ctx);
    return NULL;
}

#ifdef QC_WITH_SERVER
void *qcssl_ctx_server(const uint8_t *cert_der, size_t cert_n, const uint8_t *key_der, size_t key_n) {
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (!ctx) return NULL;
    if (ngtcp2_crypto_wolfssl_configure_server_context(ctx) != 0 ||
        wolfSSL_CTX_use_certificate_buffer(ctx, cert_der, (long)cert_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der, (long)key_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    return ctx;
}
#endif

/* Новый билет: DER-запись сессии — обёртке (qc_session_new). Возврат 0: сессию колбэк себе не забирает,
 * wolfSSL освободит её сам. Соединение находится по прикладным данным — там conn_ref (qcssl_new). */
static int on_new_session(WOLFSSL *ssl, WOLFSSL_SESSION *sess) {
    ngtcp2_crypto_conn_ref *ref = wolfSSL_get_app_data(ssl);
    if (!ref || !ref->user_data) return 0;
    int n = wolfSSL_i2d_SSL_SESSION(sess, NULL);
    if (n <= 0 || n > 8192) return 0;                  /* билет DoQ — сотни байт; больше — не наш случай */
    unsigned char *buf = malloc((size_t)n), *p = buf;
    if (!buf) return 0;
    if (wolfSSL_i2d_SSL_SESSION(sess, &p) == n) qc_session_new(ref->user_data, buf, (size_t)n);
    free(buf);
    return 0;
}

void qcssl_ctx_sessions(void *ctx) {
    wolfSSL_CTX_UseSessionTicket(ctx);
    wolfSSL_CTX_sess_set_new_cb(ctx, on_new_session);
}

int qcssl_set_session(void *ssl, const uint8_t *der, size_t n) {
    const unsigned char *p = der;
    WOLFSSL_SESSION *s = wolfSSL_d2i_SSL_SESSION(NULL, &p, (long)n);
    if (!s) return -1;
    int ok = wolfSSL_set_session(ssl, s) == WOLFSSL_SUCCESS;
    int early = ok && wolfSSL_SESSION_get_max_early_data(s) != 0;
    wolfSSL_SESSION_free(s);
    if (!ok) return -1;
    if (early) wolfSSL_set_quic_early_data_enabled(ssl, 1);
    return early ? 1 : 0;
}

int qcssl_early_accepted(void *ssl) {
    return wolfSSL_get_early_data_status(ssl) == WOLFSSL_EARLY_DATA_ACCEPTED;
}

void qcssl_ctx_free(void *ctx) {
    if (ctx) wolfSSL_CTX_free(ctx);
}

void *qcssl_new(void *ctx, void *conn_ref, const char *sni, const char *alpn, int server, int verify_name) {
    WOLFSSL *ssl = wolfSSL_new(ctx);
    if (!ssl) return NULL;
    wolfSSL_set_app_data(ssl, conn_ref);
    if (server) wolfSSL_set_accept_state(ssl); else wolfSSL_set_connect_state(ssl);
    if (alpn && alpn[0]) {
        /* Несовпадение ALPN — отказ рукопожатия (как у настоящих серверов), а не «ну ладно». */
        if (wolfSSL_UseALPN(ssl, (char *)alpn, (unsigned)strlen(alpn), WOLFSSL_ALPN_FAILED_ON_MISMATCH) != WOLFSSL_SUCCESS)
            goto fail;
    }
    if (!server && sni && sni[0]) {
        /* Адрес вместо имени (sni=31.76.69.65 у узлов Xray с сертификатом на IP): SNI не уходит
         * вовсе — RFC 6066 запрещает в нём адрес, так же поступают Go и Xray, — а сертификат
         * сверяется с SAN IP. Прежде адрес шёл в SNI и в проверку ДОМЕННОГО имени, wolfSSL
         * отказывал, и соединение не открывалось ещё до первого пакета («QUIC не открылся (-4)»). */
        unsigned char ip[16];
        if (inet_pton(AF_INET, sni, ip) == 1 || inet_pton(AF_INET6, sni, ip) == 1) {
            if (verify_name && wolfSSL_check_ip_address(ssl, sni) != WOLFSSL_SUCCESS)
                goto fail;
        } else {
            if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, sni, (unsigned short)strlen(sni)) != WOLFSSL_SUCCESS)
                goto fail;
            if (verify_name && wolfSSL_check_domain_name(ssl, sni) != WOLFSSL_SUCCESS)
                goto fail;
        }
    }
    return ssl;
fail:
    wolfSSL_free(ssl);
    return NULL;
}

int qcssl_peer_sha256(void *ssl, uint8_t out[32]) {
    WOLFSSL_X509 *x = wolfSSL_get_peer_certificate(ssl);
    if (!x) return -1;
    int len = 0;
    const unsigned char *der = wolfSSL_X509_get_der(x, &len);
    int rc = -1;
    if (der && len > 0 && wc_Sha256Hash(der, (word32)len, out) == 0) rc = 0;
    wolfSSL_X509_free(x);
    return rc;
}

int qcssl_peer_der(void *ssl, uint8_t *out, size_t cap) {
    WOLFSSL_X509 *x = wolfSSL_get_peer_certificate(ssl);
    if (!x) return -1;
    int len = 0;
    const unsigned char *der = wolfSSL_X509_get_der(x, &len);
    int rc = -1;
    if (der && len > 0 && (size_t)len <= cap) { memcpy(out, der, (size_t)len); rc = len; }
    wolfSSL_X509_free(x);
    return rc;
}

int qcssl_ctx_client_cert(void *ctx, const uint8_t *cert, size_t cert_n, const uint8_t *key, size_t key_n) {
    if (wolfSSL_CTX_use_certificate_buffer(ctx, cert, (long)cert_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_buffer(ctx, key, (long)key_n, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS)
        return -1;
    return 0;
}

void qcssl_free(void *ssl) {
    if (ssl) wolfSSL_free(ssl);
}
