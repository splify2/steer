/* Выпуск сертификатов и подписи для стендов security=tls. Зачем и почему отдельным файлом —
 * в tests/certgen.c. Типов криптобиблиотеки здесь нет. */
#ifndef STEER_TESTS_CERTGEN_H
#define STEER_TESTS_CERTGEN_H
#include <stddef.h>

struct tcg_key;

/* Новый ключ ECDSA P-256; NULL — отказ. */
struct tcg_key *tcg_key_new(void);
void tcg_key_free(struct tcg_key *k);

/* Выписать сертификат на CN (и O, если не NULL) с ключом subj. issuer_der == NULL — подписан
 * сам собой (ikey тогда не нужен); иначе издатель — этот сертификат, подпись — ключом ikey. */
int tcg_issue(struct tcg_key *subj, const char *cn, const char *org, int is_ca,
              struct tcg_key *ikey, const unsigned char *issuer_der, size_t issuer_n,
              unsigned char *der, size_t cap, size_t *der_n);
int tcg_der_to_pem(const unsigned char *der, size_t n, char *pem, size_t cap);
/* Подпись ECDSA над готовым хешем SHA-256, DER (r, s). */
int tcg_sign_sha256(struct tcg_key *k, const unsigned char digest[32],
                    unsigned char *sig, size_t cap, size_t *sig_n);
/* Deterministic public test seed, private contexts local to each call. Available
 * only in the existing WOLFSSL_CERT_GEN fixture library, never engine builds. */
int tcg_ed25519_public(const unsigned char seed[32], unsigned char public_key[32]);
int tcg_ed25519_sign(const unsigned char seed[32], const unsigned char *message,
                     size_t length, unsigned char signature[64]);
/* Сколько сертификатов из блоков PEM в тексте разбирается; текст между блоками пропускается. */
int tcg_count_pem_certs(const char *pem, size_t n);

#endif
