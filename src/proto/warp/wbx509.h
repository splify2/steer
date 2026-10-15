/* Сертификат клиента MASQUE и ключ сервера (подробности — в wbx509.c). */
#ifndef STEER_WBX509_H
#define STEER_WBX509_H

#include <stddef.h>

#define WB_SPKI_P256 91         /* SubjectPublicKeyInfo P-256, DER */
#define WB_SEC1_P256 121        /* ECPrivateKey (SEC1) P-256 с открытой половиной, DER */

size_t wb_p256_spki(const unsigned char pub[65], unsigned char out[WB_SPKI_P256]);
size_t wb_p256_sec1(const unsigned char priv[32], const unsigned char pub[65], unsigned char out[WB_SEC1_P256]);
/* Самоподписанный сертификат ключа priv (сутки, пустые имена). 0 — готов, длина в *outn. */
int wb_mq_cert(const unsigned char priv[32], unsigned char *out, size_t cap, size_t *outn);
/* SubjectPublicKeyInfo сертификата (DER): указатель внутрь cert и длина. 0 — найден. */
int wb_cert_spki(const unsigned char *cert, size_t n, const unsigned char **spki, size_t *spki_n);

#endif
