/* Проверка сертификата сервера для security=tls.
 *
 * Отдельным файлом, а не внутри tls13.c, и это не вкусовщина: слой записей TLS не знает про
 * X.509 ничего, и это обещание проверяется одной командой (`grep -n 'sc_chain\|sc_roots\|
 * sc_cert' src/proto/tls/tls13.c` — пусто). Reality сертификат цепочкой не проверяет по
 * построению — цепочка принадлежит чужому маскировочному сайту, — и путь записей обязан
 * оставаться свободным от X.509. Здесь этот код собран в одном месте, и видно, кто его зовёт:
 * tls13.c зовёт cert_verify_server, а та — слой примитивов (sc_chain_verify, sc_cert_verify_sig).
 */
#ifndef STEER_CERTVERIFY_H
#define STEER_CERTVERIFY_H
#include <stddef.h>

#define CERTV_EPARSE   (-70)   /* сообщение Certificate или CertificateVerify не разобралось */
#define CERTV_ENOROOTS (-71)   /* хранилище корней не прочиталось: проверять нечем */
#define CERTV_ECHAIN   (-72)   /* цепочка не сошлась с корнями или имя не то */
#define CERTV_ESIG     (-73)   /* подпись CertificateVerify неверна */
#define CERTV_EALG     (-74)   /* сервер подписал алгоритмом, которого мы не предлагали */

/* Где лежат корни. Путь вынесен в шов, а не зашит: стенду нужен свой набор, а на роутере это
 * файл пакета ca-bundle. Пустая строка означает «взять умолчание». */
#define CERTV_DEFAULT_ROOTS "/etc/ssl/certs/ca-certificates.crt"

/* Проверить подлинность сервера по правилам TLS 1.3 (RFC 8446 §4.4.2 и §4.4.3).
 *
 * cert_body / cert_n     — ТЕЛО сообщения Certificate, без четырёх байт заголовка;
 * cv_body  / cv_n        — тело CertificateVerify;
 * transcript / thash_n   — Transcript-Hash по сообщениям ДО CertificateVerify включительно
 *                          с Certificate, то есть ровно то, что подписал сервер;
 * host                   — имя, которое обязано найтись в сертификате;
 * roots                  — путь к хранилищу корней или NULL/"" для умолчания.
 *
 * Возвращает 0, если сервер подлинный. Всё остальное — код выше, и каждый из них означает
 * РАЗНОЕ: «нечем проверить» это не то же самое, что «проверили и не сошлось», и человеку в
 * причине непригодности узла нужно видеть именно эту разницу.
 */
int cert_verify_server(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *cv_body, size_t cv_n,
                       const unsigned char *transcript, size_t thash_n,
                       const char *host, const char *roots);

#define CERTV_EPIN     (-77)   /* сертификат не совпал ни с одним закреплённым отпечатком */

/* Правила проверки сертификата узла сверх умолчания «цепочка до корней и имя SNI».
 *
 * Повторяют клиентскую сторону Xray-core (transport/internet/tls/config.go, verifyPeerCert):
 *
 *   pcs — pinnedPeerCertSha256: SHA-256 (hex, через запятую) сертификата целиком (DER). Совпал ЛИСТ —
 *         сервер принят без проверки цепочки, срока и имени: закрепление и есть доверие. Совпал
 *         промежуточный или корень, который является CA, — цепочка проверяется, но до ЭТОГО
 *         сертификата, а не до системных корней. Не совпало ничего — отказ, до корней дело не доходит.
 *   pks — то же для sing-box (certificate_public_key_sha256): SHA-256 от SubjectPublicKeyInfo листа.
 *         Совпал — сервер принят так же, как при совпавшем листе pcs.
 *   vcn — verifyPeerCertByName: имена через запятую, против которых проверяется цепочка ВМЕСТО SNI;
 *         годится любое из них.
 *   insecure — цепочка, имя, срок и закрепления не проверяются вовсе. Остаётся подпись
 *         CertificateVerify (Go тоже проверяет её до вызова своего VerifyPeerCertificate): без неё
 *         собеседник даже не доказывает, что владеет ключом присланного сертификата. Включается
 *         только явным ключом выхода `insecure`, подписка этого не делает.
 *
 * Строки pcs и pks приходят уже приведёнными (sub.c): 64 знака hex строчными, через запятую. */
struct cert_policy {
    const char *pcs, *pks, *vcn;
    int insecure;
};

/* cert_verify_server с правилами; pol == NULL — прежнее поведение. */
int cert_verify_server_ex(const unsigned char *cert_body, size_t cert_n,
                          const unsigned char *cv_body, size_t cv_n,
                          const unsigned char *transcript, size_t thash_n,
                          const char *host, const char *roots, const struct cert_policy *pol);

/* Source-only prepared trust snapshot for the incremental TLS path. Parse
 * bounded PEM bytes on a configuration worker, before publishing the object.
 * Input is copied by the crypto backend and may be discarded after return.
 * At least one usable CA is required; unsupported/invalid PEM certificates are
 * skipped with the same documented sc_roots_load policy as the legacy path.
 * No path, process-global cache or default roots fallback. On failure *out=NULL.
 * After preparation the snapshot is immutable. Verification uses the crypto
 * backend's per-store mutex: sharing is concurrency-safe with a thread-safe
 * backend profile, but is NOT a nonblocking owner-loop guarantee. Prepare one
 * bounded store per owner or use a bounded verification worker service.
 * Caller retains ownership through every verifier return and
 * destroys only after all users quiesce; no refcount/module ownership implied. */
#define CERT_TRUST_PEM_MAX (8u * 1024u * 1024u)
struct cert_trust;
int cert_trust_prepare_pem(const unsigned char *, size_t, struct cert_trust **out);
void cert_trust_destroy(struct cert_trust *);
/* Same chain/name/signature/pin policy as _ex, but exclusively prepared roots.
 * No file/cache IO on this path. Peer-controlled certificate work still needs
 * separate handshake byte/count/CPU admission at the engine/host boundary. */
int cert_verify_server_prepared(const unsigned char *cert_body, size_t cert_n,
    const unsigned char *cv_body, size_t cv_n, const unsigned char *transcript,
    size_t thash_n, const char *host, const struct cert_trust *, const struct cert_policy *);

#define CERTV_ENOTREALITY (-75) /* сервер не доказал, что он Reality: не признал нас */
#define CERTV_EPQ         (-76) /* Reality признал, но подпись ML-DSA-65 (pqv) отсутствует или неверна */

/* Проверить, что перед нами ТОТ САМЫЙ сервер Reality.
 *
 * Сервер, признавший клиента, выписывает временный сертификат с ключом Ed25519 и кладёт в
 * поле подписи не подпись, а HMAC-SHA512(authkey, открытый ключ). Посчитать его умеет только
 * владелец постоянного ключа: authkey выведен из общего секрета с ним. Не сошлось — значит
 * нас НЕ признали и мы разговариваем с маскировочным сайтом, которому сервер нас передал.
 *
 * До этой проверки узнать такое было нечем: неудача Reality выглядит как успех, и понять,
 * признали нас или нет, удавалось только отправив запрос VLESS и посмотрев на первый байт
 * ответа. Теперь ответ известен сразу после рукопожатия — и он точный, а не по догадке.
 *
 * X.509 здесь НЕ НУЖЕН: разбор — это несколько шагов по DER, а проверка — один HMAC. Это не
 * случайность, а свойство формата, и на нём стоит то, что сборка без security=tls этой
 * проверке ничего не должна.
 *
 * cert_body / cert_n — тело сообщения Certificate, без четырёх байт заголовка;
 * authkey            — 32 байта из struct reality_state.
 */
int cert_reality_check(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *authkey);
/* After the HMAC authenticates the temporary certificate's Ed25519 public key,
 * verify its real TLS CertificateVerify proof over the pre-CV transcript.
 * Pinned REALITY4bb46b2afd8b emits Ed25519 CV, not a no-CV handshake. */
int cert_reality_verify(const unsigned char *cert_body, size_t cert_n,
    const unsigned char *cv_body, size_t cv_n, const unsigned char *transcript, size_t transcript_n);

/* Человеческое объяснение кода. Пустая строка для 0. */
/* Вторая половина доказательства Reality — подпись ML-DSA-65 (`mldsa65Verify`, `pqv` в ссылке).
 *
 * Сервер с mldsa65Seed кладёт в единственное расширение временного сертификата подпись (3309
 * байт) над HMAC-SHA512(authkey, ed25519_pub ‖ ClientHello ‖ ServerHello): оба сообщения — целиком,
 * с четырёхбайтным заголовком рукопожатия, как отправлены и получены (xtls/reality,
 * handshake_server_tls13.go). Здесь проверяется ровно это, и ТОЛЬКО после cert_reality_check —
 * подпись ML-DSA без первой не значит ничего.
 *
 * pk — 1952 байта. 0 — верна; CERTV_EPQ — расширения нет, оно не той длины или подпись не сошлась;
 * CERTV_EPARSE — сертификат не разобрался. */
int cert_reality_check_pq(const unsigned char *cert_body, size_t cert_n,
                          const unsigned char *authkey, const unsigned char *pk,
                          const unsigned char *ch, size_t ch_n,
                          const unsigned char *sh, size_t sh_n);

const char *cert_verify_strerror(int rc);

#endif
