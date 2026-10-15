/* Слой криптографических примитивов steer — всё, что протоколам нужно от криптобиблиотеки.
 *
 * ЗАЧЕМ СЛОЙ. Код протоколов (src/proto/tls, xsteer, tgws) не зовёт криптобиблиотеку сам: он
 * зовёт эти функции, а за ними стоит wolfCrypt (решение владельца 2026-09-28; docs/architecture.md,
 * «Криптография»). Прежде протоколы звали mbedtls напрямую — шестьдесят разных
 * функций в шести файлах, — и смена библиотеки означала бы правку каждого из них, включая
 * защищённые (reality.c, tls13.c, xshake.c). Теперь библиотека видна ровно в одном файле,
 * scrypto.c, и её смена — это правка одного файла под неизменный заголовок.
 *
 * ТИПОВ БИБЛИОТЕКИ ЗДЕСЬ НЕТ, и это обещание, а не удобство: заголовок подключают tls13.h и
 * через него десяток стендов `make test`, которые криптобиблиотеку не видят по построению (у них
 * нет её ни заголовков, ни объектов, — см. ext-syntax в Makefile). Раньше ради этого в tests/stub
 * лежали заглушки заголовков mbedtls с выдуманными размерами полей; теперь заглушки не нужны
 * вовсе, стенд подставляет свои функции sc_* там, где ему надо.
 *
 * КОНТЕКСТЫ — НЕПРОЗРАЧНЫЕ ФИКСИРОВАННОГО РАЗМЕРА, а не выделяемые библиотекой. Доводы:
 *
 *   - struct tls13 и struct tls13_keys держат контексты ЗНАЧЕНИЯМИ внутри себя и сами лежат
 *     внутри соединений (vless_conn, соединения tgws, xsteer), которые живут в статических
 *     таблицах туннеля и на стеке рукопожатия. Выделение на каждый ключ добавило бы по malloc на
 *     направление, путь отказа «памяти нет» в десятке мест и утечку на каждом пропущенном free —
 *     ровно тот класс ошибок, который уже стоил I-067 и R-114 (контекст AES у mbedtls лежал в
 *     куче, и его теряли). Хранилище внутри структуры не теряется: у него нет указателя;
 *   - размер хранилища — константа этого заголовка, а scrypto.c сверяет его с настоящим
 *     sizeof типа wolfSSL при компиляции (_Static_assert). Если новая версия wolfSSL или новая
 *     опция в build/wolfssl/user_settings.h увеличит структуру, сборка упадёт на месте, а не
 *     испортит соседнее поле в работе;
 *   - выравнивание объявлено у самого хранилища (16 байт). У mbedtls оно было ловушкой: контекст
 *     AES, оказавшийся на стеке по адресу, не кратному шестнадцати, ронял setkey общей защитой
 *     памяти (см. прежний STEER_AES_ALIGN16 в tgws.c). Здесь выравнивание — свойство типа, и
 *     стоит оно одно на все места, где контекст живёт.
 *
 * Цена решения — связь раскладки: libsteer и libsteer-wolfssl (шаг 4) обязаны быть собраны с
 * одним user_settings.h. Это и так условие правильности (раскладка структур wolfSSL зависит от
 * опций), и пакеты ставятся одной версией. Размеры SC_*_CTX_SIZE теперь — ABI между двумя
 * файлами, и держат его две проверки: в сборке (build/wolfssl/abi.c, те же _Static_assert, что
 * ниже в scrypto.c, но для библиотеки) и при загрузке (sc_abi_check в scrypto.c сверяет размеры
 * структур, из которых собрана загруженная libsteer-wolfssl.so, с теми, что знает libsteer).
 *
 * ПОТОКИ. Каждый контекст принадлежит одному потоку; функции без контекста (sc_hash, sc_hmac,
 * sc_hkdf_*, sc_x25519*) безопасны из любого. Хранилище корней (struct sc_roots) — общее на
 * процесс, проверка цепочки внутри себя сериализована.
 *
 * КОДЫ ВОЗВРАТА. 0 — успех, отрицательное — отказ из списка ниже. Вызывающие переводят их в свои
 * (TLS13_ECRYPTO, CERTV_*…): слою незачем знать, как отказ называется в протоколе. */
#ifndef STEER_SCRYPTO_H
#define STEER_SCRYPTO_H
#include <stddef.h>
#include <stdint.h>

#define SC_EINVAL   (-1)    /* неверный аргумент: длина, алгоритм, неразвёрнутый ключ */
#define SC_EAUTH    (-2)    /* тег AEAD не сошёлся — данные подменены или ключ не тот */
#define SC_ECRYPTO  (-3)    /* библиотека отказала там, где отказывать не должна */
#define SC_EPARSE   (-4)    /* сертификат или ключ не разобрался */
#define SC_ECHAIN   (-5)    /* цепочка не сошлась с корнями, срок вышел или имя не то */
#define SC_ESIG     (-6)    /* подпись неверна */
#define SC_ENOMEM   (-7)

/* Выравнивание хранилища контекстов: столько требуют AES-NI и ARMv8 Crypto для раундовых ключей. */
#define SC_ALIGN _Alignas(16)

/* Отпечаток сборки библиотеки: сколько полей в steer_wolfssl_abi (build/wolfssl/abi.c) — версия
 * wolfSSL, размеры структур, размеры хранилищ. Порядок полей — sc_abi_expect в scrypto.c. */
#define SC_ABI_N 13

/* ---- хеши ---------------------------------------------------------------------------------- */

/* SHA-1, SHA-224 и MD5 — не для своей криптографии, а для чужих протоколов модуля steer-proxy,
 * которые зашили их в формат провода и вывод ключей: shadowsocks (ключ из пароля — EVP_BytesToKey
 * на MD5, подключ сессии — HKDF-SHA1), trojan (пароль на проводе — hex SHA-224), VMess (cmdKey и
 * ключ ChaCha20 тела — MD5). Свой TLS и прочие протоколы их не берут. */
enum sc_hash { SC_SHA256 = 1, SC_SHA384 = 2, SC_SHA512 = 3, SC_SHA1 = 4, SC_SHA224 = 5, SC_MD5 = 6 };
#define SC_HASH_MAX 64
/* Длина вывода: 32, 48, 64, 20, 28 или 16; 0 — алгоритма нет. */
size_t sc_hash_len(enum sc_hash h);

/* Размер хранилища: SHA-512 (он же SHA-384) у wolfSSL — 224-232 байта в зависимости от
 * ускорения; запас — на обновления библиотеки, проверка — в scrypto.c. */
#define SC_HASH_CTX_SIZE 320
struct sc_hash_ctx {
    int alg;                                   /* enum sc_hash; 0 — не заведён */
    SC_ALIGN unsigned char st[SC_HASH_CTX_SIZE];
};

/* Потоковый хеш. clone нужен транскрипту TLS 1.3: хеш снимается на каждом шаге расписания
 * ключей, а сам транскрипт продолжается. final не освобождает контекст — после него он заведён
 * заново, как после init (так устроен и wolfSSL); free обязателен ровно один раз на init/clone. */
int  sc_hash_init(struct sc_hash_ctx *c, enum sc_hash h);
int  sc_hash_update(struct sc_hash_ctx *c, const void *d, size_t n);
int  sc_hash_final(struct sc_hash_ctx *c, unsigned char *out);
int  sc_hash_clone(struct sc_hash_ctx *dst, const struct sc_hash_ctx *src);
void sc_hash_free(struct sc_hash_ctx *c);
int  sc_hash(enum sc_hash h, const void *d, size_t n, unsigned char *out);

/* HMAC одним вызовом (RFC 2104). Два куска сообщения подряд — ради PRF TLS 1.2 (A(i) || seed) и
 * HKDF-Expand: склеивать их в буфер у вызывающего значило бы копию и предел длины там, где ни
 * того ни другого не нужно. msg2 может быть NULL при n2 == 0. */
int sc_hmac(enum sc_hash h, const void *key, size_t key_n,
            const void *msg, size_t n, unsigned char *out);
int sc_hmac2(enum sc_hash h, const void *key, size_t key_n,
             const void *msg, size_t n, const void *msg2, size_t n2, unsigned char *out);

/* HKDF (RFC 5869). extract пишет sc_hash_len(h) байт; пустая соль — нули длины хеша, как в RFC. */
int sc_hkdf_extract(enum sc_hash h, const void *salt, size_t salt_n,
                    const void *ikm, size_t ikm_n, unsigned char *prk);
int sc_hkdf_expand(enum sc_hash h, const void *prk, size_t prk_n,
                   const void *info, size_t info_n, unsigned char *out, size_t out_n);
int sc_hkdf(enum sc_hash h, const void *salt, size_t salt_n, const void *ikm, size_t ikm_n,
            const void *info, size_t info_n, unsigned char *out, size_t out_n);

/* ---- AEAD --------------------------------------------------------------------------------- */

enum sc_aead_alg { SC_AES128_GCM = 1, SC_AES256_GCM = 2, SC_CHACHA20_POLY1305 = 3 };

/* Ключ разворачивается ОДИН раз (sc_aead_setkey), а не на каждую запись: у AES-GCM разворот —
 * это расписание ключа и таблица GHASH, постоянная работа, которая на мелких записях (Vision шлёт
 * по 300 байт) становится основной статьёй расхода. У ChaCha20-Poly1305 разворачивать нечего, и
 * хранится сам ключ. Контекст AES у wolfSSL (Aes) — 864-896 байт; запас — на обновления. */
#define SC_AEAD_CTX_SIZE 1152
struct sc_aead {
    int alg;                                   /* enum sc_aead_alg; 0 — ключа нет */
    SC_ALIGN unsigned char st[SC_AEAD_CTX_SIZE];
};
/* Длина ключа по алгоритму: 16 или 32. nonce — всегда 12 байт, тег — всегда 16. */
size_t sc_aead_key_len(enum sc_aead_alg a);
int    sc_aead_setkey(struct sc_aead *k, enum sc_aead_alg a, const unsigned char *key);
void   sc_aead_free(struct sc_aead *k);
/* На месте: buf шифруется (расшифровывается) там же, где лежит. Тег — отдельным указателем, и
 * open его только читает: тег у TLS лежит сразу за шифротекстом, и зависеть от того, тронет ли
 * реализация соседние байты, дописывая последний блок, незачем (вызывающий копирует тег сам). */
int sc_aead_seal(struct sc_aead *k, const unsigned char nonce[12],
                 const void *aad, size_t aad_n, unsigned char *buf, size_t n,
                 unsigned char tag[16]);
int sc_aead_open(struct sc_aead *k, const unsigned char nonce[12],
                 const void *aad, size_t aad_n, unsigned char *buf, size_t n,
                 const unsigned char tag[16]);

/* ---- AES-256-CTR -------------------------------------------------------------------------- */

/* Гамма обфускации MTProto у моста tgws: ключ и начальный счётчик из рукопожатия, дальше —
 * непрерывный поток. Контекст помнит позицию внутри блока, поэтому куски любой длины подряд дают
 * ту же гамму, что один большой (как mbedtls_aes_crypt_ctr со смещением прежде). Счётчик —
 * 128-битное число big-endian, как у всех реализаций MTProto. */
#define SC_AESCTR_CTX_SIZE 1152
struct sc_aesctr {
    int ready;
    SC_ALIGN unsigned char st[SC_AESCTR_CTX_SIZE];
};
int  sc_aesctr_init(struct sc_aesctr *c, const unsigned char key[32], const unsigned char iv[16]);
int  sc_aesctr_xor(struct sc_aesctr *c, const unsigned char *in, unsigned char *out, size_t n);
void sc_aesctr_free(struct sc_aesctr *c);

/* ---- AES одним блоком (ECB) --------------------------------------------------------------- */

/* Один блок AES-128 или AES-256 (key_n — 16 или 32) на шифрование или расшифровку. Нужен там,
 * где протокол прячет блоком короткий заголовок: идентификатор VMess AEAD (AuthID), отдельный
 * заголовок UDP и заголовки личности shadowsocks 2022. Без контекста: ключ разворачивается на
 * каждый вызов — блок шифруется раз на соединение (VMess) или на датаграмму (shadowsocks 2022),
 * и развёртка рядом с AEAD самой датаграммы ничего не стоит, а хранилище на каждое соединение
 * стоило бы килобайт. */
int sc_aes_block(const unsigned char *key, size_t key_n, int decrypt,
                 const unsigned char in[16], unsigned char out[16]);

/* ---- XChaCha20-Poly1305 ------------------------------------------------------------------- */

/* AEAD с 24-байтовым nonce (draft-irtf-cfrg-xchacha) — датаграммы shadowsocks
 * 2022-blake3-chacha20-poly1305: у каждой свой случайный nonce, а ключ — сам PSK. Одним вызовом:
 * ключ на каждую датаграмму свой подключом HChaCha20, разворачивать заранее нечего. Тег — 16 байт
 * сразу за данными: seal пишет n + 16 байт в out, open читает n байт (с тегом) и пишет n - 16. */
int sc_xchacha_seal(const unsigned char key[32], const unsigned char nonce[24],
                    const void *aad, size_t aad_n, const unsigned char *in, size_t n,
                    unsigned char *out);
int sc_xchacha_open(const unsigned char key[32], const unsigned char nonce[24],
                    const void *aad, size_t aad_n, const unsigned char *in, size_t n,
                    unsigned char *out);

/* ---- SHAKE128 (FIPS 202) потоком ---------------------------------------------------------- */

/* Маска длины кусков VMess (ChunkMasking): каждый кусок тела берёт из SHAKE128(IV) два байта
 * маски длины и, при GlobalPadding, ещё два на длину набивки — и так до конца соединения, то есть
 * вывод бесконечный и читается понемногу. Вход один и короткий (16 байт IV) — он поглощается при
 * заведении. Хранилище — wc_Shake wolfSSL (около 430 байт; размер сверяют scrypto.c и
 * build/wolfssl/abi.c), плюс выжатый, но ещё не отданный блок. */
#define SC_SHAKE_CTX_SIZE 512
#define SC_SHAKE128_RATE 168
struct sc_shake {
    int ready;
    uint16_t pos;                              /* сколько байт blk уже отдано */
    unsigned char blk[SC_SHAKE128_RATE];
    SC_ALIGN unsigned char st[SC_SHAKE_CTX_SIZE];
};
int  sc_shake128_init(struct sc_shake *s, const void *in, size_t n);
int  sc_shake128_read(struct sc_shake *s, unsigned char *out, size_t n);
void sc_shake128_free(struct sc_shake *s);

/* ---- X25519 (RFC 7748) -------------------------------------------------------------------- */

/* Функция X25519 из RFC 7748 §5: скаляр ПРИЖИМАЕТСЯ внутри (на копии) — как у Go, WireGuard и
 * самого RFC, — поэтому векторы RFC проходят как есть. Нулевой общий секрет (точка малого
 * порядка у собеседника) — отказ SC_ECRYPTO: такой секрет известен всем. */
int sc_x25519(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);
/* Публичная половина: X25519(scalar, 9). */
int sc_x25519_base(unsigned char pub[32], const unsigned char scalar[32]);

/* ---- ML-KEM-768 и ML-DSA-65 (FIPS 203 и 204) ---------------------------------------------- */

/* Постквантовая часть паритета с Xray-core: половина гибрида X25519MLKEM768 в TLS 1.3 (ClientHello
 * Chrome 131+, ответ сервера REALITY), обмен «mlkem768x25519plus» у VLESS encryption и проверка
 * подписи ML-DSA-65 в сертификате REALITY (`mldsa65Verify`, `pqv` в ссылке).
 *
 * КЛЮЧИ — БАЙТАМИ, а не непрозрачными контекстами. Ключ ML-KEM у wolfSSL занимает несколько
 * килобайт и разворачивает матрицу; хранить такое значением внутри struct tls13 (как AEAD) значило
 * бы раздуть каждое соединение ради операции, которая случается один раз на рукопожатие. Поэтому
 * каждая функция сама заводит ключ в куче на время вызова и освобождает; долгоживёт у вызывающего
 * только закрытый ключ декапсуляции в закодированном виде (SC_MLKEM768_DK). Раскладка байт — FIPS 203:
 * ek — как у Go (crypto/mlkem.EncapsulationKey768.Bytes), ct — 1088 байт, ss — 32.
 *
 * СЛУЧАЙНОСТЬ ДАЁТ ВЫЗЫВАЮЩИЙ. Так Hello в стенде заморозки (tests/hellofreeze.c) остаётся
 * воспроизводимым: он подменяет единственный источник случайных байт, а не глубину библиотеки. */
#define SC_MLKEM768_EK  1184
#define SC_MLKEM768_DK  2400
#define SC_MLKEM768_CT  1088
#define SC_MLKEM768_SS  32
#define SC_MLKEM768_SEED 64     /* d || z, FIPS 203 ML-KEM.KeyGen_internal */
#define SC_MLKEM768_RND 32      /* m, FIPS 203 ML-KEM.Encaps_internal */

/* Пара ключей из seed. dk — закодированный закрытый ключ (для sc_mlkem768_decaps). */
int sc_mlkem768_keygen(unsigned char ek[SC_MLKEM768_EK], unsigned char dk[SC_MLKEM768_DK],
                       const unsigned char seed[SC_MLKEM768_SEED]);
/* Проверка ключа, пришедшего от собеседника (FIPS 203, 7.2): коэффициенты меньше q. Go отвергает
 * такие ключи в NewEncapsulationKey768, и мы тоже. SC_EPARSE — не ключ. */
int sc_mlkem768_ek_check(const unsigned char ek[SC_MLKEM768_EK]);
int sc_mlkem768_encaps(unsigned char ct[SC_MLKEM768_CT], unsigned char ss[SC_MLKEM768_SS],
                       const unsigned char ek[SC_MLKEM768_EK], const unsigned char rnd[SC_MLKEM768_RND]);
/* Декапсуляция. Неверный шифротекст ML-KEM не отвергает (неявный отказ): вернётся псевдослучайный
 * секрет, и обнаружит расхождение уже AEAD. */
int sc_mlkem768_decaps(unsigned char ss[SC_MLKEM768_SS], const unsigned char dk[SC_MLKEM768_DK],
                       const unsigned char ct[SC_MLKEM768_CT]);

#define SC_MLDSA65_PK   1952
#define SC_MLDSA65_SIG  3309
/* Проверить подпись ML-DSA-65 с ПУСТЫМ контекстом (как mldsa65.Verify(pk, msg, nil, sig) в circl).
 * 0 — верна, SC_ESIG — нет, SC_EPARSE — ключ или длина не те. */
int sc_mldsa65_verify(const unsigned char pk[SC_MLDSA65_PK], const unsigned char *msg, size_t msg_n,
                      const unsigned char *sig, size_t sig_n);

/* ---- BLAKE3 (VLESS encryption) ------------------------------------------------------------ */

/* BLAKE3 нужен только VLESS encryption: им Xray выводит ключи AEAD (DeriveKey с контекстом-строкой),
 * ключи гаммы xorpub/random и хеш ключей реле. В wolfSSL его нет, реализация своя, без библиотеки
 * (src/lib/blake3.c), и работает на любой длине входа — контекст NewAEAD бывает длиннее
 * килобайта (1216 байт открытого ключа), то есть больше одного чанка и с деревом. Порт reference
 * implementation, проверен векторами из репозитория BLAKE3 (tests/scryptomatch.c). */
void sc_blake3_hash(unsigned char out[32], const void *in, size_t n);
/* blake3.DeriveKey(out, context, material) из lukechampine.com/blake3: режим derive_key, контекст —
 * произвольные байты. out_n — до 64. */
void sc_blake3_derive_key(unsigned char *out, size_t out_n, const void *ctx, size_t ctx_n,
                          const void *material, size_t material_n);

/* ---- ECDSA P-256: ключ клиента MASQUE (модуль steer-warpbox) ---------------------------------
 *
 * Закрытый ключ — 32 байта скаляра, открытый — 65 байт несжатой точки 04||X||Y. Подпись — над
 * готовым хешем SHA-256, в DER (SEQUENCE r, s), до SC_P256_SIG_MAX байт. 0 — готово. */
#define SC_P256_SIG_MAX 72
int sc_p256_keygen(unsigned char priv[32], unsigned char pub[65]);
int sc_p256_public(const unsigned char priv[32], unsigned char pub[65]);
int sc_p256_sign(const unsigned char priv[32], const unsigned char digest[32],
                 unsigned char *sig, size_t *sig_n);

/* ---- подписи и сертификаты ---------------------------------------------------------------- */

enum sc_sig_alg { SC_SIG_RSA_PKCS1 = 1, SC_SIG_RSA_PSS = 2, SC_SIG_ECDSA = 3 };

/* Проверить подпись над ГОТОВЫМ хешем ключом из сертификата (DER).
 *
 * У PSS соль любой длины, MGF1 — тем же хешем (RFC 8446 §4.2.3). У ECDSA подпись — DER
 * (r, s), кривая — P-256 или P-384 из сертификата. У PKCS#1 v1.5 — DigestInfo с OID хеша.
 * Сертификат разбирается только ради ключа: его подлинность — дело sc_chain_verify. */
int sc_cert_verify_sig(const unsigned char *cert_der, size_t cert_n,
                       enum sc_sig_alg alg, enum sc_hash h,
                       const unsigned char *digest, size_t digest_n,
                       const unsigned char *sig, size_t sig_n);

/* Хранилище корней: разбирается один раз на процесс из текста PEM (ca-bundle), живёт до
 * выхода. Записи, которые не разобрались (алгоритм, которого нет в сборке, истёкший корень), —
 * пропускаются: требовать идеального разбора значило бы остаться без корней целиком из-за
 * одного экзотического. Ни одного корня — SC_EPARSE. */
struct sc_roots;
int  sc_roots_load(struct sc_roots **out, const unsigned char *pem, size_t n);
/* Хранилище из одного сертификата DER (закреплённый центр); не годится в центры — SC_EPARSE. */
int  sc_roots_load_der(struct sc_roots **out, const unsigned char *der, size_t n);
void sc_roots_free(struct sc_roots *r);

/* Проверить цепочку сервера: der[0] — лист, дальше — промежуточные в любом порядке и с
 * запасом (лишний не мешает). Проверяется путь до корня из хранилища (подписи, CA и keyCertSign
 * у промежуточных, ограничение длины пути), срок каждого сертификата на текущее время и имя
 * host в листе (SAN; адрес — по SAN IP). 0 — сервер подлинный, SC_ECHAIN — нет (причина одна
 * на всё: «не сошёлся с корнями или выдан не на это имя» — так её и называет certverify.c),
 * SC_EPARSE — лист не разобрался. */
int sc_chain_verify(struct sc_roots *r, const unsigned char *const *der, const size_t *der_n,
                    size_t count, const char *host);

#endif
