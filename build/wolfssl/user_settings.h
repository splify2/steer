/* Опции сборки wolfSSL для steer — ЕДИНСТВЕННОЕ место, где они записаны.
 *
 * Этот файл видит каждый .c wolfSSL (ключ -DWOLFSSL_USER_SETTINGS, settings.h подключает
 * user_settings.h по имени) и каждый .c движка, который включает заголовок wolfSSL, — то есть
 * ровно один: src/lib/scrypto.c. Больше wolfSSL в дереве не видит никто, и это не вкус, а
 * условие правильности: раскладка структур wolfSSL (Aes, wc_Sha256, Hmac…) зависит от этих
 * макросов, и библиотека, собранная с одними, рядом с вызывающим, собранным с другими, портит
 * память молча. Поэтому опций нет ни в командных строках сборок, ни в configure: их читают
 * build/wolfssl/build.sh (роутер, стенды, замеры), рецепт SDK и Android.bp — один файл на все.
 * Шаг 4 выпуска 1.10 (пакет libsteer-wolfssl, .so) берёт его же.
 *
 * ЧТО НУЖНО И ЗАЧЕМ (docs/architecture.md, «Криптография»). Своему TLS 1.3 и
 * REALITY (src/proto/tls) нужны только примитивы: SHA-256/384/512, HMAC, HKDF, AES-GCM,
 * ChaCha20-Poly1305, AES-256-CTR (мост tgws), X25519, проверка цепочки X.509 с именем и сроком
 * и подписей RSA (PKCS#1 v1.5 и PSS) и ECDSA P-256/P-384. TLS-стек самой wolfSSL нам не нужен —
 * TLS у нас свой, — но он нужен QUIC: ngtcp2 (DoQ в 1.11, hysteria2) работает поверх wolfSSL_quic_*,
 * а те стоят на TLS 1.3 wolfSSL, её SNI, ALPN, билетах сессии и слое EVP (OPENSSL_EXTRA —
 * configure wolfSSL включает его при --enable-quic принудительно, и ngtcp2 зовёт wolfSSL_EVP_*).
 * Поэтому QUIC включён заранее: пакет libsteer-wolfssl собирается один раз и для модулей
 * протоколов, и для будущего ngtcp2, а второго набора опций под QUIC не будет.
 *
 * ЧЕГО НЕТ НАМЕРЕННО. Ни opensslall, ни stunnel, ни lighty (их включает пакет libwolfssl
 * OpenWrt ради чужих программ); ни TLS 1.2 и старше в wolfSSL (наш TLS 1.2 для точки
 * web.telegram.org свой, в tls13.c), ни сервера TLS (QUIC у нас только клиент), ни DH, DSA,
 * DES, RC4, MD4, PSK, PBKDF; ни файловой системы (корни читает certverify.c сам, буфером) и
 * ни сокетного ввода-вывода (WOLFSSL_USER_IO: QUIC отдаёт байты через ngtcp2, а не сокет).
 * Ed25519 не нужен: сертификат REALITY разбирается своим кодом и сверяется HMAC-SHA512
 * (certverify.c), а не подписью.
 *
 * РАЗМЕР. В статическом бинарнике то, что не вызывается, выбрасывает компоновщик (-ffunction-
 * sections и --gc-sections в build.sh, LTO у zig), поэтому QUIC, EVP и TLS-стек wolfSSL места в
 * steerd не занимают, пока их никто не зовёт. В разделяемой libsteer-wolfssl.so (шаг 4) они
 * будут целиком — это цена одного пакета на все модули, и она меряется там же.
 */
#ifndef STEER_WOLFSSL_USER_SETTINGS_H
#define STEER_WOLFSSL_USER_SETTINGS_H

/* ---- платформа ------------------------------------------------------------------------- */
/* Источник случайности для DRBG — getrandom(2), а не открытие /dev/urandom: у процесса на
 * телефоне под SELinux нет права открывать устройство, а системный вызов разрешён всем, и на
 * роутере он есть с ядра 3.17. Свои случайные байты движок берёт так же (reality.c). */
#define WOLFSSL_GETRANDOM
#define NO_FILESYSTEM
#define WOLFSSL_USER_IO
/* Без сокетного ввода-вывода wolfio.h не подключает <sys/time.h>, а tls13.c wolfSSL на Linux
 * ждёт gettimeofday именно оттуда (время билетов сессии). Неявное объявление — ошибка у Soong
 * (-Werror=implicit-function-declaration), поэтому заголовок подключается здесь. Не для
 * ассемблера: этот файл видят и .S (через settings.h), а C-заголовок в них не разбирается. */
#if !defined(__ASSEMBLER__) && defined(__linux__)
#include <sys/time.h>
#endif
/* Потоки соединителей туннеля живут со скромным стеком (src/tunnel/tunnel.c), а разбор
 * сертификата и математика RSA держат на стеке килобайты. SMALL_STACK переносит крупные
 * временные буферы в кучу — медленнее на проценты там, где скорость не важна (рукопожатие), и
 * безопасно там, где переполнение стека молча портит соседний поток. */
#define WOLFSSL_SMALL_STACK
/* Файлы, которые wolfSSL включает в другие .c (ssl_*.c в ssl.c, misc.c как inline), собираются и
 * отдельно — пустыми; без этого ключа каждый такой файл предупреждает, а наши сборки
 * предупреждений не терпят (Soong — -Werror). */
#define WOLFSSL_IGNORE_FILE_WARN
#define NO_ERROR_STRINGS
/* Воспроизводимая сборка: без даты и времени сборки в бинарнике (строка OpenSSL_version слоя
 * совместимости). Один и тот же исходник обязан давать один и тот же пакет, а Soong отвергает
 * __DATE__ и __TIME__ вовсе (-Werror=date-time). То же делает пакет OpenWrt
 * (--enable-reproducible-build). */
#define HAVE_REPRODUCIBLE_BUILD

/* Порядок байт — по компилятору. wolfSSL берёт BIG_ENDIAN_ORDER только из WORDS_BIGENDIAN (types.h),
 * которого у нашего рецепта нет (ни configure, ни config.h), и на big-endian цели (mips_24kc) молча
 * считала бы SHA, HMAC и AES-GCM как на little-endian: векторы RFC на ней не сходились. Для остальных
 * девяти целей (все little-endian) ничего не меняется. */
#if defined(__BYTE_ORDER__) && defined(__ORDER_BIG_ENDIAN__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BIG_ENDIAN_ORDER
#endif

/* ---- TLS-стек wolfSSL: ровно то, что нужно QUIC --------------------------------------- */
#define WOLFSSL_TLS13
#define WOLFSSL_NO_TLS12
#define NO_OLD_TLS
/* Сервера TLS в поставляемой библиотеке нет. Ключ STEER_WOLFSSL_SERVER даёт его стендам
 * (tests/ext-test.sh: эхо-сервер QUIC для проверки клиента), как WOLFSSL_CERT_GEN — выпуск
 * сертификатов; сборки движка его не задают никогда. */
#ifndef STEER_WOLFSSL_SERVER
#define NO_WOLFSSL_SERVER
#endif
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_SNI
#define HAVE_ALPN
#define HAVE_SESSION_TICKET
/* 0-RTT (early data) у клиента QUIC: DoQ отправляет первый вопрос в пакетах 0-RTT по билету прошлой
 * сессии (RFC 9250 разрешает — вопрос DNS идемпотентен), см. src/proto/quic/quic.c. Без этого
 * определения wolfSSL_set_quic_early_data_enabled и max_early_data билета в библиотеке нет. Цена —
 * разбор расширения early_data и хранение лимита в билете, порядка килобайта кода; серверной половины
 * (приём 0-RTT) в поставляемой сборке нет по-прежнему. */
#define WOLFSSL_EARLY_DATA
#define WOLFSSL_QUIC
#define HAVE_EX_DATA
#define OPENSSL_EXTRA

/* ---- примитивы ------------------------------------------------------------------------- */
#define HAVE_HKDF
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512
/* SHA-384/512 нужны рукопожатию (набор TLS_AES_256_GCM_SHA384, HMAC-SHA512 у REALITY, подписи в
 * сертификатах) — десяток вызовов на соединение, а развёрнутый цикл сжатия стоил 12 КБ флеша.
 * SHA-256 (им же считается и транскрипт, и Noise у xsteer) остаётся быстрым. */
#define USE_SLOW_SHA512
#define HAVE_HASHDRBG

#define HAVE_AESGCM
/* Таблица GHASH на 4 бита (256 байт на ключ), а не на 8 (4 КБ): ключей в процессе столько же,
 * сколько направлений у соединений, и при 64 соединениях 8-битная таблица стоила бы полмегабайта
 * памяти. mbedtls, которую wolfSSL здесь сменила, держала ту же 4-битную. */
#define GCM_TABLE_4BIT
/* AES-256-CTR — гамма обфускации MTProto у моста tgws (src/proto/tgws/tgws.c). DIRECT нужен
 * установке ключа без режима (wc_AesSetKeyDirect) и прямому шифрованию блока. */
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
/* AES-ECB — защита заголовка пакета QUIC (RFC 9001, раздел 5.4.3): ngtcp2 берёт маску из
 * одного блока AES-128/256-ECB через слой EVP (wolfSSL_EVP_aes_{128,256}_ecb). ChaCha20 для
 * той же цели (TLS_CHACHA20_POLY1305_SHA256) — HAVE_CHACHA ниже. */
#define HAVE_AES_ECB
#define NO_AES_192
#define NO_AES_CBC
/* NO_AES_DECRYPT (без таблицы Td и обратного блока — GCM и CTR им не пользуются) здесь был бы
 * законен по смыслу, но в wolfSSL 5.9.4 он заодно снимает wc_AesGcmDecrypt — проверено сборкой.
 * Поэтому не задан. */

#define HAVE_CHACHA
#define HAVE_POLY1305
#define HAVE_ONE_TIME_AUTH

#define HAVE_CURVE25519

#define HAVE_ECC
#define ECC_USER_CURVES
#undef  NO_ECC256
#define HAVE_ECC384
#define ECC_SHAMIR
#define ECC_TIMING_RESISTANT

/* ---- постквантовая часть (паритет с Xray-core) ------------------------------------------ */
/* ML-KEM-768 - половина гибрида X25519MLKEM768 в TLS 1.3 (ClientHello Chrome 131+, ответ
 * сервера REALITY) и обмен «mlkem768x25519plus» у VLESS encryption. ML-KEM-512 и -1024 не
 * нужны никому из тех, кого клиент встречает (Xray и Go используют ровно 768), и без них
 * снимается треть таблиц и кода.
 *
 * SHA-3 (SHAKE128/256, SHA3-256/512) - то, на чём стоит ML-KEM: матрица A разворачивается из seed
 * SHAKE128, шум - SHAKE256, хеши ключа и шифротекста - SHA3.
 *
 * ML-DSA-65 нужна ТОЛЬКО ДЛЯ ПРОВЕРКИ: REALITY кладёт подпись в расширение поддельного
 * сертификата, и клиент, у которого в узле задан mldsa65Verify (`pqv` в ссылке), обязан её
 * проверить. Подписывать и выпускать ключи мы не будем никогда, поэтому VERIFY_ONLY снимает
 * подпись, генерацию и разбор закрытого ключа; ASN.1-разбор не нужен (ключ приходит сырым 1952
 * байта). Экономящих память вариантов (SMALL_MEM) не берём: проверка редкая, но скорость не
 * режем ради килобайт (решение владельца: скорость важнее веса). */
/* ML-KEM — переносимым C, без ассемблера aarch64 (WOLFSSL_ARMASM у wolfSSL включает armv8-mlkem-asm, а тот
 * требует SQRDMLAH из ARMv8.1 (`rdm`): на Cortex-A53 роутеров и в базовой цели NDK его нет, ассемблер
 * отказывает в сборке). Скорость: рукопожатие делает по одному keygen и decaps на соединение, это доли
 * миллисекунды у x86 и единицы у слабых ядер; узким местом оно не бывает. */
#define WC_MLKEM_NO_ASM
#define WOLFSSL_HAVE_MLKEM
#define WOLFSSL_WC_MLKEM
#define WOLFSSL_NO_ML_KEM_512
#define WOLFSSL_NO_ML_KEM_1024
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128
#define WOLFSSL_SHAKE256
#define WOLFSSL_HAVE_MLDSA
#define WOLFSSL_WC_MLDSA
#define WOLFSSL_MLDSA_VERIFY_ONLY
#define WOLFSSL_MLDSA_NO_ASN1
#define WOLFSSL_NO_ML_DSA_44
#define WOLFSSL_NO_ML_DSA_87

#define WC_RSA_PSS
/* Соль PSS любой длины — как MBEDTLS_RSA_SALT_LEN_ANY прежде: RFC 8446 требует соль длиной с
 * хеш, но встречаются серверы (и переподписывающие посредники), у которых она другая, и
 * отвергать их значило бы объявить узел неисправным там, где подпись верна (certverify.c). */
#define WOLFSSL_PSS_SALT_LEN_DISCOVER
#define WOLFSSL_PSS_LONG_SALT
#define WC_RSA_BLINDING
#define TFM_TIMING_RESISTANT
#define WOLFSSL_SP_MATH_ALL
/* Математика больших чисел нужна только проверке цепочки у security=tls — несколько операций на
 * рукопожатие, — поэтому размер кода здесь важнее скорости. */
#define WOLFSSL_SP_SMALL

#define WOLFSSL_ASN_TEMPLATE
/* Имя в сертификате бывает и адресом (DoH на 1.1.1.1): без этих двух IP из SAN не разбирается,
 * и проверка имени отвергла бы честный сертификат. */
#define WOLFSSL_ALT_NAMES
#define WOLFSSL_IP_ALT_NAME

/* MD5, SHA-224 и XChaCha20-Poly1305 — ради протоколов модуля steer-proxy, а не своей
 * криптографии (src/lib/scrypto.h): MD5 зашит в вывод ключей shadowsocks (EVP_BytesToKey) и VMess
 * (cmdKey, ключ ChaCha20 тела), SHA-224 — в пароль trojan на проводе, XChaCha20-Poly1305 — в
 * датаграммы shadowsocks 2022-blake3-chacha20-poly1305. В TLS MD5 не попадает: старые версии TLS,
 * где он был частью рукопожатия, сняты (NO_OLD_TLS выше). */
#define WOLFSSL_SHA224
#define HAVE_XCHACHA

#define NO_DSA
#define NO_DH
#define NO_RC4
#define NO_MD4
#define NO_DES3
#define NO_DES3_TLS_SUITES
#define NO_PSK
#define NO_PWDBASED

/* ---- ускорение по архитектуре ---------------------------------------------------------- */
/* x86_64: AES-NI, PCLMUL и AVX/AVX2 — только для AES и AES-GCM, ассемблером wolfSSL (файлы
 * aes_x86_64_asm.S и aes_gcm_asm.S), с выбором по CPUID во время работы: на процессоре без AES-NI
 * путь программный, и бинарник запускается там же, где запускался. Ключ ставит
 * build/wolfssl/build.sh вместе с файлами .S; сборка, где их нет (Android.bp, Soong не собирает
 * здесь ассемблер), остаётся на переносимом C.
 *
 * Почему не USE_INTEL_SPEEDUP целиком (ассемблер ещё и для ChaCha20, Poly1305, SHA и X25519).
 * Замерено сборкой: он добавлял бинарнику x86_64 больше 540 КБ — ассемблер в один раздел, и
 * компоновщик не выбрасывает из него неиспользуемые ветки AVX-512 и VAES. На x86_64 шифр туннеля —
 * AES-GCM (reality.c выбирает его по AES-NI, как Chrome), поэтому ускоряется ровно он, а VAES и
 * AVX-512 (процессоры, которых в роутерах нет) сняты. */
#if defined(STEER_WOLFSSL_ASM) && defined(__x86_64__)
#define WOLFSSL_X86_64_BUILD
#define WOLFSSL_AESNI
#define USE_INTEL_SPEEDUP_FOR_AES
#define NO_VAES_SUPPORT
#define NO_AVX512_SUPPORT
#endif
/* aarch64: ARMv8 Crypto для AES, PMULL для GHASH, NEON для ChaCha20 и Poly1305, свой код X25519 и
 * SHA — встроенным ассемблером wolfSSL (файлы port/arm/armv8-*_c.c, то есть обычный C, который
 * собирает и zig, и NDK). Инструкции криптографии выбираются по getauxval(AT_HWCAP) во время
 * работы (wolfcrypt/src/cpuid.c, aes->use_aes_hw_crypto): на Cortex-A53 без расширения (Raspberry
 * Pi 4 и родня) AES идёт программно, а не падает с SIGILL. Прежде тот же путь давала mbedtls
 * (MBEDTLS_AESCE_C) — без него AES-GCM на роутерах aarch64 откатился бы к таблицам. Файлы вне
 * aarch64 собираются в пустоту, поэтому список у build.sh и Android.bp общий. */
#if defined(__aarch64__) && !defined(STEER_WOLFSSL_NO_ARMASM)
#define WOLFSSL_ARMASM
#define WOLFSSL_ARMASM_INLINE
#endif

#endif
