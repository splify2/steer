/* Проверка сертификата сервера для security=tls. Объяснение, зачем отдельный файл, — в
 * certverify.h.
 *
 * ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ И ПОЧЕМУ ИМЕННО ЭТО. У security=tls нет ничего, кроме сертификата.
 * Reality доказывает подлинность сервера аутентификатором, который умеет посчитать только
 * владелец постоянного ключа; у обычного TLS такого ключа нет, и единственное доказательство —
 * цепочка до корня плюс подпись CertificateVerify над транскриптом. Пропустить любую из двух
 * половин значит не проверить ничего: цепочка без подписи доказывает лишь то, что кто-то
 * когда-то получил сертификат на это имя, а подпись без цепочки — что собеседник владеет
 * ключом, который мы же у него и взяли.
 *
 * ЧЕГО ЗДЕСЬ НЕТ. Ни OCSP, ни списков отзыва: на роутере их нечем и некогда качать, а
 * молчаливая имитация проверки хуже честного её отсутствия. Срок действия каждого сертификата
 * цепочки проверяет библиотека по текущему времени (sc_chain_verify), и это единственная
 * временная проверка, на которую мы опираемся.
 *
 * Сама проверка — за слоем примитивов (src/lib/scrypto.h): путь до корня, признаки CA и имя
 * строит и проверяет wolfSSL, подпись CertificateVerify — wolfCrypt. Здесь остаётся то, что
 * относится к TLS 1.3, а не к X.509: разбор сообщений Certificate и CertificateVerify, строка
 * с приставкой, которую подписывает сервер, и выбор алгоритма по коду из сообщения.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

#include "scrypto.h"
#include "certverify.h"

/* ---- хранилище корней ---------------------------------------------------------------
 *
 * Каждый ПУТЬ разбирается один раз на процесс. Файл ca-bundle — 182 КБ и полторы сотни
 * сертификатов; разбирать его на каждое соединение значило бы полсекунды и треть мегабайта на
 * КАЖДУЮ попытку узла, а сторож перебирает узлы пачками. Соединители работают в нескольких
 * потоках (tunnel.c), поэтому поиск и первая загрузка — под замком: два одновременных первых
 * обращения иначе разобрали бы хранилище дважды.
 *
 * ОДНИМ ХРАНИЛИЩЕМ НА ПРОЦЕСС оно было прежде (pthread_once и путь в глобале): путь первого
 * вызова действовал навсегда, а запись пути в общий указатель была гонкой данных (I-217). Путь —
 * шов для стенда («нужен свой набор, а на роутере это файл пакета ca-bundle»), и стенд, передавший
 * своё хранилище после одного соединения с умолчанием, молча проверял бы системными корнями.
 * Теперь ключ хранилища — сам путь; разные пути живут рядом. Список не ограничен: путей в
 * процессе столько, сколько их передали (умолчание и, у стенда, пара своих).
 *
 * Освобождения нет намеренно: хранилище живёт столько же, сколько процесс, и «освободить перед
 * выходом» здесь означало бы код, который исполняется ровно в момент, когда его результат уже
 * никому не нужен. Это же делает безопасным отдавать указатель вызывающему без счётчика ссылок:
 * запись списка не исчезает и не меняется после вставки. */
struct roots_ent {
    char *path;
    struct sc_roots *store;
    int rc;                    /* 0 — загружено; иначе CERTV_ENOROOTS (и так же навсегда, как раньше) */
    struct roots_ent *next;
};
static struct roots_ent *g_roots_list;
static pthread_mutex_t g_roots_mu = PTHREAD_MUTEX_INITIALIZER;

static int roots_read(const char *path, struct sc_roots **out) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    /* Верхняя граница — не паранойя: путь приходит из настройки, и указать им, скажем,
     * /dev/zero не должно означать «съесть всю память роутера». Нынешний ca-bundle весит
     * 182 КБ, восьми мегабайт хватит любому разумному хранилищу. */
    if (sz <= 0 || sz > 8 * 1024 * 1024) { fclose(f); return -1; }
    rewind(f);

    /* +1 байт под ноль: разбору PEM он не нужен, но текст, который где-то дальше прочтут как
     * строку, без терминатора — ловушка, и байт за неё — не цена. */
    unsigned char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';

    /* Записи, которые не разобрались, слой пропускает: в хранилище встречаются корни с
     * алгоритмами, которых нет в нашей сборке wolfSSL (и истёкшие), и требовать идеального
     * разбора значило бы остаться без корней целиком из-за одного экзотического. Отказ здесь —
     * только когда не разобралось НИЧЕГО. */
    int rc = sc_roots_load(out, buf, got);
    free(buf);
    return rc == 0 ? 0 : -1;
}

/* Хранилище по пути (NULL/"" — умолчание). 0 — готово, *out указывает на хранилище; иначе
 * CERTV_ENOROOTS. */
static int roots_get(const char *roots, struct sc_roots **out) {
    const char *path = roots && roots[0] ? roots : CERTV_DEFAULT_ROOTS;
    pthread_mutex_lock(&g_roots_mu);
    struct roots_ent *e = g_roots_list;
    while (e && strcmp(e->path, path)) e = e->next;
    if (!e) {
        e = calloc(1, sizeof(*e));
        if (e) e->path = strdup(path);
        if (!e || !e->path) {                   /* память: запись не заводим, повтор при следующем вызове */
            free(e);
            pthread_mutex_unlock(&g_roots_mu);
            return CERTV_ENOROOTS;
        }
        e->rc = roots_read(path, &e->store) == 0 ? 0 : CERTV_ENOROOTS;
        e->next = g_roots_list;
        g_roots_list = e;
    }
    int rc = e->rc;
    if (rc == 0) *out = e->store;
    pthread_mutex_unlock(&g_roots_mu);
    return rc;
}

/* ---- разбор сообщения Certificate (RFC 8446 §4.4.2) ---------------------------------
 *
 * Тело: контекст запроса (1 байт длины и байты), затем список длиной в 3 байта, а в нём
 * записи «3 байта длины + DER» с двухбайтовым хвостом расширений у каждой. Расширения не
 * читаются: в них бывает разве что signed_certificate_timestamp, на решение он не влияет.
 */
/* Сколько сертификатов цепочки берётся в проверку. Настоящие цепочки — два-четыре; всё, что
 * сверх шестнадцати, отбрасывается, а не роняет проверку: если нужный промежуточный оказался
 * семнадцатым, путь до корня не построится, и это будет честный отказ цепочки. */
#define CHAIN_MAX 16

/* Разобрать сообщение на куски DER — сами сертификаты разбирает библиотека (sc_chain_verify):
 * лист, который не разобрался, — отказ «сертификат не разобрался», промежуточный — пропуск
 * (цепочка нередко приезжает с запасом, и незнакомый алгоритм в лишнем сертификате ничего не
 * решает). */
static int parse_chain(const unsigned char *b, size_t n, const unsigned char **der,
                       size_t *der_n, size_t *count) {
    *count = 0;
    if (n < 1) return CERTV_EPARSE;
    size_t p = 1 + b[0];                       /* certificate_request_context */
    if (p + 3 > n) return CERTV_EPARSE;
    size_t list = ((size_t)b[p] << 16) | ((size_t)b[p + 1] << 8) | b[p + 2];
    p += 3;
    if (p + list > n) return CERTV_EPARSE;

    size_t end = p + list;
    while (p + 3 <= end) {
        size_t clen = ((size_t)b[p] << 16) | ((size_t)b[p + 1] << 8) | b[p + 2];
        p += 3;
        if (clen == 0 || p + clen > end) return CERTV_EPARSE;
        if (*count < CHAIN_MAX) {
            der[*count] = b + p;
            der_n[*count] = clen;
            (*count)++;
        }
        p += clen;
        if (p + 2 > end) break;
        size_t elen = ((size_t)b[p] << 8) | b[p + 1];
        p += 2;
        if (p + elen > end) return CERTV_EPARSE;
        p += elen;
    }
    return *count ? 0 : CERTV_EPARSE;
}

/* ---- подпись CertificateVerify (RFC 8446 §4.4.3) ------------------------------------
 *
 * Подписываются не байты транскрипта, а строка с приставкой: 64 пробела, «TLS 1.3, server
 * CertificateVerify», нулевой байт и хеш транскрипта. Приставка нужна затем, чтобы подпись
 * нельзя было переставить между ролями и версиями протокола, и без неё сервер не сойдётся.
 */
static const char CV_LABEL[] = "TLS 1.3, server CertificateVerify";

/* Алгоритм подписи из двух байт кода. Поддержаны РОВНО те, что мы предлагаем в
 * signature_algorithms (см. reality.c), минус rsa_pkcs1_*: в TLS 1.3 подписывать ими
 * CertificateVerify запрещено (RFC 8446 §4.4.3), они остаются только для подписей ВНУТРИ
 * сертификатов. Сервер, выбравший что-то ещё, нарушает наш же список — это отдельная
 * причина, а не «подпись не сошлась». */
/* secp521r1 (0x0603) в списке есть, а в сборке wolfSSL кривой P-521 нет (build/wolfssl/
 * user_settings.h): такую подпись мы не предлагаем (Chrome её не предлагает, reality.c тоже), и
 * сервер, выбравший её, получит отказ «подпись неверна» — ключ из сертификата не разберётся. */
static int sig_alg(unsigned code, enum sc_hash *md, enum sc_sig_alg *alg) {
    switch (code) {
        case 0x0403: *md = SC_SHA256; *alg = SC_SIG_ECDSA; return 0;  /* ecdsa_secp256r1 */
        case 0x0503: *md = SC_SHA384; *alg = SC_SIG_ECDSA; return 0;  /* ecdsa_secp384r1 */
        case 0x0603: *md = SC_SHA512; *alg = SC_SIG_ECDSA; return 0;  /* ecdsa_secp521r1 */
        case 0x0804: *md = SC_SHA256; *alg = SC_SIG_RSA_PSS; return 0;  /* rsa_pss_rsae */
        case 0x0805: *md = SC_SHA384; *alg = SC_SIG_RSA_PSS; return 0;
        case 0x0806: *md = SC_SHA512; *alg = SC_SIG_RSA_PSS; return 0;
        case 0x0809: *md = SC_SHA256; *alg = SC_SIG_RSA_PSS; return 0;  /* rsa_pss_pss */
        case 0x080A: *md = SC_SHA384; *alg = SC_SIG_RSA_PSS; return 0;
        case 0x080B: *md = SC_SHA512; *alg = SC_SIG_RSA_PSS; return 0;
        default: return CERTV_EALG;
    }
}

static int check_signature(const unsigned char *leaf, size_t leaf_n,
                           const unsigned char *cv, size_t cv_n,
                           const unsigned char *transcript, size_t thash_n) {
    if (cv_n < 4) return CERTV_EPARSE;
    unsigned code = ((unsigned)cv[0] << 8) | cv[1];
    size_t sig_n = ((size_t)cv[2] << 8) | cv[3];
    if (4 + sig_n != cv_n) return CERTV_EPARSE;

    enum sc_hash mdt;
    enum sc_sig_alg alg;
    int rc = sig_alg(code, &mdt, &alg);
    if (rc) return rc;
    size_t hn = sc_hash_len(mdt);

    /* ДЛИНА ТРАНСКРИПТА И ДЛИНА ХЕША ПОДПИСИ — РАЗНЫЕ ВЕЛИЧИНЫ, и путать их нельзя.
     *
     * Транскрипт хешируется хешем НАБОРА ШИФРОВ (RFC 8446 §4.4.1): у TLS_AES_256_GCM_SHA384
     * это 48 байт. Подпись же считается алгоритмом из самого CertificateVerify, и сервер
     * вправе выбрать rsa_pss_rsae_sha256 — 32 байта. Первая версия требовала их совпадения и
     * отвергала такое сочетание как «сертификат не разобрался»: снято на www.microsoft.com,
     * где набор SHA-384, а подпись SHA-256, — узел выглядел неисправным, притом что сервер
     * безупречен, а yandex.ru и wikipedia.org с совпадающими длинами проходили. */
    if (thash_n == 0 || thash_n > 64) return CERTV_EPARSE;

    /* 64 + 33 + 1 + 64 = 162 — с запасом на самый длинный транскрипт. */
    unsigned char content[176];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, CV_LABEL, sizeof(CV_LABEL) - 1); cn += sizeof(CV_LABEL) - 1;
    content[cn++] = 0x00;
    memcpy(content + cn, transcript, thash_n); cn += thash_n;

    unsigned char digest[64];
    if (sc_hash(mdt, content, cn, digest) != 0) return CERTV_ESIG;

    /* У PSS соль ЛЮБОЙ длины (так слой и проверяет). RFC 8446 требует, чтобы она равнялась
     * длине хеша, но встречаются серверы (и посредники, переподписывающие поток), у которых она
     * другая; отвергать их значило бы объявить узел неисправным там, где подпись верна. Ключ
     * не того вида (ECDSA-подпись на ключе RSA) — тоже «подпись неверна», как и прежде. */
    return sc_cert_verify_sig(leaf, leaf_n, alg, mdt, digest, hn, cv + 4, sig_n) == 0
               ? 0 : CERTV_ESIG;
}

int cert_verify_server(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *cv_body, size_t cv_n,
                       const unsigned char *transcript, size_t thash_n,
                       const char *host, const char *roots) {
    return cert_verify_server_ex(cert_body, cert_n, cv_body, cv_n, transcript, thash_n, host, roots, NULL);
}

static int der_next(const unsigned char **p, const unsigned char *end,
                    unsigned char *tag, const unsigned char **val, size_t *val_n);

/* Есть ли отпечаток h среди записей списка (64 знака hex строчными, через запятую). */
static int pin_listed(const char *list, const unsigned char h[32]) {
    static const char HEX[] = "0123456789abcdef";
    char want[64];
    if (!list) return 0;
    for (int i = 0; i < 32; i++) { want[2 * i] = HEX[h[i] >> 4]; want[2 * i + 1] = HEX[h[i] & 15]; }
    for (const char *p = list; *p;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        if (n == 64 && !memcmp(p, want, 64)) return 1;
        if (!e) break;
        p = e + 1;
    }
    return 0;
}

/* SubjectPublicKeyInfo сертификата целиком, вместе с заголовком (его и хеширует sing-box).
 * tbsCertificate ::= [0] version (необязательно), serial, signature, issuer, validity, subject, spki:
 * седьмое поле, либо шестое, если версии нет. Обход настоящий: у issuer и subject длина переменная. */
static int spki_of(const unsigned char *der, size_t n, const unsigned char **spki, size_t *spki_n) {
    const unsigned char *p = der, *end = der + n, *v;
    unsigned char tag;
    size_t vn;
    if (der_next(&p, end, &tag, &v, &vn) != 0 || tag != 0x30) return -1;   /* Certificate */
    const unsigned char *ip = v, *iend = v + vn;
    if (der_next(&ip, iend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* tbs */
    const unsigned char *tp = v, *tend = v + vn;
    const unsigned char *start;
    if (tp < tend && *tp == 0xA0 && der_next(&tp, tend, &tag, &v, &vn) != 0) return -1;
    for (int i = 0; i < 5; i++)                   /* serial, signature, issuer, validity, subject */
        if (der_next(&tp, tend, &tag, &v, &vn) != 0) return -1;
    start = tp;
    if (der_next(&tp, tend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;
    *spki = start;
    *spki_n = (size_t)(tp - start);
    return 0;
}

/* Цепочка против ОДНОГО хранилища и списка имён: годится любое имя (verifyPeerCertByName). */
static int chain_by_names(struct sc_roots *roots, const unsigned char *const *der, const size_t *der_n,
                          size_t count, const char *names) {
    int rc = CERTV_ECHAIN;
    for (const char *p = names; *p;) {
        const char *e = strchr(p, ',');
        size_t n = e ? (size_t)(e - p) : strlen(p);
        char one[256];
        if (n && n < sizeof one) {
            memcpy(one, p, n);
            one[n] = '\0';
            int vr = sc_chain_verify(roots, der, der_n, count, one);
            if (vr == 0) return 0;
            if (vr == SC_EPARSE) rc = CERTV_EPARSE;
        }
        if (!e) break;
        p = e + 1;
    }
    return rc;
}

int cert_verify_server_ex(const unsigned char *cert_body, size_t cert_n,
                          const unsigned char *cv_body, size_t cv_n,
                          const unsigned char *transcript, size_t thash_n,
                          const char *host, const char *roots, const struct cert_policy *pol) {
    if (!cert_body || !cv_body || !host || !host[0]) return CERTV_EPARSE;

    const unsigned char *der[CHAIN_MAX];
    size_t der_n[CHAIN_MAX], count = 0;
    int rc = parse_chain(cert_body, cert_n, der, der_n, &count);
    if (rc) return rc;

    /* Явное `insecure` выхода: остаётся подпись, всё остальное не проверяется (см. certverify.h). */
    if (pol && pol->insecure)
        return check_signature(der[0], der_n[0], cv_body, cv_n, transcript, thash_n);

    const int have_pin = pol && ((pol->pcs && pol->pcs[0]) || (pol->pks && pol->pks[0]));
    const char *names = pol && pol->vcn && pol->vcn[0] ? pol->vcn : host;
    struct sc_roots *pinned_ca = NULL;
    int leaf_pinned = 0;

    if (have_pin) {
        unsigned char h[32];
        /* Лист: и по сертификату, и по ключу (sing-box). Совпал — доверие дано закреплением. */
        if (sc_hash(SC_SHA256, der[0], der_n[0], h) == 0 && pin_listed(pol->pcs, h)) leaf_pinned = 1;
        if (!leaf_pinned && pol->pks && pol->pks[0]) {
            const unsigned char *sp;
            size_t sn;
            if (spki_of(der[0], der_n[0], &sp, &sn) == 0 && sc_hash(SC_SHA256, sp, sn, h) == 0 &&
                pin_listed(pol->pks, h))
                leaf_pinned = 1;
        }
        if (!leaf_pinned) {
            /* Промежуточный или корень: Xray берёт его хранилищем корней, если он CA (verifyChain).
             * Не CA не загрузится в хранилище центров — то же «не нашёл». */
            for (size_t i = 1; i < count && !pinned_ca; i++)
                if (sc_hash(SC_SHA256, der[i], der_n[i], h) == 0 && pin_listed(pol->pcs, h))
                    if (sc_roots_load_der(&pinned_ca, der[i], der_n[i]) != 0) pinned_ca = NULL;
            if (!pinned_ca) return CERTV_EPIN;
        }
    }

    if (!leaf_pinned) {
        struct sc_roots *store = pinned_ca;
        if (!store) {
            if (roots_get(roots, &store) != 0) return CERTV_ENOROOTS;
        }
        /* ИМЯ ПРОВЕРЯЕТСЯ ЗДЕСЬ ЖЕ, вместе с цепочкой: отдельной проверкой оно оказалось бы
         * вторым местом, где живёт разбор SAN, и разошлось бы с библиотечным. */
        rc = chain_by_names(store, der, der_n, count, names);
        if (pinned_ca) sc_roots_free(pinned_ca);
        if (rc) return rc;
    }
    return check_signature(der[0], der_n[0], cv_body, cv_n, transcript, thash_n);
}

/* ---- Reality: сервер доказывает подлинность нам ------------------------------------
 *
 * Механика описана в certverify.h. Здесь — разбор, и он намеренно СВОЙ, а не библиотечный:
 * сертификат Reality подписан ключом Ed25519, а Ed25519 в нашей сборке wolfSSL нет (он не
 * нужен ни для чего, кроме разбора этого сертификата, — см. build/wolfssl/user_settings.h), и
 * mbedtls, которую wolfSSL сменила, его не знала вовсе. Разбор всего сертификата ради двух полей
 * был бы и лишним кодом, и лишней зависимостью от того, что библиотека умеет Ed25519.
 *
 * Нужны ровно два поля, и оба лежат на предсказуемых местах DER.
 */

/* Один шаг по DER: тег, длина, значение. Возвращает 0 и двигает *p за значение; длину и
 * начало значения кладёт в *val и *val_n. Длиннее четырёх байт длина не бывает у сертификата,
 * который влез в сообщение рукопожатия. */
static int der_next(const unsigned char **p, const unsigned char *end,
                    unsigned char *tag, const unsigned char **val, size_t *val_n) {
    if (*p + 2 > end) return -1;
    *tag = *(*p)++;
    size_t n = *(*p)++;
    if (n & 0x80) {
        size_t k = n & 0x7F;
        if (k == 0 || k > 4 || *p + k > end) return -1;
        n = 0;
        while (k--) n = (n << 8) | *(*p)++;
    }
    if ((size_t)(end - *p) < n) return -1;
    *val = *p;
    *val_n = n;
    *p += n;
    return 0;
}

/* Открытый ключ Ed25519 из SubjectPublicKeyInfo.
 *
 * У Ed25519 эта структура имеет ЕДИНСТВЕННЫЙ возможный вид, потому что у алгоритма нет
 * параметров, а ключ всегда 32 байта:
 *
 *     30 2A            SEQUENCE (44 байта)
 *        30 05         SEQUENCE (алгоритм)
 *           06 03 2B 65 70   OID 1.3.101.112 (id-Ed25519)
 *        03 21 00      BIT STRING, 33 байта, ноль неиспользованных бит
 *        <32 байта>
 *
 * Поэтому ключ ищется по этой самой последовательности, а не обходом семи полей TBS. Это не
 * срезание угла: у формы нет вариантов, а обход был бы длиннее и имел бы больше мест, где
 * ошибиться. Если сертификат не Ed25519 — последовательности нет, и это ровно тот ответ,
 * который нужен: перед нами не Reality. */
static const unsigned char *find_ed25519_pub(const unsigned char *b, size_t n) {
    static const unsigned char SPKI[] = {
        0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00
    };
    if (n < sizeof(SPKI) + 32) return NULL;
    for (size_t i = 0; i + sizeof(SPKI) + 32 <= n; i++)
        if (memcmp(b + i, SPKI, sizeof(SPKI)) == 0) return b + i + sizeof(SPKI);
    return NULL;
}

/* Поле подписи — последний элемент внешней SEQUENCE сертификата:
 *     Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
 * Здесь обход настоящий: длина tbsCertificate переменная, и «искать по образцу» нечего. */
static int find_signature(const unsigned char *der, size_t n,
                          const unsigned char **sig, size_t *sig_n) {
    const unsigned char *p = der, *end = der + n, *v;
    unsigned char tag;
    size_t vn;
    if (der_next(&p, end, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* Certificate */
    const unsigned char *ip = v, *iend = v + vn;
    if (der_next(&ip, iend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* tbs */
    if (der_next(&ip, iend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* algid */
    if (der_next(&ip, iend, &tag, &v, &vn) != 0 || tag != 0x03) return -1;  /* BIT STRING */
    if (vn < 2 || v[0] != 0) return -1;      /* неиспользованных бит быть не должно */
    *sig = v + 1;
    *sig_n = vn - 1;
    return 0;
}

int cert_reality_check(const unsigned char *cert_body, size_t cert_n,
                       const unsigned char *authkey) {
    if (!cert_body || !authkey) return CERTV_EPARSE;

    /* Первый сертификат списка — тот самый. Разбор общий с проверкой цепочки, но здесь
     * нужен не разобранный объект, а СЫРЫЕ БАЙТЫ: и ключ, и подпись читаются из DER. */
    if (cert_n < 1) return CERTV_EPARSE;
    size_t p = 1 + cert_body[0];
    if (p + 3 > cert_n) return CERTV_EPARSE;
    size_t list = ((size_t)cert_body[p] << 16) | ((size_t)cert_body[p + 1] << 8) | cert_body[p + 2];
    p += 3;
    if (p + 3 > cert_n || list < 3) return CERTV_EPARSE;
    size_t clen = ((size_t)cert_body[p] << 16) | ((size_t)cert_body[p + 1] << 8) | cert_body[p + 2];
    p += 3;
    if (clen == 0 || p + clen > cert_n) return CERTV_EPARSE;
    const unsigned char *der = cert_body + p;

    const unsigned char *pub = find_ed25519_pub(der, clen);
    if (!pub) return CERTV_ENOTREALITY;      /* не Ed25519 — значит маскировочный сайт */

    const unsigned char *sig;
    size_t sig_n;
    if (find_signature(der, clen, &sig, &sig_n) != 0) return CERTV_EPARSE;

    unsigned char want[64];
    if (sc_hmac(SC_SHA512, authkey, 32, pub, 32, want) != 0) return CERTV_ESIG;

    /* Сравнение постоянного времени. Утечка здесь ничего не открывает — обе стороны байты
     * и так видят, — но сравнивать секретозависимое memcmp'ом это привычка, которую в этом
     * файле заводить не стоит. */
    if (sig_n != sizeof(want)) return CERTV_ENOTREALITY;
    unsigned char diff = 0;
    for (size_t i = 0; i < sizeof(want); i++) diff |= (unsigned char)(want[i] ^ sig[i]);
    return diff ? CERTV_ENOTREALITY : 0;
}

/* Значение первого расширения X.509 (extnValue, содержимое OCTET STRING) временного сертификата
 * Reality с ML-DSA. Обход настоящий: Certificate → tbsCertificate → поле [3] extensions → SEQUENCE →
 * первое Extension { OID, [BOOLEAN critical], OCTET STRING }. Go читает то же: Extensions[0].Value. */
static int find_first_ext_value(const unsigned char *der, size_t n,
                                const unsigned char **val, size_t *val_n) {
    const unsigned char *p = der, *end = der + n, *v;
    unsigned char tag;
    size_t vn;
    if (der_next(&p, end, &tag, &v, &vn) != 0 || tag != 0x30) return -1;   /* Certificate */
    const unsigned char *ip = v, *iend = v + vn;
    if (der_next(&ip, iend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* tbs */
    const unsigned char *tp = v, *tend = v + vn, *ev = NULL;
    size_t evn = 0;
    while (tp < tend) {
        if (der_next(&tp, tend, &tag, &v, &vn) != 0) return -1;
        if (tag == 0xA3) { ev = v; evn = vn; break; }                       /* [3] extensions */
    }
    if (!ev) return -1;
    const unsigned char *sp = ev;
    if (der_next(&sp, ev + evn, &tag, &v, &vn) != 0 || tag != 0x30) return -1;  /* Extensions */
    const unsigned char *xp = v, *xend = v + vn;
    if (der_next(&xp, xend, &tag, &v, &vn) != 0 || tag != 0x30) return -1;   /* Extension #0 */
    const unsigned char *fp = v, *fend = v + vn;
    if (der_next(&fp, fend, &tag, &v, &vn) != 0 || tag != 0x06) return -1;   /* extnID */
    if (der_next(&fp, fend, &tag, &v, &vn) != 0) return -1;
    if (tag == 0x01 && der_next(&fp, fend, &tag, &v, &vn) != 0) return -1;   /* critical */
    if (tag != 0x04) return -1;                                              /* extnValue */
    *val = v;
    *val_n = vn;
    return 0;
}

int cert_reality_check_pq(const unsigned char *cert_body, size_t cert_n,
                          const unsigned char *authkey, const unsigned char *pk,
                          const unsigned char *ch, size_t ch_n,
                          const unsigned char *sh, size_t sh_n) {
    if (!cert_body || !authkey || !pk || !ch || !sh || cert_n < 1) return CERTV_EPARSE;
    size_t p = 1 + cert_body[0];
    if (p + 6 > cert_n) return CERTV_EPARSE;
    p += 3;
    size_t clen = ((size_t)cert_body[p] << 16) | ((size_t)cert_body[p + 1] << 8) | cert_body[p + 2];
    p += 3;
    if (clen == 0 || p + clen > cert_n) return CERTV_EPARSE;
    const unsigned char *der = cert_body + p;
    const unsigned char *epub = find_ed25519_pub(der, clen);
    if (!epub) return CERTV_EPARSE;

    const unsigned char *sig;
    size_t sig_n;
    if (find_first_ext_value(der, clen, &sig, &sig_n) != 0 || sig_n != SC_MLDSA65_SIG) return CERTV_EPQ;

    /* HMAC над pub ‖ ClientHello ‖ ServerHello — тремя кусками сразу нельзя (sc_hmac2 принимает два),
     * поэтому склейка в куче: 32 + около 1,7 КБ + около 1,2 КБ. */
    size_t tot = 32 + ch_n + sh_n;
    unsigned char *msg = malloc(tot);
    if (!msg) return CERTV_EPQ;
    memcpy(msg, epub, 32);
    memcpy(msg + 32, ch, ch_n);
    memcpy(msg + 32 + ch_n, sh, sh_n);
    unsigned char mac[64];
    int rc = sc_hmac(SC_SHA512, authkey, 32, msg, tot, mac);
    free(msg);
    if (rc != 0) return CERTV_EPQ;
    return sc_mldsa65_verify(pk, mac, sizeof mac, sig, sig_n) == 0 ? 0 : CERTV_EPQ;
}

const char *cert_verify_strerror(int rc) {
    switch (rc) {
        case 0:              return "";
        case CERTV_EPARSE:   return "сертификат сервера не разобрался";
        case CERTV_ENOROOTS: return "нет хранилища корней (нужен пакет ca-bundle)";
        case CERTV_ECHAIN:   return "сертификат не сошёлся с корнями или выдан не на это имя";
        case CERTV_ESIG:     return "подпись сервера неверна";
        case CERTV_EPIN:     return "отпечаток сертификата не закреплён (pcs)";
        case CERTV_EALG:     return "сервер подписал алгоритмом, которого мы не предлагали";
        /* Формулировка про ключ, а не про сервер: узел жив и отвечает, просто нас на нём не
         * узнали — почти всегда это разошедшиеся pbk/sid или чужая подписка. */
        case CERTV_ENOTREALITY: return "узел не признал ключ (ответил маскировочный сайт)";
        case CERTV_EPQ:      return "подпись ML-DSA-65 сервера не сошлась с pqv узла";
        default:             return "проверка сертификата не удалась";
    }
}
