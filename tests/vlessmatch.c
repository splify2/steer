/* Ветви отказа vless_connect: дескриптор и ключи после каждого «нет».
 *
 * ЗАЧЕМ ОТДЕЛЬНЫМ СТЕНДОМ. У установления соединения с узлом VLESS не было ни одного
 * стенда, который доходит до TLS. tests/fake-vless.py говорит только security=none и до
 * рукопожатия не добирается; tests/run-reality.sh требует sing-box, root и сетевых
 * пространств, поэтому не входит ни в `make test`, ни в `make ext-test`. Всё, что охраняло
 * здесь освобождение — чтение кода глазами, тогда как у xsteer на ту же болезнь (I-067)
 * стенд стоит под AddressSanitizer с запуска 42. Разрыв назван в R-114; этот файл его
 * закрывает.
 *
 * ЧТО ИМЕННО ПРОВЕРЯЕТСЯ. У vless_connect ДЕВЯТЬ путей выхода по ошибке (client.c:717, 737,
 * 739, 769, 777, 792, 822, 825, 827) и три успешных, и каждый путь отказа сам решает, чем
 * закрыться: четыре зовут close(fd), четыре — vless_close(conn), а самый первый уходит до
 * того, как дескриптор появился. Перечисление с разбором — A-139. Выбор не косметический —
 * после развёртывания ключей трафика в соединении живут развёрнутые контексты шифра (у
 * mbedtls, на которой стенд родился, — в КУЧЕ, через calloc внутри setkey; у wolfCrypt за
 * слоем scrypto — внутри struct tls13, но затереть их обязан всё тот же vless_close), а на пути
 * проверки сертификата куча есть и сейчас (разбор цепочки wolfSSL), и дескриптор её не держит.
 * Вызывающие тоже не убирают: пул запасных сессий на отказе лишь помечает слот пустым, а
 * проверка узла возвращается сразу. Значит цена ошибки в выборе — утечка НА КАЖДУЮ попытку
 * при том, что попытки не кончаются: пул пополняется на каждый SYN, сторож перебирает узлы
 * пачками. Стенд наблюдает три вещи на каждой ветви: код возврата, дескрипторы процесса
 * (их число обязано вернуться к исходному) и кучу — через LeakSanitizer, отдельной
 * проверкой после каждого случая, а не одним отчётом на выходе.
 *
 * С шага 2 выпуска 1.10 установление живёт в транспорте (src/proto/transport: transport_open,
 * tr_link_open, security в trsec.c), а vless_connect лишь отдаёт ему узел; ветви отказа и
 * способы закрыться на них — прежние, а номера строк выше указывают на client.c до переезда.
 *
 * КАК ЭТО РАБОТАЕТ БЕЗ УЗЛА И БЕЗ СЕТИ. Установление TCP вынесено в шов g_tcp_dial
 * (src/proto/transport/trdial.c) — так же, как замер задержки в failover.c. Стенд отдаёт клиенту конец
 * socketpair, а на другом конце сам говорит серверную половину TLS 1.3: разбирает
 * ClientHello, достаёт из него key_share, считает X25519, выводит расписание ключей
 * рукопожатия по RFC 8446 §7.1 и шлёт зашифрованные EncryptedExtensions, при надобности
 * Certificate, и Finished. Это ровно та половина, которой в проекте не было, и без неё до
 * серверного Finished не доходил ни один стенд.
 *
 * ПОЧЕМУ СЕРВЕРНАЯ ПОЛОВИНА ЗДЕСЬ, А НЕ НА ПИТОНЕ. Стенд живёт в `make ext-test`, и та же
 * цель запускается ВНУТРИ образа сборщика при релизе (build/ext-test-image.sh). Питона там
 * может не быть вовсе, а криптобиблиотека есть по построению — на ней и собран сам движок.
 * Вторая причина: расписание ключей обязано совпасть с клиентским до байта, и когда обе
 * половины стоят на одних примитивах (слой scrypto), расхождение означает ошибку в нашем коде
 * TLS, а не разницу реализаций. Метка HKDF и приставка подписи при этом собираются здесь своими
 * копиями — иначе ошибка в них сошлась бы сама с собой.
 *
 * Нужна настоящая криптобиблиотека, поэтому в `make test` стенд не входит, как xsloop и
 * spokematch.
 *
 * ВТОРАЯ ПОЛОВИНА: security=tls СО СВОИМИ КОРНЯМИ (R-118). Ветвей Reality мало для того,
 * чтобы охватить установление соединения целиком: у Reality доказательством служит HMAC в
 * поле подписи временного сертификата, и для ОТКАЗА проверки не нужно ни цепочки X.509, ни
 * хранилища корней — то есть все шесть случаев выше проходят мимо certverify.c, у которого
 * не было ни одного стенда. Главное же в том, что при отказе проверки соединение не
 * доходит до конца никогда, а ровно та ветвь, ради которой в клиенте появился vless_close
 * (VLESS_CONN_ENOH2, ключи трафика уже развёрнуты в соединении), достижима
 * ТОЛЬКО через УДАВШУЮСЯ проверку сервера.
 *
 * Поэтому стенд выпускает цепочку сам: корень и лист на имя SNI, ключи ECDSA P-256, сроки
 * от текущего времени (замороженный в репозитории сертификат однажды истёк бы и покрасил
 * стенд не по своей вине). Корень уезжает файлом PEM, путь к нему отдаётся движку швом
 * g_cert_roots в src/proto/tls/roots.c — вторым такой же природы, что g_tcp_dial. Серверная половина
 * подписывает CertificateVerify настоящей подписью над транскриптом по Certificate
 * включительно (RFC 8446 §4.4.3, приставка из 64 пробелов и метки), и клиент проверяет её
 * своим кодом, а не нашим: расхождение здесь означает ошибку в движке.
 *
 * Что этим накрыто: успех целиком (рукопожатие, проверка цепочки, имя против sni), ветвь
 * ENOH2 с её vless_close, имя не то, «не прислал подпись», подпись не сходится, алгоритм
 * подписи не из предложенных и лист, подписанный сам собой. Без второго стенда все семь
 * ветвей были недостижимы.
 *
 * Выпуск сертификатов — tests/certgen.c на wolfCrypt с WOLFSSL_CERT_GEN (его даёт библиотеке
 * стендов tests/ext-test.sh, в сборке движка выпуска нет). ext-test задаёт STEER_HAVE_X509WRITE
 * всегда; собранный руками без него стенд случаи security=tls ПРОПУСКАЕТ ГРОМКО и говорит об
 * этом сам — молчаливый пропуск читался бы как «прошло», ровно как в I-232.
 */
/* До любого include: включаемые исходники просят расширения GNU, а первый подключённый
 * заголовок фиксирует набор. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <dirent.h>
#include <stdint.h>

/* Исходники целиком, а не компоновка — ровно два, ради двух швов: g_tcp_dial (trdial.c) и
 * g_cert_roots (roots.c) статические, и дотянуться до них иначе значило бы объявить их в
 * заголовке — то есть завести в движке публичную точку подмены ради стенда. Тот же приём, что
 * в tests/failovermatch.c. Остальное — клиент VLESS и ярусы транспорта — компонуется
 * отдельными объектами (tests/ext-test.sh). */
#include "../src/proto/transport/trdial.c"
#include "../src/proto/tls/roots.c"
#include "client.h"

#include "scrypto.h"
#if defined(STEER_HAVE_X509WRITE)
# include "certgen.h"
#endif

/* Общий секрет с эфемерным ключом собеседника: та же функция, которой пользуется tls13.c,
 * а не копия — копия крипто-кода это два места, где может разойтись прижатие скаляра. */
int x25519_shared_ext(const unsigned char priv[32], const unsigned char peer[32],
                      unsigned char out[32]);

/* Заглушка того, что живёт в src/lib/run.c: ни команд, ни устройств стенду не нужно. Заглушки
 * bind_device (src/daemon/failover.c) нет: с 1.10 (шаг 3) модуль VLESS маршрут не привязывает. */
int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#if defined(__SANITIZE_ADDRESS__)
# include <sanitizer/lsan_interface.h>
# define LEAK_CHECK() __lsan_do_recoverable_leak_check()
#else
/* Санитайзера нет — проверки кода возврата и дескрипторов всё равно идут, а про кучу
 * стенд молчать не имеет права: молчаливый пропуск читается как «прошло». Громко
 * говорится один раз, в main. */
# define LEAK_CHECK() 0
#endif

static int fails;

static void check(const char *what, long want, long got) {
    printf("%-64s %s\n", what, want == got ? "ok" : "ПРОВАЛ");
    if (want != got) {
        printf("     хочу: %ld\n     есть:  %ld\n", want, got);
        fails++;
    }
}

static void check_str(const char *what, const char *want, const char *got) {
    int ok = got && strstr(got, want) != NULL;
    printf("%-64s %s\n", what, ok ? "ok" : "ПРОВАЛ");
    if (!ok) {
        printf("     хочу подстроку: %s\n     есть:           %s\n", want, got ? got : "(нет)");
        fails++;
    }
}

/* Сколько дескрипторов открыто у процесса. Наблюдаемое напрямую: утечку дескриптора видно
 * без всякого санитайзера, и ровно эта утечка (ветка ENOH2, узел grpc с security=reality)
 * упирала процесс в RLIMIT_NOFILE за сутки опроса. */
static int fd_count(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) return -1;
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') n++;
    closedir(d);
    return n;
}

/* ---- серверная половина TLS 1.3 ------------------------------------------------
 *
 * Ровно столько, сколько нужно, чтобы клиент дошёл до конца рукопожатия: один набор шифров
 * (0x1301, AES-128-GCM с SHA-256), одна группа (X25519), никакого возобновления. */

#define SUITE_HI 0x13
#define SUITE_LO 0x01
#define HLEN 32u                       /* SHA-256: и хеш транскрипта, и длина секретов */

struct plan {
    const char *name;
    int no_keyshare;      /* ServerHello без key_share — отказ ДО вывода ключей */
    int bad_finished;     /* испортить серверный Finished */
    int cert;             /* 0 — не присылать, 1 — мусорный Certificate, 2 — сжатый (0x19) */
    const char *alpn;     /* строка ALPN в EncryptedExtensions, или NULL */
    int hangup;           /* закрыть соединение сразу после ClientHello */
    /* Ниже — путь security=tls: настоящая цепочка, выпущенная стендом (R-118). Поле cert у
     * этих случаев не читается: чем именно отвечать, решает leaf. */
    int chain;            /* 0 — не путь tls; иначе номер листа из g_leaf[] */
    int no_cv;            /* прислать Certificate и НЕ прислать CertificateVerify */
    int cv_bad_sig;       /* испортить байт подписи */
    int cv_bad_alg;       /* подписать кодом, которого мы не предлагали (rsa_pkcs1_sha256) */
    /* Шаг 5 выпуска 1.10: ws и httpupgrade поверх tls и reality — на настоящей библиотеке.
     * reality_ok — временный сертификат Reality с настоящей подписью HMAC-SHA512 на authkey
     * (единственный путь к УДАВШЕМУСЯ Reality в этом стенде); upg — после рукопожатия сервер
     * ведёт и данные: ключи трафика, запрос Upgrade, ответ 101 с первыми данными ТОЙ ЖЕ записью
     * и приём ответа клиента (1 — ws, 2 — httpupgrade). */
    int reality_ok;
    int upg;
    /* ws с ранними данными (путь `?ed=2048`): клиент пишет «hello» ДО чтения, и оно обязано уехать
     * в Sec-WebSocket-Protocol запроса — запрос у Xray при Ed > 0 откладывается до первой записи. */
    int ed_first;
};

struct srv {
    int fd;
    const struct plan *plan;
    /* Ключи записи сервера и счётчик записей. */
    unsigned char key[16], iv[12];
    unsigned char s_hs[HLEN];
    uint64_t seq;
    struct sc_hash_ctx tr;             /* транскрипт рукопожатия */
    int rc;                            /* !=0 — половина сломалась сама, а не по замыслу */
    /* Путь данных (plan.upg): секреты рукопожатия и то, что увидел сервер. */
    unsigned char hs[HLEN], c_hs[HLEN];
    int alpn_h11;                      /* в ClientHello ALPN — один http/1.1 */
    char req[4096];                    /* запрос Upgrade, как пришёл */
    int got_hello;                     /* ответ клиента после 101 дошёл и разобрался */
};

/* Постоянная пара сервера Reality для plan.reality_ok: pbk узла — её публичная половина. */
static unsigned char g_rs_priv[32], g_rs_pub[32];
/* Что сервер увидел в ALPN последнего ClientHello (для прогонов через run_case). */
static volatile int g_seen_h11 = -1;
/* Новый Xray-core принимает Reality только если гибридная группа стоит перед X25519. */
static volatile int g_seen_mlkem_before_x25519 = -1;

/* HKDF-Expand-Label из RFC 8446 §7.1. Своя копия, а не вызов статической из tls13.c:
 * стенд обязан считать метку САМ, иначе ошибка в клиентской обёртке сошлась бы сама с
 * собой и осталась незамеченной. */
static int xlabel(const unsigned char *secret, const char *label,
                  const unsigned char *ctx, size_t ctx_n,
                  unsigned char *out, size_t out_n) {
    unsigned char info[128];
    size_t n = 0, ln = strlen(label);
    if (2 + 1 + 6 + ln + 1 + ctx_n > sizeof(info)) return -1;
    info[n++] = (unsigned char)(out_n >> 8);
    info[n++] = (unsigned char)out_n;
    info[n++] = (unsigned char)(6 + ln);
    memcpy(info + n, "tls13 ", 6); n += 6;
    memcpy(info + n, label, ln);    n += ln;
    info[n++] = (unsigned char)ctx_n;
    if (ctx_n) { memcpy(info + n, ctx, ctx_n); n += ctx_n; }
    return sc_hkdf_expand(SC_SHA256, secret, HLEN, info, n, out, out_n);
}

static void tr_snapshot(const struct sc_hash_ctx *tr, unsigned char out[HLEN]) {
    struct sc_hash_ctx c;
    if (sc_hash_clone(&c, tr) != 0) { memset(out, 0, HLEN); return; }
    sc_hash_final(&c, out);
    sc_hash_free(&c);
}

static int wr_all(int fd, const unsigned char *b, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, b + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

static int rd_all(int fd, unsigned char *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, b + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Одна запись: заголовок из пяти байт, затем тело. */
static int rd_rec(int fd, unsigned char *type, unsigned char *body, size_t cap, size_t *n) {
    unsigned char h[5];
    if (rd_all(fd, h, 5)) return -1;
    size_t len = ((size_t)h[3] << 8) | h[4];
    if (len > cap) return -1;
    if (rd_all(fd, body, len)) return -1;
    *type = h[0];
    *n = len;
    return 0;
}

/* ---- своя цепочка X.509 для security=tls (R-118) ------------------------------------
 *
 * Три листа, и каждый нужен ровно одной проверке:
 *   LEAF_OK   — на имя SNI, подписан корнем: единственный путь к УДАВШЕЙСЯ проверке, а
 *               значит и к ветви ENOH2, ради которой в клиенте появился vless_close;
 *   LEAF_NAME — тем же корнем, но на другое имя: проверка обязана отказать по имени, а не
 *               пропустить «цепочка же сошлась»;
 *   LEAF_SELF — подписан сам собой: корень не при чём, отказ по цепочке.
 *
 * Ключи ECDSA P-256, а не RSA: генерация RSA-2048 занимает секунды и делала бы стенд
 * заметно медленнее без всякой пользы для проверяемого — certverify.c принимает и то, и
 * другое, а подпись CertificateVerify проверяется одной и той же sc_cert_verify_sig (RSA и
 * PSS против подписей OpenSSL проверяет tests/scryptomatch.c).
 *
 * СРОКИ СЧИТАЮТСЯ ОТ ТЕКУЩЕГО ВРЕМЕНИ, а не зашиты строкой: замороженный сертификат
 * однажды истекает и красит стенд не по своей вине — это named risk у самого R-118, и
 * закрывается он тем, что срок выпускается заново на каждый прогон.
 */
#if defined(STEER_HAVE_X509WRITE)

#define LEAF_OK   1
#define LEAF_NAME 2
#define LEAF_SELF 3

/* Имя, на которое выпущен годный лист, и оно же уезжает в SNI узла: сертификат проверяется
 * против sni, а не против host (client.c, verify_host). */
#define TLS_SNI "tls.node.invalid"

struct leaf {
    unsigned char der[2048];
    size_t der_n;
    struct tcg_key *key;         /* ключ листа — им подписывается CertificateVerify */
};

static struct leaf g_leaf[4];        /* [0] не используется: номера совпадают с LEAF_* */
static char g_roots_file[64];
static int g_chain_ready;

/* Корень, три листа и файл хранилища. Один раз на процесс: certverify.c разбирает корни
 * под pthread_once, и второе хранилище в том же процессе не подействовало бы (I-217) —
 * значит все случаи обязаны проверяться ОДНИМ набором корней. Сроки — от текущего времени
 * (tests/certgen.c), имя — в CN: SAN стенд не выпускает, и проверка имени обязана найти его
 * там, как находила прежде. */
static int chain_build(void) {
    struct tcg_key *root_key = tcg_key_new();
    if (!root_key) return -1;

    static char pem[4096];
    unsigned char root_der[2048];
    size_t root_n = 0;
    if (tcg_issue(root_key, "steer test root", NULL, 1, NULL, NULL, 0,
                  root_der, sizeof(root_der), &root_n) != 0 ||
        tcg_der_to_pem(root_der, root_n, pem, sizeof(pem)) != 0) {
        tcg_key_free(root_key);
        return -1;
    }

    struct { int idx; const char *cn; int self; } want[] = {
        { LEAF_OK,   TLS_SNI,          0 },
        { LEAF_NAME, "other.invalid",  0 },
        { LEAF_SELF, TLS_SNI,          1 },
    };
    for (size_t i = 0; i < sizeof(want) / sizeof(*want); i++) {
        struct leaf *l = &g_leaf[want[i].idx];
        if (!(l->key = tcg_key_new())) { tcg_key_free(root_key); return -1; }
        int rc = want[i].self
            ? tcg_issue(l->key, want[i].cn, NULL, 0, NULL, NULL, 0, l->der, sizeof(l->der), &l->der_n)
            : tcg_issue(l->key, want[i].cn, NULL, 0, root_key, root_der, root_n,
                        l->der, sizeof(l->der), &l->der_n);
        if (rc != 0) { tcg_key_free(root_key); return -1; }
    }
    tcg_key_free(root_key);

    snprintf(g_roots_file, sizeof(g_roots_file), "%s", "/tmp/vlessmatch-roots-XXXXXX");
    int fd = mkstemp(g_roots_file);
    if (fd < 0) return -1;
    size_t pn = strlen(pem);
    int ok = wr_all(fd, (const unsigned char *)pem, pn) == 0;
    close(fd);
    if (!ok) return -1;
    g_chain_ready = 1;
    return 0;
}

static void chain_free(void) {
    for (int i = 1; i <= LEAF_SELF; i++) { tcg_key_free(g_leaf[i].key); g_leaf[i].key = NULL; }
    if (g_roots_file[0]) unlink(g_roots_file);
}

/* Сообщение Certificate из одного листа (RFC 8446 §4.4.2): байт контекста, список из трёх
 * байт длины, в нём запись «три байта длины + DER + два байта расширений». Корень в
 * список не кладётся намеренно: он уже в хранилище, и цепочка обязана сойтись без него —
 * иначе стенд проверял бы не проверку, а щедрость сервера. */
static size_t cert_msg(const struct leaf *l, unsigned char *out, size_t cap) {
    size_t body = 1 + 3 + 3 + l->der_n + 2;
    if (4 + body > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0B;
    out[n++] = (unsigned char)(body >> 16);
    out[n++] = (unsigned char)(body >> 8);
    out[n++] = (unsigned char)body;
    out[n++] = 0x00;                                     /* certificate_request_context */
    size_t list = 3 + l->der_n + 2;
    out[n++] = (unsigned char)(list >> 16);
    out[n++] = (unsigned char)(list >> 8);
    out[n++] = (unsigned char)list;
    out[n++] = (unsigned char)(l->der_n >> 16);
    out[n++] = (unsigned char)(l->der_n >> 8);
    out[n++] = (unsigned char)l->der_n;
    memcpy(out + n, l->der, l->der_n); n += l->der_n;
    out[n++] = 0x00; out[n++] = 0x00;                    /* extensions: пусто */
    return n;
}

/* CertificateVerify: подпись над 64 пробелами, меткой, нулём и хешем транскрипта по
 * Certificate включительно. Приставка собирается ЗДЕСЬ, а не берётся из certverify.c: две
 * половины обязаны прийти к одному ответу независимо, иначе ошибка в приставке сошлась бы
 * сама с собой. */
static size_t cv_msg(const struct leaf *l, const unsigned char thash[HLEN],
                     const struct plan *pl, unsigned char *out, size_t cap) {
    unsigned char content[64 + 33 + 1 + HLEN];
    size_t cn = 0;
    memset(content, 0x20, 64); cn = 64;
    memcpy(content + cn, "TLS 1.3, server CertificateVerify", 33); cn += 33;
    content[cn++] = 0x00;
    memcpy(content + cn, thash, HLEN); cn += HLEN;

    unsigned char digest[HLEN];
    if (sc_hash(SC_SHA256, content, cn, digest) != 0) return 0;

    /* DER-подпись ECDSA P-256 — не длиннее 72 байт; запас на любой вид. */
    unsigned char sig[160];
    size_t sig_n = 0;
    if (tcg_sign_sha256(l->key, digest, sig, sizeof(sig), &sig_n) != 0) return 0;
    if (pl->cv_bad_sig) sig[sig_n / 2] ^= 0xFF;

    if (4 + 4 + sig_n > cap) return 0;
    size_t n = 0;
    out[n++] = 0x0F;
    out[n++] = 0; out[n++] = 0; out[n++] = (unsigned char)(4 + sig_n);
    /* 0x0403 — ecdsa_secp256r1_sha256, он в нашем signature_algorithms есть. 0x0401 —
     * rsa_pkcs1_sha256, которым в TLS 1.3 подписывать CertificateVerify запрещено, и мы
     * его не предлагаем: сервер, выбравший его, обязан получить отдельную причину, а не
     * «подпись не сошлась». */
    out[n++] = 0x04; out[n++] = pl->cv_bad_alg ? 0x01 : 0x03;
    out[n++] = (unsigned char)(sig_n >> 8);
    out[n++] = (unsigned char)sig_n;
    memcpy(out + n, sig, sig_n); n += sig_n;
    return n;
}
#endif /* STEER_HAVE_X509WRITE */

/* ClientHello: нужны серверная сторона обмена (key_share клиента) и session_id, который
 * сервер обязан вернуть как есть. Разбор по типам расширений, а не по смещениям: состав
 * Hello у reality.c меняется вместе с обликом браузера. */
static int ch_pick(const unsigned char *b, size_t n, unsigned char pub[32],
                   unsigned char *sid, size_t *sid_n) {
    if (n < 40 || b[0] != 0x01) return -1;
    size_t p = 4 + 2 + 32;
    size_t sn = b[p++];
    if (sn > 32 || p + sn > n) return -1;
    memcpy(sid, b + p, sn);
    *sid_n = sn;
    p += sn;
    if (p + 2 > n) return -1;
    size_t cs = ((size_t)b[p] << 8) | b[p + 1];
    p += 2 + cs;
    if (p >= n) return -1;
    p += 1 + b[p];                                  /* compression_methods */
    if (p + 2 > n) return -1;
    size_t exts = ((size_t)b[p] << 8) | b[p + 1];
    p += 2;
    size_t end = p + exts;
    if (end > n) return -1;
    while (p + 4 <= end) {
        unsigned etype = ((unsigned)b[p] << 8) | b[p + 1];
        size_t elen = ((size_t)b[p + 2] << 8) | b[p + 3];
        p += 4;
        if (p + elen > end) return -1;
        if (etype == 0x0033) {
            /* client_shares: длина списка(2), затем группа(2)+длина(2)+ключ. Берём именно
             * X25519 (0x001d): reality.c умеет предлагать и постквантовую группу, и она в
             * списке стоит первой. */
            size_t q = 2;
            int saw_mlkem = 0;
            while (q + 4 <= elen) {
                unsigned grp = ((unsigned)b[p + q] << 8) | b[p + q + 1];
                size_t kn = ((size_t)b[p + q + 2] << 8) | b[p + q + 3];
                if (q + 4 + kn > elen) break;
                if (grp == REALITY_GROUP_MLKEM && kn == REALITY_MLKEM_SHARE)
                    saw_mlkem = 1;
                if (grp == 0x001d && kn == 32) {
                    g_seen_mlkem_before_x25519 = saw_mlkem;
                    memcpy(pub, b + p + q + 4, 32);
                    return 0;
                }
                q += 4 + kn;
            }
        }
        p += elen;
    }
    return -1;
}

/* Зашифрованная запись рукопожатия: одно сообщение на запись — клиент собирает их через
 * границы записей, и так проверяется в том числе это. */
static int send_enc(struct srv *s, const unsigned char *msg, size_t n) {
    unsigned char out[4096];
    if (n + 1 + 16 + 5 > sizeof(out)) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8);
    out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x16;                              /* настоящий тип записи */

    unsigned char nonce[12];
    memcpy(nonce, s->iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (unsigned char)(s->seq >> (8 * i));

    /* Одноразовый ключ на запись — половина сервера не про скорость. Контекст в куче: на
     * стеке этого потока ему (больше килобайта) не место. */
    struct sc_aead *g = malloc(sizeof(*g));
    if (!g) return -1;
    int rc = sc_aead_setkey(g, SC_AES128_GCM, s->key);
    if (rc == 0) rc = sc_aead_seal(g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1);
    sc_aead_free(g);
    free(g);
    if (rc) return -1;
    s->seq++;
    return wr_all(s->fd, out, 5 + total);
}

/* ---- путь данных после рукопожатия: ws и httpupgrade (plan.upg) ---------------------------
 *
 * Серверная половина здесь доводит соединение до данных — то, чего стенду прежде было не
 * нужно: ключи трафика приложения (RFC 8446 §7.1, от master secret и транскрипта по серверный
 * Finished), Finished клиента под ключом рукопожатия, запрос Upgrade, ответ 101 и за ним ТОЙ
 * ЖЕ записью первые данные потока (кадр ws или сырые байты httpupgrade — остаток, который
 * транспорт обязан не потерять), и приём того, что клиент пошлёт в ответ. Ключ и счётчик у
 * каждого направления свои (struct dir). */
struct dir { struct sc_aead g; unsigned char iv[12]; uint64_t seq; int ready; };

static int dir_set(struct dir *d, const unsigned char secret[HLEN]) {
    unsigned char key[16];
    if (xlabel(secret, "key", NULL, 0, key, 16) || xlabel(secret, "iv", NULL, 0, d->iv, 12)) return -1;
    if (d->ready) sc_aead_free(&d->g);
    d->ready = 0;
    if (sc_aead_setkey(&d->g, SC_AES128_GCM, key)) return -1;
    d->ready = 1;
    d->seq = 0;
    return 0;
}

static void dir_nonce(const struct dir *d, unsigned char n[12]) {
    memcpy(n, d->iv, 12);
    for (int i = 0; i < 8; i++) n[11 - i] ^= (unsigned char)(d->seq >> (8 * i));
}

/* Следующая запись от клиента: ChangeCipherSpec пропускается, остальное расшифровывается. */
static int rec_open(struct dir *d, int fd, unsigned char *out, size_t cap, size_t *n,
                    unsigned char *inner) {
    for (;;) {
        unsigned char type;
        size_t len;
        if (rd_rec(fd, &type, out, cap, &len)) return -1;
        if (type == 0x14) continue;
        if (type != 0x17 || len < 17) return -1;
        unsigned char hdr[5] = { 0x17, 0x03, 0x03, (unsigned char)(len >> 8), (unsigned char)len };
        unsigned char nonce[12];
        dir_nonce(d, nonce);
        if (sc_aead_open(&d->g, nonce, hdr, 5, out, len - 16, out + len - 16)) return -1;
        d->seq++;
        size_t pt = len - 16;
        while (pt && !out[pt - 1]) pt--;
        if (!pt) return -1;
        *inner = out[--pt];
        *n = pt;
        return 0;
    }
}

static int rec_seal(struct dir *d, int fd, const unsigned char *msg, size_t n) {
    static __thread unsigned char out[5 + 4096 + 17];
    if (n + 17 > 4096 + 17) return -1;
    size_t total = n + 1 + 16;
    out[0] = 0x17; out[1] = 0x03; out[2] = 0x03;
    out[3] = (unsigned char)(total >> 8); out[4] = (unsigned char)total;
    memcpy(out + 5, msg, n);
    out[5 + n] = 0x17;
    unsigned char nonce[12];
    dir_nonce(d, nonce);
    if (sc_aead_seal(&d->g, nonce, out, 5, out + 5, n + 1, out + 5 + n + 1)) return -1;
    d->seq++;
    return wr_all(fd, out, 5 + total);
}

static int app_phase_dirs(struct srv *s, struct dir *cd, struct dir *sd) {
    unsigned char zeros[HLEN] = {0}, empty[HLEN], derived[HLEN], master[HLEN], th[HLEN];
    unsigned char c_ap[HLEN], s_ap[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return -1;
    if (xlabel(s->hs, "derived", empty, HLEN, derived, HLEN) != 0) return -1;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, zeros, HLEN, master) != 0) return -1;
    tr_snapshot(&s->tr, th);
    if (xlabel(master, "c ap traffic", th, HLEN, c_ap, HLEN) != 0) return -1;
    if (xlabel(master, "s ap traffic", th, HLEN, s_ap, HLEN) != 0) return -1;

    static __thread unsigned char buf[16384 + 256];
    size_t n;
    unsigned char inner;
    if (dir_set(cd, s->c_hs) || rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x16)
        return -1;                                       /* Finished клиента */
    if (dir_set(cd, c_ap) || dir_set(sd, s_ap)) return -1;

    size_t rn = 0;
    while (!strstr(s->req, "\r\n\r\n")) {
        if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
        if (rn + n >= sizeof(s->req)) return -1;
        memcpy(s->req + rn, buf, n);
        rn += n;
        s->req[rn] = '\0';
    }

    char resp[512];
    int k;
    if (s->plan->upg == 1) {
        char key[32] = "", acc[29];
        const char *kp = strstr(s->req, "\r\nSec-WebSocket-Key: ");
        if (!kp) return -1;
        sscanf(kp + 21, "%31[^\r]", key);
        tr_ws_accept(key, acc);
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                     "Connection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", acc);
        resp[k++] = (char)0x82; resp[k++] = 5;           /* кадр сервера: без маски */
        memcpy(resp + k, "FIRST", 5); k += 5;
    } else {
        k = snprintf(resp, sizeof(resp), "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\n"
                     "Upgrade: websocket\r\n\r\nFIRST");
    }
    if (rec_seal(sd, s->fd, (const unsigned char *)resp, (size_t)k)) return -1;

    /* Ранние данные ws (Ed > 0): «hello» клиента приехало в самом запросе, base64url без `=`. */
    if (s->plan->ed_first) {
        s->got_hello = strstr(s->req, "\r\nSec-WebSocket-Protocol: aGVsbG8\r\n") != NULL;
        return 0;
    }
    if (rec_open(cd, s->fd, buf, sizeof(buf), &n, &inner) || inner != 0x17) return -1;
    if (s->plan->upg == 1) {
        /* 0x82, 0x80|5, маска, «hello» под маской. */
        if (n != 11 || buf[0] != 0x82 || buf[1] != (0x80 | 5)) return -1;
        for (int i = 0; i < 5; i++) buf[6 + i] ^= buf[2 + (i & 3)];
        s->got_hello = !memcmp(buf + 6, "hello", 5);
    } else {
        s->got_hello = n == 5 && !memcmp(buf, "hello", 5);
    }
    return 0;
}

static int app_phase(struct srv *s) {
    struct dir *cd = calloc(1, sizeof(*cd)), *sd = calloc(1, sizeof(*sd));
    int rc = cd && sd ? app_phase_dirs(s, cd, sd) : -1;
    if (cd && cd->ready) sc_aead_free(&cd->g);
    if (sd && sd->ready) sc_aead_free(&sd->g);
    free(cd);
    free(sd);
    return rc;
}

static void *server_half(void *arg) {
    struct srv *s = arg;
    const struct plan *pl = s->plan;
    unsigned char ch[4096];
    unsigned char type;
    size_t ch_n = 0;

    s->rc = -1;
    if (rd_rec(s->fd, &type, ch, sizeof(ch), &ch_n) || type != 0x16) return NULL;
    if (pl->hangup) { s->rc = 0; close(s->fd); s->fd = -1; return NULL; }
    /* ALPN ровно «http/1.1» — расширение 0x0010 длиной 11, список длиной 9 (у ws и httpupgrade;
     * у прочих транспортов там пара «h2, http/1.1»). */
    s->alpn_h11 = memmem(ch, ch_n, "\x00\x10\x00\x0b\x00\x09\x08http/1.1", 11) != NULL;
    g_seen_h11 = s->alpn_h11;

    unsigned char cpub[32], sid[32];
    size_t sid_n = 0;
    if (ch_pick(ch, ch_n, cpub, sid, &sid_n)) return NULL;

    unsigned char spriv[32], spub[32];
    if (xc_x25519_keypair(spriv, spub) != 0) return NULL;

    /* ---- ServerHello ---- */
    unsigned char sh[256];
    size_t m = 0;
    sh[m++] = 0x02; m += 3;                          /* длина впишется ниже */
    sh[m++] = 0x03; sh[m++] = 0x03;
    if (xc_random(sh + m, 32) != 0) return NULL;
    m += 32;
    sh[m++] = (unsigned char)sid_n;
    memcpy(sh + m, sid, sid_n); m += sid_n;
    sh[m++] = SUITE_HI; sh[m++] = SUITE_LO;
    sh[m++] = 0x00;                                  /* compression */
    size_t exts_at = m; m += 2;
    sh[m++] = 0x00; sh[m++] = 0x2b; sh[m++] = 0x00; sh[m++] = 0x02;
    sh[m++] = 0x03; sh[m++] = 0x04;                  /* supported_versions: TLS 1.3 */
    if (!pl->no_keyshare) {
        sh[m++] = 0x00; sh[m++] = 0x33; sh[m++] = 0x00; sh[m++] = 0x24;
        sh[m++] = 0x00; sh[m++] = 0x1d; sh[m++] = 0x00; sh[m++] = 0x20;
        memcpy(sh + m, spub, 32); m += 32;
    }
    sh[exts_at]     = (unsigned char)((m - exts_at - 2) >> 8);
    sh[exts_at + 1] = (unsigned char)(m - exts_at - 2);
    sh[1] = (unsigned char)((m - 4) >> 16);
    sh[2] = (unsigned char)((m - 4) >> 8);
    sh[3] = (unsigned char)(m - 4);

    unsigned char rec[5 + 256];
    rec[0] = 0x16; rec[1] = 0x03; rec[2] = 0x03;
    rec[3] = (unsigned char)(m >> 8); rec[4] = (unsigned char)m;
    memcpy(rec + 5, sh, m);
    if (wr_all(s->fd, rec, 5 + m)) return NULL;

    if (sc_hash_init(&s->tr, SC_SHA256) != 0) return NULL;
    sc_hash_update(&s->tr, ch, ch_n);
    sc_hash_update(&s->tr, sh, m);

    if (pl->no_keyshare) { s->rc = 0; return NULL; }   /* дальше клиент уже не слушает */

    /* ---- расписание ключей рукопожатия, RFC 8446 §7.1 ---- */
    unsigned char zeros[HLEN] = {0}, empty[HLEN];
    unsigned char early[HLEN], derived[HLEN], hs[HLEN], ecdhe[32], th[HLEN];
    if (sc_hash(SC_SHA256, zeros, 0, empty) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, NULL, 0, zeros, HLEN, early) != 0) return NULL;
    if (xlabel(early, "derived", empty, HLEN, derived, HLEN) != 0) return NULL;
    if (x25519_shared_ext(spriv, cpub, ecdhe) != 0) return NULL;
    if (sc_hkdf_extract(SC_SHA256, derived, HLEN, ecdhe, 32, hs) != 0) return NULL;
    tr_snapshot(&s->tr, th);
    if (xlabel(hs, "s hs traffic", th, HLEN, s->s_hs, HLEN) != 0) return NULL;
    if (xlabel(hs, "c hs traffic", th, HLEN, s->c_hs, HLEN) != 0) return NULL;
    memcpy(s->hs, hs, HLEN);
    if (xlabel(s->s_hs, "key", NULL, 0, s->key, sizeof(s->key)) != 0) return NULL;
    if (xlabel(s->s_hs, "iv", NULL, 0, s->iv, sizeof(s->iv)) != 0) return NULL;

    /* ---- EncryptedExtensions ---- */
    unsigned char ee[64];
    size_t en = 0;
    ee[en++] = 0x08; en += 3;
    size_t elist_at = en; en += 2;
    if (pl->alpn) {
        size_t pn = strlen(pl->alpn);
        ee[en++] = 0x00; ee[en++] = 0x10;
        ee[en++] = 0x00; ee[en++] = (unsigned char)(3 + pn);
        ee[en++] = 0x00; ee[en++] = (unsigned char)(1 + pn);
        ee[en++] = (unsigned char)pn;
        memcpy(ee + en, pl->alpn, pn); en += pn;
    }
    ee[elist_at]     = (unsigned char)((en - elist_at - 2) >> 8);
    ee[elist_at + 1] = (unsigned char)(en - elist_at - 2);
    ee[1] = 0; ee[2] = (unsigned char)((en - 4) >> 8); ee[3] = (unsigned char)(en - 4);
    if (send_enc(s, ee, en)) return NULL;
    sc_hash_update(&s->tr, ee, en);

#if defined(STEER_HAVE_X509WRITE)
    /* ---- Certificate и CertificateVerify настоящей цепочкой (путь security=tls) ---- */
    if (pl->chain) {
        const struct leaf *l = &g_leaf[pl->chain];
        unsigned char msg[3072];
        size_t mn = cert_msg(l, msg, sizeof(msg));
        if (!mn) return NULL;
        if (send_enc(s, msg, mn)) return NULL;
        sc_hash_update(&s->tr, msg, mn);

        if (!pl->no_cv) {
            /* Хеш снимается ПОСЛЕ Certificate и ДО CertificateVerify — ровно то, что
             * подписывает сервер по RFC 8446 §4.4.3, и ровно то место, где клиент снимает
             * свой (tls13.c, разбор сообщения 0x0F). Ошибка на один шаг здесь дала бы
             * «подпись не сошлась» и выглядела бы находкой в движке. */
            unsigned char th_cv[HLEN];
            tr_snapshot(&s->tr, th_cv);
            size_t cn = cv_msg(l, th_cv, pl, msg, sizeof(msg));
            if (!cn) return NULL;
            if (send_enc(s, msg, cn)) return NULL;
            sc_hash_update(&s->tr, msg, cn);
        }
        goto finished;
    }
#endif

    /* ---- Certificate или его сжатый вид ---- */
    if (pl->cert == 2) {
        /* CompressedCertificate: клиент отвечает на него отказом сразу, не дожидаясь
         * Finished — сжатый сертификат означает, что нас передали маскировочному сайту. */
        unsigned char cc[16] = { 0x19, 0x00, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00,
                                 0x04, 0x01, 0x02, 0x03 };
        s->rc = send_enc(s, cc, 12) ? -1 : 0;
        return NULL;
    }
    if (pl->reality_ok) {
        /* Временный сертификат Reality: ключ Ed25519 (любые 32 байта — его никто не проверяет
         * как ключ) и поле подписи = HMAC-SHA512(authkey, ключ), где authkey — HKDF-SHA256 от
         * ECDH(постоянный ключ сервера, эфемерный клиента) с солью Random[0..20) и info
         * «REALITY» (reality.go у Xray; клиентская половина — reality.c). DER — ровно столько,
         * сколько читает cert_reality_check: SEQUENCE { tbs с SPKI Ed25519, algid, BIT STRING }. */
        unsigned char shared[32], authkey[32], epub[32], sig[64];
        if (x25519_shared_ext(g_rs_priv, cpub, shared) != 0) return NULL;
        if (sc_hkdf(SC_SHA256, ch + 6, 20, shared, 32, "REALITY", 7, authkey, 32) != 0) return NULL;
        for (int i = 0; i < 32; i++) epub[i] = (unsigned char)(0x40 + i);
        if (sc_hmac(SC_SHA512, authkey, 32, epub, 32, sig) != 0) return NULL;
        static const unsigned char spki[] = { 0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
                                              0x03, 0x21, 0x00 };
        unsigned char der[128];
        size_t dn = 0;
        der[dn++] = 0x30; der[dn++] = 0x78;                  /* Certificate, 120 байт */
        der[dn++] = 0x30; der[dn++] = 0x2C;                  /* tbsCertificate: только SPKI */
        memcpy(der + dn, spki, sizeof(spki)); dn += sizeof(spki);
        memcpy(der + dn, epub, 32); dn += 32;
        static const unsigned char alg[] = { 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70 };
        memcpy(der + dn, alg, sizeof(alg)); dn += sizeof(alg);
        der[dn++] = 0x03; der[dn++] = 0x41; der[dn++] = 0x00;
        memcpy(der + dn, sig, 64); dn += 64;
        unsigned char cm[256];
        size_t cn = 0, body = 1 + 3 + 3 + dn + 2;
        cm[cn++] = 0x0B;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(body >> 8); cm[cn++] = (unsigned char)body;
        cm[cn++] = 0;                                        /* certificate_request_context */
        size_t list = 3 + dn + 2;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(list >> 8); cm[cn++] = (unsigned char)list;
        cm[cn++] = 0; cm[cn++] = (unsigned char)(dn >> 8); cm[cn++] = (unsigned char)dn;
        memcpy(cm + cn, der, dn); cn += dn;
        cm[cn++] = 0; cm[cn++] = 0;                          /* расширений записи нет */
        if (send_enc(s, cm, cn)) return NULL;
        sc_hash_update(&s->tr, cm, cn);
    }
    if (pl->cert == 1) {
        /* Тело намеренно не разбирается ни в один сертификат: проверяется не разбор X.509,
         * а то, чем закрывается отказ проверки. */
        unsigned char cr[40];
        cr[0] = 0x0B; cr[1] = 0; cr[2] = 0; cr[3] = 32;
        memset(cr + 4, 0xA5, 32);
        if (send_enc(s, cr, 36)) return NULL;
        sc_hash_update(&s->tr, cr, 36);
    }

    /* ---- Finished ---- */
#if defined(STEER_HAVE_X509WRITE)
finished:;
#endif
    unsigned char fkey[HLEN], hash[HLEN], vd[HLEN];
    tr_snapshot(&s->tr, hash);
    if (xlabel(s->s_hs, "finished", NULL, 0, fkey, HLEN) != 0) return NULL;
    if (sc_hmac(SC_SHA256, fkey, HLEN, hash, HLEN, vd) != 0) return NULL;
    if (pl->bad_finished) vd[0] ^= 0xFF;
    unsigned char fin[4 + HLEN];
    fin[0] = 0x14; fin[1] = 0; fin[2] = 0; fin[3] = (unsigned char)HLEN;
    memcpy(fin + 4, vd, HLEN);
    if (send_enc(s, fin, sizeof(fin))) return NULL;
    sc_hash_update(&s->tr, fin, sizeof(fin));

    if (pl->upg) { s->rc = app_phase(s); return NULL; }
    s->rc = 0;
    return NULL;
}

/* ---- шов установления TCP ------------------------------------------------------ */

static int g_give_fd = -1;

static int fake_dial(const char *host, uint16_t port, int timeout_s) {
    (void)host; (void)port;
    int fd = g_give_fd;
    g_give_fd = -1;
    if (fd < 0) return TR_ECONNECT;
    /* Ровно то, что делает tcp_connect с победившим сокетом: срок на чтение и запись.
     * Без него ошибка в серверной половине вешала бы стенд, а не роняла его. */
    sock_ready(fd, timeout_s);
    return fd;
}

/* Узел: Reality поверх tcp. Именно Reality, а не security=tls: доказательством подлинности
 * здесь служит подпись временного сертификата на authkey, и для отказа проверки не нужно
 * ни хранилища корней, ни цепочки X.509 — то есть ветвь ECERT достижима без второго
 * стенда под сертификаты. Ключ pbk произвольный: X25519 умножает любые 32 байта, а сервер
 * этой пары всё равно поддельный. */
static void node_reality(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "reality");
    snprintf(n->sni, sizeof(n->sni), "%s", "www.example.com");
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
    snprintf(n->pbk, sizeof(n->pbk), "%s", "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA");
    snprintf(n->sid, sizeof(n->sid), "%s", "0123456789abcdef");
}

#if defined(STEER_HAVE_X509WRITE)
/* Узел security=tls: доказательство подлинности — цепочка до корня и имя, больше ничего.
 * pbk/sid не заполняются вовсе, и это не небрежность: у обычного TLS их не бывает, а
 * reality_build_hello при .plain = 1 их и не читает (client.c). Имя обязано быть — и
 * проверяется оно против sni, а не против host, поэтому sni здесь то, на которое выпущен
 * годный лист. */
static void node_tls(struct vless_node *n, const char *type) {
    memset(n, 0, sizeof(*n));
    snprintf(n->host, sizeof(n->host), "%s", "node.invalid");
    n->port = 443;
    snprintf(n->uuid, sizeof(n->uuid), "%s", "00000000-0000-0000-0000-000000000001");
    snprintf(n->type, sizeof(n->type), "%s", type);
    snprintf(n->security, sizeof(n->security), "%s", "tls");
    snprintf(n->sni, sizeof(n->sni), "%s", TLS_SNI);
    snprintf(n->fp, sizeof(n->fp), "%s", "chrome");
}
#endif

/* Один прогон: поднять пару, отдать один конец клиенту, второй — серверной половине.
 *
 * ctx_left, если он задан, получает число контекстов шифра, оставшихся РАЗВЁРНУТЫМИ в
 * соединении после возврата. Это наблюдаемая форма утверждения «освобождать было нечего»:
 * ветвь отказа рукопожатия закрывается одним close(fd), и безопасно это лишь пока tls13.c
 * разворачивает контексты трафика последним действием — уже после всех своих отказов.
 * Связь между двумя файлами, которую до этого стенда не охраняло ничто; проверка пойдёт
 * красной в тот день, когда порядок в tls13.c изменится. */
static int run_case(const struct plan *pl, struct vless_node *n, char *reason, size_t rn,
                    int *ctx_left) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;

    struct srv s;
    memset(&s, 0, sizeof(s));
    s.fd = sv[1];
    s.plan = pl;

    pthread_t th;
    if (pthread_create(&th, NULL, server_half, &s) != 0) {
        close(sv[0]); close(sv[1]);
        return -101;
    }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    if (rc == 0) transport_close(&c);
    g_tcp_dial = NULL;

    if (reason && rn) snprintf(reason, rn, "%s", tls13_verify_reason());
    if (ctx_left) *ctx_left = (c.link.tls.rd.ctx_ready ? 1 : 0) + (c.link.tls.wr.ctx_ready ? 1 : 0) +
                              (c.xh.up.link.tls.rd.ctx_ready ? 1 : 0) +
                              (c.xh.up.link.tls.wr.ctx_ready ? 1 : 0);

    pthread_join(th, NULL);
    if (s.fd >= 0) close(s.fd);
    /* Свой конец пары закрывает сам vless_connect (или vless_close на успехе). Не закрыл —
     * это и есть находка, и её видно проверкой по числу дескрипторов у вызывающего. */
    return rc;
}

/* Прогон ws или httpupgrade до данных: установление, первые данные за ответом 101 (они
 * приехали ОДНОЙ записью TLS с ответом), ответ клиента. 0 — всё сошлось; *srv_out — что
 * увидел сервер. */
static int run_upg(const struct plan *pl, struct vless_node *n, struct srv *s) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -100;
    memset(s, 0, sizeof(*s));
    s->fd = sv[1];
    s->plan = pl;
    pthread_t th;
    if (pthread_create(&th, NULL, server_half, s) != 0) { close(sv[0]); close(sv[1]); return -101; }

    g_give_fd = sv[0];
    g_tcp_dial = fake_dial;
    struct transport c;
    int rc = vless_connect(n, &c, 3);
    g_tcp_dial = NULL;
    if (rc == 0 && pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
    if (rc == 0) {
        static unsigned char buf[VLESS_MIN_RECV_CAP];
        size_t got = 0;
        for (int i = 0; i < 50 && !rc && !got; i++) {
            if (!transport_has_data(&c)) {
                struct pollfd p = { .fd = transport_fd(&c), .events = POLLIN, .revents = 0 };
                if (poll(&p, 1, 3000) <= 0) break;
            }
            rc = transport_read(&c, buf, sizeof(buf), &got);
        }
        if (!rc && (got != 5 || memcmp(buf, "FIRST", 5))) rc = -102;
        if (!rc && !pl->ed_first) rc = transport_write(&c, (const unsigned char *)"hello", 5);
        transport_close(&c);
    }
    pthread_join(th, NULL);
    if (s->fd >= 0) close(s->fd);
    return rc;
}

/* base64url без выравнивания — форма pbk в ссылке узла. */
static void b64url(const unsigned char *in, size_t n, char *out) {
    static const char T[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t o = 0;
    for (size_t i = 0; i < n; i += 3) {
        unsigned v = (unsigned)in[i] << 16;
        if (i + 1 < n) v |= (unsigned)in[i + 1] << 8;
        if (i + 2 < n) v |= in[i + 2];
        out[o++] = T[(v >> 18) & 63];
        out[o++] = T[(v >> 12) & 63];
        if (i + 1 < n) out[o++] = T[(v >> 6) & 63];
        if (i + 2 < n) out[o++] = T[v & 63];
    }
    out[o] = '\0';
}

/* Работает ли сама проверка кучи.
 *
 * Зачем это отдельной проверкой. Стенд, собранный С санитайзером, но запущенный с
 * ASAN_OPTIONS=detect_leaks=0, показывал бы «в куче ничего не осталось» на КАЖДОЙ ветви —
 * зелёный стенд, который больше не проверяет то, ради чего написан. Ровно этот класс
 * молчаливого отказа уже стоил проекту двух находок (I-066, I-067 не прогонялись ни разу),
 * и урок захода 75 сформулирован там же: барьер, который можно случайно выключить, обязан
 * говорить о своём состоянии сам.
 *
 * Утечка делается НАРОЧНО и тут же убирается: указатель спрятан исключающим ИЛИ, потому что
 * LeakSanitizer просматривает и стек, и регистры — живой указатель он не счёл бы утечкой.
 * Отчёт санитайзера, который появится ниже, — часть проверки, а не поломка. */
static volatile uintptr_t g_hidden;
#define HIDE_MASK ((uintptr_t)0x5a5a5a5a5a5a5a5aULL)

static void heap_check_selftest(void) {
#if defined(__SANITIZE_ADDRESS__)
    void *p = malloc(64);
    if (!p) return;
    memset(p, 0x11, 64);
    g_hidden = (uintptr_t)p ^ HIDE_MASK;
    p = NULL;
    printf("-- ниже ОЖИДАЕМЫЙ отчёт об утечке: так стенд убеждается, что проверка кучи включена --\n");
    fflush(stdout);
    int seen = LEAK_CHECK();
    printf("-- конец ожидаемого отчёта --\n");
    check("проверка кучи включена (нарочная утечка замечена)", 1, seen);
    free((void *)(g_hidden ^ HIDE_MASK));
    g_hidden = 0;
#endif
}

int main(void) {
    /* Серверная половина пишет в сокет, который клиент уже закрыл, — на отказе проверки он
     * закрывается, не дочитав. Без этого стенд умирал бы от SIGPIPE вместо того, чтобы
     * назвать результат. */
    signal(SIGPIPE, SIG_IGN);

    heap_check_selftest();

    struct vless_node node;
    node_reality(&node, "tcp");

    /* Прогрев. Первое рукопожатие тянет за собой одноразовые выделения криптобиблиотеки и
     * подъём потока, и без него первая же проверка кучи показала бы их как утечку. Что
     * прогрев сработал, видно по коду возврата: он обязан быть тем же, что в первом
     * измеряемом случае ниже. */
    {
        struct plan warm = { .name = "прогрев", .cert = 0 };
        char why[256];
        int rc = run_case(&warm, &node, why, sizeof(why), NULL);
        check("прогрев: рукопожатие дошло до проверки сертификата", TLS13_ECERT, rc);
    }

    static const struct plan plans[] = {
        { .name = "сервер не прислал сертификат", .cert = 0 },
        { .name = "сертификат не сошёлся с authkey", .cert = 1 },
        { .name = "сертификат приехал сжатым", .cert = 2 },
        { .name = "ServerHello без key_share", .no_keyshare = 1 },
        { .name = "серверный Finished не совпал", .bad_finished = 1 },
        { .name = "сервер закрылся после ClientHello", .hangup = 1 },
    };
    static const int want[] = {
        TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        TLS13_ENOKEYSHARE, TLS13_EFINISHED, TLS13_ECLOSED,
    };
    /* Причина отказа обязана дойти до вызывающего: без неё «узел не работает» и «узел не
     * тот» выглядят одинаково. Проверяется у трёх ветвей ECERT — только у них она есть. */
    static const char *why_want[] = {
        "не прислал сертификат",
        "не разобрался",
        /* Сжатый сертификат назван «не признал ключ», а не словом про сжатие, и это
         * намеренно: сервер Reality, признавший клиента, отвечает своим временным
         * сертификатом и не сжимает его — значит отвечает маскировочный сайт. Проверка
         * стоит здесь потому, что подмена этого текста на буквальный («сервер сжал
         * сертификат») увела бы человека к сжатию, к которому он не имеет отношения. */
        "не признал ключ",
        "", "", "",
    };

    for (size_t i = 0; i < sizeof(plans) / sizeof(*plans); i++) {
        /* Буфер стенда ВДВОЕ больше движкового (g_verify_reason[96]): стенд обязан
         * мерить движок, а не себя. Совпадающие размеры показали бы обрезку
         * собственным буфером как свойство движка — и наоборот. */
        char what[160], why[256] = "";
        int fd0 = fd_count(), ctx_left = -1;
        int rc = run_case(&plans[i], &node, why, sizeof(why), &ctx_left);

        snprintf(what, sizeof(what), "%s: код возврата", plans[i].name);
        check(what, want[i], rc);

        if (why_want[i][0]) {
            snprintf(what, sizeof(what), "%s: причина названа", plans[i].name);
            check_str(what, why_want[i], why);
        }

        /* Двадцать попыток подряд — то, что происходит на роутере: пул запасных сессий
         * пополняется на каждый SYN, сторож перебирает узлы пачками. Утечка на попытку
         * здесь и становится видимой, а не остаётся округлением. */
        for (int k = 0; k < 20; k++) {
            int again = run_case(&plans[i], &node, NULL, 0, NULL);
            if (again != want[i]) { rc = again; break; }
        }
        snprintf(what, sizeof(what), "%s: двадцать попыток дают тот же код", plans[i].name);
        check(what, want[i], rc);

        snprintf(what, sizeof(what), "%s: контекстов шифра не осталось развёрнутыми", plans[i].name);
        check(what, 0, ctx_left);

        snprintf(what, sizeof(what), "%s: дескрипторы вернулись к исходному числу", plans[i].name);
        check(what, fd0, fd_count());

        snprintf(what, sizeof(what), "%s: в куче ничего не осталось", plans[i].name);
        check(what, 0, LEAK_CHECK());
    }

    /* ---- удавшийся Reality и ws/httpupgrade поверх него (шаг 5 выпуска 1.10) ---------
     *
     * Сервер отвечает настоящим временным сертификатом Reality (подпись HMAC на authkey от
     * своей постоянной пары, pbk узла — её публичная половина), то есть рукопожатие здесь
     * УДАЁТСЯ, и дальше идут данные. У tcp проверяется только облик: ALPN прежний («h2,
     * http/1.1» — Hello у tcp шагом не тронут). У ws и httpupgrade — всё до данных: ALPN один
     * http/1.1, запрос Upgrade с путём без ed, ответ 101 и первые данные ОДНОЙ записью TLS (остаток
     * не теряется), ответ клиента дошёл — у ws кадром с маской. */
    if (xc_x25519_keypair(g_rs_priv, g_rs_pub) != 0) {
        printf("%-64s %s\n", "пара сервера Reality", "ПРОВАЛ");
        fails++;
    } else {
        /* ws — без ранних данных (ed=0: вырезается, Ed 0) и с ними (ed=2048: запрос уходит первой
         * записью, «hello» — в Sec-WebSocket-Protocol); httpupgrade с ed=2048 — ответ 101 читается
         * лениво, первым чтением. */
        static const char *rtype[] = { "tcp", "ws", "httpupgrade", "ws ed" };
        static const char *rpath[] = { "/w?ed=0", "/w?ed=0", "/w?ed=2048", "/w?ed=2048" };
        for (int u = 0; u < 4; u++) {
            struct plan up = { .name = "reality", .reality_ok = 1, .upg = u == 2 ? 2 : u ? 1 : 0,
                               .ed_first = u == 3 };
            struct vless_node rn;
            node_reality(&rn, u == 3 ? "ws" : rtype[u]);
            b64url(g_rs_pub, 32, rn.pbk);
            snprintf(rn.path, sizeof(rn.path), "%s", rpath[u]);
            snprintf(rn.http_host, sizeof(rn.http_host), "%s", "cdn.example");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc;
            if (u == 0) {
                g_seen_h11 = -1;
                g_seen_mlkem_before_x25519 = -1;
                rc = run_case(&up, &rn, NULL, 0, NULL);
                check("reality: временный сертификат признан — соединение установлено", 0, rc);
                check("reality + tcp: X25519MLKEM768 стоит перед X25519", 1,
                      g_seen_mlkem_before_x25519);
                check("reality + tcp: ALPN прежний, не один http/1.1", 0, g_seen_h11);
                check("reality + tcp: дескрипторы вернулись к исходному числу", fd0, fd_count());
                continue;
            }
            rc = run_upg(&up, &rn, &s);
            snprintf(what, sizeof(what), "reality + %s: соединение до данных", rtype[u]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "reality + %s: в ALPN только http/1.1", rtype[u]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "reality + %s: запрос Upgrade — путь без ed, Host из host", rtype[u]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: cdn.example\r\n", 36));
            snprintf(what, sizeof(what), u == 3 ? "reality + %s: «hello» в Sec-WebSocket-Protocol запроса"
                                                : "reality + %s: ответ клиента после 101 дошёл", rtype[u]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "reality + %s: дескрипторы вернулись к исходному числу", rtype[u]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "reality + %s: в куче ничего не осталось", rtype[u]);
            check(what, 0, LEAK_CHECK());
        }
    }

    /* ---- security=tls со своими корнями (R-118) ---------------------------------
     *
     * Здесь и только здесь проверка сервера может ПРОЙТИ, а значит только здесь достижимы
     * успешное установление целиком и ветвь ENOH2 — та, ради которой в клиенте появился
     * vless_close вместо close(fd). Корни отдаются движку швом g_cert_roots; хранилище
     * одно на весь процесс, потому что certverify.c разбирает его под pthread_once
     * (I-217), и второе тут не подействовало бы. */
#if defined(STEER_HAVE_X509WRITE)
    if (chain_build() != 0) {
        printf("%-64s %s\n", "выпуск своей цепочки X.509", "ПРОВАЛ");
        fails++;
    } else {
        g_cert_roots = g_roots_file;

        /* Прогрев второй половины: первое рукопожатие с проверкой цепочки тянет за собой
         * разбор хранилища корней под pthread_once — 
         * он остаётся в куче навсегда по замыслу (см. roots_load), и без прогрева первая
         * же проверка кучи показала бы его утечкой. */
        {
            struct plan warm = { .name = "прогрев tls", .chain = LEAF_OK };
            struct vless_node w;
            node_tls(&w, "tcp");
            int rc = run_case(&warm, &w, NULL, 0, NULL);
            check("прогрев tls: цепочка сошлась, соединение установлено", 0, rc);
        }

        static const struct plan tls_plans[] = {
            { .name = "tls: цепочка сошлась",            .chain = LEAF_OK },
            { .name = "tls: сервер выбрал не h2",        .chain = LEAF_OK, .alpn = "http/1.1" },
            { .name = "tls: лист выдан на другое имя",   .chain = LEAF_NAME },
            { .name = "tls: лист подписан сам собой",    .chain = LEAF_SELF },
            { .name = "tls: сертификат без подписи",     .chain = LEAF_OK, .no_cv = 1 },
            { .name = "tls: подпись не сходится",        .chain = LEAF_OK, .cv_bad_sig = 1 },
            { .name = "tls: алгоритм не из предложенных",.chain = LEAF_OK, .cv_bad_alg = 1 },
        };
        /* Транспорт: у случая с ALPN он ОБЯЗАН быть не raw. Для tcp ALPN не просят вовсе
         * (transport.c: у tr_tcp alpn = NULL), и проверка «сервер назвал не h2» там не
         * стоит — то есть на tcp этот случай молча прошёл бы успехом. */
        static const char *tls_type[] = { "tcp", "grpc", "tcp", "tcp", "tcp", "tcp", "tcp" };
        static const int tls_want[] = {
            0, TR_ENOH2, TLS13_ECERT, TLS13_ECERT,
            TLS13_ECERT, TLS13_ECERT, TLS13_ECERT,
        };
        /* ОЖИДАЕТСЯ ТО, ЧТО ДОХОДИТ СЕГОДНЯ, а не то, что написано в certverify.c, и разница
         * здесь — находка I-236, а не небрежность стенда. Два самых длинных текста причин не
         * влезают в g_verify_reason[96]: «сертификат не сошёлся с корнями или выдан не на это
         * имя» это 100 байт, «сервер подписал алгоритмом, которого мы не предлагали» — 99.
         * Обрезка у первого приходится НА СЕРЕДИНУ БУКВЫ. Поправить нельзя автономно: буфер
         * живёт в tls13.c, а это защищённый путь (п.5.0) — заведён proposal. Проверка ниже
         * («причина обрезана») меряет это числом, и когда буфер вырастет, она покраснеет —
         * это и будет напоминанием заменить ожидания здесь на полные тексты. */
        static const char *tls_why[] = {
            "", "",
            "выдан не на это",          /* CERTV_ECHAIN: имя проверяется третьим доводом verify */
            "не сошёлся с корнями",     /* тот же код, другая половина его текста */
            "не прислал подпись",       /* tls13.c различает «нет сертификата» и «нет подписи» */
            "подпись сервера неверна",  /* CERTV_ESIG */
            "которого мы не предлага",  /* CERTV_EALG — отдельная причина, а не «подпись плохая» */
        };
        /* Сколько байт причины дошло. -1 — «не проверяем»; 95 — обрезано движковым буфером. */
        static const int tls_why_len[] = { -1, -1, 95, -1, -1, -1, 95 };

        for (size_t i = 0; i < sizeof(tls_plans) / sizeof(*tls_plans); i++) {
            struct vless_node tn;
            node_tls(&tn, tls_type[i]);
            char what[160], why[256] = "";
            int fd0 = fd_count(), ctx_left = -1;
            int rc = run_case(&tls_plans[i], &tn, why, sizeof(why), &ctx_left);

            snprintf(what, sizeof(what), "%s: код возврата", tls_plans[i].name);
            check(what, tls_want[i], rc);

            if (tls_why[i][0]) {
                snprintf(what, sizeof(what), "%s: причина названа", tls_plans[i].name);
                check_str(what, tls_why[i], why);
            }
            if (tls_why_len[i] >= 0) {
                /* КРАСНОЕ ЗДЕСЬ — ХОРОШАЯ НОВОСТЬ: значит g_verify_reason вырос и текст
                 * доходит целиком (I-236). Тогда это число убирается, а ожидание причины
                 * выше заменяется полным текстом из certverify.c. */
                snprintf(what, sizeof(what), "%s: причина обрезана буфером движка (I-236)",
                         tls_plans[i].name);
                check(what, tls_why_len[i], (long)strlen(why));
            }

            for (int k = 0; k < 20; k++) {
                int again = run_case(&tls_plans[i], &tn, NULL, 0, NULL);
                if (again != tls_want[i]) { rc = again; break; }
            }
            snprintf(what, sizeof(what), "%s: двадцать попыток дают тот же код", tls_plans[i].name);
            check(what, tls_want[i], rc);

            snprintf(what, sizeof(what), "%s: контекстов шифра не осталось развёрнутыми", tls_plans[i].name);
            check(what, 0, ctx_left);

            snprintf(what, sizeof(what), "%s: дескрипторы вернулись к исходному числу", tls_plans[i].name);
            check(what, fd0, fd_count());

            snprintf(what, sizeof(what), "%s: в куче ничего не осталось", tls_plans[i].name);
            check(what, 0, LEAK_CHECK());
        }
        /* ws и httpupgrade поверх обычного TLS со своей цепочкой: то же, что у Reality выше,
         * плюс настоящая проверка сертификата — путь, которым идут узлы за CDN. */
        static const char *ttype[] = { "ws", "httpupgrade", "ws ed" };
        for (int u = 1; u <= 3; u++) {
            struct plan up = { .name = "tls", .chain = LEAF_OK, .upg = u == 2 ? 2 : 1, .ed_first = u == 3 };
            struct vless_node tn;
            node_tls(&tn, u == 2 ? "httpupgrade" : "ws");
            snprintf(tn.path, sizeof(tn.path), "%s", u == 1 ? "/w?ed=0" : "/w?ed=2048");
            char what[160];
            int fd0 = fd_count();
            static struct srv s;
            int rc = run_upg(&up, &tn, &s);
            snprintf(what, sizeof(what), "tls + %s: соединение до данных", ttype[u - 1]);
            check(what, 0, rc);
            snprintf(what, sizeof(what), "tls + %s: в ALPN только http/1.1", ttype[u - 1]);
            check(what, 1, s.alpn_h11);
            snprintf(what, sizeof(what), "tls + %s: Host без host — sni", ttype[u - 1]);
            check(what, 1, !strncmp(s.req, "GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n",
                                    strlen("GET /w HTTP/1.1\r\nHost: " TLS_SNI "\r\n")));
            snprintf(what, sizeof(what), "tls + %s: ответ клиента после 101 дошёл", ttype[u - 1]);
            check(what, 1, s.got_hello);
            snprintf(what, sizeof(what), "tls + %s: дескрипторы вернулись к исходному числу", ttype[u - 1]);
            check(what, fd0, fd_count());
            snprintf(what, sizeof(what), "tls + %s: в куче ничего не осталось", ttype[u - 1]);
            check(what, 0, LEAK_CHECK());
        }
        /* Сервер за TLS выбрал h2 — а апгрейд идёт по HTTP/1.1: свой код, не «не согласился на
         * HTTP/2». */
        {
            struct plan up = { .name = "tls h2", .chain = LEAF_OK, .alpn = "h2" };
            struct vless_node tn;
            node_tls(&tn, "ws");
            int rc = run_case(&up, &tn, NULL, 0, NULL);
            check("tls + ws: сервер выбрал h2 — отказ TR_ENOH1", TR_ENOH1, rc);
        }
        g_cert_roots = NULL;
        chain_free();
    }
#else
    printf("\nВНИМАНИЕ: собрано БЕЗ выпуска сертификатов (нет STEER_HAVE_X509WRITE, tests/certgen.c) —\n");
    printf("          семь случаев security=tls ПРОПУЩЕНЫ: ни удавшаяся проверка сервера,\n");
    printf("          ни ветвь ENOH2 с её vless_close здесь не проверены (R-118).\n\n");
#endif

    /* security=none: TLS нет вовсе, и путь выхода тут единственный успешный. Нужен не ради
     * него самого, а как поверка стенда: если бы шов отдавал негодный сокет, «успех» тоже
     * стал бы отказом, и все проверки выше прошли бы по неверной причине. */
    {
        struct vless_node plain;
        memset(&plain, 0, sizeof(plain));
        snprintf(plain.host, sizeof(plain.host), "%s", "node.invalid");
        plain.port = 443;
        snprintf(plain.type, sizeof(plain.type), "%s", "tcp");
        snprintf(plain.security, sizeof(plain.security), "%s", "none");

        int sv[2];
        if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return 2;
        g_give_fd = sv[0];
        g_tcp_dial = fake_dial;
        struct transport c;
        int rc = vless_connect(&plain, &c, 3);
        g_tcp_dial = NULL;
        check("security=none поверх tcp: соединение установлено", 0, rc);
        check("security=none: TLS не разворачивался", 1, c.link.plain);
        if (rc == 0) transport_close(&c);
        check("security=none: дескриптор закрыт vless_close", -1, c.link.fd);
        close(sv[1]);
        check("security=none: в куче ничего не осталось", 0, LEAK_CHECK());
    }

#if !defined(__SANITIZE_ADDRESS__)
    printf("\nВНИМАНИЕ: собрано БЕЗ AddressSanitizer — проверки «в куче ничего не осталось»\n");
    printf("          прошли пусто. Коды возврата и дескрипторы проверены, куча — НЕТ.\n");
#endif
    printf("\n%s\n", fails ? "ЕСТЬ ПРОВАЛЫ" : "все проверки прошли");
    return fails ? 1 : 0;
}
