/* Хранилище корней certverify.c: ключ — путь, а не процесс (I-217).
 *
 * Прежде путь первого вызова действовал навсегда (pthread_once), а запись пути в общий указатель
 * была гонкой потоков. Шов «свой набор корней для стенда» тем самым не работал: после одного
 * соединения с умолчанием стенд молча проверял системными корнями.
 *
 * Библиотека корней (sc_roots_*) подменена: стенду важно, какой ФАЙЛ прочитан и сколько раз, а не
 * то, что внутри. certverify.c линкуется отдельным объектом (правило unit.h: стенд не включает чужой .c),
 * а до хранилища стенд доходит через открытый cert_verify_server_ex: sc_chain_verify получает указатель
 * хранилища первым аргументом, его стенд и записывает. */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "unit.h"
#include "scrypto.h"
#include "certverify.h"

static int g_loads;                          /* сколько раз «разобрали» хранилище */
struct sc_roots { char text[64]; };
static struct sc_roots *g_last;              /* хранилище, с которым звали sc_chain_verify */

int sc_roots_load(struct sc_roots **out, const unsigned char *pem, size_t n) {
    struct sc_roots *r = calloc(1, sizeof(*r));
    memcpy(r->text, pem, n < sizeof(r->text) - 1 ? n : sizeof(r->text) - 1);
    __atomic_add_fetch(&g_loads, 1, __ATOMIC_SEQ_CST);
    *out = r;
    return 0;
}
int sc_roots_load_der(struct sc_roots **o, const unsigned char *d, size_t n) { (void)o; (void)d; (void)n; return -1; }
void sc_roots_free(struct sc_roots *r) { free(r); }
/* Всегда «цепочка не сошлась»: до проверки подписи дело не доходит, и стенду нужен только указатель. */
int sc_chain_verify(struct sc_roots *r, const unsigned char *const *d, const size_t *dn, size_t c, const char *h)
    { (void)d; (void)dn; (void)c; (void)h; __atomic_store_n(&g_last, r, __ATOMIC_SEQ_CST); return -1; }
int sc_cert_verify_sig(const unsigned char *c, size_t n, enum sc_sig_alg a, enum sc_hash h,
                       const unsigned char *dg, size_t dn, const unsigned char *s, size_t sn)
    { (void)c; (void)n; (void)a; (void)h; (void)dg; (void)dn; (void)s; (void)sn; return -1; }
int sc_hash(enum sc_hash h, const void *d, size_t n, unsigned char *o)
    { (void)h; (void)d; (void)n; (void)o; return -1; }

/* Сообщение Certificate из одного «сертификата» (содержимое любое: библиотека подменена). */
static const unsigned char CERT_MSG[] = { 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x03, 0x30, 0x00, 0x00, 0x00, 0x00 };
static const unsigned char CV_MSG[] = { 0x04, 0x03, 0x00, 0x00 };

/* Хранилище, которое звали бы для проверки с этим путём; NULL — не дошло (не прочиталось). */
static struct sc_roots *store_for(const char *path, int *rc) {
    g_last = NULL;
    *rc = cert_verify_server_ex(CERT_MSG, sizeof CERT_MSG, CV_MSG, sizeof CV_MSG, (const unsigned char *)"", 32,
                                "h.example", path, NULL);
    return g_last;
}

static void put(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    fputs(text, f);
    fclose(f);
}

static struct sc_roots *g_seen[8];
static const char *g_thread_path;

static void *worker(void *arg) {
    long i = (long)arg;
    int rc;
    struct sc_roots *r = store_for(g_thread_path, &rc);
    g_seen[i] = r;
    return NULL;
}

int main(void) {
    char a[] = "/tmp/certroots-a-XXXXXX", b[] = "/tmp/certroots-b-XXXXXX";
    close(mkstemp(a));
    close(mkstemp(b));
    put(a, "корни А");
    put(b, "корни Б");

    int rc;
    struct sc_roots *ra = store_for(a, &rc);
    check("первый путь: хранилище загружено и использовано", 1, ra != NULL);
    struct sc_roots *rb = store_for(b, &rc);
    check("второй путь: хранилище загружено и использовано", 1, rb != NULL);
    check("второй путь действует: хранилище другое, а не первого вызова", 1, ra != rb);
    if (rb) check_str("второе хранилище прочитано из своего файла", "корни Б", rb->text);
    struct sc_roots *ra2 = store_for(a, &rc);
    check("первый путь снова — то же хранилище", 1, ra == ra2);
    check("  разобрано ровно два файла, без повторного разбора", 2, g_loads);

    struct sc_roots *rx = store_for("/tmp/certroots-нет-такого", &rc);
    check("нет файла — отказ ENOROOTS, до проверки цепочки не доходит", CERTV_ENOROOTS, rc);
    check("  хранилища нет", 1, rx == NULL);
    check("  и оно не разбирается заново", 2, g_loads);
    put("/tmp/certroots-нет-такого", "x");           /* появился позже: прежний ответ держится, как раньше */
    store_for("/tmp/certroots-нет-такого", &rc);
    check("  отказ запомнен для пути (как у прежнего pthread_once)", CERTV_ENOROOTS, rc);
    unlink("/tmp/certroots-нет-такого");

    /* Восемь потоков за один новый путь: одна загрузка и один указатель. */
    char c[] = "/tmp/certroots-c-XXXXXX";
    close(mkstemp(c));
    put(c, "корни В");
    g_thread_path = c;
    g_loads = 0;
    pthread_t th[8];
    for (long i = 0; i < 8; i++) pthread_create(&th[i], NULL, worker, (void *)i);
    for (int i = 0; i < 8; i++) pthread_join(th[i], NULL);
    int same = 1;
    for (int i = 1; i < 8; i++) if (g_seen[i] != g_seen[0]) same = 0;
    check("восемь потоков: одно хранилище", 1, same && g_seen[0] != NULL);
    check("восемь потоков: одна загрузка", 1, g_loads);

    unlink(a); unlink(b); unlink(c);
    return unit_done("certrootsmatch");
}
