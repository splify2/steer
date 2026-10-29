/* Плагин warpbox без сети: разворот `kind: warp` (хук expand), ответ API по пути, файл туннеля и маски.
 *
 * ЧТО И ПОЧЕМУ ЗДЕСЬ. Сеть и ядро у модуля проверяются вживую (регистрация в API Cloudflare, подбор на
 * устройствах подбора — стенд QEMU, журнал в хабе, WARPBOX.md); здесь — то, что ломается тихо:
 *   - разворот `kind: warp` (wbexpand.c) заводит группу и члены awg с путями файлов, которые помощник
 *     потом пишет, — разойдись они, помощник писал бы файлы, которых ядро не читает;
 *   - поиск по пути в ответе API: поле внутри массива, экранированный ключ, отсутствующий путь;
 *   - файл туннеля, который пишет модуль, обязан приниматься разбором awg ядра (awg_conf_parse) —
 *     со всеми масками I1, включая собранные заново DNS, STUN и SIP: маска, которую разбор не
 *     принял, означает туннель, который не поднимется ни на одной точке, и подбор, который
 *     переберёт их все.
 * awg.c компонуется (Makefile), а не #include: стенду нужен только его открытый разбор файла (awg.h). */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include "spec.h"

int run_quiet(const char *const argv[]) { (void)argv; return 0; }

#include "awg.h"
#include "kind.h"
#include "platform.h"
#include "wbconf.h"
#include "wbjson.h"
#include "wbexpand.h"
#include "pkjson.h"

static int fails, passes;

static void check(const char *what, long want, long got) {
    if (want == got) { passes++; printf("ok   %s\n", what); return; }
    fails++;
    printf("FAIL %s\n  expected: %ld\n  actual:   %ld\n", what, want, got);
}

static void check_s(const char *what, const char *want, const char *got) {
    if (!strcmp(want, got)) { passes++; printf("ok   %s\n", what); return; }
    fails++;
    printf("FAIL %s\n  expected: %s\n  actual:   %s\n", what, want, got);
}

/* Разворот хуком expand (src/proto/warp/wbexpand.c): вход — как его даёт ядро, ответ — фрагмент JSON. */
static struct pkj *expand(const char *keys, const char *common, int *rc) {
    char in[1024];
    snprintf(in, sizeof in, "{\"api\":\"1.1\",\"output\":{\"name\":\"%s\",\"kind\":\"warp\",\"keys\":%s,\"common\":%s},"
             "\"spec\":{\"etc\":\"/etc/steer\",\"outputs\":[]},\"platform\":\"openwrt\"}",
             strstr(keys, "\"__name\"") ? "x" : "cf", keys, common);
    char err[200];
    struct pkj *d = pkj_parse(in, strlen(in), err, sizeof err);
    if (!d) { *rc = -1; return NULL; }
    char *buf = NULL;
    size_t bn = 0;
    FILE *f = open_memstream(&buf, &bn);
    *rc = warp_expand(d, f);
    fclose(f);
    pkj_free(d);
    struct pkj *o = *rc ? NULL : pkj_parse(buf, strlen(buf), err, sizeof err);
    free(buf);
    return o;
}

static void t_expand(void) {
    int rc;
    struct pkj *o = expand("{\"count\":3,\"countries\":[\"de\",\"nl\"]}", "{}", &rc);
    check("warp: разворот принят", 0, rc);
    if (!o) return;
    check_s("warp: self — группа", "group", pkj_str(pkj_path(o, "self.kind")));
    check("warp: членов — count", 3, (long)pkj_len(pkj_path(o, "self.members")));
    check_s("warp: pick по умолчанию — latency", "latency", pkj_str(pkj_path(o, "self.pick")));
    long iv = 0;
    pkj_long(pkj_path(o, "self.interval"), &iv);
    check("warp: интервал замера по умолчанию — 600 с", 600, iv);
    int helper = 0;
    pkj_bool(pkj_get(o, "helper"), &helper);
    check("warp: помощник ведёт группу (helper: true)", 1, helper);
    const struct pkj *outs = pkj_get(o, "outputs");
    check("warp: член cf.2 — awg", 1, pkj_str(pkj_path(pkj_get(outs, "cf.2"), "kind")) &&
          !strcmp(pkj_str(pkj_path(pkj_get(outs, "cf.2"), "kind")), "awg"));
    check_s("warp: файл члена — {etc}/warp/<группа>-<n>.conf", "/etc/steer/warp/cf-2.conf",
            pkj_str(pkj_path(pkj_get(outs, "cf.2"), "conf")));
    check_s("warp: IPv6 члена — nat по умолчанию", "nat", pkj_str(pkj_path(pkj_get(outs, "cf.1"), "ipv6")));
    pkj_free(o);
    o = expand("{}", "{\"ipv6\":\"off\",\"over\":\"wg0\",\"on_fail\":\"direct\"}", &rc);
    check("warp: ipv6: off, over, on_fail — приняты", 0, rc);
    if (o) {
        const struct pkj *m = pkj_get(pkj_get(o, "outputs"), "cf.1");
        check_s("  у членов off", "off", pkj_str(pkj_get(m, "ipv6")));
        check_s("  over — у членов", "wg0", pkj_str(pkj_get(m, "over")));
        check_s("  on_fail — у группы", "direct", pkj_str(pkj_path(o, "self.on_fail")));
        check("warp: count по умолчанию — один туннель", 1, (long)pkj_len(pkj_path(o, "self.members")));
        pkj_free(o);
    }
    expand("{}", "{\"ipv6\":\"routed\"}", &rc);
    check("warp: ipv6: routed — отказ", 2, rc);
    o = expand("{\"transport\":\"masque\",\"count\":2}", "{}", &rc);
    check("warp: masque — принят", 0, rc);
    if (o) {
        const struct pkj *m = pkj_get(pkj_get(o, "outputs"), "cf.2");
        check_s("  член — вид plugin-device", "plugin-device", pkj_str(pkj_get(m, "kind")));
        check("  файла туннеля у члена MASQUE нет", 1, pkj_get(m, "conf") == NULL);
        pkj_free(o);
    }
    expand("{\"countries\":[\"RU\"],\"exclude_countries\":[\"ru\"]}", "{}", &rc);
    check("warp: страна и в countries, и в exclude_countries — отказ", 2, rc);
    expand("{\"pick\":\"order\",\"tolerance\":5}", "{}", &rc);
    check("warp: tolerance без pick: latency — отказ", 2, rc);
    expand("{}", "{\"device\":\"wg9\"}", &rc);
    check("warp: device — отказ (имена туннелей выбирает ядро)", 2, rc);
}

static void t_json(void) {
    const char *d = "{\"result\":{\"id\":\"abc\",\"x\":[1,{\"q\":\"z\"}],\"config\":{\"peers\":[{\"public_key\":"
                    "\"K\\u002b=\",\"endpoint\":{\"v4\":\"1.2.3.4:0\"}}],\"interface\":{\"addresses\":"
                    "{\"v4\":\"172.16.0.2\"}}},\"warp_enabled\":true,\"n\":-12}}";
    char o[64];
    check("json: строка", 0, wb_json_get(d, "result.id", o, sizeof o));
    check_s("  значение", "abc", o);
    check("json: внутри массива", 0, wb_json_get(d, "result.config.peers.0.public_key", o, sizeof o));
    check_s("  \\u002b раскодирован", "K+=", o);
    check("json: объект в массиве", 0, wb_json_get(d, "result.x.1.q", o, sizeof o));
    check_s("  значение", "z", o);
    check("json: суррогатная пара — один знак UTF-8 из четырёх байт", 0,
          wb_json_get("{\"k\":\"a\\ud83d\\ude00b\"}", "k", o, sizeof o));
    check_s("  эмодзи U+1F600, а не две половины по три байта", "a\xF0\x9F\x98\x80" "b", o);
    check("json: одиночная верхняя половина", 0, wb_json_get("{\"k\":\"\\ud83dX\"}", "k", o, sizeof o));
    check_s("  — U+FFFD, не CESU-8", "\xEF\xBF\xBD" "X", o);
    check("json: одиночная нижняя половина", 0, wb_json_get("{\"k\":\"\\ude00\"}", "k", o, sizeof o));
    check_s("  — тоже U+FFFD", "\xEF\xBF\xBD", o);
    {
        /* I-543: обрыв не принимается за конец ответа. */
        char r1[] = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nabcde";
        int st = 0; size_t off = 0, bl = 0;
        check("http: тела меньше Content-Length — обрыв, а не короткое тело", -2,
              wb_http_split(r1, strlen(r1), &st, &off, &bl));
        char r2[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabcde";
        check("http: Content-Length сошёлся", 0, wb_http_split(r2, strlen(r2), &st, &off, &bl));
        check("  статус и тело", 200 * 100 + 5, st * 100 + (int)bl);
        char r3[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n3\r\nfgh";
        check("http: chunked без завершающего куска — обрыв", -2, wb_http_split(r3, strlen(r3), &st, &off, &bl));
        char r4[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nabcde\r\n3\r\nfgh\r\n0\r\n\r\n";
        check("http: chunked целиком", 0, wb_http_split(r4, strlen(r4), &st, &off, &bl));
        check("  тело склеено", 8, (int)bl);
        check("  и лежит с off", 0, memcmp(r4 + off, "abcdefgh", 8));
        char r5[] = "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nпросто до закрытия";
        check("http: без длины тело — всё до конца", 0, wb_http_split(r5, strlen(r5), &st, &off, &bl));
        char r6[] = "garbage";
        check("http: не HTTP", -1, wb_http_split(r6, strlen(r6), &st, &off, &bl));
    }
    check("json: \\n — перевод строки", 0, wb_json_get("{\"k\":\"a\\nb\"}", "k", o, sizeof o));
    check_s("  значение", "a\nb", o);
    check("json: true — текстом", 0, wb_json_get(d, "result.warp_enabled", o, sizeof o));
    check_s("  значение", "true", o);
    check("json: число — текстом", 0, wb_json_get(d, "result.n", o, sizeof o));
    check_s("  значение", "-12", o);
    check("json: нет пути", -1, wb_json_get(d, "result.nope", o, sizeof o));
    check("json: за концом массива", -1, wb_json_get(d, "result.x.5", o, sizeof o));
    check("json: объект — не значение", -1, wb_json_get(d, "result.config", o, sizeof o));
    check("json: не уместилось", -1, wb_json_get(d, "result.config.interface.addresses.v4", o, 4));
    /* Строка длиннее 512 байт перед искомым полем: обход её пропускает, не копируя (ответ API на
     * включение MASQUE несёт длинные поля до config). */
    static char big[2048];
    char filler[1200];
    memset(filler, 'x', sizeof(filler) - 1);
    filler[sizeof(filler) - 1] = '\0';
    snprintf(big, sizeof(big), "{\"license\":\"%s\",\"a\":[\"%s\",{\"k\":1}],\"config\":{\"v\":\"ok\"}}",
             filler, filler + 600);
    check("json: длинная строка до поля — обход её пропускает", 0, wb_json_get(big, "config.v", o, sizeof o));
    check_s("  значение", "ok", o);
    check("json: экранированная кавычка в пропускаемой строке", 0,
          wb_json_get("{\"s\":\"a\\\"b\",\"t\":\"z\"}", "t", o, sizeof o));
    check_s("  значение", "z", o);
}

/* Файл туннеля с маской k принимается разбором awg ядра; I1 доходит до разбора целиком. */
static void t_conf(void) {
    struct wb_reg r;
    memset(&r, 0, sizeof r);
    /* Ключи — валидный base64 32 байт (значения не важны разбору). */
    snprintf(r.priv, sizeof r.priv, "4OnO86dDLpqJ2U10ODwX3tarx6xlRGLfkmbSBtMgaHg=");
    snprintf(r.peer_pub, sizeof r.peer_pub, "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=");
    snprintf(r.v4, sizeof r.v4, "172.16.0.2");
    snprintf(r.v6, sizeof r.v6, "2606:4700:110:8a36:df92:102a:9602:fa18");
    char path[] = "/tmp/warpmatch-conf-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) { check("mkstemp", 0, -1); return; }
    close(fd);
    for (int k = 0; k < WB_MASKS; k++) {
        char i1[8192], what[96];
        const char *name;
        const char *m = wb_mask(k, i1, sizeof i1, &name);
        snprintf(what, sizeof what, "маска %d (%s) собрана", k, name);
        check(what, 1, m != NULL);
        struct wb_conf c = { .reg = &r, .endpoint = "162.159.192.1:2408", .i1 = m, .obfs = 1, .addr = 1, .keepalive = 25 };
        check("  файл записан", 0, wb_conf_write(path, &c));
        static struct awg_conf ac;
        struct awg_secrets s;
        char err[256] = "";
        int rc = awg_conf_load(path, &ac, &s, err, sizeof err);
        snprintf(what, sizeof what, "  разбор awg принял файл с маской %s%s%s", name, err[0] ? " — " : "", err);
        check(what, 0, rc);
        if (rc == 0) {
            check("  нужен AmneziaWG (обфускация)", 1, awg_conf_needs_awg(&ac));
            check("  один пир", 1, (long)ac.peer_n);
            check("  адреса v4 и v6", 2, (long)ac.addr_n);
            check("  MTU 1280", 1280, ac.mtu);
            check("  I1 дошёл до разбора целиком", (long)strlen(m), ac.istr[0] ? (long)strlen(ac.istr[0]) : -1);
        }
        awg_secrets_wipe(&s);
        awg_conf_free(&ac);
    }
    /* Без AmneziaWG — обычный WireGuard: разбор не требует модуля AmneziaWG. */
    struct wb_conf c = { .reg = &r, .endpoint = "162.159.192.1:2408", .obfs = 0, .addr = 0, .keepalive = 5 };
    check("без обфускации: файл записан", 0, wb_conf_write(path, &c));
    static struct awg_conf ac;
    struct awg_secrets s;
    char err[256] = "";
    check("  разбор принял", 0, awg_conf_load(path, &ac, &s, err, sizeof err));
    check("  AmneziaWG не нужен", 0, awg_conf_needs_awg(&ac));
    check("  без Address", 0, (long)ac.addr_n);
    awg_secrets_wipe(&s);
    awg_conf_free(&ac);
    char ep[64];
    check("Endpoint читается из файла", 0, wb_conf_endpoint(path, ep, sizeof ep));
    check_s("  значение", "162.159.192.1:2408", ep);
    struct stat st;
    check("файл — 0600", 0600, stat(path, &st) == 0 ? (long)(st.st_mode & 0777) : -1);
    unlink(path);
}

int main(void) {
    t_expand();
    t_json();
    t_conf();
    printf("warpmatch: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
