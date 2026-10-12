/* Модуль steer-warpbox без сети: группа `kind: warp` в спеке, ответ API по пути, файл туннеля и маски.
 *
 * ЧТО И ПОЧЕМУ ЗДЕСЬ. Сеть и ядро у модуля проверяются вживую (регистрация в API Cloudflare, подбор на
 * устройствах подбора — стенд QEMU, журнал в хабе, WARPBOX.md); здесь — то, что ломается тихо:
 *   - разбор `kind: warp` заводит группу и члены awg с путями файлов, которые модуль потом пишет, —
 *     разойдись они, модуль писал бы файлы, которых ядро не читает;
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

static int spec_load(const char *text, struct spec *sp, char *msg, size_t mn) {
    char path[] = "/tmp/warpmatch-XXXXXX";
    int fd = mkstemp(path);
    if (fd < 0) return -1;
    if (write(fd, text, strlen(text)) < 0) { close(fd); return -1; }
    close(fd);
    struct err e = { 0 };
    memset(sp, 0, sizeof(*sp));
    int rc = load_spec(path, sp, &e);
    unlink(path);
    snprintf(msg, mn, "%s", e.msg);
    return rc;
}

static void t_spec(void) {
    static struct spec sp;
    char msg[1024];
    check("warp: спека принята", 0,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, count: 3, countries: [de, nl] }\n", &sp, msg, sizeof msg) < 0);
    const struct output *g = out_by_name(&sp, "cf");
    check("warp: группа есть", 1, g && out_group(g) && g->grp.warp.on);
    if (!g) return;
    check("warp: членов — count", 3, (long)g->grp.members_n);
    check("warp: pick по умолчанию — latency", PICK_LATENCY, g->grp.pick);
    check("warp: две страны", 2, (long)g->grp.warp.cc_n);
    check_s("warp: страны в верхнем регистре", "DE", g->grp.warp.cc[0]);
    check("warp: exclude_countries не задан", 0, g->grp.warp.xcc_set);
    const struct output *m = out_by_name(&sp, "cf.2");
    check("warp: член cf.2 — awg", 1, m && kind_of(m) == &kind_awg);
    if (m) {
        check_s("warp: член знает группу", "cf", m->warp_of);
        char want[512];
        snprintf(want, sizeof want, "%s/warp/cf-2.conf", plat()->etc_dir);
        check_s("warp: файл члена — {etc}/warp/<группа>-<n>.conf", want, m->awg.conf);
        check("warp: IPv6 члена — nat по умолчанию", OUT_V6_NAT, m->ipv6);
    }
    check("warp: ipv6: off — принят", 0,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, ipv6: off }\n", &sp, msg, sizeof msg) < 0);
    m = out_by_name(&sp, "cf.1");
    check("  у членов off", OUT_V6_OFF, m ? (long)m->ipv6 : -1);
    check("warp: ipv6: routed — отказ", 1,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, ipv6: routed }\n", &sp, msg, sizeof msg) < 0);
    check("warp: masque — следующий этап, отказ", 1,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, transport: masque }\n", &sp, msg, sizeof msg) < 0);
    check("warp: страна и в countries, и в exclude_countries — отказ", 1,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, countries: [RU], exclude_countries: [ru] }\n", &sp, msg, sizeof msg) < 0);
    check("warp: count 0 — отказ", 1,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, count: 0 }\n", &sp, msg, sizeof msg) < 0);
    check("warp: чужой ключ — отказ", 1,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, members: [a] }\n", &sp, msg, sizeof msg) < 0);
    check("warp: exclude_countries: [] — исключений нет, задан явно", 0,
          spec_load("version: 2\noutputs:\n  cf: { kind: warp, exclude_countries: [] }\n", &sp, msg, sizeof msg) < 0);
    g = out_by_name(&sp, "cf");
    check("  xcc_set", 1, g && g->grp.warp.xcc_set);
    check("  xcc_n", 0, g ? (long)g->grp.warp.xcc_n : -1);
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
    check("json: true — текстом", 0, wb_json_get(d, "result.warp_enabled", o, sizeof o));
    check_s("  значение", "true", o);
    check("json: число — текстом", 0, wb_json_get(d, "result.n", o, sizeof o));
    check_s("  значение", "-12", o);
    check("json: нет пути", -1, wb_json_get(d, "result.nope", o, sizeof o));
    check("json: за концом массива", -1, wb_json_get(d, "result.x.5", o, sizeof o));
    check("json: объект — не значение", -1, wb_json_get(d, "result.config", o, sizeof o));
    check("json: не уместилось", -1, wb_json_get(d, "result.config.interface.addresses.v4", o, 4));
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
    t_spec();
    t_json();
    t_conf();
    printf("warpmatch: %d passed, %d failed\n", passes, fails);
    return fails ? 1 : 0;
}
