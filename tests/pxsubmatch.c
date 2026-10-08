/* Разбор ссылок и подписки steer-proxy (src/proto/proxy/pxsub.c) — без сети и криптографии, как
 * submatch для vless: чужой текст из интернета проверяется текстом. Вывод ключей и провод (нужна
 * криптобиблиотека) — в tests/pxmatch.c (`make ext-test`). */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include "proxy.h"
#include "unit.h"

static void test_parse(void) {
    struct px_node n;
    check("trojan ссылка", 0, px_parse_url("trojan://pass@h.example:443?security=tls&sni=s.example", &n, 0));
    check_str("trojan protocol", "trojan", px_proto_name(n.proto));
    check_str("trojan password", "pass", n.pass);
    check_str("trojan security", "tls", n.vn.security);
    check("trojan без TLS — негоден", 1, px_parse_url("trojan://pass@h.example:443?security=none", &n, 0));
    check("trojan без пароля — негоден", 1, px_parse_url("trojan://@h.example:443?security=tls&sni=s", &n, 0));

    check("ss SIP002 method:pass", 0, px_parse_url("ss://aes-256-gcm:secret@h.example:8388", &n, 0));
    check("ss method aes-256-gcm", (long)SS_AES256_GCM, (long)n.ss_method);
    check_str("ss pass", "secret", n.pass);
    check_str("ss тип tcp", "tcp", n.vn.type);
    check("ss неизвестный метод — негоден", 1, px_parse_url("ss://rc4-md5:p@h.example:1", &n, 0));
    check_str("ss неизвестный метод — причина названа", "метод rc4-md5 не поддержан", n.skip_reason);
    check("ss plugin= отвергается", 1, px_parse_url("ss://aes-128-gcm:p@h.example:1?plugin=obfs", &n, 0));
    check_str("ss plugin= — причина названа", "plugin= не поддержан", n.skip_reason);
    check("ss base64 userinfo", 0, px_parse_url("ss://YWVzLTEyOC1nY206cGFzcw==@h.example:1234", &n, 0));
    check("ss base64 method", (long)SS_AES128_GCM, (long)n.ss_method);
    /* Старая форма ss://base64(метод:пароль@хост:порт): «@» в пароле законен, хост — после
     * ПОСЛЕДНЕГО «@». */
    check("ss старая форма, @ в пароле", 0, px_parse_url("ss://YWVzLTEyOC1nY206cEBzc0BoLmV4YW1wbGU6ODM4OA==#n", &n, 0));
    check_str("ss старая форма: пароль с @", "p@ss", n.pass);
    check_str("ss старая форма: хост", "h.example", n.vn.host);
    check("ss 2022 PSK не той длины — негоден", 1,
          px_parse_url("ss://2022-blake3-aes-128-gcm:c2hvcnQ=@h.example:1", &n, 0));

    check("socks5 user:pass", 0, px_parse_url("socks5://u:p@h.example:1080", &n, 0));
    check("socks5 ver", 5, n.socks_ver);
    check_str("socks user", "u", n.user);
    check("socks без схемы socks:// = socks5", 0, px_parse_url("socks://h.example:1080", &n, 0));
    check("socks:// ver", 5, n.socks_ver);
    check("socks4", 0, px_parse_url("socks4://h.example:1080", &n, 0));
    check("socks4 ver", 4, n.socks_ver);
    check("socks4a", 0, px_parse_url("socks4a://h.example:1080", &n, 0));
    check("socks4 с паролем — негоден", 1, px_parse_url("socks4://u:p@h.example:1080", &n, 0));

    check("http basic", 0, px_parse_url("http://u:p@h.example:3128", &n, 0));
    check_str("http proto", "http", px_proto_name(n.proto));
    check_str("http security none", "none", n.vn.security);
    check("https → tls", 0, px_parse_url("https://u:p@h.example:443?sni=s", &n, 0));

    const char *vm = "vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6ImguZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidGxzIjoidGxzIiwic25pIjoicy5leGFtcGxlIn0=";
    check("vmess v2rayN", 0, px_parse_url(vm, &n, 0));
    check_str("vmess proto", "vmess", px_proto_name(n.proto));
    check("vmess sec auto", (long)VMESS_AUTO, (long)n.vmess_sec);
    check_str("vmess tls", "tls", n.vn.security);

    /* tcp с HTTP-маскировкой (type=http у v2rayN) — заголовка мы не шлём: узел непригоден с
     * причиной, а не идёт голым tcp на сервер, который ждёт HTTP-запрос. */
    /* Имя vmess в записи \u с суррогатной парой (v2rayN, панели на Python): ⚡ 📱 Германия целиком. */
    check("vmess ps с \\u: узел", 0, px_parse_url("vmess://eyJ2IjoiMiIsInBzIjoiXHUyNmExIFx1ZDgzZFx1ZGNmMSBcdTA0MTNcdTA0MzVcdTA0NDBcdTA0M2NcdTA0MzBcdTA0M2RcdTA0MzhcdTA0NGYiLCJhZGQiOiJoLmV4YW1wbGUiLCJwb3J0IjoiNDQzIiwiaWQiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEiLCJhaWQiOiIwIiwic2N5IjoiYXV0byIsIm5ldCI6InRjcCIsInRscyI6InRscyIsInNuaSI6InMuZXhhbXBsZSJ9", &n, 0));
    check_str("vmess ps с \\u: имя цело", "\xE2\x9A\xA1 \xF0\x9F\x93\xB1 \xD0\x93\xD0\xB5\xD1\x80\xD0\xBC\xD0\xB0\xD0\xBD\xD0\xB8\xD1\x8F", n.name);
    check("trojan: эмодзи в имени", 0, px_parse_url("trojan://pass@h.example:443?security=tls&sni=s.example#%E2%9A%A1%20%F0%9F%93%B1%20%D0%93", &n, 0));
    check_str("trojan: имя цело", "\xE2\x9A\xA1 \xF0\x9F\x93\xB1 \xD0\x93", n.name);
    check("vmess tcp type=http — негоден", 1, px_parse_url("vmess://eyJ2IjoiMiIsInBzIjoibiIsImFkZCI6ImguZXhhbXBsZSIsInBvcnQiOiI0NDMiLCJpZCI6IjAwMDAwMDAwLTAwMDAtMDAwMC0wMDAwLTAwMDAwMDAwMDAwMSIsImFpZCI6IjAiLCJzY3kiOiJhdXRvIiwibmV0IjoidGNwIiwidHlwZSI6Imh0dHAiLCJob3N0IjoieC5leGFtcGxlIiwicGF0aCI6Ii8iLCJ0bHMiOiIifQ==", &n, 0));
    check_str("vmess tcp type=http — причина", "tcp headerType=http не поддержан", n.skip_reason);

    check("want фильтр: ss при want=vmess — не наша", -1, px_parse_url("ss://aes-128-gcm:p@h.example:1", &n, PX_VMESS));
    check("не наша схема", -1, px_parse_url("wireguard://x@h:1", &n, 0));
    check("адрес «отвечать некому»", 1, px_parse_url("ss://aes-128-gcm:p@127.0.0.1:1", &n, 0));
}

static void test_sub(void) {
    struct px_sub_stats st;
    struct px_node out[16];
    const char *sub =
        "trojan://p@h1.example:443?security=tls&sni=a\n"
        "vless://x@h2:443\n"
        "ss://aes-128-gcm:q@h3.example:1234\n"
        "socks5://u:pw@h4.example:1080\n"
        "hysteria2://pw@h5:443\n";
    size_t got = px_parse_sub(sub, out, 16, 0, &st);
    check("подписка: пригодных 3 (trojan, ss, socks)", 3, (long)got);
    check("подписка: чужих 2 (vless, hysteria2)", 2, (long)st.foreign);

    /* want=shadowsocks — только ss. */
    got = px_parse_sub(sub, out, 16, PX_SS, &st);
    check("подписка want=ss: один узел", 1, (long)got);

    /* base64 списка ссылок. */
    char b64[512];
    const char *one = "trojan://p@h.example:443?security=tls&sni=a";
    /* простое ручное base64 здесь не нужно — px_sub_text разворачивает; проверим список как есть */
    (void)b64; (void)one;

    /* Строка длиннее прежнего буфера разбора (8192): узел обязан разобраться, а не уйти в «чужие»
     * по неинициализированному буферу. Длину даёт имя узла — у живых подписок оно бывает длинным. */
    static char longsub[20000];
    size_t o = (size_t)snprintf(longsub, sizeof longsub, "trojan://p@h.example:443?security=tls&sni=a#");
    while (o < 12000) longsub[o++] = 'n';
    snprintf(longsub + o, sizeof longsub - o, "\nss://aes-128-gcm:q@h3.example:1234\n");
    got = px_parse_sub(longsub, out, 16, 0, &st);
    check("подписка: строка длиннее 8192 — узел разобран", 2, (long)got);
    check("подписка: длинная строка не чужая", 0, (long)st.foreign);

    /* Причины пропуска доходят до skipped_reasons подписки непустыми: в собранных ранее пакетах
     * у socks4 с паролем и ss с plugin= было "reason":"" (копирование skip_reason в самого себя). */
    const char *bad =
        "socks4://u:p@h1.example:1080#s4\n"
        "ss://aes-128-gcm:p@h2.example:1?plugin=obfs#pl\n";
    got = px_parse_sub(bad, out, 16, 0, &st);
    check("подписка с негодными: пригодных 0", 0, (long)got);
    check("  пропущено 2 двумя причинами", 22, (long)(st.skipped * 10 + st.reasons_n));
    check_str("  причина socks4 названа", "socks4 не знает пароля", st.reasons[0].reason);
    check_str("  и пример — имя узла", "s4", st.reasons[0].example);
    check_str("  причина ss plugin= названа", "plugin= не поддержан", st.reasons[1].reason);
}

/* allowInsecure у узлов с TLS: подписка сама проверку сертификата не выключает (как у vless, sublink.c)
 * — узел пригоден только при insecure (ключ выхода либо `--insecure` у перечня и проверки по файлу), и
 * номера узлов с ним и без него различаются ровно на такие узлы. */
static void test_insecure(void) {
    struct px_node n;
    vless_set_insecure(0);
    check("https с allowInsecure без insecure — негоден", 1,
          px_parse_url("https://u:p@h.example:443?sni=s.example&allowInsecure=1", &n, 0));
    check_str("  причина названа", "allowInsecure: включите insecure у выхода явно", n.skip_reason);
    check("trojan с allowInsecure без insecure — негоден", 1,
          px_parse_url("trojan://p@h.example:443?security=tls&sni=s&allowInsecure=1", &n, 0));
    vless_set_insecure(1);
    check("https с allowInsecure при insecure — пригоден", 0,
          px_parse_url("https://u:p@h.example:443?sni=s.example&allowInsecure=1", &n, 0));
    check("  и помечен: подписка просит, сертификат не проверяется", 11,
          (long)(n.vn.allow_insecure * 10 + n.vn.insecure));
    check("trojan с allowInsecure при insecure — пригоден", 0,
          px_parse_url("trojan://p@h.example:443?security=tls&sni=s&allowInsecure=1", &n, 0));

    struct px_sub_stats st;
    struct px_node out[8];
    const char *sub =
        "trojan://p@h1.example:443?security=tls&sni=a#t1\n"
        "trojan://p@h2.example:443?security=tls&sni=a&allowInsecure=1#t2\n"
        "ss://aes-128-gcm:q@h3.example:1234#s3\n";
    vless_set_insecure(0);
    size_t got = px_parse_sub(sub, out, 8, 0, &st);
    check("без insecure: узел с allowInsecure пропущен, s3 — номер 1", 21,
          (long)(got * 10 + (got == 2 && !strcmp(out[1].name, "s3"))));
    /* Причина у подписки — целиком (поле причины было 64 байта при 96 у узла: «…у в» и обрубок буквы). */
    check_str("  причина в skipped_reasons — целиком", "allowInsecure: включите insecure у выхода явно",
              st.reasons[0].reason);
    vless_set_insecure(1);
    got = px_parse_sub(sub, out, 8, 0, &st);
    check("с insecure: все три, t2 — номер 1, s3 — номер 2", 3, (long)got);
    check_str("  номер 1 — t2", "t2", out[1].name);
    check_str("  номер 2 — s3", "s3", out[2].name);
    vless_set_insecure(0);
}

int main(void) {
    test_parse();
    test_sub();
    test_insecure();
    return unit_done("pxsubmatch");
}
