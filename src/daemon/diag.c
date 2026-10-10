#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <ifaddrs.h>
#include <net/if.h>

#include "spec.h"
#include "awg.h"
#include "hwid.h"
#include "obfs.h"
#include "cli.h"
#include "srs.h"
#include "ctl.h"
#include "daemon.h"
#include "groups.h"
#include "generate.h"
#include "nftquery.h"
#include "nftcompat.h"
#include "procscan.h"
#include "rtnl.h"

/* ---- explain -------------------------------------------------------------- */
/* An address from the command line ends up in an nft invocation, so it is checked
 * against a whitelist first. The earlier version interpolated it into system(),
 * which made `steer explain '$(...)'` a command-injection hole; there is no shell
 * here now, and this refuses anything that is not address-shaped regardless. */
int addr_ok(const char *a) {
    /* IPv6 (1.9): адрес или префикс, проверенный разбором, а не набором знаков — у IPv6 в
     * набор входят буквы a-f, и «beef» без двоеточия адресом не считается. */
    if (strchr(a, ':')) {
        char buf[64];
        size_t n = strlen(a);
        if (n >= sizeof(buf)) return 0;
        memcpy(buf, a, n + 1);
        char *sl = strchr(buf, '/');
        if (sl) {
            *sl = '\0';
            char *end = NULL;
            long l = strtol(sl + 1, &end, 10);
            if (!sl[1] || *end || l < 0 || l > 128) return 0;
        }
        struct in6_addr x;
        return inet_pton(AF_INET6, buf, &x) == 1;
    }
    size_t n = 0;
    for (const char *p = a; *p; p++, n++) {
        if (!((*p >= '0' && *p <= '9') || *p == '.' || *p == '/')) return 0;
        if (n > 18) return 0;
    }
    return n > 0;
}

/* ---- diag --------------------------------------------------------------------
 *
 * Один вопрос: работает ли всё. Спрашивается у ЯДРА и у живых процессов, а не у спеки —
 * спека описывает намерение, и совпадение с ней ничего не доказывает. Каждая проверка
 * отвечает своей строкой: что смотрели, каков итог и что делать, если плохо.
 *
 * Зачем отдельная команда, если есть status. status отвечает «что применено», и по нему
 * человек, у которого сайт не открывается, вынужден сам догадываться, какие из полей
 * важны. Здесь набор проверок назван прямо, вместе с причиной, и в нём есть то, чего в
 * status нет вовсе: пустой набор при непустом списке, отсутствующий редирект DNS,
 * незапущенный резолвер и две ловушки, которые движок не решает, но обязан назвать (DoH и
 * IPv6). Ровно эти два случая выглядят как «список не работает» при исправной настройке.
 *
 * Итог у проверки один из четырёх:
 *
 *   ok   — проверено и хорошо;
 *   note — совет, а не находка: работает и будет работать, но человеку полезно знать;
 *   warn — работает, но есть чем объяснить будущую жалобу;
 *   fail — сломано, трафик идёт не туда.
 *
 * `note` появился потому, что без него советы считались предупреждениями. Совет «браузер с DoH
 * резолвит сам» верен ВСЕГДА, когда есть доменные правила: он не про эту установку, а про
 * устройство мира. Считая его предупреждением, движок делал итог «работает, но есть о чём
 * знать» постоянным, интерфейс красил состояние тревожным цветом — и человек видел тревогу на
 * исправном роутере. Постоянная метка учит не смотреть на метки вовсе.
 *
 * Поэтому в счётчики note не идёт: он не отвечает на «всё ли в порядке», он отвечает на «что
 * ещё стоит знать».
 */
/* Состояние одного отчёта. Сбрасывается в начале diag_emit: демон собирает отчёт в своём
 * процессе раз за разом, и счётчики прошлого ответа не должны доехать до следующего. Поток —
 * тоже здесь, а не параметром: проверки видов (kind_ops.diag) получают только эту функцию. */
static int g_diag_first = 1;
static int g_diag_warn, g_diag_fail;
static FILE *g_diag_out;

static void diag(const char *id, const char *verdict, const char *what, const char *why) {
    /* note намеренно не считается: см. пояснение выше. */
    if (!strcmp(verdict, "warn")) g_diag_warn++;
    if (!strcmp(verdict, "fail")) g_diag_fail++;
    fprintf(g_diag_out, "%s{\"id\":\"%s\",\"verdict\":\"%s\",\"what\":\"%s\",\"why\":\"%s\"}",
            g_diag_first ? "" : ",", id, verdict, what, why);
    g_diag_first = 0;
}



/* ---- публичные резолверы внутри адресного списка ----------------------------
 *
 * Списки издателя собираются по номеру автономной системы целиком, поэтому адрес
 * публичного резолвера приезжает в категорию вместе со всем остальным, что живёт в той же
 * AS: 8.8.8.0/24 и 8.8.4.0/24 входят в «YouTube» и «Google» (AS15169), 1.1.1.0/24 — в
 * «Cloudflare» (AS13335). Человек выбирал видеохостинг, а получил заодно резолвер, и ни
 * одна сторона ему об этом не говорит.
 *
 * Таблица короткая нарочно: это не «все резолверы мира», а те, которые прописывают руками
 * и на которые поэтому реально ссылается настройка клиента. Резолвер, о котором клиент не
 * знает, в туннеле никому не мешает. */
static const struct { const char *addr; const char *who; } RESOLVERS[] = {
    { "8.8.8.8",         "Google Public DNS" },
    { "8.8.4.4",         "Google Public DNS" },
    { "1.1.1.1",         "Cloudflare DNS" },
    { "1.0.0.1",         "Cloudflare DNS" },
    { "9.9.9.9",         "Quad9" },
    { "149.112.112.112", "Quad9" },
    { "94.140.14.14",    "AdGuard DNS" },
    { "94.140.15.15",    "AdGuard DNS" },
    { "77.88.8.8",       "Яндекс DNS" },
    { "77.88.8.1",       "Яндекс DNS" },
    { "208.67.222.222",  "OpenDNS" },
    { "208.67.220.220",  "OpenDNS" },
};




/* Первый публичный резолвер, накрытый префиксом из файла списка. Возвращает его имя (и
 * пишет в found сам префикс) либо NULL.
 *
 * Один проход по файлу на все резолверы, а не проход на каждого: в списке категории бывает
 * семнадцать тысяч строк, и двенадцать проходов по нему — это двенадцать чтений с флешки
 * роутера ради одного и того же ответа. */
static const char *list_finds_resolver(const char *path, char *found, size_t found_sz) {
    FILE *in = fopen(path, "r");
    if (!in) return NULL;                 /* про нечитаемый список говорит своя проверка */
    /* Двенадцать адресов резолверов — константы времени компиляции, и разбирать их заново
     * на КАЖДОЙ строке списка значило звать sscanf тринадцать раз вместо одного. На списке
     * категории в семнадцать тысяч строк это двести тысяч лишних разборов одного и того же
     * текста, а на национальном блок-листе — миллионы; diag человек нажимает и ждёт.
     * Замер на 500 000 строк: 0,83 с против 0,09 с. */
    static uint32_t r_addr[sizeof(RESOLVERS) / sizeof(RESOLVERS[0])];
    static int r_ok[sizeof(RESOLVERS) / sizeof(RESOLVERS[0])];
    static int r_ready;
    if (!r_ready) {
        for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
            uint32_t m32;
            r_ok[i] = parse_prefix(RESOLVERS[i].addr, &r_addr[i], &m32);
        }
        r_ready = 1;
    }
    char line[512];
    const char *who = NULL;
    while (!who && fgets(line, sizeof(line), in)) {
        char *nl = strpbrk(line, "\r\n");
        if (nl) *nl = '\0';
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p || *p == '#' || *p == ';') continue;
        uint32_t net, mask;
        if (!parse_prefix(p, &net, &mask)) continue;
        for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
            if (!r_ok[i]) continue;
            if ((r_addr[i] & mask) == net) {
                snprintf(found, found_sz, "%.40s", p);   /* префикс короче, точность — от -Wformat-truncation */
                who = RESOLVERS[i].who;
                break;
            }
        }
    }
    fclose(in);
    return who;
}

/* То же для набора sing-box: его подсети назначения (клаузы, попавшие в группу), потоком. */
struct srs_resolver { const char *who; char *found; size_t found_sz; };

static int srs_resolver_cb(void *ctx, const struct srs_elem *el) {
    struct srs_resolver *r = ctx;
    if (el->kind != SRS_EL_CIDR || el->family != 4 || el->excl) return 0;
    uint32_t net = ((uint32_t)el->addr[0] << 24) | ((uint32_t)el->addr[1] << 16) |
                   ((uint32_t)el->addr[2] << 8) | el->addr[3];
    uint32_t mask = el->plen <= 0 ? 0 : 0xFFFFFFFFu << (32 - el->plen);
    for (size_t i = 0; i < sizeof(RESOLVERS) / sizeof(RESOLVERS[0]); i++) {
        uint32_t a, m32;
        if (!parse_prefix(RESOLVERS[i].addr, &a, &m32)) continue;
        if ((a & mask) != net) continue;
        snprintf(r->found, r->found_sz, "%u.%u.%u.%u/%d", el->addr[0], el->addr[1],
                 el->addr[2], el->addr[3], el->plen);
        r->who = RESOLVERS[i].who;
        return 1;                           /* нашли — дальше не читаем */
    }
    return 0;
}

static const char *srs_finds_resolver(const struct srs_psel *ps, char *found, size_t found_sz) {
    struct srs_resolver r = { NULL, found, found_sz };
    struct err e = {0};
    srs_walk(ps->set, SRS_EL_CIDR, ps->sel, srs_resolver_cb, &r, &e);
    return r.who;
}

/* Пропускает ли мост кадры через ip-хуки netfilter: 1 — да, 0 — нет, -1 — не знаем.
 *
 * Файл существует ровно тогда, когда загружен модуль br_netfilter: sysctl-и регистрирует он,
 * а не сам мост. Поэтому «файла нет» — это полноценный ответ «мост через netfilter не ходит»,
 * а не отсутствие данных. Не знаем мы только одно: когда в файле лежит не 0 и не 1 — такого
 * не бывает, но приговор наугад хуже молчания, и различать эти случаи надо.
 *
 * Путь — швом, по той же причине, что каталог состояния (--state-dir) у остальной части
 * движка: загрузить модуль в контейнере стенда нельзя, а приговор обязан проверяться так же,
 * как все прочие. Имя переменной STEER_BRIDGE_NF, читается один раз. */
/* Только на платформе с мостом раздачи (plat()->lan_bridge) — см. проверку 3b в cmd_diag. */
static int bridge_nf_on(void) {
    const char *path = getenv("STEER_BRIDGE_NF");
    if (!path || !*path) path = "/proc/sys/net/bridge/bridge-nf-call-iptables";
    FILE *f = fopen(path, "r");
    if (!f) return 0;                     /* модуля нет — значит и хождения нет */
    int c = fgetc(f);
    fclose(f);
    if (c == '0') return 0;
    if (c == '1') return 1;
    return -1;
}

/* ---- IPv6 от хоста: чего не хватает (шаг 8 выпуска 1.10) ------------------------------------
 *
 * Раздачу IPv6 в LAN настраивает человек (ip6prefix у интерфейса туннеля, ip6assign у LAN,
 * ra_default в odhcpd), и steer её не пишет (раздел 2 docs/architecture.md, «чужие пакеты —
 * настройка человека»). Поэтому diag говорит, какой строки не хватает, — по ядру (адреса, MTU) и
 * по файлам настройки, которые он только ЧИТАЕТ: /etc/config/network и /etc/config/dhcp (формат
 * UCI — строки `config`, `option`, `list`). Каталог — швом STEER_UCI_DIR (стенды; на телефоне этих
 * файлов нет, и проверки молчат).
 *
 * Проба — один эхо-запрос ICMPv6 через выход (SO_MARK выхода, у routed — с адреса LAN из префикса)
 * к STEER_V6PROBE_TARGET (умолчание — 2606:4700:4700::1111, anycast DNS Cloudflare, отвечает на
 * эхо). Ждёт не дольше 800 мс: diag отвечает и из процесса демона, и цикл демона на это время
 * стоит — это цена одного ответа, который иначе не узнать: сервер не пускает источник молча. */

static const char *uci_dir(void) {
    const char *d = getenv("STEER_UCI_DIR");
    return d && *d ? d : "/etc/config";
}

/* Слово UCI без кавычек: 'x', "x" или x. */
static void uci_word(const char **pp, char *out, size_t n) {
    const char *p = *pp;
    while (*p == ' ' || *p == '\t') p++;
    size_t k = 0;
    char q = (*p == '\'' || *p == '"') ? *p++ : 0;
    while (*p && (q ? *p != q : (*p != ' ' && *p != '\t' && *p != '\n' && *p != '\r'))) {
        if (k + 1 < n) out[k++] = *p;
        p++;
    }
    if (q && *p == q) p++;
    out[k] = '\0';
    *pp = p;
}

/* В файле UCI cfg — секция типа type, у которой option или list key равен val; её option want —
 * в out (пусто — нет такого), имя секции — в sec. 1 — секция есть; 0 — нет; -1 — файла нет. */
static int uci_find(const char *cfg, const char *type, const char *key, const char *val,
                    const char *want, char *out, size_t on, char *sec, size_t sn) {
    char path[256];
    snprintf(path, sizeof(path), "%s/%s", uci_dir(), cfg);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512], cur_type[64] = "", cur_name[64] = "", cur_want[128] = "";
    int match = 0, found = 0;
    out[0] = '\0';
    if (sec && sn) sec[0] = '\0';
    for (int eof = 0; !found && !eof; ) {
        eof = !fgets(line, sizeof(line), f);
        const char *p = line;
        char w[128];
        if (!eof) {
            while (*p == ' ' || *p == '\t') p++;
            uci_word(&p, w, sizeof(w));
        }
        if (eof || !strcmp(w, "config")) {
            if (match && !strcmp(cur_type, type)) {
                snprintf(out, on, "%s", cur_want);
                if (sec && sn) snprintf(sec, sn, "%s", cur_name);
                found = 1;
                break;
            }
            if (eof) break;
            uci_word(&p, cur_type, sizeof(cur_type));
            uci_word(&p, cur_name, sizeof(cur_name));
            cur_want[0] = '\0';
            match = 0;
            continue;
        }
        if (strcmp(w, "option") && strcmp(w, "list")) continue;
        char k[64], v[128];
        uci_word(&p, k, sizeof(k));
        uci_word(&p, v, sizeof(v));
        if (!strcmp(k, key) && !strcmp(v, val)) match = 1;
        if (!strcmp(k, want)) snprintf(cur_want, sizeof(cur_want), "%s", v);
    }
    fclose(f);
    return found;
}

/* Адреса IPv6 устройств раздачи: глобальные (не ULA) и ULA — сколько каких, и первый глобальный
 * внутри префикса p (если p задан) — в in_p.
 *
 * УСТАРЕВШИЕ АДРЕСА НЕ В СЧЁТ (проверка на QEMU-роутере 4192267). Человек снял ip6prefix, netifd
 * снял префикс, а адрес LAN из него остаётся на br-lan устаревшим (preferred_lft 0, `deprecated`
 * у `ip -6 addr`), пока не истечёт срок действия. Считался он глобальным адресом, и diag молчал
 * про ra_default («у LAN только ULA»), хотя клиентам этот адрес уже не раздаётся и маршрута по
 * умолчанию в RA без него нет. Поэтому адреса берутся rtnetlink (у getifaddrs признака нет), и
 * устаревший не считается ни глобальным, ни адресом из префикса хоста: с него ядро новых
 * соединений не заводит, и проба с него сказала бы о префиксе, которого уже нет. Прочитать не
 * вышло — прежний getifaddrs, без признака. */
struct lan6 { int gua, ula; int in_p; uint8_t a_in_p[16]; };

static void lan6_note(struct lan6 *r, const struct v6pfx *p, const uint8_t *x) {
    if ((x[0] == 0xfe && (x[1] & 0xc0) == 0x80) || x[0] == 0xff) return;
    if ((x[0] & 0xfe) == 0xfc) r->ula++;
    else r->gua++;
    if (p && p->len && !r->in_p && v6pfx_has(p, x)) {
        r->in_p = 1;
        memcpy(r->a_in_p, x, 16);
    }
}

static struct lan6 lan6_scan(const struct spec *sp, const struct v6pfx *p) {
    struct lan6 r;
    memset(&r, 0, sizeof(r));
    static struct rtnl_addr6 av[256];
    int an = rtnl_addrs6(av, sizeof(av) / sizeof(av[0]));
    if (an >= 0) {
        int idx[8];
        size_t ni = 0;
        for (size_t i = 0; i < sp->lan_dev_n && ni < 8; i++)
            if ((idx[ni] = (int)if_nametoindex(sp->lan_dev[i])) > 0) ni++;
        for (int k = 0; k < an; k++) {
            int ours = 0;
            for (size_t i = 0; i < ni && !ours; i++) ours = av[k].ifindex == idx[i];
            if (ours && !(av[k].flags & IFA_F_DEPRECATED)) lan6_note(&r, p, av[k].a);
        }
        return r;
    }
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return r;
    for (struct ifaddrs *a = ifa; a; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET6 || !a->ifa_name) continue;
        int ours = 0;
        for (size_t i = 0; i < sp->lan_dev_n && !ours; i++) ours = !strcmp(a->ifa_name, sp->lan_dev[i]);
        if (ours) lan6_note(&r, p, ((const struct sockaddr_in6 *)a->ifa_addr)->sin6_addr.s6_addr);
    }
    freeifaddrs(ifa);
    return r;
}

/* Глобальный адрес IPv6 на самом устройстве выхода (не fe80::). */
static int dev_has_v6(const char *dev) {
    struct ifaddrs *ifa = NULL;
    if (getifaddrs(&ifa) != 0) return 0;
    int yes = 0;
    for (struct ifaddrs *a = ifa; a && !yes; a = a->ifa_next) {
        if (!a->ifa_addr || a->ifa_addr->sa_family != AF_INET6 || !a->ifa_name) continue;
        const struct in6_addr *x = &((const struct sockaddr_in6 *)a->ifa_addr)->sin6_addr;
        if (!strcmp(a->ifa_name, dev) && !IN6_IS_ADDR_LINKLOCAL(x)) yes = 1;
    }
    freeifaddrs(ifa);
    return yes;
}

static long dev_mtu(const char *dev) {
    char path[128];
    snprintf(path, sizeof(path), "/sys/class/net/%.63s/mtu", dev);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    long m = -1;
    if (fscanf(f, "%ld", &m) != 1) m = -1;
    fclose(f);
    return m;
}

/* Эхо ICMPv6 через выход: 1 — ответ пришёл; 0 — ответа нет за ms; -1 — отправить не вышло (*err —
 * errno: у пира WireGuard в AllowedIPs нет ::/0 — ENOKEY, маршрута нет — ENETUNREACH…). */
static int v6_probe(const uint8_t *src, uint32_t mark, int ms, int *err) {
    const char *t = getenv("STEER_V6PROBE_TARGET");
    if (!t || !*t) t = "2606:4700:4700::1111";
    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, t, &dst.sin6_addr) != 1) { *err = EINVAL; return -1; }
    int fd = socket(AF_INET6, SOCK_RAW | SOCK_CLOEXEC, IPPROTO_ICMPV6);
    if (fd < 0) { *err = errno; return -1; }
    setsockopt(fd, SOL_SOCKET, SO_MARK, &mark, sizeof(mark));
    if (src) {
        struct sockaddr_in6 s;
        memset(&s, 0, sizeof(s));
        s.sin6_family = AF_INET6;
        memcpy(&s.sin6_addr, src, 16);
        if (bind(fd, (struct sockaddr *)&s, sizeof(s)) != 0) { *err = errno; close(fd); return -1; }
    }
    uint8_t req[16] = { 128, 0, 0, 0, 0x57, 0x36, 0, 1, 's', 't', 'e', 'e', 'r', '6', 0, 0 };
    if (sendto(fd, req, sizeof(req), 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        *err = errno;
        close(fd);
        return -1;
    }
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (;;) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long left = ms - ((now.tv_sec - t0.tv_sec) * 1000 + (now.tv_nsec - t0.tv_nsec) / 1000000);
        if (left <= 0) break;
        struct pollfd pf = { fd, POLLIN, 0 };
        if (poll(&pf, 1, (int)left) <= 0) break;
        uint8_t buf[256];
        struct sockaddr_in6 from;
        socklen_t fl = sizeof(from);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fl);
        if (n < 8) continue;
        /* Ответ на наш запрос; ошибка ICMPv6 о нём (unreachable, prohibited) — тоже «нет». */
        if (buf[0] == 129 && buf[4] == 0x57 && buf[5] == 0x36 &&
            !memcmp(&from.sin6_addr, &dst.sin6_addr, 16)) {
            close(fd);
            return 1;
        }
        if (buf[0] < 128 && n >= 8 + 40 + 8 && buf[8 + 40] == 128 && buf[8 + 40 + 4] == 0x57) {
            *err = buf[0] == 1 && buf[1] == 1 ? EACCES : EHOSTUNREACH;
            close(fd);
            return -1;
        }
    }
    close(fd);
    return 0;
}

/* Имя интерфейса netifd по устройству раздачи (секция interface с option device) — для текста и
 * для поиска его секции dhcp. */
static int lan_ifname(const struct spec *sp, char *name, size_t n, char *assign, size_t an) {
    for (size_t i = 0; i < sp->lan_dev_n; i++) {
        int r = uci_find("network", "interface", "device", sp->lan_dev[i], "ip6assign", assign, an,
                         name, n);
        if (r == 1) return 1;
        if (r < 0) return -1;
    }
    return 0;
}

/* Раздаёт ли netifd префикс: нуль-маршрут `unreachable P` в main, которым он объявляет каждый
 * раздаваемый префикс (приметы и доводы — у v6donor_derive в failover.c): не длиннее /64, не ULA,
 * не префикс провайдера (маршрут `default from P` через чужое устройство). p задан — только
 * накрывающий его или лежащий в нём. В отличие от v6donor_derive адрес LAN из префикса здесь не
 * нужен: вопрос как раз о том, почему его нет. 1 — есть, 0 — нет, -1 — маршруты не прочитать. */
static int v6_announced(const struct output *o, const struct v6pfx *p) {
    static struct rtnl_route6 rt[256];
    int n = rtnl_main6_routes(rt, sizeof(rt) / sizeof(rt[0]));
    if (n < 0) return -1;
    int donor_if = o->device[0] ? (int)if_nametoindex(o->device) : 0;
    for (int i = 0; i < n; i++) {
        if (rt[i].type != RTN_UNREACHABLE || !rt[i].dst_len || rt[i].dst_len > 64) continue;
        if ((rt[i].dst[0] & 0xfe) == 0xfc) continue;
        struct v6pfx c;
        memcpy(c.a, rt[i].dst, 16);
        c.len = rt[i].dst_len;
        if (p && p->len && !v6pfx_has(p, c.a) && !v6pfx_has(&c, p->a)) continue;
        int isp = 0;
        for (int j = 0; j < n && !isp; j++) {
            if (!rt[j].src_len || rt[j].dst_len) continue;
            struct v6pfx s;
            memcpy(s.a, rt[j].src, 16);
            s.len = rt[j].src_len;
            if ((v6pfx_has(&s, c.a) || v6pfx_has(&c, s.a)) && rt[j].oif && rt[j].oif != donor_if)
                isp = 1;
        }
        if (!isp) return 1;
    }
    return 0;
}

static void diag_v6_host(const struct spec *sp, const struct groups *gr) {
    char what[200], why[400];
    int ra_said = 0;
    for (size_t i = 0; i < sp->out_n; i++) {
        const struct output *o = &sp->out[i];
        enum out_ipv6 m = out_ipv6_mode(o);
        if (m != OUT_V6_ROUTED && m != OUT_V6_NAT) continue;
        if (!o->device[0]) continue;
        char devpath[128];
        snprintf(devpath, sizeof(devpath), "/sys/class/net/%.63s", o->device);
        if (access(devpath, F_OK) != 0) continue;   /* устройства нет — говорит проверка output */
        /* MTU ниже 1280: ядро выключает IPv6 на устройстве (минимум IPv6 — RFC 8200), и маршрут
         * IPv6 в него не встаёт. У WireGuard MTU по умолчанию 1420, но его снижают под обёртки. */
        long mtu = dev_mtu(o->device);
        if (mtu > 0 && mtu < 1280) {
            snprintf(what, sizeof(what), "выход %.40s: у %.24s MTU %ld — IPv6 на нём не работает",
                     o->name, o->device, mtu);
            diag("ipv6_host", "fail", what, "IPv6 требует MTU не меньше 1280 — поднимите MTU интерфейса");
            continue;
        }
        char lname[64] = "", assign[32] = "";
        int have_uci = lan_ifname(sp, lname, sizeof(lname), assign, sizeof(assign)) >= 0;
        struct v6pfx p = o->v6pfx;
        int derived = 0;
        if (m == OUT_V6_ROUTED && !o->v6pfx_given) derived = v6donor_derive(sp, o, &p);
        if (m == OUT_V6_ROUTED && !o->v6pfx_given && derived != 1) p.len = 0;
        struct lan6 l = lan6_scan(sp, &p);
        const uint8_t *probe_src = NULL;
        if (m == OUT_V6_ROUTED) {
            char ps[64];
            v6pfx_str(&p, ps, sizeof(ps));
            if (!p.len && derived < 0) {
                snprintf(what, sizeof(what), "выход %.40s: префикс хоста не узнать", o->name);
                diag("ipv6_host", "warn", what,
                     "у LAN адреса из нескольких префиксов, и который из них от хоста, не видно — "
                     "задайте prefix: у выхода");
                continue;
            }
            if (!p.len || !l.in_p) {
                /* Чего не хватает — ip6prefix или ip6assign, — прежде было одной строкой «задайте
                 * ip6prefix … и ip6assign …», и человек правил обе, не зная, какой нет. Различает
                 * нуль-маршрут netifd (v6_announced): его нет — префикс не раздаётся никем, нет
                 * ip6prefix; есть, а у LAN адреса из него нет — не хватает ip6assign (или он
                 * задан, но кусок LAN не достался: ip6class). Маршруты не прочитать — прежняя
                 * строка про обе. */
                int ann = v6_announced(o, p.len ? &p : NULL);
                const char *pn = p.len ? ps : "хоста";
                if (ann == 0) {
                    snprintf(what, sizeof(what), "выход %.40s: префикс %.48s не раздаётся — нет "
                             "ip6prefix", o->name, pn);
                    snprintf(why, sizeof(why), "клиенты не получат IPv6 от хоста — задайте "
                             "ip6prefix у интерфейса %.24s%s", o->device,
                             o->v6pfx_given ? "" : " (или prefix: у выхода)");
                } else if (ann == 1 && have_uci && assign[0]) {
                    snprintf(what, sizeof(what), "выход %.40s: у LAN нет адреса из префикса %.48s, "
                             "хотя ip6assign %.8s задан", o->name, pn, assign);
                    snprintf(why, sizeof(why), "клиенты не получат IPv6 от хоста — проверьте "
                             "ip6class у LAN");
                } else if (ann == 1) {
                    snprintf(what, sizeof(what), "выход %.40s: у LAN нет адреса из префикса %.48s — "
                             "нет ip6assign", o->name, pn);
                    snprintf(why, sizeof(why), "клиенты не получат IPv6 от хоста — задайте "
                             "ip6assign у LAN");
                } else {
                    snprintf(what, sizeof(what), "выход %.40s: у LAN нет адреса из префикса %.48s",
                             o->name, pn);
                    snprintf(why, sizeof(why), "клиенты не получат IPv6 от хоста — задайте "
                             "ip6prefix у интерфейса %.24s и ip6assign у LAN%s", o->device,
                             o->v6pfx_given ? "" : " (или prefix: у выхода)");
                }
                diag("ipv6_host", "warn", what, why);
            } else {
                snprintf(what, sizeof(what), "выход %.40s: префикс хоста %.48s, у LAN адрес из него",
                         o->name, ps);
                diag("ipv6_host", "ok", what, "");
                probe_src = l.a_in_p;
            }
            /* ip6assign короче префикса (число меньше длины): кусок такого размера из префикса не
             * выдать, и netifd LAN адреса не даёт. */
            long as = assign[0] ? strtol(assign, NULL, 10) : 0;
            if (have_uci && p.len && as > 0 && as < p.len) {
                snprintf(what, sizeof(what), "ip6assign %ld у %.24s больше префикса хоста /%u",
                         as, lname[0] ? lname : "LAN", p.len);
                diag("ipv6_host", "warn", what, "netifd не выдаст LAN кусок больше самого префикса — "
                     "задайте ip6assign не меньше длины префикса (обычно 64)");
            }
            /* ULA рядом с префиксом и доменные правила fake-IP в донора: поддельный адрес IPv6 —
             * ULA (fdfe:dcba:9876::/96), и к нему клиент идёт со своего ULA (RFC 6724), а такой
             * источник хост не пропустит — forward_v6 отвергает его сразу, клиент идёт по IPv4. */
            int fake = 0;
            for (size_t k = 0; k < gr->n && !fake; k++)
                fake = gr->g[k].domains && !gr->g[k].realip && !strcmp(gr->g[k].out, o->name);
            if (fake && l.ula) {
                snprintf(what, sizeof(what), "выход %.40s: у LAN есть ULA рядом с префиксом хоста",
                         o->name);
                diag("ipv6_host", "note", what,
                     "к поддельным адресам fake-IP клиенты идут с ULA, такой IPv6 хост не пропустит, "
                     "и доменные правила идут по IPv4 — оставьте LAN только префикс хоста (ip6class) "
                     "или переведите правило на realip");
            }
        } else {
            if (!dev_has_v6(o->device)) {
                snprintf(what, sizeof(what), "выход %.40s: у %.24s нет адреса IPv6", o->name,
                         o->device);
                diag("ipv6_host", "fail", what, "подменять адрес клиентов нечем — задайте у интерфейса "
                     "адрес IPv6, который хост выдал пиру");
                continue;
            }
            /* У LAN только ULA: маршрут по умолчанию в RA odhcpd объявляет без глобального префикса,
             * только если ra_default у секции dhcp этой сети не 0. */
            if (l.ula && !l.gua && have_uci && lname[0] && !ra_said) {
                ra_said = 1;            /* это про LAN, а не про выход: один раз на отчёт */
                char rd[16] = "", sec[64] = "";
                int r = uci_find("dhcp", "dhcp", "interface", lname, "ra_default", rd, sizeof(rd),
                                 sec, sizeof(sec));
                if (r >= 0 && (!rd[0] || !strcmp(rd, "0"))) {
                    snprintf(what, sizeof(what), "у LAN только ULA, а ra_default не задан");
                    snprintf(why, sizeof(why), "задайте ra_default=1 в dhcp.%.40s, иначе клиенты не "
                             "получат маршрут IPv6", sec[0] ? sec : lname);
                    diag("ipv6_host", "warn", what, why);
                }
            }
        }
        if (o->failed) continue;
        if (m == OUT_V6_ROUTED && !probe_src) continue;
        int err = 0;
        int pr = v6_probe(probe_src, o->mark, 800, &err);
        if (pr == 1) {
            snprintf(what, sizeof(what), "выход %.40s: IPv6 через %.24s отвечает", o->name, o->device);
            diag("ipv6_host", "ok", what, "");
        } else if (pr < 0 && err == ENOKEY) {
            snprintf(what, sizeof(what), "выход %.40s: IPv6 в %.24s не уходит", o->name, o->device);
            diag("ipv6_host", "warn", what, "у пира в AllowedIPs нет ::/0 — добавьте его в настройке "
                 "пира на роутере");
        } else {
            snprintf(what, sizeof(what), "выход %.40s: хост не отвечает по IPv6", o->name);
            diag("ipv6_host", "warn", what, m == OUT_V6_ROUTED
                 ? "сервер не пускает адреса префикса — проверьте AllowedIPs пира на хосте и маршрут "
                   "префикса к нему"
                 : "сервер не пускает адрес пира или не выпускает IPv6 наружу — проверьте AllowedIPs "
                   "пира на хосте и NAT66 на нём");
        }
    }
}

/* Замечания IPv6 (v6_notes в generate.c) — проверками diag с их приговором. */
static void diag_v6_note(void *ctx, const char *id, const char *verdict, const char *what,
                         const char *why) {
    (void)ctx;
    diag(id, verdict, what, why);
}

int cmd_diag(const char *spec) {
    static struct spec cfg;
    static struct groups gr;
    /* Правило 5, docs/architecture.md, раздел 2: err_die здесь довершает то, что раньше делал
     * die() изнутри load_spec/build_groups. */
    struct err e = {0};
    if (load_spec(spec, &cfg, &e) < 0) err_die(&e);
    if (registry_assign(&cfg, &e) < 0) err_die(&e);
    if (build_groups(&cfg, &gr, &e) < 0) err_die(&e);
    /* Приговор выносится тому устройству, которое несёт трафик, — тому же, о котором
     * рассказывает status и к которому привязал таблицу apply (outputs_adopt_active). */
    outputs_adopt_active(&cfg);
    return diag_emit(&cfg, &gr, stdout);
}

/* Сам отчёт — в поток out, по спеке и группам вызывающего: подкоманда читает спеку сама, демон
 * отдаёт свою из памяти (ctl.c, mem_diag) — тем же кодом, байт в байт. Код — тот, с которым
 * кончается подкоманда.
 *
 * НИ ОДНОГО ПРОЦЕССА. Раньше отчёт стоил около двадцати: nft на каждую проверку наборов и
 * цепочек, pgrep резолвера и обфускатора, ip на маршрут IPv6 и на путь к серверу обфускации, пробы
 * раскладки `nft -c` — и всё это ещё и ребёнком демона. Теперь ядро спрашивается по netlink
 * (nftquery.c, src/lib/nftdump.c, src/lib/rtnl.c), а процессы — обходом /proc
 * (src/lib/procscan.c), и демон отвечает в своём процессе. */
/* Входит ли именованный выход sp->out[i] членом в какую-нибудь группу. */
static int diag_is_member(const struct spec *sp, size_t i) {
    for (size_t g = 0; g < sp->out_n; g++) {
        const struct group_cfg *gc = out_group(&sp->out[g]);
        if (!gc) continue;
        for (size_t k = 0; k < gc->members_n; k++)
            if (gc->members[k] == i) return 1;
    }
    return 0;
}

/* Устройство этого выхода уже проверяется строкой ДРУГОГО выхода — своей строки ему не нужно.
 *
 * splify2 пишет пул v2 группой из именованных обёрток «<пул>.<устройство>» вида interface, а
 * устройство обёртки часто создаёт другой выход — туннель части пула. Раздел 7 проверял каждое
 * устройство и у туннеля, и у обёртки, а группу ещё раз по её нынешнему устройству: на роутере
 * владельца шесть строк на три устройства («выход wg0-1: вне зоны» и тут же «выход wg0.wg0-1: вне
 * зоны»). Поэтому:
 *   - член группы молчит, если его устройство есть у выхода вне групп (не члена и не группы):
 *     у того строка и так будет, и приговор тот же — вопрос задаётся устройству;
 *   - группа молчит, если её нынешнее устройство — у её же именованного члена: тот отчитается
 *     сам. У пула v1 члены безымянные (sp->anon, в раздел 7 не попадают), и там строка группы —
 *     единственная, поэтому правило их не касается (tests/diagmatch.sh, «пул»). */
static int diag_dup_device(const struct spec *sp, size_t i) {
    const struct output *o = &sp->out[i];
    if (!o->device[0]) return 0;
    const struct group_cfg *gc = out_group(o);
    if (gc) {
        for (size_t k = 0; k < gc->members_n; k++) {
            if (!spec_is_named(gc->members[k])) continue;
            const struct output *m = spec_out(sp, gc->members[k]);
            if (out_has_device(m) && !strcmp(m->device, o->device)) return 1;
        }
        return 0;
    }
    if (!diag_is_member(sp, i)) return 0;
    for (size_t j = 0; j < sp->out_n; j++) {
        if (j == i || out_group(&sp->out[j]) || diag_is_member(sp, j)) continue;
        if (out_has_device(&sp->out[j]) && !strcmp(sp->out[j].device, o->device)) return 1;
    }
    return 0;
}

int diag_emit(const struct spec *sp, const struct groups *gr, FILE *out) {
    g_diag_out = out;
    g_diag_first = 1;
    g_diag_warn = g_diag_fail = 0;
    /* Раскладка — та, что стоит в ядре: искать правила там, где их поставил apply (цепочки и
     * наборы ниже). Проба `nft -c`, которой её узнаёт компилятор, здесь не нужна: отчёт читает
     * применённое, а не решает, что применять. */
    g_nftc = nft_compat_seen();
    fprintf(out, "{\"schema\":1,\"checks\":[");

    /* 1. Таблица. Без неё всё остальное бессмысленно: apply не применялся или его снесли. */
    int table = nft_chain_here("prerouting_mark");
    diag("table", table ? "ok" : "fail",
         table ? "правила ядра steer в ядре Linux" : "правил ядра steer в ядре Linux нет",
         table ? "" : "apply не применялся или таблицу снесли — нажмите «Применить»");

    /* 2. Встречная цепочка. Её отсутствие не ломает маршрутизацию, но объёмы «внутрь»
     *    будут пустыми, и это надо назвать, а не показывать нули. */
    if (table) {
        int down = nft_chain_here("postrouting_down");
        diag("down_chain", down ? "ok" : "warn",
             down ? "скачанное считается" : "скачанное не считается",
             down ? "" : "правила от старой версии ядра steer — примените настройку заново");
    }

    /* 3. Наборы. Пустой набор при непустом списке — самая частая настоящая поломка:
     *    правило на месте, трафик мимо, и по status этого не видно. */
    for (size_t i = 0; i < gr->n; i++) {
        const struct group *g = &gr->g[i];
        if (!g->files_n && !g->srs_n && !g->domains) continue;
        long n = set_count(g->name);
        /* Старая раскладка: префиксы доменной группы лежат во второй половине набора (<имя>_n,
         * см. generate). Адресов у канала — сумма обеих. */
        if (n >= 0 && legacy_may_have_static(g)) {
            char sn[80];
            nft_static_set_name(sn, sizeof(sn), g->name);
            long m = set_count(sn);
            if (m > 0) n += m;
        }
        char what[160], why[240];
        if (n < 0) {
            snprintf(what, sizeof(what), "канал %.48s: набора в ядре нет", g->name);
            snprintf(why, sizeof(why), "apply не довёл набор до ядра — примените заново");
            diag("set", "fail", what, why);
        } else if (n == 0 && (g->files_n || group_srs_v4(g))) {
            snprintf(what, sizeof(what), "канал %.48s: набор пуст", g->name);
            snprintf(why, sizeof(why),
                     "списков %zu, но в ядре ни одного адреса — списки не скачались "
                     "или в них нет адресных строк", g->files_n + g->srs_n);
            diag("set", "fail", what, why);
        } else if (n == 0) {
            snprintf(what, sizeof(what), "канал %.48s: набор пока пуст", g->name);
            snprintf(why, sizeof(why),
                     "доменный канал наполняет резолвер по мере запросов — это нормально "
                     "до первого обращения");
            /* Тоже совет, а не находка: пустой доменный набор до первого запроса — штатное
             * состояние, и тревожить им нельзя. */
            diag("set", "note", what, why);
        } else {
            snprintf(what, sizeof(what), "канал %.48s: адресов в ядре %ld", g->name, n);
            diag("set", "ok", what, "");
        }
    }

    /* 3a. Локальные устройства. Правила по ним грузятся и на отсутствующее устройство —
     *     `iifname` сверяется по имени в момент прохода пакета, — и это правильно: zt* и
     *     tailscale0 появляются позже сети. Но «правило есть, а устройства нет» означает
     *     «правило не сработает ни разу», и молчать об этом нельзя: у человека, опечатавшегося
     *     в имени, ровно та же картина, что у исправной настройки.
     *
     *     Спрашиваем /sys/class/net, а не спеку: спека описывает намерение, а вопрос здесь
     *     про роутер. warn, а не fail — остальные устройства при этом работают. */
    for (size_t i = 0; i < sp->lan_dev_n; i++) {
        char devpath[128], what[160];
        snprintf(devpath, sizeof(devpath), "/sys/class/net/%.63s", sp->lan_dev[i]);
        if (access(devpath, F_OK) == 0) {
            snprintf(what, sizeof(what), "трафик забирается с %.64s", sp->lan_dev[i]);
            diag("lan_device", "ok", what, "");
        } else {
            snprintf(what, sizeof(what), "%.64s перечислен, но такого устройства на роутере нет",
                     sp->lan_dev[i]);
            diag("lan_device", "warn", what,
                 "правила по нему не сработают: проверьте имя или поднимите интерфейс "
                 "(у Tailscale и ZeroTier устройство появляется вместе со своим демоном)");
        }
    }

    /* 3b. br_netfilter: кадры, ходящие ВНУТРИ моста, проходят через ip-хуки netfilter.
     *
     *     ЧТО ИМЕННО ИЗ ЭТОГО СЛЕДУЕТ ДЛЯ НАС. Модуль br_netfilter вместе с
     *     `net.bridge.bridge-nf-call-iptables=1` отдаёт мостовые кадры в ip-хуки
     *     PREROUTING/FORWARD/POSTROUTING — то есть в те же, на которых висим мы. Значит наше
     *     перенаправление порта 53 начинает касаться запросов, которые из роутера не выходят
     *     вовсе: правило `… udp dport 53 counter redirect to :DNS_PORT` условия на
     *     ПОЛУЧАТЕЛЯ не имеет (и не должно — оно про клиентов), поэтому запрос клиента к
     *     DNS-серверу на той же LAN (Pi-hole, второй роутер, AdGuard на NAS) заворачивается
     *     к нам. Человек видит «Pi-hole перестал получать запросы» при исправном steer, и
     *     объяснить это нечем: в наборе правил всё верно, а в спеке про мост ничего нет.
     *
     *     ЧЕГО ЗДЕСЬ НЕ НАПИСАНО, ХОТЯ ПРОСИЛОСЬ. Цепочка разметки эти кадры тоже видит, и
     *     метка на них ложится — но в туннель они от этого НЕ уедут: мостовой кадр
     *     форвардится на L2, маршрутного поиска для него нет, а политика по fwmark (`ip
     *     rule`) спрашивается только при маршрутном поиске. Приговор поэтому говорит про
     *     перенаправление DNS, где следствие прямое, и не обещает того, чего проверить не
     *     удалось. Исключение — тот самый мостовой кадр, которому мы сами меняем получателя
     *     на локальный адрес: там br_netfilter маршрутный поиск делает, и это ровно
     *     перенаправление DNS, то есть уже названный случай.
     *
     *     МОДУЛЬ МЫ НЕ ВЫКЛЮЧАЕМ. Настройка чужая и общесистемная: её ставят docker и
     *     libvirt, у них на это свои причины, и снять её значило бы сломать соседа ради
     *     своего удобства. Наше дело — сказать.
     *
     *     warn, а не note, и разница с советом про DoH принципиальна: DoH — свойство мира,
     *     верное всегда, и warn на нём красил бы исправный роутер жёлтым навсегда. Здесь же
     *     переключаемая настройка ЭТОЙ системы с наблюдаемым следствием — то есть находка,
     *     которая объясняет будущую жалобу, и она обязана попасть в счётчик. */
    /* На телефоне моста с br_netfilter нет (раздача интернета идёт без моста Linux), а
     * приговор «кадры внутри моста идут мимо наших правил» был бы ответом на вопрос, которого
     * там никто не задаёт. */
    if (plat()->lan_bridge) {
        int brnf = bridge_nf_on();
        if (brnf == 1)
            diag("bridge_nf", "warn", "мост пропускает кадры через netfilter",
                 "загружен br_netfilter и net.bridge.bridge-nf-call-iptables=1: запросы DNS "
                 "между клиентами одной LAN тоже заворачиваются на наш резолвер — правило "
                 "порта 53 смотрит на клиента, а не на получателя, поэтому DNS-сервер внутри "
                 "сети (Pi-hole, второй роутер) перестаёт получать запросы. Ядро steer эту "
                 "настройку не трогает, она общесистемная (её ставят docker и libvirt); если "
                 "она вам не нужна: sysctl -w net.bridge.bridge-nf-call-iptables=0");
        else if (brnf == 0)
            diag("bridge_nf", "ok", "кадры внутри моста идут мимо наших правил", "");
        /* brnf < 0 — в файле не 0 и не 1. Молчим: приговор наугад хуже молчания. */
    }

    /* 4. Резолвер и редирект. Доменные каналы держатся на обоих: без редиректа клиент
     *    спрашивает не нас, без процесса спрашивать некого. */
    if (has_domains(gr)) {
        /* В старой раскладке у заворота нет своей цепочки — он правило общей цепочки nat
         * (legacy.c, шаг 4), и узнаётся по самому правилу. */
        int redir = NFT_LEGACY ? nft_redirect_here(DNS_PORT) : nft_chain_here("prerouting_dns");
        diag("dns_redirect", redir ? "ok" : "fail",
             redir ? "запросы DNS заворачиваются на ядро steer"
                   : "запросы DNS на ядро steer не заворачиваются",
             redir ? "" : "доменные каналы без этого не работают вовсе — примените настройку");
        /* Обходом /proc, а не pgrep: у демона резолвер — его ребёнок с argv[0] «…/steer»
         * (docs/architecture.md, «4а»), без демона — экземпляр procd с той же строкой. */
        int alive = proc_cmdline_find("steer dnsd", 0);
        diag("dnsd", alive ? "ok" : "fail",
             alive ? "резолвер доменных каналов работает" : "резолвер доменных каналов не запущен",
             alive ? "" : "запустите: /etc/init.d/steer restart");

        /* DoH — ловушка, которую движок не решает, но обязан назвать. Клиент с DoH
         * резолвит сам, fake-IP не появляется, и выглядит это как «список не работает»
         * при исправном наборе и правиле. */
        diag("doh", "note", "клиент может обходить DNS роутера",
             "браузер с DNS-over-HTTPS резолвит сам, и доменные каналы его трафик не видят: "
             "выключите DoH в браузере или пользуйтесь адресными списками");
    }

    /* 5. IPv6. С 1.9 правила разбирают IPv6 сами (docs/architecture.md, «4б»): подсети IPv6
     *    списков — в парных наборах, выход с IPv6 ведёт его своей таблицей (и on_fail=drop
     *    останавливает оба семейства), выход без IPv6 его отвергает, доменные каналы прикрыты
     *    подавлением AAAA. Что остаётся назвать — выходы без IPv6 и клиентов, которых по IPv6 не
     *    узнать, — говорит проверка 9 (v6_notes). Здесь — только факт, что IPv6 наружу есть
     *    (маршрут по умолчанию — по rtnetlink, без процесса). */
    if (rtnl_default6() == 1)
        diag("ipv6", "ok", "IPv6 наружу работает, правила его разбирают", "");

    /* 6. Публичный резолвер внутри списка канала на выходе VLESS.
     *
     *    Раньше здесь стояли ДВЕ проверки: общая («выход VLESS несёт только TCP») и эта.
     *    Общая ушла вместе с ограничением — туннель несёт UDP командой VLESS 2, и QUIC,
     *    WireGuard и игры через него работают. Врать о снятом ограничении хуже, чем молчать:
     *    по такой заметке уходят настраивать обход, которого больше не нужно.
     *
     *    А эта осталась, потому что осталась ЕЁ причина, только другая. Метка ставится по
     *    `ip daddr @набор` без разбора протокола, поэтому UDP-запрос к резолверу из списка
     *    уходит в туннель наравне с TCP. Пройти он теперь пройдёт — но у UDP поток к узлу
     *    свой на каждую пару адрес-порт, а у DNS каждый запрос идёт с нового порта. То есть
     *    на каждое имя приходится своё рукопожатие с узлом: имена разрешаются, но дорого и
     *    медленно, и таблица соединений заполняется однократными потоками.
     *
     *    Приговор note в обоих случаях, а не warn: имена РАЗРЕШАЮТСЯ, поломки нет. Разница
     *    лишь в том, кого это касается — при доменных правилах клиентов из from_default
     *    прикрывает перенаправление DNS на свой резолвер, и цену платят только остальные.
     *
     *    ТОЛЬКО vless (бит KC_FLOW_UDP вида), и на xsteer это НЕ распространяется, хотя оба
     *    вида — наши туннели.
     *    Причина заметки в том, что у VLESS поток к узлу свой на каждую пару адрес-порт;
     *    xsteer несёт сырой IP, как wireguard, никаких потоков к узлу у него нет, и цены
     *    тоже нет. Скопировать заметку на xsteer значило бы напечатать постоянную заметку
     *    без причины — ровно то, из-за чего была убрана проверка `udp`. */
    for (size_t i = 0; i < gr->n; i++) {
        struct output *o = out_by_name(sp, gr->g[i].out);
        if (!o || !out_has_cap(o, KC_FLOW_UDP)) continue;
        char found[64];
        const char *who = NULL;
        for (size_t k = 0; k < gr->g[i].files_n && !who; k++)
            who = list_finds_resolver(gr->g[i].files[k], found, sizeof(found));
        for (size_t k = 0; k < gr->g[i].srs_n && !who; k++)
            who = srs_finds_resolver(gr->g[i].srs[k], found, sizeof(found));
        if (!who) continue;
        /* Буферы с запасом: строки русские, в UTF-8 это два байта на букву, и обрезка по
         * границе буфера разрубила бы букву посередине. Ровно этим ломался вывод при первом
         * прогоне стенда — недобитый байт делал JSON неразбираемым (см. I-029). */
        char what[256], why[512];
        snprintf(what, sizeof(what), "канал %.40s: в списке %.20s — это %.40s",
                 gr->g[i].members_n ? gr->g[i].members[0] : gr->g[i].name, found, who);
        if (has_domains(gr))
            snprintf(why, sizeof(why),
                     "запросы DNS уйдут в туннель, а там на каждый запрос свой поток к узлу "
                     "со своим рукопожатием: имена разрешатся, но медленнее. Клиентов из "
                     "from_default прикрывает перенаправление DNS на свой резолвер, "
                     "остальные платят эту цену");
        else
            snprintf(why, sizeof(why),
                     "запросы DNS уйдут в туннель, а там на каждый запрос свой поток к узлу "
                     "со своим рукопожатием: имена разрешатся, но медленнее. Перехватить "
                     "запрос нечем — доменных правил нет, значит нет и перенаправления DNS; "
                     "уберите из списка канала категорию с адресами резолвера");
        diag("resolver", "note", what, why);
        break;                            /* одного примера довольно: причина у них общая */
    }

    /* 7. Выходы: устройство, зона фаервола, NAT. То же, что в status, но с приговором —
     *    в status это поля, и какие из них важны, человек угадывал сам. */
    for (size_t i = 0; i < sp->out_n; i++) {
        if (!out_has_device(&sp->out[i])) continue;
        if (diag_dup_device(sp, i)) continue;
        char path[128];
        snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", sp->out[i].device);
        int present = access(path, R_OK) == 0;
        char what[160], why[240];
        if (!present) {
            /* Устройства нет — но это ТРИ разных случая, а не один, и раньше все три
             * назывались одинаково: «устройства нет, туннель не поднят» (I-100).
             *
             * Клиент vless создаёт устройство только после выбора узла, а при `node: -1`
             * выбор — это перебор подписки с таймаутом восемь секунд на узел. На трёх
             * десятках нерабочих узлов исправная настройка минутами выглядела сломанной, а
             * настоящий отказ — медленной проверкой. Теперь клиент говорит, что делает, и
             * приговор берётся у него.
             *
             * PROBE_NONE — «не знаем»: файла нет, он устарел или писавший процесс мёртв.
             * Тогда ветка прежняя, слово в слово: отсутствие данных не повод менять
             * приговор. */
            /* У владельца устройства, а не у назвавшего его выхода: см. ту же строку в
             * cmd_status. */
            const struct output *po = out_for_device(sp, &sp->out[i], sp->out[i].device);
            struct probe_status pr = probe_read(po->name);
            if (pr.state == PROBE_RUNNING) {
                snprintf(what, sizeof(what), "выход %.40s: проверяю узлы, %d из %d",
                         sp->out[i].name, pr.node, pr.total);
                /* Строка короткая не для красоты: буфер 240 байт, а кириллица — два байта
                 * на знак, и обрезка пришлась бы посреди последовательности UTF-8. */
                snprintf(why, sizeof(why),
                         "узлы проверяются по очереди, до восьми секунд на каждый. "
                         "Устройство появится с первым ответившим — ждать, а не чинить");
                /* Совет, а не находка: идёт штатная работа. Красить этим состояние значило
                 * бы держать жёлтую метку на исправном роутере всё время подъёма. */
                diag("output", "note", what, why);
                continue;
            }
            /* Выбранный номер узла за пределами подписки. Отдельная ветка, и это
             * исправление вранья, снятого с живого роутера: раньше такой выход попадал в
             * ветку PROBE_FAILED с total=0 и получал приговор «в подписке нет пригодных
             * узлов» — на подписке из двадцати девяти живых узлов. Человек по такому
             * приговору идёт перекачивать подписку и менять поставщика, а поправить надо
             * одно число. */
            if (pr.state == PROBE_NO_SUCH_NODE) {
                snprintf(what, sizeof(what),
                         "выход %.40s: выбран узел %d, а пригодных в подписке %d",
                         sp->out[i].name, pr.node, pr.total);
                /* Текст короткий не для красоты: буфер 240 байт, а кириллица — два байта на
                 * знак, и обрезка пришлась бы посреди последовательности UTF-8. Ровно на
                 * этом компилятор и поймал первую редакцию (301 байт). */
                snprintf(why, sizeof(why),
                         "номер вне подписки: она обновилась, узлов стало меньше. Лучше не "
                         "задавать номер — «первый рабочий» найдёт живой сам");
                diag("output", "fail", what, why);
                continue;
            }
            if (pr.state == PROBE_ALL_EXCLUDED) {
                snprintf(what, sizeof(what),
                         "выход %.40s: все узлы-кандидаты (%d) исключены", sp->out[i].name, pr.total);
                snprintf(why, sizeof(why),
                         "exclude и exclude_name не оставили ни одного узла — уберите часть "
                         "исключений или возьмите другой узел");
                diag("output", "fail", what, why);
                continue;
            }
            if (pr.state == PROBE_FAILED) {
                if (pr.total > 0)
                    snprintf(what, sizeof(what),
                             "выход %.40s: ни один узел подписки не ответил (проверено %d)",
                             sp->out[i].name, pr.total);
                else
                    snprintf(what, sizeof(what), "выход %.40s: в подписке нет пригодных узлов",
                             sp->out[i].name);
                /* Два готовых текста вместо одного с подстановкой: с подстановкой длинная
                 * ветка не влезала в буфер, а обрезка кириллицы рвёт знак пополам. */
                if (pr.total > 0)
                    snprintf(why, sizeof(why),
                             "живого узла не нашлось. Причины по каждому ядро steer пишет в "
                             "журнал; смените узел или обновите подписку");
                else
                    snprintf(why, sizeof(why),
                             "подписка скачана, но узлов нужного вида в ней нет; проверьте "
                             "ссылку и поддержку vless/reality у поставщика");
                diag("output", "fail", what, why);
                continue;
            }
            snprintf(what, sizeof(what), "выход %.40s: устройства %.24s нет",
                     sp->out[i].name, sp->out[i].device);
            snprintf(why, sizeof(why), "туннель не поднят — %s",
                     out_engine_managed(po) ? "смотрите журнал ядра steer"
                                            : "проверьте настройку интерфейса");
            diag("output", "fail", what, why);
            continue;
        }
        /* Устройство есть, а узел за ним клиент vless потерял — сказал об этом сам (слежка за
         * узлом под демоном, src/tunnel/pool.c; сюда — из памяти демона через окружение).
         * Приговор — про узел, а не «устройство не отвечает»: устройство на месте, и чинить его
         * незачем. Причина — словами клиента. Выход при этом обычно и в отказе (сторож принял
         * down клиента), и тогда в той же строке — куда пошёл трафик канала. */
        {
            const struct output *po = out_for_device(sp, &sp->out[i], sp->out[i].device);
            struct probe_status pr = { PROBE_NONE, 0, 0, 0, "" };
            if (out_engine_managed(po)) pr = probe_read(po->name);
            if (pr.state == PROBE_LOST) {
                if (sp->out[i].failed)
                    snprintf(what, sizeof(what), "выход %.40s: узел перестал отвечать, трафик "
                             "канала %s", sp->out[i].name,
                             sp->out[i].on_fail == FAIL_DROP ? "остановлен" :
                             sp->out[i].on_fail == FAIL_ZAPRET ? "идёт через обход" :
                             "идёт напрямую");
                else
                    snprintf(what, sizeof(what), "выход %.40s: узел перестал отвечать",
                             sp->out[i].name);
                /* diag() печатает текст в кавычки как есть, а причина — чужая строка: кавычку,
                 * обратную косую и управляющие байты — пробелом, чтобы JSON не разломился. */
                for (char *c = pr.why; *c; c++)
                    if (*c == '"' || *c == '\\' || (unsigned char)*c < 0x20) *c = ' ';
                snprintf(why, sizeof(why), "%s; выход вернётся сам, когда узел ответит",
                         pr.why[0] ? pr.why : "узел не отвечает");
                diag("output", "fail", what, why);
                continue;
            }
        }
        /* Устройство есть, но сторож признал выход неработающим (ни одно устройство не
         * ответило на пробу) и поставил on_fail. Зона и NAT здесь ничего не объясняют: трафик
         * через устройство не идёт вовсе. До этой ветки отчёт говорил «устройство в зоне, NAT
         * есть» — ok на выходе, чей трафик стоит. */
        if (sp->out[i].failed) {
            snprintf(what, sizeof(what), "выход %.40s: %.24s не отвечает, трафик канала %s",
                     sp->out[i].name, sp->out[i].device,
                     sp->out[i].on_fail == FAIL_DROP ? "остановлен" :
                     sp->out[i].on_fail == FAIL_ZAPRET ? "идёт через обход" : "идёт напрямую");
            snprintf(why, sizeof(why), "выход вернётся сам, как только устройство ответит; "
                     "проверьте туннель и его сервер");
            diag("output", "fail", what, why);
            continue;
        }
        /* Устройство есть, но выключено (operstate down). status отдаёт такому выходу
         * `up: false`, а failed сторож ставит не сразу и не всякому выходу (одиночное устройство
         * без группы он не пробует) — и до этой ветки diag шёл дальше к зоне и NAT, то есть на
         * выключенном wg0 говорил «в зоне, NAT есть». Признак тот же, что у status: первые
         * четыре буквы «down» (у туннелей обычное состояние — «unknown», это не отказ). */
        {
            char st[16] = "";
            FILE *df = fopen(path, "r");
            if (df) {
                if (!fgets(st, sizeof(st), df)) st[0] = 0;
                fclose(df);
            }
            if (strncmp(st, "down", 4) == 0) {
                const struct output *po = out_for_device(sp, &sp->out[i], sp->out[i].device);
                snprintf(what, sizeof(what), "выход %.40s: устройство %.24s выключено",
                         sp->out[i].name, sp->out[i].device);
                snprintf(why, sizeof(why), "%s",
                         out_engine_managed(po)
                             ? "туннель не поднят — смотрите журнал ядра steer"
                             : "поднимите интерфейс (ifup) или проверьте его настройку; "
                               "выход вернётся сам, когда устройство поднимется");
                diag("output", "fail", what, why);
                continue;
            }
        }
        struct fwcheck c = fw_check(sp->out[i].device);
        /* Нужен ли masquerade — свойство УСТРОЙСТВА, а не выхода, который его назвал: в пуле
         * kind=interface активным бывает устройство VLESS-туннеля или хаба xsteer, и вопрос
         * решает его владелец. Без этого исправно собранный пул получал бы вечное «нет
         * masquerade» — ту самую жёлтую метку, из-за которой перестают смотреть на проверки. */
        const struct output *nat_o = out_for_device(sp, &sp->out[i], sp->out[i].device);
        if (!c.in_firewall) {
            snprintf(what, sizeof(what), "выход %.40s: %.24s вне зоны фаервола",
                     sp->out[i].name, sp->out[i].device);
            diag("output", "fail", what,
                 "фаервол отбросит ответы — добавьте устройство в зону");
        } else if (!c.masqueraded && !out_self_natting(nat_o)) {
            /* Только для kind=interface. Выходу vless masquerade не нужен: он завершает TCP
             * сам и наружу идёт от своего имени, адреса клиентов границу не переходят. Жалоба
             * на исправной системе — это постоянная жёлтая метка, которая учит не смотреть на
             * проверки вовсе. */
            snprintf(what, sizeof(what), "выход %.40s: у %.24s нет masquerade",
                     sp->out[i].name, sp->out[i].device);
            diag("output", "warn", what,
                 "без подмены адреса ответы не найдут дорогу назад, если туннель этого "
                 "не делает сам");
        } else if (c.masqueraded) {
            snprintf(what, sizeof(what), "выход %.40s: устройство %.24s в зоне, NAT есть",
                     sp->out[i].name, sp->out[i].device);
            diag("output", "ok", what, "");
        } else {
            /* Сюда попадает выход без masquerade, которому он и не нужен (vless, xsteer)
             * — для него это норма. Сказать «NAT есть» было бы прямой неправдой: его нет,
             * он просто не нужен.
             *
             * Тексты РАЗНЫЕ, и это не оформление. Формулировка vless («туннель завершает
             * TCP сам, адреса клиентов наружу не уходят») для xsteer неверна: адреса
             * уходят, к хабу. Поэтому текст даёт вид (kind_ops.selfnat_why), а не общий код:
             * одно объяснение на всех значило бы записать в диагностику неправду — а по ней
             * настраивают. */
            snprintf(what, sizeof(what), "выход %.40s: устройство %.24s в зоне",
                     sp->out[i].name, sp->out[i].device);
            diag("output", "ok", what,
                 kind_of(nat_o)->selfnat_why ? kind_of(nat_o)->selfnat_why : "");
        }
        /* ПОДМЕНА IPv6 — ОТДЕЛЬНЫМ ВОПРОСОМ (с 1.10, шаг 8). Выход, несущий IPv6 (out_route6),
         * отправляет в туннель IPv6 клиентов с их адресами — провайдерскими или ULA, — и ответ
         * вернётся, только если адреса подменены (masq6 зоны) или хост их маршрутизует. Прежде
         * строкой выше засчитывалось любое правило masquerade, в том числе одно IPv4, и о
         * половине IPv6 diag молчал. Говорим, только когда у клиентов вообще есть IPv6 наружу
         * (глобальный адрес на устройстве раздачи): без него вопроса нет, и строка была бы
         * постоянной ложной тревогой. */
        /* С ключом ipv6 (шаг 8) вопрос другой: у nat подмену ставит сам движок (своя таблица, её
         * fw_check не читает), у routed её не нужно вовсе — хост маршрутизует префикс, а masq6
         * зоны подменил бы адреса префикса адресом туннеля. */
        /* Ключ — устройства, а не выхода (out_ipv6_mode_dev, fwcheck.c): у группы, чей нынешний
         * член `ipv6: nat`, подмену на его устройство ставит движок, и «нет masquerade IPv6» там
         * было ложной тревогой. */
        int m6 = out_ipv6_mode_dev(sp, &sp->out[i], sp->out[i].device);
        if (c.in_firewall && out_route6(&sp->out[i]) && !out_self_natting(nat_o) && !c.masq6 &&
            m6 == OUT_V6_KIND && lan_has_global_v6(sp)) {
            snprintf(what, sizeof(what), "выход %.40s: у %.24s нет masquerade IPv6",
                     sp->out[i].name, sp->out[i].device);
            diag("output_nat6", "warn", what,
                 "IPv6 клиентов уйдёт в туннель с их адресами, и ответ не вернётся — включите "
                 "masq6 у зоны выхода");
        }
        /* Называется зона fw4, в которой masq6 (fwcheck.zone6), а не устройство: wg0 бывает в зоне
         * wan, и «у зоны wg0» посылало бы искать зону, которой нет. Зону не назвать (подмена
         * правилом на самом устройстве) — называется устройство. */
        if (c.masq6 && m6 == OUT_V6_ROUTED) {
            if (c.zone6[0])
                snprintf(what, sizeof(what), "выход %.40s: у зоны %.24s (в ней %.24s) включён masq6",
                         sp->out[i].name, c.zone6, sp->out[i].device);
            else
                snprintf(what, sizeof(what), "выход %.40s: IPv6 на %.24s подменяется (masquerade)",
                         sp->out[i].name, sp->out[i].device);
            /* Зона названа не по устройству (wg0 в зоне wan) — masq6 там нужен остальным её
             * интерфейсам, и совет «снимите masq6» сломал бы им IPv6: советуется своя зона. */
            char why6[300];
            if (!c.zone6[0])
                snprintf(why6, sizeof(why6), "адреса из префикса хоста подменяются адресом "
                         "туннеля, и снаружи клиентов не видно по их адресам — для ipv6: routed "
                         "снимите это правило masquerade");
            else if (!strcmp(c.zone6, sp->out[i].device))
                snprintf(why6, sizeof(why6), "адреса из префикса хоста подменяются адресом "
                         "туннеля, и снаружи клиентов не видно по их адресам — для ipv6: routed "
                         "снимите masq6 у зоны %.24s", c.zone6);
            else
                snprintf(why6, sizeof(why6), "адреса из префикса хоста подменяются адресом "
                         "туннеля, и снаружи клиентов не видно по их адресам — для ipv6: routed "
                         "перенесите %.24s в свою зону без masq6", sp->out[i].device);
            diag("ipv6_host", "warn", what, why6);
        }
    }

    /* 7a. IPv6 от хоста (ipv6: routed и nat, шаг 8 выпуска 1.10): чего не хватает в настройке
     *     роутера и хоста — раздачу IPv6 ведёт человек (netifd, odhcpd), и diag называет, что именно
     *     дописать. */
    diag_v6_host(sp, gr);

    /* 8. Свои проверки видов (kind_ops.diag): обфускация транспорта у interface, обработчик
     *    очереди и файл стратегии у zapret.
     *
     *    Обход — по видам в порядке реестра, а внутри вида — по выходам в порядке спеки. Так
     *    проверки одного вида идут подряд, одним блоком, как шли, пока были секциями этой
     *    функции (сначала все obfs, потом все zapret), и ответ не зависит от того, в каком
     *    порядке человек записал выходы разных видов. */
    for (size_t ki = 0; ki < kind_count(); ki++) {
        const struct kind_ops *k = kind_at(ki);
        if (!k->diag) continue;
        for (size_t i = 0; i < sp->out_n; i++)
            if (kind_of(&sp->out[i]) == k) k->diag(diag, sp, &sp->out[i]);
    }

    /* 9. IPv6 правил: выходы без IPv6 и клиенты, которых по IPv6 не узнать. */
    v6_notes(sp, gr, diag_v6_note, NULL);

    fprintf(out, "],\"warn\":%d,\"fail\":%d}\n", g_diag_warn, g_diag_fail);
    /* Код возврата — чтобы это годилось в скрипт, а не только глазам. */
    return g_diag_fail ? 1 : 0;
}
