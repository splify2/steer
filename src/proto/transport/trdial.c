/* Сокет до узла: TCP по ВСЕМ адресам имени (IPv4 и IPv6), а не по первому, и метка выхода-подложки.
 *
 * Нижний ярус транспорта (transport.h). От протокола здесь не зависит ничего, а любой дайлер
 * поверх тех же транспортов обязан соединяться тем же путём — с тем же перебором адресов, тем же
 * кэшем победителя и той же меткой, иначе `over` у него значил бы другое.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>

#include "transport.h"
#include "sockmark.h"

/* ---- установление TCP: ВСЕ адреса узла, а не первый ---------------------------
 *
 * Одно имя узла — это, как правило, не один адрес. Живой пример, на котором это нашлось:
 * pl.riotvpn.eu отдаёт ПЯТНАДЦАТЬ записей A, и шесть из них — чёрные дыры: SYN уходит, в
 * ответ тишина. DNS перемешивает список при каждом запросе, поэтому «первый адрес» каждый
 * раз другой, и в сорока процентах случаев он мёртвый.
 *
 * Прежний код брал res->ai_next == первый и на этом останавливался. Последствия оказались
 * куда хуже, чем «иногда не соединяется»:
 *
 *   - блокирующий connect к чёрной дыре ждёт SO_SNDTIMEO целиком — восемь секунд, — и
 *     всё это время событийный цикл СТОИТ. Не тормозит, а стоит: ни один другой поток не
 *     двигается. На роутере это выглядело как «сайты еле открываются» при простое
 *     процессора 80% и нулевых счётчиках ошибок;
 *   - Linux сообщает об этом таймауте кодом EINPROGRESS (см. __inet_stream_connect:
 *     истёк timeo — err остаётся -EINPROGRESS), а не ETIMEDOUT. То есть в логе стояло
 *     «Operation in progress» у блокирующего вызова — вид сообщения, за которым не видно
 *     ни таймаута, ни мёртвого адреса;
 *   - сторож считал узел живым или мёртвым по одной пробе, то есть по жребию.
 *
 * Поэтому здесь: неблокирующий connect, свой таймаут вместо SO_SNDTIMEO, несколько
 * попыток одновременно с задержкой между запусками, и адрес-победитель запоминается,
 * чтобы следующее соединение начиналось с него. */

#define ADDR_MAX      16   /* сколько адресов имени вообще рассматриваем */
#define ATTEMPT_MAX    4   /* сколько держим в воздухе одновременно */
#define STAGGER_MS   150   /* пауза перед запуском следующей попытки */

/* ---- адреса обоих семейств ---------------------------------------------------------------
 *
 * Узел бывает по адресу IPv6 (`vless://…@[2001:db8::1]:443`), по имени только с AAAA и по имени
 * с обеими записями (issue splify2/steer#7: раньше дозвон был зашит на AF_INET, и первые два
 * случая не открывались вовсе — «имя не разрешилось»). Поэтому адрес здесь — sockaddr_storage
 * с длиной, а не struct in_addr: семейство, сам адрес и scope id link-local (fe80::1%br-lan —
 * без него connect отвечает EINVAL) переезжают целиком, и кэш победителя хранит то же.
 *
 * Порядок адресов даёт getaddrinfo: и glibc, и musl сортируют ответ по RFC 6724, то есть IPv6
 * первым там, где у хоста он есть. Свою сортировку не заводим — только два правила поверх:
 *   - прошлый победитель идёт первым (ниже);
 *   - семейства чередуются (addrs_interleave): десять мёртвых AAAA подряд не должны стоять
 *     между нами и живым A, как у имени с чёрной дырой в одном из семейств. Это RFC 8305 §4
 *     (Happy Eyeballs v2) без его таймера на ответ DNS — resolve у нас блокирующий.
 * Срок на адрес прежний: STAGGER_MS до запуска следующей попытки (у RFC 8305 это 250 мс; здесь
 * 150, потому что до узла на роутере идёт один круг сети, а не браузерный запас на мобильную
 * связь) и общий срок timeout_s на всё соединение. Нет маршрута до семейства (у роутера без
 * глобального IPv6 это обычное дело) — connect отвечает ENETUNREACH сразу, попытка отваливается
 * мгновенно, и следующий адрес стартует без паузы: ждать нечего, а тихой чёрной дыры тут нет. */
struct tr_addr {
    struct sockaddr_storage ss;
    socklen_t len;
};

static int addr_port_set(struct tr_addr *a, uint16_t port) {
    if (a->ss.ss_family == AF_INET6) ((struct sockaddr_in6 *)&a->ss)->sin6_port = htons(port);
    else if (a->ss.ss_family == AF_INET) ((struct sockaddr_in *)&a->ss)->sin_port = htons(port);
    else return -1;
    return 0;
}

/* Один и тот же адрес: семейство, сами байты и (у IPv6) scope id; порт не сравнивается — он
 * один на всё имя. */
static int addr_same(const struct tr_addr *a, const struct tr_addr *b) {
    if (a->ss.ss_family != b->ss.ss_family) return 0;
    if (a->ss.ss_family == AF_INET6) {
        const struct sockaddr_in6 *x = (const void *)&a->ss, *y = (const void *)&b->ss;
        return !memcmp(&x->sin6_addr, &y->sin6_addr, sizeof x->sin6_addr) &&
               x->sin6_scope_id == y->sin6_scope_id;
    }
    return ((const struct sockaddr_in *)(const void *)&a->ss)->sin_addr.s_addr ==
           ((const struct sockaddr_in *)(const void *)&b->ss)->sin_addr.s_addr;
}

/* Адреса имени (оба семейства) в порядке getaddrinfo, не больше ADDR_MAX. socktype — тип
 * сокета, под который спрашиваем. Возвращает число адресов; 0 — имя не разрешилось. */
static unsigned addrs_resolve(const char *host, uint16_t port, int socktype, struct tr_addr *out) {
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", port);
    struct addrinfo hints = { .ai_family = AF_UNSPEC, .ai_socktype = socktype };
    struct addrinfo *res = NULL;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) return 0;
    unsigned an = 0;
    for (struct addrinfo *p = res; p && an < ADDR_MAX; p = p->ai_next) {
        if ((p->ai_family != AF_INET && p->ai_family != AF_INET6) ||
            p->ai_addrlen > sizeof(out[an].ss)) continue;
        memset(&out[an], 0, sizeof(out[an]));
        memcpy(&out[an].ss, p->ai_addr, p->ai_addrlen);
        out[an].len = p->ai_addrlen;
        if (addr_port_set(&out[an], port) == 0) an++;
    }
    freeaddrinfo(res);
    return an;
}

/* Чередование семейств после первого адреса: за ним — первый из другого семейства, потом снова
 * из прежнего и так далее; когда одно семейство кончилось, остаток другого идёт подряд. Внутри
 * семейства порядок getaddrinfo сохраняется. */
static void addrs_interleave(struct tr_addr *a, unsigned n) {
    if (n < 3) return;
    struct tr_addr tmp[ADDR_MAX];
    int first = a[0].ss.ss_family;
    unsigned i4 = 1, i6 = 1, k = 1;   /* указатели просмотра по семействам; k — куда писать */
    tmp[0] = a[0];
    int want_other = 1;
    while (k < n) {
        int fam = want_other ? (first == AF_INET6 ? AF_INET : AF_INET6) : first;
        unsigned *ip = fam == AF_INET6 ? &i6 : &i4;
        while (*ip < n && a[*ip].ss.ss_family != fam) (*ip)++;
        if (*ip < n) { tmp[k++] = a[(*ip)++]; want_other = !want_other; continue; }
        /* Этого семейства больше нет — остаток другого подряд. */
        fam = fam == AF_INET6 ? AF_INET : AF_INET6;
        ip = fam == AF_INET6 ? &i6 : &i4;
        while (*ip < n && k < n) { if (a[*ip].ss.ss_family == fam) tmp[k++] = a[*ip]; (*ip)++; }
        break;
    }
    memcpy(a, tmp, sizeof(a[0]) * n);
}

/* Адрес для журнала: «host» или «[host]» у IPv6. */
static const char *host_log(const char *host, char *buf, size_t n) {
    if (!strchr(host, ':')) return host;
    snprintf(buf, n, "[%s]", host);
    return buf;
}

/* Победивший адрес на имя. Живёт по потоку: работники независимы, блокировка не нужна, а
 * «каждый узнал сам» стоит одного лишнего перебора на работника при старте. Адрес — целиком
 * (семейство, байты, scope id), а не четыре байта IPv4: иначе после победы IPv6-адреса кэш не
 * мог бы ни сохранить его, ни поставить впереди. */
#define GOOD_MAX 8
static __thread struct { char host[96]; struct tr_addr ip; uint16_t port; } g_good[GOOD_MAX];
static __thread unsigned g_good_n;

static const struct tr_addr *good_get(const char *host, uint16_t port) {
    for (unsigned i = 0; i < g_good_n; i++)
        if (g_good[i].port == port && strcmp(g_good[i].host, host) == 0) return &g_good[i].ip;
    return NULL;
}

static void good_put(const char *host, uint16_t port, const struct tr_addr *ip) {
    const struct tr_addr *old = good_get(host, port);
    if (old) { *(struct tr_addr *)old = *ip; return; }
    unsigned i = g_good_n < GOOD_MAX ? g_good_n++ : GOOD_MAX - 1;
    snprintf(g_good[i].host, sizeof(g_good[i].host), "%s", host);
    g_good[i].port = port;
    g_good[i].ip = *ip;
}

/* Прошлый победитель — на место 0, если он есть в ответе. Остальной порядок не трогается. */
static void addrs_promote(struct tr_addr *a, unsigned n, const struct tr_addr *g) {
    if (!g) return;
    for (unsigned i = 1; i < n; i++)
        if (addr_same(&a[i], g)) { struct tr_addr t = a[0]; a[0] = a[i]; a[i] = t; break; }
}

static int64_t now_ms(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}

/* Готовит установленный сокет к работе остального кода: снимает O_NONBLOCK (чтение и
 * запись дальше блокирующие, с таймаутом через SO_*TIMEO) и ставит опции. */
static void sock_ready(int fd, int timeout_s) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    /* Таймаут на чтение и запись. Без него мёртвый узел вешает проверку до таймаута
     * ядра — минуты, за которые сторож не успеет обойти остальных кандидатов. */
    struct timeval tv = { .tv_sec = timeout_s, .tv_usec = 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    /* SO_RCVBUF здесь НЕ ставится, и это отказ от прежней «оптимизации», а не упущение.
     *
     * Любой вызов setsockopt(SO_RCVBUF) ОТКЛЮЧАЕТ автоподстройку приёмного окна в Linux и
     * прибивает его к заданному размеру. А скорость приёма равна «окно, поделённое на круг
     * до сервера»: при круге 60 мс полмегабайта — это потолок 68 Мбит/с, сколько бы ни
     * давал канал. Автоподстройка дошла бы до нескольких мегабайт сама.
     *
     * То есть «поставил буфер побольше» на деле означало «запретил ядру увеличивать его
     * дальше». Пределы живут в net.ipv4.tcp_rmem и настраиваются системой, а не нами. */
}

/* МЕТКА СОКЕТА К УЗЛУ — для `via` (см. «вложенные выходы» в spec.h). Её называет модуль
 * протокола при старте: out_underlay_mark выхода (underlay_setup в proto/vless/vlmain.c).
 * Своя копия того, что в obfs.c делает obfs_mark_sock, а не вызов: этот файл собирают стенды
 * без obfs.c (xhupmatch), а кода здесь три строки. required — задан via: тогда отказ SO_MARK —
 * отказ соединения, иначе оно молча ушло бы мимо выхода-цели напрямую. */
static uint32_t g_sock_mark;
static int g_sock_mark_req;

void transport_set_sock_mark(uint32_t mark, int required) {
    g_sock_mark = mark;
    g_sock_mark_req = mark && required;
}

/* ВЫХОД-ЦЕЛЬ (`via`) — ТОЛЬКО IPv4. Метка сокета ведёт пакет в таблицу цели правилом `ip rule fwmark`,
 * а у движка это правило (и маршрут по умолчанию в таблице выхода) для IPv6 у целей без IPv6 (vless,
 * xsteer, прокси) нет: сокет IPv6 с той же меткой ушёл бы по обычным правилам, то есть НАПРЯМУЮ, мимо
 * цели, — ровно то, ради чего via заводят (docs/contract-v1.md, «вложенные выходы»; то же правило у
 * awg_via_check). Поэтому при обязательной метке адрес IPv6 не пробуется вовсе: отказ называется один
 * раз в журнале, а имя с записью A идёт по IPv4. 1 — адрес запрещён. */
static int via_forbids(const struct tr_addr *a) {
    if (!g_sock_mark_req || a->ss.ss_family != AF_INET6) return 0;
    static int told;
    if (!told) {
        told = 1;
        fprintf(stderr, "steer[warn] via: адрес узла по IPv6 пропущен — через выход-цель туннель "
                        "идёт только по IPv4 (без этого он ушёл бы мимо цели); нужен адрес IPv4 "
                        "или имя с записью A\n");
    }
    return 1;
}

/* Запускает неблокирующий connect. Возвращает fd (соединение уже установлено или в
 * процессе) либо -1. */
static int attempt_start(const struct tr_addr *ip, int *done) {
    if (via_forbids(ip)) return -1;
    int fd = socket(ip->ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    /* До connect(): маршрут, а с ним устройство и адрес источника, ядро выбирает там — по
     * метке, то есть по таблице выхода-цели. */
    if (steer_sock_mark(fd, g_sock_mark) != 0 && g_sock_mark_req) {
        static int told;
        if (!told) {
            told = 1;
            fprintf(stderr, "steer[warn] via: метка 0x%08x на сокет к узлу не встала (%s) — "
                            "соединение не открываю: без метки оно ушло бы мимо выхода via\n",
                    g_sock_mark, strerror(errno));
        }
        close(fd);
        return -1;
    }
    *done = 0;
    if (connect(fd, (const struct sockaddr *)&ip->ss, ip->len) == 0) { *done = 1; return fd; }
    if (errno != EINPROGRESS) { close(fd); return -1; }
    return fd;
}

static int tcp_connect(const char *host, uint16_t port, int timeout_s) {
    struct tr_addr addr[ADDR_MAX];
    unsigned an = addrs_resolve(host, port, SOCK_STREAM, addr);
    if (an == 0) return TR_EDNS;

    /* Прошлый победитель — вперёд. В устойчивом состоянии это означает одно соединение за
     * один круг до сервера вместо перебора мёртвых адресов заново каждый раз. Дальше семейства
     * чередуются — см. шапку раздела. */
    addrs_promote(addr, an, good_get(host, port));
    addrs_interleave(addr, an);

    int fd[ATTEMPT_MAX];
    struct tr_addr fa[ATTEMPT_MAX];
    unsigned nf = 0;     /* попыток в воздухе */
    unsigned next = 0;   /* следующий адрес к запуску */
    unsigned dead = 0;   /* сколько адресов отвалилось */
    int64_t deadline = now_ms() + (long long)timeout_s * 1000;
    int64_t stagger_at = 0;
    int win = -1;

    while (win < 0) {
        int64_t t = now_ms();
        if (t >= deadline) break;

        /* Запуск новых попыток: первая сразу, дальше через STAGGER_MS. Пауза нужна, чтобы
         * при живом первом адресе (обычный случай) второй сокет вообще не открывался. */
        while (nf < ATTEMPT_MAX && next < an && t >= stagger_at) {
            int d = 0;
            struct tr_addr ip = addr[next++];
            int s = attempt_start(&ip, &d);
            if (s < 0) { dead++; continue; }
            if (d) {   /* соединилось сразу: обычно это адрес в той же сети */
                for (unsigned j = 0; j < nf; j++) close(fd[j]);
                nf = 0;
                good_put(host, port, &ip);
                win = s;
                break;
            }
            fd[nf] = s; fa[nf] = ip;
            nf++;
            stagger_at = t + STAGGER_MS;
        }
        if (win >= 0) break;
        if (nf == 0) break;   /* адреса кончились, и ни одна попытка не жива */

        struct pollfd pv[ATTEMPT_MAX];
        for (unsigned i = 0; i < nf; i++) { pv[i].fd = fd[i]; pv[i].events = POLLOUT; pv[i].revents = 0; }

        /* Ждём до ближайшего из двух событий: пора запускать следующую попытку или вышел
         * общий срок. Ограничение «только если есть куда запускать» — не мелочь: без него
         * при четырёх попытках в воздухе и непустом остатке адресов poll получал таймаут 0
         * и цикл крутился на месте, съедая ядро. */
        int64_t wait = deadline - t;
        if (next < an && nf < ATTEMPT_MAX) {
            int64_t till = stagger_at > t ? stagger_at - t : 0;
            if (till < wait) wait = till;
        }
        if (wait < 0) wait = 0;
        int pr = poll(pv, nf, (int)wait);
        if (pr < 0) { if (errno == EINTR) continue; break; }

        for (unsigned i = 0; i < nf; ) {
            if (!pv[i].revents) { i++; continue; }
            int err = 0; socklen_t el = sizeof(err);
            getsockopt(fd[i], SOL_SOCKET, SO_ERROR, &err, &el);
            if (err == 0 && !(pv[i].revents & (POLLERR | POLLHUP))) {
                win = fd[i];
                good_put(host, port, &fa[i]);
                for (unsigned j = 0; j < nf; j++) if (j != i) close(fd[j]);
                nf = 0;
                break;
            }
            /* Этот адрес отпал — освобождаем место и сразу пробуем следующий. */
            close(fd[i]); dead++;
            nf--; fd[i] = fd[nf]; fa[i] = fa[nf]; pv[i] = pv[nf];
            stagger_at = 0;
        }
    }

    if (win < 0) {
        for (unsigned i = 0; i < nf; i++) close(fd[i]);
        /* Сообщение называет масштаб: «ни один из N адресов» — это про имя узла, а не
         * про сеть, и лечится сменой узла, а не настройкой роутера. Приставка «steer vless»
         * — прежняя: по ней журнал читают, а соединяется этим путём пока только VLESS. */
        char hb[100];
        fprintf(stderr, "steer vless: %s:%u — ни один адрес не ответил (адресов %u, отпало %u)\n",
                host_log(host, hb, sizeof(hb)), port, an, dead);
        return TR_ECONNECT;
    }
    if (dead) {
        char hb[100];
        fprintf(stderr, "steer vless: %s:%u — соединился, пропущено мёртвых адресов: %u из %u\n",
                host_log(host, hb, sizeof(hb)), port, dead, an);
    }
    sock_ready(win, timeout_s);
    return win;
}

/* Шов установления TCP — симметрично g_latency_probe в failover.c и по той же причине:
 * стенду нужно провести рукопожатие с собеседником, которого он держит сам, не поднимая
 * ни сокета наружу, ни настоящего узла. В бою указатель NULL, и соединяет tcp_connect.
 *
 * Почему шов появился именно здесь. У ветвей отказа установления не было НИ ОДНОГО
 * стенда: tests/fake-vless.py говорит только security=none и до TLS не доходит, а
 * tests/run-reality.sh требует sing-box, root и сетевых пространств и потому не входит ни
 * в `make test`, ни в `make ext-test`. Всё, что охраняло здесь освобождение ключей и
 * дескриптора, — чтение кода глазами, тогда как у xsteer на ту же болезнь (I-067) стенд
 * стоит под AddressSanitizer с запуска 42. Шов дешевле поддельного сервера: адрес узла
 * перестаёт быть обязан быть настоящим, и дальше рукопожатие идёт по socketpair
 * (tests/vlessmatch.c, R-114; стенд включает этот файл, чтобы дотянуться до шва).
 *
 * Возвращает то же, что tcp_connect: дескриптор либо отрицательный код TR_*. */
static int (*g_tcp_dial)(const char *host, uint16_t port, int timeout_s);

int tr_dial(const char *host, uint16_t port, int timeout_s) {
    if (g_tcp_dial) return g_tcp_dial(host, port, timeout_s);
    return tcp_connect(host, port, timeout_s);
}

/* Сокет UDP к узлу — для протоколов, у которых датаграммы идут датаграммами (shadowsocks, SOCKS5 UDP
 * ASSOCIATE; src/proto/proxy). Та же метка, что у TCP (`over`/`via`), и тем же правилом: метка
 * обязательна — без неё сокет не открывается. Адреса обоих семейств. Перебора с ожиданием, как у TCP,
 * нет — у UDP нет рукопожатия, по которому мёртвый адрес видно сразу, — но выбор не слепой:
 *   - адрес, на котором TCP к этому имени уже побеждал (кэш выше), идёт первым: соединение с ним
 *     доказано, а «первый из ответа» мог бы оказаться семейством без пути (IPv6 у роутера без
 *     маршрута, или чёрная дыра);
 *   - дальше в порядке getaddrinfo: адрес, до которого нет маршрута, отказывает в самом connect()
 *     (ENETUNREACH), и берётся следующий.
 * Дескриптор неблокирующий и соединённый (connect), либо отрицательный код TR_*. */
int tr_dial_udp(const char *host, uint16_t port) {
    struct tr_addr addr[ADDR_MAX];
    unsigned an = addrs_resolve(host, port, SOCK_DGRAM, addr);
    if (an == 0) return TR_EDNS;
    addrs_promote(addr, an, good_get(host, port));

    int err = TR_ECONNECT;
    for (unsigned i = 0; i < an; i++) {
        if (via_forbids(&addr[i])) continue;
        int fd = socket(addr[i].ss.ss_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (fd < 0) { err = TR_ESOCK; continue; }
        if (steer_sock_mark(fd, g_sock_mark) != 0 && g_sock_mark_req) {
            close(fd);
            return TR_ESOCK;
        }
        if (connect(fd, (const struct sockaddr *)&addr[i].ss, addr[i].len) == 0) return fd;
        err = TR_ECONNECT;
        close(fd);
    }
    return err;
}
