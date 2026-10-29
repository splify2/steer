/* TUN-устройство и пересылка пакетов через VLESS.
 *
 * Почему TUN, а не SOCKS. Выход steer описан как устройство (`kind: interface`), и весь
 * механизм — метки, таблицы маршрутизации, failover, каналы — уже умеет с устройствами
 * работать. TUN означает, что VLESS вписывается в модель без единого исключения: канал
 * ведёт в него так же, как в wireguard. SOCKS потребовал бы отдельного вида выхода,
 * прозрачного проксирования и правил REDIRECT — то есть второго способа делать то же.
 *
 * Что здесь происходит: из TUN приходят IP-пакеты целиком. Мы разбираем заголовок, для
 * каждого TCP-соединения открываем свой поток VLESS и дальше переносим байты между TUN и
 * потоком. Это и есть та часть, которую в готовых решениях называют «стеком»: ядро отдаёт
 * нам пакеты, а не соединения, и восстанавливать соединения приходится самим.
 *
 * Границы реализации названы честно:
 *   TCP  — работает: состояние соединения отслеживается, поток VLESS на соединение;
 *   UDP  — работает: поток VLESS на пару адрес-порт, датаграммы едут с двухбайтовой
 *          длиной (VLESS cmd=2). Этим же путём идут QUIC и WireGuard;
 *   ICMP — не пересылается: ping через прокси требует эмуляции, которая полезна только для
 *          диагностики, а вводит в заблуждение (успешный ping не означает рабочий путь).
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <poll.h>
#include <sys/uio.h>

#include "tun.h"
#include "platform.h"

/* Заголовок разгрузки virtio, тот самый, который принимает IFF_VNET_HDR.
 *
 * Объявлен здесь, а не взят из <linux/virtio_net.h>: тот тянет virtio_types и с musl
 * собирается не на всех версиях ядерных headers, а нам нужны ровно эти десять байт.
 *
 * Числа в ПОРЯДКЕ ХОСТА, а не в сетевом. Это не небрежность: tun согласовывает порядок
 * только через VIRTIO_F_VERSION_1, которого он не объявляет, поэтому ядро читает поля
 * как __virtio16 в legacy-режиме — то есть родным порядком. Среди целей сборки есть
 * mips_24kc, он big-endian; фиксированный little-endian сломал бы разгрузку именно на нём,
 * и выглядело бы это как «на одной архитектуре пакеты не доходят». */
struct vnet_hdr {
    uint8_t flags;
    uint8_t gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
};
#define VNET_HDR_LEN 10
#define VNET_F_NEEDS_CSUM 1
#define VNET_GSO_NONE     0
#define VNET_GSO_TCPV4    1
/* Признак ECN приезжает в старшем бите типа разгрузки: на сам разбор он не влияет, но сравнивать
 * тип с ним нельзя — иначе склеенное с ECN мы бы отвергли как незнакомое. */
#define VNET_GSO_ECN      0x80
/* Раскладка обязана совпасть с ядерной побайтово: лишний байт выравнивания сдвинул бы
 * всё, и ядро прочитало бы gso_size там, где лежит csum_start. */
typedef char vnet_hdr_size_check[sizeof(struct vnet_hdr) == VNET_HDR_LEN ? 1 : -1];

/* Одна попытка открыть очередь с заданным набором флагов.
 *
 * errno сохраняется в g_open_errno: перебор наборов флагов затирает его следующей попыткой,
 * а причина нужна именно от ПЕРВОЙ — она отвечает на вопрос «почему устройства нет вовсе»,
 * тогда как последняя расскажет лишь про отказ от последнего украшения. */
static int g_open_errno;
static int g_open_stage;      /* 1 — не открылся узел TUN, 2 — отказал TUNSETIFF,
                                 3 — ядро создало устройство с другим именем */
static char g_open_got[IFNAMSIZ];   /* имя, которое вернуло ядро при stage 3 */

static int queue_open(const char *name, short flags) {
    int fd = open(plat()->tun_dev, O_RDWR);
    if (fd < 0) {
        if (!g_open_errno) { g_open_errno = errno; g_open_stage = 1; }
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", name);
    ifr.ifr_flags = flags;
    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        if (!g_open_errno) { g_open_errno = errno; g_open_stage = 2; }
        close(fd);
        return -1;
    }
    /* Ядро возвращает в ifr_name имя, которое СОЗДАЛО, и оно не обязано совпадать с
     * запрошенным: длиннее IFNAMSIZ-1 усекается молча (измерено: xs-abcdefghijklm ->
     * xs-abcdefghijkl). Не прочитав поле обратно, движок продолжал работать с именем из
     * настроек, которого в системе нет: очереди открыты и туннель жив, а tun_bring_up и
     * bind_device адресуют несуществующее устройство — три `ip` через run_quiet, три
     * проглоченных отказа, «интерфейс поднят, трафика нет» (I-107).
     *
     * Отказ, а не «взять имя ядра». Имя устройства знает не только движок: на него заведены
     * зона firewall, таблица маршрутизации и обработчик netifd, и всё это создано управляющим
     * слоем по имени из настроек. Приняв другое имя, движок разошёлся бы не с ядром, а с ними
     * — то есть та же тишина, только на шаг дальше. Реализация на Go читает имя обратно
     * (tun/tun_linux.go) и теперь так же отказывается, если оно не то. */
    if (strncmp(ifr.ifr_name, name, IFNAMSIZ) != 0) {
        if (!g_open_errno) {
            g_open_errno = ENAMETOOLONG;
            g_open_stage = 3;
            snprintf(g_open_got, sizeof(g_open_got), "%.*s", IFNAMSIZ - 1, ifr.ifr_name);
        }
        close(fd);
        return -1;
    }
    return fd;
}

/* Попросить ядро отдавать нам СКЛЕЕННОЕ. Отказ — не отказ подъёма: без него работает прежний путь
 * по одному пакету, только медленнее.
 *
 * TUN_F_CSUM обязателен: без него ядро не отдаёт ни склеенного, ни с неполной суммой, а TUN_F_TSO4
 * без него не принимается вовсе. TSO6 не просим — см. объяснение у поля rx_gso. */
static int queue_rx_gso(int fd) {
    unsigned feat = TUN_F_CSUM | TUN_F_TSO4;
    return ioctl(fd, TUNSETOFFLOAD, feat) == 0 ? 0 : -1;
}

int tun_adopt_fd(struct tun_dev *d, int fd) {
    int copy = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (copy < 0) {
        fprintf(stderr, "steer[warn] tunnel: устройство хоста (дескриптор %d) не взялось: %s\n", fd,
                strerror(errno));
        return TUN_ESETUP;
    }
    memset(d, 0, sizeof(*d));
    d->fd = copy;
    return 1;
}

int tun_open(struct tun_dev *d, int max_queues, const char *name) {
    /* IFF_NO_PI: без 4-байтного префикса протокола. Он нужен только тому, кто хочет
     * различать семейства на одном устройстве, а у нас IPv4 и разбор всё равно по
     * заголовку пакета.
     *
     * IFF_VNET_HDR: разрешает писать в устройство сегмент больше MTU с пометкой «нарежь
     * по столько», а контрольную сумму TCP оставить недосчитанной.
     *
     * IFF_MULTI_QUEUE: несколько дескрипторов на одно устройство, по одному на поток.
     *
     * Порядок попыток — от лучшего к худшему, и каждая следующая отказывается ровно от
     * одного. Ядро без той или иной поддержки не должно ронять туннель: остаться без
     * УСКОРЕНИЯ можно, остаться без туннеля нельзя.
     *
     * TUNSETOFFLOAD теперь вызывается — см. объяснение у поля rx_gso в tun.h. Коротко: буфер под
     * склеенное нужен ОДИН на очередь и живёт внутри этого файла, а выигрыш на приёме измерен и
     * оказался того же порядка, что на отдаче. */
    short base = IFF_TUN | IFF_NO_PI;
    /* STEER_TUN_NOGSO отключает разгрузку принудительно. Нужно для замеров: «стало быстрее»
     * без возможности вернуться на прежний путь одной переменной — это утверждение, которое
     * нельзя перепроверить на том же железе и той же подписке. */
    int want_gso = getenv("STEER_TUN_NOGSO") == NULL;
    /* Склейка — отдельным переключателем от разгрузки: с ней сравнивают, а не отключают
     * вместе с заголовком vnet, иначе замер мешал бы два изменения в одно. */
    int want_gro = getenv("STEER_TUN_NOGRO") == NULL;
    /* Приём склеенного — третьим переключателем, отдельно от первых двух: с ним сравнивают. */
    int want_rx = getenv("STEER_TUN_NORXGSO") == NULL;
    if (max_queues < 1) max_queues = 1;

    static const struct { int gso, multi; } order[] = {
        { 1, 1 }, { 1, 0 }, { 0, 1 }, { 0, 0 },
    };
    for (size_t i = 0; i < sizeof(order) / sizeof(*order); i++) {
        if (order[i].gso && !want_gso) continue;
        if (order[i].multi && max_queues < 2) continue;
        short flags = base;
        if (order[i].gso) flags |= IFF_VNET_HDR;
        if (order[i].multi) flags |= IFF_MULTI_QUEUE;

        int fd = queue_open(name, flags);
        /* Другое имя — не про набор флагов: следующая попытка получит то же усечение. Выходим
         * сразу, иначе устройство создаётся и удаляется четыре раза подряд впустую. */
        if (fd < 0 && g_open_stage == 3) break;
        if (fd < 0) continue;
        /* ОБНУЛЯЕМ ЦЕЛИКОМ, а не только присваиваем известные поля.
         *
         * Вызывающие объявляют массив очередей БЕЗ инициализации (`struct tun_dev tq[...]` на
         * стеке), а у структуры есть состояние, которое обязано начинаться с нуля: указатель на
         * буфер разбора склеенного, счётчики сегментов и длина отложенного одиночного пакета.
         * Пока эта функция присваивала только fd, gso и gro, всё это оставалось мусором со стека —
         * и разбор шёл по случайному указателю.
         *
         * Стоило это падения, которое нашлось только живым стендом и только в сборке с LTO: при -O0
         * мусор случайно оказывался нулями, а при LTO раскладка стека менялась, и memcpy уходил по
         * адресу 0xfd0c. То есть «работает» и «не работает» здесь зависело от ключей компилятора —
         * худший вид ошибки, какой можно оставить. */
        memset(&d[0], 0, sizeof(d[0]));
        d[0].fd = fd;
        d[0].gso = order[i].gso;
        d[0].gro = order[i].gso && want_gro;
        d[0].rx_gso = order[i].gso && want_rx && queue_rx_gso(fd) == 0;

        int n = 1;
        if (order[i].multi) {
            /* Остальные очереди — теми же флагами. Сколько дали, столько и берём: отказ на
             * пятой очереди не повод отказываться от четырёх уже открытых. */
            while (n < max_queues) {
                int extra = queue_open(name, flags);
                if (extra < 0) break;
                memset(&d[n], 0, sizeof(d[n]));
                d[n].fd = extra;
                d[n].gso = order[i].gso;
                d[n].gro = order[i].gso && want_gro;
                d[n].rx_gso = order[i].gso && want_rx && queue_rx_gso(extra) == 0;
                n++;
            }
        }
        return n;
    }
    /* Ни один набор флагов не подошёл. Молча вернуть код нельзя: он доходил до человека
     * только как код выхода процесса — и не как 40 или 41, а как 216 или 215, потому что
     * отрицательное возвращённое из main обрезается до байта. В журнале при этом не было
     * ни строки, и «туннель не поднялся» выглядело как «туннель просто не работает». */
    if (g_open_stage == 1 && (g_open_errno == ENOENT || g_open_errno == ENXIO ||
                              g_open_errno == ENODEV)) {
        fprintf(stderr, "steer[warn] tunnel: нет %s (%s) — %s\n", plat()->tun_dev,
                strerror(g_open_errno), plat()->tun_hint);
        return TUN_ENODEV;
    }
    if (g_open_stage == 3) {
        fprintf(stderr, "steer[warn] tunnel: ядро создало устройство с другим именем: "
                "просили %s, получили %s%s\n", name, g_open_got,
                strlen(name) >= IFNAMSIZ
                    ? " — имя длиннее предела ядра (IFNAMSIZ, 15 значащих символов)" : "");
        return TUN_ESETUP;
    }
    fprintf(stderr, "steer[warn] tunnel: устройство %s не создалось: %s (%s%s)\n", name,
            strerror(g_open_errno ? g_open_errno : EINVAL),
            g_open_stage == 1 ? "не открылся " : "отказал TUNSETIFF",
            g_open_stage == 1 ? plat()->tun_dev : "");
    return TUN_ESETUP;
}

/* Суммы определены ниже (там же, где их прежний потребитель), поэтому здесь — объявления: тащить
 * их выше значило бы разлучить их с объяснением, ради экономии одной строки. */
static uint32_t csum_add(const unsigned char *d, size_t n, uint32_t acc);
static uint16_t csum_fin(uint32_t acc);

/* Сумма сегмента TCP с псевдозаголовком, средствами ЭТОГО файла.
 *
 * Своя, а не obfs_tcp_csum: тянуть obfs.c ради одной функции значило бы притащить его в два стенда,
 * которым он не нужен, и завести им заглушки внешних символов. Складываемые слова те же, проход тот
 * же — здесь просто нет ничего, чего бы у этого файла уже не было. */
static uint16_t seg_tcp_csum(const unsigned char *ip4, const unsigned char *th, size_t th_n) {
    unsigned char ph[12];
    memcpy(ph, ip4 + 12, 4);
    memcpy(ph + 4, ip4 + 16, 4);
    ph[8] = 0;
    ph[9] = 6;                       /* IPPROTO_TCP */
    ph[10] = (unsigned char)(th_n >> 8);
    ph[11] = (unsigned char)(th_n & 0xFF);
    return csum_fin(csum_add(th, th_n, csum_add(ph, sizeof(ph), 0)));
}

/* ---- разбор СКЛЕЕННОГО, приехавшего от ядра ---------------------------------
 *
 * Ядро отдаёт один кадр вместо сорока пяти: общие заголовки, вся нагрузка подряд и размер сегмента
 * в метаданных. Наружу мы обязаны отдать ровно те пакеты, которые пришли бы без склейки, — иначе
 * стек той стороны увидит поток, которого не бывает, а это худший класс отказов: туннель поднят,
 * трафик идёт, часть соединений встаёт.
 *
 * Фиксовки повторяют tcp_gso_segment и inet_gso_segment ядра, и повторяют по причине, а не по
 * симметрии: номер последовательности сдвигается на СМЕЩЕНИЕ В НАГРУЗКЕ, идентификатор IP растёт на
 * сегмент, FIN и PSH достаются ТОЛЬКО последнему, обе суммы считаются заново. Оставить FIN на
 * каждом сегменте значило бы закрыть соединение той стороны на первом же куске склейки. */
static ssize_t seg_emit(struct tun_dev *d, unsigned char *buf, size_t cap) {
    size_t i = (size_t)d->seg_i;
    d->seg_i++;
    size_t off = i * d->seg_gso;
    size_t end = off + d->seg_gso;
    if (end > d->seg_body) end = d->seg_body;
    int last = d->seg_i >= d->seg_n;
    size_t n = d->seg_hdr + (end - off);
    if (n > cap) { d->rx_dropped++; return 0; }
    unsigned char *pkt = d->rx + VNET_HDR_LEN;
    memcpy(buf, pkt, d->seg_hdr);
    memcpy(buf + d->seg_hdr, pkt + d->seg_hdr + off, end - off);

    buf[2] = (unsigned char)(n >> 8);
    buf[3] = (unsigned char)(n & 0xFF);
    uint16_t id = (uint16_t)(d->seg_id + (uint16_t)i);
    buf[4] = (unsigned char)(id >> 8);
    buf[5] = (unsigned char)(id & 0xFF);
    buf[10] = buf[11] = 0;
    uint16_t ipck = csum_fin(csum_add(buf, 20, 0));
    buf[10] = (unsigned char)(ipck >> 8);
    buf[11] = (unsigned char)(ipck & 0xFF);

    unsigned char *th = buf + 20;
    uint32_t seq = d->seg_seq + (uint32_t)off;
    th[4] = (unsigned char)(seq >> 24); th[5] = (unsigned char)(seq >> 16);
    th[6] = (unsigned char)(seq >> 8);  th[7] = (unsigned char)(seq & 0xFF);
    th[13] = last ? d->seg_flags : (unsigned char)(d->seg_flags & ~(unsigned char)0x09);
    th[16] = th[17] = 0;
    uint16_t tck = seg_tcp_csum(buf, th, n - 20);
    th[16] = (unsigned char)(tck >> 8);
    th[17] = (unsigned char)(tck & 0xFF);
    return (ssize_t)n;
}

/* Разобрать только что прочитанный кадр: либо это одиночный пакет (возможно, с НЕПОЛНОЙ суммой,
 * которую ядро оставило устройству, — её мы обязаны достроить), либо склеенный супер-кадр. */
static void seg_take(struct tun_dev *d, size_t frame_n) {
    const struct vnet_hdr *vh = (const struct vnet_hdr *)(const void *)d->rx;
    unsigned char *pkt = d->rx + VNET_HDR_LEN;
    size_t pkt_n = frame_n - VNET_HDR_LEN;
    d->seg_i = d->seg_n = 0;
    d->single = 0;

    unsigned char gso_type = (unsigned char)(vh->gso_type & (unsigned char)~VNET_GSO_ECN);
    if (gso_type == VNET_GSO_NONE) {
        /* Неполная сумма: в поле лежит сумма псевдозаголовка, тело не просуммировано. Так ядро
         * отдаёт пакеты СВОИХ сокетов. Отправить такой пакет в туннель как есть значит отдать той
         * стороне пакет, который её же стек молча выбросит. Поле входит в считаемый отрезок, поэтому
         * отдельного слагаемого не нужно — то же самое делает ядро в skb_checksum_help. */
        if (vh->flags & VNET_F_NEEDS_CSUM) {
            size_t st = vh->csum_start, of = vh->csum_offset;
            if (st + of + 2 > pkt_n) { d->rx_dropped++; return; }
            uint16_t ck = csum_fin(csum_add(pkt + st, pkt_n - st, 0));
            pkt[st + of] = (unsigned char)(ck >> 8);
            pkt[st + of + 1] = (unsigned char)(ck & 0xFF);
        }
        d->single = pkt_n;
        return;
    }
    /* Склеенное. Принимаем только то, что умеем разложить: TSO6 мы у ядра не просили, и всё
     * прочее — в счётчик, а не наугад. */
    if (gso_type != VNET_GSO_TCPV4) { d->rx_dropped++; return; }
    size_t hdr_n = vh->hdr_len, gso = vh->gso_size;
    if (!gso || hdr_n < 40 || hdr_n > pkt_n) { d->rx_dropped++; return; }
    if (pkt[0] != 0x45 || pkt[9] != 6) { d->rx_dropped++; return; }
    /* Длина заголовков считается ПО ПАКЕТУ, а не берётся из hdr_len. Ядро пишет в hdr_len
     * skb_headlen — «сколько линейной части», и это подсказка, а не длина заголовков: у
     * пакета собственного сокета линейная часть — ровно заголовки, а у ФОРВАРДИМОГО
     * склеенного (клиент локальной сети → роутер → TUN) линейной может быть весь первый
     * пакет. Прежнее требование `20 + doff == hdr_len` выбрасывало такой супер-кадр целиком
     * в rx_dropped, клиент повторял, ядро склеивало снова — и так до конца потока. hdr_len
     * остаётся нижней границей проверки: короче заголовков он быть не может. Половина на Go
     * (tun/offload_linux.go) поступает так же. */
    size_t doff = (size_t)(pkt[32] >> 4) * 4;
    size_t seg_hdr = 20 + doff;
    if (doff < 20 || seg_hdr > hdr_n) { d->rx_dropped++; return; }
    d->seg_hdr = seg_hdr;
    d->seg_body = pkt_n - seg_hdr;
    d->seg_gso = gso;
    d->seg_n = (int)((d->seg_body + gso - 1) / gso);
    if (d->seg_n <= 0) { d->rx_dropped++; d->seg_n = 0; return; }
    uint32_t sq;
    memcpy(&sq, pkt + 24, 4);
    d->seg_seq = ntohl(sq);
    d->seg_id = (uint16_t)(((uint16_t)pkt[4] << 8) | pkt[5]);
    d->seg_flags = pkt[33];
}

ssize_t tun_read_packet(struct tun_dev *d, unsigned char *buf, size_t cap) {
    if (!d->gso) return read(d->fd, buf, cap);
    if (!d->rx_gso) {
        /* Заголовок разгрузки приезжает и на чтении — он нам не нужен (без TUNSETOFFLOAD ядро
         * отдаёт обычные пакеты), но снять его обязаны, иначе разбор поедет на десять байт. */
        struct vnet_hdr vh;
        struct iovec iov[2] = { { &vh, sizeof(vh) }, { buf, cap } };
        ssize_t r = readv(d->fd, iov, 2);
        if (r <= (ssize_t)sizeof(vh)) return r <= 0 ? r : 0;
        return r - (ssize_t)sizeof(vh);
    }
    /* Буфер выделяется ЛЕНИВО: очередей бывает до четырёх, и 64 КБ на каждую там, где склейка не
     * пригодилась, — впустую. Не выделился — работаем прежним путём, а не падаем. */
    if (!d->rx) {
        d->rx = malloc(VNET_HDR_LEN + TUN_FRAME_MAX);
        if (!d->rx) { d->rx_gso = 0; return tun_read_packet(d, buf, cap); }
    }
    for (;;) {
        if (d->single) {
            size_t n = d->single;
            d->single = 0;
            if (n > cap) { d->rx_dropped++; continue; }
            memcpy(buf, d->rx + VNET_HDR_LEN, n);
            return (ssize_t)n;
        }
        if (d->seg_i < d->seg_n) {
            ssize_t n = seg_emit(d, buf, cap);
            if (n > 0) return n;
            continue;
        }
        ssize_t r = read(d->fd, d->rx, VNET_HDR_LEN + TUN_FRAME_MAX);
        if (r <= (ssize_t)VNET_HDR_LEN) return r <= 0 ? r : 0;
        seg_take(d, (size_t)r);
    }
}

/* ---- разбор IP-заголовка --------------------------------------------------- */
/* Только то, что нужно для маршрутизации соединения: адреса, порты, флаги TCP. Полного
 * разбора нет намеренно — чем меньше кода трогает недоверенные байты из сети, тем меньше
 * места для ошибки в нём. */
int ip_parse(const unsigned char *p, size_t n, struct flow_key *k, size_t *payload_off) {
    if (n < 20) return -1;
    size_t ihl;
    if ((p[0] >> 4) == 6) {
        /* IPv6: фиксированный заголовок 40 байт. За ним — TCP, UDP или заголовок фрагментации (RFC 8200:
         * смещение в 8-байтовых блоках — старшие 13 бит, M — младший). Другие расширения разбирать
         * нечем (hop-by-hop, маршрутизация и параметры получателя пользовательский UDP и TCP не несут), и
         * такой пакет отвергается: допустить их значило бы дать двум пакетам одного потока разные хэши
         * раздачи по рабочим (tun_flow_owner смотрит только на следующий заголовок). */
        if (n < 40) return -1;
        size_t plen = ((size_t)p[4] << 8) | p[5];
        if (plen + 40 > n) return -1;
        k->v6 = 1;
        memcpy(k->src6, p + 8, 16);
        memcpy(k->dst6, p + 24, 16);
        k->proto = p[6];
        k->frag = 0;
        ihl = 40;
        if (p[6] == 44) {
            if (n < 48) return -1;
            unsigned fo = (unsigned)((p[42] << 8) | p[43]);
            if (fo & 0xFFF8) return -1;              /* не первый фрагмент — заголовка нет */
            k->frag = (fo & 1) ? 1 : 0;
            k->proto = p[40];
            ihl = 48;
        }
        goto l4;
    }
    if ((p[0] >> 4) != 4) return -1;
    ihl = (size_t)(p[0] & 0x0F) * 4;
    if (ihl < 20 || n < ihl) return -1;

    k->v6 = 0;
    k->proto = p[9];
    memcpy(&k->src, p + 12, 4);
    memcpy(&k->dst, p + 16, 4);

    /* Фрагменты. Раньше эти два байта не читались вовсе, и для TCP это проходило
     * незамеченным: в продолжении фрагмента на месте заголовка лежат данные, из них
     * выходили случайные порты, соединение по ним не находилось, и пакет тихо пропадал —
     * то есть верный итог по неверной причине.
     *
     * Для UDP такой итог уже не годится: случайные порты — это НОВЫЙ поток, а новый поток
     * означает рукопожатие с узлом. Мусорный фрагмент открывал бы сессию к узлу.
     *
     * Продолжение фрагмента (смещение не ноль) разобрать нечем — заголовка в нём нет,
     * поэтому отказ. У первого фрагмента заголовок есть, но датаграмма неполна: он
     * размечается флагом, а решает вызывающий (см. handle_packet). */
    unsigned frag = (unsigned)((p[6] << 8) | p[7]);
    if (frag & 0x1FFF) return -1;                    /* не первый фрагмент — заголовка нет */
    k->frag = (frag & 0x2000) ? 1 : 0;               /* MF: продолжение будет */

l4:
    if (k->proto == 6) {                             /* TCP */
        if (n < ihl + 20) return -1;
        const unsigned char *t = p + ihl;
        k->sport = (uint16_t)((t[0] << 8) | t[1]);
        k->dport = (uint16_t)((t[2] << 8) | t[3]);
        size_t doff = (size_t)(t[12] >> 4) * 4;
        if (doff < 20 || n < ihl + doff) return -1;
        k->tcp_flags = t[13];
        k->window = (uint16_t)((t[14] << 8) | t[15]);
        /* Масштаб окна из опций SYN (kind 3, RFC 7323).
         *
         * Без него объявленное окно читается как 16 бит, то есть максимум 64 КБ, — а
         * современный клиент присылает 65535 со множителем и имеет в виду мегабайты.
         * Считать его буквально значит держать в пути не больше 64 КБ и упереться в это
         * задолго до полосы: при подтверждениях раз в 5 мс это 13 МБ/с потолка.
         *
         * Опции разбираются только в SYN: дальше их не бывает, а множитель постоянен на
         * всё соединение. */
        k->wscale = 0;
        k->ws_seen = 0;
        if ((k->tcp_flags & TCP_SYN) && doff > 20) {
            size_t o = ihl + 20, end = ihl + doff;
            while (o < end && o < n) {
                unsigned char kind = p[o];
                if (kind == 0) break;                 /* конец списка опций */
                if (kind == 1) { o++; continue; }     /* заполнитель */
                if (o + 1 >= end) break;
                unsigned char olen = p[o + 1];
                if (olen < 2 || o + olen > end) break;
                if (kind == 3 && olen == 3) {
                    k->wscale = p[o + 2] > 14 ? 14 : p[o + 2];
                    k->ws_seen = 1;
                    break;
                }
                o += olen;
            }
        }
        k->seq = ((uint32_t)t[4] << 24) | ((uint32_t)t[5] << 16) |
                 ((uint32_t)t[6] << 8) | t[7];
        k->ack = ((uint32_t)t[8] << 24) | ((uint32_t)t[9] << 16) |
                 ((uint32_t)t[10] << 8) | t[11];
        if (payload_off) *payload_off = ihl + doff;
        return 0;
    }
    if (k->proto == 17) {                            /* UDP */
        if (n < ihl + 8) return -1;
        const unsigned char *u = p + ihl;
        k->sport = (uint16_t)((u[0] << 8) | u[1]);
        k->dport = (uint16_t)((u[2] << 8) | u[3]);
        if (payload_off) *payload_off = ihl + 8;
        return 0;
    }
    return -1;
}

/* ---- контрольные суммы ----------------------------------------------------- */
/* Считаются здесь, а не берутся у ядра: пакеты, которые мы синтезируем для клиента,
 * ядро не проверяет на выходе из TUN, но проверит стек клиента. Неверная сумма означает
 * молча отброшенный пакет — то есть соединение, которое «висит» без ошибки. */
static uint32_t csum_add(const unsigned char *d, size_t n, uint32_t acc) {
    /* Словами по четыре байта, а не байтовыми парами: memcpy сворачивается в
     * одну неупорядоченную загрузку, ntohl — в перестановку байтов (на BE — в
     * ничто), и на каждые 4 байта остаётся два сложения вместо четырёх
     * загрузок со сдвигами. Через эту функцию идёт каждый UDP-пакет к клиенту
     * и весь поток при выключенной разгрузке — на роутерном ядре это заметно.
     *
     * Сумма ТА ЖЕ САМАЯ, а не «эквивалентная по свёртке»: складываются те же
     * 16-битные слова, только парами за шаг, и переполнение uint32 недостижимо
     * (даже 64 КБ данных дают < 2^31), так что и сырое значение acc совпадает
     * с прежним побитово. */
    size_t i = 0;
    for (; i + 4 <= n; i += 4) {
        uint32_t w;
        memcpy(&w, d + i, 4);
        w = ntohl(w);
        acc += (w >> 16) + (w & 0xFFFF);
    }
    for (; i + 1 < n; i += 2)
        acc += ((uint32_t)d[i] << 8) | d[i + 1];
    if (n & 1) acc += (uint32_t)d[n - 1] << 8;
    return acc;
}
static uint16_t csum_fin(uint32_t acc) {
    while (acc >> 16) acc = (acc & 0xFFFF) + (acc >> 16);
    return (uint16_t)~acc;
}

/* Собрать TCP-пакет для отправки клиенту. Адреса и порты меняются местами: мы отвечаем
 * от имени того, к кому клиент обращался. */
/* Сумма псевдозаголовка TCP: адреса, протокол, длина. */
static uint32_t tcp_pseudo_sum(uint32_t src, uint32_t dst, size_t tcp_len) {
    unsigned char pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0; pseudo[9] = 6;
    pseudo[10] = (unsigned char)(tcp_len >> 8); pseudo[11] = (unsigned char)tcp_len;
    return csum_add(pseudo, 12, 0);
}

/* Сумма псевдозаголовка IPv6 (RFC 8200, 8.1): адреса, длина верхнего уровня (32 бита), следующий заголовок. */
static uint32_t pseudo6_sum(const unsigned char *src, const unsigned char *dst, size_t len, unsigned char nh) {
    unsigned char ph[40];
    memcpy(ph, src, 16);
    memcpy(ph + 16, dst, 16);
    ph[32] = (unsigned char)(len >> 24); ph[33] = (unsigned char)(len >> 16);
    ph[34] = (unsigned char)(len >> 8);  ph[35] = (unsigned char)len;
    ph[36] = ph[37] = ph[38] = 0;
    ph[39] = nh;
    return csum_add(ph, sizeof(ph), 0);
}

/* Очередь записи в устройство (I-534). Раньше при EAGAIN поток цикла стоял в poll по миллисекунде, до 200
 * раз: заполненная очередь устройства останавливала ВСЕ соединения потока на срок до 200 мс, хотя клиенту
 * нужна была одна датаграмма. Теперь не доставшаяся датаграмма уходит в очередь потока, а цикл идёт дальше:
 * когда устройство снова принимает (EPOLLOUT, stack.c), очередь сливается по порядку — порядок пакетов
 * сохраняется, запись в обход очереди его бы переставила.
 *
 * Предел очереди — TUN_WQ_MAX байт на поток: это та же очередь, что ядро держит у устройства
 * (txqueuelen 500 пакетов — три четверти мегабайта), только пережидающая пики, и память у неё не должна
 * расти без счёта. Дальше датаграмма отбрасывается и считается — как у любого UDP при перегрузке; у
 * соединения конца это не вызывает. Отбрасывание обратным давлением не лечится: UDP клиента отправителя
 * не слышит. */
#define TUN_WQ_MAX (4u << 20)

struct tun_wq_pkt {
    struct tun_wq_pkt *next;
    int fd;
    size_t n;
    unsigned char d[];
};
static __thread struct {
    struct tun_wq_pkt *head, *tail;
    size_t bytes;
    unsigned long long dropped;
} g_wq;

int tun_wq_pending(void) { return g_wq.head != NULL; }
unsigned long long tun_wq_dropped(void) { return g_wq.dropped; }

/* Слить очередь, пока устройство принимает. 0 — пусто, 1 — устройство снова занято (ждать EPOLLOUT),
 * -1 — устройство сломано (очередь брошена). */
int tun_wq_flush(void) {
    while (g_wq.head) {
        struct tun_wq_pkt *p = g_wq.head;
        ssize_t w = write(p->fd, p->d, p->n);
        if (w < 0 && errno == EINTR) continue;
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return 1;
        /* Записано или отказано насовсем (устройство закрыто, пакет не принят ядром): пакет уходит из
         * очереди — повтор того, что ядро отвергло, не имеет смысла, а хвост ждать не должен. */
        g_wq.head = p->next;
        if (!g_wq.head) g_wq.tail = NULL;
        g_wq.bytes -= p->n;
        free(p);
    }
    return 0;
}

void tun_wq_free(void) {
    while (g_wq.head) {
        struct tun_wq_pkt *p = g_wq.head;
        g_wq.head = p->next;
        free(p);
    }
    g_wq.tail = NULL;
    g_wq.bytes = 0;
}

/* Записать пакет (iov — заголовок vnet и сам пакет). 0 — записан или в очереди (и отброшенный по
 * пределу очереди — тоже 0: потеря UDP не рвёт соединение), -1 — устройство отказало насовсем. */
static int tun_writev(const struct tun_dev *d, struct iovec *iov, int n) {
    if (g_wq.head && tun_wq_flush() < 0) return -1;
    if (!g_wq.head) {
        for (;;) {
            if (writev(d->fd, iov, n) >= 0) return 0;
            if (errno == EINTR) continue;
            break;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) return -1;
    }
    size_t len = 0;
    for (int i = 0; i < n; i++) len += iov[i].iov_len;
    if (g_wq.bytes + len > TUN_WQ_MAX) {
        static __thread time_t said;
        time_t now = time(NULL);
        if (!g_wq.dropped++ || now - said >= 10) {
            said = now;
            fprintf(stderr, "steer[warn] tunnel: очередь записи в устройство полна (%u КиБ) — датаграммы "
                            "клиенту отбрасываются; всего отброшено %llu\n", TUN_WQ_MAX >> 10, g_wq.dropped);
        }
        return 0;
    }
    struct tun_wq_pkt *p = malloc(sizeof(*p) + len);
    if (!p) { g_wq.dropped++; return 0; }
    p->next = NULL;
    p->fd = d->fd;
    p->n = len;
    size_t off = 0;
    for (int i = 0; i < n; i++) {
        memcpy(p->d + off, iov[i].iov_base, iov[i].iov_len);
        off += iov[i].iov_len;
    }
    if (g_wq.tail) g_wq.tail->next = p; else g_wq.head = p;
    g_wq.tail = p;
    g_wq.bytes += len;
    return 0;
}

void tun_write_ctl(const struct tun_dev *d, const unsigned char *pkt, size_t n) {
    struct iovec iov[2];
    int i = 0;
    struct vnet_hdr vh;
    if (d->gso) {
        /* Суммы в служебном пакете уже посчитаны, поэтому ядру сообщаем «ничего не надо». */
        memset(&vh, 0, sizeof(vh));
        vh.gso_type = VNET_GSO_NONE;
        iov[i].iov_base = &vh;
        iov[i].iov_len = sizeof(vh);
        i++;
    }
    iov[i].iov_base = (void *)(uintptr_t)pkt;
    iov[i].iov_len = n;
    i++;
    /* Без повторов и без проверки: потерянный SYN-ACK или ACK клиент пришлёт заново сам,
     * а вешать на это ожидание значило бы задержать весь цикл ради пакета без данных. */
    (void)!writev(d->fd, iov, i);
}

/* ---- склейка соседних сегментов в одну запись -------------------------------
 *
 * Обоснование, условия и цена — в tun.h. Здесь только арифметика.
 */

/* Разобрать пакет настолько, насколько нужно склейке. 0 — годен, -1 — нет.
 *
 * Требования жёсткие: IPv4 без опций, TCP без опций, не фрагмент, флаги ровно ACK или
 * ACK|PSH. Всё остальное отдаётся отдельной записью — склеить лишнее означает отдать
 * клиенту испорченный поток, и заметить это можно только дампом. */
static int gro_parse(const unsigned char *p, size_t n, size_t *hdr_n, size_t *pay_n,
                    uint32_t *seq) {
    if (n < 40) return -1;
    if (p[0] != 0x45) return -1;                       /* IPv4, ihl 20, без опций IP */
    if (p[9] != 6) return -1;                          /* TCP */
    /* Фрагменты: смещение обязано быть нулевым, флаг MF снят. DF (0x40) допустим. */
    if ((p[6] & 0x3F) != 0 || p[7] != 0) return -1;
    if ((p[6] & 0x20) != 0) return -1;                 /* MF */
    size_t tot = ((size_t)p[2] << 8) | p[3];
    if (tot != n || tot < 40) return -1;
    /* ОПЦИИ TCP РАЗРЕШЕНЫ, и это не мелочь: Linux по умолчанию включает метки времени, то
     * есть заголовок у обычного сегмента 32 байта, а не 20. Первая версия этой склейки
     * требовала «без опций» и поэтому не склеивала НИ ОДНОГО пакета живого потока —
     * счётчики показали 100% отказов разбора. Опции склейке не мешают, потому что ядро при
     * нарезке копирует заголовок целиком в каждый кусок; условие ниже требует, чтобы у
     * склеиваемых пакетов байты опций были ОДИНАКОВЫ, — тогда результат нарезки совпадает с
     * тем, что отправитель послал бы одним суперкадром. Так же поступает аппаратный GRO. */
    size_t doff = (size_t)(p[32] >> 4) * 4;
    if (doff < 20 || doff > 60 || 20 + doff >= tot) return -1;
    *hdr_n = 20 + doff;
    unsigned char fl = p[33];
    /* SYN, FIN, RST, URG — смена состояния соединения; такие пакеты не склеиваем вовсе,
     * хотя ядро и умеет ставить FIN на последний кусок: цена ошибки здесь несоизмерима с
     * выигрышем на одном пакете за соединение. */
    if (fl & ~(unsigned char)0x18) return -1;          /* разрешены только ACK и PSH */
    if (!(fl & 0x10)) return -1;                       /* ACK обязателен */
    *pay_n = tot - *hdr_n;
    if (*pay_n == 0) return -1;                        /* голое подтверждение склеивать нечего */
    uint32_t s;
    memcpy(&s, p + 24, 4);
    *seq = ntohl(s);
    return 0;
}

/* Тот же поток и та же обстановка, что у уже накопленного? Сравниваются адреса, порты,
 * ttl, tos, номер подтверждения и окно: ядро при нарезке КОПИРУЕТ заголовок первого пакета
 * во все куски, меняя только номер, сумму и флаги последнего. Значит склеивать пакеты с
 * разным окном или подтверждением нельзя — получатель увидел бы в ранних сегментах поздние
 * значения. */
static int gro_same(const unsigned char *a, const unsigned char *b, size_t hdr_n) {
    if (a[1] != b[1] || a[8] != b[8]) return 0;        /* tos, ttl */
    if (memcmp(a + 12, b + 12, 8) != 0) return 0;      /* адреса */
    if (memcmp(a + 20, b + 20, 4) != 0) return 0;      /* порты */
    if (memcmp(a + 28, b + 28, 4) != 0) return 0;      /* номер подтверждения */
    if (a[32] != b[32]) return 0;                      /* длина заголовка TCP */
    if (memcmp(a + 34, b + 34, 2) != 0) return 0;      /* окно */
    /* Опции TCP байт в байт: ядро скопирует опции ПЕРВОГО пакета во все куски, поэтому
     * разные метки времени в склеенном наборе означали бы, что получатель увидит не то, что
     * ему отправили. */
    if (hdr_n > 40 && memcmp(a + 40, b + 40, hdr_n - 40) != 0) return 0;
    return 1;
}

void tun_gro_flush(const struct tun_dev *d, struct tun_gro *g) {
    if (g->frames <= 0) { tun_gro_reset(g); return; }
    if (g->frames == 1) {
        /* Один пакет — ровно прежнее поведение: суммы в нём уже верные (он пришёл таким из
         * туннеля), поэтому ядру говорим «ничего считать не надо». */
        tun_write_ctl(d, g->first, g->hdr_n + g->seg);
        tun_gro_reset(g);
        return;
    }
    unsigned char *p = g->first;
    size_t tot = g->hdr_n + g->total_pay;
    /* Длина всего склеенного в заголовке IP: по ней ядро и поймёт, что резать. */
    p[2] = (unsigned char)(tot >> 8);
    p[3] = (unsigned char)(tot & 0xFF);
    p[10] = p[11] = 0;
    uint16_t ipsum = csum_fin(csum_add(p, 20, 0));
    p[10] = (unsigned char)(ipsum >> 8);
    p[11] = (unsigned char)ipsum;
    /* Сумма TCP — НЕДОСЧИТАННАЯ, только псевдозаголовок, в том же виде, что готовит себе
     * ядро в __tcp_v4_send_check (см. подробное объяснение в tun_write_data: инвертировать
     * её здесь ещё раз означало бы отдать сумму, которая не сойдётся ни у одного куска). */
    uint32_t src, dst;
    memcpy(&src, p + 12, 4);
    memcpy(&dst, p + 16, 4);
    uint16_t partial = (uint16_t)~csum_fin(tcp_pseudo_sum(src, dst,
                                                         g->hdr_n - 20 + g->total_pay));
    p[20 + 16] = (unsigned char)(partial >> 8);
    p[20 + 17] = (unsigned char)partial;

    struct vnet_hdr vh;
    memset(&vh, 0, sizeof(vh));
    vh.flags = VNET_F_NEEDS_CSUM;
    vh.csum_start = 20;
    vh.csum_offset = 16;
    vh.hdr_len = (uint16_t)g->hdr_n;
    vh.gso_type = VNET_GSO_TCPV4;
    vh.gso_size = (uint16_t)g->seg;
    memcpy(g->vh, &vh, sizeof(vh));
    g->iov[0].iov_base = g->vh;
    g->iov[0].iov_len = sizeof(vh);
    /* Записи без повторов и без проверки — как в tun_write_ctl: переполненная очередь
     * устройства это перегрузка, а не отказ, и внутренний TCP разберётся с потерей сам. */
    (void)!writev(d->fd, g->iov, g->nio);
    tun_gro_reset(g);
}

void tun_gro_push(const struct tun_dev *d, struct tun_gro *g, unsigned char *pkt, size_t n) {
    size_t pay_n = 0, hdr_n = 0;
    uint32_t seq = 0;
    /* Без разгрузки склеивать нечем: ядро не поймёт пометку, а считать суммы за него по
     * всем данным дороже, чем сэкономленный вызов. */
    if (!d->gro || gro_parse(pkt, n, &hdr_n, &pay_n, &seq) != 0) {
        tun_gro_flush(d, g);
        tun_write_ctl(d, pkt, n);
        return;
    }
    if (g->frames > 0) {
        int fits = g->nio < (int)(sizeof(g->iov) / sizeof(g->iov[0]));
        /* Приклеиваем, только если номер продолжает предыдущий, размер не больше первого
         * (последний кусок вправе быть короче, остальные обязаны быть ровно как первый) и
         * поток тот же. */
        if (fits && seq == g->next_seq && pay_n <= g->seg && hdr_n == g->hdr_n &&
            gro_same(g->first, pkt, hdr_n)) {
            g->iov[g->nio].iov_base = pkt + hdr_n;
            g->iov[g->nio].iov_len = pay_n;
            g->nio++;
            g->total_pay += pay_n;
            g->frames++;
            g->next_seq = seq + (uint32_t)pay_n;
            /* Короткий кусок закрывает набор: за ним нарезка уже не сойдётся. То же и с
             * PSH — ядро ставит его только на последний кусок, значит он и должен быть
             * последним.
             *
             * PSH ПРИ ЭТОМ НАКАПЛИВАЕТСЯ В ЗАГОЛОВКЕ НАБОРА, и это не мелочь. Заголовок
             * склеенного кадра берётся у ПЕРВОГО пакета, а флаг стоял у последнего — значит без
             * этой строки он терялся, и получатель не видел «конец записи приложения» вовсе.
             * Нарезка (у нас и в ядре) отдаёт флаги последнему куску, поэтому накопленный здесь
             * PSH там же и окажется. Ровно так поступает GRO ядра, и то же делает реализация на
             * Go. Найдено круговым стендом: склейка с разбором обязаны быть обратны, а на этом
             * флаге они расходились. */
            g->first[33] |= (unsigned char)(pkt[33] & 0x08);
            if (pay_n < g->seg || (pkt[33] & 0x08)) tun_gro_flush(d, g);
            return;
        }
        tun_gro_flush(d, g);
    }
    /* Начинаем новый набор: первый пакет едет целиком одним вектором (заголовок и нагрузка
     * у него уже лежат подряд), остальные — только нагрузками. */
    g->first = pkt;
    g->seg = pay_n;
    g->hdr_n = hdr_n;
    g->total_pay = pay_n;
    g->frames = 1;
    g->next_seq = seq + (uint32_t)pay_n;
    g->nio = 2;
    g->iov[1].iov_base = pkt;
    g->iov[1].iov_len = hdr_n + pay_n;
    /* PSH на первом же пакете означает «набора не будет»: отдаём сразу. */
    if (pkt[33] & 0x08) tun_gro_flush(d, g);
}

/* ICMP «порт недостижим» на пакет, который мы нести не умеем.
 *
 * ЧТО СЮДА ПОПАДАЕТ СЕЙЧАС. TCP и UDP туннель несёт оба (см. заголовок этого файла и место
 * вызова в stack.c: ветка сузилась до `k.proto != 6 && k.proto != 17`). Остаётся всё
 * прочее — ICMP, ESP, GRE, — то есть то, для чего у VLESS нет команды и помочь чему нечем.
 *
 * Зачем это вообще есть. В туннель попадает всё, что совпало с адресным списком: правило
 * метки протокол не различает и не должно, иначе такой трафик пошёл бы открытым путём, и
 * сайт увидел бы настоящий адрес ровно там, где его прятали. А непереносимый пакет прежде
 * выбрасывался молча.
 *
 * Молча — это и была ошибка, ценой которой стало «speed.cloudflare.com не открывается
 * вообще». ИСТОРИЯ, а не нынешнее положение дел: тогда UDP мы ещё не несли, и браузер шёл к
 * Cloudflare по QUIC, то есть UDP на 443. Тишина для него означает не «нельзя», а «пока не
 * ответили»: он ждёт, повторяет, и только потом пробует TCP. На сайтах, которые предпочитают
 * QUIC особенно настойчиво, это выглядело как мёртвая страница при полностью живом туннеле —
 * TCP до тех же адресов проходил за 250 мс, 7 попыток из 7. Ради этого случая функция и
 * появилась; QUIC с тех пор ходит через туннель сам, а вывод остался и стоит того, чтобы его
 * помнить: молчание дороже отказа, потому что отказ можно обработать, а молчание — только
 * переждать.
 *
 * ICMP-ошибка превращает ожидание в мгновенный отказ. Источником ставится тот адрес, к
 * которому клиент обращался, — то же решение, что и в синтезированных RST выше: мы отвечаем
 * от имени назначения, потому что для клиента мы и есть путь к нему.
 *
 * Формат (RFC 792): заголовок ICMP 8 байт, дальше заголовок исходного пакета IP и первые
 * 8 байт его данных — по ним клиент и опознаёт, какое своё соединение отвергли. */
size_t icmp_unreach_build(unsigned char *out, size_t cap,
                          const unsigned char *orig, size_t orig_n) {
    if (orig_n >= 40 && (orig[0] >> 4) == 6) {
        /* ICMPv6 «адресат недостижим, порт недостижим» (RFC 4443, 3.1: тип 1, код 4). Цитата — сколько
         * влезет в минимальный MTU IPv6 (1280), сумма — с псевдозаголовком, в отличие от ICMPv4. */
        size_t quote = orig_n > 1280 - 48 ? 1280 - 48 : orig_n;
        size_t total6 = 40 + 8 + quote;
        if (cap < total6) return 0;
        memset(out, 0, 48);
        out[0] = 0x60;
        out[4] = (unsigned char)((8 + quote) >> 8);
        out[5] = (unsigned char)(8 + quote);
        out[6] = 58;                                /* ICMPv6 */
        out[7] = 64;
        memcpy(out + 8, orig + 24, 16);             /* от имени назначения */
        memcpy(out + 24, orig + 8, 16);             /* клиенту */
        out[40] = 1;                                /* destination unreachable */
        out[41] = 4;                                /* port unreachable */
        memcpy(out + 48, orig, quote);
        uint16_t ic6 = csum_fin(csum_add(out + 40, 8 + quote, pseudo6_sum(out + 8, out + 24, 8 + quote, 58)));
        out[42] = (unsigned char)(ic6 >> 8);
        out[43] = (unsigned char)ic6;
        return total6;
    }
    if (orig_n < 20) return 0;
    size_t ihl = (size_t)(orig[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > orig_n) return 0;
    size_t quote = ihl + 8 > orig_n ? orig_n : ihl + 8;   /* заголовок + 8 байт данных */
    size_t total = 20 + 8 + quote;
    if (cap < total) return 0;

    memset(out, 0, 28);
    out[0] = 0x45;                                  /* IPv4, заголовок 20 байт */
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[6] = 0x40;                                  /* не фрагментировать */
    out[8] = 64;                                    /* TTL */
    out[9] = 1;                                     /* ICMP */
    memcpy(out + 12, orig + 16, 4);                 /* от имени назначения */
    memcpy(out + 16, orig + 12, 4);                 /* клиенту */
    uint16_t ipc = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipc >> 8);
    out[11] = (unsigned char)ipc;

    out[20] = 3;                                    /* destination unreachable */
    out[21] = 3;                                    /* port unreachable */
    /* Следующие 4 байта — нули: для кода 3 они не используются. */
    memcpy(out + 28, orig, quote);
    uint16_t ic = csum_fin(csum_add(out + 20, 8 + quote, 0));
    out[22] = (unsigned char)(ic >> 8);
    out[23] = (unsigned char)ic;
    return total;
}

/* Тело tcp_build и tcp_build6: v6 — семейство, src и dst — байты адресов в сетевом порядке (4 или 16). */
static size_t tcp_build_af(unsigned char *out, size_t cap, int v6,
                           const unsigned char *src, const unsigned char *dst,
                           uint16_t sport, uint16_t dport,
                           uint32_t seq, uint32_t ack, unsigned char flags,
                           const unsigned char *data, size_t data_n, uint16_t window,
                           unsigned mss, int wscale) {
    /* Опции: MSS занимает 4 байта, масштаб окна 3, и вместе они дают 7 — а длина
     * заголовка TCP измеряется в 32-битных словах. Дополняем NOP до восьми. */
    size_t opt_n = 0;
    if (mss) opt_n += 4;
    if (wscale >= 0) opt_n += 4;                     /* NOP + kind + len + shift */
    size_t iph = v6 ? 40 : 20;
    size_t total = iph + 20 + opt_n + data_n;
    if (total > cap) return 0;
    memset(out, 0, iph + 20 + opt_n);

    if (v6) {
        size_t pl = 20 + opt_n + data_n;
        out[0] = 0x60;                               /* IPv6 */
        out[4] = (unsigned char)(pl >> 8);
        out[5] = (unsigned char)pl;
        out[6] = 6;                                  /* TCP */
        out[7] = 64;                                 /* предел переходов */
        memcpy(out + 8, src, 16);
        memcpy(out + 24, dst, 16);
    } else {
        out[0] = 0x45;                               /* IPv4, ihl=5 */
        out[2] = (unsigned char)(total >> 8);
        out[3] = (unsigned char)total;
        out[8] = 64;                                 /* TTL */
        out[9] = 6;                                  /* TCP */
        memcpy(out + 12, src, 4);
        memcpy(out + 16, dst, 4);
        out[10] = 0; out[11] = 0;
        uint16_t ipsum = csum_fin(csum_add(out, 20, 0));
        out[10] = (unsigned char)(ipsum >> 8);
        out[11] = (unsigned char)ipsum;
    }

    unsigned char *t = out + iph;
    t[0] = (unsigned char)(sport >> 8); t[1] = (unsigned char)sport;
    t[2] = (unsigned char)(dport >> 8); t[3] = (unsigned char)dport;
    t[4] = (unsigned char)(seq >> 24); t[5] = (unsigned char)(seq >> 16);
    t[6] = (unsigned char)(seq >> 8);  t[7] = (unsigned char)seq;
    t[8] = (unsigned char)(ack >> 24); t[9] = (unsigned char)(ack >> 16);
    t[10] = (unsigned char)(ack >> 8); t[11] = (unsigned char)ack;
    t[12] = (unsigned char)(((20 + opt_n) / 4) << 4); /* data offset в 32-битных словах */
    t[13] = flags;
    t[14] = (unsigned char)(window >> 8); t[15] = (unsigned char)window;
    size_t o = 20;
    if (mss) {
        t[o++] = 2;                                  /* kind: MSS */
        t[o++] = 4;                                  /* длина опции */
        t[o++] = (unsigned char)(mss >> 8);
        t[o++] = (unsigned char)mss;
    }
    if (wscale >= 0) {
        t[o++] = 1;                                  /* NOP: выравнивание до слова */
        t[o++] = 3;                                  /* kind: масштаб окна */
        t[o++] = 3;                                  /* длина опции */
        t[o++] = (unsigned char)wscale;
    }
    if (data_n) memcpy(t + 20 + opt_n, data, data_n);

    uint32_t acc;
    if (v6) {
        acc = pseudo6_sum(src, dst, 20 + opt_n + data_n, 6);
    } else {
        uint32_t s4, d4;
        memcpy(&s4, src, 4);
        memcpy(&d4, dst, 4);
        acc = tcp_pseudo_sum(s4, d4, 20 + opt_n + data_n);
    }
    acc = csum_add(t, 20 + opt_n + data_n, acc);
    uint16_t tsum = csum_fin(acc);
    t[16] = (unsigned char)(tsum >> 8);
    t[17] = (unsigned char)tsum;
    return total;
}

size_t tcp_build(unsigned char *out, size_t cap,
                 uint32_t src, uint32_t dst, uint16_t sport, uint16_t dport,
                 uint32_t seq, uint32_t ack, unsigned char flags,
                 const unsigned char *data, size_t data_n, uint16_t window,
                 unsigned mss, int wscale) {
    return tcp_build_af(out, cap, 0, (const unsigned char *)&src, (const unsigned char *)&dst, sport, dport,
                        seq, ack, flags, data, data_n, window, mss, wscale);
}

size_t tcp_build6(unsigned char *out, size_t cap,
                  const uint8_t src[16], const uint8_t dst[16], uint16_t sport, uint16_t dport,
                  uint32_t seq, uint32_t ack, unsigned char flags,
                  const unsigned char *data, size_t data_n, uint16_t window,
                  unsigned mss, int wscale) {
    return tcp_build_af(out, cap, 1, src, dst, sport, dport, seq, ack, flags, data, data_n, window, mss, wscale);
}

/* ---- UDP клиенту ----------------------------------------------------------- */
/* Сумма псевдозаголовка UDP: то же, что у TCP, но с номером протокола 17. */
static uint32_t udp_pseudo_sum(uint32_t src, uint32_t dst, size_t udp_len) {
    unsigned char pseudo[12];
    memcpy(pseudo, &src, 4);
    memcpy(pseudo + 4, &dst, 4);
    pseudo[8] = 0; pseudo[9] = 17;
    pseudo[10] = (unsigned char)(udp_len >> 8); pseudo[11] = (unsigned char)udp_len;
    return csum_add(pseudo, 12, 0);
}

/* Заголовок IPv4 с полями фрагментации. Отдельно от tcp_build не ради красоты: датаграмма
 * может не влезть в MTU, и тогда один и тот же заголовок печатается несколько раз с разным
 * смещением. */
static void ip4_hdr(unsigned char *out, size_t total, uint32_t src, uint32_t dst,
                    unsigned char proto, uint16_t id, unsigned frag_off, int more) {
    memset(out, 0, 20);
    out[0] = 0x45;
    out[2] = (unsigned char)(total >> 8);
    out[3] = (unsigned char)total;
    out[4] = (unsigned char)(id >> 8);
    out[5] = (unsigned char)id;
    unsigned flags = (frag_off / 8) | (more ? 0x2000u : 0u);
    out[6] = (unsigned char)(flags >> 8);
    out[7] = (unsigned char)flags;
    out[8] = 64;                                     /* TTL */
    out[9] = proto;
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    uint16_t ipsum = csum_fin(csum_add(out, 20, 0));
    out[10] = (unsigned char)(ipsum >> 8);
    out[11] = (unsigned char)ipsum;
}

/* Отдать клиенту датаграмму. Адреса и порты уже поменяны местами вызывающим: мы отвечаем
 * от имени того, к кому клиент обращался.
 *
 * Фрагментация здесь не про экзотику. Датаграмма приезжает от узла ЦЕЛОЙ — по пути к нему
 * её собрало ядро сервера, — и в MTU нашего устройства она может не влезть: классический
 * случай это ответ DNS с EDNS0, где клиент сам объявил буфер в 4096 байт. Без нарезки
 * такой ответ пришлось бы выбросить, то есть «UDP работает, а большие ответы теряются» —
 * поломка, которую ищут месяцами. Собирает фрагменты обратно стек клиента, это его
 * обычная работа.
 *
 * Смещение фрагмента считается в восьмибайтовых блоках, поэтому кусок обязан быть кратен
 * восьми — кроме последнего. Возвращает 0 или -1. */
int udp_write_to_client(const struct tun_dev *d, uint32_t src, uint32_t dst,
                        uint16_t sport, uint16_t dport,
                        const unsigned char *data, size_t n, uint16_t ip_id) {
    /* Заголовок UDP плюс сама датаграмма: сумма UDP считается по ВСЕЙ датаграмме, а не по
     * куску, поэтому собрать её надо целиком и только потом нарезать. Статический буфер, а
     * не стек: 64 КБ на стеке в цикле, который и без того держит буфер записи TLS. */
    static __thread unsigned char l4[8 + UDP_DGRAM_ABS];
    if (n > UDP_DGRAM_ABS) return -1;

    size_t udp_len = 8 + n;
    l4[0] = (unsigned char)(sport >> 8); l4[1] = (unsigned char)sport;
    l4[2] = (unsigned char)(dport >> 8); l4[3] = (unsigned char)dport;
    l4[4] = (unsigned char)(udp_len >> 8); l4[5] = (unsigned char)udp_len;
    l4[6] = 0; l4[7] = 0;
    memcpy(l4 + 8, data, n);
    uint32_t acc = udp_pseudo_sum(src, dst, udp_len);
    acc = csum_add(l4, udp_len, acc);
    uint16_t usum = csum_fin(acc);
    /* Ноль в поле суммы означает «сумма не считалась», поэтому по RFC 768 его заменяют на
     * 0xFFFF: обе величины дают один и тот же результат при проверке. */
    if (!usum) usum = 0xFFFF;
    l4[6] = (unsigned char)(usum >> 8);
    l4[7] = (unsigned char)usum;

    unsigned char pkt[20 + UDP_MTU_PAYLOAD];
    size_t off = 0;
    while (off < udp_len) {
        size_t chunk = udp_len - off;
        if (chunk > UDP_MTU_PAYLOAD) chunk = UDP_MTU_PAYLOAD & ~7u;
        int more = off + chunk < udp_len;
        ip4_hdr(pkt, 20 + chunk, src, dst, 17, ip_id, (unsigned)off, more);
        memcpy(pkt + 20, l4 + off, chunk);
        /* Через tun_writev, а НЕ через tun_write_ctl, и это не мелочь.
         *
         * tun_write_ctl не проверяет результат и не повторяет: он для служебных пакетов, где
         * потеря дёшева — SYN-ACK или ACK клиент пришлёт заново сам. Здесь же уходят ДАННЫЕ,
         * и при заполненной очереди устройства writev отвечает EAGAIN, то есть датаграмма
         * пропадает молча.
         *
         * Замерено на живом роутере: страница по HTTP/3 через туннель то скачивалась за
         * 840 мс, то вставала на четверти и добиралась до конца за двадцать секунд, то
         * обрывалась совсем — при том, что узел присылал всё. QUIC потерю переживает, но не
         * такую: очередь заполняется как раз на скачивании, то есть теряется не отдельная
         * датаграмма, а подряд идущая пачка.
         *
         * Дождаться места дешевле: очередь TUN опустошает ядро, отдавая пакеты в LAN, и
         * ожидание здесь измеряется миллисекундой. Ровно так же поступает путь TCP
         * (tun_write_data), и по той же причине.
         *
         * Заголовок vnet при включённой разгрузке обязателен ВСЕГДА, а не только при
         * нарезке: без него ядро прочитает первые десять байт нашего IP-заголовка как этот
         * заголовок. Нарезку не просим — суммы посчитаны, пакет уже размером в MTU. */
        struct iovec iov[2];
        int nio = 0;
        struct vnet_hdr vh;
        if (d->gso) {
            memset(&vh, 0, sizeof(vh));
            vh.gso_type = VNET_GSO_NONE;
            iov[nio].iov_base = &vh;
            iov[nio].iov_len = sizeof(vh);
            nio++;
        }
        iov[nio].iov_base = pkt;
        iov[nio].iov_len = 20 + chunk;
        nio++;
        if (tun_writev(d, iov, nio) != 0) return -1;
        off += chunk;
    }
    return 0;
}

/* Один пакет клиенту: с заголовком vnet при включённой разгрузке (обязателен всегда, см. udp_write_to_client). */
static int tun_write_pkt(const struct tun_dev *d, const unsigned char *pkt, size_t n) {
    struct iovec iov[2];
    int nio = 0;
    struct vnet_hdr vh;
    if (d->gso) {
        memset(&vh, 0, sizeof(vh));
        vh.gso_type = VNET_GSO_NONE;
        iov[nio].iov_base = &vh;
        iov[nio].iov_len = sizeof(vh);
        nio++;
    }
    iov[nio].iov_base = (void *)(uintptr_t)pkt;
    iov[nio].iov_len = n;
    nio++;
    return tun_writev(d, iov, nio);
}

/* IPv6: то же, что udp_write_to_client. Сумма UDP у IPv6 обязательна (RFC 8200, 8.1) и считается по
 * псевдозаголовку из 16-байтовых адресов; ноль в поле суммы здесь запрещён, поэтому тоже 0xFFFF. Датаграмма,
 * не влезающая в MTU, режется заголовком фрагментации: в каждом куске фиксированный заголовок (следующий
 * заголовок 44), восемь байт фрагментации (смещение в блоках по 8 байт, M, 32-битный номер) и кусок,
 * кратный восьми, кроме последнего. Выше MTU фрагменты ждёт собрать стек клиента. */
int udp_write_to_client6(const struct tun_dev *d, const uint8_t src[16], const uint8_t dst[16],
                         uint16_t sport, uint16_t dport,
                         const unsigned char *data, size_t n, uint32_t frag_id) {
    static __thread unsigned char l4[8 + UDP_DGRAM_ABS];
    if (n > UDP_DGRAM_ABS) return -1;
    size_t udp_len = 8 + n;
    l4[0] = (unsigned char)(sport >> 8); l4[1] = (unsigned char)sport;
    l4[2] = (unsigned char)(dport >> 8); l4[3] = (unsigned char)dport;
    l4[4] = (unsigned char)(udp_len >> 8); l4[5] = (unsigned char)udp_len;
    l4[6] = 0; l4[7] = 0;
    memcpy(l4 + 8, data, n);
    uint16_t usum = csum_fin(csum_add(l4, udp_len, pseudo6_sum(src, dst, udp_len, 17)));
    if (!usum) usum = 0xFFFF;
    l4[6] = (unsigned char)(usum >> 8);
    l4[7] = (unsigned char)usum;

    unsigned char pkt[40 + 8 + UDP6_MTU_PAYLOAD];
    if (40 + udp_len <= TUN_MTU) {
        memset(pkt, 0, 40);
        pkt[0] = 0x60;
        pkt[4] = (unsigned char)(udp_len >> 8);
        pkt[5] = (unsigned char)udp_len;
        pkt[6] = 17;
        pkt[7] = 64;
        memcpy(pkt + 8, src, 16);
        memcpy(pkt + 24, dst, 16);
        memcpy(pkt + 40, l4, udp_len);
        return tun_write_pkt(d, pkt, 40 + udp_len);
    }
    size_t per = (UDP6_MTU_PAYLOAD - 8) & ~(size_t)7;   /* нагрузка куска: 1448 */
    size_t off = 0;
    while (off < udp_len) {
        size_t chunk = udp_len - off;
        if (chunk > per) chunk = per;
        int more = off + chunk < udp_len;
        memset(pkt, 0, 48);
        pkt[0] = 0x60;
        pkt[4] = (unsigned char)((8 + chunk) >> 8);
        pkt[5] = (unsigned char)(8 + chunk);
        pkt[6] = 44;                                /* заголовок фрагментации */
        pkt[7] = 64;
        memcpy(pkt + 8, src, 16);
        memcpy(pkt + 24, dst, 16);
        pkt[40] = 17;                               /* за ним — UDP */
        unsigned fo = (unsigned)off | (more ? 1u : 0u);   /* off кратно 8: младшие три бита свободны */
        pkt[42] = (unsigned char)(fo >> 8);
        pkt[43] = (unsigned char)fo;
        pkt[44] = (unsigned char)(frag_id >> 24); pkt[45] = (unsigned char)(frag_id >> 16);
        pkt[46] = (unsigned char)(frag_id >> 8);  pkt[47] = (unsigned char)frag_id;
        memcpy(pkt + 48, l4 + off, chunk);
        if (tun_write_pkt(d, pkt, 48 + chunk) != 0) return -1;
        off += chunk;
    }
    return 0;
}

/* ---- программа раздачи в ядре (R-146) ------------------------------------------------------------
 *
 * ЗАЧЕМ. Несколько рабочих потоков держат каждое соединение целиком, и пакеты клиента обязаны приходить
 * владельцу. Раздавал их поток-читатель: читал единственную очередь и копировал пакет в кольцо рабочего.
 * Это работает, но стоит — на скачивании одним потоком ACK клиента шёл через читателя и будил рабочего
 * через eventfd: минус 12–25 % скорости и плюс 20–45 % процессора на ГиБ (стенд perf-tb, 2 ядра).
 * Ядро умеет раздавать само: у устройства с IFF_MULTI_QUEUE очередь для пакета выбирает программа eBPF
 * (TUNSETSTEERINGEBPF, ядро ≥ 4.16), если она стоит. Тогда каждый рабочий читает СВОЮ очередь, как
 * единственный поток прежде, — ни читателя, ни копии, ни побудок.
 *
 * ПОЧЕМУ НЕ РАЗДАЧА ЯДРА ПО УМОЛЧАНИЮ. Без программы ядро выбирает очередь по своему хэшу и таблице
 * потоков, и обе половины соединения к одной очереди не привязывает — на роутере это было 12 против
 * 292 Мбит/с (stack.c, у g_conns). Программа считает tun_flow_owner — тот же хэш, которым рабочий
 * проверяет, что пакет его (handle_packet), так что расхождение видно счётчиком «не у владельца».
 *
 * КАК. Программа — 60 с небольшим инструкций, собранных здесь же (библиотека bpf не нужна): загрузки
 * LD_ABS/LD_IND по смещениям от сетевого заголовка (SKF_NET_OFF), арифметика 32-битная, как в
 * tun_mix32, сжатие в номер — 64-битным умножением, как в tun_flow_owner. Ядро берёт результат по
 * модулю числа очередей, а он и так меньше. Загрузка, выходящая за пакет (усечённый заголовок),
 * завершает программу с нулём — такой пакет всё равно не разберётся.
 *
 * Не встала (ядро без bpf, без JIT — работает интерпретатор, без TUNSETSTEERINGEBPF, отказ проверяющего)
 * — причина в why, и раздаёт читатель (stack.c). */
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/filter.h>

struct bpf_prog_buf {
    struct bpf_insn in[192];
    int n;
};

static void bi(struct bpf_prog_buf *b, uint8_t code, uint8_t dst, uint8_t src, int16_t off, int32_t imm) {
    struct bpf_insn *x = &b->in[b->n++];
    memset(x, 0, sizeof(*x));
    x->code = code;
    x->dst_reg = dst;
    x->src_reg = src;
    x->off = off;
    x->imm = imm;
}

/* x = tun_mix32(x), t — временный регистр. Всё 32-битное (BPF_ALU): старшие биты обнуляются, как у uint32_t. */
static void bi_mix32(struct bpf_prog_buf *b, uint8_t x, uint8_t t) {
    static const struct { int sh; uint32_t mul; } st[3] = { { 16, 0x85EBCA6Bu }, { 13, 0xC2B2AE35u }, { 16, 0 } };
    for (int i = 0; i < 3; i++) {
        bi(b, BPF_ALU | BPF_MOV | BPF_X, t, x, 0, 0);
        bi(b, BPF_ALU | BPF_RSH | BPF_K, t, 0, 0, st[i].sh);
        bi(b, BPF_ALU | BPF_XOR | BPF_X, x, t, 0, 0);
        if (st[i].mul) bi(b, BPF_ALU | BPF_MUL | BPF_K, x, 0, 0, (int32_t)st[i].mul);
    }
}

/* Переход вперёд на метку, которой ещё нет: запомнить место, смещение вписать потом (bi_land). */
static int bi_jmp(struct bpf_prog_buf *b, uint8_t op, uint8_t dst, int32_t imm) {
    bi(b, BPF_JMP | op | BPF_K, dst, 0, 0, imm);
    return b->n - 1;
}
static void bi_land(struct bpf_prog_buf *b, int at) { b->in[at].off = (int16_t)(b->n - at - 1); }

static void steer_prog_build(struct bpf_prog_buf *b, unsigned nq) {
    enum { R0 = 0, R1, R2, R6 = 6, R7, R8, R9, R10 };
    b->n = 0;
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R6, R1, 0, 0);              /* LD_ABS берёт пакет из r6 */
    bi(b, BPF_LD | BPF_B | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 0);     /* версия и длина заголовка */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R7, R0, 0, 0);
    bi(b, BPF_ALU | BPF_RSH | BPF_K, R0, 0, 0, 4);
    int is4 = bi_jmp(b, BPF_JEQ, R0, 4);
    /* IPv6: адреса сворачиваются исключением по четырём словам, дальше та же формула (tun_flow_owner в
     * tun.h); следующий заголовок — вместо протокола, порты — только если он TCP или UDP (у фрагмента 44 —
     * их нет, и все куски датаграммы дают один хэш). */
    int not6 = bi_jmp(b, BPF_JNE, R0, 6);                          /* ни IPv4, ни IPv6 — очередь 0 */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_K, R7, 0, 0, 40);              /* r7 = длина заголовка */
    bi(b, BPF_LD | BPF_B | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 6);     /* следующий заголовок */
    bi(b, BPF_STX | BPF_W | BPF_MEM, R10, R0, -4, 0);
    bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 24);    /* назначение, четыре слова */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R9, R0, 0, 0);
    for (int w = 28; w <= 36; w += 4) {
        bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + w);
        bi(b, BPF_ALU | BPF_XOR | BPF_X, R9, R0, 0, 0);
    }
    bi(b, BPF_LDX | BPF_W | BPF_MEM, R0, R10, -4, 0);
    bi(b, BPF_ALU | BPF_ADD | BPF_X, R9, R0, 0, 0);                /* свёртка назначения + протокол */
    bi_mix32(b, R9, R2);
    bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 8);     /* источник, четыре слова */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R8, R0, 0, 0);
    for (int w = 12; w <= 20; w += 4) {
        bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + w);
        bi(b, BPF_ALU | BPF_XOR | BPF_X, R8, R0, 0, 0);
    }
    bi(b, BPF_ALU | BPF_XOR | BPF_X, R8, R9, 0, 0);
    bi_mix32(b, R8, R2);
    bi(b, BPF_LDX | BPF_W | BPF_MEM, R0, R10, -4, 0);
    int p6tcp = bi_jmp(b, BPF_JEQ, R0, 6);
    int p6none = bi_jmp(b, BPF_JNE, R0, 17);
    bi_land(b, p6tcp);
    bi(b, BPF_LD | BPF_W | BPF_IND, 0, R7, 0, SKF_NET_OFF);        /* порты */
    bi(b, BPF_ALU | BPF_XOR | BPF_X, R8, R0, 0, 0);
    bi_mix32(b, R8, R2);
    bi_land(b, p6none);
    int fin6 = bi_jmp(b, BPF_JA, 0, 0);                            /* к общему концу, мимо блока IPv4 */
    bi_land(b, is4);
    bi(b, BPF_ALU | BPF_AND | BPF_K, R7, 0, 0, 0x0F);
    bi(b, BPF_ALU | BPF_LSH | BPF_K, R7, 0, 0, 2);                 /* r7 = ihl в байтах */
    bi(b, BPF_LD | BPF_B | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 9);     /* протокол */
    bi(b, BPF_STX | BPF_W | BPF_MEM, R10, R0, -4, 0);              /* LD_ABS портит r1-r5: протокол — на стек */
    bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 16);    /* назначение */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R9, R0, 0, 0);
    bi(b, BPF_LDX | BPF_W | BPF_MEM, R0, R10, -4, 0);
    bi(b, BPF_ALU | BPF_ADD | BPF_X, R9, R0, 0, 0);                /* назначение + протокол */
    bi_mix32(b, R9, R2);
    bi(b, BPF_LD | BPF_W | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 12);    /* источник */
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R8, R0, 0, 0);
    bi(b, BPF_ALU | BPF_XOR | BPF_X, R8, R9, 0, 0);
    bi_mix32(b, R8, R2);                                           /* r8 = хэш адресов и протокола */
    bi(b, BPF_LD | BPF_H | BPF_ABS, 0, 0, 0, SKF_NET_OFF + 6);     /* флаги и смещение фрагмента */
    bi(b, BPF_ALU | BPF_AND | BPF_K, R0, 0, 0, 0x3FFF);
    int frag = bi_jmp(b, BPF_JNE, R0, 0);                          /* фрагмент — без портов */
    bi(b, BPF_LDX | BPF_W | BPF_MEM, R0, R10, -4, 0);
    int tcp = bi_jmp(b, BPF_JEQ, R0, 6);
    int notudp = bi_jmp(b, BPF_JNE, R0, 17);
    bi_land(b, tcp);
    int shortihl = bi_jmp(b, BPF_JLT, R7, 20);
    bi(b, BPF_LD | BPF_W | BPF_IND, 0, R7, 0, SKF_NET_OFF);        /* порты: источник << 16 | назначение */
    bi(b, BPF_ALU | BPF_XOR | BPF_X, R8, R0, 0, 0);
    bi_mix32(b, R8, R2);
    bi_land(b, frag);
    bi_land(b, notudp);
    bi_land(b, shortihl);
    bi_land(b, fin6);
    bi(b, BPF_ALU64 | BPF_MOV | BPF_X, R0, R8, 0, 0);              /* (uint64_t)h * nq >> 32 */
    bi(b, BPF_ALU64 | BPF_MUL | BPF_K, R0, 0, 0, (int32_t)nq);
    bi(b, BPF_ALU64 | BPF_RSH | BPF_K, R0, 0, 0, 32);
    bi(b, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
    bi_land(b, not6);
    bi(b, BPF_ALU64 | BPF_MOV | BPF_K, R0, 0, 0, 0);
    bi(b, BPF_JMP | BPF_EXIT, 0, 0, 0, 0);
}

int tun_steer_attach(int fd, unsigned nq, char *why, size_t why_n) {
    if (why_n) why[0] = 0;
    if (getenv("STEER_TUN_NOSTEER")) {
        snprintf(why, why_n, "выключена (STEER_TUN_NOSTEER)");
        return -1;
    }
    static struct bpf_prog_buf b;
    steer_prog_build(&b, nq);
    union bpf_attr a;
    memset(&a, 0, sizeof(a));
    a.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
    a.insns = (uint64_t)(uintptr_t)b.in;
    a.insn_cnt = (uint32_t)b.n;
    a.license = (uint64_t)(uintptr_t)"GPL";
    int pfd = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof(a));
    if (pfd < 0) {
        int e = errno;
        /* Без журнала проверяющего — первая попытка: журнал, не влезший в буфер, сам по себе отказ
         * (ENOSPC). Отказали — повтор с журналом, только чтобы назвать причину. */
        static char log[16384];
        log[0] = 0;
        a.log_buf = (uint64_t)(uintptr_t)log;
        a.log_size = sizeof(log);
        a.log_level = 1;
        int again = (int)syscall(__NR_bpf, BPF_PROG_LOAD, &a, sizeof(a));
        if (again >= 0) close(again);
        /* Последняя непустая строка журнала проверяющего — сама причина отказа. */
        const char *last = "";
        for (char *s = log; *s; ) {
            char *nl = strchr(s, '\n');
            if (nl) *nl = 0;
            if (*s) last = s;
            if (!nl) break;
            s = nl + 1;
        }
        snprintf(why, why_n, "программа не загрузилась: %s%s%s", strerror(e), *last ? " — " : "", last);
        return -1;
    }
    int rc = ioctl(fd, TUNSETSTEERINGEBPF, &pfd);
    int e = errno;
    close(pfd);    /* устройство держит свою ссылку на программу */
    if (rc != 0) {
        snprintf(why, why_n, "устройство её не приняло (TUNSETSTEERINGEBPF): %s", strerror(e));
        return -1;
    }
    return 0;
}
