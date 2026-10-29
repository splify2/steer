/* ---- торренты клиентов правила: распознавание и запоминание в наборе правил ------------------
 *
 * ЗАЧЕМ. Продавцы VPN банят за BitTorrent: их панели (Marzban, Remnawave, 3x-ui, Hiddify — Xray-core
 * или sing-box) включают sniffing и правило `protocol: bittorrent`. Человеку с «всё устройство через
 * VPN» нужен способ не пускать торрент-клиентов дома в туннель: `torrent: block` у правила — такой
 * трафик отвергается, `torrent: direct` — идёт напрямую мимо выхода правила.
 *
 * ПОЧЕМУ КЛЮЧ ПРАВИЛА, а не свойство выхода и не условие списка. Решение «куда» принимает правило:
 * выход общий у многих правил (и член групп), а «напрямую» — это отказ от метки, которую ставит именно
 * правило. Ключ правила ведёт себя как `quic: block`: действует только на пакеты, до которых дошло
 * это правило, и правило выше своих торрентов не теряет. Условия «протокол» у списков нет вовсе — его
 * пришлось бы протащить через наборы, резолвер и слияние групп ради одного случая.
 *
 * ГДЕ РАСПОЗНАЁТСЯ — в nftables (prerouting_mark, до метки правила), полезной нагрузкой `@ih`
 * (полезная нагрузка над заголовком L4; ядро OpenWrt 25.12, Linux 6.12, её принимает — стенд QEMU):
 * так ключ работает у всех выходов разом — у устройств
 * ядра (WireGuard, AmneziaWG, WARP) и у туннелей с пользовательским стеком (vless, hysteria2, прокси),
 * — и пакет не доходит до выхода вовсе.
 *
 * ЧТО РАСПОЗНАЁТСЯ. Эталон — снифферы серверной стороны, по которым банят: всё, что Xray-core
 * (common/protocol/bittorrent: SniffBittorrent, SniffUTP) или sing-box (common/sniff/bittorrent.go:
 * BitTorrent, UTP, UDPTracker) назовут bittorrent, распознаётся и здесь; сверх них — DHT и трекеры по
 * HTTP. Правила — torrent_sig ниже, по одному на признак, с доводами у каждого.
 *
 * ЗАПОМИНАНИЕ. Один признак ловит малую часть: uTP после SYN, шифрованный MSE/PE и ответы DHT по
 * содержимому не узнать. Поэтому признак запоминается на TORRENT_TTL (каждое совпадение продлевает):
 *   - torrent_src[6] — UDP-сокет клиента (адрес . порт источника): DHT, uTP и UDP-трекеры у клиента
 *     идут с одного порта, и всё с него дальше — торрент;
 *   - torrent_peer[6] — пир (клиент . адрес . порт назначения) из рукопожатия TCP, SYN uTP и трекера:
 *     следующее соединение к тому же пиру — торрент, в том числе шифрованное (MSE) и по TCP после uTP.
 * Потолок набора — TORRENT_SIZE: набор, который пополняют пакеты клиентов, ядро без потолка не
 * заводит (size 0 оно само делает 65535), а без предела любое устройство в сети наполняло бы память
 * роутера. Переполнение не отказ: новые записи не запоминаются (update — отдельным правилом, его неудача
 * не снимает вердикт), распознавание по содержимому идёт дальше; status называет число записей.
 *
 * DIRECT. Перенаправить можно только поток, который ещё не ушёл в выход: первый пакет (SYN, первая
 * датаграмма) или поток, уже пущенный напрямую (метки соединения нет). Поток, уже открытый через выход
 * (рукопожатие BitTorrent идёт первым пакетом ДАННЫХ, после SYN, ушедшего в выход), — отвергается: его
 * пир запомнен, и следующее соединение к нему идёт напрямую с первого пакета. */
#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "spec.h"
#include "groups.h"
#include "ir.h"
#include "marks.h"
#include "nftdump.h"
#include "torrent.h"

int torrent_used(const struct groups *gr, int pol) {
    for (size_t i = 0; i < gr->n; i++) {
        const struct l4match *m = gr->g[i].l4;
        if (m && m->torrent && (!pol || m->torrent == pol)) return 1;
    }
    return 0;
}

static struct nft_set *dyn_set(struct nft_table *t, const char *name, const char *key) {
    struct nft_set *s = ir_set_add(t, name, key);
    if (!s) return NULL;
    s->flags = NFT_SET_DYNAMIC | NFT_SET_TIMEOUT;
    s->size = TORRENT_SIZE;
    s->timeout = TORRENT_TTL;
    return s;
}

/* Признаки по содержимому — в цепочку распознавания политики (pc), с переходом в её цепочку
 * запоминания пира (peer) или сразу в цепочку вердикта (hit). Все правила — по первому байту
 * полезной нагрузки и длине: дешёвые сравнения, и до поиска в наборах доходит только похожее. */
static void torrent_sig(struct nft_chain *pc, const char *peer, const char *hit) {
    struct nft_rule *r;
    /* Рукопожатие BitTorrent по TCP (BEP 3): 0x13 и «BitTorrent protocol» — первые 20 байт потока.
     * Xray (SniffBittorrent) и sing-box (BitTorrent) проверяют ровно их, первым пакетом данных. Здесь —
     * в любом пакете TCP: строка из 20 байт в начале сегмента иначе не встречается. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto tcp");
    ir_x(r, "@ih,0,128 0x13426974546f7272656e742070726f74 @ih,128,32 0x6f636f6c");
    ir_x(r, "goto %s", peer);
    /* SYN uTP (BEP 29) без расширений, как его узнаёт Xray (SniffUTP): тип 4 версии 1 (0x41),
     * расширения нет, timestamp_difference нулевой, датаграмма — ровно заголовок (20 байт). На любом
     * порту и в любом состоянии: правило sing-box ниже не смотрит на порт 53. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto udp");
    ir_x(r, "udp length 28 @ih,0,16 0x4100 @ih,64,32 0x00000000");
    ir_x(r, "goto %s", peer);
    /* uTP, как его узнаёт sing-box (UTP): любой тип 0..4 версии 1 и цепочка расширений; sing-box
     * смотрит ПЕРВУЮ датаграмму потока, после DNS, QUIC и STUN. Первая датаграмма — `ct state new`
     * (у UDP это всё, что ушло до первого ответа). DNS — порт 53 (sing-box отдаёт ему датаграмму раньше
     * по разбору; разбора DNS здесь нет), STUN — по magic cookie 0x2112a442 на месте 4..7; QUIC
     * (длинный заголовок, старший бит первого байта) под первые байты не подходит сам. Первое звено
     * цепочки: байт 1 — тип расширения; ноль — расширений нет, иначе тип следующего звена (байт 20)
     * не больше 4. Глубже цепочка не проверяется (смещение звена зависит от длины предыдущего) —
     * правило шире sing-box, а не уже. Расширения Xray (1 и 2) — частный случай. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto udp ct state new udp dport != 53 udp length >= 28");
    ir_x(r, "@ih,0,8 { 0x01, 0x11, 0x21, 0x31, 0x41 } @ih,32,32 != 0x2112a442 @ih,8,8 0x00");
    ir_x(r, "goto %s", peer);
    r = ir_rule(pc);
    ir_x(r, "meta l4proto udp ct state new udp dport != 53 udp length >= 30");
    ir_x(r, "@ih,0,8 { 0x01, 0x11, 0x21, 0x31, 0x41 } @ih,32,32 != 0x2112a442 @ih,8,8 != 0x00 @ih,160,8 <= 0x04");
    ir_x(r, "goto %s", peer);
    /* Connect к UDP-трекеру (BEP 15), как его узнаёт sing-box (UDPTracker): protocol_id
     * 0x41727101980 и action 0 (connect), не короче 16 байт. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto udp udp length >= 24");
    ir_x(r, "@ih,0,64 0x0000041727101980 @ih,64,32 0x00000000");
    ir_x(r, "goto %s", peer);
    /* Сверх Xray и sing-box. DHT (BEP 5): запрос `d1:ad2:id20:` и ответ `d1:rd2:id20:` — словарь
     * bencode с ключами по порядку, id узла первым. Пиром узел DHT не запоминается: их тысячи, а
     * сокет клиента запоминает вердикт. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto udp");
    ir_x(r, "@ih,0,96 { 0x64313a6164323a696432303a, 0x64313a7264323a696432303a }");
    ir_x(r, "goto %s", hit);
    /* Трекер по HTTP: `GET /announce` (и announce.php) и `GET /scrape`. По HTTPS не виден. */
    r = ir_rule(pc);
    ir_x(r, "meta l4proto tcp");
    ir_x(r, "@ih,0,104 0x474554202f616e6e6f756e6365");
    ir_x(r, "goto %s", peer);
    r = ir_rule(pc);
    ir_x(r, "meta l4proto tcp");
    ir_x(r, "@ih,0,88 0x474554202f736372617065");
    ir_x(r, "goto %s", peer);
}

static void torrent_policy(struct nft_table *t, int pol) {
    const char *pc_name = pol == TORRENT_DIRECT ? TORRENT_CHAIN_DIRECT : TORRENT_CHAIN_BLOCK;
    char peer[48], hit[48];
    snprintf(peer, sizeof(peer), "%s_peer", pc_name);
    snprintf(hit, sizeof(hit), "%s_hit", pc_name);
    struct nft_chain *pc = ir_chain_add(t, pc_name);
    ir_gap(pc);
    struct nft_chain *cp = ir_chain_add(t, peer);
    struct nft_chain *ch = ir_chain_add(t, hit);
    struct nft_rule *r;

    /* Память — первой: сокет и пир, уже узнанные, не ждут признака (поиск в наборе дешевле разбора
     * содержимого, и у потока, пущенного напрямую, он держит решение до конца). */
    r = ir_rule(pc);
    ir_rule_fam(r, 4);
    ir_family(r, 4);
    ir_x(r, "meta l4proto udp");
    ir_setref(r, "ip saddr . udp sport", "torrent_src");
    ir_x(r, "goto %s", hit);
    r = ir_rule(pc);
    ir_rule_fam(r, 6);
    ir_family(r, 6);
    ir_x(r, "meta l4proto udp");
    ir_setref(r, "ip6 saddr . udp sport", "torrent_src6");
    ir_x(r, "goto %s", hit);
    r = ir_rule(pc);
    ir_rule_fam(r, 4);
    ir_family(r, 4);
    ir_setref(r, "ip saddr . ip daddr . th dport", "torrent_peer");
    ir_x(r, "goto %s", peer);
    r = ir_rule(pc);
    ir_rule_fam(r, 6);
    ir_family(r, 6);
    ir_setref(r, "ip6 saddr . ip6 daddr . th dport", "torrent_peer6");
    ir_x(r, "goto %s", peer);
    torrent_sig(pc, peer, hit);

    /* Запомнить пира и — к вердикту. update отдельным правилом: переполненный набор обрывает правило
     * на update, и вердикт за ним не случился бы. */
    r = ir_rule(cp);
    ir_rule_fam(r, 4);
    ir_family(r, 4);
    ir_x(r, "update @torrent_peer { ip saddr . ip daddr . th dport }");
    r = ir_rule(cp);
    ir_rule_fam(r, 6);
    ir_family(r, 6);
    ir_x(r, "update @torrent_peer6 { ip6 saddr . ip6 daddr . th dport }");
    ir_x(ir_rule(cp), "goto %s", hit);

    r = ir_rule(ch);
    ir_rule_fam(r, 4);
    ir_family(r, 4);
    ir_x(r, "meta l4proto udp update @torrent_src { ip saddr . udp sport }");
    r = ir_rule(ch);
    ir_rule_fam(r, 6);
    ir_family(r, 6);
    ir_x(r, "meta l4proto udp update @torrent_src6 { ip6 saddr . udp sport }");
    /* Вердикт. Отказ — сразу: TCP — сброс, остальное — ICMP «запрещено», как у kind=block, чтобы
     * клиент не ждал срока и перешёл к другому пиру. У direct отказ — только потоку, уже открытому
     * через выход (метка соединения стоит); остальное уходит из цепочки разметки без метки — обычным
     * путём, напрямую. */
    for (int k = 0; k < 2; k++) {
        r = ir_rule(ch);
        if (pol == TORRENT_DIRECT) ir_x(r, "ct mark and 0x%08x != 0x00000000", STEER_MARK_MASK);
        if (!k) ir_x(r, "meta l4proto tcp");
        ir_counter(r, 0, 0);
        ir_x(r, "%s", k ? "reject with icmpx admin-prohibited" : "reject with tcp reset");
        ir_comment(r, "steer-torrent:block");
    }
    if (pol == TORRENT_DIRECT) {
        r = ir_rule(ch);
        ir_counter(r, 0, 0);
        ir_x(r, "accept");
        ir_comment(r, "steer-torrent:direct");
    }
}

void torrent_emit(struct nft_table *t, const struct groups *gr) {
    if (!torrent_used(gr, 0)) return;
    struct nft_set *first = dyn_set(t, "torrent_src", "ipv4_addr . inet_service");
    if (first) ir_gap(first);
    dyn_set(t, "torrent_src6", "ipv6_addr . inet_service");
    dyn_set(t, "torrent_peer", "ipv4_addr . ipv4_addr . inet_service");
    dyn_set(t, "torrent_peer6", "ipv6_addr . ipv6_addr . inet_service");
    if (torrent_used(gr, TORRENT_BLOCK)) torrent_policy(t, TORRENT_BLOCK);
    if (torrent_used(gr, TORRENT_DIRECT)) torrent_policy(t, TORRENT_DIRECT);
}

struct tstat { uint64_t bp, bb, dp, db; };

static void tstat_take(void *arg, const char *comment, int has_counter, uint64_t p, uint64_t b) {
    struct tstat *s = arg;
    if (!has_counter || !comment) return;
    if (!strcmp(comment, "steer-torrent:block")) { s->bp += p; s->bb += b; }
    else if (!strcmp(comment, "steer-torrent:direct")) { s->dp += p; s->db += b; }
}

void torrent_status_print(FILE *out, const struct groups *gr) {
    if (!torrent_used(gr, 0)) return;
    struct tstat s = { 0 };
    static const char *const chains[] = { TORRENT_CHAIN_BLOCK "_hit", TORRENT_CHAIN_DIRECT "_hit" };
    nfd_chain_rules(NFD_INET, nft_table(), chains, 2, tstat_take, &s);
    long n[4];
    static const char *const sets[4] = { "torrent_src", "torrent_src6", "torrent_peer", "torrent_peer6" };
    for (int i = 0; i < 4; i++) n[i] = nfd_set_count(NFD_INET, nft_table(), sets[i]);
    fprintf(out, ",\"torrent\":{\"blocked\":{\"packets\":%llu,\"bytes\":%llu},"
                 "\"direct\":{\"packets\":%llu,\"bytes\":%llu},\"remembered\":{\"sockets\":%ld,\"peers\":%ld},"
                 "\"limit\":%lu}",
            (unsigned long long)s.bp, (unsigned long long)s.bb, (unsigned long long)s.dp,
            (unsigned long long)s.db, (n[0] < 0 ? 0 : n[0]) + (n[1] < 0 ? 0 : n[1]),
            (n[2] < 0 ? 0 : n[2]) + (n[3] < 0 ? 0 : n[3]), TORRENT_SIZE);
}
