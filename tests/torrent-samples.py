#!/usr/bin/env python3
# Образцы торрент-трафика и обычного трафика для стенда tests/torrentmatch.sh (ключ `torrent` правила).
#
# ЭТАЛОН — снифферы серверной стороны, по которым панели VPN банят за BitTorrent: Xray-core
# (common/protocol/bittorrent: SniffBittorrent, SniffUTP; образцы — его bittorrent_test.go) и sing-box
# (common/sniff/bittorrent.go: BitTorrent, UTP, UDPTracker; образцы — его bittorrent_test.go; порядок
# снифферов UDP — route/route.go: DNS, QUIC, STUN, uTP, UDP-трекер). Ниже — их логика, переписанная
# один в один (xray_*, sb_*), и ожидание стенда: ядро steer обязано отвергнуть всё, что хоть один из
# них назовёт bittorrent (не уже их), и пропустить обычный трафик.
#
#   torrent-samples.py ref             — таблица: образец, Xray, sing-box, ожидание steer; проверка, что
#                                        переписанная логика согласна с их тестами (код выхода 1 — нет)
#   torrent-samples.py list            — «имя протокол ожидание» по строке
#   torrent-samples.py send ИМЯ АДРЕС ПОРТ_НАЗН ПОРТ_ИСТ — послать образец (TCP: соединиться и
#                                        отправить; печатает sent, rst или refused)
#   torrent-samples.py recv ЖУРНАЛ ПОРТ… — принимать UDP и TCP на портах, писать «порт_ист байт» в журнал
import os
import select
import socket
import struct
import sys


def utp(ptype, ext, tsdiff, *payload):
    """Заголовок uTP из Xray bittorrent_test.go (utpPacket)."""
    b = bytearray(20)
    b[0] = (ptype << 4) | 1
    b[1] = ext
    struct.pack_into(">H", b, 2, 0x4a3f)
    struct.pack_into(">I", b, 4, 0x8c3a91d2)
    struct.pack_into(">I", b, 8, tsdiff)
    struct.pack_into(">I", b, 12, 0x00100000)
    struct.pack_into(">H", b, 16, 0x71ee)
    struct.pack_into(">H", b, 18, 0)
    return bytes(b) + bytes(payload)


H = bytes.fromhex
SB_UTP = [
    # sing-box bittorrent_test.go, TestSniffUTP (первый образец укорочен: проверке нужны первые байты
    # и цепочка расширений, а не полкилобайта шифра; длина датаграммы на признак не влияет).
    H("010041a282d7ee7b583afb160004000006d8318da776968f92d666f7963f32dae23ba0d2c810d8b8209cc4939f54fde9"),
    H("01001ecb68176f215d04326300100000dbcf30292d14b54e9ee2d115ee5b8ebc7fad3e882d4fcdd0c14c6b917c11cb4c"),
    H("21001ecb6817f2805d044fd700100000dbd03029"),
    H("410277ef0b1fb1f60000000000040000c233000000080000000000000000"),
]
SB_NOT_UTP = H("0102736470696e674958d580121500000000000079aaed6717a39c27b07c0c") + bytes(200)
SB_TRACKER = [H("00000417271019800000000078e90560"), H("00000417271019800000000022c5d64d"),
              H("000004172710198000000000b3863541")]
BT_HS = b"\x13BitTorrent protocol" + bytes(8) + bytes(range(20)) + b"-qB4650-" + bytes(12)
DNS_4100 = bytes([0x41, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                  0x01, ord('a'), 0x02, ord('c'), ord('o'), 0x00, 0x00, 0x01, 0x00, 0x01])
DNS_PLAIN = H("123401000001000000000000076578616d706c6503636f6d0000010001")
QUIC_INITIAL = H("c300000001088394c8f03e5157080000449e") + bytes(1180)
STUN_BIND = H("000100002112a442") + bytes(range(12))
STUN_RESP = H("0101000c2112a442") + bytes(range(12)) + H("0020000800012e1a") + bytes(4)
WG_INIT = H("01000000") + bytes(range(144))
DHT_PING = b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:qe"
DHT_RESP = b"d1:rd2:id20:mnopqrstuvwxyz123456e1:t2:aa1:y1:re"
ANNOUNCE = b"GET /announce?info_hash=%12%34&peer_id=-qB4650-&port=6881 HTTP/1.1\r\nHost: t.example\r\n\r\n"
SCRAPE = b"GET /scrape?info_hash=%12%34 HTTP/1.1\r\nHost: t.example\r\n\r\n"
HTTP_GET = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
TLS_HELLO = H("160301020001") + bytes(200)

# (имя, протокол, полезная нагрузка, порт назначения или None — любой)
SAMPLES = [
    ("tcp-bt-handshake", "tcp", BT_HS, None),
    ("tcp-bt-incomplete", "tcp", H("13426974546f7272656e74"), None),       # sing-box: нужно больше данных
    ("tcp-bt-wrong", "tcp", H("13426974546f7272656e75"), None),            # sing-box TestSniffNotBittorrent
    ("tcp-http-announce", "tcp", ANNOUNCE, None),
    ("tcp-http-scrape", "tcp", SCRAPE, None),
    ("tcp-http-get", "tcp", HTTP_GET, None),
    ("tcp-tls-hello", "tcp", TLS_HELLO, None),
    ("utp-syn", "udp", utp(4, 0, 0), None),
    ("utp-syn-sack", "udp", utp(4, 1, 0) + bytes([0, 4, 0xff, 0, 0xff, 0]), None),
    ("utp-syn-extbits", "udp", utp(4, 2, 0) + bytes([0, 8, 1, 2, 3, 4, 5, 6, 7, 8]), None),
    ("utp-syn-extbits-badlen", "udp", utp(4, 2, 0) + bytes([0, 4, 1, 2, 3, 4]), None),
    ("utp-syn-tsdiff", "udp", utp(4, 0, 0x1234), None),
    ("utp-syn-trailing", "udp", utp(4, 0, 0, ord('x')), None),
    ("utp-data", "udp", utp(0, 0, 0x5678, ord('x'), ord('y'), ord('z')), None),
    ("utp-state", "udp", utp(2, 0, 0x5678), None),
    ("utp-fin", "udp", utp(1, 0, 0x5678), None),
    ("utp-wrong-version", "udp", bytes([4 << 4 | 2]) + utp(4, 0, 0)[1:], None),
    ("utp-type5", "udp", utp(5, 0, 0), None),
    ("utp-unknown-ext", "udp", utp(4, 2, 0), None),
    ("utp-chain-past-end", "udp", utp(4, 1, 0, 0, 8, 0xff), None),
    ("utp-sack-not4", "udp", utp(4, 1, 0) + bytes([0, 3, 0xff, 0, 0xff]), None),
    ("utp-short", "udp", utp(4, 0, 0)[:19], None),
    ("sb-utp-1", "udp", SB_UTP[0], None),
    ("sb-utp-2", "udp", SB_UTP[1], None),
    ("sb-utp-3", "udp", SB_UTP[2], None),
    ("sb-utp-4", "udp", SB_UTP[3], None),
    ("sb-not-utp", "udp", SB_NOT_UTP, None),
    ("sb-tracker-1", "udp", SB_TRACKER[0], None),
    ("sb-tracker-2", "udp", SB_TRACKER[1], None),
    ("sb-tracker-3", "udp", SB_TRACKER[2], None),
    ("dht-ping", "udp", DHT_PING, None),
    ("dht-response", "udp", DHT_RESP, None),
    ("dns-txid-4100", "udp", DNS_4100, 53),
    ("dns-plain", "udp", DNS_PLAIN, 53),
    ("quic-initial", "udp", QUIC_INITIAL, 443),
    ("stun-binding", "udp", STUN_BIND, 3478),
    ("stun-response", "udp", STUN_RESP, None),
    ("wireguard-init", "udp", WG_INIT, None),
    ("udp-plain", "udp", b"hello, this is not a torrent at all", None),
]


# ---- Xray-core: common/protocol/bittorrent/bittorrent.go ----
def xray_tcp(b):
    return len(b) >= 20 and b[0] == 19 and b[1:20] == b"BitTorrent protocol"


def xray_utp(b):
    if len(b) < 20 or b[0] != 0x41 or struct.unpack(">I", b[8:12])[0] != 0:
        return False
    ext, off = b[1], 20
    while ext != 0:
        if len(b) < off + 2:
            return False
        ln = b[off + 1]
        if ext == 1:
            if ln < 4 or ln % 4:
                return False
        elif ext == 2:
            if ln != 8:
                return False
        else:
            return False
        if len(b) < off + 2 + ln:
            return False
        ext = b[off]
        off += 2 + ln
    return len(b) == off


# ---- sing-box: common/sniff (bittorrent.go, dns.go, stun.go; порядок — route/route.go) ----
def sb_tcp(b):
    return len(b) >= 20 and b[0] == 19 and b[1:20] == b"BitTorrent protocol"


def sb_utp(b):
    if len(b) < 20:
        return False
    if b[0] & 0x0F != 1 or b[0] >> 4 > 4:
        return False
    ext, pos = b[1], 20
    while ext != 0:
        if pos >= len(b):
            return False
        ext = b[pos]
        pos += 1
        if ext > 4:
            return False
        if pos >= len(b):
            return False
        ln = b[pos]
        pos += 1 + ln                   # bytes.Reader.Seek за конец не ошибка, ошибка — следующее чтение
    return True


def sb_tracker(b):
    return len(b) >= 16 and struct.unpack(">Q", b[:8])[0] == 0x41727101980 and struct.unpack(">I", b[8:12])[0] == 0


def sb_dns_name(b, off):
    while True:
        if off >= len(b):
            return None
        ln = b[off]
        if ln == 0:
            return off + 1
        if ln & 0xC0 == 0xC0:
            return off + 2 if off + 2 <= len(b) else None
        off += 1 + ln


def sb_dns(b):
    # verifyDNSQueryHeader: не ответ, opcode 0, одни вопросы (и дополнительные записи), длина точная.
    if len(b) < 12:
        return False
    flags = struct.unpack(">H", b[2:4])[0]
    if flags & 0x8000 or (flags >> 11) & 0xF or struct.unpack(">H", b[6:8])[0] or struct.unpack(">H", b[8:10])[0]:
        return False
    qd = struct.unpack(">H", b[4:6])[0]
    if qd == 0 or struct.unpack(">H", b[10:12])[0]:
        return False
    off = 12
    for _ in range(qd):
        off = sb_dns_name(b, off)
        if off is None or off + 4 > len(b):
            return False
        off += 4
    return off == len(b)


def sb_stun(b):
    return len(b) >= 20 and struct.unpack(">I", b[4:8])[0] == 0x2112A442 and \
        len(b) >= 20 + struct.unpack(">H", b[2:4])[0]


def sb_quic(b):
    return len(b) >= 1200 and b[0] & 0xC0 == 0xC0


def sb_udp(b):
    for name, f in (("dns", sb_dns), ("quic", sb_quic), ("stun", sb_stun)):
        if f(b):
            return False
    return sb_utp(b) or sb_tracker(b)


# ---- steer (ключ torrent): что ловят правила nft (compile/torrent.c), на первой датаграмме ----
def steer_udp(b, dport):
    if len(b) == 20 and b[0] == 0x41 and b[1] == 0 and b[8:12] == bytes(4):
        return True
    if dport != 53 and len(b) >= 20 and b[0] in (0x01, 0x11, 0x21, 0x31, 0x41) and b[4:8] != H("2112a442"):
        if b[1] == 0:
            return True
        if len(b) >= 22 and b[20] <= 4:
            return True
    if len(b) >= 16 and b[:12] == H("000004172710198000000000"):
        return True
    return b[:12] in (b"d1:ad2:id20:", b"d1:rd2:id20:")


def steer_tcp(b):
    return b[:20] == b"\x13BitTorrent protocol" or b[:13] == b"GET /announce" or b[:11] == b"GET /scrape"


def verdicts(name, proto, pl, dport):
    if proto == "tcp":
        return xray_tcp(pl), sb_tcp(pl), steer_tcp(pl)
    return xray_utp(pl), sb_udp(pl), steer_udp(pl, dport or 40000)


def ref():
    bad = 0
    # Сверка переписанной логики с тестами самих Xray и sing-box.
    want_x = {"utp-syn": 1, "utp-syn-sack": 1, "utp-syn-extbits": 1, "utp-syn-extbits-badlen": 0,
              "utp-syn-tsdiff": 0, "utp-syn-trailing": 0, "utp-data": 0, "utp-state": 0, "utp-fin": 0,
              "utp-wrong-version": 0, "utp-type5": 0, "utp-unknown-ext": 0, "utp-chain-past-end": 0,
              "utp-sack-not4": 0, "utp-short": 0, "dns-txid-4100": 0}
    for name, proto, pl, dport in SAMPLES:
        x, s, st = verdicts(name, proto, pl, dport)
        if name in want_x and int(x) != want_x[name]:
            print("REF-FAIL xray %s" % name); bad = 1
        if name.startswith(("sb-utp", "sb-tracker")) and not s:
            print("REF-FAIL sing-box %s" % name); bad = 1
        if name in ("sb-not-utp", "tcp-bt-incomplete", "tcp-bt-wrong") and s:
            print("REF-FAIL sing-box %s" % name); bad = 1
        if (x or s) and not st:
            print("NARROWER %s: Xray %s, sing-box %s, steer нет" % (name, x, s)); bad = 1
        print("%-24s %-4s xray=%-3s sing-box=%-3s steer=%s" % (name, proto, "bt" if x else "-", "bt" if s else "-",
                                                               "bt" if st else "-"))
    return bad


def main():
    cmd = sys.argv[1]
    if cmd == "ref":
        sys.exit(ref())
    if cmd == "list":
        for name, proto, pl, dport in SAMPLES:
            print(name, proto, "bt" if verdicts(name, proto, pl, dport)[2] else "ok", dport or 0)
        return
    if cmd == "send":
        name, addr, dport, sport = sys.argv[2], sys.argv[3], int(sys.argv[4]), int(sys.argv[5])
        s = next(x for x in SAMPLES if x[0] == name)
        if s[1] == "udp":
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.bind(("0.0.0.0", sport))
            u.sendto(s[2], (addr, dport))
            print("sent")
            return
        t = socket.socket()
        t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        t.bind(("0.0.0.0", sport))
        t.settimeout(3)
        try:
            t.connect((addr, dport))
            t.sendall(s[2])
            t.settimeout(1)
            try:
                d = t.recv(100)
                print("rst" if d is None else "sent")
            except ConnectionResetError:
                print("rst")
            except socket.timeout:
                print("sent")
        except (ConnectionRefusedError, ConnectionResetError):
            print("refused")
        except (socket.timeout, OSError):
            print("timeout")
        return
    if cmd == "recv":
        log, ports = sys.argv[2], [int(p) for p in sys.argv[3:]]
        socks = {}
        for p in ports:
            u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            u.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            u.bind(("0.0.0.0", p))
            socks[u] = ("udp", p)
            t = socket.socket()
            t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            t.bind(("0.0.0.0", p))
            t.listen(16)
            socks[t] = ("listen", p)
        while True:
            r, _, _ = select.select(list(socks), [], [])
            for x in r:
                kind, p = socks[x]
                if kind == "udp":
                    d, a = x.recvfrom(65535)
                    p = a[1]
                elif kind == "listen":
                    c, a = x.accept()
                    socks[c] = ("conn", a[1])
                    continue
                else:
                    try:
                        d = x.recv(65535)
                    except OSError:
                        d = b""
                    if not d:
                        del socks[x]
                        x.close()
                        continue
                with open(log, "a") as f:
                    f.write("%d %d\n" % (p, len(d)))


if __name__ == "__main__":
    main()
