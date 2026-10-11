#!/usr/bin/env python3
"""Минимальный сервер SOCKS5 без авторизации — узел для стендов с адресом IPv4 и IPv6 (tests/nodev6.sh).

    CONNECT: после ответа «успех» читает запрос клиента и отвечает коротким HTTP-ответом — этого
             хватает проверке узла (`steer proxy-probe`): рукопожатие прошло, ответ пришёл.
    UDP ASSOCIATE: отвечает адресом ретранслятора --udp-bnd (ATYP 1 или 4 по записи адреса) и портом,
             на котором ждёт датаграммы; каждую шлёт обратно эхом с тем же заголовком. Адрес ретранслятора
             нарочно отдельный от адреса сервера: клиент обязан пойти по названному, а не по адресу узла.

Слушатель — на --bind (адрес IPv4 или IPv6, семейство по записи)."""
import argparse
import socket
import socketserver
import struct
import threading

HTTP = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"


def recv_exactly(s, n):
    buf = b""
    while len(buf) < n:
        c = s.recv(n - len(buf))
        if not c:
            return None
        buf += c
    return buf


def addr_bytes(ip):
    if ":" in ip:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, ip)
    return b"\x01" + socket.inet_pton(socket.AF_INET, ip)


class H(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        head = recv_exactly(s, 2)
        if not head or head[0] != 5:
            return
        recv_exactly(s, head[1])
        s.sendall(b"\x05\x00")
        req = recv_exactly(s, 4)
        if not req:
            return
        atyp = req[3]
        if atyp == 1:
            recv_exactly(s, 4)
        elif atyp == 4:
            recv_exactly(s, 16)
        elif atyp == 3:
            recv_exactly(s, recv_exactly(s, 1)[0])
        recv_exactly(s, 2)
        if req[1] == 1:
            s.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            s.recv(4096)
            s.sendall(HTTP)
        elif req[1] == 3:
            fam = socket.AF_INET6 if ":" in self.server.udp_bnd else socket.AF_INET
            u = socket.socket(fam, socket.SOCK_DGRAM)
            u.bind((self.server.udp_bnd, 0))
            port = u.getsockname()[1]
            s.sendall(b"\x05\x00\x00" + addr_bytes(self.server.udp_bnd) + struct.pack(">H", port))
            u.settimeout(0.5)
            s.settimeout(0.2)
            while True:
                try:
                    d, a = u.recvfrom(65535)
                    u.sendto(d, a)           # тот же заголовок SOCKS5 и данные — эхо
                except socket.timeout:
                    pass
                try:
                    if s.recv(1) == b"":
                        break
                except socket.timeout:
                    pass
                except OSError:
                    break
            u.close()


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", required=True)
    ap.add_argument("--port", type=int, default=1080)
    ap.add_argument("--udp-bnd", default=None, help="адрес ретранслятора UDP в ответе (по умолчанию — --bind)")
    a = ap.parse_args()
    if ":" in a.bind:
        Server.address_family = socket.AF_INET6
    srv = Server((a.bind, a.port), H)
    srv.udp_bnd = a.udp_bnd or a.bind
    print("fake-socks: %s:%d" % (a.bind, a.port), flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
