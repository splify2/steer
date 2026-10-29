#!/usr/bin/env python3
"""Цели стенда tests/vless-soak.sh за узлом: HTTP/1.1 с keep-alive и эхо UDP.

Живёт в пространстве сервера; Xray ходит сюда как в интернет. Слушает 0.0.0.0, поэтому отвечает и на
адреса пробы узла (1.1.1.1:80, 8.8.8.8:80 — vless_probe), и на цель трафика стенда.

    GET /<байт>     — ответ ровно столько байт (Content-Length), соединение остаётся открытым
    UDP :5353       — датаграмма возвращается как есть
    --mask АДРЕС:ПОРТ СЕРТ КЛЮЧ — (вместо порта HTTP) маскировочный сайт Reality: TLS 1.3 только с X25519, по потоку на соединение.
        Не openssl s_server: тот однопоточный, и одно повисшее соединение (его и устраивает беда «tarpit»)
        останавливало маскировку целиком — Reality без ответа маски молчит на всех клиентов, и стенд
        приписывал это туннелю.
"""
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BLOCK = b"x" * 65536


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        try:
            n = int(self.path.strip("/").split("?")[0] or "16")
        except ValueError:
            n = 16
        self.send_response(204 if self.path.startswith("/generate_204") else 200)
        self.send_header("Content-Length", str(n))
        self.end_headers()
        left = n
        while left > 0:
            k = min(left, len(BLOCK))
            self.wfile.write(BLOCK[:k])
            left -= k

    do_HEAD = do_GET

    def log_message(self, *a):
        pass


def udp_echo(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", port))
    while True:
        d, a = s.recvfrom(65535)
        s.sendto(d, a)


class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 1024


def mask(addr, cert, key):
    import ssl
    host, port = addr.rsplit(":", 1)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    # Только X25519: Reality 2.0.x с маской, выбравшей X25519MLKEM768, не договаривается (отдельная находка).
    ctx.set_ecdh_curve("X25519")
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, int(port)))
    ls.listen(1024)

    def one(c):
        c.settimeout(30)
        try:
            with ctx.wrap_socket(c, server_side=True) as t:
                t.recv(4096)
                t.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        except Exception:      # noqa: BLE001 — маске всё равно, кто не договорился
            pass
        finally:
            c.close()
    while True:
        c, _ = ls.accept()
        threading.Thread(target=one, args=(c,), daemon=True).start()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--mask":
        mask(*sys.argv[2:5])
    threading.Thread(target=udp_echo, args=(5353,), daemon=True).start()
    srv = S(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 80), H)
    print("vless-soak-srv: готов", flush=True)
    srv.serve_forever()
