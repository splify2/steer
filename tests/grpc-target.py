#!/usr/bin/env python3
"""Цель для tests/run-grpc.sh: HTTP на одном адресе, без keep-alive.

  grpc-target.py АДРЕС ПОРТ

  /pg/<КБ>   страница нужного размера и закрытие соединения («Connection: close»);
  /big/<МБ>  крупный ответ, который читают сколько нужно (долгая закачка вниз);
  /up        приём выгрузки: тело читается и выбрасывается (долгая выгрузка вверх).

Ответ цели и закрытие идут подряд, без паузы, — ровно так отвечает 1.1.1.1:80 на запрос пробы узла
(«GET /» с «Connection: close»): после этого сервер gRPC кончает поток данными, концевыми HEADERS и
RST_STREAM одним сбросом буфера (см. tests/grpcmatch.c)."""
import socket, sys, threading

def handle(c):
    try:
        c.settimeout(120)
        buf = b''
        while b'\r\n\r\n' not in buf:
            d = c.recv(65536)
            if not d:
                return
            buf += d
        head, _, rest = buf.partition(b'\r\n\r\n')
        parts = head.split(b'\r\n', 1)[0].decode('latin1').split()
        path = parts[1] if len(parts) > 1 else '/'
        if path.startswith('/up'):
            cl = 0
            for h in head.split(b'\r\n')[1:]:
                if h.lower().startswith(b'content-length:'):
                    cl = int(h.split(b':', 1)[1])
            got = len(rest)
            while got < cl:
                d = c.recv(1 << 20)
                if not d:
                    break
                got += len(d)
            body = b'ok %d' % got
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % len(body) + body)
            return
        n = 2
        if path.startswith('/pg/'):
            n = int(path[4:]) * 1024
        elif path.startswith('/big/'):
            n = int(path[5:]) * 1024 * 1024
        c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n' % n)
        blk = b'x' * 65536
        sent = 0
        while sent < n:
            k = min(len(blk), n - sent)
            c.sendall(blk[:k])
            sent += k
    except Exception:
        pass
    finally:
        try:
            c.close()
        except Exception:
            pass

def main():
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen(4096)
    while True:
        c, _ = s.accept()
        c.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        threading.Thread(target=handle, args=(c,), daemon=True).start()

main()
