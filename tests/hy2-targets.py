#!/usr/bin/env python3
"""Цели для стенда tests/run-hy2.sh: то, к чему ходит клиент ЧЕРЕЗ туннель hysteria2.

Живут в сетевом пространстве сервера hysteria2 (настоящего, apernet/hysteria) на адресе, которого у
клиента нет вовсе, — попасть туда можно только через туннель:

  TCP :80    GET /big.bin — файл заданного размера (случайное, но одно и то же содержимое: по нему
             сверяется хеш), PUT /up — принимает тело и отвечает числом принятых байт;
  UDP :53    ответчик DNS: на любой запрос типа A отвечает 192.0.2.53 (разбор вопроса — руками);
  UDP :7     эхо: возвращает датаграмму как есть (проверка фрагментации: 3000 байт не влезают в один
             датаграмм QUIC);
  UDP :9     сумма: отвечает sha256 принятой датаграммы и её длиной — ответ короткий, поэтому им
             проверяется ПУТЬ ТУДА для крупных датаграмм (эталонный сервер ответов от 4096 байт
             клиенту не возвращает, так что эхо на них не годится).
"""
import argparse
import hashlib
import http.server
import os
import socket
import struct
import threading


def dns_answer(q):
    if len(q) < 12:
        return None
    i = 12
    while i < len(q) and q[i] != 0:
        i += q[i] + 1
    end = i + 5
    qsec = q[12:end]
    hdr = q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00"
    ans = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([192, 0, 2, 53])
    return hdr + qsec + ans


def udp_loop(ip, port, fn):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    while True:
        d, a = s.recvfrom(65535)
        r = fn(d)
        if r:
            s.sendto(r, a)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--mb", type=int, default=8)
    a = ap.parse_args()

    big = os.path.join(a.dir, "big.bin")
    h = hashlib.sha256()
    with open(big, "wb") as f:
        blk = hashlib.sha256(b"hy2").digest() * 1024
        for _ in range(a.mb * 32):
            f.write(blk)
            h.update(blk)
    with open(os.path.join(a.dir, "big.sha256"), "w") as f:
        f.write(h.hexdigest() + "\n")

    class H(http.server.SimpleHTTPRequestHandler):
        def __init__(self, *args, **kw):
            super().__init__(*args, directory=a.dir, **kw)

        def log_message(self, *args):
            pass

        def do_PUT(self):
            n = int(self.headers.get("Content-Length", "0"))
            got = 0
            while got < n:
                b = self.rfile.read(min(65536, n - got))
                if not b:
                    break
                got += len(b)
            body = ("%d\n" % got).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer((a.ip, 80), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    threading.Thread(target=udp_loop, args=(a.ip, 53, dns_answer), daemon=True).start()
    threading.Thread(target=udp_loop, args=(a.ip, 7, lambda d: d), daemon=True).start()
    threading.Thread(target=udp_loop, args=(a.ip, 9, lambda d: hashlib.sha256(d).hexdigest().encode()
                                            + b" %d" % len(d)), daemon=True).start()
    print("targets: ready", flush=True)
    threading.Event().wait()


if __name__ == "__main__":
    main()
