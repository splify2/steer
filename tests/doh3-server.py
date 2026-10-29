#!/usr/bin/env python3
"""Сервер DoH по HTTP/3 для проверки клиента dnsd: настоящие QUIC, HTTP/3 и QPACK независимой реализации
(aioquic с pylsqpack — кодировщик ls-qpack на C), поведение — по пути запроса.

Зачем свой, если есть dnsproxy (tests/doh3up.sh, он тоже говорит по HTTP/3). dnsproxy отвечает всегда
правильно, а клиенту важны как раз неправильные и редкие случаи: отказ кодом 500, сброс потока, ответ
кусками, закрытие соединения посреди работы, молчание. Их удобно вызывать по пути запроса.

    doh3-server.py АДРЕС ПОРТ СЕРТИФИКАТ КЛЮЧ ЖУРНАЛ

Пути:
  /ok        ответ 200 на каждый вопрос (одна запись A, 203.0.113.99), заголовки ответа — с Хаффманом
  /st500     ответ 500 с телом; /st404 — 404
  /rst       на каждый вопрос сброс потока кодом H3_REQUEST_REJECTED
  /split     тело двумя кадрами DATA и пустой кадр GREASE между ними, и трейлеры после
  /silent    вопрос принимается, ответа нет
  /short     тело 5 байт (короче заголовка DNS)
  /close     после первого ответа на соединении — CONNECTION_CLOSE(H3_NO_ERROR); следующий вопрос
             на нём пропадает, клиент обязан пересоздать соединение

Журнал (по строке): «conn N», «settings cap=… blocked=…» (что клиент объявил), «req ПУТЬ метод authority
ct=… accept=… id=…» (id — номер сообщения DNS в теле), «closed N».
"""
import asyncio, os, sys

sys.path.insert(0, os.environ.get("DOH3_PYLIB", "/nonexistent"))
from aioquic.asyncio import QuicConnectionProtocol, serve
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import ConnectionTerminated, ProtocolNegotiated

addr, port, crt, key, logf = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4], sys.argv[5]
lg = open(logf, "a", buffering=1)
nconn = 0


def log(s):
    lg.write(s + "\n")


def answer(q):
    e = 12
    while q[e]:
        e += 1 + q[e]
    e += 5
    return (q[:2] + b"\x81\x80" + q[4:6] + b"\x00\x01\x00\x00\x00\x00" + q[12:e] +
            b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + bytes([203, 0, 113, 99]))


class Proto(QuicConnectionProtocol):
    def __init__(self, *a, **k):
        global nconn
        super().__init__(*a, **k)
        nconn += 1
        self.n = nconn
        self.http = None
        self.req = {}
        self.served = 0
        self.logged = False
        log("conn %d" % self.n)

    def quic_event_received(self, event):
        if isinstance(event, ProtocolNegotiated):
            self.http = H3Connection(self._quic)
        if isinstance(event, ConnectionTerminated):
            log("closed %d" % self.n)
        if self.http:
            for e in self.http.handle_event(event):
                self.h3(e)
            if not self.logged and self.http.received_settings is not None:
                s = self.http.received_settings
                log("settings cap=%s blocked=%s" % (s.get(1), s.get(7)))
                self.logged = True

    def h3(self, e):
        if isinstance(e, HeadersReceived):
            h = dict(e.headers)
            self.req[e.stream_id] = {"h": h, "body": b""}
        elif isinstance(e, DataReceived):
            self.req[e.stream_id]["body"] += e.data
        else:
            return
        if not e.stream_ended:
            return
        r = self.req.pop(e.stream_id)
        h, body = r["h"], r["body"]
        path = h.get(b":path", b"").decode()
        qid = (body[0] << 8 | body[1]) if len(body) >= 2 else -1
        log("req %s %s %s ct=%s accept=%s id=%d" % (path, h.get(b":method", b"").decode(), h.get(b":authority", b"").decode(),
            h.get(b"content-type", b"").decode(), h.get(b"accept", b"").decode(), qid))
        self.reply(e.stream_id, path, body)

    def reply(self, sid, path, body):
        self.served += 1
        hs = [(b":status", b"200"), (b"content-type", b"application/dns-message"), (b"server", b"doh3-test"),
              (b"cache-control", b"max-age=60")]
        if path == "/silent":
            return
        if path == "/rst":
            self._quic.reset_stream(sid, 0x10b)
            self.transmit()
            return
        if path == "/close" and self.served >= 2:
            return                                   # вопрос на «умершем» соединении пропадает
        if path in ("/st500", "/st404"):
            self.http.send_headers(sid, [(b":status", path[3:].encode()), (b"content-type", b"text/plain")])
            self.http.send_data(sid, b"nope", end_stream=True)
        elif path == "/short":
            self.http.send_headers(sid, hs)
            self.http.send_data(sid, b"12345", end_stream=True)
        elif path == "/split":
            a = answer(body)
            self.http.send_headers(sid, hs)
            self.http.send_data(sid, a[:7], end_stream=False)
            self._quic.send_stream_data(sid, b"\x21\x00", end_stream=False)       # пустой кадр GREASE
            self.http.send_data(sid, a[7:], end_stream=False)
            self.http.send_headers(sid, [(b"x-trailer", b"1")], end_stream=True)
        else:
            self.http.send_headers(sid, hs)
            self.http.send_data(sid, answer(body), end_stream=True)
        self.transmit()
        if path == "/close" and self.served == 1:
            self._quic.close(error_code=0x100)
            self.transmit()


async def main():
    cfg = QuicConfiguration(is_client=False, alpn_protocols=H3_ALPN)
    cfg.load_cert_chain(crt, key)
    await serve(addr, port, configuration=cfg, create_protocol=Proto)
    await asyncio.Future()


asyncio.run(main())
