#!/usr/bin/env python3
"""Потоки для стенда hysteria2 (tests/run-hy2.sh): выгрузка на пределе и медленный читатель.

Два сценария, и оба про ОБРАТНОЕ ДАВЛЕНИЕ — то, что curl с файлом в 8 МиБ не показывает:

  выгрузка    sink (в пространстве сервера) принимает и считает принятое по секундам, send (у клиента)
              льёт в туннель без остановки и без предела скорости — быстрее, чем QUIC
              успевает шифровать. Проверяется, что приём идёт ровно: не встаёт на нули и не
              проваливается (сверку делает оболочка стенда по журналу sink).
  скачивание  serve (у сервера) отдаёт на каждое соединение образец без остановки, slowread (у
              клиента) читает его МЕДЛЕННО и сверяет побайтно. Память модуля при этом меряет
              оболочка стенда: клиент отстаёт от сети, и очередь к нему ограничена окном QUIC, а не
              растёт с каждым принятым байтом; а темп чтения показывает, доходит ли до сервера
              обновление окна приёма.

  hy2-flow.py sink     --ip A --port P --log ФАЙЛ        принимает; раз в секунду «ВРЕМЯ БАЙТ» в журнал
  hy2-flow.py send     --ip A --port P --secs T --conns N [--cc bbr]   льёт без остановки T секунд
  hy2-flow.py serve    --ip A --port P                   отдаёт образец на каждое соединение
  hy2-flow.py slowread --ip A --port P --secs T --conns N --kbps K     читает K КБ/с на соединение

Образец — повторяющийся блок простой длины (65521): ни размер сообщения клиентской стороны (16000),
ни сегмент TCP, ни пакет QUIC на него не делятся, и перестановка, потеря или двойная отдача куска
очереди сбивают сверку сразу, а не по совпадению.
"""
import argparse
import socket
import sys
import threading
import time

PERIOD = 65521          # простое: ни с одним размером кусков по пути не совпадает


def pattern():
    b = bytearray(PERIOD)
    x = 12345
    for i in range(PERIOD):
        x = (x * 1103515245 + 12345) & 0x7FFFFFFF
        b[i] = (x >> 16) & 0xFF
    return bytes(b)


def listen(ip, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, port))
    s.listen(64)
    print("ready", flush=True)
    return s


def sink(a):
    srv = listen(a.ip, a.port)
    got = [0]
    live = [0]               # открытых соединений сейчас
    seen = [0]               # было ли хоть одно
    lock = threading.Lock()

    def report():
        # Журнал ведётся с первого принятого соединения и до закрытия последнего: пустые секунды ДО
        # и ПОСЛЕ выгрузки в него не попадают, а любая нулевая секунда посередине — это останов.
        t0 = time.time()
        last = 0
        with open(a.log, "w") as f:
            while True:
                time.sleep(1.0)
                cur = got[0]
                f.write(f"{int(time.time() - t0)} {cur - last}\n")
                f.flush()
                last = cur
                with lock:
                    if live[0] == 0:
                        return

    def rx(c):
        buf = bytearray(1 << 20)
        while True:
            try:
                n = c.recv_into(buf)
            except OSError:
                break
            if n == 0:
                break
            got[0] += n
        c.close()
        with lock:
            live[0] -= 1

    while True:
        c, _ = srv.accept()
        with lock:
            live[0] += 1
            first = not seen[0]
            seen[0] = 1
        if first:
            threading.Thread(target=report, daemon=True).start()
        threading.Thread(target=rx, args=(c,), daemon=True).start()


def send(a):
    stop = time.time() + a.secs
    total = [0]
    socks = []
    buf = b"\0" * (1 << 20)

    def tx(s):
        while time.time() < stop:
            try:
                s.sendall(buf)
                total[0] += len(buf)
            except OSError:
                break

    ths = []
    for _ in range(a.conns):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if a.cc:
            try:
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_CONGESTION, a.cc.encode())
            except OSError:
                print(f"предупреждение: перегрузка {a.cc} недоступна — берётся умолчание ядра", file=sys.stderr)
        s.settimeout(30)
        s.connect((a.ip, a.port))
        s.settimeout(None)
        socks.append(s)
        th = threading.Thread(target=tx, args=(s,), daemon=True)
        th.start()
        ths.append(th)
    # Выгрузка, которая встала, держит sendall вечно: ждём не дольше срока и три секунды сверху,
    # потом обрываем сами. Здоровая кончается в срок, и закрытие идёт сразу — приёмнику не нужна
    # лишняя «пустая» секунда в конце журнала.
    for th in ths:
        th.join(max(0.0, stop + 3 - time.time()))
    for s in socks:
        try:
            s.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        s.close()
    print(f"sent={total[0]}", flush=True)


def serve(a):
    srv = listen(a.ip, a.port)
    pat = pattern()

    def tx(c):
        try:
            while True:
                c.sendall(pat)
        except OSError:
            pass
        c.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=tx, args=(c,), daemon=True).start()


def slowread(a):
    pat = pattern()
    big = pat + pat
    stop = time.time() + a.secs
    res = []
    lock = threading.Lock()

    def rd(i):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(30)
        s.connect((a.ip, a.port))
        pos = 0
        bad = 0
        # Читаем кусками по 32 КБ и после каждого спим столько, чтобы выйти на a.kbps.
        step = 32768
        while time.time() < stop:
            try:
                d = s.recv(step)
            except OSError:
                break
            if not d:
                break
            p = pos % PERIOD
            if d != big[p:p + len(d)]:
                bad += 1
            pos += len(d)
            time.sleep(len(d) / (a.kbps * 1000.0))
        s.close()
        with lock:
            res.append((pos, bad))

    ths = [threading.Thread(target=rd, args=(i,)) for i in range(a.conns)]
    for t in ths:
        t.start()
    for t in ths:
        t.join()
    print(f"read={sum(p for p, _ in res)} bad={sum(b for _, b in res)} conns={len(res)}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["sink", "send", "serve", "slowread"])
    ap.add_argument("--ip", required=True)
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--secs", type=int, default=20)
    ap.add_argument("--conns", type=int, default=1)
    ap.add_argument("--kbps", type=int, default=1000)
    ap.add_argument("--log", default="/dev/null")
    ap.add_argument("--cc", default="")
    a = ap.parse_args()
    {"sink": sink, "send": send, "serve": serve, "slowread": slowread}[a.mode](a)


if __name__ == "__main__":
    main()
