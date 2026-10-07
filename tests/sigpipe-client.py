#!/usr/bin/env python3
"""Клиент локальной сети для стенда tests/sigpipe.sh: много соединений через туннель, которые
обрываются в самый неудобный момент.

    sigpipe-client.py ЦЕЛЬ --ping                       одно соединение «строка — эхо»: туннель жив?
    sigpipe-client.py ЦЕЛЬ --storm СЕК [--up N] [--abort-up N] [--abort-down N]

Три вида рабочих, все — в цикле «соединиться, нагрузить, оборвать, снова» до конца срока:

  up        выгрузка на порт 80 поддельного узла (tests/sigpipe-node.py): узел сам закрывает соединение
            после случайного числа байт, пока клиент ещё шлёт, — стек туннеля дописывает в закрытый
            сокет узла пакеты, уже лежавшие в очереди TUN. Рабочий шлёт, пока запись не вернёт ошибку
            (туннель ответил RST) или не кончится срок.
  abort-up  выгрузка на порт 82 (приёмник, который не закрывается): клиент сам обрывает соединение
            посреди передачи — RST (SO_LINGER 1,0), пока данные ещё в пути.
  abort-down скачивание с порта 81 (источник): клиент обрывает соединение RST, пока узел ещё шлёт.

Печатает одну строку с итогами по видам — сколько соединений открыто, сколько оборвано каким способом и
сколько байт ушло, — чтобы стенд видел, что нагрузка была настоящей.
"""
import argparse
import random
import socket
import struct
import sys
import threading
import time


def rst_close(s):
    """Закрыть, отправив RST: непрочитанное и неотправленное выбрасывается, а не доводится."""
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    try:
        s.close()
    except OSError:
        pass


def connect(target, port, timeout=5.0):
    s = socket.socket()
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.connect((target, port))
    return s


def ping(target):
    """Строка в туннель, эхо обратно: 0 — туннель жив."""
    t0 = time.time()
    last = "нет попыток"
    while time.time() - t0 < 20:
        try:
            s = connect(target, 7, 3.0)
            s.settimeout(3.0)
            s.sendall(b"ping\n")
            buf = b""
            while not buf.endswith(b"\n"):
                c = s.recv(4096)
                if not c:
                    break
                buf += c
            s.close()
            if buf == b"PONG ping\n":
                print("ping: ответ через %.2f с" % (time.time() - t0))
                return 0
            last = "ответ %r" % buf
        except OSError as e:
            last = "%s: %s" % (type(e).__name__, e)
        time.sleep(0.3)
    print("ping: туннель не ответил за 20 с (%s)" % last)
    return 1


class Stats:
    def __init__(self):
        self.lock = threading.Lock()
        self.d = {}

    def add(self, k, n=1):
        with self.lock:
            self.d[k] = self.d.get(k, 0) + n


def worker(kind, target, deadline, st):
    blob = b"\xa5" * (1 << 20)
    while time.time() < deadline:
        try:
            if kind == "up":
                s = connect(target, 80)
                s.settimeout(10.0)
                st.add("up:открыто")
                sent = 0
                try:
                    while time.time() < deadline:
                        sent += s.send(blob)
                    st.add("up:срок вышел")
                except socket.timeout:
                    st.add("up:застряло")
                except OSError:
                    # узел закрыл соединение, туннель ответил RST (или оборвал запись) — штатный исход
                    st.add("up:оборвано узлом")
                st.add("байт ушло", sent)
                rst_close(s)
            elif kind == "abort-up":
                s = connect(target, 82)
                s.settimeout(10.0)
                st.add("abort-up:открыто")
                want = random.randint(100 * 1024, 3 * 1024 * 1024)
                sent = 0
                try:
                    while sent < want and time.time() < deadline:
                        sent += s.send(blob[:min(len(blob), want - sent)])
                except OSError:
                    st.add("abort-up:ошибка записи")
                st.add("байт ушло", sent)
                rst_close(s)
                st.add("abort-up:RST")
            elif kind == "abort-down":
                s = connect(target, 81)
                s.settimeout(10.0)
                st.add("abort-down:открыто")
                want = random.randint(50 * 1024, 2 * 1024 * 1024)
                got = 0
                try:
                    while got < want and time.time() < deadline:
                        c = s.recv(262144)
                        if not c:
                            break
                        got += len(c)
                except OSError:
                    st.add("abort-down:ошибка чтения")
                st.add("байт принято", got)
                rst_close(s)
                st.add("abort-down:RST")
        except OSError as e:
            st.add("%s:не соединился (%s)" % (kind, type(e).__name__))
            time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("target")
    ap.add_argument("--ping", action="store_true")
    ap.add_argument("--storm", type=float, default=0, metavar="СЕК")
    ap.add_argument("--up", type=int, default=12)
    ap.add_argument("--abort-up", type=int, default=6)
    ap.add_argument("--abort-down", type=int, default=6)
    a = ap.parse_args()
    if a.ping:
        sys.exit(ping(a.target))
    if a.storm <= 0:
        ap.error("нужен --ping или --storm СЕК")
    st = Stats()
    deadline = time.time() + a.storm
    ts = []
    for kind, n in (("up", a.up), ("abort-up", a.abort_up), ("abort-down", a.abort_down)):
        for _ in range(n):
            ts.append(threading.Thread(target=worker, args=(kind, a.target, deadline, st), daemon=True))
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=a.storm + 30)
    print("клиент: " + " ".join("%s=%d" % kv for kv in sorted(st.d.items())))


main()
