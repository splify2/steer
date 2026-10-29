#!/usr/bin/env python3
"""Клиент стенда нескольких рабочих потоков (tests/run-tunnel-mt.sh, R-146).

Открывает CONNS соединений разом к потоковому эху (tests/fake-vless.py, порт 8), каждое шлёт MB мегабайт
своего содержимого и ОДНОВРЕМЕННО читает его обратно, сверяя байт в байт. Содержимое у каждого соединения
своё и зависит от смещения блока, поэтому перепутанные между соединениями, пропущенные, повторённые
или переставленные куски не совпадут нигде. Код выхода 0 — все соединения вернули ровно то, что
отправили.

Зачем так. Раздача пакетов по рабочим потокам ломается тихо: половина соединения у чужого потока — и
соединение просто не идёт (подтверждения не доходят до владельца). «Дошло ли» отвечает ТОЛЬКО сверка
всего объёма, а одно соединение этого не покажет: при хэше по соединению оно попадёт одному потоку и
в любом случае пройдёт.
"""
import random
import socket
import sys
import threading
import time

BLOCK = 1 << 16


def block_of(base, b):
    """Блок номер b: база, сдвинутая на b*37 байт, — соседние блоки не совпадают."""
    k = (b * 37) % BLOCK
    return base[k:] + base[:k]


def one(idx, host, port, mb, res):
    base = random.Random(idx).randbytes(BLOCK)
    total = mb * 1024 * 1024
    try:
        s = socket.create_connection((host, port), timeout=60)
    except OSError as e:
        res[idx] = "соединение: %r" % e
        return
    s.settimeout(60)

    def writer():
        try:
            sent, b = 0, 0
            while sent < total:
                chunk = block_of(base, b)[: min(BLOCK, total - sent)]
                s.sendall(chunk)
                sent += len(chunk)
                b += 1
            s.shutdown(socket.SHUT_WR)
        except OSError as e:
            res[idx] = "запись: %r" % e

    t = threading.Thread(target=writer, daemon=True)
    t.start()
    got, b, buf = 0, 0, b""
    try:
        while got < total:
            chunk = s.recv(1 << 16)
            if not chunk:
                break
            buf += chunk
            while len(buf) >= min(BLOCK, total - got):
                n = min(BLOCK, total - got)
                if buf[:n] != block_of(base, b)[:n]:
                    res[idx] = "байты расходятся в блоке %d (принято %d из %d)" % (b, got, total)
                    return
                buf = buf[n:]
                got += n
                b += 1
                if got >= total:
                    break
    except OSError as e:
        res[idx] = "чтение: %r (принято %d из %d)" % (e, got, total)
        return
    t.join(timeout=30)
    if got != total:
        res[idx] = "принято %d из %d" % (got, total)
    elif idx not in res:
        res[idx] = None
    s.close()


def main():
    host, port, conns, mb = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4])
    res = {}
    ts = [threading.Thread(target=one, args=(i, host, port, mb, res)) for i in range(conns)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=150)
    dt = time.monotonic() - t0
    bad = [(i, res.get(i, "не завершилось")) for i in range(conns) if res.get(i, "x") is not None]
    for i, why in bad[:10]:
        print("  соединение %d: %s" % (i, why))
    ok = conns - len(bad)
    print("  mtclient: %d из %d соединений вернули %d МБ байт в байт за %.1f с" % (ok, conns, mb, dt))
    sys.exit(0 if not bad else 1)


if __name__ == "__main__":
    main()
