#!/usr/bin/env python3
"""Нагрузка для tests/run-grpc.sh: долгие потоки в обе стороны и короткие «страницы», которые
открываются и закрываются, пока те идут.

  grpc-load.py --target ХОСТ:ПОРТ --dur СЕК [--down N] [--up N] [--rate R] [--kb К] [--report СЕК]

Цель — сервер tests/grpc-target.py: /big/<МБ> отдаёт данные без конца, /up принимает выгрузку.

Что измеряется и что считается провалом (код выхода 1, причины — в последней строке «ИТОГ»):
  - короткие «страницы» (GET /pg/<КБ>, Connection: close): каждая обязана прийти ЦЕЛИКОМ и закрыться —
    усечённая (меньше КБ), зависшая (нет конца за срок) или сброшенная считается отказом, их число — 0;
  - долгие потоки: за окно report секунд каждое направление обязано сдвинуться (иначе — «встало»), и ни
    один поток не должен оборваться до конца прогона;
  - по окнам печатаются Мбит/с вниз и вверх, число страниц и отказов.
"""
import argparse, socket, sys, threading, time, collections

ap = argparse.ArgumentParser()
ap.add_argument('--target', required=True)
ap.add_argument('--dur', type=float, default=190)
ap.add_argument('--down', type=int, default=2, help='долгих потоков вниз')
ap.add_argument('--up', type=int, default=2, help='долгих потоков вверх')
ap.add_argument('--rate', type=float, default=10, help='коротких страниц в секунду')
ap.add_argument('--kb', type=int, default=30)
ap.add_argument('--report', type=float, default=10)
ap.add_argument('--page-timeout', type=float, default=15)
ap.add_argument('--stall', type=float, default=15, help='сколько секунд без движения — «встало»')
a = ap.parse_args()

host, port = a.target.rsplit(':', 1)
port = int(port)
lock = threading.Lock()
t_start = time.time()
t_end = t_start + a.dur
cnt = {'down': 0, 'up': 0}                  # байт за всё время
last_move = {'down': time.time(), 'up': time.time()}
pages = {'ok': 0, 'fail': 0, 'why': collections.Counter()}
long_dead = []                              # потоки, оборвавшиеся раньше конца
stalls = []

def conn():
    s = socket.create_connection((host, port), timeout=20)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(30)
    return s

def down_flow(i):
    try:
        s = conn()
        s.sendall(('GET /big/100000 HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n').encode())
        while time.time() < t_end:
            d = s.recv(1 << 20)
            if not d:
                raise OSError('EOF от сервера')
            with lock:
                cnt['down'] += len(d)
                last_move['down'] = time.time()
        s.close()
    except Exception as e:
        if time.time() < t_end - 1:
            with lock:
                long_dead.append('вниз#%d: %s: %s' % (i, type(e).__name__, e))

def up_flow(i):
    try:
        s = conn()
        s.sendall(('POST /up HTTP/1.1\r\nHost: t\r\nContent-Length: 100000000000\r\nConnection: close\r\n\r\n').encode())
        blk = b'u' * (256 * 1024)
        while time.time() < t_end:
            s.sendall(blk)
            with lock:
                cnt['up'] += len(blk)
                last_move['up'] = time.time()
        s.close()
    except Exception as e:
        if time.time() < t_end - 1:
            with lock:
                long_dead.append('вверх#%d: %s: %s' % (i, type(e).__name__, e))

def page():
    why = None
    try:
        s = socket.create_connection((host, port), timeout=a.page_timeout)
        s.settimeout(a.page_timeout)
        s.sendall(('GET /pg/%d HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n' % a.kb).encode())
        got = 0
        while True:
            d = s.recv(65536)
            if not d:
                break
            got += len(d)
        s.close()
        if got < a.kb * 1024:
            why = 'усечена (%d из %d)' % (got, a.kb * 1024)
    except socket.timeout:
        why = 'зависла (нет конца за %gс)' % a.page_timeout
    except Exception as e:
        why = '%s' % type(e).__name__
    with lock:
        if why:
            pages['fail'] += 1
            pages['why'][why.split(' (')[0]] += 1
        else:
            pages['ok'] += 1

threads = []
for i in range(a.down):
    t = threading.Thread(target=down_flow, args=(i,), daemon=True); t.start(); threads.append(t)
for i in range(a.up):
    t = threading.Thread(target=up_flow, args=(i,), daemon=True); t.start(); threads.append(t)

prev = dict(cnt); prev_t = time.time()
next_page = time.time() + 1.0         # страницы начинаются, когда долгие потоки уже разогнались
next_rep = time.time() + a.report
page_threads = []
while time.time() < t_end:
    now = time.time()
    if a.rate > 0 and now >= next_page:
        t = threading.Thread(target=page, daemon=True); t.start(); page_threads.append(t)
        next_page += 1.0 / a.rate
    if now >= next_rep:
        with lock:
            dt = now - prev_t
            dn = (cnt['down'] - prev['down']) * 8 / dt / 1e6
            up = (cnt['up'] - prev['up']) * 8 / dt / 1e6
            prev = dict(cnt); prev_t = now
            print('t=%4.0fс вниз %7.1f Мбит/с  вверх %7.1f Мбит/с  страниц %d (отказов %d)' % (
                now - t_start, dn, up, pages['ok'] + pages['fail'], pages['fail']), flush=True)
            for k in ('down', 'up'):
                n = a.down if k == 'down' else a.up
                if n and now - last_move[k] > a.stall:
                    stalls.append('%s: нет движения %.0f с на %.0f-й секунде' % (k, now - last_move[k], now - t_start))
        next_rep += a.report
    time.sleep(0.005)

for t in page_threads:
    t.join(timeout=a.page_timeout + 2)

bad = []
if pages['fail']:
    bad.append('страниц с отказом: %d (%s)' % (pages['fail'], dict(pages['why'])))
if long_dead:
    bad.append('долгие потоки оборвались: ' + '; '.join(long_dead[:4]))
if stalls:
    bad.append('поток встал: ' + '; '.join(stalls[:3]))
if a.down and cnt['down'] == 0:
    bad.append('вниз не передано ни байта')
if a.up and cnt['up'] == 0:
    bad.append('вверх не передано ни байта')
print('ИТОГ: страниц %d ok / %d отказов; передано вниз %.0f МБ, вверх %.0f МБ; %s' % (
    pages['ok'], pages['fail'], cnt['down'] / 1e6, cnt['up'] / 1e6,
    'ПРОВАЛ — ' + ' | '.join(bad) if bad else 'без отказов'), flush=True)
sys.exit(1 if bad else 0)
