#!/usr/bin/env python3
"""Долгий стенд выхода VLESS (tests/vless-soak.sh): трафик, простои и обрывы по расписанию.

Запускается в пространстве клиента (ip netns exec), туннель и сервер поднимает vless-soak.sh. Здесь —
нагрузка и беды, которые с выходом случаются со временем, и приговор: после каждой беды трафик через
выход обязан вернуться сам, без перезапуска, а дескрипторы и потоки процесса — не копиться.

Нагрузка (всё время, кроме фазы простоя):
  - проба: каждые 2 с новое соединение и GET — по ней считается «трафик идёт»;
  - держатели: соединения keep-alive, каждое переиспользуется после паузы 5 с … 12 мин (как браузер и
    приложения); переиспользование обязано либо пройти, либо отказать быстро (RST/FIN), а не висеть;
  - UDP: каждую секунду датаграмма с нового порта к эху за узлом;
  - закачка 16 МБ раз в 3 мин, залп из 120 соединений раз в 4 мин;
  - брошенные: соединения с недописанным запросом, до 40 сразу, старые закрываются RST.

Беды по кругу: простой (тишина дольше connIdle Xray), kill -9 сервера, глухая потеря связи с узлом
(пакеты к узлу и от него молча отбрасываются), «как ТСПУ» (TCP устанавливается, данные пропадают), смена адреса узла (имя узла в hosts указывает на другой
адрес, прежний исчезает молча), падение WAN (интерфейс вниз и вверх).
"""
import argparse
import json
import os
import random
import socket
import struct
import subprocess
import sys
import threading
import time

P = argparse.ArgumentParser()
P.add_argument("--minutes", type=float, default=60)
P.add_argument("--pid", type=int, default=0, help="pid процесса туннеля (на этой машине)")
P.add_argument("--proc-cmd", default="", help="вместо --pid: команда, печатающая «fd rss_кб потоков» процесса "
               "туннеля (туннель на другой машине, скажем на роутере стенда)")
P.add_argument("--set-node-cmd", default="", help="команда смены адреса узла, {ip} — новый адрес "
               "(по умолчанию — запись в --hosts)")
P.add_argument("--wan-down-cmd", default="", help="команда падения WAN (по умолчанию — ip link down --wan)")
P.add_argument("--wan-up-cmd", default="", help="команда подъёма WAN")
P.add_argument("--work", required=True)
P.add_argument("--sv", required=True, help="пространство сервера")
P.add_argument("--hosts", default="", help="файл hosts пространства клиента")
P.add_argument("--node", required=True, help="имя узла в подписке")
P.add_argument("--ip-a", required=True)
P.add_argument("--ip-b", required=True)
P.add_argument("--target", required=True)
P.add_argument("--xray", required=True, help="команда сервера (строка для sh)")
P.add_argument("--wan", default="cl0")
P.add_argument("--wan-gw", default="")
P.add_argument("--node-net", default="")
P.add_argument("--port", type=int, default=443)
P.add_argument("--idle", type=int, default=330, help="фаза простоя, с")
P.add_argument("--recover", type=int, default=180, help="предел восстановления после беды, с")
P.add_argument("--steady", type=int, default=120, help="ровный трафик между бедами, с")
P.add_argument("--crowd", type=int, default=0, help="устройств в толпе (0 — без толпы)")
P.add_argument("--crowd-conns", type=int, default=8, help="соединений keep-alive у устройства толпы")
P.add_argument("--udp-spray", type=float, default=0, help="новых потоков UDP в секунду к разным адресам "
               "(как DHT торрента или QUIC многих вкладок); 0 — нет")
P.add_argument("--spray-net", default="203.0.113", help="первые три октета адресов --udp-spray")
P.add_argument("--only", default="", help="беды через запятую (по умолчанию все по кругу)")
A = P.parse_args()

T0 = time.monotonic()
LOG = open(os.path.join(A.work, "soak.log"), "a", buffering=1)
lock = threading.Lock()
quiet = threading.Event()        # фаза простоя: нагрузка молчит
stop = threading.Event()


def now():
    return time.monotonic() - T0


def log(*a):
    s = "%8.1f %s" % (now(), " ".join(str(x) for x in a))
    with lock:
        LOG.write(s + "\n")
        print(s, flush=True)


# ---- клиент HTTP -------------------------------------------------------------------------------

def http_get(sock, n, timeout):
    sock.settimeout(timeout)
    sock.sendall(b"GET /%d HTTP/1.1\r\nHost: t\r\n\r\n" % n)
    buf = b""
    while b"\r\n\r\n" not in buf:
        d = sock.recv(65536)
        if not d:
            raise ConnectionError("FIN до ответа")
        buf += d
    head, body = buf.split(b"\r\n\r\n", 1)
    cl = 0
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            cl = int(line.split(b":")[1])
    got = len(body)
    while got < cl:
        d = sock.recv(min(1 << 20, cl - got))
        if not d:
            raise ConnectionError("FIN посреди ответа (%d из %d)" % (got, cl))
        got += len(d)
    return got


def fetch_new(n, timeout=10):
    s = socket.socket()
    try:
        s.settimeout(timeout)
        s.connect((A.target, 80))
        return http_get(s, n, timeout)
    finally:
        s.close()


def errname(e):
    if isinstance(e, socket.timeout):
        return "timeout"
    return type(e).__name__ + (":" + str(e.errno) if getattr(e, "errno", None) else "")


# ---- счётчики ------------------------------------------------------------------------------------

probes = []          # (t, ok, ошибка)
stats = {"crowd_live": 0, "crowd_open_fail": 0, "crowd_req_fail": 0, "crowd_gone": 0, "keep_ok": 0, "keep_fast_fail": 0, "keep_hang": 0, "keep_reopen_fail": 0,
         "udp_ok": 0, "udp_fail": 0, "bulk_ok": 0, "bulk_fail": 0, "burst_ok": 0, "burst_fail": 0}
mon = []             # (t, fd, rss_kb, threads)


def bump(k, v=1):
    with lock:
        stats[k] += v


def prober():
    while not stop.is_set():
        if quiet.is_set():
            time.sleep(0.5)
            continue
        t = now()
        try:
            fetch_new(2048, 8)
            ok, err = True, ""
        except Exception as e:      # noqa: BLE001 — стенд считает любой отказ
            ok, err = False, errname(e)
        with lock:
            probes.append((t, ok, err))
        time.sleep(max(0.0, 2.0 - (now() - t)))


def keeper(i):
    rnd = random.Random(i)
    s = None
    while not stop.is_set():
        if s is None:
            if quiet.is_set():
                time.sleep(1)
                continue
            try:
                s = socket.create_connection((A.target, 80), timeout=10)
                http_get(s, 1024, 10)
            except Exception:       # noqa: BLE001
                bump("keep_reopen_fail")
                if s:
                    s.close()
                s = None
                time.sleep(2)
                continue
        pause = rnd.choice([5, 20, 60, 150, 330, 720])
        end = now() + pause
        while now() < end and not stop.is_set():
            time.sleep(1)
        while quiet.is_set() and not stop.is_set():
            time.sleep(1)
        if stop.is_set():
            break
        t = now()
        try:
            http_get(s, 4096, 20)
            bump("keep_ok")
        except Exception as e:      # noqa: BLE001
            # Переиспользование мёртвого соединения: честно — быстрый отказ; висеть 20 с — нет.
            if isinstance(e, socket.timeout):
                bump("keep_hang")
                with lock:
                    hangs.append(now())
                log("держатель %d: переиспользование после %d с висит (%s)" % (i, pause, errname(e)))
            else:
                bump("keep_fast_fail")
            s.close()
            s = None
    if s:
        s.close()


def udper():
    while not stop.is_set():
        if quiet.is_set():
            time.sleep(0.5)
            continue
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(3)
        tok = os.urandom(16)
        try:
            u.sendto(tok, (A.target, 5353))
            d, _ = u.recvfrom(2048)
            bump("udp_ok" if d == tok else "udp_fail")
        except Exception:           # noqa: BLE001
            bump("udp_fail")
        finally:
            u.close()
        time.sleep(1)


def udp_spray():
    # Один сокет, как у торрента: каждая датаграмма — к новому адресу и порту, то есть новый поток туннеля.
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    k = 0
    while not stop.is_set():
        if quiet.is_set():
            time.sleep(0.5)
            continue
        k += 1
        dst = ("%s.%d" % (A.spray_net, 8 + k % 240), 20000 + (k // 240) % 40000)
        try:
            u.sendto(b"d1:ad2:id20:" + os.urandom(20) + b"e1:q4:ping1:t2:aa1:y1:qe", dst)
        except OSError:
            pass
        time.sleep(1.0 / A.udp_spray)


def bulk():
    while not stop.wait(180):
        if quiet.is_set():
            continue
        try:
            fetch_new(16 << 20, 60)
            bump("bulk_ok")
        except Exception as e:      # noqa: BLE001
            bump("bulk_fail")
            log("закачка 16 МБ: %s" % errname(e))


def burst():
    while not stop.wait(240):
        if quiet.is_set():
            continue
        res = []

        def one():
            try:
                fetch_new(65536, 20)
                res.append(1)
            except Exception:       # noqa: BLE001
                res.append(0)
        th = [threading.Thread(target=one) for _ in range(120)]
        for t in th:
            t.start()
        for t in th:
            t.join()
        bump("burst_ok", sum(res))
        bump("burst_fail", len(res) - sum(res))


def abandoner():
    held = []
    while not stop.wait(20):
        if quiet.is_set():
            continue
        try:
            s = socket.create_connection((A.target, 80), timeout=5)
            s.sendall(b"GET /1 HTTP/1.1\r\nHost:")
            held.append(s)
        except Exception:           # noqa: BLE001
            pass
        while len(held) > 40:
            s = held.pop(0)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
            s.close()
    for s in held:
        s.close()


# ---- толпа: много устройств, уходящих без FIN ----------------------------------------------------
#
# Устройство держит --crowd-conns соединений keep-alive и раз в 20-40 с шлёт по каждому запрос (приложение
# с пушами, мессенджер, вкладка). Раз в минуту одно устройство уходит без FIN — телефон ушёл из Wi-Fi: его
# порты попадают в набор правила nft пространства клиента, и ни один пакет этих соединений больше не
# выходит и не входит. Вместо ушедшего приходит новое. Туннель обязан отпускать соединения ушедших, иначе
# записи копятся, и новые соединения начинают получать отказ.

def crowd_nft():
    sh("nft -f - <<'E'\ntable inet soakgone {\n set p { type inet_service; }\n"
       " chain o { type filter hook output priority -300; policy accept; tcp sport @p drop; }\n"
       " chain i { type filter hook input priority -300; policy accept; tcp dport @p drop; }\n}\nE")


def crowd_open():
    try:
        s = socket.create_connection((A.target, 80), timeout=10)
        http_get(s, 256, 10)
        bump("crowd_live")
        return s
    except Exception:               # noqa: BLE001
        bump("crowd_open_fail")
        return None


def crowd_device(dev_id, gone_ev):
    rnd = random.Random(1000 + dev_id)
    socks = []
    while not stop.is_set() and not gone_ev.is_set():
        # Приложения держат свои соединения: отпущенное туннелем или не открывшееся открывается заново.
        while len(socks) < A.crowd_conns and not stop.is_set() and not quiet.is_set():
            s = crowd_open()
            if s is None:
                break
            socks.append(s)
        gone_ev.wait(rnd.uniform(20, 40))
        if stop.is_set() or gone_ev.is_set():
            break
        if quiet.is_set():
            continue
        for s in list(socks):
            try:
                http_get(s, 256, 15)
            except Exception:       # noqa: BLE001
                bump("crowd_req_fail")
                socks.remove(s)
                bump("crowd_live", -1)
                s.close()
    if gone_ev.is_set():
        ports = [str(s.getsockname()[1]) for s in socks]
        if ports:
            sh("nft add element inet soakgone p { %s }" % ", ".join(ports))
        bump("crowd_live", -len(socks))
        bump("crowd_gone", len(socks))
        crowd_ghosts.extend(socks)  # не закрывать: FIN всё равно не дошёл бы, а порт остаётся занятым
    else:
        for s in socks:
            s.close()


crowd_ghosts = []
hangs = []           # когда переиспользование висело
# Окна бед, в которых путь к узлу пропадал молча (без RST): соединение, открытое до беды, узнать о ней не может
# раньше порога молчания туннеля (silence, умолчание пула — 60 с) — его зависание там законно.
silent_windows = []
SILENCE_GRACE = 90


def crowd():
    crowd_nft()
    devs = {}
    nid = 0
    for _ in range(A.crowd):
        ev = threading.Event()
        threading.Thread(target=crowd_device, args=(nid, ev), daemon=True).start()
        devs[nid] = ev
        nid += 1
    while not stop.wait(60):
        if quiet.is_set():
            continue
        k = random.choice(list(devs))
        devs.pop(k).set()
        ev = threading.Event()
        threading.Thread(target=crowd_device, args=(nid, ev), daemon=True).start()
        devs[nid] = ev
        nid += 1


def proc_sample():
    if A.proc_cmd:
        for _ in range(3):
            r = subprocess.run(A.proc_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               text=True, timeout=60)
            v = r.stdout.split()
            if len(v) == 3 and all(x.isdigit() for x in v):
                return tuple(int(x) for x in v)
            time.sleep(2)
        return None
    pid = A.pid
    try:
        fd = len(os.listdir("/proc/%d/fd" % pid))
        rss = thr = 0
        with open("/proc/%d/status" % pid) as f:
            for line in f:
                if line.startswith("VmRSS:"):
                    rss = int(line.split()[1])
                elif line.startswith("Threads:"):
                    thr = int(line.split()[1])
        return fd, rss, thr
    except OSError:
        return None


def monitor():
    while not stop.is_set():
        s = proc_sample()
        if s is None:
            log("ПРОЦЕСС ТУННЕЛЯ ИСЧЕЗ (pid %d %s)" % (A.pid, A.proc_cmd))
            stop.set()
            return
        with lock:
            mon.append((now(),) + s)
        stop.wait(10)


# ---- беды ----------------------------------------------------------------------------------------

def sh(cmd, ns=None):
    if ns:
        cmd = "ip netns exec %s sh -c %s" % (ns, shlex_quote(cmd))
    return subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)


def shlex_quote(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


xray = {"p": None}


def xray_start():
    xray["p"] = subprocess.Popen(A.xray, shell=True, start_new_session=True,
                                 stdout=open(os.path.join(A.work, "xray.log"), "a"), stderr=subprocess.STDOUT)


def xray_kill():
    p = xray["p"]
    if p:
        try:
            os.killpg(p.pid, 9)
        except ProcessLookupError:
            pass
        p.wait()
        xray["p"] = None


cur_ip = {"ip": A.ip_a}


def set_hosts(ip):
    if A.set_node_cmd:
        sh(A.set_node_cmd.replace("{ip}", ip))
        return
    # Запись на месте, а не переименование: hosts пространства привязан к /etc/hosts по inode.
    with open(A.hosts, "r+") as f:
        f.seek(0)
        f.truncate()
        f.write("127.0.0.1 localhost\n%s %s\n" % (ip, A.node))


def d_idle():
    quiet.set()
    log("простой %d с: нагрузка молчит, держатели держат" % A.idle)
    stop.wait(A.idle)
    quiet.clear()


def d_kill():
    xray_kill()
    log("сервер убит (kill -9)")
    stop.wait(20)
    xray_start()
    log("сервер поднят заново")


def d_blackhole():
    r = sh("nft -f - <<'E'\ntable inet soakbh {\n chain i { type filter hook input priority -300; policy accept; "
           "tcp dport %d drop; }\n chain o { type filter hook output priority -300; policy accept; "
           "tcp sport %d drop; }\n}\nE" % (A.port, A.port), A.sv)
    log("глухая потеря связи с узлом на 90 с", r.stdout.strip())
    stop.wait(90)
    sh("nft delete table inet soakbh", A.sv)
    log("связь с узлом вернулась")


def d_tarpit():
    # Как ТСПУ: TCP с узлом устанавливается, а данные в обе стороны молча пропадают (рукопожатие TLS/Reality
    # и запрос VLESS повисают на установленном соединении, а не на SYN).
    r = sh("nft -f - <<'E'\ntable inet soaktp {\n chain i { type filter hook input priority -300; policy accept; "
           "tcp dport %d meta length > 80 drop; }\n chain o { type filter hook output priority -300; policy accept; "
           "tcp sport %d meta length > 80 drop; }\n}\nE" % (A.port, A.port), A.sv)
    log("узел принимает TCP, но данные пропадают — 120 с", r.stdout.strip())
    stop.wait(120)
    sh("nft delete table inet soaktp", A.sv)
    log("данные к узлу снова идут")


def d_ipchange():
    old = cur_ip["ip"]
    new = A.ip_b if old == A.ip_a else A.ip_a
    sh("ip addr add %s/32 dev node 2>/dev/null; true" % new, A.sv)
    set_hosts(new)
    sh("ip addr del %s/32 dev node" % old, A.sv)
    cur_ip["ip"] = new
    log("адрес узла сменился: %s → %s (прежний молчит)" % (old, new))


def d_wanflap():
    sh(A.wan_down_cmd or "ip link set %s down" % A.wan)
    log("WAN вниз на 20 с")
    stop.wait(20)
    sh(A.wan_up_cmd or "ip link set %s up; ip route replace %s via %s dev %s" % (A.wan, A.node_net, A.wan_gw, A.wan))
    log("WAN вверх")


DISRUPT = {"none": lambda: log("без беды"), "tarpit": d_tarpit, "idle": d_idle, "kill": d_kill, "blackhole": d_blackhole, "ipchange": d_ipchange,
           "wanflap": d_wanflap}
ORDER = [x for x in (A.only.split(",") if A.only else
                     ["idle", "kill", "blackhole", "ipchange", "tarpit", "wanflap", "idle", "ipchange"]) if x]


def wait_recover(limit):
    """5 проб подряд удачны — восстановились. Возвращает секунды или None."""
    t0 = now()
    with lock:
        start = len(probes)
    while now() - t0 < limit and not stop.is_set():
        with lock:
            tail = [ok for (_, ok, _) in probes[start:]]
        run = 0
        for ok in tail:
            run = run + 1 if ok else 0
            if run >= 5:
                return now() - t0
        time.sleep(1)
    return None


def window_rate(t_from):
    with lock:
        w = [ok for (t, ok, _) in probes if t >= t_from]
    return (sum(w), len(w))


def window_errors(t_from):
    """Отказы проб окна: {ошибка: [секунды стенда]} — чтобы провал ровного участка было с чем разбирать."""
    errs = {}
    with lock:
        for (t, ok, e) in probes:
            if t >= t_from and not ok:
                errs.setdefault(e, []).append(round(t))
    return errs


def main():
    set_hosts(A.ip_a)
    xray_start()
    time.sleep(2)
    for f in [prober, udper, bulk, burst, abandoner, monitor] + [lambda i=i: keeper(i) for i in range(16)]:
        threading.Thread(target=f, daemon=True).start()
    if A.crowd:
        threading.Thread(target=crowd, daemon=True).start()
    if A.udp_spray > 0:
        threading.Thread(target=udp_spray, daemon=True).start()

    deadline = A.minutes * 60
    verdict = []
    base = None
    rec = wait_recover(60)
    if rec is None:
        log("ТРАФИК НЕ ПОШЁЛ на старте")
        verdict.append("старт: трафик не пошёл")
    stop.wait(30)
    with lock:
        base = mon[-1] if mon else None
    log("старт: fd/rss/потоки", base)
    k = 0
    while now() < deadline - A.steady and not stop.is_set():
        name = ORDER[k % len(ORDER)]
        k += 1
        log("== беда %d: %s" % (k, name))
        t_beg = now()
        DISRUPT[name]()
        if name in ("blackhole", "ipchange", "tarpit", "wanflap"):
            silent_windows.append((t_beg, now() + SILENCE_GRACE))
        rec = wait_recover(A.recover)
        if rec is None:
            with lock:
                errs = {}
                for (t, ok, e) in probes[-60:]:
                    if not ok:
                        errs[e] = errs.get(e, 0) + 1
            log("НЕ ВОССТАНОВИЛСЯ за %d с после «%s»; отказы проб: %s" % (A.recover, name, errs))
            verdict.append("%s: не восстановился за %d с" % (name, A.recover))
            # Дальше мерить нечего, но ждём ещё круг — вдруг вернётся (для отчёта о времени).
            late = wait_recover(600)
            log("позднее восстановление:", "нет" if late is None else "%.0f с" % late)
            if late is None:
                break
        else:
            log("восстановился за %.1f с" % rec)
        t1 = now()
        stop.wait(A.steady)
        ok, n = window_rate(t1)
        log("ровный участок: проб %d/%d, счётчики %s, процесс %s" % (ok, n, json.dumps(stats), mon[-1] if mon else "-"))
        if n and ok < n * 0.95:
            verdict.append("%s: ровный участок после — проб %d/%d" % (name, ok, n))
            log("отказы проб ровного участка:", window_errors(t1))

    # Конец: нагрузку остановить, клиентские соединения закрыть, дать туннелю убрать за собой.
    stop.set()
    time.sleep(70)
    end = proc_sample()
    log("конец: fd/rss/потоки", end, "старт", base)
    if end is None:
        verdict.append("процесс туннеля исчез")
    elif base and end[0] > base[1] + 32:
        verdict.append("дескрипторы копятся: %d на старте → %d в покое после стенда" % (base[1], end[0]))
    bad = [t for t in hangs if not any(a <= t - 20 <= b or a <= t <= b for a, b in silent_windows)]
    if bad:
        verdict.append("переиспользование соединения висело вне бед с молчаливым обрывом: %d раз (%s)" %
                       (len(bad), ", ".join("%.0f" % t for t in bad)))
    xray_kill()
    with open(os.path.join(A.work, "soak.json"), "w") as f:
        json.dump({"verdict": verdict, "stats": stats, "mon": mon[-1:] + mon[:1],
                   "probes_fail": sum(1 for p in probes if not p[1]), "probes": len(probes)}, f,
                  ensure_ascii=False)
    log("ИТОГ:", "ЧИСТО" if not verdict else "; ".join(verdict))
    return 0 if not verdict else 1


if __name__ == "__main__":
    sys.exit(main())
