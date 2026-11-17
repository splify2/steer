"""Isolated core-service HY2 TCP adapter gate; never a full product claim."""
import argparse
import hashlib
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import threading
import time


def line(process, timeout=6):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError("bounded adapter/client response deadline")
    result = process.stdout.readline(4096).strip()
    if not result:
        raise RuntimeError("adapter/client exited before response")
    return result


def command(process, text, expected):
    process.stdin.write(text + "\n")
    process.stdin.flush()
    if line(process) != expected:
        raise AssertionError("unexpected command response: " + text.split()[0])


def stats(process, predicate):
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        process.stdin.write("stats\n")
        process.stdin.flush()
        fields = line(process).split()
        if len(fields) != 13 or fields[0] != "STATS":
            raise AssertionError("invalid host accounting")
        value = list(map(int, fields[1:]))
        if predicate(value):
            return value
        time.sleep(.01)
    raise AssertionError("host accounting barrier not reached: " + repr(value))


class Echo:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(.1)
        self.address = "127.0.0.1:" + str(self.listener.getsockname()[1])
        self.domain = "localhost:" + str(self.listener.getsockname()[1])
        self.lock = threading.Lock()
        self.accepts = 0
        self.connections = []
        self.workers = []
        self.stopped = threading.Event()
        self.hold_eof = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(5)
            with self.lock:
                self.accepts += 1
                self.connections.append(conn)
            worker = threading.Thread(target=self.echo, args=(conn,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def echo(self, conn):
        try:
            while not self.stopped.is_set():
                data = conn.recv(16384)
                if not data:
                    # Keep backend write open after FIN: target read is pending
                    # until QUIC cancellation, independent of EOF scheduling.
                    while self.hold_eof.is_set() and not self.stopped.wait(.01):
                        pass
                    conn.shutdown(socket.SHUT_WR)
                    return
                conn.sendall(data)
        except OSError:
            pass
        finally:
            conn.close()

    def count(self):
        with self.lock:
            return self.accepts

    def close(self):
        self.stopped.set()
        self.listener.close()
        with self.lock:
            for conn in self.connections:
                conn.close()
        self.thread.join(1)
        for worker in self.workers:
            worker.join(.2)


class SlowSink(Echo):
    def echo(self, conn):
        conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        while not self.stopped.wait(.05):
            pass
        conn.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    args = parser.parse_args()
    for label in ("host", "client"):
        path = getattr(args, label).resolve(strict=True)
        setattr(args, label, path)
        print(label, "sha256=" + hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    env = dict(os.environ, STEER_LAB_HY2_TOKEN=secrets.token_urlsafe(24))
    processes = []
    bad = None
    redactions = [env["STEER_LAB_HY2_TOKEN"]]
    echo = Echo()
    slow = SlowSink()

    def launch(path, arguments=(), environment=env):
        process = subprocess.Popen([str(path), *arguments], env=environment, text=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        processes.append(process)
        redactions.append(environment["STEER_LAB_HY2_TOKEN"])
        return process

    try:
        host = launch(args.host)
        ready = line(host).split()
        if len(ready) != 2 or ready[0] != "PORT" or not 0 < int(ready[1]) < 65536:
            raise AssertionError("invalid endpoint startup")
        address = "127.0.0.1:" + ready[1]
        web = launch(args.client, [address, "web"])
        if line(web) != "PASS owned web body" or web.wait(timeout=3):
            raise AssertionError("owned optional config body")
        bad = launch(args.client, [address], dict(env, STEER_LAB_HY2_TOKEN=secrets.token_urlsafe(24)))
        if bad.wait(timeout=5) == 0:
            raise AssertionError("invalid auth unexpectedly accepted")
        if echo.count():
            raise AssertionError("invalid auth reached target")
        client = launch(args.client, [address])
        if line(client) != "READY HY2 TCP":
            raise AssertionError("client handshake")
        command(client, "echo " + echo.address + " 524288", "PASS echo")
        command(client, "echo " + echo.domain + " 65536", "PASS echo")
        command(client, "hold " + echo.address, "PASS hold")
        command(host, "deny", "ACK deny")
        before = echo.count()
        command(client, "reject " + echo.address, "PASS reject")
        if echo.count() != before:
            raise AssertionError("retired listener minted a target flow")
        command(client, "send", "PASS send")
        command(host, "allow", "ACK allow")
        command(client, "echo " + echo.address + " 16384", "PASS echo")
        command(host, "epoch", "ACK epoch")
        before = echo.count()
        command(client, "reject " + echo.address, "PASS reject")
        if echo.count() != before:
            raise AssertionError("revoked auth epoch minted a target flow")
        command(client, "send", "PASS send")
        neighbor = launch(args.client, [address])
        if line(neighbor) != "READY HY2 TCP":
            raise AssertionError("new epoch neighbor handshake")
        command(neighbor, "hold " + echo.domain, "PASS hold")
        stats(host, lambda s: s[1] == 2 and s[4] == 2)
        command(neighbor, "capacity " + echo.address, "PASS capacity 15")
        command(neighbor, "send", "PASS send")
        command(client, "send", "PASS send")
        command(neighbor, "drop-filled", "PASS drop-filled")
        stats(host, lambda s: s[1] == 2)
        command(neighbor,"recover " + echo.address + " 15","PASS recover 15")
        command(neighbor,"send","PASS send")
        command(neighbor,"drop-filled","PASS drop-filled")
        stats(host,lambda s:s[1]==2)
        for _ in range(40):
            command(neighbor, "echo " + echo.address + " 4096", "PASS echo")
            stats(host, lambda s: s[1] == 2)
        # Target read is known pending before client cancellation.
        before = stats(host, lambda s: s[4] >= 2)
        echo.hold_eof.set()
        command(neighbor, "drop", "PASS drop")
        stats(host, lambda s: s[1] == 1 and s[8] > before[8])
        echo.hold_eof.clear()
        command(client, "send", "PASS send")
        # Block a real resolver worker before route completion, then cancel.
        command(host, "dns-hold", "ACK dns-hold")
        command(neighbor, "open " + echo.domain, "PASS open")
        before = stats(host, lambda s: s[3] == 1)
        command(neighbor, "drop", "PASS drop")
        stats(host, lambda s: s[1] == 1 and s[7] > before[7])
        command(host, "dns-release", "ACK dns-release")
        # More cancelled retained input than the connection's1MiB credit.
        # Each barrier proves50000payload bytes reached engine before cancel;
        # leave stream credit for the upstream request's random padding.
        command(host, "dns-hold", "ACK dns-hold")
        for _ in range(25):
            command(neighbor, "queue " + echo.domain, "PASS queue")
            stats(host, lambda s: s[3] == 1 and s[11] == 50000)
            command(neighbor, "drop", "PASS drop")
            stats(host, lambda s: s[1] == 1 and not s[11])
        command(host, "dns-release", "ACK dns-release")
        command(client, "send", "PASS send")
        # Hold a real connected-success callback until after protocol cancel.
        command(host, "route-hold", "ACK route-hold")
        command(neighbor, "open " + echo.address, "PASS open")
        stats(host, lambda s: s[10] == 1 and s[3] == 1)
        command(neighbor, "drop", "PASS drop")
        before = stats(host, lambda s: s[6] == 1 and s[2] == 2)
        command(host, "route-release", "ACK route-release")
        stats(host, lambda s: s[1] == 1 and s[9] > before[9])
        command(client, "send", "PASS send")
        # Stop with a proven target read pending; all leases/ops must drain.
        stats(host, lambda s: s[4] == 1)
        command(host, "stop", "DRAINED leases=0 operations=0 buffers=0")
        if host.wait(timeout=3):
            raise AssertionError("adapter cleanup failure")
        for process in (client, neighbor):
            command(process, "quit", "PASS quit")
            if process.wait(timeout=3):
                raise AssertionError("client cleanup failure")
        # New lifecycle API gate, independent of host-side admission callback.
        paused = launch(args.host, environment=dict(env, STEER_LAB_PAUSED="1"))
        startup = line(paused).split()
        if len(startup)!=2 or startup[0]!="PORT":
            raise AssertionError("paused endpoint startup")
        address = "127.0.0.1:" + startup[1]
        probe = launch(args.client, [address])
        if select.select([probe.stdout], [], [], .2)[0]:
            raise AssertionError("prepared endpoint admitted a client")
        stats(paused, lambda s: not s[0] and not s[1])
        probe.kill();probe.wait(timeout=3)
        command(paused, "activate", "ACK activate")
        healthy = launch(args.client, [address])
        if line(healthy)!="READY HY2 TCP":
            raise AssertionError("activation handshake")
        command(healthy, "hold " + echo.address, "PASS hold")
        routing = launch(args.client, [address])
        if line(routing)!="READY HY2 TCP":
            raise AssertionError("routing client handshake")
        command(paused, "dns-hold", "ACK dns-hold")
        command(routing, "queue " + echo.domain, "PASS queue")
        stats(paused, lambda s: s[3]==1 and s[11]==50000)
        writing = launch(args.client, [address])
        if line(writing)!="READY HY2 TCP":
            raise AssertionError("writing client handshake")
        command(writing, "flood " + slow.address, "PASS flood")
        stats(paused, lambda s: s[3]==1 and s[4]>=1 and s[5]>=1)
        command(paused, "retire", "ACK retire")
        command(healthy, "send", "PASS send")
        before = echo.count()
        command(healthy, "reject " + echo.address, "PASS reject")
        if echo.count()!=before:
            raise AssertionError("retired endpoint admitted a new stream")
        probe = launch(args.client, [address])
        if select.select([probe.stdout], [], [], .2)[0]:
            raise AssertionError("retired endpoint admitted a new connection")
        stats(paused, lambda s: not any(s[:7]))
        probe.kill();probe.wait(timeout=3)
        for process in (healthy,routing,writing):
            command(process,"expect-end","PASS expect-end")
        command(paused, "dns-release", "ACK dns-release")
        command(paused, "stop", "DRAINED leases=0 operations=0 buffers=0")
        if paused.wait(timeout=3):
            raise AssertionError("retired endpoint drain failed")
        for process in (healthy,routing,writing):
            command(process,"quit","PASS quit")
            if process.wait(timeout=3):
                raise AssertionError("retired client cleanup")
        # Distinct engine capacity gate: QUIC allows16, engine only4 TCP flows.
        engine = launch(args.host,environment=dict(env,STEER_LAB_ENGINE_LIMIT="1"))
        startup=line(engine).split();address="127.0.0.1:"+startup[1]
        limited=launch(args.client,[address])
        if line(limited)!="READY HY2 TCP":
            raise AssertionError("engine capacity handshake")
        command(limited,"hold " + echo.address,"PASS hold")
        before=echo.count()
        command(limited,"capacity " + echo.address,"PASS capacity 3")
        if echo.count()!=before+3:
            raise AssertionError("engine rejection reached target")
        command(limited,"send","PASS send")
        command(limited,"drop-filled","PASS drop-filled")
        stats(engine,lambda s:s[1]==1)
        command(limited,"echo " + echo.address + " 4096","PASS echo")
        command(engine,"stop","DRAINED leases=0 operations=0 buffers=0")
        if engine.wait(timeout=3):
            raise AssertionError("engine capacity cleanup")
        command(limited,"quit","PASS quit")
        if limited.wait(timeout=3):
            raise AssertionError("engine client cleanup")
        print("PASS pinned Hysteria TCP binary echo/domain; auth/admission/epoch; cancelled streams preserve neighbors; stop drains leases/operations/buffers")
        print("No UDP, full-core, production or soak claim")
        print("PASS prepare-paused/activate/retire: old flow drains, new streams/connections refused; deadline cancels proven route/read/write and all callbacks drain")
    finally:
        for process in processes:
            failed = process.poll() not in (None, 0)
            if process.poll() is None:
                process.kill()
                process.wait(timeout=3)
            if failed:
                diagnostic = process.stderr.read(4096)
                for value in redactions:
                    diagnostic = diagnostic.replace(value, "<redacted>")
                # Expected auth rejection deliberately has no diagnostic output.
                if process is not bad:
                    print("child diagnostic:", diagnostic, flush=True)
            for stream in (process.stdin, process.stdout, process.stderr):
                stream.close()
        echo.close()
        slow.close()


if __name__ == "__main__":
    main()
