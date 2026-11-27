"""Ordinary DNS-over-TCP client slots; invoke via dns-tcpc-cost.sh only."""
import contextlib
import hashlib
import json
import math
import os
from pathlib import Path
import resource
import socket
import struct
import subprocess
import tempfile
import threading
import time

DNS = ("127.0.0.1", 15300)
UP = ("127.0.0.1", 15353)
QUESTION = b"\x04slot\x04test\0\0\1\0\1"
QUERY = struct.pack("!5H", 0x100, 1, 0, 0, 0) + QUESTION
ANSWER = (struct.pack("!5H", 0x8180, 1, 1, 0, 0) + QUESTION +
          struct.pack("!HHHIH", 0xc00c, 1, 1, 0, 4) + socket.inet_aton("192.0.2.42"))
CLEANUP = 12.5  # TCP_IDLE_SEC=10, plus the one-second reap tick and margin


def log(**fields):
    print(json.dumps(fields), flush=True)


def recv_n(sock, count):
    buf = bytearray()
    while len(buf) < count:
        data = sock.recv(count-len(buf))
        if not data:
            raise EOFError("incomplete DNS frame")
        buf.extend(data)
    return bytes(buf)


def frame(payload):
    return struct.pack("!H", len(payload)) + payload


def receive(sock):
    return recv_n(sock, struct.unpack("!H", recv_n(sock, 2))[0])


class Fixture(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.hits = 0
        self.listener = socket.create_server(UP)

    def run(self):
        while True:
            sock, _ = self.listener.accept()
            with sock:
                sock.settimeout(2)
                packet = receive(sock)
                assert packet[2:] == QUERY
                self.hits += 1
                sock.sendall(frame(packet[:2] + ANSWER))


def ask(sock, seq):
    tid = struct.pack("!H", seq)
    start = time.monotonic_ns()
    sock.sendall(frame(tid + QUERY))
    assert receive(sock) == tid + ANSWER
    return (time.monotonic_ns()-start)/1000


def control(sock, fixture):
    # Same established TCP connection for all 40 RTTs in each window.
    hits = fixture.hits
    samples = []
    for i in range(40):
        samples.append(ask(sock, 2000+i))
        time.sleep(.005)
    assert fixture.hits == hits+len(samples)
    samples.sort()
    return {f"p{p}_us": round(samples[math.ceil(len(samples)*p/100)-1], 1) for p in (50, 95)}


def sockets(proc, established_only=True):
    # Only the PID we spawned and its private netns. Count server-owned
    # accepted endpoints, not SYNs, backlog, upstreams or client-side FDs.
    fds = list((proc/"fd").iterdir())
    owned = {os.readlink(fd) for fd in fds}
    peers = set()
    for table in ("tcp", "tcp6"):
        for row in (proc/"net"/table).read_text().splitlines()[1:]:
            cols = row.split()
            local_port = int(cols[1].split(":")[1], 16)
            peer_port = int(cols[2].split(":")[1], 16)
            if (peer_port and local_port == DNS[1] and f"socket:[{cols[9]}]" in owned and
                    (not established_only or cols[3] == "01")):
                peers.add(peer_port)
    return len(fds), peers


def cpu(proc):
    return int((proc/"schedstat").read_text().split()[0])


def snapshot(proc, expected):
    fds, peers = sockets(proc)
    assert peers == {s.getsockname()[1] for s in expected}, (len(peers), len(expected))
    fields = {k.rstrip(":"):int(v) for k,v,*_ in
              (line.split() for line in (proc/"smaps_rollup").read_text().splitlines()[1:])}
    return dict(fd=fds, accepted=len(peers), rss_kib=fields["Rss"], pss_kib=fields["Pss"],
                anon_kib=fields["Anonymous"], cpu_ns=cpu(proc))


def quiet(proc):
    start = cpu(proc)
    t = time.monotonic()
    time.sleep(2.2)
    return dict(quiet_cpu_us=round((cpu(proc)-start)/1000, 1), quiet_s=round(time.monotonic()-t, 3))


def connect():
    return socket.create_connection(DNS, timeout=2)


def no_clients(proc):
    # A client close doesn't imply that dnsd has already consumed its FIN.
    until = time.monotonic()+2
    while sockets(proc, established_only=False)[1]:
        assert time.monotonic() < until
        time.sleep(.01)


def run_level(binary, level, fixture, tmp):
    # New process per level; same process, allocator and tables across both cycles.
    state = tmp/str(level)
    state.mkdir()
    with (state/"dnsd.log").open("w+") as err:
        child = subprocess.Popen([binary, "dnsd", "--spec", tmp/"spec", "--state-dir", state,
                                  "--listen-port", str(DNS[1]), "--upstream-port", str(UP[1])],
                                 stdout=err, stderr=err)
        proc = Path(f"/proc/{child.pid}")
        def emit(phase, **fields):
            log(level=level, pid=child.pid, phase=phase, **fields)
        try:
            until = time.monotonic()+4
            while True:
                assert child.poll() is None, "dnsd exited before readiness"
                try:
                    with connect() as sock:
                        # Warm the forwarding path and one tcpu slot.
                        ask(sock, 0)
                        baseline_rtt = control(sock, fixture)
                    break
                except ConnectionRefusedError:
                    assert time.monotonic() < until
                    time.sleep(.02)
            no_clients(proc)
            baseline = snapshot(proc, [])
            emit("baseline", **baseline, **baseline_rtt, **quiet(proc))
            for cycle in (1, 2):
                with connect() as sock:
                    pre = control(sock, fixture)
                no_clients(proc)
                emit("before", cycle=cycle, **snapshot(proc, []), **pre)
                replies = attempts = 0
                with contextlib.ExitStack() as stack:
                    held = []
                    hits = fixture.hits
                    start_cpu = cpu(proc)
                    start = time.monotonic()
                    for i in range(level):
                        attempts += 1
                        sock = stack.enter_context(connect())
                        held.append(sock)
                        ask(sock, i)
                        replies += 1
                        time.sleep(.002)  # bounded ramp; never >1 outstanding request
                    fill_ms = (time.monotonic()-start)*1000
                    fill_cpu_ms = (cpu(proc)-start_cpu)/1e6
                    assert fixture.hits == hits+level
                    peak = snapshot(proc, held)
                    assert peak["fd"] == baseline["fd"]+level
                    rtt = control(held[-1], fixture)  # included in the level, not N+1
                    idle = quiet(proc)
                    snapshot(proc, held)  # quiet measurement also stayed at N
                    emit("during", cycle=cycle, attempts=attempts, responses=replies,
                         forwarded=level, fill_ms=round(fill_ms, 2), fill_cpu_ms=round(fill_cpu_ms, 2),
                         **peak, **rtt, **idle)
                    time.sleep(CLEANUP)
                    # No client close until after proof of timer-based server close.
                    post = snapshot(proc, [])
                    assert post["fd"] == baseline["fd"]
                    for sock in held:
                        assert sock.recv(1) == b""
                idle = quiet(proc)
                with connect() as sock:
                    rtt = control(sock, fixture)
                emit("after", cycle=cycle, eof=level, cleanup_s=CLEANUP, **post, **rtt, **idle)
            assert child.poll() is None
        finally:
            child.terminate()
            child.wait(timeout=4)
            err.seek(0)
            emit("dnsd-log", log=err.read()[-2000:], exit=child.returncode)


def main():
    assert os.getpid() == 1 and os.getuid() == 65534 and socket.if_nameindex() == [(1, "lo")]
    soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    assert soft == resource.RLIM_INFINITY or soft >= 4096, "insufficient inherited NOFILE"
    resource.setrlimit(resource.RLIMIT_NOFILE, (4096, 4096))  # only lower the inherited ceiling
    binary = Path("/run/steerd")
    fixture = Fixture()
    fixture.start()
    log(kernel=os.uname().release, machine=os.uname().machine, sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        nofile=4096, tcp_client_limit=1024, levels=[1,100,1000], control_n=40, affinity=sorted(os.sched_getaffinity(0)))
    with tempfile.TemporaryDirectory() as name:
        tmp = Path(name)
        (tmp/"spec").write_text('{"schema":1,"from_default":["127.0.0.0/8"],'
                                '"outputs":{"direct":{"kind":"direct"}},"channels":[]}\n')
        for level in (1,100,1000):
            run_level(binary, level, fixture, tmp)
    log(result="PASS", fixture_responses=fixture.hits)


if __name__ == "__main__":
    main()
