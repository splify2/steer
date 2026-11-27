"""Linux acceptance fixture. Run only via direct_tcp_budget_test.sh."""
import asyncio
import copy
import json
import os
import resource
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from prototype_test import control, core
from prototype_socks_outbound_test import original, outbound
from socks_loopback_test import request as socks
from vless_loopback_test import request as vless

PORTS = (29071, 29072)
FRAME = 5003  # crosses the expanded relay slice
BLOCK = bytes(range(256)) * 128
BLOCKS = 512


def sample(pid):
    p = Path("/proc") / str(pid)
    fields = {s.split(":")[0]: int(s.split()[1]) for s in
              (p / "smaps_rollup").read_text().splitlines() if s.startswith(("Rss:", "Pss:"))}
    return dict(fd=len(list((p / "fd").iterdir())), **fields)


class Echo:
    def __init__(self, n):
        self.n = n
        self.gated = set()
        self.all_present = asyncio.Event()
        self.release = asyncio.Event()
        self.resume_slow = asyncio.Event()
        self.slow_started = asyncio.Event()
        self.errors = []

    async def serve(self, reader, writer):
        try:
            while tag := await reader.read(1):
                if tag == b"S":
                    self.slow_started.set()
                    await self.resume_slow.wait()
                    for _ in range(BLOCKS):
                        data = await reader.readexactly(len(BLOCK))
                        assert data == BLOCK
                        writer.write(data)
                        await writer.drain()
                    continue
                assert tag in (b"G", b"E")
                data = await reader.readexactly(FRAME)
                if tag == b"G":
                    self.gated.add(writer.get_extra_info("peername"))
                    if len(self.gated) == self.n:
                        self.all_present.set()
                    await self.release.wait()
                writer.write(data)
                await writer.drain()
        except Exception as e:
            self.errors.append(repr(e))
        finally:
            writer.close()

    async def barrier(self, peers, seq):
        self.gated.clear()
        self.all_present.clear()
        self.release.clear()
        jobs = [asyncio.create_task(exchange(p, i, seq, b"G")) for i, p in enumerate(peers)]
        try:
            await asyncio.wait_for(self.all_present.wait(), 8)
            assert len(self.gated) == self.n and not any(j.done() for j in jobs)
        finally:
            self.release.set()
        await asyncio.gather(*jobs)
        return len(self.gated)


async def exchange(peer, i, seq, tag=b"E"):
    r, w = peer
    data = (i.to_bytes(4, "big") + seq.to_bytes(4, "big")) * (FRAME // 8) + b"end"
    assert len(data) == FRAME
    w.write(tag + data)
    await w.drain()
    assert await r.readexactly(FRAME) == data


async def dial(i, port):
    v = i % 2
    r, w = await asyncio.open_connection("127.0.0.1", PORTS[v])
    if v:
        w.write(vless(port))
        assert await r.readexactly(2) == b"\0\0"
    else:
        w.write(b"\x05\x01\0")
        assert await r.readexactly(2) == b"\x05\0"
        w.write(socks(port))
        assert (await r.readexactly(10))[:4] == b"\x05\0\0\x01"
    return r, w


async def excess(port):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    try:
        # The host rejects before decoding a handshake; a timeout is not a rejection.
        assert await asyncio.wait_for(r.read(1), 2) == b""
    except ConnectionResetError:
        pass
    finally:
        w.close()


async def drained(ctl, pid, baseline):
    for _ in range(200):
        code, st = control(ctl, "STATUS")
        assert code == 200
        if st["activeClients"] == 0 and st["retainedGenerations"] == 1:
            snap = sample(pid)
            if snap["fd"] == baseline["fd"]:
                return snap
        await asyncio.sleep(.02)
    raise AssertionError(("drain", st, sample(pid)))


def timed(ctl, *request):
    start = time.monotonic_ns()
    code, body = control(ctl, *request)
    assert code == 200
    return body, round((time.monotonic_ns() - start) / 1e6, 3)


async def exercise(ctl, doc, pid, n, target, echo):
    baseline = sample(pid)
    st, _ = timed(ctl, "STATUS")
    assert st["persistence"] and st["tcpClientLimit"] == n
    rev, idle_apply = timed(ctl, "APPLY", doc, 1)
    assert rev["revision"] == 2
    await drained(ctl, pid, baseline)
    if n != 32:
        mixed = copy.deepcopy(doc)
        mixed["outbounds"]["proxy"] = outbound(target)
        assert control(ctl, "APPLY", mixed, 2)[0] == 422
    peers = []
    gates = []
    try:
        for i in range(n):
            peers.append(await dial(i, target))
        gates.append(await echo.barrier(peers, 1))
        for port in PORTS:
            await excess(port)
        st, _ = timed(ctl, "STATUS")
        assert st["activeClients"] == n
        peak = sample(pid)
        assert peak["fd"] == baseline["fd"] + 2*n

        # A bounded producer on flow zero, upstream deliberately not reading.
        r, w = peers[0]
        w.get_extra_info("socket").setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 262144)
        w.transport.set_write_buffer_limits(high=len(BLOCK))
        progress = 0

        async def slow_upload():
            nonlocal progress
            w.write(b"S")
            for _ in range(BLOCKS):
                w.write(BLOCK)
                await w.drain()
                progress += 1

        async def slow_download():
            for _ in range(BLOCKS):
                assert await r.readexactly(len(BLOCK)) == BLOCK

        sender = asyncio.create_task(slow_upload())
        receiver = asyncio.create_task(slow_download())
        await echo.slow_started.wait()

        rounds = 0
        stop = False

        async def traffic():
            nonlocal rounds
            while not stop:
                await asyncio.gather(*(exchange(peers[i], i, 10+rounds) for i in range(1, n)))
                rounds += 1

        load = asyncio.create_task(traffic())
        try:
            # Witness a blocked writer while every other stream keeps moving.
            for _ in range(100):
                prior = progress
                await asyncio.sleep(.1)
                if rounds and 0 < progress == prior < BLOCKS:
                    break
            else:
                raise AssertionError(("no backpressure", progress, rounds))
            blocked_bytes = progress * len(BLOCK)
            statuses = []
            for _ in range(3):
                st, ms = await asyncio.to_thread(timed, ctl, "STATUS")
                assert st["activeClients"] == n
                statuses.append(ms)
            rev, busy_apply = await asyncio.to_thread(timed, ctl, "APPLY", doc, 2)
            assert rev["revision"] == 3 and not sender.done()
            st, ms = await asyncio.to_thread(timed, ctl, "STATUS")
            statuses.append(ms)
            assert st["generation"] == 3 and st["retainedGenerations"] == 2 and st["activeClients"] == n
            pinned = sample(pid)
        finally:
            stop = True
            echo.resume_slow.set()
        await asyncio.gather(load, sender, receiver)
        gates.append(await echo.barrier(peers, 2))
        for _, writer in peers:
            writer.close()
        peers.clear()
        released = await drained(ctl, pid, baseline)
        for i in range(n):
            peers.append(await dial(i, target))
        gates.append(await echo.barrier(peers, 3))
    finally:
        for _, writer in peers:
            writer.close()
    final = await drained(ctl, pid, baseline)
    assert not echo.errors
    return dict(n=n, socks=n//2, vless=n//2, simultaneous_echo_before_after_refill=gates,
                rejected_extra=2, traffic_rounds=rounds, blocked_after_bytes=blocked_bytes,
                recovered_slow_bytes=BLOCKS*len(BLOCK), idle=baseline, peak=peak,
                pinned_after_apply=pinned, release=released, refill_release=final,
                idle_apply_ms=idle_apply, busy_apply_ms=busy_apply, busy_status_ms=statuses)


async def run(binary, profile, n):
    doc = original(*PORTS)
    doc["routing"] = {"default": "direct", "rules": []}
    doc["secrets"] = {"identity": {"source": "env", "kind": "uuid", "name": "STEER_TEST_UUID"}}
    doc["inbounds"]["direct"].update(plugin="vless:bundle", flow=["stream"],
                                     options={"principal_id": "test", "uuid": {"secret": "identity"}})
    echo = Echo(n)
    with socket.socket() as sock, tempfile.TemporaryDirectory() as tmp:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 32768)
        sock.bind(("127.0.0.1", 0))
        sock.listen(32)
        port = sock.getsockname()[1]
        async with await asyncio.start_server(echo.serve, sock=sock, limit=8192):
            args = ["--direct-tcp-clients", str(n)] if n > 32 else []
            state = Path(tmp) / "state"
            state.mkdir(mode=0o700)
            with core(binary, tmp, doc, state_directory=state, extra_args=args) as ctl:
                pid, = map(int, Path(f"/proc/self/task/{os.getpid()}/children").read_text().split())
                data = await asyncio.wait_for(exercise(ctl, doc, pid, n, port, echo), 90)
                print(json.dumps(dict(profile=profile, nofile=resource.getrlimit(resource.RLIMIT_NOFILE),
                                      pid=pid, **data)), flush=True)


def negative(full, nano, tmp):
    # Valid boot document: mistaking a later missing-file error for CLI rejection would pass.
    cfg = Path(tmp) / "valid.json"
    cfg.write_text(json.dumps(original(*PORTS)))
    for binary, value, limit in ((nano,"100",4096), (full,"999",4096), (full,"1000",2127), (full,"100",327)):
        r = subprocess.run([binary, "--config", str(cfg), "--control", tmp+"/ctl", "--direct-tcp-clients", value],
                           preexec_fn=lambda: resource.setrlimit(resource.RLIMIT_NOFILE, (limit,limit)),
                           capture_output=True, timeout=5)
        assert r.returncode == 2
        if limit < 4096:
            assert str(limit+1).encode() in r.stderr
        print(json.dumps(dict(rejected_option=value, binary=binary, nofile=limit, rc=r.returncode,
                              diagnostic=r.stderr.decode().strip())), flush=True)


def main(full, nano):
    assert os.getpid() == 1 and os.getuid() == 65534 and socket.if_nameindex() == [(1, "lo")]
    with tempfile.TemporaryDirectory() as tmp:
        negative(full, nano, tmp)
    for binary, profile, n in ((nano,"Nano",32), (full,"Full",32), (full,"Full",100), (full,"Full",1000)):
        asyncio.run(run(binary, profile, n))


if __name__ == "__main__":
    main(*sys.argv[1:])
