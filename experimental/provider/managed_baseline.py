#!/usr/bin/env python3
"""Bounded loopback-only concurrency baseline for the managed SOCKS core."""
import argparse
import concurrent.futures
import http.server
import json
import os
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def read_exact(sock, size):
    chunks = bytearray()
    while len(chunks) < size:
        data = sock.recv(size - len(chunks))
        if not data:
            raise RuntimeError("unexpected EOF")
        chunks.extend(data)
    return bytes(chunks)


def proc_stats(pid):
    fd_count = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    status = Path(f"/proc/{pid}/status").read_text()
    rss = next(int(line.split()[1]) for line in status.splitlines()
               if line.startswith("VmRSS:"))
    return {"fd": fd_count, "rss_kib": rss}


def control(path, command, document=None, revision=None):
    body = b"" if document is None else json.dumps(document, separators=(",", ":")).encode()
    header = command + (f" {revision}" if revision is not None else "")
    if document is not None:
        header += f" {len(body)}"
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(3)
        s.connect(str(path))
        s.sendall(header.encode() + b"\n" + body)
        line = bytearray()
        while not line.endswith(b"\n"):
            line.extend(read_exact(s, 1))
        parts = line.split()
        code = 200 if parts[0] == b"OK" else int(parts[1])
        size = int(parts[-1])
        return code, json.loads(read_exact(s, size))


def socks_connect(port, target_port):
    s = socket.create_connection(("127.0.0.1", port), timeout=3)
    s.settimeout(5)
    s.sendall(b"\x05\x01\x00")
    if read_exact(s, 2) != b"\x05\x00":
        raise RuntimeError("SOCKS greeting rejected")
    s.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
    reply = read_exact(s, 4)
    if reply[:2] != b"\x05\x00":
        raise RuntimeError(f"SOCKS CONNECT failed: {reply!r}")
    atyp = reply[3]
    read_exact(s, (4 if atyp == 1 else 16 if atyp == 4 else 1))
    if atyp == 3:
        n = s.recv(1)[0]
        read_exact(s, n)
    read_exact(s, 2)
    return s


class EchoServer:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(32)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def run(self):
        self.sock.settimeout(.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self.echo, args=(conn,), daemon=True).start()

    @staticmethod
    def echo(conn):
        with conn:
            while True:
                data = conn.recv(16384)
                if not data:
                    return
                conn.sendall(data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    parser.add_argument("--concurrency", type=int, default=8)
    parser.add_argument("--bytes-per-client", type=int, default=131072)
    parser.add_argument("--timeout", type=int, default=30)
    args = parser.parse_args()
    if not 1 <= args.concurrency <= 12 or not 4096 <= args.bytes_per_client <= 524288:
        parser.error("bounds: concurrency 1..12, bytes-per-client 4096..524288")
    if args.concurrency * args.bytes_per_client > 6 * 1024 * 1024:
        parser.error("total echoed payload is capped at 6 MiB")
    if not 5 <= args.timeout <= 45:
        parser.error("timeout bound is 5..45 seconds")

    socks_port, target_port = free_port(), free_port()
    document = {"prototype": "steer-linux-v1",
                "listeners": [{"id": "baseline", "protocol": "socks", "enabled": True,
                               "listen": {"address": "127.0.0.1", "port": socks_port},
                               "auth": {"type": "none"}}],
                "routing": {"default": "direct", "rules": []}}
    echo = EchoServer()
    echo.thread.start()
    start = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(prefix="steer-managed-baseline-") as temp:
            root = Path(temp)
            config, ctl = root / "config.json", root / "core.sock"
            config.write_text(json.dumps(document))
            proc = subprocess.Popen([args.core, "--config", str(config), "--control", str(ctl)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                ready = proc.stdout.readline()
                if not ready.startswith(b"READY "):
                    raise RuntimeError(f"core did not become ready: {ready!r}")
                initial = json.loads(ready[6:])
                if initial.get("generation", initial.get("revision")) != 1:
                    raise RuntimeError(f"unexpected initial state {initial}")
                before = proc_stats(proc.pid)
                barrier = threading.Barrier(args.concurrency + 2)
                latencies, failures = [], []
                latency_lock = threading.Lock()
                payload_size = 4096
                rounds = args.bytes_per_client // payload_size
                def worker(index):
                    local = []
                    try:
                        sock = socks_connect(socks_port, echo.port)
                        barrier.wait(timeout=3)
                        for sequence in range(rounds):
                            payload = bytes([index & 255]) * payload_size
                            began = time.perf_counter_ns()
                            sock.sendall(payload)
                            if read_exact(sock, payload_size) != payload:
                                raise RuntimeError("echo mismatch")
                            local.append((time.perf_counter_ns() - began) / 1e6)
                        sock.close()
                    except Exception as exc:
                        failures.append(repr(exc))
                    with latency_lock:
                        latencies.extend(local)

                def local_reads():
                    barrier.wait(timeout=3)
                    # Unix read and an independent loopback HTTP GET run during
                    # the same active transfer window.
                    code, state = control(ctl, "GET")
                    if code != 200 or state["revision"] not in (1, 2, 3):
                        failures.append(f"Unix GET: {code}, {state}")
                    with socket.create_connection(("127.0.0.1", httpd.server_port), timeout=3) as s:
                        s.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                        result = bytearray()
                        while True:
                            chunk = s.recv(4096)
                            if not chunk:
                                break
                            result.extend(chunk)
                    if b"baseline-http-ok" not in result:
                        failures.append("loopback HTTP read failed")

                class Handler(http.server.BaseHTTPRequestHandler):
                    def do_GET(self):
                        body = b"baseline-http-ok"
                        self.send_response(200)
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    def log_message(self, *_):
                        pass
                httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                httpd_thread = threading.Thread(target=httpd.serve_forever, daemon=True)
                httpd_thread.start()
                deadline = time.monotonic() + args.timeout
                load_started = time.monotonic()
                with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency + 1) as pool:
                    futures = [pool.submit(worker, i) for i in range(args.concurrency)]
                    reader = pool.submit(local_reads)
                    # Wait until workers are active, then publish two policy
                    # generations while their existing streams remain pinned.
                    barrier.wait(timeout=3)
                    blocked = json.loads(json.dumps(document))
                    blocked["routing"]["default"] = "block"
                    c1, _ = control(ctl, "APPLY", blocked, 1)
                    if c1 != 200:
                        failures.append(f"generation switch to block returned {c1}")
                    direct = json.loads(json.dumps(document))
                    c2, _ = control(ctl, "APPLY", direct, 2)
                    if c2 != 200:
                        failures.append(f"generation switch to direct returned {c2}")
                    for future in futures + [reader]:
                        future.result(timeout=max(.1, deadline - time.monotonic()))
                load_elapsed = time.monotonic() - load_started
                after = proc_stats(proc.pid)
                status_code, status = control(ctl, "STATUS")
                if status_code != 200 or status.get("generation") != 3:
                    failures.append(f"final status unexpected: {status_code} {status}")
                if len(latencies) != args.concurrency * rounds:
                    failures.append(f"round-trip count {len(latencies)} != {args.concurrency * rounds}")
                httpd.shutdown()
                httpd.server_close()
                total = args.concurrency * rounds * payload_size
                ordered = sorted(latencies)
                def percentile(p):
                    return ordered[min(len(ordered)-1, int((len(ordered)-1)*p))]
                print(json.dumps({
                    "result": "PASS" if not failures and len(latencies) == args.concurrency * rounds else "FAIL",
                    "scope": "loopback managed SOCKS5 CONNECT to local TCP echo; local HTTP + Unix GET; generations 1->2->3",
                    "concurrency": args.concurrency, "payload_bytes": total,
                    "round_trips": len(latencies), "elapsed_seconds": round(load_elapsed, 4),
                    "throughput_mib_s": round(total / load_elapsed / 1048576, 3),
                    "latency_ms": {"p50": round(percentile(.50), 3), "p95": round(percentile(.95), 3)} if ordered else None,
                    "process": {"before": before, "after": after,
                                "fd_delta": after["fd"]-before["fd"],
                                "rss_delta_kib": after["rss_kib"]-before["rss_kib"]},
                    "failures": failures,
                    "bounds": {"timeout_seconds": args.timeout, "payload_cap_bytes": 6*1024*1024}
                }, sort_keys=True))
            finally:
                if proc.poll() is None:
                    proc.terminate()
                try:
                    out, err = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=3)
                    raise RuntimeError("core required SIGKILL after shutdown timeout")
                if proc.returncode != 0:
                    raise RuntimeError(f"core exit {proc.returncode}: {err[-1000:]!r}")
    finally:
        echo.stop.set()
        echo.sock.close()
    if time.monotonic() - start > args.timeout + 10:
        raise RuntimeError("overall run exceeded cleanup-inclusive time bound")
    if failures:
        raise RuntimeError(f"baseline failed: {failures}")


if __name__ == "__main__":
    main()
