#!/usr/bin/env python3
"""Idle process PSS/FD and stripped binary sizes for legacy daemon vs Nano."""
import argparse
import hashlib
import json
import selectors
import socket
import statistics
import subprocess
import tempfile
import time
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def process_sample(pid):
    root = Path(f"/proc/{pid}")
    pss = next(int(line.split()[1]) for line in (root / "smaps_rollup").read_text().splitlines()
               if line.startswith("Pss:"))
    fds = len(list((root / "fd").iterdir()))
    return {"pss_kib": pss, "fd": fds}


def wait_path(path, proc, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"process exited {proc.returncode}")
        if path.exists():
            return
        time.sleep(.02)
    raise RuntimeError("startup deadline waiting for Unix socket")


def wait_ready(proc, timeout=5):
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout, selectors.EVENT_READ)
    try:
        if not selector.select(timeout):
            raise RuntimeError("managed core READY deadline")
        line = proc.stdout.readline()
        if not line.startswith(b"READY "):
            raise RuntimeError(f"managed core did not become ready: {line!r}")
        state = json.loads(line[6:])
        if not state.get("runtimeReady"):
            raise RuntimeError(f"managed core not ready: {state}")
    finally:
        selector.close()


def measure(binary, mode, repeat):
    rows = []
    for _ in range(repeat):
        with tempfile.TemporaryDirectory(prefix=f"steer-idle-{mode}-") as td:
            root = Path(td)
            ctl, state = root / "core.sock", root / "state"
            if mode == "legacy":
                spec = root / "spec.json"
                spec.write_text('{"version":2,"outputs":{},"rules":[]}')
                argv = [binary, "daemon", "--socket", str(ctl), "--spec", str(spec),
                        "--state-dir", str(state)]
            else:
                port = free_port()
                config = root / "config.json"
                config.write_text(json.dumps({
                    "prototype": "steer-linux-v1",
                    "listeners": [{
                        "id": "idle", "protocol": "socks", "enabled": True,
                        "listen": {"address": "127.0.0.1", "port": port},
                        "auth": {"type": "none"}}],
                    "routing": {"default": "direct", "rules": []}}))
                argv = [binary, "--config", str(config), "--control", str(ctl),
                        ]
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                if mode == "legacy":
                    wait_path(ctl, proc)
                else:
                    wait_ready(proc)
                time.sleep(.75)
                rows.append(process_sample(proc.pid))
            finally:
                proc.terminate()
                try:
                    _, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=2)
                    raise RuntimeError("process exceeded bounded shutdown")
                if proc.returncode != 0:
                    raise RuntimeError(f"process exit {proc.returncode}: {stderr[-500:]!r}")
    return {
        "samples": rows,
        "median": {key: int(statistics.median(row[key] for row in rows))
                   for key in ("pss_kib", "fd")}}


def file_info(path):
    p = Path(path)
    digest = hashlib.sha256(p.read_bytes()).hexdigest()
    return {"path": str(p.resolve()), "bytes": p.stat().st_size, "sha256": digest}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--legacy-steerd", required=True,
                        help="stripped Steer 2.1.4 steerd executable")
    parser.add_argument("--managed-core", required=True,
                        help="stripped managed Nano executable")
    parser.add_argument("--repeat", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeat <= 5:
        parser.error("repeat bound is 1..5")
    legacy = str(Path(args.legacy_steerd).resolve())
    managed = str(Path(args.managed_core).resolve())
    result = {
        "method": "same-host idle Linux process; 750ms settling; proc smaps_rollup PSS and FD count",
        "traffic": "none; no matched performance workload (different capabilities)",
        "legacy_v2": {"version": subprocess.check_output([legacy, "--version"], text=True).strip(),
                      "steerd": file_info(legacy),
                      "idle": measure(legacy, "legacy", args.repeat)},
        "managed_nano": {"core": file_info(managed),
                         "idle": measure(managed, "managed", args.repeat)},
        "bounds": {"iterations": args.repeat, "startup_timeout_seconds": 5,
                   "shutdown_timeout_seconds": 5,
                   "network": "127.0.0.1 only; no external destination"},
    }
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
