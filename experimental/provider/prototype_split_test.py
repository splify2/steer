#!/usr/bin/env python3
"""Real store and Unix control: synced selection can diverge from live runtime."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile

from prototype_test import control, core, free_port, listener, roundtrip, socks_flow
from socks_loopback_test import server


def raw_control(path, operation):
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8)
        sock.connect(str(path))
        sock.sendall(operation.encode() + b"\n")
        line = b""
        while not line.endswith(b"\n"):
            chunk = sock.recv(1)
            assert chunk
            line += chunk
        length = int(line.split()[-1])
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            assert chunk
            data += chunk
        return line + data


def main(normal, fault, baseline):
    with tempfile.TemporaryDirectory(prefix="steer-split-", dir="/tmp/opencode") as directory, server() as target:
        root = Path(directory)
        port = free_port()
        original = {"prototype": "steer-linux-v1", "listeners": [listener("socks", port)],
                    "routing": {"default": "direct", "rules": []}}
        candidate = copy.deepcopy(original)
        candidate["listeners"][0]["label"] = "durable candidate"
        candidate["routing"]["default"] = "block"
        snapshots = []
        for binary in (normal, fault, baseline):
            state = root / ("ordinary" + str(len(snapshots)))
            state.mkdir(mode=0o700)
            with core(binary, root, original, state_directory=state) as path:
                snapshots.append((raw_control(path, "STATUS"), raw_control(path, "GET")))
        assert snapshots[0] == snapshots[1] == snapshots[2], "non-opt-in responses changed"
        success_state = root / "success"
        success_state.mkdir(mode=0o700)
        with core(normal, root, original, state_directory=success_state,
                  extra_args=("--experimental-durable-split",)) as path:
            code, result = control(path, "APPLY", candidate, 1)
            assert code == 200 and result["revision"] == 2
            status = control(path, "STATUS")[1]
            assert status["selectedRevision"] == status["runtimeGeneration"] == 2
            assert not status["splitFenced"]
            assert control(path, "GET")[1]["document"] == candidate
        state = root / "split"
        state.mkdir(mode=0o700)
        with core(fault, root, original, state_directory=state,
                  extra_args=("--experimental-durable-split", "--test-fail-after-sync")) as path:
            with socks_flow(port, target) as pinned:
                roundtrip(pinned, b"before")
                before = control(path, "GET")[1]
                assert before["revision"] == before["runtimeGeneration"] == 1
                code, result = control(path, "APPLY", candidate, 1)
                assert code == 503 and not result.get("applied", False), (code, result)
                status = control(path, "STATUS")[1]
                selected = control(path, "GET")[1]
                assert status["revision"] == status["selectedRevision"] == 2
                assert status["generation"] == status["runtimeGeneration"] == 1
                assert status["splitFenced"] and not status["runtimeReady"] and not status["durability_uncertain"]
                assert selected["revision"] == 2 and selected["runtimeGeneration"] == 1
                assert selected["splitFenced"] and selected["document"] == candidate
                disk = json.loads((state / "config.json").read_text())
                assert disk["revision"] == 2 and disk["document"] == selected["document"], disk
                roundtrip(pinned, b"pinned-after-error")
                with socks_flow(port, target) as fresh:
                    roundtrip(fresh, b"new-after-error")
                for base in (1, 2):
                    code, result = control(path, "APPLY", original, base)
                    assert code == 503 and not result.get("applied", False)
                assert control(path, "GET")[1] == selected
        # A normal build must not accept the test-only switch.
        result = subprocess.run([normal, "--config", str(root / "config.json"), "--control",
                                 str(root / "bad.sock"), "--state-dir", str(state),
                                 "--experimental-durable-split", "--test-fail-after-sync"],
                                capture_output=True, timeout=8)
        assert result.returncode != 0 and not (root / "bad.sock").exists()
    print("PASS real store synced divergence, selected GET, fencing and live SOCKS")


if __name__ == "__main__":
    main(*sys.argv[1:])
