#!/usr/bin/env python3
"""Injected fsync stages exercise host publication and loop responsiveness."""
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import tempfile
import time
from prototype_test import control, core, free_port, listener, roundtrip, socks_flow
from socks_loopback_test import connect, exact, greeting, request, response, server


def wait_marker(path):
    deadline = time.monotonic() + 3
    while not path.exists():
        assert time.monotonic() < deadline, "writer did not reach injected pause"
        time.sleep(0.01)


def main(binary, shim):
    # ASan requires its runtime first when an interposer is explicitly preloaded.
    dependencies = subprocess.check_output(["ldd", binary], text=True)
    asan = [line.split("=>", 1)[1].split()[0] for line in dependencies.splitlines()
            if "libasan.so" in line and "=>" in line]
    preload = ":".join(asan + [os.path.abspath(shim)])
    document = {"prototype": "steer-linux-v1", "listeners": [listener("fault-test", free_port())],
                "routing": {"default": "direct", "rules": []}}
    port = document["listeners"][0]["listen"]["port"]
    with tempfile.TemporaryDirectory(prefix="steer-sync-test-") as directory, server() as target:
        base = Path(directory); state = base / "state"; state.mkdir(mode=0o700)
        pause, entered, file_fail, dir_fail = [base / name for name in ("pause", "entered", "file-fail", "dir-fail")]
        env = {"LD_PRELOAD": preload, "STEER_TEST_PAUSE_FILE_SYNC": str(pause),
               "STEER_TEST_SYNC_ENTERED": str(entered), "STEER_TEST_FAIL_FILE_SYNC": str(file_fail),
               "STEER_TEST_FAIL_DIRECTORY_SYNC": str(dir_fail)}
        with core(binary, directory, document, state_directory=state, extra_env=env) as path:
            with socks_flow(port, target) as pinned:
                candidate = copy.deepcopy(document); candidate["listeners"].append(listener("prepared", free_port()))
                pause.touch()
                try:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        pending = pool.submit(control, path, "APPLY", candidate, 1)
                        wait_marker(entered)
                        before = time.monotonic()
                        state_before = control(path, "STATUS")[1]
                        assert state_before["revision"] == 1 and len(state_before["listeners"]) == 1
                        assert control(path, "GET")[1]["document"] == document
                        assert control(path, "APPLY", candidate, 1)[0] == 503
                        roundtrip(pinned, b"packet-processing-during-file-fsync")
                        assert time.monotonic() - before < 1, "disk IO blocked the loop"
                        pause.unlink()
                        assert pending.result(timeout=5)[1]["revision"] == 2
                finally:
                    pause.unlink(missing_ok=True)
                file_fail.touch()
                code, body = control(path, "APPLY", document, 2)
                assert code == 503 and not body.get("applied", False)
                file_fail.unlink()
                assert control(path, "GET")[1]["revision"] == 2
                blocked = copy.deepcopy(candidate); blocked["routing"]["default"] = "block"
                dir_fail.touch()
                code, body = control(path, "APPLY", blocked, 2)
                assert code == 503 and body["applied"] and body["durability_uncertain"] and body["revision"] == 3
                actual = control(path, "GET")[1]
                assert actual["revision"] == 3 and actual["document"] == blocked and actual["durability_uncertain"]
                assert control(path, "STATUS")[1]["durability_uncertain"]
                with connect(port) as sock:
                    greeting(sock); sock.sendall(request(target)); assert response(sock) == 2
                roundtrip(pinned, b"old-flow-after-visible-uncertain-rename")
                dir_fail.unlink()
                applied = control(path, "APPLY", candidate, 3)[1]
                assert applied["revision"] == 4 and not applied["durability_uncertain"]
                # Abandon an apply while the writer is paused. Reuse the first
                # control slot for a partial STATUS; the old response must not
                # reach that new connection when the commit completes.
                entered.unlink(missing_ok=True); pause.touch()
                abandoned = copy.deepcopy(candidate)
                abandoned["listeners"][0]["label"] = "Committed after caller disconnected"
                wire = json.dumps(abandoned).encode()
                old = socket.socket(socket.AF_UNIX); old.settimeout(5); old.connect(str(path))
                old.sendall(f"APPLY 4 {len(wire)}\n".encode() + wire)
                wait_marker(entered); old.close()
                assert control(path, "STATUS")[1]["revision"] == 4
                with socket.socket(socket.AF_UNIX) as reused:
                    reused.settimeout(5); reused.connect(str(path)); reused.sendall(b"STAT")
                    pause.unlink()
                    deadline = time.monotonic() + 3
                    while control(path, "GET")[1]["revision"] != 5:
                        assert time.monotonic() < deadline
                        time.sleep(0.01)
                    reused.settimeout(0.15)
                    try:
                        assert not reused.recv(1), "old apply response reached reused control slot"
                        raise AssertionError("reused control connection closed unexpectedly")
                    except TimeoutError:
                        pass
                    reused.settimeout(5); reused.sendall(b"US\n")
                    header = b""
                    while not header.endswith(b"\n"):
                        header += exact(reused, 1); assert len(header) < 128
                    assert header.startswith(b"OK ")
                    status = json.loads(exact(reused, int(header.split()[1])))
                    assert status["revision"] == 5 and "applied" not in status and "listeners" in status
    print("prototype fsync stage and responsiveness fixtures passed")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
