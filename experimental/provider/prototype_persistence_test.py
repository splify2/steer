#!/usr/bin/env python3
"""Optional durable host state, restart precedence and disk-failure rollback."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
from prototype_test import control, core, free_port, listener, roundtrip, socks_flow
from socks_loopback_test import connect, greeting, request, response, server


def main(binary):
    document = {"prototype": "steer-linux-v1", "listeners": [listener("persisted", free_port())],
                "routing": {"default": "direct", "rules": []}}
    port = document["listeners"][0]["listen"]["port"]
    with tempfile.TemporaryDirectory(prefix="steer-persistence-") as directory, server() as target:
        state = Path(directory) / "state"; state.mkdir(mode=0o700)
        with core(binary, directory, document, state_directory=state) as path:
            original = control(path, "GET")[1]
            assert original["persistence"] and not original["durability_uncertain"]
            assert (state / "config.json").stat().st_mode & 0o777 == 0o600
            candidate = copy.deepcopy(document); candidate["listeners"][0]["label"] = "Saved configuration"
            assert control(path, "APPLY", candidate, 1, half_close=True)[1]["revision"] == 2
            assert json.loads((state / "config.json").read_text())["revision"] == 2
            if os.geteuid() != 0:
                # Directory-fd ownership does not bypass create permissions.
                # File prepare fails before rename; runtime and disk stay rev2.
                failed = copy.deepcopy(candidate); new_port = free_port()
                failed["listeners"].append(listener("must-rollback", new_port))
                state.chmod(0o500)
                try:
                    code, result = control(path, "APPLY", failed, 2)
                    assert code == 503 and not result.get("applied", False)
                finally:
                    state.chmod(0o700)
                assert control(path, "GET")[1]["revision"] == 2
                assert json.loads((state / "config.json").read_text())["revision"] == 2
                try:
                    connect(new_port).close(); raise AssertionError("disk-failed listener leaked")
                except ConnectionRefusedError:
                    pass
            with socks_flow(port, target) as sock:
                roundtrip(sock, b"old-traffic-after-disk-failure")
        # Committed snapshot wins even when the original source is invalid.
        with core(binary, directory, "invalid source", state_directory=state, expected_revision=2) as path:
            saved = control(path, "GET")[1]
            assert saved["document"] == candidate and saved["revision"] == 2
            assert control(path, "APPLY", document, 1)[0] == 409
            blocked = copy.deepcopy(candidate); blocked["routing"]["default"] = "block"
            assert control(path, "APPLY", blocked, 2)[1]["revision"] == 3
            with connect(port) as sock:
                greeting(sock); sock.sendall(request(target)); assert response(sock) == 2
        with core(binary, directory, document, state_directory=state, expected_revision=3) as path:
            assert control(path, "GET")[1]["document"] == blocked
        # Corruption must not silently fall back to the otherwise valid source.
        (state / "config.json").write_text("corrupt")
        config = Path(directory) / "config.json"; config.write_text(json.dumps(document))
        result = subprocess.run([binary, "--config", str(config), "--control", str(Path(directory) / "core.sock"),
                                 "--state-dir", str(state)], capture_output=True, timeout=8)
        assert result.returncode != 0 and not result.stdout and not result.stderr
    print("prototype persistence restart and rollback fixtures passed")


if __name__ == "__main__":
    main(sys.argv[1])
