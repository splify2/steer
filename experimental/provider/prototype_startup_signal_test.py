#!/usr/bin/env python3
"""SIGTERM during deferred startup rollback; use the link-wrapper binary."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


def main(binary):
    with tempfile.TemporaryDirectory(prefix="steer-startup-signal-") as directory:
        os.chmod(directory, 0o700)
        control = str(Path(directory) / "control.sock")
        with socket.socket(socket.AF_UNIX) as occupied, socket.socket() as port:
            occupied.bind(control)
            occupied.listen()
            port.bind(("127.0.0.1", 0))
            listener_port = port.getsockname()[1]
            port.close()
            document = {"prototype": "steer-linux-v1", "listeners": [{
                "id": "rollback", "protocol": "socks",
                "listen": {"address": "127.0.0.1", "port": listener_port},
                "auth": {"type": "none"}}],
                "routing": {"default": "direct", "rules": []}}
            source = Path(directory) / "config.json"
            source.write_text(json.dumps(document))
            result = subprocess.run([binary, "--config", str(source), "--control", control],
                                    capture_output=True, timeout=10)
            assert result.returncode == 1 and not result.stdout and not result.stderr, (
                result.returncode, result.stderr)
            assert Path(control).exists(), "removed another control listener"
            with socket.socket() as released:
                released.bind(("127.0.0.1", listener_port))
    print("startup rollback SIGTERM fixture passed")


if __name__ == "__main__":
    main(sys.argv[1])
