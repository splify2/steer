#!/usr/bin/env python3
"""Origin VLESS backend -> pinned external Xray inbound -> real TCP target.

Plain TCP only. Target answers after its three request bytes, so this gate does
not claim Xray forwards request FIN to the target. The independent local C suite
tests EOF-dependent reverse response separately. UUID is a public test value.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xray", required=True)
    parser.add_argument("--probe", required=True)
    args = parser.parse_args()
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = {"log": {"loglevel": "none"}, "inbounds": [{
        "listen": "127.0.0.1", "port": port, "protocol": "vless",
        "settings": {"clients": [{"id": "2a000000-0000-0000-0000-000000000000"}],
                     "decryption": "none"},
        "streamSettings": {"network": "tcp", "security": "none"}}],
        "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [{
            "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"]}]}}]}
    with tempfile.TemporaryDirectory(prefix="steer-vless-origin-xray-") as directory:
        path = Path(directory) / "config.json"
        path.write_text(json.dumps(config))
        process = subprocess.Popen([args.xray, "run", "-c", str(path)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 5
            while True:
                assert process.poll() is None, "external Xray startup failed"
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        break
                except OSError:
                    assert time.monotonic() < deadline, "external Xray startup timeout"
                    time.sleep(.01)
            result = subprocess.run([args.probe, str(port)], capture_output=True, timeout=10)
            assert result.returncode == 0 and not result.stderr, (result.returncode, result.stderr)
            assert b"plain TCP target echo PASS" in result.stdout
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError("external Xray shutdown timeout") from None
    print("Xray sha256=" + hashlib.sha256(Path(args.xray).read_bytes()).hexdigest())
    print("origin VLESS -> Xray -> TCP echo passed (plain TCP, no TLS/target-FIN claim)")


if __name__ == "__main__":
    main()
