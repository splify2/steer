#!/usr/bin/env python3
"""Independent HY2 upstream and loopback echo for SDK backend."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from hy2_tcp_client_test import certificate
from hy2_udp_client_test import owned_udp


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--client", type=Path, required=True)
    p.add_argument("--server", type=Path, required=True)
    args = p.parse_args()
    client, server = args.client.resolve(strict=True), args.server.resolve(strict=True)
    with tempfile.TemporaryDirectory(dir="/tmp/opencode", prefix="hy2-sdk-") as tmp:
        root = Path(tmp)
        ca, _, cert, key = certificate(root)
        token = "temporary-sdk-loopback"
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo, \
                socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            echo.bind(("127.0.0.1", 0))
            echo.settimeout(8)
            reserve.bind(("127.0.0.1", 0))
            port = reserve.getsockname()[1]
            reserve.close()
            cfg = root / "server.yaml"
            cfg.write_text(f"listen: 127.0.0.1:{port}\ntls:\n  cert: {cert}\n  key: {key}\n"
                           f"auth:\n  type: password\n  password: {token}\ndisableUDP: false\n")
            peer = subprocess.Popen([str(server), "--disable-update-check", "-c", str(cfg), "server"],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            received = []

            def serve():
                data, address = echo.recvfrom(2048)
                received.append((data, owned_udp(peer.pid, address[1])))
                echo.sendto(data, address)

            thread = threading.Thread(target=serve)
            try:
                end = time.monotonic() + 5
                while not owned_udp(peer.pid, port):
                    assert peer.poll() is None and time.monotonic() < end
                    time.sleep(.02)
                thread.start()
                subprocess.run([str(client), str(port), str(ca), str(echo.getsockname()[1])],
                               env=dict(os.environ, STEER_LAB_HY2_TOKEN=token), check=True, timeout=12)
                thread.join(2)
                assert not thread.is_alive() and len(received) == 1
                assert received[0][0] == bytes((i * 17) & 255 for i in range(1000))
                assert received[0][1], "target sender is not upstream-owned"
                print("PASS SDK echo source is upstream")
            finally:
                peer.terminate()
                peer.wait(timeout=5)
                thread.join(9) if thread.ident is not None else None


if __name__ == "__main__":
    main()
