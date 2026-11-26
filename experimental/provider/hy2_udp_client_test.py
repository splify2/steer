#!/usr/bin/env python3
"""Fixed-target HY2 UDP client against a separate upstream server; loopback only."""
import argparse
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from hy2_tcp_client_test import certificate


def owned_udp(pid, port):
    inodes = set()
    for path in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(path)
        except FileNotFoundError:
            continue
        if target.startswith("socket:["):
            inodes.add(target[8:-1])
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        for line in Path(path).read_text().splitlines()[1:]:
            parts = line.split()
            if int(parts[1].split(":")[1], 16) == port and parts[9] in inodes:
                return True
    return False


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--server", required=True, type=Path,
                        help="independent upstream hysteria CLI")
    args = parser.parse_args()
    client, server = args.client.resolve(strict=True), args.server.resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="hy2-udp-out-", dir="/tmp/opencode") as tmp:
        root = Path(tmp)
        ca, _, cert, key = certificate(root)
        token = "temporary-loopback-fixture"
        env = dict(os.environ, STEER_LAB_HY2_TOKEN=token)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as echo:
            echo.bind(("127.0.0.1", 0))
            echo.settimeout(5)
            target = echo.getsockname()[1]

            def run(disabled, target_text="127.0.0.1", receiver=echo):
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
                    reserve.bind(("127.0.0.1", 0))
                    port = reserve.getsockname()[1]
                config = root / "server.yaml"
                config.write_text(
                    f"listen: 127.0.0.1:{port}\ntls:\n  cert: {cert}\n  key: {key}\n"
                    f"auth:\n  type: password\n  password: {token}\n"
                    f"disableUDP: {'true' if disabled else 'false'}\n")
                peer = subprocess.Popen([str(server), "--disable-update-check", "-c", str(config), "server"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                got = []

                def receive():
                    try:
                        data, address = receiver.recvfrom(2048)
                        got.append((data, address, owned_udp(peer.pid, address[1])))
                        receiver.sendto(data, address)
                    except socket.timeout:
                        pass

                t = threading.Thread(target=receive)
                try:
                    end = time.monotonic() + 5
                    while not owned_udp(peer.pid, port):
                        assert peer.poll() is None and time.monotonic() < end, "upstream readiness"
                        time.sleep(.02)
                    t.start()
                    mode = "no-udp" if disabled else "success"
                    subprocess.run([str(client), str(port), str(ca), str(receiver.getsockname()[1]), mode],
                                   env=dict(env, STEER_TEST_UDP_TARGET=target_text), check=True, timeout=10)
                    if not disabled:
                        t.join(2)
                        assert not t.is_alive() and len(got) == 1
                        data, address, owned = got[0]
                        assert data == bytes((i * 17) & 255 for i in range(1000))
                        assert owned, f"echo sender {address} not owned by upstream peer"
                        print(f"PASS UDP payload and upstream-owned source for {target_text}")
                    else:
                        t.join(6)
                        assert not t.is_alive() and not got, "disabled UDP reached destination"
                        print("PASS UDP negotiation refusal without target traffic")
                finally:
                    peer.terminate()
                    peer.wait(timeout=5)
                    if t.is_alive():
                        t.join(6)
            run(False)
            run(True)
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as echo6:
                echo6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                echo6.bind(("::1", 0))
                echo6.settimeout(5)
                run(False, "::1", echo6)
                run(False, "0:0:0:0:0:0:0:1", echo6)
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as offline:
                offline.bind(("127.0.0.1", 0))
                offline.settimeout(.2)
                for rejected in ("target.lab.invalid", "::ffff:127.0.0.1", "0.0.0.0",
                                 "224.0.0.1", "::", "ff02::1", "fe80::1"):
                    subprocess.run([str(client), str(offline.getsockname()[1]), str(ca), str(target), "domain"],
                                   env=dict(env, STEER_TEST_UDP_TARGET=rejected), check=True, timeout=5)
                try:
                    offline.recvfrom(2048)
                    raise AssertionError("domain rejection opened the upstream connection")
                except socket.timeout:
                    print("PASS domain and ambiguous/non-unicast IPs rejected before upstream network activity")
                subprocess.run([str(client), str(offline.getsockname()[1]), str(ca), str(target), "timeout"],
                               env=env, check=True, timeout=10)
                echo.settimeout(.2)
                try:
                    echo.recvfrom(2048)
                    raise AssertionError("offline upstream fell back to direct")
                except socket.timeout:
                    print("PASS offline upstream without direct fallback")


if __name__ == "__main__":
    main()
