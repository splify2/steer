"""Managed HY2 echo at MTU 1380; run inside a fresh Linux network namespace."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import tempfile

from hy2_adapter_test import Echo, command, line
from prototype_hy2_test import fixtures
from prototype_hy2_udp_test import DatagramEcho
from prototype_test import core, free_port
from socks_loopback_test import exact


def live_reply(peer, udp):
    """Cut MTU between the two halves of an exchange on an established stream."""
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(3)
        peer.stdin.write(f"hold 127.0.0.1:{listener.getsockname()[1]}\n")
        peer.stdin.flush()
        with listener.accept()[0] as target:
            target.settimeout(3)
            target.sendall(exact(target, 8192))
            assert line(peer) == "PASS hold"
            command(peer, "udp-open live " + udp.address + " 512", "PASS udp-open")
            for _ in range(5):
                peer.stdin.write("send\n")
                peer.stdin.flush()
                target.sendall(exact(target, 32768))
                assert line(peer) == "PASS send"
            peer.stdin.write("send\n")
            peer.stdin.flush()
            accepted = exact(target, 32768)
            subprocess.run(["ip", "link", "set", "lo", "mtu", "1380"], check=True)
            try:
                target.sendall(accepted)
                assert line(peer) == "PASS send"
                command(peer, "udp-send live " + udp.address + " 512", "PASS udp-send")
            finally:
                subprocess.run(["ip", "link", "set", "lo", "mtu", "1500"], check=True)
            command(peer, "udp-send live " + udp.address + " 512", "PASS udp-send")
            assert udp.count() == 3


def run(host, client, bind, live):
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory()))
        state = root / "state"
        state.mkdir(mode=0o700)
        cert, key, _ = fixtures(root)
        env = dict(os.environ, STEER_LAB_HY2_TOKEN=secrets.token_urlsafe(24),
                   STEER_LAB_CA_FILE=str(cert), STEER_LAB_KEY=str(key), STEER_LAB_EXPECT_UDP="1")
        port = free_port()
        doc = {
            "version": 3,
            "plugin_remotes": {"local": {"url": "https://github.com/splify2/steer-protocols",
                                         "trust": "steer-linked-prototype-v1"}},
            "plugins": {"proxy": {"remote": "local", "package": "steer-protocols", "version": "0.0.0"}},
            "secrets": {k: {"source": "env", "kind": kind, "name": name} for k, kind, name in (
                ("password", "password", "STEER_LAB_HY2_TOKEN"), ("cert", "certificate", "STEER_LAB_CA_FILE"),
                ("key", "private_key", "STEER_LAB_KEY"))},
            "inbounds": {"hy2": {"plugin": "hysteria2:proxy", "flow": ["stream", "datagram"],
                                 "listen": {"address": bind, "port": port}, "transport": {"type": "quic"},
                                 "options": {"principal_id": "client", "password": {"secret": "password"}},
                                 "security": {"type": "tls", "certificate": {"secret": "cert"},
                                              "private_key": {"secret": "key"}}}},
            "outbounds": {"net": {"type": "direct", "flow": ["stream", "datagram"]}},
            "routing": {"default": "net", "rules": []},
        }
        udp = DatagramEcho()
        stack.callback(udp.close)
        stack.enter_context(core(host, root, doc, state_directory=state, extra_env=env))
        addr = f"[{bind}]:{port}" if ":" in bind else f"{bind}:{port}"
        peer = stack.enter_context(subprocess.Popen([client, addr], env=env, text=True,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE))
        stack.callback(peer.terminate)
        assert line(peer) == "READY HY2 TCP"
        if live:
            live_reply(peer, udp)
        else:
            tcp = Echo()
            stack.callback(tcp.close)
            command(peer, "hold " + tcp.address, "PASS hold")  # Exact 8192 bytes, stock 3 s deadline.
            command(peer, "udp-open live " + udp.address + " 512", "PASS udp-open")
            command(peer, "echo " + tcp.address + " 8192", "PASS echo")
            command(peer, "send", "PASS send")  # 32768 more on the original stream.
            command(peer, "udp-send live " + udp.address + " 512", "PASS udp-send")
            assert tcp.count() == 2 and udp.count() == 2
        command(peer, "quit", "PASS quit")
        assert peer.wait(timeout=5) == 0
        print(f"PASS managed HY2 {bind}: " + ("live return-direction downshift and UDP" if live
                                              else "MTU 1380 at startup, held stream, second stream and UDP"))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True, type=Path)
    parser.add_argument("--client", required=True, type=Path)
    parser.add_argument("--live-reply", action="store_true", help="lower MTU after target accepts the request")
    args = parser.parse_args()
    if os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net"):
        parser.error("isolated network namespace required")
    initial = 1500 if args.live_reply else 1380
    if json.loads(subprocess.check_output(["ip", "-j", "link", "show", "lo"]))[0]["mtu"] != initial:
        parser.error(f"expected loopback MTU {initial}")
    for address in ("127.0.0.1", "::1"):
        run(args.host.resolve(strict=True), args.client.resolve(strict=True), address, args.live_reply)
