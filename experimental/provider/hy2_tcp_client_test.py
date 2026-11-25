#!/usr/bin/env python3
"""Loopback interoperability against upstream Hysteria2, never external targets."""
import argparse
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import tempfile
import threading


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        with self.server.lock:
            self.server.accepted += 1
        while data := self.request.recv(32768):
            self.request.sendall(data)


def openssl(*args):
    subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=8)


def certificate(directory):
    ca, ca_key = directory / "ca.pem", directory / "ca.key"
    other_ca = directory / "other.pem"
    crt, key, csr, ext = (directory / name for name in ("server.pem", "server.key", "csr", "ext"))
    for cert, priv, cn in ((ca, ca_key, "test-root"), (other_ca, directory / "other.key", "untrusted")):
        openssl("req", "-x509", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-keyout", priv, "-out", cert, "-subj", f"/CN={cn}", "-days", "1",
                "-addext", "basicConstraints=critical,CA:TRUE")
    openssl("req", "-nodes", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", key, "-out", csr, "-subj", "/CN=wrong.test")
    ext.write_text("basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n"
                   "extendedKeyUsage=serverAuth\n", encoding="ascii")
    openssl("x509", "-req", "-in", csr, "-CA", ca, "-CAkey", ca_key, "-CAcreateserial",
            "-out", crt, "-days", "1", "-extfile", ext)
    return ca, other_ca, crt, key


def run(args):
    with tempfile.TemporaryDirectory(prefix="steer-hy2-test-", dir="/tmp/opencode") as tmp, \
            socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as echo, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as silent:
        echo.accepted = 0
        echo.lock = threading.Lock()
        echo.daemon_threads = True
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        silent.bind(("127.0.0.1", 0))
        target_port = echo.server_address[1]
        directory = Path(tmp)
        ca, other_ca, crt, key = certificate(directory)
        broken = directory / "broken.pem"
        broken.write_text("not a root", encoding="ascii")
        fifo = directory / "fifo"
        os.mkfifo(fifo)
        env = dict(os.environ, STEER_LAB_HY2_TOKEN="loopback-fixture:credential",
                   STEER_LAB_CA_FILE=str(ca), STEER_LAB_EXPECT_UDP="0")
        oracle = subprocess.Popen([args.server, crt, key, str(target_port)], env=env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            assert select.select([oracle.stdout], [], [], 5)[0], "server not ready"
            line = oracle.stdout.readline().strip()
            assert line.isdecimal(), "server failed to publish a loopback port"
            port = int(line)
            control = subprocess.run([args.oracle_client, f"127.0.0.1:{port}"], env=env,
                                     input=f"echo 127.0.0.1:{target_port} 32768\nquit\n",
                                     text=True, capture_output=True, timeout=8)
            assert control.returncode == 0 and "PASS echo" in control.stdout, control.stderr

            def probe(mode, name="localhost", roots=ca, target="target.test", endpoint=port, **overrides):
                subprocess.run([args.client, str(endpoint), name, str(roots), target,
                                str(target_port), mode], env=dict(env, **overrides), check=True, timeout=10)

            probe("success")
            probe("success", name="127.0.0.1", target="127.0.0.1")
            probe("unavailable", name="wrong.test")  # CN is not a substitute for existing SAN.
            probe("unavailable", roots=other_ca)
            probe("rejected", STEER_LAB_HY2_TOKEN="wrong-credential")
            probe("rejected", target="denied.test")
            probe("prepare-error", roots=broken)
            probe("prepare-error", roots=directory / "missing")
            probe("prepare-error", roots=fifo)
            probe("prepare-error", name="")
            probe("prepare-error", STEER_LAB_HY2_TOKEN="broken\r\nheader")
            probe("cancel", endpoint=silent.getsockname()[1])
            probe("timeout", endpoint=silent.getsockname()[1])
            with echo.lock:
                assert echo.accepted == 3, "rejected path reached the target"
        finally:
            oracle.terminate()
            oracle.communicate(timeout=5)
            echo.shutdown()
            thread.join(timeout=5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--oracle-client", required=True)
    run(parser.parse_args())
    print("HY2 outbound transport: interop, verification, generation drain, cancel and timeout PASS")
