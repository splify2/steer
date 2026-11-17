#!/usr/bin/env python3
"""Real loopback TCP fixtures; no external Python dependencies."""
import concurrent.futures
import contextlib
import http.server
import os
import selectors
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import threading
import time


def exact(sock, count):
    result = b""
    while len(result) < count:
        part = sock.recv(count - len(result))
        assert part, "unexpected EOF"
        result += part
    return result


def response(sock):
    head = exact(sock, 4)
    assert head[0] == 5 and head[2] == 0
    count = {1: 4, 4: 16}.get(head[3])
    assert count
    exact(sock, count + 2)
    return head[1]


def request(port, address="127.0.0.1"):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return b"\x05\x01\x00" + bytes([4 if family == socket.AF_INET6 else 1]) + socket.inet_pton(family, address) + struct.pack("!H", port)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while True:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(data)
        except (OSError, TimeoutError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class IPv6Server(Server):
    address_family = socket.AF_INET6


class HTTP(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "14")
        self.end_headers()
        self.wfile.write(b"steer-curl-lab")

    def log_message(self, *args):
        pass


@contextlib.contextmanager
def server(cls=Server, handler=Echo, address="127.0.0.1"):
    instance = cls((address, 0), handler)
    worker = threading.Thread(target=instance.serve_forever, daemon=True)
    worker.start()
    try:
        yield instance.server_address[1]
    finally:
        instance.shutdown()
        instance.server_close()
        worker.join()


@contextlib.contextmanager
def host(binary, policy="direct", auth=False, address="127.0.0.1", extra_env=None):
    env = dict(os.environ)
    env.pop("STEER_LAB_USER", None)
    env.pop("STEER_LAB_PASSWORD", None)
    if auth:
        env.update(STEER_LAB_USER="lab-user", STEER_LAB_PASSWORD="lab-pass")
    if extra_env:
        env.update(extra_env)
    process = subprocess.Popen([binary, policy, address, "0"], env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        # Bound incomplete lines too: readiness may expose only one byte.
        line = bytearray()
        startup_deadline = time.monotonic() + 5
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"\n" not in line:
                remaining = startup_deadline - time.monotonic()
                assert remaining > 0 and selector.select(timeout=remaining), "host startup deadline exceeded"
                chunk = os.read(process.stdout.fileno(), 64 - len(line))
                assert chunk, "host exited before publishing bound port"
                line.extend(chunk)
                assert len(line) < 64, "host startup line exceeds bound"
        assert line.startswith(b"PORT ") and line.endswith(b"\n") and len(line.split()) == 2, "invalid host startup line"
        yield int(line.split()[1])
    finally:
        process.terminate()
        try:
            output, errors = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=5)
            raise AssertionError("host shutdown deadline exceeded") from None
        assert process.returncode == 0, (process.returncode, errors)
        assert not output and not errors, (output, errors)


def connect(port, address="127.0.0.1"):
    return socket.create_connection((address, port), timeout=8)


def greeting(sock, auth=False):
    sock.sendall(b"\x05\x02\x00\x02")
    assert exact(sock, 2) == (b"\x05\x02" if auth else b"\x05\x00")


def echo(port, target, payload, fragmented=False):
    with connect(port) as sock:
        wire = b"\x05\x01\x00" + request(target) + payload[:16000]
        if fragmented:
            for byte in wire[:13]:
                sock.sendall(bytes([byte]))
            sock.sendall(wire[13:])
        else:
            sock.sendall(wire)
        assert exact(sock, 2) == b"\x05\x00"
        assert response(sock) == 0
        # Concurrent sender exercises backpressure beyond both 16KiB buffers.
        def send():
            sock.sendall(payload[16000:])
            sock.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            sending = pool.submit(send)
            assert exact(sock, len(payload)) == payload
            assert sock.recv(1) == b""
            sending.result()


def main(binary):
    with contextlib.ExitStack() as held_sockets, server() as target, host(binary) as port:
        echo(port, target, bytes(range(256)) * 4096, True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(echo, port, target, bytes([i]) * 40000) for i in range(16)]
            for future in futures:
                future.result()
        # Peer EOF during partial greeting/request must reclaim resources.
        for partial in (b"\x05", b"\x05\x01\x00\x05\x01\x00\x01"):
            with connect(port) as sock:
                sock.sendall(partial)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            failed_port = reserved.getsockname()[1]
        with connect(port) as sock:
            greeting(sock)
            sock.sendall(request(failed_port))
            assert response(sock) == 5
            assert sock.recv(1) == b""
        for wire, code in ((b"\x05\x01\x00\x03\x09localhost\x00\x50", 4),
                           (b"\x05\x02\x00\x01", 7), (b"\x05\x03\x00\x01", 7)):
            with connect(port) as sock:
                greeting(sock)
                sock.sendall(wire)
                assert response(sock) == code
                assert sock.recv(1) == b""
        curl = shutil.which("curl")
        if curl:
            with server(handler=HTTP) as http_port:
                result = subprocess.run([curl, "--silent", "--show-error", "--fail", "--max-time", "8",
                                         "--noproxy", "", "--socks5", f"127.0.0.1:{port}",
                                         f"http://127.0.0.1:{http_port}/"], capture_output=True, check=True)
                assert result.stdout == b"steer-curl-lab"
            print("curl SOCKS5 -> lab inbound -> HTTP passed")
        else:
            print("curl unavailable; independent client check skipped")
        # Exact bounded admission: 32 live handshakes, then deterministic EOF.
        for _ in range(32):
            sock = held_sockets.enter_context(connect(port)); greeting(sock)
        with connect(port) as sock:
            assert sock.recv(1) == b""
        # ExitStack keeps peers alive through host SIGTERM with 32 pending reads.
    with server() as target, host(binary, "block") as port:
        with connect(port) as sock:
            greeting(sock); sock.sendall(request(target)); assert response(sock) == 2
    with server() as target, host(binary, auth=True) as port:
        with connect(port) as sock:
            sock.sendall(b"\x05\x01\x00"); assert exact(sock, 2) == b"\x05\xff"
            assert sock.recv(1) == b""
        for password, success in ((b"wrong", False), (b"lab-pass", True)):
            with connect(port) as sock:
                greeting(sock, True)
                sock.sendall(b"\x01\x08lab-user" + bytes([len(password)]) + password + request(target) + b"auth-echo")
                assert exact(sock, 2) == (b"\x01\x00" if success else b"\x01\x01")
                if success:
                    assert response(sock) == 0
                    assert exact(sock, 9) == b"auth-echo"
                else:
                    assert sock.recv(1) == b""
    try:
        with server(IPv6Server, address="::1") as target, host(binary, address="::1") as port:
            with connect(port, "::1") as sock:
                greeting(sock); sock.sendall(request(target, "::1") + b"ipv6")
                assert response(sock) == 0 and exact(sock, 4) == b"ipv6"
    except OSError as error:
        if error.errno not in (97, 99):
            raise
        print("IPv6 loopback unavailable; IPv6 check skipped")
    with host(binary) as port:
        with connect(port) as sock:
            sock.sendall(b"\x05")
            assert sock.recv(1) == b""  # absolute 5s handshake deadline
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0)); occupied.listen()
        result = subprocess.run([binary, "direct", "127.0.0.1", str(occupied.getsockname()[1])],
                                capture_output=True, timeout=8)
        assert result.returncode == 1 and not result.stdout and not result.stderr
    print("socks loopback TCP fixtures passed")


if __name__ == "__main__":
    main(sys.argv[1])
