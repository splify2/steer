#!/usr/bin/env python3
"""VLESS plain TCP over the shared bounded lab host; synthetic wire client."""
import concurrent.futures
import contextlib
import os
import select
import socket
import struct
import subprocess
import sys
import uuid
from socks_loopback_test import (connect, exact, host, server, IPv6Server)

# Public disposable fixture UUID, not an operator credential.
UUID = "7944c5ab-40b5-4c01-97d6-9d5a55e8d0bf"
ENV = {"STEER_LAB_UUID": UUID}


def request(port, address="127.0.0.1", identity=UUID, command=1, addon=b""):
    try:
        target = b"\x01" + socket.inet_pton(socket.AF_INET, address)
    except OSError:
        if ":" in address:
            target = b"\x03" + socket.inet_pton(socket.AF_INET6, address)
        else:
            name = address.encode("ascii")
            target = b"\x02" + bytes([len(name)]) + name
    return b"\x00" + uuid.UUID(identity).bytes + bytes([len(addon)]) + addon + bytes([command]) + struct.pack("!H", port) + target


def eof(sock):
    try:
        assert sock.recv(1) == b"", "failure must not produce VLESS success header"
    except ConnectionResetError:
        pass  # close with unread pipelined request/body may send TCP RST


def echo(port, target, payload, fragment=False):
    with connect(port) as sock:
        header = request(target)
        if fragment:
            for byte in header[:-1]:
                sock.sendall(bytes([byte]))
            sock.sendall(header[-1:] + payload[:16000])
        else:
            sock.sendall(header + payload[:16000])
        assert exact(sock, 2) == b"\x00\x00"
        def send():
            sock.sendall(payload[16000:])
            sock.shutdown(socket.SHUT_WR)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(send)
            assert exact(sock, len(payload)) == payload
            eof(sock)
            future.result()


def main(binary):
    with contextlib.ExitStack() as held, server() as target, host(binary, extra_env=ENV) as port:
        echo(port, target, bytes(range(256)) * 4096, True)
        with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
            futures = [pool.submit(echo, port, target, bytes([i]) * 40000) for i in range(16)]
            for future in futures:
                future.result()
        # Explicit empty flow is still plain TCP; nonempty flow is denied below.
        with connect(port) as sock:
            sock.sendall(request(target, addon=b"\x0a\x00") + b"empty-flow")
            assert exact(sock, 2) == b"\x00\x00" and exact(sock, 10) == b"empty-flow"
        bad = (
            request(target, identity="11111111-1111-1111-1111-111111111111"),
            request(target, command=2), request(target, command=3),
            request(target, addon=b"\x0a\x04flow"),
            request(target, address="localhost"),
            b"\x01" + request(target)[1:],
            b"\x00" + uuid.UUID(UUID).bytes + b"\x41",
        )
        for wire in bad:
            with connect(port) as sock:
                sock.sendall(wire + b"never-relay")
                eof(sock)
        # Truncated metadata and EOF must reclaim admission/resources.
        for length in (1, 16, 18, 23):
            with connect(port) as sock:
                sock.sendall(request(target)[:length])
                sock.shutdown(socket.SHUT_WR)
                eof(sock)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0)); failed_port = reserved.getsockname()[1]
        with connect(port) as sock:
            sock.sendall(request(failed_port))
            eof(sock)  # no optimistic 00 00 on failed dial
        # Fill exactly 32 slots, verifying their live status with no response:
        # complete headers would dial, so keep them at one partial version byte.
        # Connect in one batch then a 33rd, whose close proves the admission cap.
        peers = []
        for _ in range(32):
            sock = held.enter_context(connect(port)); sock.sendall(b"\x00"); peers.append(sock)
        with connect(port) as sock:
            sock.settimeout(2)  # admission close, not the 5s handshake deadline
            eof(sock)
        assert not select.select(peers, [], [], 0)[0], "admitted peer unexpectedly closed"
        # held peers outlive host context, exercising SIGTERM with pending reads.
    with server() as target, host(binary, "block", extra_env=ENV) as port:
        with connect(port) as sock:
            sock.sendall(request(target) + b"denied"); eof(sock)
    try:
        with server(IPv6Server, address="::1") as target, host(binary, address="::1", extra_env=ENV) as port:
            with connect(port, "::1") as sock:
                sock.sendall(request(target, "::1") + b"ipv6")
                assert exact(sock, 2) == b"\x00\x00" and exact(sock, 4) == b"ipv6"
    except OSError as error:
        if error.errno not in (97, 99):
            raise
        print("IPv6 loopback unavailable; IPv6 check skipped")
    with host(binary, extra_env=ENV) as port:
        with connect(port) as sock:
            sock.sendall(b"\x00"); eof(sock)  # absolute 5s handshake deadline
    env = dict(os.environ)
    for value in (None, "", "invalid", "0" * 36):
        env.pop("STEER_LAB_UUID", None)
        if value is not None:
            env["STEER_LAB_UUID"] = value
        result = subprocess.run([binary, "direct"], env=env, capture_output=True, timeout=5)
        assert result.returncode == 2 and not result.stdout and not result.stderr
    with socket.socket() as occupied:
        occupied.bind(("127.0.0.1", 0)); occupied.listen()
        result = subprocess.run([binary, "direct", "127.0.0.1", str(occupied.getsockname()[1])],
                                env=dict(os.environ, **ENV), capture_output=True, timeout=5)
        assert result.returncode == 1 and not result.stdout and not result.stderr
    print("vless loopback TCP fixtures passed")


if __name__ == "__main__":
    main(sys.argv[1])
