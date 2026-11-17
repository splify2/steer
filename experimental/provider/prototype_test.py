#!/usr/bin/env python3
"""Black-box transactional config/control tests against one foreground host."""
import contextlib
import copy
import json
import os
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from socks_loopback_test import connect, exact, greeting, request, response, server
from vless_loopback_test import UUID, request as vless_request, eof


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def control(path, op, document=None, revision=None, fragmented=False):
    body = b"" if document is None else json.dumps(document, separators=(",", ":")).encode()
    header = op
    if revision is not None:
        header += f" {revision}"
    if document is not None:
        header += f" {len(body)}"
    wire = header.encode() + b"\n" + body
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(8); sock.connect(str(path))
        if fragmented:
            for byte in wire[:20]:
                sock.sendall(bytes([byte]))
            sock.sendall(wire[20:])
        else:
            sock.sendall(wire)
        line = b""
        while not line.endswith(b"\n"):
            line += exact(sock, 1)
            assert len(line) < 128
        parts = line.split()
        code = 200 if parts[0] == b"OK" else int(parts[1])
        return code, json.loads(exact(sock, int(parts[-1])))


def listener(identity, port, protocol="socks"):
    auth = {"type": "none"} if protocol == "socks" else {
        "type": "uuid", "principal_id": "alice", "uuid_ref": "env:STEER_TEST_UUID"}
    return {"id": identity, "protocol": protocol, "enabled": True,
            "listen": {"address": "127.0.0.1", "port": port}, "auth": auth}


@contextlib.contextmanager
def core(binary, directory, document, state_directory=None, expected_revision=1, extra_env=None):
    path = Path(directory) / "core.sock"
    config = Path(directory) / "config.json"
    config.write_text(document if isinstance(document, str) else json.dumps(document), encoding="utf-8")
    arguments = [binary, "--config", str(config), "--control", str(path)]
    if state_directory:
        arguments += ["--state-dir", str(state_directory)]
    env = dict(os.environ, STEER_TEST_UUID=UUID)
    if extra_env:
        env.update(extra_env)
    process = subprocess.Popen(arguments, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        line = bytearray(); deadline = time.monotonic() + 8
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while b"\n" not in line:
                remaining = deadline - time.monotonic()
                assert remaining > 0 and selector.select(timeout=remaining), "core startup deadline"
                chunk = os.read(process.stdout.fileno(), 8192 - len(line))
                assert chunk, "core startup EOF"
                line.extend(chunk); assert len(line) < 8192
        assert line.startswith(b"READY "), "core startup failed"
        state = json.loads(line[6:])
        assert state["runtimeReady"] and state["revision"] == expected_revision
        assert path.stat().st_mode & 0o777 == 0o600
        yield path
    finally:
        process.terminate()
        try:
            output, errors = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill(); process.communicate(timeout=5)
            raise AssertionError("core shutdown deadline") from None
        assert process.returncode == 0 and not output and not errors, (process.returncode, errors)
        assert not path.exists()


def socks_flow(port, target):
    sock = connect(port)
    greeting(sock); sock.sendall(request(target)); assert response(sock) == 0
    return sock


def roundtrip(sock, value=b"generation-echo"):
    sock.sendall(value); assert exact(sock, len(value)) == value


def domain_request(target):
    return b"\x05\x01\x00\x03\x09localhost" + target.to_bytes(2, "big")


def main(binary):
    socks_port, vless_port = free_port(), free_port()
    document = {"prototype": "steer-linux-v1",
                "listeners": [listener("socks", socks_port), listener("vless", vless_port, "vless")],
                "routing": {"default": "direct", "rules": []}}
    with tempfile.TemporaryDirectory(prefix="steer-core-test-") as directory, server() as target:
        with contextlib.ExitStack() as peers, core(binary, directory, document) as path:
            code, get = control(path, "GET")
            assert code == 200 and get["revision"] == 1 and get["document"] == document
            assert not get["persistence"]
            assert control(path, "STATUS")[1]["generation"] == 1
            pinned = peers.enter_context(socks_flow(socks_port, target)); roundtrip(pinned)
            with connect(vless_port) as sock:
                sock.sendall(vless_request(target) + b"vless-core")
                assert exact(sock, 2) == b"\x00\x00" and exact(sock, 10) == b"vless-core"
            with connect(socks_port) as sock:
                greeting(sock); sock.sendall(domain_request(target) + b"domain-socks")
                assert response(sock) == 0 and exact(sock, 12) == b"domain-socks"
                sock.shutdown(socket.SHUT_WR); eof(sock)
            with connect(vless_port) as sock:
                sock.sendall(vless_request(target, "localhost") + b"domain-vless")
                assert exact(sock, 2) == b"\x00\x00" and exact(sock, 12) == b"domain-vless"
                sock.shutdown(socket.SHUT_WR); eof(sock)
            invalid = copy.deepcopy(document); invalid["unrecognized"] = True
            assert control(path, "VALIDATE", invalid)[0] == 422
            assert control(path, "APPLY", invalid, 1)[0] == 422
            assert control(path, "GET")[1]["revision"] == 1
            assert control(path, "VALIDATE", document, fragmented=True) == (200, {"valid": True, "persistence": False})
            blocked = copy.deepcopy(document); blocked["routing"]["default"] = "block"
            assert control(path, "APPLY", blocked, 1, fragmented=True)[1]["revision"] == 2
            roundtrip(pinned, b"old-generation-still-direct")
            with connect(socks_port) as sock:
                greeting(sock); sock.sendall(request(target)); assert response(sock) == 2
            with connect(vless_port) as sock:
                sock.sendall(vless_request(target)); eof(sock)
            assert control(path, "APPLY", document, 1)[0] == 409
            assert control(path, "APPLY", document, 2)[1]["revision"] == 3
            with socks_flow(socks_port, target) as sock:
                roundtrip(sock)
            # Prepare one new listener successfully, then force a bind failure.
            # Neither candidate listener may leak into the published generation.
            new_port, occupied_port = free_port(), free_port()
            with socket.socket() as occupied:
                occupied.bind(("127.0.0.1", occupied_port)); occupied.listen()
                candidate = copy.deepcopy(document)
                candidate["listeners"] += [listener("prepared", new_port), listener("occupied", occupied_port)]
                assert control(path, "APPLY", candidate, 3)[0] == 422
            assert control(path, "GET")[1]["revision"] == 3
            try:
                connect(new_port).close()
                raise AssertionError("rolled-back listener is reachable")
            except ConnectionRefusedError:
                pass
            with socks_flow(socks_port, target) as sock:
                roundtrip(sock)
            added = copy.deepcopy(document); added["listeners"].append(listener("extra", new_port))
            assert control(path, "APPLY", added, 3)[1]["revision"] == 4
            with socks_flow(new_port, target) as sock:
                roundtrip(sock)
            disabled = copy.deepcopy(added); disabled["listeners"][0]["enabled"] = False
            assert control(path, "APPLY", disabled, 4)[1]["revision"] == 5
            try:
                connect(socks_port).close()
                raise AssertionError("disabled listener is reachable")
            except ConnectionRefusedError:
                pass
            roundtrip(pinned, b"disabled-listener-old-flow-lives")
            assert control(path, "APPLY", added, 5)[1]["revision"] == 6
            with socks_flow(socks_port, target) as sock:
                roundtrip(sock)
            roundtrip(pinned, b"reenabled-after-established-flow")
            identity_policy = copy.deepcopy(added)
            identity_policy["routing"] = {"default": "block", "rules": [
                {"id": "allow-alice", "inbound": "vless", "principal": "alice", "action": "direct"}]}
            assert control(path, "APPLY", identity_policy, 6)[1]["revision"] == 7
            with connect(socks_port) as sock:
                greeting(sock); sock.sendall(request(target)); assert response(sock) == 2
            with connect(vless_port) as sock:
                sock.sendall(vless_request(target) + b"verified-principal")
                assert exact(sock, 2) == b"\x00\x00" and exact(sock, 18) == b"verified-principal"
            roundtrip(pinned, b"old-generation-survives-identity-policy")
            domain_policy = copy.deepcopy(added)
            domain_policy["routing"] = {"default": "direct", "rules": [
                {"id": "block-localhost", "domain": "localhost", "action": "block"}]}
            assert control(path, "APPLY", domain_policy, 7)[1]["revision"] == 8
            with connect(socks_port) as sock:
                greeting(sock); sock.sendall(domain_request(target)); assert response(sock) == 2
            with socks_flow(socks_port, target) as sock:
                roundtrip(sock, b"numeric-bypasses-domain-rule")
            roundtrip(pinned, b"old-generation-survives-domain-policy")
            assert control(path, "BOGUS")[0] == 400
            # Reject oversized framing before reading a document; a truncated
            # body must never publish a revision.
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5); sock.connect(str(path)); sock.sendall(b"VALIDATE 65537\n")
                assert sock.recv(128).startswith(b"ERR 400 ")
            with socket.socket(socket.AF_UNIX) as sock:
                sock.settimeout(5); sock.connect(str(path)); sock.sendall(b"APPLY 8 20\n{}")
                sock.shutdown(socket.SHUT_WR); eof(sock)
            assert control(path, "GET")[1]["revision"] == 8
    print("configured core transactional TCP fixtures passed")


if __name__ == "__main__":
    main(sys.argv[1])
