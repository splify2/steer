#!/usr/bin/env python3
"""Managed SOCKS5 outbound: independent Xray or separate Steer test peer."""
import argparse
import concurrent.futures
import contextlib
import copy
import hashlib
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from prototype_test import control, core, free_port, roundtrip
from socks_loopback_test import connect, exact, greeting, host, request, response, server
from vless_loopback_test import eof

USER, PASSWORD = "lab-user", "lab-pass"  # disposable fixture credentials
ENV = {"STEER_TEST_PROXY_USER": USER, "STEER_TEST_PROXY_PASSWORD": PASSWORD,
       "STEER_TEST_LONG_PASSWORD": "p" * 256, "STEER_TEST_EMPTY_PASSWORD": ""}


@contextlib.contextmanager
def xray_inbounds(binary):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        noauth, auth = sock.getsockname()[1], free_port()
    config = {"log": {"loglevel": "none"}, "inbounds": [
        {"listen": "127.0.0.1", "port": noauth, "protocol": "socks",
         "settings": {"auth": "noauth", "udp": False}},
        {"listen": "127.0.0.1", "port": auth, "protocol": "socks",
         "settings": {"auth": "password", "accounts": [{"user": USER, "pass": PASSWORD}], "udp": False}},
    ], "outbounds": [{"protocol": "freedom", "settings": {"finalRules": [
        {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"]}]}}]}
    with tempfile.TemporaryDirectory(prefix="steer-socks-oracle-") as directory:
        path = Path(directory) / "xray.json"
        path.write_text(json.dumps(config))
        with subprocess.Popen([binary, "run", "-c", str(path)], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL) as process:
            try:
                deadline = time.monotonic() + 5
                for port in (noauth, auth):
                    while True:
                        assert process.poll() is None, "Xray exited before readiness"
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=.1):
                                break
                        except OSError:
                            assert time.monotonic() < deadline, "Xray readiness timeout"
                            time.sleep(.01)
                yield noauth, auth
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


@contextlib.contextmanager
def scripted_peer(handler):
    with socket.socket() as sock, concurrent.futures.ThreadPoolExecutor(max_workers=1) as worker:
        sock.bind(("127.0.0.1", 0)); sock.listen(1); sock.settimeout(8)
        def receive():
            peer, _ = sock.accept()
            with peer:
                peer.settimeout(8)
                handler(peer)
        result = worker.submit(receive)
        yield sock.getsockname()[1]
        result.result(timeout=8)


def open_flow(port, target, code=0):
    sock = connect(port)
    try:
        greeting(sock)
        sock.sendall(request(target))
        assert response(sock) == code
        return sock
    except BaseException:
        sock.close()
        raise


def transfer(port, target, payload=b"managed-socks-outbound"):
    with open_flow(port, target) as sock:
        roundtrip(sock, payload)


def outbound(port, authenticated=False):
    opts = {"username": {"secret": "user"}, "password": {"secret": "pass"}} if authenticated else {}
    return {"plugin": "socks:bundle", "options": opts, "endpoint": {"address": "127.0.0.1", "port": port}}


def original(via, direct):
    return {"version": 3, "plugin_remotes": {"local": {
        "url": "https://github.com/splify2/steer-protocols", "trust": "steer-linked-prototype-v1"}},
        "plugins": {"bundle": {"remote": "local", "package": "steer-protocols", "version": "0.0.0"}},
        "inbounds": {name: {"plugin": "socks:bundle", "options": {},
                           "listen": {"address": "127.0.0.1", "port": port}}
                     for name, port in (("via", via), ("direct", direct))},
        "outbounds": {"direct": {"type": "direct"}, "deny": {"type": "block"}},
        "routing": {"default": "deny", "rules": [
            {"name": "bypass", "match": {"inbound": ["direct"]}, "outbound": "direct"}]}}


def run(binary, noauth, auth):
    with socket.socket() as offline, socket.socket() as one, server() as target, \
            tempfile.TemporaryDirectory(prefix="steer-socks-managed-") as directory:
        offline.bind(("127.0.0.1", 0))
        one.bind(("127.0.0.1", 0))
        via, direct = one.getsockname()[1], free_port()
        one.close()
        base = original(via, direct)
        staged = copy.deepcopy(base)
        staged["secrets"] = {"user": {"source": "env", "kind": "username", "name": "STEER_TEST_PROXY_USER"},
                             "pass": {"source": "env", "kind": "password", "name": "STEER_TEST_PROXY_PASSWORD"}}
        staged["outbounds"].update(proxy=outbound(noauth), auth=outbound(auth, True),
                                   offline=outbound(offline.getsockname()[1]))
        staged["routing"]["rules"].append({"name": "proxy", "match": {"inbound": ["via"]}, "outbound": "proxy"})
        state = Path(directory) / "state"; state.mkdir(mode=0o700)
        with core(binary, directory, base, state_directory=state, extra_env=ENV) as path:
            assert control(path, "STATUS")[1]["capabilities"]["spec_v3_socks_tcp_outbound"] is True
            for edit in (
                lambda d: d["outbounds"]["auth"]["options"].pop("username"),
                lambda d: d["outbounds"]["auth"]["options"].update(password=PASSWORD),
                lambda d: d["secrets"]["pass"].update(kind="username"),
                lambda d: d["secrets"]["pass"].update(name="STEER_TEST_EMPTY_PASSWORD"),
                lambda d: d["secrets"]["pass"].update(name="STEER_TEST_LONG_PASSWORD"),
                lambda d: d["outbounds"]["proxy"].update(flow=["stream", "datagram"]),
                lambda d: d["outbounds"]["proxy"].update(plugin="socks:missing"),
            ):
                invalid = copy.deepcopy(staged); edit(invalid)
                assert control(path, "VALIDATE", invalid)[0] == 422
                assert control(path, "APPLY", invalid, 1)[0] == 422
            assert control(path, "VALIDATE", staged)[0] == 200
            assert control(path, "GET")[1]["revision"] == 1
            conflict = copy.deepcopy(staged)
            conflict["inbounds"]["conflict"] = copy.deepcopy(conflict["inbounds"]["via"])
            conflict["inbounds"]["conflict"]["listen"]["port"] = noauth
            assert control(path, "VALIDATE", conflict)[0] == 200
            assert control(path, "APPLY", conflict, 1)[0] == 422
            assert control(path, "GET")[1]["revision"] == 1
            with open_flow(via, target, 2):
                pass
            transfer(direct, target, b"direct-before")
            assert control(path, "APPLY", staged, 1)[1]["revision"] == 2
            with open_flow(via, target) as old:
                roundtrip(old, b"noauth-via-upstream")
                assert control(path, "APPLY", conflict, 2)[0] == 422
                assert control(path, "GET")[1]["revision"] == 2
                transfer(via, target)
                secured = copy.deepcopy(staged)
                secured["routing"]["rules"][-1]["outbound"] = "auth"
                assert control(path, "APPLY", secured, 2)[1]["revision"] == 3
                transfer(via, target, b"userpass-via-upstream")
                failed = copy.deepcopy(secured)
                failed["routing"]["rules"][-1]["outbound"] = "offline"
                assert control(path, "APPLY", failed, 3)[1]["revision"] == 4
                with open_flow(via, target, 5):
                    pass
                transfer(direct, target, b"uncoupled-direct")
                roundtrip(old, b"noauth-old-generation")
            assert control(path, "APPLY", secured, 4)[1]["revision"] == 5
            saved = (state / "config.json").read_text()
            assert USER not in saved and PASSWORD not in saved
        with core(binary, directory, "not valid", state_directory=state, expected_revision=5, extra_env=ENV) as path:
            assert control(path, "GET")[1]["document"] == secured
            transfer(via, target, b"after-restart")


def fragmented(peer, target):
    assert exact(peer, 3) == b"\x05\x01\x00"
    peer.sendall(b"\x05"); time.sleep(.01); peer.sendall(b"\x00")
    assert exact(peer, 5) == b"\x05\x01\x00\x03\x09"
    assert exact(peer, 11) == b"localhost" + target.to_bytes(2, "big")
    peer.sendall(b"\x05\x00"); time.sleep(.01)
    peer.sendall(b"\x00\x03"); time.sleep(.01)
    peer.sendall(b"\x01\x61\x00\x00early")
    assert exact(peer, 4) == b"tail"
    assert peer.recv(1) == b""  # proxy preserves the client FIN
    peer.sendall(b"after-fin")


def downgrade(peer, _target):
    assert exact(peer, 3) == b"\x05\x01\x02"
    peer.sendall(b"\x05\x00")
    assert peer.recv(1) == b""  # must not disclose credentials or target


def reject_auth(peer, _target):
    assert exact(peer, 3) == b"\x05\x01\x02"
    peer.sendall(b"\x05\x02")
    expected = b"\x01" + bytes([len(USER)]) + USER.encode() + bytes([len(PASSWORD)]) + PASSWORD.encode()
    assert exact(peer, len(expected)) == expected
    peer.sendall(b"\x01\x01")
    assert peer.recv(1) == b""  # no CONNECT after denied authentication


def truncated(peer, target):
    assert exact(peer, 3) == b"\x05\x01\x00"
    peer.sendall(b"\x05\x00")
    assert exact(peer, 10) == request(target)
    peer.sendall(b"\x05\x00\x00\x03\x02x")  # EOF before remaining name and port


def refused(peer, target):
    assert exact(peer, 3) == b"\x05\x01\x00"
    peer.sendall(b"\x05\x00")
    assert exact(peer, 10) == request(target)
    peer.sendall(b"\x05\x05\x00\x01" + b"\0" * 6)


def stalled(peer, _target):
    assert exact(peer, 3) == b"\x05\x01\x00"
    assert peer.recv(1) == b""  # deadline closes the pending upstream read


def wire_cases(binary):
    for handler, status in ((fragmented, 0), (downgrade, 1), (reject_auth, 1),
                            (truncated, 1), (refused, 5), (stalled, None)):
        with socket.socket() as sentinel:
            sentinel.bind(("127.0.0.1", 0))
            target = sentinel.getsockname()[1]
            wire_case(binary, handler, status, target)


def wire_case(binary, handler, status, target):
    with scripted_peer(lambda peer: handler(peer, target)) as upstream, \
            tempfile.TemporaryDirectory(prefix="steer-socks-wire-") as directory:
        with socket.socket() as one:
            one.bind(("127.0.0.1", 0)); port, direct = one.getsockname()[1], free_port()
        doc = original(port, direct)
        doc["secrets"] = {"user": {"source": "env", "kind": "username", "name": "STEER_TEST_PROXY_USER"},
                          "pass": {"source": "env", "kind": "password", "name": "STEER_TEST_PROXY_PASSWORD"}}
        doc["outbounds"]["proxy"] = outbound(upstream, handler in (downgrade, reject_auth))
        doc["routing"]["default"] = "proxy"
        with core(binary, directory, doc, extra_env=ENV), connect(port) as sock:
            greeting(sock)
            start = time.monotonic()
            wire = b"\x05\x01\x00\x03\x09localhost" + target.to_bytes(2, "big") + b"tail"
            sock.sendall(wire if handler is fragmented else request(target))
            if handler is stalled:
                first = sock.recv(1)
                if first:
                    assert first == b"\x05" and exact(sock, 1) == b"\x06"
                assert 3.5 < time.monotonic() - start < 8
            else:
                assert response(sock) == status
            if handler is fragmented:
                assert exact(sock, 5) == b"early"
                sock.shutdown(socket.SHUT_WR)
                assert exact(sock, 9) == b"after-fin"
                eof(sock)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    oracle = parser.add_mutually_exclusive_group(required=True)
    oracle.add_argument("--xray")
    oracle.add_argument("--fixture")
    parser.add_argument("--wire-cases", action="store_true")
    args = parser.parse_args()
    with contextlib.ExitStack() as stack:
        if args.xray:
            noauth, auth = stack.enter_context(xray_inbounds(args.xray))
        else:
            noauth = stack.enter_context(host(args.fixture))
            auth = stack.enter_context(host(args.fixture, auth=True))
        run(args.core, noauth, auth)
    if args.xray:
        print("Xray sha256=" + hashlib.sha256(Path(args.xray).read_bytes()).hexdigest())
    if args.wire_cases:
        wire_cases(args.core)
    print("managed SOCKS5 TCP: NOAUTH/USERPASS, alias, fail-closed, rollback and restart passed")


if __name__ == "__main__":
    main()
