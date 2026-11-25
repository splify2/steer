#!/usr/bin/env python3
"""Managed SOCKS5 -> plain VLESS outbound -> separate loopback VLESS server."""
import argparse
import copy
import hashlib
import socket
import tempfile
from pathlib import Path

from prototype_test import control, core, free_port, roundtrip
from socks_loopback_test import connect, exact, greeting, host, request, server
from vless_loopback_test import ENV, UUID
from vless_stream_xray_test import xray_inbound


def connect_via(inbound, target, expected=0):
    sock = connect(inbound)
    try:
        greeting(sock)
        sock.sendall(request(target))
        header = exact(sock, 4)
        assert header[:3] == bytes([5, expected, 0]), header
        bound = exact(sock, {1: 6, 4: 18}[header[3]])
        return sock, bound
    except BaseException:
        sock.close()
        raise


def check(inbound, target, expected, via_vless=False):
    sock, bound = connect_via(inbound, target, expected)
    with sock:
        if not expected:
            if via_vless:
                assert bound == b"\0" * 6  # upstream has no SOCKS bind address
            else:
                assert bound[:4] == b"\x7f\0\0\x01" and bound[4:] != b"\0\0"
            roundtrip(sock, b"managed-vless-outbound")


def run(binary, upstream):
    # A bound-but-not-listening port cannot be stolen by another test service.
    with socket.socket() as unavailable, tempfile.TemporaryDirectory(prefix="steer-vless-managed-") as directory, \
            server() as target:
        unavailable.bind(("127.0.0.1", 0))
        offline = unavailable.getsockname()[1]
        # Reserve both simultaneously so they cannot be accidentally identical.
        with socket.socket() as one:
            one.bind(("127.0.0.1", 0))
            via = one.getsockname()[1]
            bypass = free_port()
        state = Path(directory) / "state"; state.mkdir(mode=0o700)
        original = {
            "version": 3,
            "plugin_remotes": {"linked": {"url": "https://github.com/splify2/steer-protocols",
                                           "trust": "steer-linked-prototype-v1"}},
            "plugins": {"bundle": {"remote": "linked", "package": "steer-protocols", "version": "0.0.0"}},
            "inbounds": {name: {"plugin": "socks:bundle", "options": {},
                               "listen": {"address": "127.0.0.1", "port": port}}
                         for name, port in (("via", via), ("bypass", bypass))},
            "outbounds": {"deny": {"type": "block"}, "direct": {"type": "direct"}},
            "routing": {"default": "deny", "rules": [
                {"name": "bypass", "match": {"inbound": ["bypass"]}, "action": "route", "outbound": "direct"}]},
        }
        candidate = copy.deepcopy(original)
        candidate["secrets"] = {"peer-id": {"source": "env", "kind": "uuid", "name": "STEER_TEST_OUTBOUND_UUID"}}
        candidate["outbounds"]["proxy"] = {
            "plugin": "vless:bundle", "endpoint": {"address": "127.0.0.1", "port": upstream},
            "options": {"uuid": {"secret": "peer-id"}},
        }
        candidate["outbounds"]["offline"] = copy.deepcopy(candidate["outbounds"]["proxy"])
        candidate["outbounds"]["offline"]["endpoint"]["port"] = offline
        candidate["routing"]["rules"].append(
            {"name": "via", "match": {"inbound": ["via"]}, "action": "route", "outbound": "proxy"})
        env = {"STEER_TEST_OUTBOUND_UUID": UUID, "STEER_TEST_INVALID_UUID": "malformed"}
        with core(binary, directory, original, state_directory=state, extra_env=env) as path:
            status = control(path, "STATUS")[1]
            assert status["capabilities"]["spec_v3_vless_tcp_outbound"] is True
            for edit in (
                lambda d: d["secrets"]["peer-id"].update(name="STEER_TEST_INVALID_UUID"),
                lambda d: d["secrets"]["peer-id"].update(kind="password"),
                lambda d: d["outbounds"]["proxy"].update(plugin="vless:missing"),
                lambda d: d["outbounds"]["proxy"]["options"].update(uuid=UUID),
                lambda d: d["outbounds"]["proxy"]["endpoint"].update(address="localhost"),
                lambda d: d["outbounds"]["proxy"].update(security={"type": "tls"}),
                lambda d: d["outbounds"]["proxy"].update(flow=["stream", "datagram"]),
                lambda d: d["outbounds"]["proxy"].update(detour="direct"),
            ):
                invalid = copy.deepcopy(candidate)
                edit(invalid)
                assert control(path, "VALIDATE", invalid)[0] == 422
                assert control(path, "APPLY", invalid, 1)[0] == 422
            assert control(path, "VALIDATE", candidate)[0] == 200
            assert control(path, "GET")[1]["revision"] == 1
            check(via, target, 2)
            check(bypass, target, 0)
            assert control(path, "APPLY", candidate, 1)[1]["revision"] == 2
            pinned, bound = connect_via(via, target)
            with pinned:
                assert bound == b"\0" * 6
                roundtrip(pinned, b"through-first-binding")
                # A bind conflict after backend preparation must retain rev2.
                conflict = copy.deepcopy(candidate)
                conflict["inbounds"]["conflict"] = copy.deepcopy(conflict["inbounds"]["via"])
                conflict["inbounds"]["conflict"]["listen"]["port"] = upstream
                assert control(path, "VALIDATE", conflict)[0] == 200
                assert control(path, "APPLY", conflict, 2)[0] == 422
                check(via, target, 0, via_vless=True)
                second = copy.deepcopy(candidate)
                second["routing"]["rules"][-1]["outbound"] = "offline"
                assert control(path, "APPLY", second, 2)[1]["revision"] == 3
                check(via, target, 5)  # lower TCP refusal, no direct fallback
                check(bypass, target, 0)
                roundtrip(pinned, b"retired-binding-still-relays")
            persisted = copy.deepcopy(candidate)
            persisted["routing"]["rules"].pop()
            persisted["routing"]["default"] = "proxy"
            assert control(path, "APPLY", persisted, 3)[1]["revision"] == 4
            assert UUID not in (state / "config.json").read_text()
        with core(binary, directory, "not a valid startup file", state_directory=state,
                  expected_revision=4, extra_env=env) as path:
            assert control(path, "GET")[1]["document"] == persisted
            check(via, target, 0, via_vless=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", required=True)
    oracle = parser.add_mutually_exclusive_group(required=True)
    oracle.add_argument("--xray")
    oracle.add_argument("--fixture")
    args = parser.parse_args()
    upstream = xray_inbound(args.xray, UUID) if args.xray else host(args.fixture, extra_env=ENV)
    with upstream as port:
        run(args.core, port)
    if args.xray:
        print("Xray sha256=" + hashlib.sha256(Path(args.xray).read_bytes()).hexdigest())
    print("managed VLESS outbound: alias routing, fail-closed, rollback, drain and restart passed")


if __name__ == "__main__":
    main()
