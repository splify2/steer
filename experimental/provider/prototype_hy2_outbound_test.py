#!/usr/bin/env python3
"""Optional managed HY2 TCP: a SOCKS ingress and upstream Hysteria2 on loopback."""
import argparse
import contextlib
import copy
import json
import os
from pathlib import Path
import select
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

from hy2_tcp_client_test import certificate, Echo
from hy2_adapter_test import line
from prototype_prepare_fault_test import receive, start_request
from prototype_socks_outbound_test import original
from prototype_test import control, core, free_port, roundtrip
from socks_loopback_test import connect, exact, greeting, request, response
from vless_loopback_test import UUID


@contextlib.contextmanager
def peer(binary, crt, key, target, env):
    process = subprocess.Popen([binary, crt, key, str(target)], env=dict(os.environ, **env),
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        assert select.select([process.stdout], [], [], 5)[0], "Hysteria server readiness"
        port = process.stdout.readline().strip()
        assert port.isdecimal(), "Hysteria server exited before readiness"
        yield int(port)
        assert process.poll() is None
    finally:
        process.terminate()
        process.communicate(timeout=5)


@contextlib.contextmanager
def flow(port, target, code=0, domain=None):
    with connect(port) as sock:
        greeting(sock)
        if domain is None:
            sock.sendall(request(target))
        else:
            name = domain.encode("ascii")
            sock.sendall(b"\x05\x01\x00\x03" + bytes([len(name)]) + name + target.to_bytes(2, "big"))
        assert response(sock) == code
        yield sock


def count(echo):
    with echo.lock:
        return echo.accepted


def apply(path, doc, rev):
    code, body = control(path, "APPLY", doc, rev)
    assert code == 200 and body["revision"] == rev + 1, (code, body)
    return rev + 1


def blocked_ca(binary, directory, staged, rotated, env, target, socks):
    """A read barrier deliberately stalls the outbound CA loader, not the owner."""
    arm, config, path = (directory / name for name in ("arm", "config.json", "core.sock"))
    config.write_text(json.dumps(staged), encoding="utf-8")
    notify_r, notify_w = os.pipe()
    release_r, release_w = os.pipe()
    process = None
    try:
        fault_env = dict(os.environ, **env, STEER_TEST_UUID=UUID,
                         STEER_TEST_TLS_READ_PATH=env["STEER_TEST_HY2_CA"],
                         STEER_TEST_TLS_READ_ARM=str(arm), STEER_TEST_TLS_READ_NOTIFY=str(notify_w),
                         STEER_TEST_TLS_READ_RELEASE=str(release_r))
        process = subprocess.Popen([binary, "--config", str(config), "--control", str(path)],
                                   env=fault_env, pass_fds=(notify_w, release_r),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        assert line(process).startswith("READY ")
        with flow(socks, target) as held:
            arm.write_bytes(b"1")
            with start_request(path, "APPLY", rotated, 1) as pending:
                assert select.select([notify_r], [], [], 3)[0], "outbound CA was not read"
                assert os.read(notify_r, 1) == b"1"
                assert control(path, "STATUS")[1]["generation"] == 1
                assert control(path, "GET")[1]["revision"] == 1
                assert control(path, "VALIDATE", staged)[0] == 503
                roundtrip(held, b"owner-serving-during-blocked-ca")
                with flow(socks, target) as fresh:
                    roundtrip(fresh, b"active-context-pinned")
                os.write(release_w, b"g")
                assert receive(pending)[1]["revision"] == 2
    finally:
        if process:
            os.write(release_w, b"g")
            process.terminate()
            out, err = process.communicate(timeout=8)
            assert process.returncode == 0 and not out and not err, (process.returncode, err)
        for fd in (notify_r, notify_w, release_r, release_w):
            os.close(fd)


def run(args, echo, directory):
    ca, other, crt, key = certificate(directory)
    broken = directory / "broken.pem"
    broken.write_text("not a CA", encoding="ascii")
    env = {"STEER_LAB_HY2_TOKEN": "managed-fixture-correct",
           "STEER_TEST_HY2_BAD_AUTH": "managed-fixture-incorrect",
           "STEER_TEST_HY2_CA": str(ca), "STEER_TEST_HY2_OTHER_CA": str(other),
           "STEER_TEST_HY2_BROKEN_CA": str(broken)}
    target = echo.server_address[1]
    with peer(args.server, crt, key, target, env) as upstream, \
            peer(args.server, crt, key, target, env) as replacement:
        socks, direct = free_port(), free_port()
        base = original(socks, direct)
        staged = copy.deepcopy(base)
        staged["secrets"] = {
            "hy-password": {"source": "env", "kind": "password", "name": "STEER_LAB_HY2_TOKEN"},
            "hy-roots": {"source": "env", "kind": "certificate", "name": "STEER_TEST_HY2_CA"},
            "vl-id": {"source": "env", "kind": "uuid", "name": "STEER_TEST_UUID"},
        }
        # These entries take real table slots but no routes. If the HY2 index
        # accidentally selects one, it cannot speak to the QUIC oracle.
        staged["outbounds"]["sock-unused"] = {"plugin": "socks:bundle", "options": {},
                                               "endpoint": {"address": "127.0.0.1", "port": upstream}}
        staged["outbounds"]["vless-unused"] = {"plugin": "vless:bundle", "options": {"uuid": {"secret": "vl-id"}},
                                                "endpoint": {"address": "127.0.0.1", "port": upstream}}
        staged["outbounds"]["hy"] = {
            "plugin": "hysteria2:bundle", "flow": ["stream"],
            "transport": {"type": "quic"},
            "security": {"type": "tls", "server_name": "localhost", "verify": True},
            "options": {"password": {"secret": "hy-password"}, "ca_bundle": {"secret": "hy-roots"}},
            "endpoint": {"address": "127.0.0.1", "port": upstream},
        }
        staged["routing"]["rules"].append({"name": "via-hy2", "match": {"inbound": ["via"]},
                                            "outbound": "hy"})
        rotated = copy.deepcopy(staged)
        rotated["outbounds"]["hy"]["endpoint"]["port"] = replacement
        rotated["outbounds"]["hy"]["security"]["server_name"] = "127.0.0.1"
        state = directory / "state"
        state.mkdir(mode=0o700)
        if args.minimal:
            with core(args.minimal, directory, base) as path:
                caps = control(path, "STATUS")[1]["capabilities"]
                assert "spec_v3_hysteria2_tcp_outbound" not in caps
                assert "spec_v3_hysteria2_stream_only_inbound" not in caps
                assert control(path, "VALIDATE", staged)[0] == 422

        with core(args.core, directory, base, state_directory=state, extra_env=env) as path:
            caps = control(path, "STATUS")[1]["capabilities"]
            assert caps["spec_v3_hysteria2_tcp_outbound"] is True
            assert caps["spec_v3_hysteria2_stream_only_inbound"] is True
            for edit in (
                lambda d, h: h.update(flow=["stream", "datagram"]),
                lambda d, h: h["options"].update(password="literal"),
                lambda d, h: h["options"].pop("ca_bundle"),
                lambda d, h: h["security"].update(verify=False),
                lambda d, h: h["security"].update(verify="true"),
                lambda d, h: h["security"].pop("server_name"),
                lambda d, h: h["security"].update(server_name="bad/name"),
                lambda d, h: h["endpoint"].update(address="localhost"),
                lambda d, h: d["secrets"]["hy-password"].update(name="STEER_TEST_HY2_PASSWORD_ABSENT"),
                lambda d, h: d["secrets"]["hy-roots"].update(kind="password"),
                lambda d, h: d["secrets"]["hy-roots"].update(name="STEER_TEST_HY2_BROKEN_CA"),
            ):
                invalid = copy.deepcopy(staged)
                edit(invalid, invalid["outbounds"]["hy"])
                assert control(path, "VALIDATE", invalid)[0] == 422
                assert control(path, "APPLY", invalid, 1)[0] == 422
            assert control(path, "VALIDATE", staged)[0] == 200
            assert control(path, "GET")[1]["revision"] == 1
            assert count(echo) == 0, "validation reached the peer target"
            with flow(socks, target, 2):
                pass
            rev = apply(path, staged, 1)
            assert control(path, "APPLY", rotated, 1)[0] == 409
            with flow(socks, target, domain="target.test") as old, connect(socks) as no_open:
                greeting(no_open)  # pin the old ingress, but do not admit an outbound yet
                # Exercise QUIC send and receive credit through the SDK adapter.
                payload = bytes(range(256)) * 2048
                writer = threading.Thread(target=old.sendall, args=(payload,))
                writer.start()
                assert exact(old, len(payload)) == payload
                writer.join(timeout=5)
                assert not writer.is_alive()
                rev = apply(path, rotated, rev)
                no_open.sendall(request(target))
                assert response(no_open) == 2
                roundtrip(old, b"previous-generation")
                with flow(socks, target) as current:
                    roundtrip(current, b"new-generation")
                    current.shutdown(socket.SHUT_WR)
                    assert current.recv(1) == b""
                # Continued traffic distinguishes a fixed drain from idle expiry.
                end = time.monotonic() + args.drain_wait
                while True:
                    assert time.monotonic() < end, "retired stream was not reclaimed"
                    try:
                        old.sendall(b"d")
                        if old.recv(1) == b"":
                            break
                    except (ConnectionResetError, BrokenPipeError):
                        break
                    time.sleep(.1)
            end = time.monotonic() + 5
            while control(path, "STATUS")[1]["retainedGenerations"] != 1:
                assert time.monotonic() < end, "generation leaked after drain"
                time.sleep(.02)
            for edit in (
                lambda d, h: h["security"].update(server_name="wrong.test"),
                lambda d, h: d["secrets"]["hy-roots"].update(name="STEER_TEST_HY2_OTHER_CA"),
                lambda d, h: d["secrets"]["hy-password"].update(name="STEER_TEST_HY2_BAD_AUTH"),
            ):
                denied = copy.deepcopy(rotated)
                edit(denied, denied["outbounds"]["hy"])
                assert control(path, "VALIDATE", denied)[0] == 200  # no network during validation
                rev = apply(path, denied, rev)
                before = count(echo)
                with flow(socks, target, 1):  # numeric target would succeed via direct
                    pass
                assert count(echo) == before, "upstream rejection fell back to direct"
                with flow(direct, target) as sock:
                    roundtrip(sock, b"unrelated-direct-still-live")
            rev = apply(path, rotated, rev)
            before = count(echo)
            with flow(socks, target, 1, domain="denied.test"):
                pass
            assert count(echo) == before
            persisted = (state / "config.json").read_text()
            assert env["STEER_LAB_HY2_TOKEN"] not in persisted and str(ca) not in persisted

        with core(args.core, directory, "not valid", state_directory=state,
                  expected_revision=rev, extra_env=env) as path:
            assert control(path, "GET")[1]["document"] == rotated
            with flow(socks, target, domain="target.test") as sock:
                roundtrip(sock, b"validated-durable-restart")
        if args.fault_core:
            blocked_ca(args.fault_core, directory, staged, rotated, env, target, socks)
        # If the committed roots are missing, bootstrap must fail instead of
        # restoring the valid but unrelated direct-only seed config.
        config = directory / "config.json"
        config.write_text(json.dumps(base), encoding="utf-8")
        ca.unlink()
        result = subprocess.run([args.core, "--config", str(config), "--control",
                                 str(directory / "core.sock"), "--state-dir", str(state)],
                                env=dict(os.environ, **env), capture_output=True, timeout=8)
        assert result.returncode != 0 and not result.stdout and not result.stderr
        assert not (directory / "core.sock").exists()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core", required=True)
    parser.add_argument("--server", required=True)
    parser.add_argument("--minimal", help="non-HY2 core or Nano binary")
    parser.add_argument("--fault-core", help="optional steer-prototype-hy2-fault with a CA read barrier")
    parser.add_argument("--drain-wait", type=float, default=35)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="managed-hy2-out-", dir="/tmp/opencode") as temp, \
            socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as echo:
        echo.lock = threading.Lock()
        echo.accepted = 0
        echo.daemon_threads = True
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        try:
            run(args, echo, Path(temp))
        finally:
            echo.shutdown()
            thread.join(timeout=5)
    print("PASS HY2 managed outbound: validation, TCP, trust/name/auth, no fallback, drain, restart")
