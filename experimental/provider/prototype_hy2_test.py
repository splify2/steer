"""Managed shared-core HY2 TCP/TLS gate. Loopback, disposable state only."""
import argparse
import ast
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import tempfile
import threading
import time
from hy2_adapter_test import Echo, command, line
from prototype_test import control, core, free_port, listener, roundtrip, socks_flow
from socks_loopback_test import connect, exact
from vless_loopback_test import request as vless_request


def fixtures(directory):
    source = (Path(__file__).resolve().parents[2] / "tests/qccert.h").read_text()
    block = re.search(r"qc_cert_pem\[\]\s*=\s*(.*?);", source, re.S).group(1)
    pem = "".join(ast.literal_eval(value) for value in re.findall(r'"(?:\\.|[^"\\])*"', block)).encode()
    key = re.search(r"qc_key_der\[\]\s*=\s*\{(.*?)\};", source, re.S).group(1)
    der = bytes(int(value, 16) for value in re.findall(r"0x([0-9a-fA-F]{2})", key))
    certificate, private_key, raw_key, wrong_key = [directory / name for name in ("certificate.pem", "key.pem", "key.der", "wrong.pem")]
    certificate.write_bytes(pem)
    raw_key.write_bytes(der); raw_key.chmod(0o600)
    subprocess.run(["openssl", "pkey", "-inform", "DER", "-in", str(raw_key), "-out", str(private_key)], check=True, capture_output=True)
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(wrong_key)], check=True, capture_output=True)
    private_key.chmod(0o600); wrong_key.chmod(0o600)
    return certificate, private_key, wrong_key


def status(path, predicate=lambda value: True):
    deadline = time.monotonic() + 4
    while time.monotonic() < deadline:
        code, value = control(path, "STATUS")
        assert code == 200
        if predicate(value):
            return value
        time.sleep(.01)
    raise AssertionError("bounded managed runtime barrier")


class Traffic:
    def __init__(self, sock):
        self.sock = sock; self.stop = threading.Event(); self.times = []; self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True); self.thread.start()

    def run(self):
        try:
            while not self.stop.is_set():
                begin = time.monotonic(); roundtrip(self.sock, bytes(range(64)))
                self.times.append((time.monotonic() - begin) * 1000)
                self.stop.wait(.005)
        except Exception as error:
            self.error = type(error).__name__

    def close(self):
        self.stop.set(); self.thread.join(3); self.sock.close()
        assert not self.thread.is_alive() and self.error is None and self.times


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--minimal-host", type=Path)
    parser.add_argument("--expect-udp", action="store_true", help="expect the managed UDP-capable server profile")
    args = parser.parse_args()
    for label in ("host", "client", "minimal_host"):
        path = getattr(args, label)
        if path:
            path = path.resolve(strict=True); setattr(args, label, path)
            print(label, "sha256=" + hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    children = []; traffic = None; echo = Echo()
    token = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="steer-managed-hy2-") as temporary:
        directory = Path(temporary); state = directory / "state"; state.mkdir(mode=0o700)
        certificate, key, wrong = fixtures(directory)
        original_certificate = certificate.read_bytes()
        env = dict(os.environ, STEER_LAB_EXPECT_UDP="1" if args.expect_udp else "0", STEER_LAB_HY2_TOKEN=token, STEER_LAB_CA_FILE=str(certificate),
                   STEER_TEST_HY2_PASSWORD=token, STEER_TEST_HY2_CERT=str(certificate),
                   STEER_TEST_HY2_KEY=str(key), STEER_TEST_HY2_WRONG_KEY=str(wrong))
        port, vless_port = free_port(), free_port()
        hy2 = {"id": "hy2-local", "protocol": "hysteria2", "enabled": True,
               "listen": {"address": "127.0.0.1", "port": port},
               "auth": {"type": "password", "principal_id": "alice", "password_ref": "env:STEER_TEST_HY2_PASSWORD"},
               "tls": {"certificate_ref": "env:STEER_TEST_HY2_CERT", "private_key_ref": "env:STEER_TEST_HY2_KEY"}}
        document = {"prototype": "steer-linux-v1", "listeners": [listener("socks-local", port), listener("vless-local", vless_port, "vless"), hy2],
                    "routing": {"default": "block", "rules": [{"id": "allow-socks", "inbound": "socks-local", "action": "direct"},
                        {"id": "allow-vless", "inbound": "vless-local", "action": "direct"},
                        {"id": "allow-hy2", "inbound": "hy2-local", "principal": "alice", "action": "direct"}]}}

        def client():
            process = subprocess.Popen([str(args.client), "127.0.0.1:" + str(port)], env=env, text=True,
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            children.append(process)
            assert line(process) == "READY HY2 TCP"
            return process

        try:
            with core(str(args.host), directory, document, state_directory=state, extra_env=env) as path:
                runtime = status(path); assert runtime["capabilities"]["providers"] == ["socks", "vless", "hysteria2"]
                assert runtime["capabilities"]["inbound"]["hysteria2"] == {"tcp": True, "udp": args.expect_udp, "tls": True}
                assert len(runtime["listeners"]) == 3  # SOCKS TCP and HY2 UDP share one numeric port.
                revision = 1; current = copy.deepcopy(document)
                code, snapshot = control(path, "GET"); assert code == 200 and snapshot["document"] == current
                with socks_flow(port, int(echo.address.rsplit(":", 1)[1])) as flow:
                    roundtrip(flow)
                with connect(vless_port) as flow:
                    flow.sendall(vless_request(int(echo.address.rsplit(":", 1)[1]))); assert exact(flow, 2) == b"\0\0"; roundtrip(flow)
                peer = client(); command(peer, "echo " + echo.domain + " 524288", "PASS echo")
                command(peer, "hold " + echo.address, "PASS hold")
                assert status(path)["activeClients"] >= 1
                traffic = Traffic(socks_flow(port, int(echo.address.rsplit(":", 1)[1])))
                for i in range(20):
                    assert control(path, "VALIDATE", current)[0] == 200
                    if i % 5 == 0:
                        code, result = control(path, "APPLY", current, revision); assert code == 200
                        revision = result["revision"]
                traffic.close(); print("TLS prepare concurrent loopback traffic:", json.dumps({"samples": len(traffic.times), "max_ms": round(max(traffic.times), 3)}), flush=True); traffic = None
                blocked = copy.deepcopy(current); blocked["routing"]["rules"][-1]["action"] = "block"
                code, result = control(path, "APPLY", blocked, revision); assert code == 200; revision = result["revision"]; current = blocked
                before = echo.count(); command(peer, "reject " + echo.address, "PASS reject"); assert echo.count() == before
                command(peer, "send", "PASS send")
                assert control(path, "APPLY", document, revision - 1)[0] == 409
                code, result = control(path, "APPLY", document, revision); assert code == 200; revision = result["revision"]; current = copy.deepcopy(document)
                command(peer, "echo " + echo.domain + " 65536", "PASS echo")
                mismatch = copy.deepcopy(current); mismatch["listeners"][-1]["tls"]["private_key_ref"] = "env:STEER_TEST_HY2_WRONG_KEY"
                code, result = control(path, "VALIDATE", mismatch)
                assert code == 422, (code, result)
                certificate.write_bytes(b"invalid certificate")
                assert control(path, "APPLY", current, revision)[0] == 422
                certificate.write_bytes(original_certificate + b"\n")
                assert control(path, "VALIDATE", current)[0] == 200
                assert control(path, "APPLY", current, revision)[0] == 422  # valid changed material requires drain/rebind
                certificate.write_bytes(original_certificate)
                assert control(path, "GET")[1]["revision"] == revision
                command(peer, "send", "PASS send")
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                    occupied.bind(("127.0.0.1", 0)); failed = copy.deepcopy(current); extra = copy.deepcopy(hy2)
                    extra["id"] = "must-rollback"; extra["listen"]["port"] = occupied.getsockname()[1]
                    unused = free_port(); failed["listeners"].append(listener("prepared-tcp", unused)); failed["listeners"].append(extra)
                    assert control(path, "APPLY", failed, revision)[0] == 422
                    assert control(path, "GET")[1]["document"] == current
                    with socket.socket() as check: check.bind(("127.0.0.1", unused))
                command(peer, "send", "PASS send")
                disabled = copy.deepcopy(current); disabled["listeners"][-1]["enabled"] = False
                code, result = control(path, "APPLY", disabled, revision); assert code == 200; revision = result["revision"]; current = disabled
                assert status(path)["drainingListeners"][0]["id"] == "hy2-local"
                before = echo.count(); command(peer, "reject " + echo.address, "PASS reject"); assert echo.count() == before
                command(peer, "send", "PASS send")
                assert control(path, "APPLY", document, revision)[0] == 422  # retired UDP bind remains owned
                command(peer, "drop", "PASS drop")
                status(path, lambda value: not value["drainingListeners"])
                command(peer, "quit", "PASS quit"); assert peer.wait(timeout=3) == 0
                code, result = control(path, "APPLY", document, revision); assert code == 200; revision = result["revision"]; current = copy.deepcopy(document)
                peer = client(); command(peer, "echo " + echo.address + " 65536", "PASS echo"); command(peer, "quit", "PASS quit"); assert peer.wait(timeout=3) == 0
                assert token not in json.dumps(control(path, "GET")[1])
            # Durable references survive restart; no private key/token values in document.
            with core(str(args.host), directory, {"deliberately": "ignored"}, state_directory=state, expected_revision=revision, extra_env=env) as path:
                assert control(path, "GET")[1]["document"] == current
                peer = client(); command(peer, "echo " + echo.domain + " 16384", "PASS echo"); command(peer, "quit", "PASS quit"); assert peer.wait(timeout=3) == 0
            if args.minimal_host:
                minimal = directory / "minimal"; minimal.mkdir(mode=0o700)
                disabled = copy.deepcopy(document); disabled["listeners"][-1]["enabled"] = False
                with core(str(args.minimal_host), minimal, disabled, extra_env=env) as path:
                    runtime = status(path); assert runtime["capabilities"]["providers"] == ["socks", "vless"]
                    assert not runtime["capabilities"]["inbound"]["hysteria2"]["tcp"]
                    assert control(path, "VALIDATE", document)[0] == 422
            print("PASS managed shared core: verified TLS PEM/password HY2 + SOCKS/VLESS, read/validate/CAS/rules, material-change and bind rollback, retire/drain/rebind, durable restart; TCP traffic gate (UDP capability separately asserted)")
        finally:
            if traffic: traffic.close()
            for process in children:
                failed = process.poll() not in (None, 0)
                if process.poll() is None: process.kill(); process.wait(timeout=3)
                if failed:
                    diagnostic = process.stderr.read(4096).replace(token, "<redacted>")
                    print("client diagnostic:", diagnostic, flush=True)
                for stream in (process.stdin, process.stdout, process.stderr): stream.close()
            echo.close()


if __name__ == "__main__":
    main()
