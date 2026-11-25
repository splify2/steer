#!/usr/bin/env python3
"""Managed SOCKS v3 through real WireGuard peers in two disposable netns."""
import contextlib
import copy
import errno
import json
import os
import secrets
import select
import shutil
import signal
import subprocess
import sys
import tempfile
from pathlib import Path

from prototype_test import control


VPN = "10.80.0.1"
VPN6 = "fd80::1"
UNDERLAY = "192.0.2.1"
PORT = 11080
TARGET = 18080
USER_ENV = "STEER_FIXTURE_SOCKS_USERNAME"
PASS_ENV = "STEER_FIXTURE_SOCKS_PASSWORD"
ALLOW = ["--allow-socks-vpn-bind", VPN, USER_ENV, PASS_ENV,
         "--allow-socks-vpn-bind", "fd80:0::0001", USER_ENV, PASS_ENV]
PAYLOAD = b"vpn-socks-ok"


def run(argv, **kwargs):
    return subprocess.run(argv, capture_output=True, timeout=10, **kwargs)


def checked(argv, **kwargs):
    # Do not include raw stderr, raw command arguments, or input in failures.
    result = run(argv, **kwargs)
    assert result.returncode == 0, f"{Path(argv[0]).name} failed ({result.returncode})"
    return result.stdout


@contextlib.contextmanager
def process(argv, **kwargs):
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs) as proc:
        try:
            yield proc
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=10)


def ready(proc, prefix):
    assert select.select([proc.stdout], [], [], 8)[0], "startup deadline"
    line = proc.stdout.readline()
    assert line.startswith(prefix), "startup failed"
    return line[len(prefix):]


@contextlib.contextmanager
def netns():
    with process(["unshare", "-n", "--", sys.executable, "-u", "-c",
                  "import sys; print('READY'); sys.stdin.read()"], stdin=subprocess.PIPE) as keeper:
        ready(keeper, b"READY")
        assert os.readlink(f"/proc/{keeper.pid}/ns/net") != os.readlink("/proc/self/ns/net")
        yield ["nsenter", "-t", str(keeper.pid), "-n", "--"], str(keeper.pid)


def wireguard(server, peer, peer_pid):
    checked(server + ["ip", "link", "add", "srv-under", "type", "veth", "peer", "name", "cli-under"])
    checked(server + ["ip", "link", "set", "cli-under", "netns", peer_pid])
    private = [checked(["wg", "genkey"]) for _ in range(2)]
    public = [checked(["wg", "pubkey"], input=key).decode().strip() for key in private]
    for i, (ns, link) in enumerate(((server, "srv-under"), (peer, "cli-under"))):
        checked(ns + ["ip", "link", "set", "lo", "up"])
        checked(ns + ["ip", "addr", "add", f"192.0.2.{i + 1}/30", "dev", link])
        checked(ns + ["ip", "link", "set", link, "up"])
        checked(ns + ["ip", "link", "add", "vpn-test", "type", "wireguard"])
        command = ns + ["wg", "set", "vpn-test", "private-key", "/dev/stdin", "listen-port", "51820",
                        "peer", public[1 - i], "allowed-ips", f"10.80.0.{2 - i}/32,fd80::{2 - i}/128"]
        if i == 1:
            command += ["endpoint", f"{UNDERLAY}:51820"]
        checked(command, input=private[i])
        checked(ns + ["ip", "addr", "add", f"10.80.0.{i + 1}/30", "dev", "vpn-test"])
        checked(ns + ["ip", "-6", "addr", "add", f"fd80::{i + 1}/64", "dev", "vpn-test", "nodad"])
        checked(ns + ["ip", "link", "set", "vpn-test", "up"])
    checked(peer + ["ping", "-q", "-c", "2", "-W", "2", VPN])
    handshakes = checked(server + ["wg", "show", "vpn-test", "latest-handshakes"]).split()
    assert len(handshakes) == 2 and int(handshakes[-1]) > 0


def probe(ns, address, port=PORT, expected="closed"):
    checked(ns + [sys.executable, "-c", r"""
import errno, socket, sys
addr, port, expected, target, refused = sys.argv[1:]
with socket.socket(socket.AF_INET6 if ":" in addr else socket.AF_INET) as s:
    s.settimeout(4)
    rc = s.connect_ex((addr, int(port)))
    if expected == "closed":
        assert rc == int(refused)
    else:
        assert rc == 0
        # For an anonymous client, pipeline a real CONNECT to exercise fail-closed admission.
        s.sendall(b'\x05\x01\x00' + (b'\x05\x01\x00\x01\x7f\x00\x00\x01'
                  + int(target).to_bytes(2, 'big') if expected == "reject" else b''))
        assert s.makefile('rb').read(2) == (b'\x05\xff' if expected == "reject" else b'\x05\x00')
""", address, str(port), expected, str(TARGET), str(errno.ECONNREFUSED)])


def curl(ns, address, user, password):
    proxy = f"[{address}]" if ":" in address else address
    return run(ns + ["curl", "-q", "-fsS", "--max-time", "5", "--noproxy", "",
                     "--proxy", f"socks5h://{proxy}:{PORT}", "--config", "-",
                     f"http://127.0.0.1:{TARGET}/"],
               input=f'proxy-user = "{user}:{password}"\n'.encode())


def listener(address, port=PORT, authenticated=True):
    return {"plugin": "socks:local", "listen": {"address": address, "port": port},
            "options": {"principal_id": "vpn-peer", "username": {"secret": "login"},
                        "password": {"secret": "pass"}} if authenticated else {}}


def endpoints(ns, port=PORT):
    lines = checked(ns + ["ss", "-H", "-ltn", "sport", "=", f":{port}"]).decode().splitlines()
    return {line.split()[3] for line in lines}


def test(binary, work, server, peer):
    user, password = secrets.token_hex(20), secrets.token_hex(24)
    env = dict(os.environ, **{USER_ENV: user, PASS_ENV: password})
    dir_state = work / "state"
    dir_state.mkdir(mode=0o700)
    source = work / "source.json"
    baseline = {
        "version": 3,
        "plugin_remotes": {"local": {"url": "https://github.com/splify2/steer-protocols",
                                      "trust": "steer-linked-prototype-v1"}},
        "plugins": {"local": {"remote": "local", "package": "steer-protocols", "version": "0.0.0"}},
        "inbounds": {"local": listener("127.0.0.1", authenticated=False)},
        "outbounds": {"deny": {"type": "block"}, "origin": {"type": "direct"}},
        "routing": {"default": "deny", "rules": []},
        "secrets": {"login": {"kind": "username", "source": "env", "name": USER_ENV},
                    "pass": {"kind": "password", "source": "env", "name": PASS_ENV}},
    }
    candidate = copy.deepcopy(baseline)
    candidate["inbounds"].update(vpn=listener(VPN), vpn6=listener(VPN6))
    candidate["routing"]["rules"] = [
        {"name": f"{inbound}-direct", "match": {"inbound": [inbound]}, "outbound": "origin"}
        for inbound in ("vpn", "vpn6")
    ]
    source.write_text(json.dumps(baseline))
    legacy = {"prototype": "steer-linux-v1", "listeners": [
        {"id": "open", "protocol": "socks", "listen": {"address": "0.0.0.0", "port": PORT},
         "auth": {"type": "none"}}], "routing": {"default": "direct", "rules": []}}

    def launch(path, args=()):
        return server + [binary, "--config", str(source), "--control", str(path),
                         "--state-dir", str(dir_state), *args]

    with process(launch(work / "default.sock"), env=env) as proc:
        path = work / "default.sock"
        assert json.loads(ready(proc, b"READY "))["capabilities"]["spec_v3_socks_vpn_bind"]["addresses"] == []
        assert control(path, "VALIDATE", candidate)[0] == 422
        assert control(path, "APPLY", legacy, 1)[0] == 422
        assert endpoints(server) == {f"127.0.0.1:{PORT}"}
        probe(peer, VPN)
        probe(server, "127.0.0.1", expected="noauth")
        proc.terminate()
        assert proc.wait(timeout=8) == 0

    # Count accepts (not just HTTP requests), so an unauthenticated dial is visible.
    hits = work / "hits"
    hits.touch()
    target = r"""
import http.server, sys
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b'vpn-socks-ok'
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args):
        pass
class Origin(http.server.HTTPServer):
    def get_request(self):
        request = super().get_request()
        with open(sys.argv[2], 'ab') as f:
            f.write(b'x')
        return request
with Origin(('127.0.0.1', int(sys.argv[1])), Handler) as s:
    print('READY')
    s.serve_forever()
"""
    with process(server + [sys.executable, "-u", "-c", target, str(TARGET), str(hits)]) as origin:
        ready(origin, b"READY")
        path = work / "apply.sock"
        with process(launch(path, ALLOW), env=env) as proc:
            caps = json.loads(ready(proc, b"READY "))["capabilities"]
            assert caps["spec_v3_socks_vpn_bind"] == {"auth": "userpass", "addresses": [VPN, VPN6]}
            assert control(path, "VALIDATE", candidate, half_close=True)[0] == 200
            assert control(path, "GET")[1]["revision"] == 1
            probe(peer, VPN)
            for address in ("0.0.0.0", "::", UNDERLAY, "localhost"):
                invalid = copy.deepcopy(candidate)
                invalid["inbounds"]["vpn"]["listen"]["address"] = address
                assert control(path, "VALIDATE", invalid)[0] == 422
                assert control(path, "APPLY", invalid, 1)[0] == 422
            invalid = copy.deepcopy(candidate)
            invalid["inbounds"]["vpn"]["options"] = {}
            assert control(path, "VALIDATE", invalid)[0] == 422
            assert control(path, "APPLY", invalid, 1)[0] == 422
            invalid = copy.deepcopy(candidate)
            invalid["secrets"]["pass"]["name"] = "PATH"
            assert control(path, "VALIDATE", invalid)[0] == 422
            assert control(path, "APPLY", legacy, 1)[0] == 422
            assert control(path, "APPLY", candidate, 1)[1]["revision"] == 2
            assert endpoints(server) == {f"127.0.0.1:{PORT}", f"{VPN}:{PORT}", f"[{VPN6}]:{PORT}"}
            probe(peer, UNDERLAY)
            probe(peer, VPN, expected="reject")
            probe(peer, VPN6, expected="reject")
            assert curl(peer, VPN, user, secrets.token_hex(24)).returncode == 97
            assert curl(peer, VPN, secrets.token_hex(20), password).returncode == 97
            assert not hits.read_bytes(), "an unauthenticated request reached the origin"
            for address in (VPN, VPN6):
                result = curl(peer, address, user, password)
                assert result.returncode == 0 and result.stdout == PAYLOAD, "authenticated SOCKS relay failed"
            assert hits.read_bytes() == b"xx"
            probe(server, "127.0.0.1", expected="noauth")

            occupied = """
import socket, sys
with socket.socket() as s:
    s.bind((sys.argv[1], int(sys.argv[2])))
    s.listen()
    print('READY')
    sys.stdin.read()
"""
            with process(server + [sys.executable, "-u", "-c", occupied, VPN, str(PORT + 2)],
                         stdin=subprocess.PIPE) as held:
                ready(held, b"READY")
                conflict = copy.deepcopy(candidate)
                conflict["inbounds"].update(new=listener(VPN, PORT + 1), busy=listener(VPN, PORT + 2))
                assert control(path, "VALIDATE", conflict)[0] == 200
                probe(peer, VPN, PORT + 1)
                assert control(path, "APPLY", conflict, 2)[0] == 422
                probe(peer, VPN, PORT + 1)
                assert control(path, "GET")[1]["document"] == candidate
                assert curl(peer, VPN, user, password).stdout == PAYLOAD
            proc.kill()
            assert proc.wait(timeout=8) == -signal.SIGKILL

        denied = work / "denied.sock"
        for args, credentials in [([], env), (ALLOW, dict(env, **{PASS_ENV: ""}))]:
            result = run(launch(denied, args), env=credentials)
            assert result.returncode != 0 and not result.stdout and not denied.exists()
            assert not endpoints(server)
        recovered = work / "recovered.sock"
        with process(launch(recovered, ALLOW), env=env) as proc:
            assert json.loads(ready(proc, b"READY "))["revision"] == 2
            assert control(recovered, "GET")[1]["document"] == candidate
            assert endpoints(server) == {f"127.0.0.1:{PORT}", f"{VPN}:{PORT}", f"[{VPN6}]:{PORT}"}
            assert curl(peer, VPN, user, password).stdout == PAYLOAD
            assert curl(peer, VPN6, user, password).stdout == PAYLOAD
            probe(peer, VPN, expected="reject")
            probe(peer, UNDERLAY)
            proc.terminate()
            assert proc.wait(timeout=8) == 0
    for path in (source, dir_state / "config.json"):
        stored = path.read_bytes()
        assert user.encode() not in stored and password.encode() not in stored


def main():
    for name in ("unshare", "nsenter", "ip", "wg", "ss", "ping", "curl"):
        if not shutil.which(name):
            print(f"SKIP missing {name}")
            return 77
    if run(["unshare", "-n", "--", "true"]).returncode:
        print("SKIP network namespace creation not permitted")
        return 77
    with tempfile.TemporaryDirectory(prefix="steer-vpn-") as directory:
        with netns() as (server, _), netns() as (peer, pid):
            wireguard(server, peer, pid)
            test(os.path.abspath(sys.argv[1]), Path(directory), server, peer)
    print("PASS managed SOCKS v3 over WireGuard: IPv4/IPv6 curl, authentication, validation, rollback and recovery")
    return 0


if __name__ == "__main__":
    sys.exit(main())
