#!/usr/bin/env python3
"""One linked-v3 Core, six real ingress paths, one passive peer, disposable netns."""
import copy
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time

from kernel_wg_owned_stage_test import child, line, run
from prototype_hy2_test import fixtures
from prototype_test import control, free_port, roundtrip
from prototype_wg_outbound_test import no_connect, udp_port
from socks_loopback_test import exact, greeting, request, response
from vless_loopback_test import UUID, eof, request as vless_request

DEST = "198.51.100.77"
PASSIVE = "192.0.2.2"
DIRECT = "192.0.2.1"
SOURCES = ("10.215.0.1", "10.215.0.2")
CAP = "spec_v3_wireguard_stream_outbound_netns"
ECHO = """
import socket, threading
def echo(c):
    with c:
        c.settimeout(15)
        while data := c.recv(4096):
            c.sendall(data)
with socket.socket() as s:
    s.bind(("0.0.0.0",0))
    s.listen()
    print(s.getsockname()[1],flush=True)
    while True:
        c, peer=s.accept()
        print(peer[0],flush=True)
        threading.Thread(target=echo,args=(c,),daemon=True).start()
"""


def socks(port, target):
    s = socket.create_connection(("127.0.0.1", port), timeout=6)
    greeting(s)
    s.sendall(request(target, DEST))
    return s


def wait(predicate):
    end = time.monotonic() + 5
    while not predicate():
        assert time.monotonic() < end, "generation drain deadline"
        time.sleep(.02)


def main(binary, oracle, fault):
    if (os.path.samefile("/proc/self/ns/net", "/proc/self/fd/3") or
            os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net")):
        sys.exit("disposable netns required")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="wg-linked-") as tmp, \
            child("unshare", "-n", "sh", "-c", "echo READY; exec sleep 120") as passive:
        assert line(passive) == "READY"
        ns = ("nsenter", "-t", str(passive.pid), "-n")
        root = Path(tmp)
        state = root / "state"
        (state / "wg-linked-journal").mkdir(mode=0o700, parents=True)
        crt, tls_key, _ = fixtures(root)
        remote_key = run("wg", "genkey")
        remote_pub = run("wg", "pubkey", input=remote_key).strip()
        keyfile = root / "peer.key"
        keyfile.write_text(remote_key)
        keys = [run("wg", "genkey") for _ in SOURCES]
        public = [run("wg", "pubkey", input=k).strip() for k in keys]
        psk = run("wg", "genpsk")
        psk_path = root / "psk"
        psk_path.write_text(psk)
        env = dict(os.environ, STEER_LAB_CA_FILE=str(crt), STEER_LAB_HY2_TOKEN="disposable-hy2",
                   STEER_TEST_TLS_KEY=str(tls_key), STEER_TEST_UUID=UUID,
                   STEER_WG_ONE=keys[0].strip(), STEER_WG_TWO=keys[1].strip(), STEER_WG_PSK=psk.strip())
        run("ip", "link", "set", "lo", "up")
        run(*ns, "ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "wg-underlay", "type", "veth", "peer", "name", "passive-lan")
        run("ip", "link", "set", "passive-lan", "netns", str(passive.pid))
        run("ip", "addr", "add", f"{DIRECT}/24", "dev", "wg-underlay")
        run("ip", "link", "set", "wg-underlay", "up")
        run(*ns, "ip", "addr", "add", f"{PASSIVE}/24", "dev", "passive-lan")
        run(*ns, "ip", "link", "set", "passive-lan", "up")
        run(*ns, "ip", "addr", "add", f"{DEST}/32", "dev", "lo")
        run("ip", "route", "add", f"{DEST}/32", "via", PASSIVE, "dev", "wg-underlay")
        run(*ns, "ip", "link", "add", "passive-wg", "type", "wireguard")
        passive_port = udp_port()
        run(*ns, "wg", "set", "passive-wg", "private-key", str(keyfile), "listen-port", str(passive_port))
        run(*ns, "ip", "link", "set", "passive-wg", "up")
        for source, pub in zip(SOURCES, public):
            run(*ns, "wg", "set", "passive-wg", "peer", pub, "preshared-key", str(psk_path),
                "allowed-ips", f"{source}/32")
            run(*ns, "ip", "route", "add", f"{source}/32", "dev", "passive-wg")

        # Explicit rules for six ordinary listeners. Each pair reaches the
        # same IP and port, without DNS, but selects a different registry slot.
        base = {"version": 3,
                "plugin_remotes": {"local": {"url": "https://github.com/splify2/steer-protocols",
                                            "trust": "steer-linked-prototype-v1"}},
                "plugins": {"bundle": {"remote": "local", "package": "steer-protocols", "version": "0.0.0"}},
                "secrets": {}, "inbounds": {}, "outbounds": {"net": {"type": "direct"}, "deny": {"type": "block"}},
                "routing": {"default": "deny", "rules": []}}

        def secret(doc, id_, kind, name):
            doc["secrets"][id_] = {"source": "env", "name": name, "kind": kind}
            return {"secret": id_}

        uuid = secret(base, "uuid", "uuid", "STEER_TEST_UUID")
        password = secret(base, "hy-password", "password", "STEER_LAB_HY2_TOKEN")
        certificate = secret(base, "hy-cert", "certificate", "STEER_LAB_CA_FILE")
        private = secret(base, "hy-key", "private_key", "STEER_TEST_TLS_KEY")
        used = set()

        def port(allocate):
            while (value := allocate()) in used:
                pass
            used.add(value)
            return value

        for proto in ("socks", "vless", "hysteria2"):
            for path in ("wg", "direct"):
                name = f"{proto}-{path}"
                node = {"plugin": f"{proto}:bundle", "flow": ["stream"],
                        "listen": {"address": "127.0.0.1", "port": port(udp_port if proto == "hysteria2" else free_port)},
                        "options": {}}
                if proto == "vless":
                    node["options"] = {"principal_id": "fixture", "uuid": uuid}
                if proto == "hysteria2":
                    node["options"] = {"principal_id": "fixture", "password": password}
                    node["transport"] = {"type": "quic"}
                    node["security"] = {"type": "tls", "certificate": certificate, "private_key": private}
                base["inbounds"][name] = node
                base["routing"]["rules"].append({"name": name, "match": {"inbound": [name]}, "outbound": "net"})

        def mixed(which):
            doc = copy.deepcopy(base)
            ref = secret(doc, "wg-private", "wireguard_private_key", ("STEER_WG_ONE", "STEER_WG_TWO")[which])
            psk_ref = secret(doc, "wg-psk", "wireguard_preshared_key", "STEER_WG_PSK")
            doc["outbounds"]["vpn"] = {
                "plugin": "wireguard:bundle", "variant": "kernel", "flow": ["stream"],
                "transport": {"type": "udp"}, "endpoint": {"address": PASSIVE, "port": passive_port},
                "options": {"private_key": ref, "listen_port": port(udp_port), "mtu": 1420,
                            "addresses": [f"{SOURCES[which]}/32"], "route_prefix": f"{DEST}/32",
                            "peers": [{"allowed_ips": [f"{DEST}/32"], "principal_id": "passive",
                                       "public_key": remote_pub, "preshared_key": psk_ref}]}}
            for rule in doc["routing"]["rules"]:
                if rule["name"].endswith("-wg"):
                    rule["outbound"] = "vpn"
            return doc

        first, second = mixed(0), mixed(1)
        seed = root / "seed.json"
        seed.write_text(json.dumps(base))

        def start(label, *, enabled=True, crash=None):
            ctl = root / f"{label}.sock"
            args = [binary, "--config", str(seed), "--control", str(ctl)]
            proc_env = env.copy()
            if enabled:
                args += ["--state-dir", str(state), "--allow-wg-stream-netns"]
            if crash:
                proc_env.update(LD_PRELOAD=fault, STEER_TEST_WG_COMMIT_CRASH=crash)
            return ctl, child(*args, env=proc_env, pass_fds=(3,))

        def ready(process):
            row = line(process)
            assert row.startswith("READY "), row
            return json.loads(row[6:])

        def device_set():
            return {row["ifname"] for row in json.loads(run("ip", "-j", "link", "show"))
                    if row["ifname"].startswith("sw")}

        def counters():
            return {key: (int(rx), int(tx)) for key, rx, tx in
                    (row.split() for row in run(*ns, "wg", "show", "passive-wg", "transfer").splitlines())}

        def handshake():
            return {key: int(value) for key, value in
                    (row.split() for row in run(*ns, "wg", "show", "passive-wg", "latest-handshakes").splitlines())}

        def inlet(name):
            return base["inbounds"][name]["listen"]["port"]

        def matrix(path, source, *, linked=True):
            for protocol in ("socks", "vless", "hysteria2"):
                entry = inlet(f"{protocol}-{path}")
                before = counters()
                if protocol == "socks":
                    with socks(entry, target) as s:
                        assert response(s) == (0 if source else 2)
                        if source:
                            roundtrip(s)
                elif protocol == "vless":
                    with socket.create_connection(("127.0.0.1", entry), timeout=6) as s:
                        s.sendall(vless_request(target, DEST))
                        if source:
                            assert exact(s, 2) == b"\0\0"
                            roundtrip(s)
                        else:
                            eof(s)
                else:
                    mode = "echo" if source else "reject"
                    result = subprocess.run((oracle, f"127.0.0.1:{entry}", f"{DEST}:{target}", mode),
                                            env=dict(env, STEER_TEST_LINKED_HY2="1" if linked else "0"),
                                            text=True, capture_output=True, timeout=10)
                    assert result.returncode == 0 and result.stdout.strip() == f"PASS {mode}", result.stderr
                if source:
                    assert line(echo) == source
                else:
                    no_connect(echo)
                after = counters()
                if source in SOURCES:
                    key = public[SOURCES.index(source)]
                    assert all(a > b for a, b in zip(after[key], before[key])), (protocol, before, after)
                else:
                    assert after == before, (protocol, before, after)

        def apply(ctl, doc, revision):
            code, reply = control(ctl, "APPLY", doc, revision)
            assert code == 200, (code, reply)
            assert control(ctl, "GET")[1]["document"] == doc
            return reply["revision"]

        with child(*ns, sys.executable, "-c", ECHO) as echo:
            target = int(line(echo))
            rejected = root / "same-namespace.sock"
            with child("sh", "-c", 'exec "$@" 3</proc/self/ns/net', "sh", binary,
                       "--config", str(seed), "--control", str(rejected), "--state-dir", str(state),
                       "--allow-wg-stream-netns", env=env) as core:
                assert core.wait(timeout=5) != 0 and not rejected.exists()
            ctl, instance = start("normal", enabled=False)
            with instance as core:
                status = ready(core)
                assert status["revision"] == 1 and CAP not in status["capabilities"]
                assert control(ctl, "VALIDATE", first)[0] == 422
                assert control(ctl, "APPLY", first, 1)[0] == 422
                matrix("direct", DIRECT, linked=False)
                core.terminate()
                assert core.wait(timeout=5) == 0

            ctl, instance = start("apply")
            with instance as core:
                status = ready(core)
                assert status["revision"] == 1 and status["capabilities"][CAP] is True
                assert control(ctl, "VALIDATE", first)[0] == 200
                wrong = copy.deepcopy(first)
                wrong["secrets"]["wg-psk"]["name"] = "STEER_WG_MISSING"
                assert control(ctl, "VALIDATE", wrong)[0] == 422
                assert not device_set()
                main_before = run("ip", "-j", "route", "show", "table", "main")
                revision = apply(ctl, first, 1)
                assert run("ip", "-j", "route", "show", "table", "main") == main_before
                [old_device] = device_set()
                matrix("direct", DIRECT)
                assert handshake() == {key: 0 for key in public}
                matrix("wg", SOURCES[0])
                assert handshake()[public[0]] > 0 and handshake()[public[1]] == 0
                print("PASS one linked revision: independent SOCKS5, VLESS and upstream HY2 use WG or direct", flush=True)

                with socks(inlet("socks-wg"), target) as old:
                    assert response(old) == 0 and line(echo) == SOURCES[0]
                    roundtrip(old)
                    with socket.socket() as occupied:
                        occupied.bind(("127.0.0.1", 0))
                        occupied.listen()
                        failed = copy.deepcopy(second)
                        failed["inbounds"]["blocked-bind"] = copy.deepcopy(base["inbounds"]["socks-wg"])
                        failed["inbounds"]["blocked-bind"]["listen"]["port"] = occupied.getsockname()[1]
                        assert control(ctl, "APPLY", failed, revision)[0] == 422
                        wait(lambda: device_set() == {old_device})
                        assert control(ctl, "GET")[1]["revision"] == revision
                        roundtrip(old)
                    revision = apply(ctl, second, revision)
                    [new_device] = device_set() - {old_device}
                    assert old_device in device_set()
                    roundtrip(old, b"draining old WG keeps its own link")
                    matrix("wg", SOURCES[1])
                wait(lambda: device_set() == {new_device})
                revision = apply(ctl, base, revision)
                wait(lambda: not device_set())
                matrix("wg", DIRECT)  # these same rules now explicitly select net
                core.kill()
                assert core.wait(timeout=5) == -signal.SIGKILL

            ctl, instance = start("recover-without-wg")
            with instance as core:
                assert ready(core)["revision"] == revision
                assert not device_set() and control(ctl, "GET")[1]["document"] == base
                revision = apply(ctl, second, revision)
                matrix("wg", SOURCES[1])
                core.terminate()
                assert core.wait(timeout=5) == 0

            for phase in ("before", "after"):
                ctl, instance = start(f"crash-{phase}", crash=phase)
                with instance as core:
                    assert ready(core)["revision"] == revision
                    try:
                        control(ctl, "APPLY", first, revision)
                    except (OSError, AssertionError):
                        pass
                    assert core.wait(timeout=5) == -signal.SIGKILL
                ctl, instance = start(f"recover-{phase}")
                with instance as core:
                    got = ready(core)["revision"]
                    assert (got == revision if phase == "before" else got > revision)
                    assert control(ctl, "GET")[1]["document"] == (second if phase == "before" else first)
                    assert len(device_set()) == 1
                    matrix("wg", SOURCES[1 if phase == "before" else 0])
                    matrix("direct", DIRECT)
                    revision = got
                    core.terminate()
                    assert core.wait(timeout=5) == 0

            ctl, instance = start("uncertain", crash="unsynced")
            with instance as core:
                assert ready(core)["revision"] == revision
                code, reply = control(ctl, "APPLY", second, revision)
                assert code == 503 and reply["durability_uncertain"], (code, reply)
                status = control(ctl, "STATUS")[1]
                assert status["revision"] == revision and not status["runtimeReady"]
                assert len(device_set()) == 2 and control(ctl, "GET")[1]["document"] == first
                assert control(ctl, "APPLY", second, revision)[0] == 503
                with socket.create_connection(("127.0.0.1", inlet("vless-direct")), timeout=5) as s:
                    eof(s)
                no_connect(echo)
                core.terminate()
                assert core.wait(timeout=5) == 0
                assert len(device_set()) == 2

            ctl, instance = start("reconcile")
            with instance as core:
                assert ready(core)["revision"] > revision
                assert control(ctl, "GET")[1]["document"] == second
                [device] = device_set()
                matrix("wg", SOURCES[1])
                run("ip", "link", "delete", "dev", device)
                assert not control(ctl, "STATUS")[1]["runtimeReady"]
                matrix("wg", None)
                matrix("direct", DIRECT)
                core.terminate()
                assert core.wait(timeout=5) == 0

            ctl, instance = start("missing")
            with instance as core:
                assert core.wait(timeout=5) != 0 and not ctl.exists()
            for entry in state.rglob("*"):
                if entry.is_file():
                    data = entry.read_bytes()
                    assert all(k.strip().encode() not in data for k in [*keys, psk])
            print("PASS late listener rollback, live WG drain, both crash boundaries, uncertainty fence and device loss",
                  flush=True)


if __name__ == "__main__":
    main(*(str(Path(arg).resolve(strict=True)) for arg in sys.argv[1:]))
