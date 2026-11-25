#!/usr/bin/env python3
"""Real Core-selected TCP egress to a passive peer, in disposable namespaces."""
import copy
from contextlib import ExitStack
import ipaddress
import json
import os
from pathlib import Path
import select
import socket
import sys
import tempfile
from jsonschema import Draft202012Validator, FormatChecker

from kernel_wg_owned_stage_test import child, line, run
from prototype_test import control, core as normal_core, free_port, listener
from socks_loopback_test import greeting, response

DEST = "198.51.100.77"
OUTSIDE = "198.51.100.78"
SOURCE = "10.215.0.1"
PASSIVE = "192.0.2.2"

ECHO = """
import socket
with socket.socket() as s:
    s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("0.0.0.0",0))
    s.listen()
    print(s.getsockname()[1],flush=True)
    while True:
        c, from_=s.accept()
        print(from_[0],flush=True)
        with c:
            c.settimeout(3)
            with c.makefile("rb") as request:
                data=request.readline(1024)
                if data:
                    c.sendall(from_[0].encode()+b" "+data)
"""


def udp_port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def connect(socks, address, port, expected_source=None):
    with socket.create_connection(("127.0.0.1", socks), timeout=6) as s:
        greeting(s)
        s.sendall(b"\x05\x01\x00\x01" + ipaddress.IPv4Address(address).packed + port.to_bytes(2, "big"))
        code = response(s)
        if expected_source is None:
            assert code == 2, f"expected block, SOCKS returned {code}"
            return
        assert code == 0, f"WG connect returned {code}"
        s.sendall(b"managed-wg\n")
        expected = expected_source.encode() + b" managed-wg\n"
        actual = bytearray()
        while len(actual) < len(expected):
            packet = s.recv(128)
            assert packet
            actual.extend(packet)
        assert actual == expected


def direct_is_possible(address, port):
    with socket.create_connection((address, port), timeout=3) as s:
        s.sendall(b"decoy\n")
        with s.makefile("rb") as reply:
            assert reply.readline(128) == b"192.0.2.1 decoy\n"


def no_connect(echo):
    assert not select.select([echo.stdout], [], [], 0.15)[0], "rejected SOCKS flow reached target"

def guard_tables():
    return {row for row in run("nft","list","tables").splitlines() if row.startswith("table inet steer_wg_")}


def main(binary, ordinary=None):
    scoped = ordinary is not None
    if (os.path.samefile("/proc/self/ns/net", "/proc/self/fd/3") or
            os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net")):
        sys.exit("disposable netns required")
    Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="wg-egress-") as tmp, \
            child("unshare", "-n", "sh", "-c", "echo READY; exec sleep 90") as remote:
        assert line(remote) == "READY"
        ns = ("nsenter", "-t", str(remote.pid), "-n")
        root = Path(tmp)
        state = root / "state"
        (state / ("wg-scoped-journal" if scoped else "wg-journal")).mkdir(mode=0o700, parents=True)
        active_secret, passive_secret = run("wg", "genkey"), run("wg", "genkey")
        active_key = run("wg", "pubkey", input=active_secret).strip()
        passive_key = run("wg", "pubkey", input=passive_secret).strip()
        passive_file = root / "peer.key"
        passive_file.write_text(passive_secret)
        env = {**os.environ, "STEER_WG_CLIENT_KEY": active_secret.strip()}
        socks, local_port, passive_port = free_port(), udp_port(), udp_port()
        run("ip", "link", "set", "lo", "up")
        run(*ns, "ip", "link", "set", "lo", "up")
        run("ip", "link", "add", "wg-underlay", "type", "veth", "peer", "name", "passive-lan")
        run("ip", "link", "set", "passive-lan", "netns", str(remote.pid))
        run("ip", "addr", "add", "192.0.2.1/24", "dev", "wg-underlay")
        run("ip", "link", "set", "wg-underlay", "up")
        run(*ns, "ip", "addr", "add", f"{PASSIVE}/24", "dev", "passive-lan")
        run(*ns, "ip", "link", "set", "passive-lan", "up")
        for address in (DEST, OUTSIDE):
            run(*ns, "ip", "addr", "add", f"{address}/32", "dev", "lo")
            # A genuine reachable direct path, with lower preference than the
            # future WG route. Rejecting the SOCKS flow must not fall back here.
            run("ip", "route", "add", f"{address}/32", "via", PASSIVE, "dev", "wg-underlay", "metric", "200")
        run(*ns, "ip", "link", "add", "passive-wg", "type", "wireguard")
        run(*ns, "wg", "set", "passive-wg", "private-key", str(passive_file),
            "listen-port", str(passive_port), "peer", active_key, "allowed-ips", f"{SOURCE}/32")
        run(*ns, "ip", "link", "set", "passive-wg", "up")
        run(*ns, "ip", "route", "add", f"{SOURCE}/32", "dev", "passive-wg")

        doc = {
            "version": 3,
            "plugin_remotes": {"local": {"url": "https://example.invalid", "trust": "local"}},
            "plugins": {"main": {"remote": "local", "package": "protocols", "version": "0.0.0"}},
            "secrets": {"client": {"source": "env", "name": "STEER_WG_CLIENT_KEY", "kind": "wireguard_private_key"}},
            "inbounds": {"socks-entry": {"plugin": "socks:main", "flow": ["stream"],
                        "listen": {"address": "127.0.0.1", "port": socks}, "options": {}}},
            "outbounds": {"tunnel": {
                "plugin": "wireguard:main", "flow": ["stream"], "variant": "kernel", "transport": {"type": "udp"},
                "endpoint": {"address": PASSIVE, "port": passive_port},
                "options": {"private_key": {"secret": "client"}, "listen_port": local_port,
                            "addresses": [f"{SOURCE}/32"], "route_prefix": f"{DEST}/32",
                            "peers": [{"public_key": passive_key, "principal_id": "passive",
                                       "allowed_ips": [f"{DEST}/32"]}]} }},
            "routing": {"default": "tunnel", "rules": []},
        }
        schema = Path(__file__).resolve().parents[2] / "docs/schemas/wireguard-tcp-netns-outbound-v1.json"
        validator = Draft202012Validator(json.loads(schema.read_text()), format_checker=FormatChecker())
        validator.validate(doc["outbounds"]["tunnel"])

        def start(path, with_socks=True):
            args = ("--socks-port", str(socks)) if with_socks else ()
            if scoped and with_socks:
                args += ("--scoped-route",)
            elif scoped:
                return child(binary, "--wg-netns-profile", "--control", str(path), "--state-dir",
                             str(inbound_state), env=env, pass_fds=(3,))
            return child(binary, "--wg-netns-profile", "--control", str(path), "--state-dir", str(state),
                         *args, env=env, pass_fds=(3,))

        inbound_state = root / "inbound"
        (inbound_state / "wg-journal").mkdir(mode=0o700, parents=True)

        def scoped_device(address):
            rules = json.loads(run("ip", "-j", "rule", "show"))
            [lookup] = [r for r in rules if r.get("oif", "").startswith("sw") and r["priority"] == 1]
            table = lookup["table"]
            device = lookup["oif"]
            [route] = json.loads(run("ip", "-j", "route", "show", "table", table))
            assert route["dst"] == address and route["dev"] == device
            return device, table

        def ready(p):
            value = line(p)
            assert value.startswith("READY ")
            return json.loads(value[6:])

        with ExitStack() as stack:
            echo = stack.enter_context(child(*ns, sys.executable, "-c", ECHO))
            if scoped:
                direct_port = free_port()
                ordinary_dir = root / "ordinary"
                ordinary_dir.mkdir(mode=0o700)
                direct_doc = {"prototype": "steer-linux-v1",
                              "listeners": [listener("direct-entry", direct_port)],
                              "routing": {"default": "direct", "rules": []}}
                direct_ctl = stack.enter_context(normal_core(ordinary, ordinary_dir, direct_doc))
                assert control(direct_ctl, "VALIDATE", doc)[0] == 422
                assert control(direct_ctl, "APPLY", doc, 1)[0] == 422
            service = int(line(echo))
            direct_is_possible(DEST, service)
            assert line(echo) == "192.0.2.1"
            path = root / "inbound.sock"
            with start(path, with_socks=False) as core:
                assert "wg_stream_outbound_netns" not in ready(core)["capabilities"]
                assert control(path, "VALIDATE", doc)[0] == 422
                core.terminate()
                assert core.wait(timeout=5) == 0
            path = root / "first.sock"
            with start(path) as core:
                caps = ready(core)["capabilities"]
                assert caps["wg_stream_outbound_netns"] and not caps["wg_device_outbound"]
                assert caps["wg_stream_outbound_netns_schema"] == schema.stem
                connect(socks, DEST, service)  # empty revision: blocked
                no_connect(echo)
                result = control(path, "VALIDATE", doc)
                assert result[0] == 200, result
                for bad in ("prefix", "recursive", "direct"):
                    invalid = copy.deepcopy(doc)
                    out = invalid["outbounds"]["tunnel"]
                    if bad == "prefix":
                        out["options"]["route_prefix"] = f"{OUTSIDE}/32"
                    elif bad == "recursive":
                        out["endpoint"]["address"] = DEST
                    else:
                        invalid["routing"]["default"] = "direct"
                    assert control(path, "VALIDATE", invalid)[0] == 422
                    assert control(path, "APPLY", invalid, 0)[0] == 422
                assert "(none)" in run(*ns, "wg", "show", "passive-wg", "endpoints")
                main_before = run("ip", "-j", "route", "show", "table", "main")
                if scoped:
                    # A rule with the same priority but without an oif can
                    # preempt the selector. Never replace or remove it.
                    run("ip", "rule", "add", "pref", "1", "lookup", "main")
                    foreign_rules = run("ip", "-j", "rule", "show")
                    assert control(path, "APPLY", doc, 0)[0] == 503
                    assert run("ip", "-j", "rule", "show") == foreign_rules
                    assert not guard_tables()
                    run("ip", "rule", "del", "pref", "1", "lookup", "main")
                result = control(path, "APPLY", doc, 0)
                assert result[0] == 200, result
                [route] = json.loads(run("ip", "-j", "route", "get", DEST))
                if scoped:
                    device, table = scoped_device(DEST)
                    assert route["dev"] == "wg-underlay"
                    assert run("ip", "-j", "route", "show", "table", "main") == main_before
                    connect(direct_port, DEST, service, "192.0.2.1")
                    assert line(echo) == "192.0.2.1"
                else:
                    device = route["dev"]
                    assert device.startswith("sw") and route["prefsrc"] == SOURCE
                revision = control(path, "STATUS")[1]["revision"]
                assert run(*ns, "wg", "show", "passive-wg", "latest-handshakes").split()[1] == "0"
                connect(socks, DEST, service, SOURCE)
                assert line(echo) == SOURCE
                assert int(run(*ns, "wg", "show", "passive-wg", "latest-handshakes").split()[1]) > 0
                print("PASS Core chose WG TCP: first handshake initiated by SOCKS flow, explicit route and WG source",
                      flush=True)
                direct_is_possible(OUTSIDE, service)
                assert line(echo) == "192.0.2.1"
                connect(socks, OUTSIDE, service)
                no_connect(echo)
                with child(sys.executable,"-c",ECHO) as local_echo:
                    blocked = int(line(local_echo))
                    try_new = """import socket,sys
try:
    with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=0.7,
                                  source_address=(sys.argv[3],0)):
        raise AssertionError("unsolicited peer connection reached client")
except TimeoutError:
    pass
"""
                    run(*ns,sys.executable,"-c",try_new,SOURCE,str(blocked),DEST)
                    no_connect(local_echo)
                # A foreign main route (legacy mode) or an intercepting rule
                # (scoped mode) fails staging without replacing either owner.
                conflict = "198.51.100.79"
                current_guards = guard_tables()
                assert len(current_guards) == 1
                run("ip","route","add",f"{conflict}/32","via",PASSIVE,"dev","wg-underlay")
                candidate = copy.deepcopy(doc)
                changed = candidate["outbounds"]["tunnel"]["options"]
                changed["addresses"] = ["10.215.0.9/32"]
                changed["route_prefix"] = f"{conflict}/32"
                changed["peers"][0]["allowed_ips"] = [f"{conflict}/32"]
                changed["listen_port"] = udp_port()
                assert control(path,"VALIDATE",candidate)[0] == 200
                if scoped:
                    run("ip", "rule", "add", "pref", "1", "lookup", "main")
                assert control(path,"APPLY",candidate,revision)[0] == 503
                if scoped:
                    run("ip", "rule", "del", "pref", "1", "lookup", "main")
                assert control(path,"GET")[1]["document"] == doc
                assert json.loads(run("ip","-j","route","get",conflict))[0]["dev"] == "wg-underlay"
                assert {r["ifname"] for r in json.loads(run("ip","-j","link","show"))
                        if r["ifname"].startswith("sw")} == {device}
                assert guard_tables() == current_guards
                connect(socks,DEST,service,SOURCE)
                assert line(echo) == SOURCE
                core.kill()
                assert core.wait(timeout=5) == -9
            path = root / "restart.sock"
            with start(path) as core:
                assert ready(core)["revision"] == revision and control(path, "GET")[1]["document"] == doc
                if scoped:
                    assert scoped_device(DEST) == (device, table)
                    run("ip", "route", "del", f"{DEST}/32", "table", table, "dev", device)
                    connect(socks, DEST, service)
                    no_connect(echo)
                    assert not control(path, "STATUS")[1]["runtimeReady"]
                    connect(direct_port, DEST, service, "192.0.2.1")
                    assert line(echo) == "192.0.2.1"
                    run("ip", "route", "add", f"{DEST}/32", "table", table,
                        "dev", device, "scope", "link", "proto", "242")
                    rule = ("pref", "2", "oif", device, "unreachable", "table", table, "protocol", "242")
                    run("ip", "rule", "del", *rule)
                    connect(socks, DEST, service)
                    no_connect(echo)
                    run("ip", "rule", "add", *rule)
                else:
                    assert json.loads(run("ip", "-j", "route", "get", DEST))[0]["dev"] == device
                connect(socks, DEST, service, SOURCE)
                assert line(echo) == SOURCE
                # A handshake already accepted on generation 1 cannot use
                # generation 3's connector, even for a newly allowed target.
                source2 = "10.215.0.9"
                replacement = copy.deepcopy(doc)
                cfg = replacement["outbounds"]["tunnel"]["options"]
                cfg["addresses"] = [f"{source2}/32"]
                cfg["route_prefix"] = f"{OUTSIDE}/32"
                cfg["peers"][0]["allowed_ips"] = [f"{OUTSIDE}/32"]
                while cfg["listen_port"] == local_port:
                    cfg["listen_port"] = udp_port()
                run(*ns,"wg","set","passive-wg","peer",active_key,"allowed-ips",f"{SOURCE}/32,{source2}/32")
                run(*ns,"ip","route","add",f"{source2}/32","dev","passive-wg")
                with socket.create_connection(("127.0.0.1",socks),timeout=4) as old:
                    greeting(old)
                    result = control(path,"APPLY",replacement,revision)
                    assert result[0] == 200, result
                    old.sendall(b"\x05\x01\x00\x01"+ipaddress.IPv4Address(OUTSIDE).packed+service.to_bytes(2,"big"))
                    assert response(old) == 2
                    no_connect(echo)
                assert control(path,"GET")[1]["document"] == replacement
                if scoped:
                    new_device, _ = scoped_device(OUTSIDE)
                else:
                    new_device = json.loads(run("ip","-j","route","get",OUTSIDE))[0]["dev"]
                assert new_device.startswith("sw") and new_device != device
                connect(socks,OUTSIDE,service,source2)
                assert line(echo) == source2
                run("ip", "link", "delete", "dev", new_device)
                direct_is_possible(OUTSIDE, service)
                assert line(echo) == "192.0.2.1"
                connect(socks, OUTSIDE, service)
                no_connect(echo)
                assert not control(path, "STATUS")[1]["runtimeReady"]
                core.terminate()
                assert core.wait(timeout=5) == 0
            with start(root / "missing.sock") as core:
                assert core.wait(timeout=5) != 0
                assert not (root / "missing.sock").exists()
            print("PASS restart and generation switch; old handshake cannot use new WG; device loss never falls back",
                  flush=True)
            if scoped:
                print("PASS ordinary Core direct to same target before first WG handshake; missing route and rule denied",
                      flush=True)


if __name__ == "__main__":
    main(str(Path(sys.argv[1]).resolve(strict=True)),
         str(Path(sys.argv[3]).resolve(strict=True)) if len(sys.argv) == 4 and sys.argv[2] == "--scoped-route" else None)
