#!/usr/bin/env python3
"""Run only under: unshare -n -- ... CORE DEFAULT_CORE COMMIT_SHIM 3</proc/self/ns/net."""
import copy
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile

from kernel_wg_owned_stage_test import child, line, run, intent
from prototype_test import control


def port():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        return sock.getsockname()[1]


def owned():
    return {row["ifname"] for row in json.loads(run("ip", "-j", "link", "show")) if row["ifname"].startswith("sw")}


def guards():
    return {line for line in run("nft", "list", "tables").splitlines() if line.startswith("table inet steer_wg_")}

ECHO = """
import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(5)
    s.bind((sys.argv[1],0))
    print(s.getsockname()[1],flush=True)
    data,addr=s.recvfrom(2048)
    assert addr[0]==sys.argv[2]
    s.sendto(data,addr)
"""
SEND = """
import socket,sys
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
    s.settimeout(3)
    s.bind((sys.argv[1],0))
    s.connect((sys.argv[2],int(sys.argv[3])))
    data=bytes(range(256))*4
    s.sendall(data)
    assert s.recv(2048)==data
"""

def roundtrip(namespaces, addresses):
    # Fresh independently initiated application datagrams in either direction,
    # not just WireGuard keepalives or an echo reply to an inbound flow.
    for a,b in ((0,1),(1,0)):
        with child(*namespaces[b],sys.executable,"-c",ECHO,addresses[b],addresses[a]) as echo:
            run(*namespaces[a],sys.executable,"-c",SEND,addresses[a],addresses[b],line(echo))
            assert echo.wait(timeout=5)==0

def traffic(peers, network):
    for slot, (ns, _, _) in enumerate(peers,2):
        local,remote=f"{network}.1",f"{network}.{slot}"
        run(*ns,"ping","-n","-q","-c","1","-W","2",local)
        run("ping","-n","-q","-c","1","-W","2",remote)
        roundtrip(((),ns),(local,remote))

def peer_config(peer, slot, public, listen, network, private=None):
    ns, psk_path, outer = peer
    args = ("private-key", str(private)) if private else ()
    run(*ns,"wg","set","wg-peer",*args,"peer",public,"preshared-key",str(psk_path),
        "endpoint",f"{outer}:{listen}","allowed-ips",f"{network}.1/32")
    run(*ns,"ip","addr","add",f"{network}.{slot}/24","dev","wg-peer")
    run(*ns,"ip","link","set","wg-peer","up")


def main(binary, default, shim):
    if os.path.samefile("/proc/self/ns/net", "/proc/self/fd/3") or os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net"):
        sys.exit("disposable netns required")
    # Some hosts choose a forwarding-enabled default for newly created
    # namespaces. This fixture is local-only; change only the verified netns.
    Path("/proc/sys/net/ipv4/ip_forward").write_text("0\n")
    for tool in ("unshare", "nsenter", "ip", "wg", "nft", "ping"):
        if not shutil.which(tool):
            sys.exit(f"missing {tool}")
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="steer-core-wg-") as tmp, ExitStack() as children:
        base = Path(tmp)
        state = base / "state"
        (state / "wg-journal").mkdir(mode=0o700, parents=True)
        key = run("wg", "genkey")
        public = run("wg", "pubkey", input=key).strip()
        env = {**os.environ, "STEER_WG_TEST_KEY": key.strip()}
        # When Core is ASan-linked, the runtime must precede a preloaded shim.
        libraries = run("ldd", binary).splitlines()
        preload = ":".join([row.split("=>", 1)[1].split()[0] for row in libraries
                            if "libasan.so" in row and "=>" in row] + [shim])
        listen = port()
        peers, specs = [], []
        for slot in (2, 3):
            peer = children.enter_context(child("unshare", "-n", "sh", "-c", "echo READY; exec sleep 90"))
            assert line(peer) == "READY"
            ns = ("nsenter", "-t", str(peer.pid), "-n")
            priv, psk = run("wg", "genkey"), run("wg", "genpsk")
            client_key, peer_psk = base / f"peer{slot}.key", base / f"peer{slot}.psk"
            client_key.write_text(priv)
            peer_psk.write_text(psk)
            env_name = f"STEER_WG_TEST_PSK{slot}"
            env[env_name] = psk.strip()
            spec = {"public_key": run("wg", "pubkey", input=priv).strip(), "principal_id": f"peer-{slot}",
                    "allowed_ips": [f"10.203.0.{slot}/32"], "preshared_key": {"secret": f"psk{slot}"}}
            specs.append(spec)
            outer, local = f"out{slot}", f"192.0.{slot}.1"
            run("ip","link","add",outer,"type","veth","peer","name","inner")
            run("ip","link","set","inner","netns",str(peer.pid))
            run("ip","addr","add",f"{local}/24","dev",outer)
            run("ip","link","set",outer,"up")
            run(*ns,"ip","addr","add",f"192.0.{slot}.2/24","dev","inner")
            run(*ns,"ip","link","set","inner","up")
            run(*ns,"ip","link","add","wg-peer","type","wireguard")
            peers.append((ns,peer_psk,local))
            peer_config(peers[-1],slot,public,listen,"10.203.0",client_key)
        doc = intent(specs[0]["public_key"], listen)
        opts = doc["inbounds"]["vpn"]["options"]
        opts["addresses"] = ["10.203.0.1/24"]
        opts["peers"] = specs
        del doc["secrets"]["psk"]
        for slot in (2,3):
            doc["secrets"][f"psk{slot}"] = {"source":"env","name":f"STEER_WG_TEST_PSK{slot}",
                                          "kind":"wireguard_preshared_key"}
        doc["outbounds"] = {"local-output": {"type": "direct", "flow": ["device"]}}
        doc["routing"]["default"] = "local-output"
        def start(path, exe=binary, crash=None):
            settings = env if not crash else {**env, "LD_PRELOAD": preload, "STEER_TEST_WG_COMMIT_CRASH": crash}
            return child(exe, "--wg-netns-profile", "--control", str(path), "--state-dir", str(state),
                         env=settings, pass_fds=(3,))
        with start(base / "disabled.sock", default) as p:
            assert p.wait(timeout=5) != 0 and not owned() and not guards()
        with start(base / "initial.sock") as p:
            path = base / "initial.sock"
            hello = line(p)
            assert json.loads(hello.removeprefix("READY "))["revision"] == 0
            assert not control(path, "STATUS")[1]["runtimeReady"]
            assert control(path, "VALIDATE", doc)[0] == 200
            unsupported = copy.deepcopy(doc)
            unsupported["outbounds"]["local-output"]["type"] = "interface"
            assert control(path, "VALIDATE", unsupported)[0] == 422
            assert not owned() and not guards()
            assert control(path, "APPLY", doc, 0, half_close=True)[0] == 200
            status = control(path, "STATUS")[1]
            assert status["runtimeReady"] and status["capabilities"] == {
                "wg_device_inbound_netns": True, "wg_device_outbound": False}
            assert control(path, "GET")[1]["document"] == doc
            baseline = owned(), guards()
            assert len(baseline[0]) == len(baseline[1]) == 1
            traffic(peers,"10.203.0")
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as occupied:
                occupied.bind(("0.0.0.0", 0))
                bad = copy.deepcopy(doc)
                other = bad["inbounds"]["vpn"]["options"]
                other["listen_port"] = occupied.getsockname()[1]
                other["addresses"] = ["10.204.0.1/24"]
                for slot,spec in enumerate(other["peers"],2):
                    spec["allowed_ips"] = [f"10.204.0.{slot}/32"]
                assert control(path, "VALIDATE", bad)[0] == 200
                assert control(path, "APPLY", bad, 1)[0] == 503
            assert control(path, "GET")[1]["revision"] == 1 and (owned(), guards()) == baseline
            traffic(peers,"10.203.0")
            p.kill()
            assert p.wait(timeout=5) == -9
        with start(base / "restart.sock") as p:
            path = base / "restart.sock"
            assert json.loads(line(p).removeprefix("READY "))["revision"] == 1
            assert control(path, "GET")[1]["document"] == doc
            assert (owned(), guards()) == baseline
            traffic(peers,"10.203.0")
            p.terminate()
            assert p.wait(timeout=5) == 0
        print("PASS Core v3 Apply: two independent peers, UDP initiated both ways, port-conflict rollback and restart",
              flush=True)

        candidate_port = port()
        assert candidate_port != listen
        candidate = copy.deepcopy(doc)
        opts = candidate["inbounds"]["vpn"]["options"]
        opts["listen_port"] = candidate_port
        opts["addresses"] = ["10.204.0.1/24"]
        for slot,spec in enumerate(opts["peers"],2):
            spec["allowed_ips"] = [f"10.204.0.{slot}/32"]
        for boundary in ("before", "after"):
            path = base / f"kill-{boundary}.sock"
            with start(path, crash=boundary) as p:
                assert json.loads(line(p).removeprefix("READY "))["revision"] == 1
                try:
                    control(path, "APPLY", candidate, 1)
                except (OSError, AssertionError):
                    pass
                else:
                    raise AssertionError("fault did not kill Core")
                assert p.wait(timeout=5) == -9
            assert len(owned()) == len(guards()) == 2
            with start(base / f"restart-{boundary}.sock") as p:
                path = base / f"restart-{boundary}.sock"
                status = json.loads(line(p).removeprefix("READY "))
                assert status["runtimeReady"] and len(owned()) == len(guards()) == 1
                if boundary == "before":
                    assert status["revision"] == 1 and (owned(), guards()) == baseline
                    assert control(path, "GET")[1]["document"] == doc
                    traffic(peers,"10.203.0")
                else:
                    assert status["revision"] > 1 and not (owned() & baseline[0] or guards() & baseline[1])
                    assert control(path, "GET")[1]["document"] == candidate
                    for slot,peer in enumerate(peers,2):
                        run(*peer[0],"wg","set","wg-peer","peer",public,"remove")
                        peer_config(peer,slot,public,candidate_port,"10.204.0")
                    traffic(peers,"10.204.0")
                p.terminate()
                assert p.wait(timeout=5) == 0
            print(f"PASS SIGKILL {boundary} config commit: Core restores selected revision over real peer", flush=True)


if __name__ == "__main__":
    main(*map(lambda x: str(Path(x).resolve(strict=True)), sys.argv[1:]))
