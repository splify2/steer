"""Kernel WG staging/recovery fixture. Run only via unshare -n with the opt-in."""
from contextlib import contextmanager
import base64
import copy
import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import sys
import tempfile


def run(*argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, capture_output=True, timeout=10, **kwargs).stdout


@contextmanager
def child(*argv, **kwargs):
    with subprocess.Popen(argv, text=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs) as process:
        try:
            yield process
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


def line(process):
    assert select.select([process.stdout], [], [], 5)[0], "fixture response timed out"
    text = process.stdout.readline().strip()
    assert text, "fixture exited without response"
    return text


def enter(process):
    process.stdin.write("\n")
    process.stdin.flush()


def traffic(peer):
    run(*peer, "ping", "-n", "-q", "-c", "1", "-W", "2", "10.203.0.1")
    program = """import socket, sys
payload = bytes(range(256)) * 4
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.connect(("10.203.0.1", int(sys.argv[1])))
    sock.sendall(payload)
    assert sock.recv(2048) == payload
"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target:
        target.settimeout(4)
        target.bind(("10.203.0.1", 0))
        with child(*peer, sys.executable, "-c", program, str(target.getsockname()[1])) as client:
            data, address = target.recvfrom(2048)
            assert data == bytes(range(256)) * 4 and address[0] == "10.203.0.2"
            target.sendto(data, address)
            assert client.wait(timeout=5) == 0


def intent(public, port, address="10.203.0"):
    return {
        "version": 3,
        "plugin_remotes": {"local": {"url": "https://example.invalid", "trust": "local"}},
        "plugins": {"main": {"remote": "local", "package": "protocols", "version": "0.0.0"}},
        "secrets": {
            "server": {"source": "env", "name": "STEER_WG_TEST_KEY", "kind": "wireguard_private_key"},
            "psk": {"source": "env", "name": "STEER_WG_TEST_PSK", "kind": "wireguard_preshared_key"},
        },
        "inbounds": {"vpn": {
            "plugin": "wireguard:main", "flow": ["device"], "device": {"name": "logical-vpn"},
            "options": {
                "private_key": {"secret": "server"}, "listen_port": port,
                "addresses": [address + ".1/24", "fd00::1/64"],
                "peers": [{
                    "public_key": public, "principal_id": "local-client",
                    "allowed_ips": [address + ".2/32", "fd00::2/128"], "preshared_key": {"secret": "psk"},
                }],
            },
        }},
        "outbounds": {"deny": {"type": "block", "flow": ["device"]}},
        "routing": {"default": "deny", "rules": []},
    }


def validate(binary):
    from jsonschema import Draft202012Validator

    schema = Path(__file__).resolve().parents[3] / "plugin-sdk/schema/draft/wireguard-inbound-options.schema.json"
    validator = Draft202012Validator(json.loads(schema.read_text()))
    key = base64.b64encode(bytes(range(1, 33))).decode()
    other_key = base64.b64encode(bytes(range(2, 34))).decode()
    no_key = base64.b64encode(bytes(32)).decode()
    with tempfile.TemporaryDirectory(prefix="steer-wg-options-") as directory:
        path = Path(directory) / "wg.json"

        def check(expected, mutate=lambda d, o, p: None, shape=True, **env):
            document = intent(other_key, 51820)
            options = document["inbounds"]["vpn"]["options"]
            mutate(document, options, options["peers"][0])
            assert validator.is_valid(options) == shape, options
            path.write_text(json.dumps(document))
            environment = {**os.environ, "STEER_WG_TEST_KEY": key, "STEER_WG_TEST_PSK": other_key, **env}
            result = subprocess.run([binary, "--options", str(path)], capture_output=True, env=environment, timeout=5)
            assert result.returncode == expected and not result.stdout and not result.stderr, result

        check(0)
        check(0, lambda d, o, p: p.pop("preshared_key"), STEER_WG_TEST_PSK="")
        check(2, lambda d, o, p: o.update(private_key=key), shape=False)
        check(2, lambda d, o, p: o.update(listen_port="51820"), shape=False)
        check(2, lambda d, o, p: o.update(listen_port=0), shape=False)
        check(2, lambda d, o, p: o.update(mtu=1279), shape=False)
        check(2, lambda d, o, p: o.update(fwmark=1), shape=False)
        check(2, lambda d, o, p: o.update(addresses=[]), shape=False)
        check(2, lambda d, o, p: o.update(addresses=["10.0.0.1/33"]))
        check(2, lambda d, o, p: p.update(endpoint="127.0.0.1:1234"), shape=False)
        check(2, lambda d, o, p: p.update(public_key=other_key[:-2] + "B="), shape=False)
        check(2, lambda d, o, p: p.update(public_key=no_key))
        check(2, lambda d, o, p: p.update(allowed_ips=["10.203.0.2/24"]))
        check(2, lambda d, o, p: o["peers"].append({**p, "public_key": key, "allowed_ips": ["fd00::/64"]}))
        check(2, lambda d, o, p: o["peers"].append({**p, "allowed_ips": ["10.203.0.3/32"]}))
        check(2, lambda d, o, p: o.update(peers=[copy.deepcopy(p) for _ in range(9)]), shape=False)
        check(2, lambda d, o, p: d["secrets"].pop("server"))
        check(2, lambda d, o, p: d["secrets"]["psk"].update(kind="wireguard_private_key"))
        check(3, STEER_WG_TEST_KEY="")
        check(3, STEER_WG_TEST_PSK=no_key)
        check(3, STEER_WG_TEST_PSK="!" * 44)
    print("WG v3 options: SDK shape, typed secret IDs, CIDR ownership conflicts, key failure/wipe PASS")


def main():
    if (os.environ.get("STEER_TEST_OWNED_NETNS") != "1" or
            os.path.samefile("/proc/self/ns/net", "/proc/1/ns/net")):
        sys.exit("an explicitly opted-in disposable network namespace is required")
    for tool in ("unshare", "nsenter", "ip", "nft", "wg", "ping"):
        if not shutil.which(tool):
            sys.exit(f"missing test tool: {tool}")
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="steer-wg-stage-") as temporary, \
            child("unshare", "-n", "sh", "-c", 'echo READY; exec sleep 120') as peer_process:
        assert line(peer_process) == "READY"
        peer = ("nsenter", "-t", str(peer_process.pid), "-n")
        work = Path(temporary)
        active, rollback, restart = (work / label for label in ("active", "rollback", "restart"))
        for directory in (active, rollback, restart):
            directory.mkdir(mode=0o700)
        server_key, client_key = run("wg", "genkey"), run("wg", "genkey")
        server_public, client_public = (run("wg", "pubkey", input=value).strip() for value in (server_key, client_key))
        psk = run("wg", "genpsk")
        environment = {**os.environ, "STEER_WG_TEST_KEY": server_key.strip(), "STEER_WG_TEST_PSK": psk.strip()}
        client_file, psk_file, server_file, failed_file = (
            work / name for name in ("client.key", "peer.psk", "wg.json", "failed.json"))
        client_file.write_text(client_key)
        psk_file.write_text(psk)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as binder:
            binder.bind(("0.0.0.0", 0))
            port = binder.getsockname()[1]
        server_file.write_text(json.dumps(intent(client_public, port)))
        failed_file.write_text(json.dumps(intent(client_public, port, "10.204.0")))

        run("ip", "link", "add", "wg-sentinel", "type", "wireguard")
        run("ip", "link", "add", "wg-outer", "type", "veth", "peer", "name", "wg-peer")
        run("ip", "link", "set", "wg-peer", "netns", str(peer_process.pid))
        for prefix, name, address in (((), "wg-outer", "192.0.2.1"), (peer, "wg-peer", "192.0.2.2")):
            run(*prefix, "ip", "link", "set", "lo", "up")
            run(*prefix, "ip", "addr", "add", address + "/24", "dev", name)
            run(*prefix, "ip", "link", "set", name, "up")
        run(*peer, "ip", "link", "add", "clientwg", "type", "wireguard")
        run(*peer, "wg", "set", "clientwg", "private-key", str(client_file), "peer", server_public,
            "preshared-key", str(psk_file), "endpoint", f"192.0.2.1:{port}", "allowed-ips", "10.203.0.1/32")
        run(*peer, "ip", "addr", "add", "10.203.0.2/24", "dev", "clientwg")
        run(*peer, "ip", "link", "set", "clientwg", "up")

        def guard(process, verify_drop=False):
            reply = line(process).split()
            assert len(reply) == 3 and reply[0] == "DOWN"
            _, interface, table = reply
            assert interface != "logical-vpn"
            link, = json.loads(run("ip", "-j", "link", "show", "dev", interface))
            assert "UP" not in link["flags"]
            assert run("wg", "show", interface, "peers").strip() == client_public
            assert "drop" in run("nft", "list", "table", "inet", table)
            enter(process)
            assert line(process) == "UP"
            if verify_drop:
                denied = subprocess.run([*peer, "ping", "-n", "-q", "-c", "1", "-W", "2", "10.203.0.1"],
                                        capture_output=True, timeout=5)
                assert denied.returncode == 1
                _, latest = run("wg", "show", interface, "latest-handshakes").split()
                assert int(latest) > 0
            enter(process)
            assert line(process) == "ALLOWED"
            return interface, table

        def absent(interface):
            assert interface not in {item["ifname"] for item in json.loads(run("ip", "-j", "link", "show"))}
            run("ip", "link", "show", "dev", "wg-sentinel")

        with child(binary, "--serve", str(active), str(server_file), env=environment) as server:
            old, old_table = guard(server, verify_drop=True)
            traffic(peer)
            print("PASS journaled identity stages keys/addresses DOWN, then guarded UP carries ICMP and exact binary UDP", flush=True)
            result = run(binary, "--rollback", str(rollback), str(failed_file), env=environment).split()
            assert len(result) == 2 and result[0] == "ROLLED_BACK"
            absent(result[1])
            traffic(peer)
            print("PASS exclusive address conflict retires only failed staged link; existing peer still carries traffic", flush=True)
            server.kill()
            server.wait(timeout=5)
        run("ip", "link", "show", "dev", old)
        assert run(binary, "--recover", str(active)).strip() == "RECOVERED"
        assert run(binary, "--recover", str(active)).strip() == "RECOVERED"
        absent(old)
        run("nft", "delete", "table", "inet", old_table)
        with child(binary, "--serve", str(restart), str(server_file), env=environment) as server:
            replacement, new_table = guard(server)
            assert replacement != old
            # Reinstall the identical peer to discard its previous session on the same port.
            run(*peer, "wg", "set", "clientwg", "peer", server_public, "remove")
            run(*peer, "wg", "set", "clientwg", "peer", server_public,
                "preshared-key", str(psk_file), "endpoint", f"192.0.2.1:{port}", "allowed-ips", "10.203.0.1/32")
            traffic(peer)
            enter(server)
            assert line(server) == "RETIRED" and server.wait(timeout=5) == 0
        absent(replacement)
        assert f"table inet {new_table}" not in run("nft", "list", "tables")
        print("PASS after SIGKILL exact durable link cleanup is repeatable; reprovisioned real peers carry traffic")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--validate":
        validate(sys.argv[2])
    else:
        main()
