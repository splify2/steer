"""Kernel WG staging/recovery fixture. Run only via unshare -n with the opt-in."""
from contextlib import contextmanager
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
def child(*argv):
    with subprocess.Popen(argv, text=True, stdin=subprocess.PIPE,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
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
        client_file, server_file, failed_file = (work / name for name in ("client.key", "wg.conf", "failed.conf"))
        client_file.write_text(client_key)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as binder:
            binder.bind(("0.0.0.0", 0))
            port = binder.getsockname()[1]
        config = (f"[Interface]\nPrivateKey = {server_key.strip()}\nListenPort = {port}\nAddress = 10.203.0.1/24\n"
                  f"[Peer]\nPublicKey = {client_public}\nAllowedIPs = 10.203.0.2/32\n")
        server_file.write_text(config)
        failed_file.write_text(config.replace("10.203.0.", "10.204.0."))

        run("ip", "link", "add", "wg-sentinel", "type", "wireguard")
        run("ip", "link", "add", "wg-outer", "type", "veth", "peer", "name", "wg-peer")
        run("ip", "link", "set", "wg-peer", "netns", str(peer_process.pid))
        for prefix, name, address in (((), "wg-outer", "192.0.2.1"), (peer, "wg-peer", "192.0.2.2")):
            run(*prefix, "ip", "link", "set", "lo", "up")
            run(*prefix, "ip", "addr", "add", address + "/24", "dev", name)
            run(*prefix, "ip", "link", "set", name, "up")
        run(*peer, "ip", "link", "add", "clientwg", "type", "wireguard")
        run(*peer, "wg", "set", "clientwg", "private-key", str(client_file), "peer", server_public,
            "endpoint", f"192.0.2.1:{port}", "allowed-ips", "10.203.0.1/32")
        run(*peer, "ip", "addr", "add", "10.203.0.2/24", "dev", "clientwg")
        run(*peer, "ip", "link", "set", "clientwg", "up")

        def guard(process, verify_drop=False):
            reply = line(process).split()
            assert len(reply) == 2 and reply[0] == "DOWN"
            interface = reply[1]
            link, = json.loads(run("ip", "-j", "link", "show", "dev", interface))
            assert "UP" not in link["flags"]
            assert run("wg", "show", interface, "peers").strip() == client_public
            install = (
                "add table inet wg_fixture\n"
                "add chain inet wg_fixture ingress { type filter hook prerouting priority -10; policy accept; }\n"
            )
            allow = f"add rule inet wg_fixture ingress meta iif {link['ifindex']} ip saddr 10.203.0.2 ip daddr 10.203.0.1 accept\n"
            drop = f"add rule inet wg_fixture ingress meta iif {link['ifindex']} drop\n"
            run("nft", "-f", "-", input=install + ("" if verify_drop else allow) + drop)
            enter(process)
            assert line(process) == "UP"
            if verify_drop:
                denied = subprocess.run([*peer, "ping", "-n", "-q", "-c", "1", "-W", "2", "10.203.0.1"],
                                        capture_output=True, timeout=5)
                assert denied.returncode == 1
                _, latest = run("wg", "show", interface, "latest-handshakes").split()
                assert int(latest) > 0
                run("nft", "-f", "-", input="flush chain inet wg_fixture ingress\n" + allow + drop)
            return interface

        def absent(interface):
            assert interface not in {item["ifname"] for item in json.loads(run("ip", "-j", "link", "show"))}
            run("ip", "link", "show", "dev", "wg-sentinel")

        with child(binary, "--serve", str(active), str(server_file)) as server:
            old = guard(server, verify_drop=True)
            traffic(peer)
            print("PASS journaled identity stages keys/addresses DOWN, then guarded UP carries ICMP and exact binary UDP", flush=True)
            result = run(binary, "--rollback", str(rollback), str(failed_file)).split()
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
        run("nft", "delete", "table", "inet", "wg_fixture")
        with child(binary, "--serve", str(restart), str(server_file)) as server:
            replacement = guard(server)
            assert replacement != old
            # Reinstall the identical peer to discard its previous session on the same port.
            run(*peer, "wg", "set", "clientwg", "peer", server_public, "remove")
            run(*peer, "wg", "set", "clientwg", "peer", server_public,
                "endpoint", f"192.0.2.1:{port}", "allowed-ips", "10.203.0.1/32")
            traffic(peer)
            enter(server)
            assert line(server) == "RETIRED" and server.wait(timeout=5) == 0
        absent(replacement)
        run("nft", "delete", "table", "inet", "wg_fixture")
        print("PASS after SIGKILL exact durable link cleanup is repeatable; reprovisioned real peers carry traffic")


if __name__ == "__main__":
    main()
