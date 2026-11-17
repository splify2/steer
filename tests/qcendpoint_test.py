"""Independent pinned QUIC client against bounded C endpoint; loopback only."""
import argparse
import hashlib
from pathlib import Path
import select
import socket
import subprocess


def line(process, timeout):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise TimeoutError("endpoint response deadline")
    value = process.stdout.readline(4096)
    if not value:
        raise RuntimeError("endpoint exited unexpectedly")
    return value.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    args = parser.parse_args()
    for label in ("server", "client"):
        path = getattr(args, label).resolve(strict=True)
        setattr(args, label, path)
        print(label, path, "sha256=", hashlib.sha256(path.read_bytes()).hexdigest(), flush=True)
    server = subprocess.Popen([str(args.server)], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    release = None
    try:
        startup = line(server, 5).split()
        if len(startup) != 2 or startup[0] != "PORT" or not 0 < int(startup[1]) < 65536:
            raise RuntimeError("invalid endpoint readiness")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as malformed:
            for packet in (b"", b"\x40" + bytes(40), b"\xc0" + bytes(1199),
                           b"\xc0\x00\x00\x00\x01\xff" + bytes(1500)):
                malformed.sendto(packet, ("127.0.0.1", int(startup[1])))
        subprocess.run([str(args.client), "127.0.0.1:" + startup[1]], check=True, timeout=15)
        server.stdin.write("stats\n")
        server.stdin.flush()
        status = line(server, 3).split()
        if len(status) != 7 or status[0] != "STATS":
            raise RuntimeError("invalid endpoint counters")
        active, accepted, closed, idle, handshakes, errors = map(int, status[1:])
        if (active, accepted, closed, handshakes, errors) != (0, 3, 3, 3, 0) or idle < 2:
            raise RuntimeError("endpoint isolation/capacity/idle counters: " + " ".join(status))
        release = subprocess.Popen([str(args.client), "127.0.0.1:" + startup[1], "release"],
                                   stdout=subprocess.PIPE, text=True)
        if line(release, 5) != "READY release":
            raise RuntimeError("release client readiness")
        server.stdin.write("free\n")
        server.stdin.flush()
        if release.wait(timeout=3):
            raise RuntimeError("owned-child free failed")
        server.stdin.write("stats\n")
        server.stdin.flush()
        status = line(server, 3).split()
        if len(status) != 7 or status[0] != "STATS":
            raise RuntimeError("invalid release counters")
        active, accepted, closed, idle, handshakes, errors = map(int, status[1:])
        if (active, accepted, closed, handshakes, errors) != (0, 4, 4, 4, 0):
            raise RuntimeError("owned-child free leaked a slot or closed UDP endpoint")
        print("PASS endpoint-owned qc_free closes/reaps child and preserves shared descriptor")
        server.stdin.write("quit\n")
        server.stdin.flush()
        if server.wait(timeout=3):
            raise RuntimeError("endpoint host reported callback error")
        print("PASS one UDP fd, CID/peer isolation, capacity reuse, timer expiry/reap; no HY2 server claim")
    finally:
        if release is not None:
            if release.poll() is None:
                release.kill()
                release.wait(timeout=2)
            release.stdout.close()
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=2)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=2)
        for stream in (server.stdin, server.stdout, server.stderr):
            stream.close()


if __name__ == "__main__":
    main()
