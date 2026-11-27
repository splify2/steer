"""Compare the heap-denied C primitives and the ordinary CLI with hashlib."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def sample(n):
    # Nonuniform, including high bytes; argv cannot contain NUL.
    return bytes(1 + (i * 17) % 255 for i in range(n))


probe, cli = sys.argv[1:]
for n in (0, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 129, 4097):
    data = sample(n)
    got = subprocess.check_output([probe, data]).decode().strip()
    assert got == hashlib.sha256(data).hexdigest(), ("sha256", n)

# salt || BE32 can cross both the padding boundary and the block boundary.
for n in (0, 1, 51, 52, 55, 56, 59, 60, 61, 63, 64, 65, 115, 116, 127, 128, 129):
    for k in (0, 63, 64, 65, 129):
        pw, salt = sample(k), sample(n)
        for iters, length in ((0, 16), (1, 32), (3, 33), (2, 64)):
            got = subprocess.check_output([probe, "--pbkdf2", pw, salt, str(iters), str(length)])
            want = hashlib.pbkdf2_hmac("sha256", pw, salt, max(1, iters), length)
            assert bytes.fromhex(got.decode()) == want, ("pbkdf2", n, k, iters, length)

with tempfile.TemporaryDirectory() as tmp:
    net = Path(tmp) / "net"
    net.mkdir()
    env = dict(PATH=os.defpath, STEER_SYSNET=str(net), STEER_SOCKET=tmp + "/no.sock")
    mac = b"10:bb:cc:dd:ee:ff"
    want = hashlib.pbkdf2_hmac("sha256", b"splify2-telemetry:" + mac,
                               b"splify2-telemetry-id/1", 600000, 16)
    for plugged in (False, True):
        if plugged:
            port = net / "eth0"
            port.mkdir()
            (port / "device").touch()
            (port / "address").write_bytes(mac + b"\n")
        for cmd in ([probe, "--dev-id"], [cli, "dev-id"]):
            assert json.loads(subprocess.check_output(cmd, env=env)) == {
                "tid": "sp-" + want.hex() if plugged else ""}
print("PASS: SHA-256 / PBKDF2 block boundaries without heap; synthetic dev-id at 600000 and no interface")
