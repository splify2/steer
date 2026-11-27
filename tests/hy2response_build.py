#!/usr/bin/env python3
"""Exercise the real legacy Hysteria2 response callback with explicit dependencies."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--wolfssl-library", required=True)
p.add_argument("--ngtcp2-library", required=True)
p.add_argument("--sanitize", action="store_true")
a = p.parse_args()
libraries = [Path(a.ngtcp2_library).resolve(), Path(a.wolfssl_library).resolve()]
flags = []
for library in libraries:
    flags += shlex.split(Path(str(library) + ".cflags").read_text())
includes = ["-I" + str(path) for path in (root / "src").rglob("*") if path.is_dir()]
cc = shlex.split(os.environ.get("CC", "cc"))
checks = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if a.sanitize else []
with tempfile.TemporaryDirectory(prefix="steer-hy2-response-") as directory:
    binary = str(Path(directory) / "response")
    command = cc + ["-O1", "-g", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections",
        "-DSTEER_HY2_RESPONSE_TEST"] + checks + includes + flags + ["tests/hy2respmatch.c",
        "src/proto/hysteria2/hy2conn.c", "src/proto/hysteria2/hy2wire.c", "src/proto/quic/quic.c",
        "src/proto/quic/qcssl.c"] + list(map(str, libraries)) + ["-Wl,--gc-sections", "-pthread", "-lm", "-o", binary]
    subprocess.run(command, cwd=root, check=True, timeout=180)
    subprocess.run([binary], cwd=root, check=True, timeout=90)
