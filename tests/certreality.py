#!/usr/bin/env python3
"""Actual REALITY CertificateVerify signatures with the fixture-only profile."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--wolfssl-library", required=True)
parser.add_argument("--sanitizer", choices=("address", "thread"))
args = parser.parse_args()
library = Path(args.wolfssl_library).resolve()
flags = shlex.split(Path(str(library) + ".cflags").read_text())
if "-DWOLFSSL_CERT_GEN" not in flags:
    parser.error("requires an archive built with fixture-only WOLFSSL_CERT_GEN")
cc = shlex.split(os.environ.get("CC", "cc"))
base = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-Isrc/lib", "-Isrc/proto/tls", "-Itests"]
san = (["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if args.sanitizer == "address"
       else ["-fsanitize=thread", "-fno-omit-frame-pointer"] if args.sanitizer == "thread" else [])
def run(command, **kwargs):
    return subprocess.run(command, cwd=root, check=True, timeout=90, **kwargs)
with tempfile.TemporaryDirectory(prefix="steer-reality-cv-") as directory:
    work = Path(directory)
    run(cc + base + san + flags + ["-Wno-switch", "-c", "src/lib/scrypto.c", "-o", str(work / "crypto.o")])
    run(cc + base + san + flags + ["-c", "tests/certgen.c", "-o", str(work / "certgen.o")])
    run(cc + base + san + ["tests/certrealitymatch.c", "src/proto/tls/certverify.c", str(work / "crypto.o"),
        str(work / "certgen.o"), str(library), "-pthread", "-lm", "-o", str(work / "test")])
    run([str(work / "test")], env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1",
                                     UBSAN_OPTIONS="halt_on_error=1", TSAN_OPTIONS="halt_on_error=1"))
