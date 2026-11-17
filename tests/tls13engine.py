#!/usr/bin/env python3
"""Source-only engine ownership/fragmentation gate, no production runtime claim."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--wolfssl-library", required=True)
p.add_argument("--sanitizer", choices=("address", "thread"))
a = p.parse_args()
library = Path(a.wolfssl_library).resolve()
flags = shlex.split(Path(str(library) + ".cflags").read_text())
cc = shlex.split(os.environ.get("CC", "cc"))
base = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-pedantic", "-ffunction-sections", "-fdata-sections", "-Isrc/lib", "-Isrc/proto/tls"]
san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if a.sanitizer == "address" else ["-fsanitize=thread"] if a.sanitizer else []
with tempfile.TemporaryDirectory(prefix="steer-tls-engine-") as work:
    crypto = str(Path(work) / "crypto.o")
    subprocess.run(cc + base + san + flags + ["-Wno-switch", "-c", "src/lib/scrypto.c", "-o", crypto],
                   cwd=root, check=True, timeout=90)
    binary = str(Path(work) / "engine")
    subprocess.run(cc + base + san + ["tests/tls13engineinitmatch.c", "src/proto/tls/tls13.c",
        "src/proto/tls/certverify.c", crypto, str(library), "-Wl,--gc-sections", "-Wl,--wrap=sc_hash_init",
        "-Wl,--wrap=sc_hash_update", "-Wl,--wrap=sc_hash_clone", "-pthread", "-lm", "-o", binary],
        cwd=root, check=True, timeout=90)
    subprocess.run([binary], cwd=root, check=True, timeout=60,
        env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1",
                 TSAN_OPTIONS="halt_on_error=1"))
