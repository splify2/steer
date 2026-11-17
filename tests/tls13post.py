#!/usr/bin/env python3
"""Real-crypto TLS record regressions using an explicitly supplied lab backend."""
import argparse
import os
import pathlib
import shlex
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
p = argparse.ArgumentParser()
p.add_argument("--wolfssl-library", required=True)
p.add_argument("--sanitize", action="store_true")
p.add_argument("--baseline", default="05742cc0f87a00f84dd43bd441cdcaa1fd10151c")
a = p.parse_args()
lib = pathlib.Path(a.wolfssl_library).resolve()
flags = shlex.split(pathlib.Path(str(lib) + ".cflags").read_text())
cc = shlex.split(os.environ.get("CC", "cc"))
includes = ["-Isrc/lib", "-Isrc/proto/tls", "-Isrc/proto/vless"]
base = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections"]
san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if a.sanitize else []
def run(args, **kw):
    subprocess.run(args, cwd=root, check=True, timeout=90, **kw)
with tempfile.TemporaryDirectory(prefix="steer-tls-post-") as path:
    work = pathlib.Path(path)
    run(cc + base + san + includes + ["tests/tls13offermatch.c", "-o", str(work / "offers")])
    run([str(work / "offers")], env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1"))
    crypto = str(work / "crypto.o")
    run(cc + base + san + includes + flags + ["-Wno-switch", "-c", "src/lib/scrypto.c", "-o", crypto])
    run(cc + base + san + includes + ["-DSTEER_TLS13_TEST", "-Wl,--wrap=write", "-Wl,--wrap=send", "-Wl,--wrap=realloc", "tests/tls13postmatch.c", "src/proto/tls/tls13.c", "src/proto/tls/certverify.c", "src/proto/vless/vision.c", crypto, str(lib), "-Wl,--gc-sections", "-pthread", "-lm", "-o", str(work / "records")])
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1")
    run([str(work / "records")], env=env)
    # Old header is fixed independently of the working tree or later commits.
    old = subprocess.check_output(["git", "show", a.baseline + ":src/proto/tls/tls13.h"], cwd=root)
    (work / "tls13.h").write_bytes(old)
    # Existing lab wolfSSL archive is non-PIC; the consumer exports the real
    # crypto backend, while the new TLS DSO resolves those symbols at load time.
    run(cc + base + san + includes + ["-fPIC", "-shared", "-DSTEER_TLS13_TEST", "src/proto/tls/tls13.c", "-o", str(work / "libtlsnew.so")])
    run(cc + base + san + ["-I" + path, "-Isrc/lib", "tests/tls13oldconsumer.c", crypto, str(lib), "-rdynamic", "-L" + path, "-ltlsnew", "-Wl,-rpath," + path, "-Wl,--unresolved-symbols=ignore-in-shared-libs", "-pthread", "-lm", "-o", str(work / "old")])
    run([str(work / "old")], env=env)
