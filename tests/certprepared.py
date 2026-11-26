#!/usr/bin/env python3
"""Prepared trust snapshot with actual crypto; fixture keys never logged."""
import argparse
import hashlib
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
cc = shlex.split(os.environ.get("CC", "cc"))
base = ["-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-UNDEBUG", "-Isrc/lib", "-Isrc/proto/tls"]
san = (["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if args.sanitizer == "address"
       else ["-fsanitize=thread", "-fno-omit-frame-pointer"] if args.sanitizer == "thread" else [])


def run(command, **kwargs):
    return subprocess.run(command, cwd=root, check=True, timeout=60, **kwargs)


with tempfile.TemporaryDirectory(prefix="steer-cert-prepared-") as directory:
    work = Path(directory)
    def openssl(*command):
        run(["openssl", *map(str, command)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    for name in ("root", "wrong"):
        openssl("req", "-new", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-sha256", "-days", "1", "-subj", "/CN=" + name,
                "-addext", "basicConstraints=critical,CA:TRUE",
                "-keyout", work / (name + ".key"), "-out", work / (name + ".pem"))
    openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-sha256", "-subj", "/CN=tls.example", "-keyout", work / "leaf.key",
            "-out", work / "leaf.csr")
    (work / "leaf.ext").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:tls.example\n")
    openssl("x509", "-req", "-in", work / "leaf.csr", "-CA", work / "root.pem",
            "-CAkey", work / "root.key", "-CAcreateserial", "-days", "1", "-sha256",
            "-extfile", work / "leaf.ext", "-out", work / "leaf.pem")
    openssl("x509", "-in", work / "leaf.pem", "-outform", "DER", "-out", work / "leaf.der")
    (work / "database").write_text("")
    (work / "serial").write_text("01\n")
    (work / "ca.cnf").write_text("[ca]\ndefault_ca=issuer\n[issuer]\ndatabase=" + str(work / "database") +
        "\nserial=" + str(work / "serial") + "\nnew_certs_dir=" + str(work) +
        "\ndefault_md=sha256\npolicy=names\n[names]\ncommonName=supplied\n[server]\n" + (work / "leaf.ext").read_text())
    openssl("ca", "-batch", "-config", work / "ca.cnf", "-cert", work / "root.pem",
            "-keyfile", work / "root.key", "-in", work / "leaf.csr", "-startdate", "20200101000000Z",
            "-enddate", "20200102000000Z", "-extensions", "server", "-out", work / "expired.pem")
    openssl("x509", "-in", work / "expired.pem", "-outform", "DER", "-out", work / "expired.der")
    (work / "content").write_bytes(b" " * 64 + b"TLS 1.3, server CertificateVerify\0" + hashlib.sha256(b"transcript").digest())
    openssl("dgst", "-sha256", "-sign", work / "leaf.key", "-out", work / "verify.sig", work / "content")
    run(cc + base + san + flags + ["-Wno-switch", "-c", "src/lib/scrypto.c", "-o", str(work / "crypto.o")])
    run(cc + base + san + ["tests/certpreparedmatch.c", "src/proto/tls/certverify.c", str(work / "crypto.o"),
                         str(library), "-Wl,-wrap,fopen", "-pthread", "-lm", "-o", str(work / "test")])
    env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1", UBSAN_OPTIONS="halt_on_error=1", TSAN_OPTIONS="halt_on_error=1")
    run([str(work / "test"), str(work / "root.pem"), str(work / "wrong.pem"),
         str(work / "leaf.der"), str(work / "verify.sig"), str(work / "expired.der")], env=env)
