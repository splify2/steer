#!/usr/bin/env python3
"""Build the legacy real-TLS interop probe with explicit lab dependency flags."""
import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--wolfssl-library", required=True)
parser.add_argument("--output", required=True)
parser.add_argument("--sanitize", action="store_true")
parser.add_argument("--thread-sanitize", action="store_true")
parser.add_argument("--vless-fixture", action="store_true", help="legacy TLS/REALITY lifecycle fixture with real server signing")
args = parser.parse_args()
if args.sanitize and args.thread_sanitize:
    parser.error("choose one sanitizer")
library = Path(args.wolfssl_library).resolve()
flags = shlex.split(Path(str(library) + ".cflags").read_text())
cc = shlex.split(os.environ.get("CC", "cc"))
extra_link = []
base = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections"]
includes = ["-I" + str(path) for path in (root / "src").rglob("*") if path.is_dir()]
san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if args.sanitize else ["-fsanitize=thread"] if args.thread_sanitize else []
sources = ["tests/transportprobe.c", *map(str, (root / "src/proto/transport").glob("*.c")),
           *["src/proto/tls/" + name + ".c" for name in ("tls13", "reality", "chello", "ech", "certverify", "h2", "roots")],
           *["src/platform/" + name + ".c" for name in ("platform", "openwrt", "android")], "src/profile/profile.c"]
output = Path(args.output).resolve()
output.parent.mkdir(parents=True, exist_ok=True)
if args.vless_fixture:
    if "-DWOLFSSL_CERT_GEN" not in flags:
        parser.error("vless fixture requires an archive built with WOLFSSL_CERT_GEN")
    sources = [source for source in sources if Path(source).name not in ("transportprobe.c", "trdial.c", "roots.c")]
    sources += ["tests/vlessmatch.c", *["src/proto/vless/" + name + ".c" for name in ("client", "vless_proto", "vision")]]
    sources = list(dict.fromkeys(sources))
    base += ["-DSTEER_HAVE_X509WRITE", "-DHAVE_CONFIG_H"]
with tempfile.TemporaryDirectory(prefix="steer-transport-build-") as directory:
    crypto = str(Path(directory) / "crypto.o")
    subprocess.run(cc + base + san + includes + flags + ["-Wno-switch", "-c", "src/lib/scrypto.c", "-o", crypto],
                   cwd=root, check=True, timeout=90)
    objects = [crypto]
    if args.vless_fixture:
        certgen = str(Path(directory) / "certgen.o")
        subprocess.run(cc + base + san + includes + flags + ["-c", "tests/certgen.c", "-o", certgen], cwd=root, check=True, timeout=90)
        objects.append(certgen)
    subprocess.run(cc + base + san + includes + sources + objects + [str(library), *extra_link, "-Wl,--gc-sections", "-pthread", "-lm", "-ldl", "-o", str(output)],
                   cwd=root, check=True, timeout=180)
