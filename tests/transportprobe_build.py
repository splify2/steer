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
parser.add_argument("--engine-probe", action="store_true", help="source-only incremental TLS engine, prepared trust and no transport FD access")
parser.add_argument("--origin-probe", action="store_true", help="source-only VLESS/TLS/native origin composition with shared verification worker")
args = parser.parse_args()
if sum((args.engine_probe,args.origin_probe,args.vless_fixture)) > 1:
    parser.error("choose one fixture")
if args.sanitize and args.thread_sanitize:
    parser.error("choose one sanitizer")
library = Path(args.wolfssl_library).resolve()
flags = shlex.split(Path(str(library) + ".cflags").read_text())
if (args.engine_probe or args.origin_probe) and os.name == "posix" and "-DSTEER_WOLFSSL_POSIX_TIME_SAFE=1" not in flags:
    parser.error("prepared parallel TLS requires the recipe-built POSIX time-safe backend profile")
cc = shlex.split(os.environ.get("CC", "cc"))
extra_link = []
base = ["-std=c11", "-D_POSIX_C_SOURCE=200809L", "-O1", "-g", "-Wall", "-Wextra", "-Werror", "-ffunction-sections", "-fdata-sections"]
includes = ["-I" + str(path) for path in (root / "src").rglob("*") if path.is_dir()]
san = ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"] if args.sanitize else ["-fsanitize=thread"] if args.thread_sanitize else []
sources = ["tests/transportprobe.c", *map(str, (root / "src/proto/transport").glob("*.c")),
           *["src/proto/tls/" + name + ".c" for name in ("tls13", "reality", "chello", "ech", "certverify", "h2", "roots")],
           *["src/platform/" + name + ".c" for name in ("platform", "capabilities", "openwrt", "android")], "src/profile/profile.c"]
output = Path(args.output).resolve()
if args.engine_probe:
    sources[0] = "tests/tls13engineprobe.c"
if args.origin_probe:
    sources = [source for source in sources if "src/proto/transport/" not in source and source != "tests/transportprobe.c"]
    sources += ["experimental/provider/tls_stream_backend_probe.c", *["experimental/provider/" + name + ".c" for name in
        ("tls_stream_backend","vless_stream_backend","native_stream_backend","route_stream","stream_backend",
         "stream","buffers","operations","binding_lease","flow_metadata","route_dial","resolver","host_worker")],
        "experimental/provider/tls_stream_faults.c", "src/daemon/loop.c", "../steer-protocols/src/vless/outbound.c"]
    includes += ["-Iexperimental/provider", "-I../plugin-sdk/include", "-I../steer-protocols/src"]
    extra_link += ["-Wl,--wrap=" + name for name in ("steer_draft_host_worker_submit", "steer_draft_host_job_release",
        "steer_draft_operations_create", "steer_draft_operation_start", "steer_draft_operation_resolve", "cert_verify_server_prepared")]
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
