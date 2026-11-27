#!/usr/bin/env python3
"""Compare every legacy TLS field offset against the pinned pre-fix ABI."""
import argparse
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument("--baseline", default="v2.1.4", help="explicit old-header commit")
args = parser.parse_args()
fields = "fd ready live oq v12 rbuf rbuf_n rbuf_off alpn rd wr rd_seq wr_seq tr tr384 hash_n".split()
layouts={"tls13":fields,
 "tr_link":"fd plain rx_direct nopq live oq tls".split(),
 "transport":"link fr h2 de xh h1 enc".split(),
 "h2":"io started status done old_status frame_peeked pend pend_n frame_left frame_type frame_flags frame_ours frame_sid pend_err goaway why pad_wait pad_left skip_left ctl ctl_n recv_credit recv_credit_conn send_win send_win_conn peer_init_win sid open_sid open_n browser".split()}
with tempfile.TemporaryDirectory(prefix="steer-tls-abi-") as td:
    td = pathlib.Path(td)
    for path in ("src/proto/tls/tls13.h","src/proto/tls/h2.h","src/proto/transport/transport.h"):
        old = subprocess.check_output(["git", "show", args.baseline + ":" + path], cwd=root)
        (td / pathlib.Path(path).name).write_bytes(old)
    results = []
    for header in (td / "transport.h", root / "src/proto/transport/transport.h"):
        source = '#include <stdio.h>\n#include <stddef.h>\n#include "' + str(header) + '"\nint main(void){\n'
        for struct,members in layouts.items():
            source += 'printf("'+struct+' %zu %zu", sizeof(struct '+struct+'), _Alignof(struct '+struct+'));\n'
            source += ''.join('printf(" %zu",offsetof(struct '+struct+',' + f + '));\n' for f in members)
            source += 'puts("");\n'
        source += 'puts("");return 0;}\n'
        (td / "probe.c").write_text(source)
        subprocess.run(["cc", "-std=c11", "-Werror", "-I" + str(root / "src/lib"),"-I" + str(root / "src/proto/tls"), str(td / "probe.c"), "-o", str(td / "probe")], check=True)
        results.append(subprocess.check_output([td / "probe"]))
    assert results[0] == results[1], (results[0], results[1])
    print("TLS/H2/link/transport legacy sizeof/align/all offsets PASS:\n"+results[1].decode().strip())
