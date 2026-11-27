"""Provision once and verify supd replies. No fork of a service, no remove."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import socket
import stat
import struct
import tempfile
import uuid

from controller import LOCK, TOKEN, Refusal, mount, parent, require, sha, syncdir
from signed import ELF, LAB, move, verify


TYPE = "supd-full/1"
BIND = "user.steer.supd1.binding"
PHASE = "user.steer.supd1.phase"
ORDER = (".", "owner.lock", "child.lock", "history", "type", "tree", "tree/bin", "tree/assets",
         "tree/assets/fonts", "tree/licenses", "tree/LICENSE", "tree/MANIFEST", "tree/MANIFEST.sig",
         "tree/plugin.json", "tree/"+ELF, "tree/licenses/libyaml.txt", "tree/assets/index.html",
         "tree/assets/app.css", "tree/assets/app.js", "tree/assets/config-model.js",
         "tree/assets/fonts/Onest-OFL.txt", "tree/assets/fonts/onest-cyrillic.woff2",
         "tree/assets/fonts/onest-latin.woff2")


def inventory(p):
    lines = []
    base = mount(p.parent)
    for name in ORDER:
        f = p/name
        s = f.lstat()
        require(s.st_uid == os.getuid() and mount(f) == base, "foreign-object")
        digest = "-"
        children = {Path(n).name for n in ORDER if n != "." and str(Path(n).parent) == name}
        if children:
            require(stat.S_ISDIR(s.st_mode) and not s.st_mode & 0o7022 and set(os.listdir(f)) == children,
                    "changed-directory")
        else:
            require(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "changed-file")
            if name not in ("owner.lock", "child.lock", "history"):
                require(s.st_size <= 8 << 20)
                digest = sha(f.read_bytes())
        lines.append(f"{name} {s.st_dev} {s.st_ino} {s.st_mode:o} {digest}\n")
    return "".join(lines).encode()


def init(p, archive):
    require(os.geteuid()==os.getuid() and os.getegid()==os.getgid(), "unprivileged-domain-required")
    parent(p)
    require(not os.path.lexists(p) and len(os.fsencode(p)) <= 80, "new-private-domain-required")
    g = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(dir=p.parent, prefix=".prepare-") as scratch:
        tmp = Path(scratch)/"new"
        tmp.mkdir(mode=0o700)
        (tmp/"stage").mkdir(mode=0o700)
        info = {}
        verify(tmp, "0"*32+":"+g, archive, info.update)
        require(info["version"] == "0.0.0")
        move(tmp/"stage"/g, tmp/"tree")
        (tmp/"stage").rmdir()
        for name in ("owner.lock", "child.lock", "type", "history"):
            (tmp/name).touch(mode=0o600)
        (tmp/"type").write_text(f"{TYPE}\n{p}\n{g}\n{archive}\n{info['key']}\n")
        (tmp/"history").write_text(f"start {g}\n")
        os.setxattr(tmp/"history", PHASE, b"A", os.XATTR_CREATE)
        os.setxattr(tmp, BIND, inventory(tmp), os.XATTR_CREATE)
        for name in ("owner.lock", "child.lock", "type", "history"):
            with (tmp/name).open("rb") as f:
                os.fsync(f.fileno())
        syncdir(tmp)
        move(tmp, p)
    return g


def request(p, op, g, ticket="-", endpoint=None):
    parent(p)
    require(TOKEN.fullmatch(g) and op in ("status", "fence", "check") and
            (ticket == "-" or TOKEN.fullmatch(ticket)), "invalid-command")
    bind = os.getxattr(p, BIND)
    require(bind == inventory(p), "changed-binding")
    rows = (p/"type").read_text().splitlines()
    require(len(rows)==5 and rows[:3]==[TYPE,str(p),g], "wrong-domain")
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(3)
        s.connect(endpoint or "\0steer-supd1-"+g)
        pid,uid,_ = struct.unpack("3i",s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        with (p/"owner.lock").open("rb") as lock:
            result = fcntl.fcntl(lock,fcntl.F_GETLK,LOCK.pack(fcntl.F_WRLCK,0,0,0,0))
        require(uid == os.getuid() and pid > 0 and LOCK.unpack(result) == (fcntl.F_WRLCK,0,0,0,pid)
                and any(exe.is_file() and os.path.samefile(f"/proc/{pid}/exe",exe)
                        for exe in (LAB/"steerd", LAB/"steerd-compatible")), "foreign-owner")
        challenge = uuid.uuid4().hex
        s.sendall(f"{op} {g} {challenge} {ticket}".encode())
        reply = s.recv(512).decode().split()
        require(len(reply)==8 and reply[:4]==[TYPE,op,g,challenge] and reply[6]==str(pid), "unconfirmed")
        result, proof = reply[4:6]
        if result not in ("active","fenced","excluded","pending"):
            raise Refusal(result)
        if op != "status":
            require(result=="excluded" and TOKEN.fullmatch(proof) and reply[7]=="0" and
                    (op=="fence" or ticket==proof), result if result=="pending" else "unconfirmed")
            require(os.getxattr(p,BIND)==bind==inventory(p) and os.getxattr(p/"history",PHASE)==b"F" and
                    (p/"history").read_text()==f"start {g}\nfence {g}\n", "unsealed")
        return dict(state=result, generation=g, receipt=proof, owner=pid, child=int(reply[7]))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--supd-full-prefix",required=True,type=Path)
    parser.add_argument("op",choices=("init","status","fence","check"))
    parser.add_argument("identity",help="archive digest for init; exact generation otherwise")
    parser.add_argument("receipt",nargs="?",default="-")
    a = parser.parse_args()
    try:
        p = a.supd_full_prefix
        print(json.dumps(init(p,a.identity) if a.op=="init" else request(p,a.op,a.identity,a.receipt)))
    except (OSError,ValueError,Refusal) as e:
        raise SystemExit("supd-full refused: "+str(e))
