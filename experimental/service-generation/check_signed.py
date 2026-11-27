"""Process/namespace test. Fault points are constructors, not wire commands."""
import concurrent.futures
import contextlib
import ctypes
import fcntl
from http.client import HTTPConnection
import io
import json
import os
from pathlib import Path
import shutil
import select
import signal
import socket
import struct
import subprocess as sp
import sys
import tarfile
import tempfile
import time
import uuid

import controller as gen
from signed import (DIRS, ELF, FEED, LAB, PROFILE, SLOT, History, Owner, Refusal,
                    boundary, call, sha)


def fixtures(first=False):
    assert os.getuid() == 0
    with tempfile.TemporaryDirectory() as private:
        tmp = Path(private)
        keys = [tmp/"publisher", tmp/"other"]
        for key in keys:
            sp.run(["./s2p", "keygen", "-o", key], check=True)
        (FEED/"publisher.pub").write_bytes(keys[0].with_suffix(".pub").read_bytes())
        ids = {}

        def save(name, data):
            digest = sha(data)
            (FEED/(digest+".s2p")).write_bytes(data)
            ids[name] = digest

        for name, key in zip(("A", "B", "foreign"), (keys[0], keys[0], keys[1])):
            meta = Path("pkg/plugin.json")
            m = json.loads(meta.read_bytes())
            if not first or name!="A":
                m["description"] = "Full UI fixture "+name
                meta.write_text(json.dumps(m))
            sp.run(["./s2p", "build", "pkg", "--arch", "x86_64", "--key", key.with_suffix(".sec"),
                    "-o", tmp], check=True)
            archive, = tmp.glob("*.s2p")
            save(name, archive.read_bytes())
            archive.unlink()
        # Valid original signature; one payload byte no longer matches MANIFEST.
        buf = io.BytesIO()
        with tarfile.open(FEED/(ids["A"]+".s2p")) as src, tarfile.open(fileobj=buf, mode="w:gz") as dst:
            for member in src:
                data = src.extractfile(member).read() if member.isfile() else b""
                if member.name == "assets/app.css":
                    data = bytes([data[0]^1])+data[1:]
                dst.addfile(member, io.BytesIO(data) if member.isfile() else None)
        save("tampered", buf.getvalue())
        if first:
            buf=io.BytesIO()
            with tarfile.open(FEED/(ids["A"]+".s2p")) as src, tarfile.open(fileobj=buf,mode="w:gz") as dst:
                for member in src:
                    data=src.extractfile(member).read() if member.isfile() else b""
                    if member.name=="MANIFEST.sig":
                        pos=data.index(b"\n")+24
                        data=data[:pos]+(b"A" if data[pos:pos+1]!=b"A" else b"B")+data[pos+1:]
                    dst.addfile(member,io.BytesIO(data) if member.isfile() else None)
            save("bad-signature",buf.getvalue())
            for case in ("wrong-mode","extra","wrong-host"):
                extra=Path("pkg/extra")
                css=Path("pkg/assets/app.css")
                if case=="extra":
                    extra.write_text("unexpected signed file")
                elif case=="wrong-mode":
                    css.chmod(0o755)
                else:
                    with Path("pkg",ELF).open("ab") as f:
                        f.write(b"not the approved ELF")
                sp.run(["./s2p","build","pkg","--arch","x86_64","--key",keys[0].with_suffix(".sec"),
                        "-o",tmp],check=True)
                archive,=tmp.glob("*.s2p")
                save(case,archive.read_bytes())
                archive.unlink()
                css.chmod(0o644)
                extra.unlink(missing_ok=True)
        (FEED/"fixtures.json").write_text(json.dumps(ids))


def denied(fn, *args):
    try:
        fn(*args)
    except (Refusal, OSError, ValueError) as e:
        return str(e)
    raise AssertionError(("unexpected success", args))


def eventually(fn):
    deadline = time.monotonic()+5
    while time.monotonic() < deadline:
        try:
            value = fn()
            if value:
                return value
        except ConnectionRefusedError:
            pass
        time.sleep(.02)
    raise AssertionError("timeout")


@contextlib.contextmanager
def server(p, cut=None):
    cmd = ([sys.executable, "-B", "check_signed.py", "owner", p, cut] if cut else
           [sys.executable, "-B", "signed.py", "--signed-full-prefix", p, "serve"])
    s = sp.Popen(cmd)
    try:
        def up():
            assert s.poll() is None
            return call(p, "status")["owner"] == s.pid
        eventually(up)
        yield s
    finally:
        s.kill()
        s.wait(timeout=3)


def stage(p, image):
    g = boundary(p)["nonce"]+":"+uuid.uuid4().hex
    return g, call(p, "stage", g, image)["binding"]


def observe(p, g, info):
    tree = p/SLOT
    def running():
        status = call(p, "status")
        pid = status["pid"]
        if pid and status["live"] == g and os.path.samefile(f"/proc/{pid}/exe", tree/ELF):
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            assert argv[:3] == [os.fsencode(tree/ELF), b"--assets", os.fsencode(tree/"assets")]
            return pid
    pid = eventually(running)
    assert gen.ident(tree) == info["inode"] and sha((tree/"MANIFEST").read_bytes()) == info["manifest"]
    return pid


def served_assets(p, pid, slot=SLOT):
    # Test ancestor only: ask the already identified child for its listening
    # address. No global socket/PID enumeration; a port is never identity.
    libc = ctypes.CDLL(None, use_errno=True)
    with contextlib.ExitStack() as stack:
        pidfd = os.pidfd_open(pid)
        stack.callback(os.close, pidfd)
        def listening():
            for entry in Path(f"/proc/{pid}/fd").iterdir():
                if not os.readlink(entry).startswith("socket:["):
                    continue
                fd = libc.syscall(438, pidfd, int(entry.name), 0)  # Linux x86_64 pidfd_getfd
                if fd < 0:
                    raise OSError(ctypes.get_errno(), "pidfd_getfd UI child")
                with socket.socket(fileno=fd) as listener:
                    if listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN):
                        return listener.getsockname()
        host, port = eventually(listening)
        assert host == "127.0.0.1"
    for name in ("app.css", "fonts/onest-cyrillic.woff2"):
        with contextlib.closing(HTTPConnection(host, port, timeout=2)) as conn:
            conn.request("GET", "/"+name)
            reply = conn.getresponse()
            assert reply.status == 200 and reply.read() == (p/slot/"assets"/name).read_bytes()


def hist(p):
    return History(p, boundary(p))


@contextlib.contextmanager
def queued_fence(p, g):
    """Send to the authenticated owner; leave its reply unread during reinstall."""
    t = boundary(p)
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as s:
        s.connect(gen.address(t))
        pid, uid, _ = struct.unpack("3i", s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        with (p/"owner.lock").open("rb") as f:
            owner = gen.LOCK.unpack(fcntl.fcntl(f,fcntl.F_GETLK,gen.LOCK.pack(fcntl.F_WRLCK,0,0,0,0)))
        assert uid == os.getuid() and owner == (fcntl.F_WRLCK,0,0,0,pid)
        q = [PROFILE,t["nonce"],gen.ID,[g],"fence",uuid.uuid4().hex]
        s.sendall(gen.enc(q))
        assert select.select([s], [], [], 3)[0]
        def read():
            reply = json.loads(s.recv(8192))
            assert reply["owner"] == pid and reply["request"] == q and reply["excluded"] is True
            return reply["receipt"]
        yield read


def stage_cuts(root, image):
    p = root/"cuts"
    gen.init(p, PROFILE, DIRS)
    g = boundary(p)["nonce"]+":"+uuid.uuid4().hex
    for cut in ("before-stage", "after-stage"):
        with server(p, cut) as dying:
            denied(call, p, "stage", g, image)
            assert dying.wait(timeout=3) == -signal.SIGKILL
        h = hist(p)
        assert h.preparing[0] == g and h.preparing[1]["archive"] == image and not h.bound
        assert (g in h.where) == (cut == "after-stage") and not list((p/"slot").iterdir())
    with server(p, "before-reply") as dying:
        info = call(p, "stage", g, image)["binding"]
        assert denied(call, p, "switch", None, g, None) == "fresh-owner-receipt-required"
        denied(call, p, "switch", None, g, call(p, "admit", g)["receipt"])
        assert dying.wait(timeout=3) == -signal.SIGKILL
    with server(p) as old:
        pid = observe(p, g, info)
        assert denied(call, p, "switch", None, g, None) == "stale-generation"
        fd = os.pidfd_open(pid)
        signal.pidfd_send_signal(fd, signal.SIGSTOP)
        eventually(lambda: "\nState:\tT" in Path(f"/proc/{pid}/status").read_text())
        old.kill()
        old.wait(timeout=3)
    with server(p, "before-detach") as dying:
        assert denied(call, p, "fence", g) == "previous-child-not-excluded"
        assert denied(call, p, "switch", g, None, None) == "fresh-owner-receipt-required"
        assert hist(p).pending is None and gen.ident(p/SLOT) == info["inode"]
        signal.pidfd_send_signal(fd, signal.SIGCONT)
        assert select.select([fd], [], [], 3)[0]
        os.close(fd)
        receipt = call(p, "fence", g)["receipt"]
        denied(call, p, "switch", g, None, receipt)
        assert dying.wait(timeout=3) == -signal.SIGKILL
    assert hist(p).pending == [g,None] and hist(p).where[g] == SLOT
    with server(p):
        assert denied(call, p, "switch", g, None, receipt) == "fresh-owner-receipt-required"
        call(p, "switch", g, None, call(p, "fence", g)["receipt"])


def main():
    assert os.getuid() == 65534 and os.getpid() == 1 and socket.if_nameindex() == [(1, "lo")]
    packages = json.loads((FEED/"fixtures.json").read_bytes())
    with tempfile.TemporaryDirectory(prefix="e4-lab-") as d:
        root = Path(d)
        stage_cuts(root, packages["A"])
        p, n = root/"subject", root/"neighbor"
        for path in (p, n):
            gen.init(path, PROFILE, DIRS)
            denied(gen.boundary, path)  # older profile cannot run its fixed host here
        data = root/"user-data"
        data.write_bytes(os.urandom(128))
        saved = (gen.ident(data), data.read_bytes())
        with server(n):
            ng, ni = stage(n, packages["A"])
            call(n, "switch", None, ng, call(n, "admit", ng)["receipt"])
            neighbor = observe(n, ng, ni), (n/"history").read_bytes()
            with server(p):
                invalid = boundary(p)["nonce"]+":"+uuid.uuid4().hex
                for name, why in (("foreign", "plugin.signed_unknown_key"), ("tampered", "plugin.file_mismatch")):
                    assert denied(call, p, "stage", invalid, packages[name]) == "verify: "+why
                    assert not (p/"history").read_bytes() and not list((p/"stage").iterdir())
                a, ai = stage(p, packages["A"])
                b, bi = stage(p, packages["B"])
                assert ai["manifest"] != bi["manifest"] and ai["payload"] != bi["payload"]
                assert not list((p/"slot").iterdir()) and hist(p).bound[a] == ai
                call(p, "switch", None, a, call(p, "admit", a)["receipt"])
                observe(p, a, ai)
                assert denied(call, p, "switch", a, b, None) == "fresh-owner-receipt-required"
            with server(p, "before-detach") as dying:
                observe(p, a, ai)  # restarted owner actually ran the installed bytes
                receipt = call(p, "fence", a)["receipt"]
                assert denied(call, n, "switch", a, None, receipt) == "stale-generation"
                denied(call, p, "switch", a, b, receipt)
                assert dying.wait(timeout=3) == -signal.SIGKILL
            assert hist(p).pending == [a,b] and hist(p).where[a] == SLOT
            denied(call, p, "fence", a)
            # Offline status cannot finish a pending intent. A missing sealed
            # tail is damage even when the old tree is still in its slot.
            cli = [sys.executable, "-B", "signed.py", "--signed-full-prefix", p, "inspect"]
            histfile = p/"history"
            saved_log = histfile.read_bytes()
            assert json.loads(sp.check_output(cli))["pending"] == [a,b]
            short = b"".join(saved_log.splitlines(keepends=True)[:-1])
            histfile.write_bytes(short)
            fail = sp.run(cli, capture_output=True)
            assert fail.returncode and b"recovery-blocked" in fail.stderr and histfile.read_bytes() == short
            assert gen.ident(p/SLOT) == ai["inode"]
            histfile.write_bytes(saved_log)
            for cut, location in (("after-detach", None), ("after-attach", b)):
                with server(p, cut) as dying:
                    assert denied(call, p, "switch", a, b, receipt) == "fresh-owner-receipt-required"
                    receipt = call(p, "fence", a)["receipt"]
                    assert denied(call, p, "switch", a, None, receipt) == "different-pending-intent"
                    denied(call, p, "switch", a, b, receipt)
                    assert dying.wait(timeout=3) == -signal.SIGKILL
                h = hist(p)
                assert h.pending == [a,b] and h.where[a] == Path("retired")/a[33:]
                assert (h.where[b] == SLOT) == bool(location)
            with server(p):
                assert call(p, "status")["pid"] is None
                ticket = call(p, "fence", a)["receipt"]
                with queued_fence(p, a) as late:
                    call(p, "switch", a, b, ticket)
                    pid = observe(p, b, bi)
                    served_assets(p, pid)
                    assert denied(call, p, "switch", a, None, late()) == "stale-generation"
                before = (p/"history").read_bytes()
                assert denied(call, p, "switch", a, None, receipt) == "stale-generation"
                assert denied(call, p, "fence", a) == "stale-generation"
                assert (p/"history").read_bytes() == before and observe(p, b, bi) == pid
                c, ci = stage(p, packages["B"])  # same name, version AND signed bytes
                assert ci["payload"] == bi["payload"] and ci["inode"] != bi["inode"]
                ticket = call(p, "fence", b)["receipt"]
                before = (p/"history").read_bytes()
                assert denied(call, p, "switch", b, "../neighbor/slot/full-ui", ticket) == "unknown-or-retired-target"
                moved = root/"saved-tree"
                (p/SLOT).rename(moved)
                shutil.copytree(moved, p/SLOT)
                assert denied(call, p, "switch", b, None, ticket) == "changed-tree"
                assert (p/"history").read_bytes() == before
                (p/SLOT).rename(root/"byte-identical-copy")
                moved.rename(p/SLOT)
                css = p/SLOT/"assets/app.css"
                original = css.read_bytes()
                css.write_bytes(original+b"x")
                assert denied(call, p, "switch", b, None, ticket) == "changed-tree"
                assert (p/"history").read_bytes() == before and css.read_bytes() == original+b"x"
                css.write_bytes(original)
                extra = p/SLOT/"extra"
                extra.symlink_to(n/SLOT)
                assert denied(call, p, "switch", b, None, ticket) == "unexpected-tree-entry"
                assert (p/"history").read_bytes() == before and extra.is_symlink()
                extra.unlink()
                # A delayed receipt races a same-name reinstall. Both have the
                # same prior generation; at most one operation can commit.
                def compete(target):
                    try:
                        return call(p, "switch", b, target, ticket)
                    except Refusal as e:
                        return str(e)
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    results = list(pool.map(compete, (None, c)))
                assert sum(isinstance(x,dict) for x in results) == 1, results
                if not hist(p).live:
                    assert denied(call, p, "switch", b, c, ticket) == "fresh-owner-receipt-required"
                    call(p, "switch", b, c, call(p, "fence", b)["receipt"])
                observe(p, c, ci)
                assert denied(call, p, "switch", b, None, ticket) == "stale-generation"
                last = call(p, "fence", c)["receipt"]
                call(p, "switch", c, None, last)
                assert not list((p/"slot").iterdir()) and hist(p).retired == {a,b,c}
            assert (observe(n,ng,ni), (n/"history").read_bytes()) == neighbor
            assert (gen.ident(data),data.read_bytes()) == saved
            call(n, "switch", ng, None, call(n, "fence", ng)["receipt"])
        print(json.dumps({"result":"PASS", "A":ai, "B":bi, "cuts":["before-stage","after-stage",
                          "before-detach","after-detach","after-attach","before-reply"],
                          "race":[x if isinstance(x,str) else "commit" for x in results],
                          "unchanged_neighbor":neighbor[0]}))


if __name__ == "__main__":
    if sys.argv[1:] in (["fixtures"],["first-fixtures"]):
        fixtures(sys.argv[1]=="first-fixtures")
    elif sys.argv[1:2] == ["owner"]:
        def cut(point):
            if point == sys.argv[3]:
                os.kill(os.getpid(), signal.SIGKILL)
        Owner(Path(sys.argv[2]), cut).serve()
    else:
        main()
