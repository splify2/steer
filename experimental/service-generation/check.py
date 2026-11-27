"""Process cuts in one disposable network/PID/mount namespace. No port probes."""
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess as sp
import sys
import tempfile
import time
import uuid

from controller import (ATTR, HOST, Ledger, Refusal, Supervisor, address, boundary, init, request)


def token(p):
    return boundary(p)["nonce"]+":"+uuid.uuid4().hex


def log(case,**kw):
    print(json.dumps(dict(case=case,**kw)))


def history(p):
    return (p/"history").read_bytes(),os.getxattr(p/"history",ATTR)


def ledger(p):
    return Ledger(p,boundary(p))


def refused(fn,*args):
    try:
        fn(*args)
    except (ValueError,OSError,Refusal) as e:
        return str(e)
    raise AssertionError("unexpected success")


def eventually(fn):
    end = time.monotonic()+4
    while time.monotonic() < end:
        try:
            value = fn()
            if value:
                return value
        except (ConnectionRefusedError,FileNotFoundError):
            pass
        time.sleep(.01)
    raise AssertionError("timeout: "+repr(fn))


@contextlib.contextmanager
def owner(p,cut=None):
    # Fault injection is only in this test constructor, never a wire operation.
    cmd = ([sys.executable,"-B","check.py","owner",p,cut] if cut else
           [sys.executable,"-B","controller.py","--service-generation-prefix",p,"serve"])
    s = sp.Popen(cmd)
    try:
        g = token(p)
        def bound():
            assert s.poll() is None
            reply = request(p,"status",g)
            return reply["owner"] == s.pid
        eventually(bound)
        yield s
    finally:
        if s.poll() is None:
            s.kill()
        s.wait(timeout=3)


def live(p,g):
    # Named by our authenticated peer. Check the executable, not just its PID.
    def running():
        pid = request(p,"status",g)["pid"]
        return pid if pid and os.path.samefile(f"/proc/{pid}/exe",HOST) else None
    return eventually(running)


def gone(fd):
    poll = select.poll()
    poll.register(fd,select.POLLIN)
    return bool(poll.poll(3000))


def test_cuts(parent):
    for cut in ("before-reserve","tail-reserve","after-reserve","before-publish","tail-publish","after-publish",
                "tail-fence","after-fence"):
        p = parent/cut
        init(p)
        g = token(p)
        phase = cut.split("-")[1]
        with owner(p,cut) as s:
            if phase != "reserve":
                assert request(p,"reserve",g)["pid"] is None
            if phase == "fence":
                request(p,"publish",g)
                live(p,g)
            refused(request,p,phase,g)
            assert s.wait(timeout=3) == -signal.SIGKILL
        h = ledger(p)
        expected = ("absent" if cut == "before-reserve" else "reserve" if phase == "reserve" or
                    cut == "before-publish" else phase)
        assert h.rows.get(g,"absent") == expected
        journal = history(p)
        refused(request,p,"fence",g)
        assert history(p) == journal
        with owner(p):
            h = ledger(p)
            assert h.seal == h.head
            if expected == "absent":
                refused(request,p,"fence",g)
                refused(request,p,"publish",g)
                assert history(p) == journal
                request(p,"reserve",g)
            if expected == "reserve":
                assert request(p,"reserve",g)["phase"] == "reserve"
            if expected == "publish":
                assert request(p,"publish",g)["phase"] == "publish"
                live(p,g)
            # After a parent death the pipe/lease may still be draining.
            def closed():
                try:
                    return request(p,"fence",g)["excluded"]
                except Refusal as e:
                    if str(e) != "previous-child-not-excluded":
                        raise
            eventually(closed)
            assert ledger(p).rows == {g:"fence"}
            assert refused(request,p,"publish",g) == "irrevocably-fenced"
        log(cut,at_cut=expected,final="fence")


def restart(a,b):
    g,n = token(a),token(b)
    with owner(b):
        request(b,"reserve",n)
        request(b,"publish",n)
        other = live(b,n)
        neighbor = history(b)
        with owner(a) as s:
            request(a,"reserve",g)
            snap = history(a)
            duplicate = sp.run([sys.executable,"-B","controller.py","--service-generation-prefix",a,"serve"],
                               capture_output=True,timeout=2)
            assert duplicate.returncode and history(a) == snap
            first = request(a,"publish",g)
            pid = live(a,g)
            assert first["pid"] == pid and ledger(a).rows == {g:"publish"}
            # Positive restart control: this owner actually respawns an unfenced child.
            fd = os.pidfd_open(pid)
            signal.pidfd_send_signal(fd,signal.SIGKILL)
            assert gone(fd)
            os.close(fd)
            pid = live(a,g)
            assert pid != first["pid"]
            fd = os.pidfd_open(pid)
            signal.pidfd_send_signal(fd,signal.SIGSTOP)
            eventually(lambda: "\nState:\tT" in Path(f"/proc/{pid}/status").read_text())
            s.kill()
            s.wait(timeout=3)
        snapshot = history(a)
        assert refused(request,b,"fence",g) == "wrong-prefix-generation"
        assert refused(request,a,"fence",g,address(boundary(b))) == "foreign-owner"
        refused(request,a,"fence",g)
        # Same uid, exact endpoint, no lock ownership. No request bytes disclosed.
        with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as stranger:
            stranger.bind(address(boundary(a)))
            stranger.listen(1)
            assert refused(request,a,"fence",g) == "foreign-owner"
            c,_ = stranger.accept()
            with c:
                assert not c.recv(1024)
        assert history(a) == snapshot and history(b) == neighbor
        with owner(a) as replacement:
            # Its local child table is empty but the old UI still holds the lease.
            assert refused(request,a,"fence",g) == "previous-child-not-excluded"
            assert ledger(a).rows == {g:"fence"}
            assert refused(request,a,"reserve",token(a)) == "previous-child-not-excluded"
            signal.pidfd_send_signal(fd,signal.SIGCONT)
            assert gone(fd)
            os.close(fd)
            proof = request(a,"fence",g)
            assert proof["excluded"] and proof["owner"] == replacement.pid
        with owner(a):
            assert request(a,"status",g)["pid"] is None
            assert request(a,"fence",g)["head"] == proof["head"]
            assert refused(request,a,"publish",g) == "irrevocably-fenced"
            later = token(a)
            request(a,"reserve",later)
            request(a,"publish",later)
            live(a,later)
            snap = history(a)
            refused(request,a,"fence",g)  # stale request cannot stop a later incarnation
            assert request(a,"status",g)["phase"] == "fence"
            assert history(a) == snap
            assert request(a,"fence",later)["excluded"]
            assert ledger(a).rows == {g:"fence",later:"fence"}
        assert live(b,n) == other and history(b) == neighbor
        assert request(b,"fence",n)["excluded"]
        log("restart",old_child=pid,receipt_owner=proof["owner"],unchanged_neighbor=other,
            refused_while_old_child_stopped=True,retained=2)


def damage(parent):
    p = parent/"damage"
    init(p)
    g = token(p)
    with owner(p):
        request(p,"reserve",g)
        request(p,"fence",g)
        good,seal = history(p)
        for data in (good.splitlines(keepends=True)[0],good[:-1],good.replace(b"reserve",b"publish")):
            (p/"history").write_bytes(data)
            why = refused(request,p,"fence",g)
            assert history(p) == (data,seal)
            log("damaged-history",refused=why)
        (p/"history").write_bytes(good)
        (p/"owner.lock").rename(parent/"saved")
        (p/"owner.lock").touch(mode=0o600)
        refused(request,p,"reserve",g)
        assert history(p) == (good,seal)
        (p/"owner.lock").unlink()
        (parent/"saved").rename(p/"owner.lock")
        assert request(p,"fence",g)["excluded"]
    # Missing evidence is not equivalent to an empty history, even on cold start.
    (p/"history").unlink()
    s = sp.run([sys.executable,"-B","controller.py","--service-generation-prefix",p,"serve"],capture_output=True,timeout=2)
    assert s.returncode != 0 and not (p/"history").exists()
    log("damaged-layout",no_reinit=True)


def main():
    assert os.getuid() == 65534 and os.getpid() == 1 and socket.if_nameindex() == [(1,"lo")]
    with tempfile.TemporaryDirectory(prefix="e4-lab-") as d:
        root = Path(d)
        a,b = root/"subject",root/"neighbor"
        for p in (a,b):
            init(p)
            refused(init,p)
        f = root/"files"
        def pm(p,act):
            return sp.run(["/run/e4/steerd","--managed-prefix",p,"plugin",act,"--json"],capture_output=True,timeout=3)
        assert pm(f,"init").returncode == 0
        refused(init,f)
        refused(request,f,"reserve",token(a))
        assert pm(f,"list").returncode == 0 and pm(a,"list").returncode != 0
        legacy = root/"legacy"
        legacy.mkdir(mode=0o700)
        (legacy/"state.json").write_text("legacy sentinel")
        refused(init,legacy)
        assert list(legacy.iterdir()) == [legacy/"state.json"]
        assert not (a/"installed").exists() and not (f/"history").exists()
        log("separate-prefix",managed_offline=True)
        test_cuts(root)
        restart(a,b)
        damage(root)
    log("service-generation",result="PASS")


if __name__ == "__main__":
    if sys.argv[1:2] == ["owner"]:
        def crash(point):
            if point == sys.argv[3]:
                os.kill(os.getpid(),signal.SIGKILL)
        Supervisor(Path(sys.argv[2]),crash).serve()
    else:
        main()
