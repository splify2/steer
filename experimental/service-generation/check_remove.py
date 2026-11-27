"""All transactional commands (including recovery) run the real C manager."""
import concurrent.futures
import contextlib
import ctypes
import json
import os
from pathlib import Path
import select
import shutil
import signal
import socket
import subprocess as sp
import tempfile
import time
import uuid

from native_manager import init
from signed import ELF, FEED, LAB, sha


def token():
    return uuid.uuid4().hex


def provision(p, archive):
    g=init(p,archive,True)
    return g,sha(os.getxattr(p,"user.steer.supd2.binding"))


def run(p,op,g,b,t):
    return sp.run([LAB/"steerd","--supd-full-prefix",p,"plugin",op+"-exact",g,b,t],
                  capture_output=True,timeout=5)


def expect(p,op,g,b,t,state):
    r=run(p,op,g,b,t)
    code=1 if state=="refused" else 0 if state=="removed" else 3
    assert r.returncode==code,(op,state,r.returncode,r.stderr,r.stdout)
    if code!=1:
        assert json.loads(r.stdout)==dict(state=state,generation=g,binding=b,tx=t)
    else:
        assert not r.stdout


@contextlib.contextmanager
def unchanged(p):
    """Catch even transient directory writes and xattr changes."""
    libc=ctypes.CDLL(None,use_errno=True)
    fd=libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
    assert fd>=0
    try:
        for d in [p,*p.rglob("*")]:
            if d.is_dir() and not d.is_symlink():
                assert libc.inotify_add_watch(fd,os.fsencode(d),0xfce)>=0
        yield
        assert not select.select([fd],[],[],0)[0],"unexpected filesystem mutation"
    finally:
        os.close(fd)


def wait(fn):
    deadline=time.monotonic()+5
    while time.monotonic()<deadline:
        result=fn()
        if result:
            return result
        time.sleep(.02)
    raise AssertionError("timeout")


def daemon(p,exe):
    return [exe,"daemon","--supervise","--supd-full-prefix",p]


@contextlib.contextmanager
def owner(p,g,b,t,cut=None):
    env=os.environ.copy()
    if cut:
        env.update(LD_PRELOAD=str(LAB/"cut.so"),REMOVE_CUT=cut)
    proc=sp.Popen(daemon(p,LAB/"steerd"),env=env)
    try:
        def up():
            assert proc.poll() is None
            # Don't inspect a committed domain with a lost-reply cut armed.
            return run(p,"inspect",g,b,t).returncode in (0,3)
        wait(up)
        yield proc
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def live(p,proc):
    def child():
        ids=Path(f"/proc/{proc.pid}/task/{proc.pid}/children").read_text().split()
        return int(ids[0]) if len(ids)==1 and os.path.samefile(f"/proc/{ids[0]}/exe",p/"tree"/ELF) else 0
    return wait(child)


def finish(p,g,b,t):
    def replay():
        r=run(p,"recover",g,b,t)
        if r.returncode==3:
            assert json.loads(r.stdout)["state"]=="pending"
            return False
        assert r.returncode==0 and json.loads(r.stdout)==dict(state="removed",generation=g,binding=b,tx=t),r.stderr
        return True
    wait(replay)


def old_refusal(p,g):
    for version in ("prior","v214"):
        exe=LAB/version/"steerd"
        env=dict(os.environ,LD_LIBRARY_PATH=str(exe.parent),STEER_PLUGIN_DIR=str(p),STEER_PLUGINS_ROOT=str(p),
                 STEER_PLUGIN_ETC=str(p.parent/"old-etc"),STEER_PLUGINS_ETC=str(p.parent/"old-etc"))
        with unchanged(p):
            r=sp.run(daemon(p,exe),capture_output=True,env=env,timeout=2)
            assert r.returncode!=0
            r=sp.run([exe,"--supd-full-prefix",p,"plugin","remove-exact",g,
                      sha(os.getxattr(p,"user.steer.supd2.binding")),token()],env=env,capture_output=True,timeout=3)
            assert r.returncode!=0
            for name in ("tree","retired-"+g):
                r=sp.run([exe,"plugin","remove",name,"--force","--json"],capture_output=True,env=env,timeout=3)
                assert r.returncode!=0 and json.loads(r.stdout)["code"]=="plugin.busy",(version,r.stdout,r.stderr)


def cuts(root,archive):
    for cut,at in (("before-decision","active"),("after-decision","intent"),("after-intent-seal","intent"),
                   ("after-rename","quarantined"),("sync-error","quarantined"),
                   ("after-commit-record","quarantined"),("lost-reply","removed")):
        p=root/cut
        g,b=provision(p,archive)
        t=token()
        ino=(p/"tree").stat().st_ino
        with owner(p,g,b,t,cut) as s:
            live(p,s)
            r=run(p,"remove",g,b,t)
            while r.returncode==3:
                assert json.loads(r.stdout)["state"]=="pending"
                r=run(p,"recover",g,b,t)
            assert r.returncode==1 and not r.stdout
            if cut=="sync-error":
                with unchanged(p):
                    expect(p,"recover",g,b,t,"refused")
                    expect(p,"inspect",g,b,t,"quarantined")
            else:
                assert s.wait(timeout=2)==-signal.SIGKILL
        assert (p/"tree").exists()==(at in ("active","intent"))
        with unchanged(p):
            expect(p,"recover",g,b,t,"refused")  # no owner, even after commit
        old_refusal(p,g)
        with owner(p,g,b,t):
            expect(p,"inspect",g,b,t,at)
            if at=="active":
                with unchanged(p):
                    expect(p,"recover",g,b,t,"refused")
                assert run(p,"remove",g,b,t).returncode in (0,3)
            else:
                with unchanged(p):
                    expect(p,"remove",g,b,t,"refused")
                    expect(p,"recover",g,b,token(),"refused")
            if cut=="after-intent-seal":
                attr="user.steer.supd2.intent"
                original=os.getxattr(p/"history",attr)
                wrong=token()
                raw=f"{g} {b} {wrong}".encode()
                os.setxattr(p/"history",attr,raw+b" "+sha(raw).encode())
                with unchanged(p):
                    expect(p,"recover",g,b,wrong,"refused")
                    expect(p,"recover",g,b,t,"refused")
                os.setxattr(p/"history",attr,original)
            if at=="quarantined":
                # A moved tree is not committed; damage must not complete the
                # journal, nor can a byte-identical tree with a new inode pass.
                q=p/("retired-"+g)
                q.rename(root/"saved")
                shutil.copytree(root/"saved",q)
                with unchanged(p):
                    expect(p,"recover",g,b,t,"refused")
                q.rename(root/"copy")
                (root/"saved").rename(q)
                shutil.rmtree(root/"copy")
            finish(p,g,b,t)
            assert (p/("retired-"+g)).stat().st_ino==ino
            assert (p/"history").read_text()==f"start {g}\n"
            with unchanged(p):
                expect(p,"inspect",g,b,t,"removed")
                expect(p,"recover",g,b,t,"removed")
                expect(p,"recover",g,b,token(),"refused")
            if cut=="lost-reply":
                attr="user.steer.supd2.commit"
                original=os.getxattr(p/"history",attr)
                os.removexattr(p/"history",attr)
                with unchanged(p):
                    expect(p,"inspect",g,b,t,"refused")
                    expect(p,"recover",g,b,t,"refused")
                os.setxattr(p/"history",attr,original)
        print(json.dumps(dict(cut=cut,observed=at,recovered="removed")))


def wire(g):
    s=socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET)
    s.settimeout(2)
    s.connect("\0steer-supd2-"+g)
    return s


def main():
    assert os.getuid()==65534 and os.getpid()==1 and socket.if_nameindex()==[(1,"lo")]
    archive=json.loads((FEED/"fixtures.json").read_bytes())["A"]
    with tempfile.TemporaryDirectory(prefix="e4-lab-") as tmp:
        root=Path(tmp)
        p,n=root/"subject",root/"neighbor"
        v1=root/"fence-only"
        legacy_g=init(v1,archive)
        with unchanged(v1):
            expect(v1,"remove",legacy_g,sha(os.getxattr(v1,"user.steer.supd1.binding")),token(),"refused")
        g,b=provision(p,archive)
        ng,nb=provision(n,archive)
        data=root/"user-settings"
        data.write_bytes(os.urandom(256))
        saved=data.stat().st_ino,data.read_bytes()
        t=token()
        with owner(n,ng,nb,t) as neighbor, unchanged(n):
            other=live(n,neighbor)
            with owner(p,g,b,t) as first:
                pid=live(p,first)
                with unchanged(p):
                    expect(p,"remove",ng,nb,t,"refused")
                    expect(p,"remove",g,nb,t,"refused")
                    expect(p,"recover",g,b,t,"refused")
                # Wrong challenge from a different connection, even for a
                # valid exact tree. No intent, no signal and no rename.
                with wire(g) as s:
                    stale=s.recv(32)
                with unchanged(p), wire(g) as s:
                    assert s.recv(32)!=stale
                    s.sendall(f"remove {g} {b} {t} ".encode()+stale)
                    assert not s.recv(320)
                with unchanged(p), wire(g) as s:
                    s.sendall(f"remove {g} {nb} {t} ".encode()+s.recv(32))
                    assert s.recv(320).endswith(b" conflict")
                # The manager cannot treat a prior scan as authority.
                with wire(g) as s:
                    fresh=s.recv(32)
                    css=p/"tree/assets/app.css"
                    original=css.read_bytes()
                    css.write_bytes(b"changed")
                    with unchanged(p):
                        s.sendall(f"remove {g} {b} {t} ".encode()+fresh)
                        assert s.recv(320).endswith(b" damaged")
                    css.write_bytes(original)
                # Occupied destination is not something the owner may clean up.
                dst=p/("retired-"+g)
                dst.symlink_to(n/"tree")
                with unchanged(p):
                    expect(p,"remove",g,b,t,"refused")
                dst.unlink()
                os.kill(pid,signal.SIGSTOP)
                wait(lambda:"\nState:\tT" in Path(f"/proc/{pid}/status").read_text())
                fd=os.pidfd_open(pid)
                first.kill()
                first.wait(timeout=2)
            # Same uid, right address, no pinned POSIX owner lock.
            with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as fake, unchanged(p):
                fake.bind("\0steer-supd2-"+g)
                fake.listen(1)
                expect(p,"remove",g,b,t,"refused")
                c,_=fake.accept()
                with c:
                    assert not c.recv(320)
            with owner(p,g,b,t) as successor:
                with unchanged(p), wire(g) as s:
                    assert s.recv(32)!=stale
                    s.sendall(f"remove {g} {b} {t} ".encode()+stale)
                    assert not s.recv(320)
                rival=token()
                with concurrent.futures.ThreadPoolExecutor(2) as pool:
                    r=list(pool.map(lambda x:run(p,"remove",g,b,x),(t,rival)))
                assert sorted(x.returncode for x in r)==[1,3]
                if r[1].returncode==3:
                    t=rival
                assert (p/"tree").is_dir()
                expect(p,"inspect",g,b,t,"intent")
                successor.send_signal(signal.SIGHUP)
                expect(p,"recover",g,b,t,"pending")
                assert not select.select([fd],[],[],0)[0]
                successor.kill()
                successor.wait(timeout=2)
            with owner(p,g,b,t):
                expect(p,"recover",g,b,t,"pending")
                signal.pidfd_send_signal(fd,signal.SIGCONT)
                assert select.select([fd],[],[],3)[0]
                os.close(fd)
                finish(p,g,b,t)
                with unchanged(p):
                    expect(p,"remove",g,b,token(),"refused")
            cuts(root,archive)
            assert live(n,neighbor)==other and saved==(data.stat().st_ino,data.read_bytes())
        # Normal path: one manager invocation, including the wait for the
        # real supervisor's child-exit callback. No Python recovery loop.
        with owner(n,ng,nb,t) as normal:
            live(n,normal)
            expect(n,"remove",ng,nb,t,"removed")
        with unchanged(n):
            expect(n,"recover",ng,nb,t,"refused")  # committed but owner absent
        print(json.dumps(dict(result="PASS",retained_neighbor=other,stopped_orphan="pending",
                              competing_decisions=1,external_data="unchanged",archive=archive)))


if __name__=="__main__":
    main()
