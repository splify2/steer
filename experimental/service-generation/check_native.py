"""Only steerd runs services here. Python is the offline provisioner / IPC client."""
import contextlib
import json
import os
from pathlib import Path
import select
import signal
import socket
import subprocess as sp
import tempfile
import time

from native_manager import BIND, PHASE, init, request
from signed import ELF, FEED, LAB, Refusal, sha


def wait(fn, timeout=9):
    end = time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            value = fn()
            if value:
                return value
        except ConnectionRefusedError:
            pass
        time.sleep(.04)
    raise AssertionError(f"timeout: {fn}")


def denied(fn, *args):
    try:
        fn(*args)
    except (Refusal,OSError) as e:
        return str(e)
    raise AssertionError(("unexpected success",args))


def command(p):
    return [LAB/"steerd","daemon","--supervise","--supd-full-prefix",p]


@contextlib.contextmanager
def owner(p,g,env,compatible=False):
    cmd=command(p)
    if compatible:
        cmd[0]=LAB/"steerd-compatible"
    s = sp.Popen(cmd,env=env)
    try:
        def connected():
            assert s.poll() is None
            return request(p,"status",g)["owner"] == s.pid
        wait(connected)
        yield s
    finally:
        s.terminate()
        s.wait(timeout=8)


def live(p,g,ppid):
    def running():
        pid = request(p,"status",g)["child"]
        if pid and os.path.samefile(f"/proc/{pid}/exe",p/"tree"/ELF):
            assert f"\nPPid:\t{ppid}\n" in Path(f"/proc/{pid}/status").read_text()
            argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
            assert argv[1:] == [b"--port",b"0",b"--assets",os.fsencode(p/"tree/assets"),
                                b"--core-control",os.fsencode(str(p)+"-v3.sock"),b""]
            return pid
    return wait(running)


def receipt(p,g):
    def attempt():
        try:
            return request(p,"fence",g)["receipt"]
        except Refusal as e:
            if str(e)!="pending":
                raise
    return wait(attempt)


def main():
    assert os.getuid()==65534 and os.getpid()==1 and socket.if_nameindex()==[(1,"lo")]
    feed = json.loads((FEED/"fixtures.json").read_bytes())
    with tempfile.TemporaryDirectory(prefix="e4-lab-") as tmp:
        home = Path(tmp)
        a,b = home/"subject",home/"neighbor"
        assert "plugin.signed_unknown_key" in denied(init,a,feed["foreign"]) and not a.exists()
        assert "plugin.file_mismatch" in denied(init,a,feed["tampered"]) and not a.exists()
        g,n = init(a,feed["A"]),init(b,feed["A"])
        denied(init,a,feed["B"])
        before = (a/"history").read_bytes()
        assert before == f"start {g}\n".encode()
        print(json.dumps(dict(case="before-first-start", uid=os.getuid(), kernel=os.uname().release,
                              generation=g, archive=feed["A"], manifest=sha((a/"tree/MANIFEST").read_bytes()),
                              elf=sha((a/"tree"/ELF).read_bytes()), binding=sha(os.getxattr(a,BIND)),
                              owner_builds=[sha((LAB/name).read_bytes()) for name in ("steerd","steerd-compatible")])))
        denied(request,a,"fence",g)  # offline evidence cannot mint a receipt
        # A visible, enabled legacy service and executable seam. Neither is
        # consulted by this role (even on reload or after the terminal fence).
        pkg = home/"plugins/steer-ui"
        pkg.mkdir(parents=True)
        trap = pkg/"foreign"
        trap.write_text(f"#!/bin/sh\ntouch {home}/unexpected\n")
        trap.chmod(0o755)
        m = json.loads((a/"tree/plugin.json").read_bytes())
        m["compat"]["steer-api"]="^1.2"
        m["steer"]={"services":[{"name":"full-ui","prog":"foreign"}]}
        (pkg/"plugin.json").write_text(json.dumps(m))
        etc=home/"config"
        (etc/"repos.d").mkdir(parents=True)
        (etc/"state.json").write_text(json.dumps({"schema":1,"plugins":{"steer-ui":{
            "version":"0.0.0","enabled":True,"state":"enabled"}}}))
        env=dict(os.environ, STEER_PLUGINS_ROOT=str(pkg.parent), STEER_PLUGINS_ETC=str(etc),
                 STEER_SUPERVISE_EXE=str(trap))
        env.update({"STEER_PLUGIN_"+key:str(home/val) for key,val in
                    dict(DIR="plugins",ETC="config",RUN="run",TMP="tmp",KEYS="keys",SEED="seed",
                         KEEPD="keep",SYSROOT="sysroot").items()})
        entry, = json.loads(sp.check_output([LAB/"steerd","plugin","list","--json"],env=env))["plugins"]
        assert entry["enabled"] and entry["services"]==["full-ui"]
        with owner(b,n,env) as neighbor:
            other=live(b,n,neighbor.pid)
            with owner(a,g,env) as s:
                assert sp.run(command(a),capture_output=True,timeout=2).returncode != 0
                assert denied(request,a,"fence",g,"-","\0steer-supd1-"+n)=="foreign-owner"
                assert denied(request,b,"fence",g)=="wrong-domain"
                p1=live(a,g,s.pid)
                os.kill(p1,signal.SIGKILL)
                wait(lambda: request(a,"status",g)["child"]==0)
                p2=live(a,g,s.pid)  # stock delayed respawn
                assert p2!=p1
            with owner(a,g,env) as s:
                cold = live(a,g,s.pid)
                assert cold != p2
                # Kill the live process with a damaged active history. Wait
                # beyond the stock backoff; neither timer nor HUP may fork.
                log = a/"history"
                log.write_bytes(b"")
                assert denied(request,a,"fence",g)=="damaged"
                os.kill(cold,signal.SIGKILL)
                time.sleep(5.4)
                children = Path(f"/proc/{s.pid}/task/{s.pid}/children")
                assert not children.read_text().strip()
                s.send_signal(signal.SIGHUP)
                time.sleep(.2)
                assert not log.read_bytes()
                assert not children.read_text().strip()
                log.write_bytes(before)
                s.send_signal(signal.SIGHUP)
                renewed=live(a,g,s.pid)
                assert renewed != cold
                os.kill(renewed,signal.SIGSTOP)
                wait(lambda: "\nState:\tT" in Path(f"/proc/{renewed}/status").read_text())
                old=os.pidfd_open(renewed)
                s.kill()
                s.wait(timeout=3)
            assert (a/"history").read_bytes()==before
            with owner(a,g,env,compatible=True) as s:
                assert request(a,"status",g)["child"]==0
                assert os.path.samefile(f"/proc/{s.pid}/exe", LAB/"steerd-compatible")
                s.send_signal(signal.SIGHUP)
                assert denied(request,a,"fence",g)=="pending"
                assert request(a,"status",g)["state"]=="fenced" and not select.select([old],[],[],0)[0]
                assert denied(request,a,"check",g,"0"*32)=="refused"
                signal.pidfd_send_signal(old,signal.SIGCONT)
                assert select.select([old],[],[],3)[0]
                os.close(old)
                ticket=receipt(a,g)
                assert request(a,"check",g,ticket)["receipt"]==ticket
                assert denied(request,b,"check",n,ticket)=="refused"
                s.kill()
                s.wait(timeout=3)
            with owner(a,g,env) as s:
                assert denied(request,a,"check",g,ticket)=="refused"
                s.send_signal(signal.SIGHUP)
                assert request(a,"status",g)["child"]==0 and receipt(a,g)!=ticket
            # Loss of sealed tail, missing identity, changed payload: no
            # repair/truncate on restart and no fallback to legacy manifest.
            expected=before+f"fence {g}\n".encode()
            assert (a/"history").read_bytes()==expected
            os.setxattr(a/"history",PHASE,b"A",os.XATTR_REPLACE)  # intact, prepared fence
            with owner(a,g,env):
                held=request(a,"status",g)
                assert held["state"]=="pending" and held["child"]==0
                receipt(a,g)
            for rel,data in (("history",before),("type",b"legacy"),("tree/assets/app.css",b"changed")):
                f=a/rel
                saved=f.read_bytes()
                f.write_bytes(data)
                assert sp.run(command(a),env=env,capture_output=True,timeout=2).returncode != 0
                assert f.read_bytes()==data
                f.write_bytes(saved)
            (a/"child.lock").rename(home/"lost")
            assert sp.run(command(a),env=env,capture_output=True,timeout=2).returncode != 0
            assert not (a/"child.lock").exists()
            (home/"lost").rename(a/"child.lock")
            assert not (home/"unexpected").exists() and live(b,n,neighbor.pid)==other
            assert (b/"history").read_text()==f"start {n}\n"
            assert request(b,"check",n,receipt(b,n))["state"]=="excluded"
            assert os.getxattr(a/"history",PHASE)==b"F" and os.getxattr(a,BIND)
        print(json.dumps(dict(result="PASS",generation=g,respawn=[p1,p2],cold=cold,reload=renewed,neighbor=other,
                              compatible_takeover=True,stopped_orphan="pending",cold_stale="refused",removal=False)))


if __name__=="__main__":
    main()
