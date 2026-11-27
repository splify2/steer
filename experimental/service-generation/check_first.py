"""Test driver only. Archive → domain/receipt → fork → exact remove are C operations."""
import contextlib
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess as sp
import tempfile
import uuid

from check_signed import ELF, FEED, LAB, eventually, served_assets, sha

FEEDS=json.loads((FEED/"fixtures.json").read_bytes())
HOST=(LAB/"host.sha256").read_text().strip()


def token():
    return uuid.uuid4().hex


def cmd(p,*args):
    return [LAB/"steerd","--supd-full-prefix",p,"plugin",*args]


def install(p,tx,case="A"):
    d=FEEDS[case]
    return cmd(p,"install-first",tx,FEED/(d+".s2p"),d,FEED/"publisher.pub",HOST)


def run(argv,ok=True,cut=None):
    env=dict(os.environ)
    if cut:
        env.update(LD_PRELOAD=str(LAB/"first-cut.so"),INSTALL_CUT=cut)
    r=sp.run(argv,capture_output=True,env=env,timeout=8)
    if ok:
        assert r.returncode==0,(argv,r.stdout,r.stderr)
        return json.loads(r.stdout)
    assert r.returncode!=0 and not r.stdout,(argv,r.returncode,r.stdout)
    return r


def receipt(p,tx):
    return run(cmd(p,"confirm-first",tx))


def snapshot(p):
    return [(f.relative_to(p),f.stat().st_dev,f.stat().st_ino,f.stat().st_mode,
             None if f.is_dir() else sha(f.read_bytes()),
             {k:os.getxattr(f,k) for k in os.listxattr(f)}) for f in [p,*sorted(p.rglob("*"))]]


@contextlib.contextmanager
def owner(p):
    s=sp.Popen([LAB/"steerd","daemon","--supervise","--supd-full-prefix",p])
    def live():
        assert s.poll() is None
        kids=Path(f"/proc/{s.pid}/task/{s.pid}/children").read_text().split()
        if len(kids)==1 and os.path.samefile(f"/proc/{kids[0]}/exe",p/"tree"/ELF):
            return int(kids[0])
    try:
        yield eventually(live)
    finally:
        s.terminate()
        s.wait(timeout=5)


def main():
    assert os.getuid()==65534 and os.getpid()==1 and socket.if_nameindex()==[(1,"lo")]
    assert not (LAB/"native_manager.py").exists()
    with tempfile.TemporaryDirectory(prefix="e4-lab-") as tmp:
        root=Path(tmp)
        p,n,data=root/"subject",root/"neighbor",root/"user-data"
        data.write_bytes(os.urandom(96))
        orig=data.stat().st_ino,data.read_bytes()
        nt=token()
        nr=run(install(n,nt))
        assert receipt(n,nt)==nr
        with owner(n) as neighbor:
            stable=snapshot(n)
            for case in ("foreign","bad-signature","tampered","wrong-mode","extra","wrong-host"):
                t=token()
                r=run(install(p,t,case),False)
                assert not p.exists()
                run(cmd(p,"confirm-first",t),False)
                print(case,r.stderr.decode().strip())
                if case=="bad-signature":
                    assert b"plugin.signature_mismatch" in r.stderr
            p.mkdir()
            run(install(p,token()),False)
            assert not list(p.iterdir())
            p.rmdir()
            p.symlink_to(n)
            run(install(p,token()),False)
            p.unlink()
            race=root/"race"
            attempts=[(case,token()) for case in ("A","B")]
            procs=[sp.Popen(install(race,x,case),stdout=sp.PIPE) for case,x in attempts]
            answers=[proc.communicate(timeout=8)[0] for proc in procs]
            codes=[proc.returncode for proc in procs]
            assert sorted(codes)==[0,1] and not answers[codes.index(1)]
            case,winner=attempts[codes.index(0)]
            assert receipt(race,winner)==json.loads(answers[codes.index(0)])
            assert (race/"type").read_text().splitlines()[3]==FEEDS[case]
            run(cmd(race,"confirm-first",attempts[codes.index(1)][1]),False)
            # Stop after the signed binding exists but before rename; a rival
            # installer cannot adopt it and the actual UI cannot start from it.
            t=token()
            env=dict(os.environ,LD_PRELOAD=str(LAB/"first-cut.so"),INSTALL_CUT="hold")
            s=sp.Popen(install(p,t),stdout=sp.PIPE,env=env)
            _,status=os.waitpid(s.pid,os.WUNTRACED)
            assert os.WIFSTOPPED(status) and not p.exists()
            run(install(p,token(),"B"),False)
            stage=root/(".first-"+t)/"new"
            r=sp.run([LAB/"steerd","daemon","--supervise","--supd-full-prefix",stage],timeout=2)
            assert r.returncode!=0
            tree=stage/"tree"
            tree.rename(root/"displaced")
            shutil.copytree(root/"displaced",tree)
            s.send_signal(signal.SIGCONT)
            out,_=s.communicate(timeout=5)
            assert s.returncode!=0 and not out and not p.exists()
            for point in ("partial","prepared"):
                t=token()
                assert run(install(p,t),False,point).returncode==-signal.SIGKILL and not p.exists()
                run(cmd(p,"confirm-first",t),False)
                run(install(p,t),False)
            # Real completed rename, failed final fsync; never a success reply.
            t=token()
            run(install(p,t),False,"parent-eio")
            r=receipt(p,t)
            assert r["state"]=="installed" and r["tx"]==t
            run(install(p,t),False)
            run(cmd(p,"confirm-first",nt),False)
            q=root/"reply-loss"
            qt=token()
            assert run(install(q,qt),False,"published").returncode==-signal.SIGKILL
            assert receipt(q,qt)["tx"]==qt
            proof=root/(".first-"+qt)/"receipt"
            proof.unlink()
            run(cmd(q,"confirm-first",qt),False)
            run(install(q,token()),False)
            # Fresh successful install through the public command, then
            # identify the fork by inode and fetch actual installed UI assets.
            a=root/"end-to-end"
            tx=token()
            r=run(install(a,tx))
            assert r==receipt(a,tx)
            g,b=r["generation"],r["binding"]
            assert r["state"]=="installed" and r["tx"]==tx
            assert (a/"type").read_text().splitlines()==["supd-full/2",str(a),g,FEEDS["A"],
                                                        sha((FEED/"publisher.pub").read_bytes())]
            assert (a/"history").read_text()==f"start {g}\n"
            assert sha(os.getxattr(a,"user.steer.supd2.binding"))==b
            ino=(a/"tree").stat().st_ino
            with owner(a) as child:
                served_assets(a,child,"tree")
                rem=token()
                run(cmd(a,"remove-exact",nr["generation"],nr["binding"],rem),False)
                result=run(cmd(a,"remove-exact",g,b,rem))
                assert result==dict(state="removed",generation=g,binding=b,tx=rem)
                assert not (a/"tree").exists() and (a/("retired-"+g)).stat().st_ino==ino
                run(cmd(a,"confirm-first",tx),False)
            assert os.path.samefile(f"/proc/{neighbor}/exe",n/"tree"/ELF)
            assert stable==snapshot(n) and orig==(data.stat().st_ino,data.read_bytes())
            print(json.dumps(dict(result="PASS",archive=FEEDS["A"],key=sha((FEED/"publisher.pub").read_bytes()),
                                  host=HOST,installed=r,http=["app.css","fonts/onest-cyrillic.woff2"],
                                  removed=result,quarantine_inode=ino,neighbor_pid=neighbor,
                                  cuts=["partial","prepared","published","parent-eio"],race_winner=case,
                                  substituted_tree="refused")))


if __name__=="__main__":
    main()
