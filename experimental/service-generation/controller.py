"""Linux x86_64 lab only. Single launch authority for steer-ui/full-ui."""
import argparse
import contextlib
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import stat
import struct
import subprocess
import tempfile
import time
import uuid


PROFILE = "steer-lab-service-generation/1"
ID = "steer-ui/full-ui"
HOST = Path("/run/e4/host")  # immutable lab inputs, never chosen by a request
ATTR = "user.steer_gen_head"
NAMES = ("type", "owner.lock", "child.lock", "history")
TOKEN = re.compile("[0-9a-f]{32}")


class Refusal(Exception):
    pass


def require(ok, why="damaged-boundary"):
    if not ok:
        raise Refusal(why)


def enc(x):
    return json.dumps(x,sort_keys=True,separators=(",",":")).encode()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def belongs(nonce,g):
    return isinstance(g,str) and g.startswith(nonce+":") and TOKEN.fullmatch(g[33:])


def ident(p):
    s = p.lstat()
    return [s.st_dev,s.st_ino]


def mount(p):
    fd = os.open(p,os.O_PATH | os.O_NOFOLLOW)
    try:
        return re.search(r"^mnt_id:\s*(\d+)$",Path(f"/proc/self/fdinfo/{fd}").read_text(),re.M)[1]
    finally:
        os.close(fd)


def parent(p):
    require(os.getuid() != 0 and p == p.resolve() and p.parent.parent == Path("/tmp") and
            p.parent.name.startswith("e4-lab-") and re.fullmatch(r"[a-z][a-z0-9-]{0,24}",p.name),
            "private-lab-path-required")
    s = p.parent.lstat()
    require(s.st_uid == os.getuid() and s.st_mode == stat.S_IFDIR | 0o700)
    require(not any(os.path.lexists(p.parent/n) for n in ("installed","etc","type","history",".lock")),
            "nested-installation")


def syncdir(p):
    fd = os.open(p,os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def init(p,profile=PROFILE,dirs=()):
    parent(p)
    require(not os.path.lexists(p),"new-prefix-required")
    tmp = Path(tempfile.mkdtemp(dir=p.parent,prefix=".e4-init-"))
    try:
        for name in NAMES:
            (tmp/name).touch(mode=0o600,exist_ok=False)
        for name in dirs:
            (tmp/name).mkdir(mode=0o700)
            syncdir(tmp/name)
        stamp = {"profile":profile,"id":ID,"nonce":uuid.uuid4().hex,"path":str(p),
                 "root":ident(tmp),"objects":{n:ident(tmp/n) for n in NAMES+dirs}}
        (tmp/"type").write_bytes(enc(stamp))
        os.setxattr(tmp/"history",ATTR,sha(enc(stamp)).encode(),os.XATTR_CREATE)
        for n in NAMES:
            with (tmp/n).open("rb") as f:
                os.fsync(f.fileno())
        syncdir(tmp)
        libc = ctypes.CDLL(None,use_errno=True)
        if libc.renameat2(-100,os.fsencode(tmp),-100,os.fsencode(p),1):
            raise OSError(ctypes.get_errno(),"publish new prefix")
        syncdir(p.parent)
    finally:
        if tmp.exists():
            shutil.rmtree(tmp)


def boundary(p,profile=PROFILE,dirs=()):
    parent(p)
    s = p.lstat()
    require(s.st_uid == os.getuid() and s.st_mode == stat.S_IFDIR | 0o700 and mount(p) == mount(p.parent))
    require(set(os.listdir(p)) == set(NAMES+dirs))
    for n in dirs:
        s = (p/n).lstat()
        require(s.st_mode == stat.S_IFDIR | 0o700 and s.st_uid == os.getuid() and mount(p/n) == mount(p))
    for n in NAMES:
        s = (p/n).lstat()
        require(s.st_mode == stat.S_IFREG | 0o600 and s.st_nlink == 1 and s.st_uid == os.getuid()
                and s.st_dev == p.stat().st_dev and mount(p/n) == mount(p))
        if n.endswith(".lock"):
            require(s.st_size == 0)
    require((p/"type").stat().st_size < 2048)
    raw = (p/"type").read_bytes()
    t = json.loads(raw)
    require(isinstance(t,dict) and isinstance(t.get("nonce"),str) and TOKEN.fullmatch(t["nonce"]))
    require(raw == enc({"profile":profile,"id":ID,"nonce":t["nonce"],"path":str(p),
                        "root":ident(p),"objects":{n:ident(p/n) for n in NAMES+dirs}}))
    return t


class Ledger:
    """Append and fsync a linked frame, then seal its hash on the pinned inode.
    A full one-frame lead can be replayed. Neither a short frame nor a missing
    sealed tail is permission to truncate/reinitialize. No writes in __init__.
    """
    def __init__(self,p,t):
        self.path = p/"history"
        self.nonce = t["nonce"]
        self.head = sha(enc(t))
        self.rows = {}
        self.last = None
        require(self.path.stat().st_size <= 1<<20)
        data = self.path.read_bytes()
        self.seal = os.getxattr(self.path,ATTR).decode()
        prev = None
        for line in data.splitlines(keepends=True):
            gen,phase,h = json.loads(line)
            require(belongs(self.nonce,gen) and line == enc([gen,phase,h])+b"\n")
            prev = self.head
            self.advance(gen,phase)
            require(self.head == h)
        require(self.seal in (prev,self.head))

    def advance(self,g,phase):
        old = self.rows.get(g)
        if phase == "reserve":
            require(old is None and (not self.last or self.rows[self.last] == "fence"),"generation-conflict")
        elif phase == "publish":
            require(self.last == g and old == "reserve","generation-not-reserved")
        else:
            require(phase == "fence" and self.last == g and old in ("reserve","publish"),"wrong-generation")
        self.head = sha(enc([self.head,ID,g,phase]))
        self.rows[g] = phase
        self.last = g

    def seal_tail(self):
        if self.seal != self.head:
            with self.path.open("rb") as f:
                os.fsync(f.fileno())
                os.setxattr(f.fileno(),ATTR,self.head.encode(),os.XATTR_REPLACE)
                os.fsync(f.fileno())
            self.seal = self.head

    def change(self,g,phase,checkpoint):
        # Reject stale messages before completing even a valid prepared tail.
        require(self.rows.get(g) != "fence" or phase == "fence","irrevocably-fenced")
        if self.last == g and self.rows[g] == phase:
            self.seal_tail()
            return
        require(self.seal == self.head,"replay-required")
        self.advance(g,phase)
        line = enc([g,phase,self.head])+b"\n"
        # Leave room to publish AND fence this incarnation even at capacity.
        require(self.path.stat().st_size+len(line)+(512 if phase == "reserve" else 0) <= 1<<20,"history-full")
        checkpoint("before-"+phase)
        with self.path.open("ab",buffering=0) as f:
            require(f.write(line) == len(line))
            os.fsync(f.fileno())
        checkpoint("tail-"+phase)
        self.seal_tail()
        checkpoint("after-"+phase)


# POSIX process-owned lock, NOT flock. Verify the connected peer holds the
# write lock on this prefix's pinned inode. Linux x86_64 struct flock offsets.
LOCK = struct.Struct("@hh4xqqi4x")


def address(t):
    return "\0steer-e4-"+t["nonce"]


def request(p,op,g,endpoint=None):
    t = boundary(p)
    require(belongs(t["nonce"],g),"wrong-prefix-generation")
    reply = exchange(p,t,op,g,endpoint)
    if op == "fence":
        require(boundary(p) == t)
        h = Ledger(p,t)
        require(reply.get("excluded") is True and h.last == g and h.rows[g] == "fence"
                and h.head == h.seal == reply.get("head"),"unconfirmed-fence")
    return reply


def exchange(p,t,op,g,endpoint=None,timeout=3):
    with socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as s:
        s.settimeout(timeout)
        s.connect(endpoint if endpoint is not None else address(t))
        pid,uid,_ = struct.unpack("3i",s.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
        with (p/"owner.lock").open("rb") as f:
            lock = fcntl.fcntl(f,fcntl.F_GETLK,LOCK.pack(fcntl.F_WRLCK,0,0,0,0))
        require(LOCK.unpack(lock) == (fcntl.F_WRLCK,os.SEEK_SET,0,0,pid)
                and pid > 0 and uid == os.getuid(),"foreign-owner")
        challenge = uuid.uuid4().hex
        q = [t["profile"],t["nonce"],ID,g,op,challenge]
        s.sendall(enc(q))
        reply = json.loads(s.recv(8192))
        require(isinstance(reply,dict) and reply.get("request") == q and reply.get("owner") == pid,"unconfirmed")
        if reply.get("ok") is not True:
            raise Refusal(reply.get("error","unconfirmed"))
        return reply


class Supervisor:
    boundary = staticmethod(boundary)
    journal = Ledger

    def __init__(self,p,checkpoint):
        self.p,self.checkpoint = p,checkpoint
        self.child,self.reader,self.g = None,None,None

    def reap(self):
        if self.child and self.child.poll() is not None:
            os.close(self.reader)
            self.child,self.reader,self.g = None,None,None

    @contextlib.contextmanager
    def lease(self):
        # Child inherits this open file description across exec. If its parent
        # dies (even while child is stopped), a replacement cannot infer exit.
        with (self.p/"child.lock").open("rb") as f:
            try:
                fcntl.flock(f,fcntl.LOCK_EX|fcntl.LOCK_NB)
            except BlockingIOError:
                raise Refusal("previous-child-not-excluded") from None
            yield f

    def reconcile(self,h):
        self.reap()
        if self.child or not h.last or h.rows[h.last] != "publish":
            return
        require(h.head == h.seal)
        self.spawn(h.last,HOST,"/run/e4/assets","0.0.0")

    def spawn(self,g,host,assets,version):
        with self.lease() as lease:
            r,w = os.pipe()
            try:
                args = [host,"--assets",assets,"--port","0",
                        "--core-control",str(self.p.parent/(self.p.name+"-v3.sock"))]
                self.child = subprocess.Popen(args,env={"STEER_PLUGIN_ID":"steer-ui","STEER_PLUGIN_VERSION":version,
                    "STEER_EVENT_FD":str(w)},pass_fds=(lease.fileno(),w),stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            except BaseException:
                os.close(r)
                raise
            finally:
                os.close(w)
            self.reader,self.g = r,g

    def apply(self,h,op,g):
        require(belongs(h.nonce,g),"bad-generation")
        self.reap()
        if op != "status":
            require(op in ("reserve","publish","fence"),"unknown-operation")
            if op == "reserve" and g not in h.rows:
                require(not self.child,"previous-child-not-excluded")
                with self.lease():
                    pass
            h.change(g,op,self.checkpoint)
        if op == "fence":
            # Terminal history is sealed BEFORE signalling a direct child.
            if self.child:
                require(self.g == g)
                self.child.terminate()
                self.child.wait(timeout=1)
                self.reap()
            with self.lease():
                return {"excluded":True,"head":h.head}
        if op == "publish":
            self.reconcile(h)
        return {"phase":h.rows.get(g),"head":h.head,"pid":self.child.pid if self.g == g else None}

    def tick_needed(self):
        return True

    def serve(self):
        t = self.boundary(self.p)
        with (self.p/"owner.lock").open("r+b") as owner, socket.socket(socket.AF_UNIX,socket.SOCK_SEQPACKET) as server:
            fcntl.lockf(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
            h = self.journal(self.p,t)
            server.bind(address(t))
            # No clients yet. Complete only an intact, single prepared tail.
            h.seal_tail()
            server.listen(4)
            server.settimeout(.1)
            next_tick = 0
            while True:
                if time.monotonic() >= next_tick:
                    try:
                        if self.tick_needed():
                            require(self.boundary(self.p) == t)
                            h = self.journal(self.p,t)
                            h.seal_tail()
                            self.reconcile(h)
                    except (OSError,ValueError,TypeError,Refusal):
                        pass  # no launch or cleanup on a damaged boundary
                    next_tick = time.monotonic()+.1
                try:
                    c,_ = server.accept()
                except TimeoutError:
                    continue
                with c:
                    c.settimeout(2)
                    q = None
                    try:
                        _,uid,_ = struct.unpack("3i",c.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
                        require(uid == os.getuid())
                        q = json.loads(c.recv(1024))
                        require(isinstance(q,list) and len(q)==6 and q[:3]==[t["profile"],t["nonce"],ID])
                        require(self.boundary(self.p) == t)
                        result = self.apply(self.journal(self.p,t),q[4],q[3])
                        reply = dict(ok=True,**result)
                    except (OSError,ValueError,TypeError,Refusal,subprocess.TimeoutExpired) as e:
                        reply = dict(ok=False,error=str(e))
                    try:
                        c.sendall(enc(dict(reply,request=q,owner=os.getpid())))
                    except OSError:
                        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-generation-prefix",required=True,type=Path)
    parser.add_argument("op",choices=("init","serve","reserve","publish","fence","status"))
    parser.add_argument("generation",nargs="?")
    a = parser.parse_args()
    p = a.service_generation_prefix
    os.umask(0o077)
    require(bool(a.generation) == (a.op not in ("serve","init")),"generation-argument")
    if a.op == "init":
        init(p)
        print(json.dumps({"profile":PROFILE,"prefix_id":boundary(p)["nonce"]}))
    elif a.op == "serve":
        Supervisor(p,lambda phase: None).serve()
    else:
        print(json.dumps(request(p,a.op,a.generation)))


if __name__ == "__main__":
    try:
        main()
    except (OSError,ValueError,Refusal) as e:
        raise SystemExit(f"service-generation: refused: {e}")
