"""Comparable offline install, first replay status, next status. See accompanying .md."""
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import random
import shutil
import signal
import socket
import subprocess as sp
import sys
import tarfile
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


P = Path("/run/volume/p")
T = Path("/tmp")
ARCH = T/"archives"
REG, KEEP = P/"etc/state.json", P/"keep.d/plugins"
TYPES = {"files": ("fixture-base","fixture-app"), "net1": ("net1","vless")}
VERS = ("v214","file","core")
SIZES = {"4K":4096,"8M":8<<20,"64M":64<<20}
ELF = ("libs2p-net.so.1","vless")
MODE = sys.argv[1]
REL = ("lib/"+ELF[0],"bin/vless")
HASH = {"A": ("4a49b2112a47d09a25f4957e0f0b6edc4aa4cd7a27bb5aa63d497e8e98c04be0",
              "b84d78230aebc369f9c577131a214d7540e0ffb629fd21629ead2a93e8a4bb0e"),
        "B": ("81d6a68371183727591cc782ce855c79d2e0add3ef1f7fea65629624d731fd91",
              "10b057d60bbdc21beb64d32e9a3817f94962ac1ca3f7d0f52f10818d9e3163b4")}


def emit(**kw):
    print(json.dumps(kw,ensure_ascii=False))


def sha(b):
    return hashlib.sha256(b).hexdigest()


def digest(p):
    with p.open("rb") as f:
        return hashlib.file_digest(f,"sha256").hexdigest()


def make_archives():
    # Public deterministic fixture key; trusted only in the disposable volume.
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"steer cost fixture").digest())
    def block(b):
        return b"untrusted comment: cost fixture\n"+base64.b64encode(b"Edcostkey1"+b)+b"\n"
    pub = block(key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))
    ARCH.mkdir()
    for family,ids in TYPES.items():
        for g in HASH:
            libver = {"A":"1.5.0","B":"1.6.0"}[g]
            for i,id_ in enumerate(ids):
                payload = Path("/run",g,ELF[i]).read_bytes()
                assert sha(payload) == HASH[g][i]
                ver = "2.1.4" if i else libver
                if family == "files":
                    m = dict(schema=1,id=id_,name=id_,version=ver,arch=["x86_64"])
                    if i:
                        m["requires"] = {"plugins":{ids[0]:libver}}
                    files = {"data/"+ELF[i]:payload}
                    if MODE == "stream" and not i:
                        # Incompressible signed file, unlike the user config outside MANIFEST.
                        files["data/bulk"] = random.Random(ord(g)).randbytes(63<<20)
                else:
                    base = Path("/run/examples",id_)
                    m = json.loads((base/"plugin.json").read_bytes())
                    m.update(version=ver,arch=["x86_64"])
                    files = {REL[i]:payload}
                    if not i:
                        m["libs"][0]["abi"] = {"A":"1.4","B":"1.5"}[g]
                        m["compat"]["steer-crypto"] = "^2.0"
                    else:
                        m["requires"] = {"plugins":{"net1":libver}}
                        for k in ("ui","i18n"):
                            del m[k]
                        del m["compat"]["host-api"]
                        files["kinds/vless.schema.json"] = (base/"kinds/vless.schema.json").read_bytes()
                for j in range(24):
                    files[f"data/part{j:02}"] = (f"{g}:{id_}:{j}\n".encode()*512)[:4096]
                files = {"plugin.json":json.dumps(m,ensure_ascii=False).encode(),**files}
                def mode(name):
                    return 0o755 if name in REL else 0o644
                manifest = (f"s2p 1 {id_} {ver} x86_64\n"+"".join(
                    f"{sha(b)} {len(b)} {mode(n):04o} {n}\n" for n,b in files.items())).encode()
                p = ARCH/f"{g}-{id_}.s2p"
                with p.open("wb") as raw, gzip.GzipFile(filename="",fileobj=raw,mode="wb",mtime=0) as gz, \
                        tarfile.open(fileobj=gz,mode="w|",format=tarfile.USTAR_FORMAT) as tar:
                    for n,b in {"plugin.json":files.pop("plugin.json"),"MANIFEST":manifest,
                                "MANIFEST.sig":block(key.sign(manifest)),**files}.items():
                        t = tarfile.TarInfo(n)
                        t.mode,t.size = mode(n),len(b)
                        tar.addfile(t,io.BytesIO(b))
                emit(archive=p.name,bytes=p.stat().st_size,sha256=digest(p),payload=sha(payload))
    return pub


def env(v,native=False):
    dirs = dict(DIR=P/"installed",ETC=REG.parent,KEEPD=KEEP,KEYS=P/"keys",TMP=P/"tmp",
                RUN=P/"run",SYSROOT=P/"sys",SPEC=P/"spec",SEED=P/"seed")
    e = dict(os.environ,STEER_PLUGIN_INITD="",STEER_SOCKET=str(P/"offline"),STEER_PLUGIN_ARCH="x86_64",
             LD_LIBRARY_PATH=f"/run/{v}"+(":/run/native" if native else ""))
    if not native:
        e["STEER_PLUGIN_CRYPTO"] = "2.0"
    return e | {"STEER_PLUGIN_"+k:str(p) for k,p in dirs.items()}


def invoke(v,family,g=None,meter=False,cut=False,native=False):
    ids = TYPES[family]
    args = ["install","--file",ARCH/f"{g}-{ids[0]}.s2p","--file",ARCH/f"{g}-{ids[1]}.s2p"] if g else ["status"]
    cmd = [f"/run/{v}/steerd","plugin",*args,"--json"]
    if meter:
        cmd = ["/run/meter",T/"metric",*cmd]
    e = env(v,native)
    if cut:
        e.update(LD_PRELOAD="/run/cut.so",CUT="state2")
    r = sp.run(cmd,env=e,capture_output=True,timeout=60)
    if cut:
        assert r.returncode == -signal.SIGKILL and not r.stdout and (P/"installed/.install-in-progress").exists(),r
        return
    reply = json.loads(r.stdout)
    assert not r.returncode and reply["ok"],(cmd,r.stderr,reply)
    if not g:
        assert all(p["files_ok"] and p["enabled"] and not p["unsigned"] for p in reply["plugins"])
    return json.loads((T/"metric").read_bytes()) if meter else reply


def tree(family):
    return {str(p.relative_to(P)):digest(p) for id_ in TYPES[family]
            for p in (P/"installed"/id_).rglob("*") if p.is_file()}


def initial(family,pub):
    if P.exists():
        shutil.rmtree(P)
    keys = P/"keys/plugins"
    keys.mkdir(parents=True)
    (keys/"fixture.pub").write_bytes(pub)
    invoke("core",family,"A")
    # Match state bytes across versions, including old timestamps and user files.
    state = json.loads(REG.read_bytes())
    for d in state["plugins"].values():
        d["installed_at"] = "2026-01-01T00:00:00Z"
    REG.write_text(json.dumps(state)); REG.chmod(0o640)
    KEEP.write_bytes(b"# local prior keep\n"); KEEP.chmod(0o640)
    conf = REG.parent/"conf/site.conf"
    conf.parent.mkdir(exist_ok=True)
    conf.write_bytes(b"outside package tree\n")
    shutil.copytree(P,T/f"seed-{family}")


def restore(family,size):
    shutil.rmtree(P)
    shutil.copytree(T/f"seed-{family}",P)
    user = P/"installed"/TYPES[family][0]/"local"
    user.mkdir()
    for i in range(48):
        (user/f"u{i:02}.conf").write_text(f"user {i}\n")
    # Ordinary, fully allocated, not sparse. No compression in the measured volume.
    with (user/"site.conf").open("wb") as f:
        buf = (b"local setting = 0123456789abcde\n"*32768)
        for off in range(0,SIZES[size],len(buf)):
            f.write(buf[:min(SIZES[size]-off,len(buf))])
    return user


def cycle(v,family,size,rep):
    def record(op,m,**kw):
        emit(rev=v,family=family,size=size,rep=rep,op=op,**m,**kw)
    user = restore(family,size)
    outside = REG.parent/"conf/site.conf"
    orig = outside.read_bytes()
    m = invoke(v,family,"B",meter=True,native=MODE == "native")
    for i,id_ in enumerate(TYPES[family]):
        path = REL[i] if family == "net1" else "data/"+ELF[i]
        assert digest(P/"installed"/id_/path) == HASH["B"][i]
    assert not user.exists() and outside.read_bytes() == orig
    record("update",m,inner=0,external=1)
    if v == "v214" or (v == "file" and family == "net1"):
        return  # no such group replay; never time legacy mixed status as recovery
    user = restore(family,size)
    before = tree(family)
    meta = [(p.read_bytes(),p.stat().st_mode) for p in (REG,KEEP)]
    ino = (user/"site.conf").stat().st_ino
    invoke(v,family,"B",cut=True)
    assert (P/"installed/.install-in-progress").read_text().startswith("G1 active ")
    ARCH.rename(T/"away")
    try:
        first = invoke(v,family,meter=True)
        assert not (P/"installed/.install-in-progress").exists() and not (P/"installed/.group-txn").exists()
        clean = invoke(v,family,meter=True)
        assert tree(family) == before and (user/"site.conf").stat().st_ino == ino
        assert meta == [(p.read_bytes(),p.stat().st_mode) for p in (REG,KEEP)]
        assert outside.read_bytes() == orig
        record("recovery",first,inner=49,external=1)
        record("clean",clean,inner=49,external=1)
    finally:
        (T/"away").rename(ARCH)


if __name__ == "__main__":
    assert os.getpid() == 1 and os.getuid() == 65534 and socket.if_nameindex() == [(1,"lo")]
    emit(kernel=os.uname().release,glibc=os.confstr("CS_GNU_LIBC_VERSION"),load=os.getloadavg(),
         pagesize=os.sysconf("SC_PAGE_SIZE"),affinity=sorted(os.sched_getaffinity(0)),repeats=20)
    for v in VERS:
        exe = f"/run/{v}/steerd"
        e = env(v,MODE == "native" and v == "v214")
        emit(rev=v,mode=MODE,elf=digest(Path(exe)),version=json.loads(sp.check_output([exe,"version","--json"],env=e)),
             loaded=sp.check_output([exe],env=e|{"LD_TRACE_LOADED_OBJECTS":"1"},text=True))
    pub = make_archives()
    for family in TYPES:
        initial(family,pub)
    # Stock v2.1.4 trust/compat behavior, no spoofed version, never timed as a successful update.
    restore("net1","4K")
    r = sp.run(["/run/v214/steerd","plugin","install","--file",ARCH/"B-net1.s2p",
                "--file",ARCH/"B-vless.s2p","--json"],env=env("v214",True),capture_output=True)
    refusal = json.loads(r.stdout)
    assert r.returncode == 1 and not refusal["ok"] and refusal["code"] == "plugin.compat_needs_core",r
    assert (refusal["args"]["axis"],refusal["args"]["have"]) == ("steer-crypto","1.0"),refusal
    emit(native_v214=refusal)
    cases = [(v,f,s) for v in VERS for f in TYPES for s in SIZES]
    if MODE == "stream":
        cases = [(v,"files","4K") for v in VERS]
    elif MODE == "native":
        cases = [("v214","files",s) for s in SIZES]
    rng = random.Random(544)
    for rep in range(21):  # warm-up of each combination; retain 1..20
        rng.shuffle(cases)
        for v,f,s in cases:
            cycle(v,f,s,rep)
    emit(finish_load=os.getloadavg())
