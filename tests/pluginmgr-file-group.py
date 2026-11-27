"""Recovery contract for signed local legacy groups; run via the .sh."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tarfile
import tempfile
import threading
import socketserver
import shutil
from contextlib import contextmanager

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


BASE, APP = IDS = ("fixture-base", "fixture-app")
OLD, NEW = "1.0.0", "2.0.0"
BIN = "/run/steerd"


def record(**data):
    print(json.dumps(data, ensure_ascii=False))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fixtures(work):
    key = Ed25519PrivateKey.generate()
    prefix = b"Ed" + os.urandom(8)

    def block(data):
        return b"untrusted comment: local fixture\n" + base64.b64encode(prefix + data) + b"\n"

    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    keys = work / "keys/plugins"
    keys.mkdir(parents=True)
    (keys / "fixture.pub").write_bytes(block(pub))
    packs = {}
    for pkg, ver, dep in [(BASE, OLD, None), (APP, OLD, OLD), (BASE, NEW, None),
                          (APP, NEW, NEW), (APP, "2.0.1", "3.0.0"), (APP,"2.0.2",NEW)]:
        meta = dict(schema=1, id=pkg, version=ver, arch="all", compat={"steer-api": "^1.0"})
        if dep:
            meta["requires"] = {"plugins": {BASE: dep}}
            meta["permissions"] = ["fs:/fixture/"]
            meta["keep"] = [f"/fixture/{ver}.conf"]
        hook = ver == "2.0.2"
        if hook:
            meta["scripts"] = {"postinst":"postinst"}
        body = json.dumps(meta).encode()
        payload = f"{pkg} {ver}\n".encode()
        script = b'#!/bin/sh\necho "$1" >> "$STEER_PLUGIN_CONF/calls"\n'
        manifest = (f"s2p 1 {pkg} {ver} all\n{sha(body)} {len(body)} 0644 plugin.json\n"
                    f"{sha(payload)} {len(payload)} 0644 payload\n" +
                    (f"{sha(script)} {len(script)} 0755 postinst\n" if hook else "")).encode()
        files = {"plugin.json": body, "MANIFEST": manifest,
                 "MANIFEST.sig": block(key.sign(manifest)), "payload": payload}
        if hook:
            files["postinst"] = script
        path = work / f"{pkg}-{ver}.s2p"
        with tarfile.open(path, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name, content in files.items():
                entry = tarfile.TarInfo(name)
                entry.size = len(content)
                entry.mode = 0o755 if name == "postinst" else 0o644
                tar.addfile(entry, io.BytesIO(content))
        packs[pkg, ver] = path, files
    return packs


@contextmanager
def observer(path, journal):
    """Only a local ctl protocol oracle: record events and gate the health reply."""
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline().split()
            code = 0
            if line[0] == b"plugin-event":
                d = json.loads(self.rfile.read(int(line[1])))
                server.events.append((d["id"], d["version"], journal.exists()))
            if line[0] == b"plugin-reload":
                server.reloads += 1
                if server.reloads == server.reject:
                    code = 1
                if server.reloads == server.pause:
                    server.at_health.set()
                    server.resume.wait(timeout=5)
            self.wfile.write(json.dumps(dict(code=code, stdout="{}", stderr="fixture health" if code else ""))
                             .encode() + b"\n")
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        server.reloads = server.reject = server.pause = 0
        server.events = []
        server.at_health, server.resume = threading.Event(), threading.Event()
        t = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01})
        t.start()
        try:
            yield server
        finally:
            server.resume.set()
            server.shutdown()
            t.join()


def scenario(work, case):
    packs = fixtures(work)
    tree, state, keep = work/"plugins", work/"etc/state.json", work/"keep.d/plugins"
    marker = tree/".install-in-progress"
    env = dict(PATH=os.defpath, HOME=str(work), STEER_PLUGIN_INITD="", STEER_SOCKET=str(work/"ctl"),
               STEER_PLUGIN_ARCH="fixture", STEER_SPEC=str(work/"spec"))
    for k,p in dict(DIR="plugins", ETC="etc", KEYS="keys", SEED="seed", RUN="run", TMP="tmp",
                    PKG="no-pkg-manager", SYSROOT="sys", KEEPD="keep.d/plugins", SPEC="spec").items():
        env["STEER_PLUGIN_"+k] = str(work/p)

    def cmd(*args, fault="", rc=0):
        extra = {"LD_PRELOAD": "/run/cut.so", "CUT": fault} if fault else {}
        r = subprocess.run([BIN,"plugin",*args,"--json"], capture_output=True, env=env|extra, timeout=8)
        assert r.returncode == rc, (args,fault,r)
        if rc == -signal.SIGKILL:
            assert not r.stdout
            return
        result = json.loads(r.stdout)
        assert result["ok"] == (rc == 0), result
        return result

    def args(v, second=None):
        return ["install","--file",packs[BASE,v][0],"--file",packs[APP,second or v][0]]

    def contents(v, ids=IDS):
        for i in ids:
            files = {p.name:p.read_bytes() for p in (tree/i).iterdir()}
            expected = packs[i,v][1].copy()
            if v == OLD and i == APP:
                expected["local.conf"] = b"user bytes\n"
            assert files == expected
        if APP in ids:
            assert json.loads((tree/APP/"plugin.json").read_bytes())["requires"]["plugins"] == {BASE:v}

    initial = case not in ("absent","mixed")
    with observer(work/"ctl",marker) as ctl:
        if initial:
            cmd(*args(OLD))
            (tree/APP/"local.conf").write_bytes(b"user bytes\n")
            contents(OLD)
        elif case == "mixed":
            cmd("install","--file",packs[BASE,OLD][0])
        if state.exists():
            data = json.loads(state.read_bytes())
            data["unknown_legacy_field"] = ["preserve"]
            state.write_bytes(json.dumps(data,indent=2).encode())
            state.chmod(0o640)
            keep.write_bytes(b"custom keep bytes\n"); keep.chmod(0o640)
        before = [p.read_bytes() if p.exists() else None for p in (state,keep)]
        platform = work/"etc/platform.env"
        platform.parent.mkdir(exist_ok=True)
        platform.write_bytes(b"owned by platform\n")
        ctl.events.clear()
        if case == "hook":
            cmd(*args(NEW,"2.0.2"))
            assert not marker.exists() and not list(tree.glob(".group-*"))
            assert (work/"etc/conf"/APP/"calls").read_text().splitlines() == ["--check",OLD]
            assert [e["version"] for e in cmd("status")["plugins"]] == [NEW,"2.0.2"]
            record(case=case, legacy_hook="check + postinst")
            return
        if case == "duplicate":
            assert cmd("install","--file",packs[BASE,NEW][0],"--file",packs[BASE,OLD][0],
                       rc=1)["code"] == "plugin.group_duplicate"
        elif case in ("success","health"):
            if case == "success":
                ctl.pause = ctl.reloads + 2
                with subprocess.Popen([BIN,"plugin",*args(NEW),"--json"],env=env, stdout=subprocess.PIPE) as p:
                    assert ctl.at_health.wait(4)
                    assert marker.exists() and not ctl.events
                    assert cmd("list",rc=1)["code"] == "plugin.busy"
                    ctl.resume.set()
                    assert json.loads(p.communicate(timeout=5)[0])["ok"] and p.returncode == 0
                assert ctl.events == [(i,NEW,False) for i in IDS]
            else:
                ctl.reject = ctl.reloads + 2
                assert cmd(*args(NEW),rc=1)["code"] == "plugin.group_health_failed"
        elif case == "refusal":
            assert cmd(*args(NEW,"2.0.1"),rc=1)["code"] == "plugin.needs_plugin"
        elif case.startswith("error:"):
            code = {"error:place":"plugin.place_failed","error:decision":"plugin.install_degraded"}
            assert cmd(*args(NEW),fault=case,rc=1)["code"] == code.get(case,"plugin.write_failed")
            if case == "error:decision":
                assert marker.exists() and not ctl.events
                for path,_ in packs.values():
                    path.unlink()
        elif case in ("preparing","publish"):
            cmd(*args(NEW),fault=case,rc=-signal.SIGKILL)
            for path,_ in packs.values():
                path.unlink()
            assert marker.exists() and state.read_bytes() == before[0]
        else:
            step = case if case in ("state1","decision","gc") else "state2"
            cmd(*args(NEW),fault=step,rc=-signal.SIGKILL)
            assert marker.exists() and not ctl.events
            ver = [NEW, OLD if step == "state1" else NEW]
            assert [json.loads(state.read_bytes())["plugins"][i]["version"] for i in IDS] == ver
            for i,v in zip(IDS,ver):
                contents(v,[i])
            for path,_ in packs.values():
                path.unlink()
            if case == "replay":
                cmd("status",fault="restore",rc=-signal.SIGKILL)
                assert marker.exists()
            if case in ("damaged","foreign-keep","missing-marker"):
                target = (next(tree.glob(".group-*/old-fixture-app/payload")) if case == "damaged"
                          else marker if case == "missing-marker" else keep)
                original = target.read_bytes()
                if target == marker:
                    marker.unlink()
                else:
                    target.write_bytes(b"altered")
                witness = state.read_bytes()
                for action in ("status","list","migrate"):
                    assert cmd(action,rc=1)["code"] == "plugin.install_degraded"
                    assert state.read_bytes() == witness
                    assert not target.exists() if target == marker else target.read_bytes() == b"altered"
                    contents(NEW)
                target.write_bytes(original)
        d = cmd("status")
        entries = {p["id"]:p for p in d["plugins"]}
        assert not marker.exists() and not list(tree.glob(".group-*"))
        if case in ("success","decision","gc"):
            contents(NEW)
            assert all(entries[i]["version"] == NEW and entries[i]["files_ok"] for i in IDS)
        elif case == "absent":
            assert not entries and all(not (tree/i).exists() for i in IDS)
        elif case == "mixed":
            contents(OLD,[BASE])
            assert set(entries) == {BASE} and not (tree/APP).exists()
        else:
            contents(OLD)
            assert all(entries[i]["version"] == OLD and entries[i]["files_ok"] for i in IDS)
        if case in ("health","refusal"):
            assert NEW in entries[BASE]["bad_versions"] and keep.read_bytes() == before[1]
            back = json.loads(state.read_bytes())
            for i in IDS if case == "health" else (BASE,):
                assert back["plugins"][i]["bad_versions"].pop(NEW)
            assert back == json.loads(before[0])
        elif case not in ("success","decision","gc"):
            for path,orig in zip((state,keep),before):
                if orig is None:
                    assert not path.exists()
                else:
                    assert path.read_bytes() == orig and path.stat().st_mode & 0o777 == 0o640
        assert platform.read_bytes() == b"owned by platform\n"
        if case != "success":
            assert not ctl.events
        record(case=case, versions={i:p["version"] for i,p in entries.items()}, events=ctl.events,
               state_before=sha(before[0]) if before[0] is not None else None,
               state_after=sha(state.read_bytes()) if state.exists() else None)


def managed(work):
    packs = fixtures(work)
    prefix = work/"prefix"
    def run(*args, rc=0):
        r = subprocess.run([BIN,"--managed-prefix",prefix,"plugin",*args,"--json"],
                           capture_output=True, timeout=5)
        assert r.returncode == rc, r
        return json.loads(r.stdout)
    run("init")
    shutil.copy(work/"keys/plugins/fixture.pub", prefix/"keys/plugins/")
    a,b = (packs[i,OLD][0] for i in IDS)
    assert run("install","--file",a,"--file",b,rc=1)["code"] == "plugin.prefix_operation"
    run("install","--file",a)
    assert run("install","--file",b,rc=1)["code"] == "plugin.prefix_package"
    assert [(p["id"],p["version"]) for p in run("list")["plugins"]] == [(BASE,OLD)]
    run("remove",BASE)
    print("PASS managed single / refusal of multiple files")


if __name__ == "__main__":
    assert os.getpid() == 1 and os.getuid() == 65534 and socket.if_nameindex() == [(1, "lo")]
    for case in ("success","refusal","health","duplicate","hook","state1","state2","replay","decision",
                 "absent","mixed","damaged","foreign-keep","missing-marker","preparing","publish","gc",
                 "error:publish","error:state2","error:keep","error:place","error:decision"):
        with tempfile.TemporaryDirectory() as tmp:
            scenario(Path(tmp),case)
    with tempfile.TemporaryDirectory() as tmp:
        managed(Path(tmp))
