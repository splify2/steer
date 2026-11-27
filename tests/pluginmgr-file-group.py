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
import time
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
            if not line:
                return
            code = 0
            if line[0] == b"plugin-event":
                d = json.loads(self.rfile.read(int(line[1])))
                server.events.append((d["id"], d["version"], journal.exists()))
            if line[0] == b"plugin-reload":
                server.reloads += 1
                server.observed.append(tuple(
                    json.loads(p.read_bytes())["version"] if p.exists() else None
                    for p in (journal.parent/i/"plugin.json" for i in IDS)))
                if server.reloads == server.reject:
                    code = 1
                if server.reloads == server.pause:
                    server.at_health.set()
                    server.resume.wait(timeout=5)
                reply = dict(v=1,cmd="plugin-reload",code=code,enabled=True,
                             reload=dict(dnsd="none",outputs="none"),
                             changed=dict(ruleset=False,routing=[],helpers=[],dnsd=False))
                if code:
                    reply.update(stderr="fixture health")
                mode = server.replies.get(server.reloads)
                if mode == "lost":
                    return  # запрос прочитан, listener остаётся на месте
                if mode == "partial":
                    self.wfile.write(json.dumps(reply).encode())  # EOF без LF
                    return
                if mode == "unknown":
                    reply = dict(v=1,error="unknown-command",code="ctl.unknown_command")
                if mode == "bare":
                    reply = dict(code=0)
                if mode == "wrong":
                    reply.update(cmd="status")
                if mode == "truncated":
                    reply.update(truncated=True)
                if mode == "incomplete":
                    del reply["changed"]
                if mode == "malformed":
                    self.wfile.write(json.dumps(reply).encode()[:-1]+b",}\n")
                    return
                if mode == "config":
                    reply.update(code=1,stderr="invalid fixture spec")
                if mode == "changed-error":
                    reply.update(code=2,stderr="invalid fixture spec")
            else:
                reply = dict(code=0,stdout="{}")
            self.wfile.write(json.dumps(reply).encode()+b"\n")
    with socketserver.UnixStreamServer(str(path), Handler) as server:
        server.reloads = server.reject = server.pause = 0
        server.events = []
        server.replies, server.observed = {}, []
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
        start = ctl.reloads
        ctl.observed.clear()
        def readback(v):
            for action in ("status","list"):
                assert {p["id"]:p["version"] for p in cmd(action)["plugins"]} == {i:v for i in IDS}
                contents(v)
            assert not marker.exists() and not list(tree.glob(".group-*"))

        if case == "real-ctl":
            path = work/"daemon.sock"
            env.update(STEER_SOCKET=str(path), STEER_CTL_ENABLED="0", STEER_PLUGIN_AUTO="0",
                       STEER_PLUGINS_ROOT=str(tree), STEER_PLUGINS_ETC=str(state.parent))
            (work/"spec").write_text("version: 2\noutputs:\n  d: { kind: direct }\n")
            (work/"daemon-state").mkdir()
            with subprocess.Popen([BIN,"daemon","--socket",path,"--allow-uid",str(os.getuid()),
                                   "--spec",work/"spec","--state-dir",work/"daemon-state"],
                                  env=env,stderr=subprocess.PIPE) as p:
                try:
                    for _ in range(100):
                        if path.is_socket() or p.poll() is not None:
                            break
                        time.sleep(.02)
                    assert path.is_socket(), p.poll()
                    cmd(*args(NEW))
                    readback(NEW)
                finally:
                    p.terminate()
                    p.communicate(timeout=5)
            record(case=case,versions=[NEW,NEW])
            return
        if case.startswith(("pre:","post:")) or case in ("config","config-changed","config-lost","rollback-lost"):
            mode = case.partition(":")[2]
            post = not case.startswith("pre:")
            ctl.replies[start + (2 if post else 1)] = mode
            if case.startswith("config"):
                ctl.replies.update({start+1:"config",start+2:{"config":"config","config-lost":"lost",
                                                             "config-changed":"changed-error"}[case]})
            if case == "rollback-lost":
                ctl.replies.update({start+2:"lost",start+3:"partial",start+4:"unknown"})
            code = ("plugin.install_degraded" if case == "rollback-lost" else
                    "plugin.group_health_failed" if case == "config-changed" else "plugin.group_reload_unconfirmed")
            rc = int(case != "config")
            result = cmd(*args(NEW),rc=rc,fault="publish" if not post else "")
            if rc:
                assert result["code"] == code
            for path,_ in packs.values():
                path.unlink()
            if case == "rollback-lost":
                assert marker.exists() and cmd("status",rc=1)["code"] == "plugin.install_degraded"
                assert marker.exists()
            readback(OLD if rc else NEW)
            if rc and case != "config-changed":
                assert before == [state.read_bytes(),keep.read_bytes()]
            assert ctl.events == ([] if rc else [(i,NEW,False) for i in IDS])
            expected = [(OLD,OLD)] + ([(NEW,NEW)] if post else [])
            if post and rc:
                expected.extend([(OLD,OLD)]*(3 if case == "rollback-lost" else 1))
            assert ctl.observed == expected, ctl.observed
            record(case=case,code=result.get("code"),observed=ctl.observed,events=ctl.events)
            return
        if case in ("offline","owner-running","owner-starting","stale","replay-owner"):
            path = work/"ctl"
            if case == "replay-owner":
                cmd(*args(NEW),fault="state2",rc=-signal.SIGKILL)
                for archive,_ in packs.values():
                    archive.unlink()
            path.rename(work/"original")
            if case == "replay-owner":
                for _ in range(2):
                    assert cmd("status",rc=1)["code"] == "plugin.install_degraded" and marker.exists()
                    contents(OLD)
                with observer(path,marker) as other:
                    assert cmd("list",rc=1)["code"] == "plugin.install_degraded" and marker.exists()
                    env["STEER_SOCKET"] = str(work/"original")
                    assert cmd("list",rc=1)["code"] == "plugin.install_degraded" and marker.exists()
                    env["STEER_SOCKET"] = str(path)
                    assert not other.observed and not other.events
                path.unlink()
                assert ctl.observed == [(OLD,OLD)]
            elif case == "stale":
                with socket.socket(socket.AF_UNIX) as sock:
                    sock.bind(str(path))
                assert cmd(*args(NEW),rc=1)["code"] == "plugin.group_reload_unconfirmed"
                path.unlink()
            else:
                init = work/"initd"
                init.write_text("#!/bin/sh\n[ \"$1\" = running ] || exit 9\nexit "+
                                ("0\n" if case == "owner-running" else "1\n"))
                if case == "owner-starting":
                    init.write_text('#!/bin/sh\n[ "$1" = running ] || exit 9\n'
                                    '[ -f "$HOME/started" ] && exit 0\ntouch "$HOME/started"\nexit 1\n')
                init.chmod(0o755)
                env["STEER_PLUGIN_INITD"] = str(init)
                rc = int(case != "offline")
                result = cmd(*args(NEW),rc=rc)
                if rc:
                    assert result["code"] == "plugin.group_reload_unconfirmed"
            (work/"original").rename(path)
            readback(NEW if case == "offline" else OLD)
            assert not ctl.events
            if case != "offline":
                assert before == [state.read_bytes(),keep.read_bytes()]
            if case == "replay-owner":
                assert ctl.observed == [(OLD,OLD)]*2
            record(case=case,observed=ctl.observed,events=ctl.events)
            return
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
                 "error:publish","error:state2","error:keep","error:place","error:decision",
                 "pre:lost","pre:partial","pre:bare","post:lost","post:partial","post:unknown",
                 "post:wrong","post:bare","post:truncated","post:incomplete","post:malformed",
                 "config","config-changed","config-lost","rollback-lost","replay-owner","offline",
                 "owner-running","owner-starting","stale","real-ctl"):
        with tempfile.TemporaryDirectory() as tmp:
            scenario(Path(tmp),case)
    with tempfile.TemporaryDirectory() as tmp:
        managed(Path(tmp))
