"""Приёмка G1 для net1/VLESS: ответ manager, деревья и реальный загрузчик."""
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import socketserver
import subprocess
import tarfile
import tempfile
import threading
from contextlib import contextmanager


RUN = Path("/run")
IDS = ("net1", "vless")
SO = "libs2p-net.so.1"
REL = {"net1": "lib/"+SO, "vless": "bin/vless"}
NET = {"A": "1.5.0", "B": "1.6.0"}
ABI = {"A": "1.4", "B": "1.5"}
HASH = {
    "A": ("4a49b2112a47d09a25f4957e0f0b6edc4aa4cd7a27bb5aa63d497e8e98c04be0",
          "b84d78230aebc369f9c577131a214d7540e0ffb629fd21629ead2a93e8a4bb0e"),
    "B": ("81d6a68371183727591cc782ce855c79d2e0add3ef1f7fea65629624d731fd91",
          "10b057d60bbdc21beb64d32e9a3817f94962ac1ca3f7d0f52f10818d9e3163b4"),
}


def log(**fields):
    print(json.dumps(fields, ensure_ascii=False))


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(argv, env=None, rc=0, fds=()):
    r = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=10, pass_fds=fds)
    if rc is not None:
        assert r.returncode == rc, (argv, r.returncode, r.stdout, r.stderr)
    return r


def files(d):
    return {str(p.relative_to(d)): sha(p.read_bytes()) for p in sorted(d.rglob("*")) if p.is_file()}


@contextmanager
def ctl(env, marker, pair, case):
    seen, events, busy = [], [], []
    class Handler(socketserver.StreamRequestHandler):
        def handle(self):
            line = self.rfile.readline().split()
            cmd = line[0].decode()
            seen.append((cmd,pair()))
            r = dict(v=1,cmd=cmd,code=0)
            if cmd == "plugin-reload":
                if case == "online-success" and pair() == ("B","B"):
                    for act in ("list","status"):
                        res = run(["./steerd","plugin",act,"--json"],env,1)
                        busy.append(json.loads(res.stdout)["code"])
                r.update(enabled=True,reload=dict(dnsd="none",outputs="none"),
                         changed=dict(ruleset=False,dnsd=False,routing=[],helpers=[]))
            elif cmd == "status":
                if case == "lost-status" or (case == "lost-health" and pair() == ("B","B")):
                    return
                up = case == "online-success" or pair() == ("A","A")
                body = dict(schema=1,outputs=dict(edge=dict(kind="vless",up=up)))
                r.update(stdout=json.dumps(body),stderr="")
            elif cmd == "plugin-event":
                events.append((json.loads(self.rfile.read(int(line[1])))["id"],marker.exists()))
            self.wfile.write(json.dumps(r).encode()+b"\n")
    with socketserver.UnixStreamServer(env["STEER_SOCKET"],Handler) as server:
        t = threading.Thread(target=server.serve_forever,kwargs={"poll_interval":0.01})
        t.start()
        try:
            yield
        finally:
            server.shutdown()
            t.join()
    log(case=case,ctl=seen,events=events,busy=busy)
    expect = [("A","A")]
    if case != "lost-status":
        expect.append(("B","B"))
    if case == "online-success":
        assert events == [(i,False) for i in IDS] and busy == ["plugin.busy"]*2
    else:
        assert not events
        if case != "lost-status":
            expect.append(("A","A"))
    assert [p for cmd,p in seen if cmd == "plugin-reload"] == expect
    assert list(dict.fromkeys(p for cmd,p in seen if cmd == "status")) == list(dict.fromkeys(expect))


def packages(work, case):
    key = work/"fixture"
    run(["./s2p", "keygen", "-o", key])
    public = key.with_suffix(".pub")
    packs, signed = {}, {}
    for g in NET:
        for index, i in enumerate(IDS):
            src = RUN/g/Path(REL[i]).name
            assert sha(src.read_bytes()) == HASH[g][index]
            dist, stage = work/g/"packs", work/g/i
            dist.mkdir(parents=True, exist_ok=True)
            dest = stage/REL[i]
            dest.parent.mkdir(parents=True)
            shutil.copy(src, dest)
            example = RUN/"examples"/i
            m = json.loads((example/"plugin.json").read_bytes())
            m["arch"] = ["x86_64"]
            if i == "net1":
                m["version"] = NET[g]
                m["libs"][0]["abi"] = ABI[g]
                m["compat"]["steer-crypto"] = "^2.0"  # обе локальные фикстуры на этом host
                m.pop("description")  # пример SDK описывает встроенный wolfSSL
            else:
                # Только локальный helper, без системного инсталлятора, UI и служб.
                m["version"] = "2.1.4"  # обе настоящие программы объявляют одну версию
                for field in ("ui", "i18n"):
                    del m[field]
                del m["compat"]["host-api"]
                m["requires"] = {"plugins": {"net1": "^1.4" if g == "A" else "^1.6.0"}}
                if case == "output-down":
                    m["health"]["timeout_s"] = 1
                shutil.copytree(example/"kinds", stage/"kinds")
            (stage/"plugin.json").write_text(json.dumps(m, ensure_ascii=False))
            run(["./s2p", "lint", stage, "--schema-only"])
            # SDK build для OpenWrt требует musl PT_INTERP. Эти ELF оставляем
            # неизменными: локальный host-архив v1, подпись SDK, проверка в manager.
            p = packs[g,i] = dist/f"{i}-{m['version']}-x86_64.s2p"
            body = {n:(stage/n).read_bytes() for n in files(stage)}
            mode = lambda n: 0o755 if n == REL[i] else 0o644
            text = f"s2p 1 {i} {m['version']} x86_64\n" + "".join(
                f"{sha(b)} {len(b)} {mode(n):04o} {n}\n" for n,b in body.items())
            with tarfile.open(p, "w:gz", format=tarfile.USTAR_FORMAT) as t:
                for n,b in {"plugin.json":body.pop("plugin.json"),"MANIFEST":text.encode(),
                            "MANIFEST.sig":b"",**body}.items():
                    entry = tarfile.TarInfo(n)
                    entry.size, entry.mode = len(b), mode(n)
                    t.addfile(entry, io.BytesIO(b))
            if (case,g,i) != ("unsigned","B","vless"):
                run(["./s2p", "sign", p, "--key", key.with_suffix(".sec")])
            with tarfile.open(p) as t:
                signed[g,i] = {e.name: sha(t.extractfile(e).read()) for e in t if e.isfile()}
            assert signed[g,i][REL[i]] == HASH[g][index]
            log(fixture=g, id=i, elf=HASH[g][index], archive=sha(p.read_bytes()),
                sdk_manifest=sha((example/"plugin.json").read_bytes()), public_key=sha(public.read_bytes()))
            shutil.rmtree(stage)
    key.with_suffix(".sec").unlink()
    return packs, signed, public


def scenario(case):
    with tempfile.TemporaryDirectory() as tmp:
        w = Path(tmp)
        packs, signed, pub = packages(w,case)
        tree, state = w/"installed", w/"etc/state.json"
        keys = w/"keys/plugins"
        keys.mkdir(parents=True)
        shutil.copy(pub, keys)
        env = dict(os.environ, STEER_PLUGIN_INITD="", STEER_SOCKET=str(w/"offline"), STEER_PLUGIN_ARCH="x86_64")
        for k, path in dict(DIR=tree, ETC=state.parent, KEYS=keys.parent, TMP=w/"tmp", RUN=w/"run",
                            SEED=w/"seed", KEEPD=w/"keep", SYSROOT=w/"sys", SPEC=w/"spec").items():
            env["STEER_PLUGIN_"+k] = str(path)

        def observed(argv, extra=None, rc=None):
            with tempfile.TemporaryFile("w+") as f:
                fd = f.fileno()
                e = env | {"LD_AUDIT": "/run/audit.so", "NET1_TRACE_FD": str(fd)} | (extra or {})
                r = run(argv, e, rc, (fd,))
                f.seek(0)
                maps = [line.rstrip().split("\t") for line in f]
            return r, maps

        def install(lib, app, cut=None, rc=0, mismatch=False):
            # Вход специально в обратном порядке. Менеджер сам выбирает библиотеку первой.
            trace = w/"loader"
            trace.mkdir(exist_ok=True)
            extra = {"LD_PRELOAD":"/run/cut.so","CUT":cut} if cut else {}
            if mismatch:
                extra["LD_PRELOAD"] = "/run/fingerprint.so"
            r = run(["./steerd","plugin","install","--file",packs[app,"vless"],
                     "--file",packs[lib,"net1"],"--json"]+(["--unsigned"] if case == "unsigned" else []),env | extra |
                    {"LD_DEBUG":"libs,files","LD_DEBUG_OUTPUT":str(trace/"probe")}, rc)
            maps = []
            for p in trace.iterdir():
                lines = p.read_text().splitlines()
                libs = [l.split("calling init: ")[1] for l in lines if "calling init: " in l and l.endswith(SO)]
                execs = [l.split("needed by ")[1].split(" [")[0] for l in lines
                         if f"file={SO} " in l and "needed by " in l]
                maps.extend((exe,path) for exe in execs for path in libs)
                p.unlink()
            log(case=case, install=[lib,app], rc=r.returncode, stdout=r.stdout, probe_maps=maps)
            if cut:
                assert not r.stdout
                return
            result = json.loads(r.stdout)
            assert result["ok"] == (rc == 0)
            if rc == 0 or mismatch:
                assert any(".group-txn/new-vless/" in exe and Path(path).resolve() == tree/"net1"/REL["net1"]
                           for exe,path in maps), maps
            if rc == 0:
                assert any(Path(exe) == tree/"vless"/REL["vless"] and
                           Path(path).resolve() == tree/"net1"/REL["net1"] for exe,path in maps), maps
            return result

        def get(act):
            r = run(["./steerd","plugin",act,"--json"],env,None)
            d = json.loads(r.stdout)
            assert r.returncode in (0,1) and d["ok"] == (r.returncode == 0)
            log(case=case, action=act, response=d)
            return d

        def disk():
            return {i:files(tree/i) for i in IDS}

        def pair():
            live = disk()
            return tuple(next(g for g in NET if all(live[i].get(p) == h for p,h in signed[g,i].items()))
                         for i in IDS)

        def runtime(lib, app):
            exe, so = tree/"vless/bin/vless", tree/"net1/lib"/SO
            assert pair() == (lib, app)
            # Обычный RUNPATH ELF, без LD_LIBRARY_PATH. Для hello — только
            # отсутствующий conf: процесс завершается до обслуживания трафика.
            r, maps = observed([exe], {"STEER_LIB_PROBE":"1"})
            with tempfile.TemporaryFile("w+") as hello:
                fd = hello.fileno()
                h = run([exe,"vless","fixture","--conf",w/"no-conf"], env | {"STEER_EVENT_FD":str(fd)},
                        None,(fd,))
                hello.seek(0)
                lines = hello.read().splitlines()
            log(case=case,runtime=[lib,app],map=maps,probe_rc=r.returncode,probe=(r.stdout+r.stderr).strip(),
                hello_rc=h.returncode,hello=lines)
            assert len(maps) == 1 and Path(maps[0][0]) == exe and Path(maps[0][1]).resolve() == so
            if (lib, app) == ("A","B"):
                assert r.returncode == h.returncode == 127 and not lines
                assert "s2p_transport_shutdown_write" in r.stderr and "undefined symbol" in r.stderr
            else:
                assert r.returncode == 0 and f"net1 {NET[lib]} (ABI {ABI[lib]}" in r.stdout
                assert h.returncode != 0  # hello с последующим отказом на отсутствующем conf
                assert json.loads(lines[0]) == dict(ev="hello", api="1.1", ver="2.1.4", mod="vless")

        old = "B" if case in ("success-reverse","cut-reverse","refusal") else "A"
        new = "B" if old == "A" else "A"
        install(old,old)
        (tree/"net1/local.conf").write_bytes(b"not in the signed archive\n")
        marker, txn, keep = tree/".install-in-progress", tree/".group-txn", w/"keep"
        data = json.loads(state.read_bytes())
        data["unknown_local_key"] = [1,"preserve"]
        state.write_text(json.dumps(data,indent=2))
        state.chmod(0o640)
        keep.write_bytes(b"locally edited keep\n")
        keep.chmod(0o600)
        before, orig, orig_keep = disk(), state.read_bytes(), keep.read_bytes()
        inodes = [(tree/i).stat().st_ino for i in IDS]
        runtime(old,old)
        if case == "refusal":
            # B требует ^1.6.0; реальные архивы A/B, а не искусственная поломка ELF.
            assert install(new,old,rc=1)["code"] == "plugin.needs_plugin"
        elif case == "controlled-abi-refusal":
            refused = install(new,new,rc=1,mismatch=True)
            assert refused["code"] == "plugin.lib_abi_mismatch"
            assert "3eaa55ce2b68a812" in refused["args"]["why"]
        elif case == "unsigned":
            assert install(new,new,rc=1)["code"] == "plugin.archive_unsigned"
        elif case in ("output-down","lost-status","lost-health","online-success"):
            with ctl(env,marker,pair,case):
                if case == "online-success":
                    install(new,new)
                else:
                    code = install(new,new,rc=1)["code"]
                    assert code == ("plugin.group_health_failed" if case == "output-down" else "plugin.group_reload_unconfirmed")
        elif case == "other-so":
            # Та же версия и байты B, но системный поиск выбрал чужой inode.
            env["LD_LIBRARY_PATH"] = str(RUN/new)
            assert install(new,new,rc=1)["code"] == "plugin.lib_abi_mismatch"
            del env["LD_LIBRARY_PATH"]
        elif case == "silent-probe":
            env["NET1_SILENT_EXE"] = str(tree/"vless/bin/vless")
            assert install(new,new,rc=1,mismatch=True)["code"] == "plugin.lib_abi_mismatch"
            del env["NET1_SILENT_EXE"]
        else:
            cut = {"cut-update":"state1","cut-reverse":"state1","replay":"state2","state2":"state2",
                   "damaged":"state1","decision":"decision","gc":"gc"}.get(case)
            install(new,new,cut,-signal.SIGKILL if cut else 0)
            if cut:
                assert marker.read_text().split()[1] == ("finished" if cut in ("decision","gc") else "active")
                assert pair() == (new,old if cut == "state1" else new)
                assert json.loads(state.read_bytes())["plugins"]["net1"]["version"] == NET[new]
                runtime(*pair())
        for path in packs.values():
            path.unlink()
        at_cut = state.read_bytes()
        log(case=case,before=sha(orig),before_tree=before,before_read=sha(at_cut),pair_before_read=pair(),
            marker=(tree/".install-in-progress").exists(),prev=files(tree/".prev"))
        if case == "replay":
            r = run(["./steerd","plugin","list","--json"],env | {"LD_PRELOAD":"/run/cut.so","CUT":"restore-vless"},
                    -signal.SIGKILL)
            assert not r.stdout and marker.exists()
            assert pair() == (new,old)
            log(case=case,recovery_rc=r.returncode)
        if case == "damaged":
            (txn/"old-net1/local.conf").unlink()
            evidence = files(txn)
            for act in ("list","status","status"):
                assert get(act)["code"] == "plugin.install_degraded" and files(txn) == evidence and marker.exists()
            assert state.read_bytes() == at_cut
            log(case=case,classification="explicit-degraded")
            return
        target_new = case in ("success","success-reverse","online-success","decision","gc")
        at_decision = (disk(),state.read_bytes(),keep.read_bytes())
        for act in ("list","status","status"):
            d = get(act)
            assert d["ok"] and pair() == ((new,new) if target_new else (old,old))
            entries = {p["id"]:p for p in d["plugins"]}
            assert {i:entries[i]["version"] for i in IDS} == {"net1":NET[pair()[0]],"vless":"2.1.4"}
            assert all(not p["unsigned"] and p["enabled"] for p in entries.values())
            if act == "status":
                assert all(p["files_ok"] for p in entries.values())
            assert not marker.exists() and not txn.exists()
            if target_new:
                assert (disk(),state.read_bytes(),keep.read_bytes()) == at_decision
            else:
                assert before == disk() and inodes == [(tree/i).stat().st_ino for i in IDS]
                assert keep.read_bytes() == orig_keep and keep.stat().st_mode & 0o777 == 0o600
                assert state.stat().st_mode & 0o777 == 0o640
                if case not in ("refusal","controlled-abi-refusal","output-down","other-so","silent-probe"):
                    assert orig == state.read_bytes()
        after = pair()
        runtime(*after)
        log(case=case,after_read=sha(state.read_bytes()),pair_after_read=after,trees=disk())
        if case in ("refusal","controlled-abi-refusal","output-down","other-so","silent-probe"):
            assert before == disk() and after == (old,old)
            back = json.loads(state.read_bytes())
            assert back["plugins"]["net1"]["bad_versions"].pop(NET[new])
            if case in ("output-down","other-so","silent-probe"):
                assert back["plugins"]["vless"]["bad_versions"].pop("2.1.4")
            assert back == json.loads(orig)
        log(case=case, classification="all-new" if target_new else "all-old")


if __name__ == "__main__":
    assert os.getpid() == 1 and os.getuid() == 65534 and socket.if_nameindex() == [(1,"lo")]
    manager = json.loads(run(["./steerd","version","--json"]).stdout)
    loaded = run(["./steerd"],os.environ | {"LD_TRACE_LOADED_OBJECTS":"1"}).stdout
    for so in RUN.glob("libsteer*.so.*"):
        assert f"{so.name} => {so} (" in loaded
    log(manager=manager,elf=sha((RUN/"steerd").read_bytes()),libs=loaded,
        core_libs={p.name:sha(p.read_bytes()) for p in RUN.glob("libsteer*.so.*")},
        sdk_tool=sha((RUN/"s2p").read_bytes()))
    for case in ("success","success-reverse","refusal","controlled-abi-refusal","unsigned","cut-update",
                 "cut-reverse","state2","replay","damaged","decision","gc","other-so","silent-probe",
                 "output-down","lost-status","lost-health","online-success"):
        scenario(case)
