"""Проверка отдельными процессами: настоящие архив, rename, ссылки и state.json."""

import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import tempfile


BIN = Path(sys.argv[1]).resolve()
OLD, NEW = "1.0.0", "1.1.0"


def package(file, version, *, missing_dep=False, conf=False, hook_fail=False, payload=None):
    name = "demo-old" if version == OLD else "demo-new"
    manifest = {
        "schema": 1, "id": "demo", "version": version, "arch": "all",
        "compat": {"steer-api": "^1.3"}, "permissions": ["fs:/fixture/"],
        "steer": {"links": [
            {"path": "/fixture/demo-shared", "target": name},
            {"path": f"/fixture/{name}", "target": name},
        ]},
        "keep": [f"/fixture/keep-{version}"],
    }
    if missing_dep:
        manifest["requires"] = {"plugins": {"missing": "^1.0"}}
    if conf:
        manifest["steer"]["links"].append(
            {"path": "/fixture/conf", "target": name, "mode": "conf"})
    files = {"plugin.json": json.dumps(manifest).encode(), name: (payload or version).encode()}
    if hook_fail:
        manifest["scripts"] = {"postinst": "postinst"}
        files["plugin.json"] = json.dumps(manifest).encode()
        files["postinst"] = b'#!/bin/sh\n[ "$1" = --check ]\n'
    entries = "".join(f"{hashlib.sha256(b).hexdigest()} {len(b)} "
                      f"{'0755' if n == 'postinst' else '0644'} {n}\n"
                      for n, b in files.items())
    with tarfile.open(file, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for n, b in [("plugin.json", files["plugin.json"]),
                     ("MANIFEST", f"s2p 1 demo {version} all\n{entries}".encode()),
                     ("MANIFEST.sig", b""), *((n, b) for n, b in files.items() if n != "plugin.json")]:
            member = tarfile.TarInfo(n)
            member.size = len(b)
            member.mode = 0o755 if n == "postinst" else 0o644
            tar.addfile(member, io.BytesIO(b))


class Fixture:
    def __init__(self, root):
        self.root = Path(root)
        self.env = {"PATH": os.defpath, "STEER_PLUGIN_ARCH": "fixture",
                    "STEER_PLUGIN_INITD": "", "STEER_SOCKET": str(self.root / "socket")}
        for k, p in dict(DIR="plugins", ETC="etc", KEYS="keys", SEED="seed",
                         RUN="run", TMP="tmp", KEEPD="keep.d/plugins", SYSROOT="sys",
                         PKG="no-pkg-manager", SPEC="no-spec").items():
            self.env["STEER_PLUGIN_" + k] = str(self.root / p)
        self.env["STEER_SPEC"] = str(self.root / "no-spec")
        self.marker = self.root / "plugins/.install-in-progress"
        self.state = self.root / "etc/state.json"
        for v in (OLD, NEW):
            package(self.root / v, v)

    def run(self, *args, fault=""):
        return subprocess.run([BIN, "plugin", *args, "--json"], cwd=self.root,
                              env={**self.env, "PM_TEST_FAULT": fault},
                              capture_output=True, text=True, timeout=10)

    def install(self, version, fault=""):
        return self.run("install", "--unsigned", "--file", version, fault=fault)

    def generation(self):
        entry = json.loads(self.state.read_text())["plugins"].get("demo") if self.state.exists() else None
        folder = self.root / "plugins/demo"
        links = self.root / "sys/fixture"
        keep = self.root / "keep.d/plugins"
        if entry is None:
            assert not folder.exists() and not list(links.glob("demo-*"))
            assert not keep.exists() or "/fixture/keep-" not in keep.read_text()
            return None
        version = entry["version"]
        assert version in (OLD, NEW), entry
        name = "demo-old" if version == OLD else "demo-new"
        assert json.loads((folder / "plugin.json").read_text())["version"] == version
        assert (folder / name).read_text() == version
        assert {p.name for p in links.glob("demo-*")} == {"demo-shared", name}
        assert all(p.is_symlink() and p.read_text() == version for p in links.glob("demo-*"))
        assert [p for p in keep.read_text().splitlines() if p.startswith("/fixture/keep-")] == [
            f"/fixture/keep-{version}"]
        return version


def result(r):
    assert r.stdout, (r.returncode, r.stderr)
    return json.loads(r.stdout)


def assert_degraded(r):
    assert r.returncode == 1 and result(r)["code"] == "plugin.install_degraded", (
        r.returncode, r.stdout, r.stderr)


def assert_killed(r):
    assert r.returncode == -signal.SIGKILL, (r.returncode, r.stdout, r.stderr)


def crash(f, initial, fault):
    if initial:
        assert f.install(OLD).returncode == 0 and f.generation() == OLD
        # Старые/неизвестные поля и форматирование должны пережить replay.
        data = json.loads(f.state.read_text())
        data["legacy_unknown"] = {"foo": [1, 2]}
        f.state.write_text(json.dumps(data, indent=4))
    old_state = f.state.read_bytes() if initial else None
    r = f.install(NEW, fault)
    assert_killed(r)
    reopened = f.run("status")
    assert reopened.returncode == 0 and result(reopened)["ok"], (reopened.stdout, reopened.stderr)
    assert not f.marker.exists()
    if fault == "after:commit":
        assert f.generation() == NEW
    else:
        assert f.generation() == initial
        assert (f.state.read_bytes() if f.state.exists() else None) == old_state


def io_error(f, step):
    assert f.install(OLD).returncode == 0 and f.generation() == OLD
    data = json.loads(f.state.read_text())
    data["legacy_unknown"] = "kept"
    f.state.write_text(json.dumps(data, indent=4))
    old_state = f.state.read_bytes()
    r = f.install(NEW, f"eio:{step}")
    assert r.returncode and not result(r)["ok"], (r.returncode, r.stdout)
    assert f.run("status").returncode == 0 and f.generation() == OLD
    assert not f.marker.exists()
    if step in {"marker", "prev", "place", "state", "keep"}:
        assert f.state.read_bytes() == old_state
    if step == "state":
        assert result(r)["code"] == "plugin.write_failed"
        assert NEW not in json.loads(f.state.read_text())["plugins"]["demo"]["bad_versions"]


def replay_error(f):
    assert f.install(OLD).returncode == 0
    assert_degraded(f.install(NEW, "eio-always:state"))
    assert f.marker.exists()
    assert_degraded(f.run("status", fault="eio:state"))
    assert f.marker.exists()
    assert f.run("status").returncode == 0 and f.generation() == OLD
    assert not f.marker.exists()


def replay_twice(f, step):
    assert f.install(OLD).returncode == 0
    assert_killed(f.install(NEW, "after:state"))
    assert_killed(f.run("status", fault=step))
    assert f.marker.exists()
    reopened = f.run("migrate")
    assert reopened.returncode == 1 and result(reopened)["code"] == "plugin.seed_no_index"
    assert f.run("status").returncode == 0 and f.generation() == OLD
    assert not f.marker.exists()


def unsafe(f):
    assert f.install(OLD).returncode == 0
    package(f.root / NEW, NEW, conf=True)
    assert_killed(f.install(NEW, "after:keep"))
    assert_degraded(f.run("status"))
    assert_degraded(f.run("migrate"))
    assert f.marker.exists()
    assert (f.root / "sys/fixture/conf").read_text() == NEW


def foreign(f):
    assert f.install(OLD).returncode == 0
    assert_killed(f.install(NEW, "after:state"))
    path = f.root / "sys/fixture/demo-shared"
    path.unlink()
    path.write_text("foreign")
    assert_degraded(f.run("status"))
    assert_degraded(f.run("migrate"))
    assert f.marker.exists() and path.read_text() == "foreign"


def malformed_marker(f):
    assert f.install(OLD).returncode == 0
    assert_killed(f.install(NEW, "after:state"))
    f.marker.write_text("unknown format\n")
    assert_degraded(f.run("list"))
    assert_degraded(f.run("migrate"))
    assert f.marker.read_text() == "unknown format\n"


def unreadable_state(f):
    assert f.install(OLD).returncode == 0
    f.state.unlink()
    f.state.mkdir()
    r = f.run("status")
    assert r.returncode == 1 and result(r)["code"] == "plugin.file_unreadable"


def same_version(f):
    assert f.install(OLD).returncode == 0
    assert f.run("disable", "demo").returncode == 0
    baseline = f.state.read_bytes()
    package(f.root / "same", OLD, payload="new build")
    assert_killed(f.install("same", "after:state"))
    assert (f.root / "plugins/demo/demo-old").read_text() == "new build"
    assert f.run("status").returncode == 0 and f.generation() == OLD
    assert f.state.read_bytes() == baseline
    assert json.loads(baseline)["plugins"]["demo"]["state"] == "disabled"


def legacy_conf(f):
    for v in (OLD, NEW):
        package(f.root / v, v, conf=True)
    assert f.install(OLD).returncode == 0
    path = f.root / "sys/fixture/conf"
    path.write_text("mine")
    assert f.install(NEW).returncode == 0 and f.generation() == NEW
    assert path.read_text() == "mine"


def legacy_hook(f):
    assert f.install(OLD).returncode == 0
    package(f.root / NEW, NEW, hook_fail=True)
    r = f.install(NEW)
    assert r.returncode == 1 and result(r)["code"] == "plugin.health_failed_restored"
    assert f.run("status").returncode == 0 and f.generation() == OLD
    assert NEW in json.loads(f.state.read_text())["plugins"]["demo"]["bad_versions"]


def missing_dep(f):
    assert f.install(OLD).returncode == 0
    package(f.root / NEW, NEW, missing_dep=True)
    r = f.install(NEW)
    assert r.returncode and result(r)["code"] == "plugin.needs_plugin"
    assert f.run("status").returncode == 0 and f.generation() == OLD


def legacy(f):
    assert f.install(OLD).returncode == 0
    assert f.install(NEW).returncode == 0 and f.generation() == NEW
    assert f.run("status").returncode == 0


if __name__ == "__main__":
    checks = [(fn.__name__, fn) for fn in (legacy, missing_dep, replay_error, unsafe, foreign,
                                         malformed_marker, unreadable_state, same_version,
                                         legacy_conf, legacy_hook)]
    checks += [(f"EIO {s}", lambda f, s=s: io_error(f, s))
               for s in ("marker", "prev", "place", "link", "state", "keep")]
    checks += [(f"replay {s}", lambda f, s=s: replay_twice(f, s))
               for s in ("after:unplace", "after:restore", "before:link-old", "after:state")]
    for v in (OLD, None):
        for fault in ("before:marker", "after:marker", "before:prev", "after:prev", "before:place",
                      "after:place", "before:link", "after:link", "before:state", "after:state",
                      "after:keep", "before:commit", "after:commit"):
            if v or not fault.endswith(":prev"):
                checks.append((f"{v} {fault}", lambda f, v=v, fault=fault: crash(f, v, fault)))
    failed = 0
    for name, fn in checks:
        with tempfile.TemporaryDirectory(prefix="pm-reopen-") as d:
            try:
                fn(Fixture(d))
                print(f"PASS {name}")
            except (AssertionError, OSError, KeyError) as e:
                print(f"FAIL {name}: {type(e).__name__} {e}")
                failed += 1
    sys.exit(bool(failed))
