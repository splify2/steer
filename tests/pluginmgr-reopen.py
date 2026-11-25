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


def package(file, version, *, missing_dep=False, conf=False):
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
    files = {"plugin.json": json.dumps(manifest).encode(), name: version.encode()}
    entries = "".join(f"{hashlib.sha256(b).hexdigest()} {len(b)} 0644 {n}\n"
                      for n, b in files.items())
    with tarfile.open(file, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for n, b in [("plugin.json", files["plugin.json"]),
                     ("MANIFEST", f"s2p 1 demo {version} all\n{entries}".encode()),
                     ("MANIFEST.sig", b""), (name, files[name])]:
            member = tarfile.TarInfo(n)
            member.size = len(b)
            member.mode = 0o644
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
        for v in (OLD, NEW):
            package(self.root / v, v)

    def run(self, *args, fault=""):
        return subprocess.run([BIN, "plugin", *args, "--json"], cwd=self.root,
                              env={**self.env, "PM_TEST_FAULT": fault},
                              capture_output=True, text=True, timeout=10)

    def install(self, version, fault=""):
        return self.run("install", "--unsigned", "--file", version, fault=fault)

    def generation(self):
        state = self.root / "etc/state.json"
        entry = json.loads(state.read_text())["plugins"].get("demo") if state.exists() else None
        folder = self.root / "plugins/demo"
        links = self.root / "sys/fixture"
        keep = self.root / "keep.d/plugins"
        if entry is None:
            assert not folder.exists() and not list(links.glob("demo-*"))
            assert not keep.exists() or "/fixture/keep-" not in keep.read_text()
            return None
        version = entry["version"]
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


def crash(f, initial, fault):
    if initial:
        assert f.install(OLD).returncode == 0 and f.generation() == OLD
    r = f.install(NEW, fault)
    assert r.returncode == -signal.SIGKILL, (r.returncode, r.stdout, r.stderr)
    reopened = f.run("status")
    if reopened.returncode:
        assert result(reopened)["code"] == "plugin.install_degraded", result(reopened)
        migrate = f.run("migrate")
        assert migrate.returncode and result(migrate)["code"] == "plugin.install_degraded"
    else:
        assert result(reopened)["ok"]
        assert f.generation() in {initial, NEW}


def state_error(f):
    assert f.install(OLD).returncode == 0 and f.generation() == OLD
    r = f.install(NEW, "eio:state")
    assert r.returncode and not result(r)["ok"], (r.returncode, r.stdout)
    reopened = f.run("status")
    if reopened.returncode:
        assert result(reopened)["code"] == "plugin.install_degraded"
    else:
        assert f.generation() == OLD


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
    checks = [(fn.__name__, fn) for fn in (legacy, missing_dep, state_error)]
    for v in (OLD, None):
        for fault in ("before:prev", "after:prev", "after:place", "after:link",
                      "before:state", "after:state", "after:keep"):
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
