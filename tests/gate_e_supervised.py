#!/usr/bin/env python3
"""Disposable unprivileged Gate E supervisor: real v2.1.4/v3 binaries, no services."""
import hashlib
import json
import os
from pathlib import Path
import selectors
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parents[1]
BUNDLE = ROOT / "experimental/offline-bundle/bundle.py"
PREFLIGHT = ROOT / "tools/gate_e_preflight.py"
LEGACY_FIXTURE = ROOT / "tests/fixtures/gate-e/legacy-v2-lan.json"


def require_unprivileged():
    if os.geteuid() == 0:
        raise SystemExit("run as an unprivileged user; this fixture never needs root")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_bundle(root, label, core, state_format, state_files):
    bundle = root / ("bundle-" + label)
    (bundle / "state").mkdir(parents=True)
    shutil.copyfile(core, bundle / "core")
    (bundle / "core").chmod(0o500)
    (bundle / "state/FORMAT").write_text(state_format + "\n")
    for name, data in state_files.items():
        dest = bundle / "state" / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)
    manifest = {
        path.relative_to(bundle).as_posix(): digest(path)
        for path in bundle.rglob("*") if path.is_file()
    }
    manifest_path = root / ("manifest-" + label + ".json")
    manifest_path.write_text(json.dumps(manifest, sort_keys=True))
    return bundle, manifest_path


def bundle_cli(prefix, *args, ok=True):
    result = subprocess.run(
        [sys.executable, str(BUNDLE), "--prefix", str(prefix), *map(str, args)],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    if (result.returncode == 0) != ok:
        raise AssertionError((result.returncode, result.stdout, result.stderr))
    return result.stdout.strip()


def install(prefix, bundle, manifest):
    return bundle_cli(prefix, "install", bundle, "--manifest", manifest)


def state_dir(prefix):
    return Path(bundle_cli(prefix, "state-dir"))


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Echo:
    def __enter__(self):
        self.server = socket.socket()
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.port = self.server.getsockname()[1]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()
        return self

    def serve(self):
        self.server.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.server.accept()
            except socket.timeout:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                raise
            with conn:
                conn.settimeout(2)
                try:
                    while data := conn.recv(4096):
                        conn.sendall(data)
                except OSError:
                    pass

    def __exit__(self, *_):
        self.stop.set()
        self.server.close()
        self.thread.join(timeout=2)


def socks_roundtrip(port_num, target_port):
    with socket.create_connection(("127.0.0.1", port_num), timeout=4) as sock:
        sock.settimeout(4)
        sock.sendall(b"\x05\x01\x00")
        assert sock.recv(2) == b"\x05\x00"
        sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + target_port.to_bytes(2, "big"))
        reply = sock.recv(10)
        assert len(reply) == 10 and reply[:2] == b"\x05\x00", reply
        sock.sendall(b"supervised-clean-install")
        assert sock.recv(24) == b"supervised-clean-install"


def supervised_v3(core, state, config, control):
    proc = subprocess.Popen(
        [str(core), "--config", str(config), "--control", str(control),
         "--state-dir", str(state)],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=False,
    )
    try:
        selector = selectors.DefaultSelector()
        selector.register(proc.stdout, selectors.EVENT_READ)
        if not selector.select(timeout=8):
            raise AssertionError("v3 foreground child did not become ready")
        line = proc.stdout.readline()
        if not line.startswith(b"READY "):
            raise AssertionError("v3 foreground child did not report READY: " + line[:128].decode(errors="replace"))
        status = json.loads(line[6:])
        assert status["runtimeReady"] and status["revision"] == 1
        return proc
    except BaseException:
        proc.kill()
        proc.communicate(timeout=5)
        raise


def wait_stop(proc):
    proc.terminate()
    out, err = proc.communicate(timeout=8)
    assert proc.returncode == 0, (proc.returncode, err.decode(errors="replace"))
    assert not out and not err, (out, err)


def supervised_legacy_version(binary, state):
    # The temporary supervisor's admission contract is checked before exec.
    if (state / "FORMAT").read_text() != "steer-legacy-v2.1.4\n":
        raise RuntimeError("refusing legacy executable with foreign state format")
    return subprocess.run(
        [str(binary), "--version"], capture_output=True, text=True, check=True,
    ).stdout


def main():
    require_unprivileged()
    if len(sys.argv) != 5:
        raise SystemExit(
            "usage: gate_e_supervised.py LEGACY_STEER LEGACY_STEERD V3_STEER_PROTOTYPE WG_JOURNAL_DIR"
        )
    legacy_cli, legacy_core, v3_core = (Path(arg).resolve(strict=True) for arg in sys.argv[1:4])
    wg_journal = Path(sys.argv[4]).resolve(strict=True)
    if not wg_journal.is_dir() or any(p.is_symlink() or not p.is_file()
                                      for p in wg_journal.iterdir()):
        raise SystemExit("WG_JOURNAL_DIR must be a directory of regular, non-symlink journal records")
    with tempfile.TemporaryDirectory(prefix="steer-gate-e-supervised-") as tmp:
        root = Path(tmp)
        os.chmod(root, 0o700)

        # Existing v2.1.4 config and executable are inspected in a private
        # prefix. The exact spec bytes are passed to the CLI preflight and
        # remain unchanged; a blocked result must leave the active generation.
        legacy_prefix = root / "legacy-prefix"
        legacy_prefix.mkdir(mode=0o700)
        raw_legacy = LEGACY_FIXTURE.read_bytes()
        legacy_bundle, legacy_manifest = make_bundle(
            root, "legacy", legacy_core, "steer-legacy-v2.1.4",
            {"spec.json": raw_legacy},
        )
        legacy_generation = install(legacy_prefix, legacy_bundle, legacy_manifest)
        legacy_state = state_dir(legacy_prefix)
        legacy_spec = legacy_state / "spec.json"
        immutable_hash = digest(legacy_spec)
        active_before = bundle_cli(legacy_prefix, "status")
        version = subprocess.run(
            [str(legacy_prefix / "active/core"), "--version"],
            capture_output=True, text=True, check=True,
        ).stdout.strip()
        assert "2.1.4" in version, version
        preflight = subprocess.run(
            [sys.executable, str(PREFLIGHT), "--steer", str(legacy_cli), "--spec", str(legacy_spec)],
            capture_output=True, text=True, check=False,
        )
        report = json.loads(preflight.stdout)
        assert preflight.returncode == 1, (preflight.returncode, report)
        assert report["status"] == "blocked"
        assert report["source_sha256"] == immutable_hash
        assert report["input_unchanged"] is True and digest(legacy_spec) == immutable_hash
        assert "lan_capture" in {item["semantic"] for item in report["blocking_semantics"]}
        assert "rules" in {item["semantic"] for item in report["blocking_semantics"]}
        assert bundle_cli(legacy_prefix, "status") == active_before == legacy_generation
        print("PASS v2.1.4 exact-byte preflight blocks LAN capture before any generation switch")

        # Fresh, independent v3 install: no legacy spec/config is copied. This
        # child-only supervisor starts the actual v3 binary and loopback SOCKS;
        # it never registers with systemd or touches nft/routing.
        clean_prefix = root / "clean-v3-prefix"
        clean_prefix.mkdir(mode=0o700)
        socks_port = port()
        intent = {
            "version": 3,
            "plugin_remotes": {
                "local": {"url": "https://github.com/splify2/steer-protocols",
                          "trust": "steer-linked-prototype-v1"}
            },
            "plugins": {
                "proxy": {"remote": "local", "package": "steer-protocols", "version": "0.0.0"}
            },
            "secrets": {},
            "inbounds": {
                "socks-local": {"plugin": "socks:proxy", "options": {},
                                "listen": {"address": "127.0.0.1", "port": socks_port}}
            },
            "outbounds": {"internet": {"type": "direct"}, "deny": {"type": "block"}},
            "routing": {
                "default": "deny",
                "rules": [{"name": "socks-local", "match": {"inbound": ["socks-local"]},
                           "outbound": "internet"}],
            },
        }
        clean_bundle, clean_manifest = make_bundle(
            root, "clean-v3", v3_core, "steer-prototype-v3-store-v1",
            {"intent.json": json.dumps(intent, separators=(",", ":")).encode()},
        )
        install(clean_prefix, clean_bundle, clean_manifest)
        clean_state = state_dir(clean_prefix)
        config = clean_state / "intent.json"
        control = root / "clean-v3.sock"
        with Echo() as echo:
            proc = supervised_v3(clean_prefix / "active/core", clean_state, config, control)
            try:
                socks_roundtrip(socks_port, echo.port)
            finally:
                wait_stop(proc)
        snapshot = json.loads((clean_state / "config.json").read_text())
        assert snapshot["format"] == "steer-spec-v3"
        print("PASS supervised clean v3 prefix starts real binary, persists v3 state, and relays loopback SOCKS")

        # Isolated compatibility-pair canary, not migration: the v3 journal
        # stays in its own generation; rollback selects the real v2.1.4 binary
        # with its legacy state directory. No legacy intent is copied to v3.
        pair_prefix = root / "artifact-pair-prefix"
        pair_prefix.mkdir(mode=0o700)
        a_bundle, a_manifest = make_bundle(
            root, "pair-v2", legacy_core, "steer-legacy-v2.1.4",
            {"spec.json": b'{"version":2}'},
        )
        a_generation = install(pair_prefix, a_bundle, a_manifest)
        a_state = state_dir(pair_prefix)
        assert "2.1.4" in supervised_legacy_version(pair_prefix / "active/core", a_state)
        b_bundle, b_manifest = make_bundle(
            root, "pair-v3", v3_core, "steer-prototype-v3-linked-wg-v1",
            {"intent.json": json.dumps(intent, separators=(",", ":")).encode(),
             **{"wg-linked-journal/" + p.name: p.read_bytes() for p in wg_journal.iterdir()}},
        )
        install(pair_prefix, b_bundle, b_manifest)
        b_state = state_dir(pair_prefix)
        assert b_state != a_state
        assert len(list((b_state / "wg-linked-journal").iterdir())) >= 2
        # A supervisor must reject the new state before execing the legacy image.
        assert (b_state / "FORMAT").read_text() != "steer-legacy-v2.1.4\n"
        try:
            supervised_legacy_version(legacy_core, b_state)
        except RuntimeError as exc:
            assert str(exc) == "refusing legacy executable with foreign state format"
        else:
            raise AssertionError("legacy process supervisor accepted v3 WG state")
        assert bundle_cli(pair_prefix, "rollback") == a_generation
        assert state_dir(pair_prefix) == a_state
        assert not (a_state / "wg-linked-journal").exists()
        assert len(list((b_state / "wg-linked-journal").iterdir())) >= 2
        assert "2.1.4" in supervised_legacy_version(pair_prefix / "active/core", state_dir(pair_prefix))
        print("PASS offline rollback restores v2 executable+legacy state; serialized v3 WG journal stays isolated")


if __name__ == "__main__":
    main()
