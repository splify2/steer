#!/usr/bin/env python3
"""Local fixture tests for the conservative, read-only Gate E preflight."""
import hashlib
import json
import os
import pathlib
import stat
import subprocess
import sys
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFLIGHT = ROOT / "tools/gate_e_preflight.py"
STEER = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "build/steer"


def run(text):
    with tempfile.TemporaryDirectory(prefix="gate-e-preflight-") as td:
        spec = pathlib.Path(td) / "input.yaml"
        spec.write_text(text, encoding="utf-8")
        original = spec.read_bytes()
        result = subprocess.run(
            [sys.executable, str(PREFLIGHT), "--steer", str(STEER), "--spec", str(spec)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=False,
        )
        report = json.loads(result.stdout)
        assert spec.read_bytes() == original
        assert report["source_sha256"] == hashlib.sha256(original).hexdigest()
        assert report["input_unchanged"] is True
        assert report["preflight_only"] is True
        assert report["conversion_performed"] is False
        return result.returncode, report, result.stdout


rc, report, _ = run('{"version":2}')
assert rc == 0
assert report["status"] == "preflight_subset"
assert report["target_profile"] == "linked-socks-v1-loopback"
assert report["supported_semantics"] == ["empty_no_route_intent", "legacy_v2_schema"]
assert report["blocking_semantics"] == []

rc, report, _ = run('{"version":2,"lan":{}}')
assert rc == 1
assert "lan_capture" in {item["semantic"] for item in report["blocking_semantics"]}

legacy = json.dumps({
    "version": 2,
    "lan": {"devices": ["br-lan"]},
    "outputs": {
        "direct": {"kind": "direct"},
        "vpn": {"kind": "interface", "device": "wg0"},
    },
    "rules": [{"name": "lan-all", "to": "all", "out": "vpn"}],
})
rc, report, _ = run(legacy)
assert rc == 1
assert report["status"] == "blocked"
assert {item["semantic"] for item in report["blocking_semantics"]} == {
    "lan_capture", "rules", "outputs"
}

secret = "TOP-SECRET-fixture-value"
rc, report, serialized = run(json.dumps({
    "version": 2,
    "outputs": {
        "remote": {
            "kind": "tunnel",
            "protocol": "vless",
            "subscription": f"https://user:{secret}@example.invalid/sub",
        }
    },
    "dns": {"mode": "fakeip"},
}))
assert rc == 1
assert report["status"] == "blocked"
assert {item["semantic"] for item in report["blocking_semantics"]} == {
    "lan_capture", "outputs", "dns"
}
assert secret not in serialized

rc, report, serialized = run('{"version":2,"unexpected_future_key":true}')
assert rc == 2
assert report["status"] == "rejected"
assert report["blocking_semantics"] == [
    {"code": "legacy_parser_rejected", "semantic": "document"}
]
assert "unexpected_future_key" not in serialized

rc, report, _ = run("version: 2\n")
assert rc == 2
assert report["blocking_semantics"] == [
    {"code": "source_format_not_exactly_inspectable", "semantic": "document"}
]


def changed_source(mode):
    with tempfile.TemporaryDirectory(prefix="gate-e-preflight-race-") as td:
        root = pathlib.Path(td)
        spec = root / "input.json"
        replacement = root / "replacement.json"
        capture = root / "parser-input.bin"
        cli = root / "snapshot-cli"
        original = b'{"version":2}'
        replacement_bytes = b'{"version":2,"private-source-value":"must-not-leak"}'
        spec.write_bytes(original)
        replacement.write_bytes(replacement_bytes)
        cli.write_text(
            f"""#!{sys.executable}
import json, os, pathlib, sys
if len(sys.argv) == 2:
    print("snapshot-test-cli")
    raise SystemExit(0)
raw = sys.stdin.buffer.read()
pathlib.Path({str(capture)!r}).write_bytes(raw)
if {mode!r} == "replace":
    os.replace({str(replacement)!r}, {str(spec)!r})
else:
    os.unlink({str(spec)!r})
sys.stdout.buffer.write(raw)
""",
            encoding="utf-8",
        )
        cli.chmod(cli.stat().st_mode | stat.S_IXUSR)
        env = dict(os.environ, TMPDIR=td)
        result = subprocess.run(
            [sys.executable, str(PREFLIGHT), "--steer", str(cli), "--spec", str(spec)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
            check=False,
        )
        report = json.loads(result.stdout)
        assert result.returncode == 2
        assert report["status"] == "rejected"
        assert report["source_sha256"] == hashlib.sha256(original).hexdigest()
        assert report["input_unchanged"] is False
        assert report["blocking_semantics"] == [
            {"code": "input_changed", "semantic": "source"}
        ]
        assert capture.read_bytes() == original
        assert "private-source-value" not in result.stdout
        assert result.stderr == ""
        expected = {cli.name, capture.name}
        if mode == "replace":
            expected.add(spec.name)
            assert spec.read_bytes() == replacement_bytes
        else:
            expected.add(replacement.name)
            assert not spec.exists()
        assert {path.name for path in root.iterdir()} == expected


changed_source("replace")
changed_source("delete")
print("gate_e_preflight_test: parser acceptance, conservative block, rejection, redaction and immutability PASS")
