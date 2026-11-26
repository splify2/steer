#!/usr/bin/env python3
"""Local fixture tests for the conservative, read-only Gate E preflight."""
import hashlib
import json
import os
import pathlib
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
print("gate_e_preflight_test: parser acceptance, conservative block, rejection, redaction and immutability PASS")
