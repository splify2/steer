#!/usr/bin/env python3
"""Compare poisoned candidate storage with the 841fa28 compiler.

Run with `make test-plan-storage`. The published base object must be present
locally, or STEER_SPEC_BASELINE must name its spec.c (its hash is checked).
No network or allocator settings are used.
"""
import json
import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
BASE = "841fa28ca72eecebeb955d6879ec814f920e479b"
PARSER = ["src/lib/ynode.c", "src/lib/err.c", "src/lib/jsonw.c",
          *["src/third_party/libyaml/" + x + ".c" for x in
            ("api", "reader", "scanner", "parser")]]


def build(directory, name, source):
    flags = ["-O2", "-g", "-std=c11", "-UNDEBUG", "-D_POSIX_C_SOURCE=200809L",
             "-DHAVE_CONFIG_H", "-I" + str(HERE), "-I" + str(ROOT / "src/lib"),
             "-I" + str(ROOT / "src/third_party/libyaml")]
    cc = shlex.split(os.environ.get("CC", "cc"))
    obj = directory / (name + ".o")
    subprocess.run(cc + flags + ["-Dmalloc=plan_test_malloc",
                   "-Dcalloc=plan_test_calloc", "-Dfree=plan_test_free",
                   "-c", str(source), "-o", str(obj)], check=True)
    executable = directory / name
    subprocess.run(cc + flags + [str(HERE / "plan_storage_probe.c"), str(obj),
                   *[str(ROOT / p) for p in PARSER], "-o", str(executable)], check=True)
    return executable


def doc():
    return {"version": 3, "plugin_remotes": {}, "plugins": {}, "inbounds": {},
            "outbounds": {"direct": {"type": "direct"}},
            "routing": {"default": "direct", "rules": []}}


def main():
    cases = [("empty", "{}"), ("broken", "{"), ("valid", json.dumps(doc()))]
    invalid = doc()
    invalid["routing"]["rules"] = [
        {"match": {}, "action": 7},
        {"name": "a", "match": {}, "action": "route"},
        {"name": "a", "match": {}, "action": "reject"}]
    cases.append(("partial-rules", json.dumps(invalid)))
    d = doc()
    d["plugin_remotes"] = {"official": {"url": "https://example.invalid", "trust": "root"}}
    d["plugins"] = {"proxy": {"remote": "official", "package": "protocols", "version": "1.0.0"}}
    d["secrets"] = {"key": {"source": "env", "name": "EXAMPLE_SECRET", "kind": "password"}}
    d["inbounds"] = {"listener": {"enabled": False, "plugin": "socks:proxy",
        "listen": {"address": "127.0.0.1", "port": 1234},
        "options": {"password": {"secret": "key"}}, "flow": ["stream"]}}
    d["dns"] = {"servers": {"local": {"type": "local"}}, "default": "local",
                "rules": [{"name": "dns-rule", "match": {}, "server": "local",
                           "strategy": "ipv4_only", "cache_timeout": "5s"}]}
    d["routing"]["rules"] = [{"name": "missing", "match": {"user": ["unknown"]},
                               "outbound": "direct"}]
    cases.append(("private-views-and-unresolved", json.dumps(d)))
    for n in (511, 512, 513):
        d = doc()
        d["outbounds"] = {f"o{i}": {"type": "direct"} for i in range(n)}
        cases.append((f"nodes-{n}", json.dumps(d)))
    for n in (1023, 1024, 1025):
        d = doc()
        d["routing"]["rules"] = [{"name": f"r{i}", "match": {}, "action": "reject"} for i in range(n)]
        cases.append((f"rules-{n}", json.dumps(d)))
    # A single 1025-element list fails invalid_rule_list before insertion.
    # Split across routing and DNS to exercise the shared rule_limit instead.
    d = doc()
    d["routing"]["rules"] = [{"name": f"r{i}", "match": {}, "action": "reject"} for i in range(1024)]
    d["dns"] = {"servers": {"local": {"type": "local"}}, "default": "local",
                "rules": [{"name": "overflow", "match": {}, "action": "reject"}]}
    cases.append(("rules-combined-overflow", json.dumps(d)))
    for n in (4094, 4095, 4096):
        d = doc()
        # Split at 4096 because list_text itself caps a single list there.
        d["routing"]["rules"] = [
            {"name": f"r{i}", "match": {"user": ["missing"] * count}, "action": "reject"}
            for i, count in enumerate((min(n, 4096), max(0, n-4096))) if count]
        cases.append((f"edges-{n}", json.dumps(d)))
    # An unavailable inventory fills the diagnostics table before reporting
    # requirement_limit; repeat the overflow case with a READY inventory below.
    for n in (681, 682, 683, 684):
        d = doc()
        d["routing"]["rules"] = [{"name": f"r{i}", "match": {
            "domain": ["example.invalid"], "network_type": ["wifi"]}, "action": "reject"}
            for i in range(n)]
        cases.append((f"requirements-{n}", json.dumps(d)))
    d = doc()
    d["routing"]["rules"] = [{"name": f"r{i}", "match": {
        "domain": ["example.invalid"], "network_type": ["wifi"]}, "action": "reject"}
        for i in range(681)]
    d["routing"]["rules"].append({"name": "last", "match": {"domain": ["example.invalid"]}, "action": "reject"})
    cases.append(("requirements-2047", json.dumps(d)))
    for n in (255, 256, 257):
        d = doc()
        d.update({f"unknown{i}": 1 for i in range(n)})
        cases.append((f"diagnostics-{n}", json.dumps(d)))
    with tempfile.TemporaryDirectory(prefix="steer-plan-test-") as tmp:
        tmp = Path(tmp)
        old = tmp / "baseline.c"
        supplied = os.environ.get("STEER_SPEC_BASELINE")
        baseline = Path(supplied).read_bytes() if supplied else subprocess.check_output(
            ["git", "-C", str(ROOT), "show", BASE + ":experimental/spec/spec.c"])
        assert hashlib.sha256(baseline).hexdigest() == \
            "55b0e7f6dc3f88488fa4970fa3e8526fe1733c6589ea343ee83d80addd2387ba"
        old.write_bytes(baseline)
        binaries = [build(tmp, "baseline", old), build(tmp, "candidate", HERE / "spec.c")]
        # Both objects share this driver; candidate malloc returns 0xa5-filled
        # storage. The baseline calloc preserves the original zero-fill.
        for name, source in cases:
            path = tmp / "input.json"
            path.write_text(source)
            outputs = [subprocess.check_output([str(binary), str(path)]) for binary in binaries]
            assert outputs[0] == outputs[1], name
            fields = outputs[1].splitlines()[0].decode().split()
            nodes, edges, requirements, diagnostics = map(int, fields[4:8])
            if name.startswith("nodes-"):
                assert nodes == min(int(name.split("-")[1]), 512), name
            if name.startswith("edges-"):
                # The routing default contributes one edge.
                assert edges == min(int(name.split("-")[1])+1, 4096), (name, edges)
                if name == "edges-4096":
                    assert b'"edge_limit"' in outputs[1]
            if name == "rules-1024":
                assert outputs[1].count(b"\nrule ") == 1024
            if name == "rules-1025":
                assert outputs[1].count(b"\nrule ") == 0
            if name == "rules-combined-overflow":
                assert outputs[1].count(b"\nrule ") == 1024
            if name.startswith("diagnostics-"):
                assert diagnostics == min(int(name.split("-")[1]), 256), name
            if name == "requirements-2047":
                assert requirements == 2047
            if name in ("requirements-682", "requirements-683"):
                assert requirements == 2048
            if name == "private-views-and-unresolved":
                assert b"4294967295" in outputs[1] and b'"dns-rule"' in outputs[1]
            print(f"PASS {name}: nodes={nodes} edges={edges} requirements={requirements} diagnostics={diagnostics}")
        for name, source in [*cases[:5], *[c for c in cases if c[0] in
                             ("requirements-683", "rules-combined-overflow")]]:
            path = tmp / "input.json"
            path.write_text(source)
            outputs = [subprocess.check_output([str(binary), str(path), "ready"]) for binary in binaries]
            assert outputs[0] == outputs[1], name
            if name == "valid":
                assert b"requirement 15 4294967295 " in outputs[1]
            if name == "requirements-683":
                assert b'"requirement_limit"' in outputs[1]
            if name == "rules-combined-overflow":
                assert b'"rule_limit"' in outputs[1]
            print("PASS ready inventory " + name)
        for binary in binaries:
            subprocess.run([str(binary), "oom"], check=True, stdout=subprocess.DEVNULL)
        print("PASS plan/source allocation failure and poisoned early return")


if __name__ == "__main__":
    main()
