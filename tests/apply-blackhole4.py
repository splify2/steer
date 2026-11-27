"""RULE_TEST_MODE=blackhole4 sh tests/apply-rule-fault.sh (private net/mount ns)."""
import json
import os
from pathlib import Path
import subprocess
import time

BIN = "/run/fixture/steerd"
REG = Path("/tmp/state/registry")
ACTIVE = Path("/tmp/active.json")
CAND = Path("/tmp/candidate.json")
HITS = Path("/tmp/rule-fault-hit")
FLAG = Path("/tmp/fault")
SOCK = "/tmp/ctl.sock"
errors = []


def spec(name, dev, policy="drop"):
    return json.dumps({"version": 2, "lan": {"devices": ["lo"]},
                       "outputs": {name: {"kind": "interface", "device": dev, "ipv6": "off", "on_fail": policy}},
                       "rules": [{"to": "all", "out": name}]}) + "\n"


def invoke(args, mode="", text=None):
    HITS.write_text("")
    return subprocess.run([BIN, *args], input=text, capture_output=True, text=True, timeout=30,
                          env=dict(os.environ, STEER_TEST_RULE_MODE=mode))


def apply(path, *cmd, mode=""):
    return invoke([*cmd, "--spec", path, "--state-dir", "/tmp/state"], mode)


def routes(table):
    return subprocess.check_output(["ip", "-4", "route", "show", "table", table], text=True).splitlines()


def report(case, p, expected, ok, **info):
    print(json.dumps(dict(case=case, exit=p.returncode, expected=expected, hits=HITS.read_text().splitlines(),
                          registry=REG.read_text().splitlines(), **info)))
    if p.returncode != expected or not ok:
        errors.append(case)
        print(p.stderr)


def main():
    assert all(os.path.ismount(d) for d in ("/etc", "/tmp", "/run", "/var"))
    for ns in ("net", "mnt"):
        assert os.readlink("/proc/self/ns/" + ns) != os.environ["OLD" + ns.upper()]
    os.environ.update(STEER_CTL_ENABLED="1", STEER_NFT_TABLE="steer_fixture", STEER_TEST_RULE_FAULT=str(FLAG))
    FLAG.touch()
    old = spec("original", "vpn0", "direct")
    ACTIVE.write_text(old)
    args = ["apply-commit", "--route", "candidate"]
    for dev, policy, mode, cmd, code in [
        ("vpn0", "drop", "backstop4", ["apply"], 1),
        ("missing0", "drop", "fallback4", ["apply"], 1),
        ("missing0", "drop", "backstop4", args, 1),
        ("vpn0", "drop", "backstop4", args, 1),
        ("vpn0", "drop", "fallback4", ["apply"], 0),
        ("missing0", "drop", "", ["apply"], 0),
        ("vpn0", "drop", "", args, 0),
        ("missing0", "direct", "fallback4", ["apply"], 0),
    ]:
        assert apply(ACTIVE, "apply").returncode == 0
        reg = REG.read_bytes()
        assert reg.split()[0] == b"original"
        CAND.write_text(spec("candidate", dev, policy))
        p = apply(CAND, *cmd, mode=mode)
        hit = HITS.read_text().splitlines()
        required = policy == "drop" and (mode == "backstop4" or (mode == "fallback4" and dev == "missing0"))
        ok = bool(hit) == required and all(op == mode for op in hit)
        ok &= ACTIVE.read_text() == old and (REG.read_bytes() == reg if code else REG.read_text().split()[0] == "candidate")
        # Single-output fixtures reuse the table; the registry name distinguishes generations.
        rows = routes(reg.decode().split()[2])
        if dev == "vpn0" and policy == "drop":
            ok &= any("default dev vpn0" in r for r in rows) and not any(r.startswith("blackhole default") and "metric" not in r for r in rows)
        if not code and policy == "drop":
            ok &= any(r.startswith("blackhole default") and "metric 65535" in r for r in rows)
            if dev == "missing0":
                ok &= any(r.startswith("blackhole default") and "metric" not in r for r in rows)
        if not code and policy == "direct":
            ok &= not rows
        report(f"{cmd[0]} {dev} {policy} {mode}", p, code, ok, routes=rows)

    # Targeted --rule does not promise a route and must not attempt to replace one.
    CAND.write_text(spec("candidate", "vpn0"))
    assert apply(CAND, "apply").returncode == 0
    reg = REG.read_bytes()
    table = reg.decode().split()[2]
    before = routes(table)
    p = apply(CAND, "apply-commit", "--rule", "candidate", mode="backstop4")
    report("rule-only leaves routes alone", p, 0, not HITS.read_text() and REG.read_bytes() == reg and routes(table) == before)

    for dev, mode in (("vpn0", "backstop4"), ("missing0", "fallback4")):
        ACTIVE.write_text(old)
        assert apply(ACTIVE, "apply").returncode == 0
        reg = REG.read_bytes()
        new = spec("candidate", dev)
        daemon = subprocess.Popen([BIN, "ctl-serve", "--socket", SOCK, "--spec", ACTIVE,
                                   "--state-dir", "/tmp/state", "--lists-dir", "/tmp/lists"],
                                  env=dict(os.environ, STEER_TEST_RULE_MODE=mode))
        try:
            for _ in range(100):
                if Path(SOCK).is_socket():
                    break
                assert daemon.poll() is None
                time.sleep(.05)
            for code in (1, 0):
                if not code:
                    FLAG.unlink()
                p = invoke(["ctl", "--socket", SOCK, "apply"], text=new)
                obj = json.loads(p.stdout)
                ok = type(obj["code"]) is int and obj["code"] == code
                ok &= obj["applied"] is (not code) and obj["saved"] is (not code)
                ok &= ACTIVE.read_text() == (old if code else new)
                if code:
                    ok &= REG.read_bytes() == reg and obj.get("rolled_back") is True and mode in HITS.read_text().splitlines()
                else:
                    ok &= REG.read_text().split()[0] == "candidate" and not HITS.read_text()
                status = {k: obj[k] for k in ("code", "saved", "applied", "rolled_back") if k in obj}
                report(f"ctl {dev} {mode}", p, code, ok, response=status, old_file=ACTIVE.read_text() == old)
        finally:
            daemon.terminate()
            daemon.wait(timeout=10)
            FLAG.touch()
    # Named manual group: fo_fail_apply directly, without a failed device bind.
    group = json.loads(spec("up", "vpn0"))
    group["outputs"]["down"] = dict(kind="interface", device="missing0", ipv6="off", on_fail="direct")
    group["outputs"]["man"] = dict(kind="group", pick="manual", members=["up", "down"], default="up", on_fail="drop")
    group["rules"][0]["out"] = "man"
    CAND.write_text(json.dumps(group))
    assert apply(CAND, "apply").returncode == 0
    for member, mode in (("down", "fallback4"), ("up", "backstop4")):
        files = [Path("/tmp/select"), Path("/tmp/state/active"), Path("/tmp/state/groups")]
        before = [f.read_bytes() if f.exists() else None for f in files]
        p = apply(CAND, "select", "man", member, mode=mode)
        unchanged = before == [f.read_bytes() if f.exists() else None for f in files]
        report(f"select {member} {mode}", p, 1, unchanged and mode in HITS.read_text().splitlines())
        p = apply(CAND, "select", "man", member)
        report(f"select {member} retry", p, 0, f"man {member}" in files[0].read_text())
        if member == "down":
            reg = REG.read_bytes()
            p = apply(CAND, "apply-commit", "--route", "man", mode=mode)
            report("targeted failed group", p, 1, mode in HITS.read_text().splitlines() and REG.read_bytes() == reg)
    assert not errors, errors


if __name__ == "__main__":
    main()
