"""Run via apply-rule-fault.sh, after its netns, private mounts and dummy setup."""
import json
import os
from pathlib import Path
import subprocess
import time

BIN = "/run/fixture/steerd"
OLD = Path("/tmp/active.json")
NEW = Path("/tmp/dual.json")
REG = Path("/tmp/state/registry")
FLAG = Path("/tmp/fault")
HITS = Path("/tmp/rule-fault-hit")


def run(args, code=0, **opts):
    p = subprocess.run(args, capture_output=True, text=True, timeout=30, **opts)
    assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
    return p.stdout


def spec(name, ipv6):
    return json.dumps({"version": 2, "lan": {"devices": ["lo"]},
                       "outputs": {name: {"kind": "interface", "device": "vpn0",
                                          "ipv6": ipv6, "on_fail": "drop"}},
                       "rules": [{"to": "all", "out": name}]}) + "\n"


def apply(label, path, mode="", expect=0, hits=False, only_rule=False):
    HITS.write_text("")
    args = ["apply-commit", "--rule", "dual"] if only_rule else ["apply"]
    run([BIN, *args, "--spec", path, "--state-dir", "/tmp/state"], expect,
        env=dict(os.environ, STEER_TEST_RULE_MODE=mode))
    seen = HITS.read_text().splitlines()
    assert (mode in seen) == hits, (label, seen)
    print(json.dumps(dict(case=label, exit=expect, hits=seen, registry=REG.read_text().strip())))


def main():
    assert os.readlink("/proc/self/ns/net") != os.environ["OLDNET"]
    assert os.readlink("/proc/self/ns/mnt") != os.environ["OLDMNT"]
    assert all(os.path.ismount(d) for d in ("/tmp", "/etc", "/run", "/var"))
    os.environ.update(STEER_RULE_PREF="200", STEER_NFT_TABLE="steer_fixture",
                      STEER_TEST_RULE_FAULT=str(FLAG), STEER_CTL_ENABLED="1")
    FLAG.touch()
    old, new = spec("v4", "off"), spec("dual", "nat")
    OLD.write_text(old)
    NEW.write_text(new)
    apply("ipv6:off", OLD, "rule6")
    original = REG.read_bytes()
    apply("family explicitly unavailable", NEW, "no-family6", hits=True)
    assert "fwmark" not in run(["ip", "-6", "rule"])
    apply("reset v4 fixture", OLD)
    assert REG.read_bytes() == original
    apply("CLI mandatory rule", NEW, "rule6", 1, True)
    assert REG.read_bytes() == original and OLD.read_text() == old
    tables = ["ip", "-6", "route", "show", "table", "all"]
    before = run(tables)
    apply("targeted mandatory rule", NEW, "rule6", 1, True, only_rule=True)
    assert run(tables) == before and REG.read_bytes() == original

    # A different output name makes accidental publication of the candidate
    # registry observable. The control client has its own process exit status.
    HITS.write_text("")
    sock = "/tmp/ctl.sock"
    daemon = subprocess.Popen([BIN, "ctl-serve", "--socket", sock, "--spec", OLD,
                               "--state-dir", "/tmp/state", "--lists-dir", "/tmp/lists"],
                              env=dict(os.environ, STEER_TEST_RULE_MODE="rule6"))
    try:
        for _ in range(100):
            if Path(sock).is_socket():
                break
            assert daemon.poll() is None
            time.sleep(.05)
        for code in (1, 0):
            if not code:
                FLAG.unlink()
            obj = json.loads(run([BIN, "ctl", "--socket", sock, "apply"], code, input=new))
            assert type(obj["code"]) is int and obj["code"] == code
            assert obj["applied"] is (not code) and obj["saved"] is (not code)
            assert OLD.read_text() == (old if code else new)
            assert (REG.read_bytes() == original) == bool(code)
            if code:
                assert obj["rolled_back"] is True and "rule6" in HITS.read_text().splitlines()
            print(json.dumps(dict(case="ctl apply", exit=code, response=obj,
                                  file="old" if code else "candidate", registry=REG.read_text().strip())))
    finally:
        daemon.terminate()
        daemon.wait(timeout=10)
    name, mark, table = REG.read_text().split()
    assert name == "dual"
    rule = f"fwmark 0x{int(mark, 16):x}/"
    assert rule in run(["ip", "-6", "rule"])
    assert rule in run(["ip", "-4", "rule"])
    routes = ["ip", "-6", "route", "show", "table", table]
    active = run(routes)
    assert "default dev vpn0" in active and "prohibit default" in active and "metric 65535" in active
    print(json.dumps(dict(case="positive dual stack", table=table, routes=active.splitlines())))
    # Targeted repair must not rebind even when a different rule priority is requested.
    os.environ["STEER_RULE_PREF"] = "100"
    FLAG.touch()
    old_rules = run(["ip", "-6", "rule"])
    apply("targeted rejected replacement", NEW, "rule6", 1, True, only_rule=True)
    assert run(["ip", "-6", "rule"]) == old_rules
    apply("targeted confirmed replacement", NEW, only_rule=True)
    rules = [s for s in run(["ip", "-6", "rule"]).splitlines() if rule in s]
    assert len(rules) == 1 and rules[0].startswith("100:") and run(routes) == active

    apply("unconfirmed spare prohibit", NEW, "backstop6", 1, True)
    Path("/proc/sys/net/ipv6/conf/vpn0/disable_ipv6").write_text("1")
    apply("unconfirmed fallback prohibit", NEW, "fallback6", 1, True)
    apply("device IPv4-only, confirmed fallback", NEW)
    blocked = run(routes)
    assert "default dev vpn0" in run(["ip", "-4", "route", "show", "table", table])
    assert rule in run(["ip", "-6", "rule"])
    assert blocked.count("prohibit default") == 2 and "default dev vpn0" not in blocked
    print(json.dumps(dict(case="IPv6 fallback", routes=blocked.splitlines())))

    # No IPv4 device: both CLI on_fail branches still have a required rule6.
    # Change priority so the old matching rule cannot satisfy the operation.
    os.environ["STEER_RULE_PREF"] = "75"
    for policy in ("drop", "direct"):
        candidate = json.loads(new)
        candidate["outputs"]["dual"].update(device="missing0", on_fail=policy)
        NEW.write_text(json.dumps(candidate))
        apply("missing device, " + policy, NEW, "rule6", 1, True)
        assert OLD.read_text() == new and REG.read_text().split()[0] == "dual"


if __name__ == "__main__":
    main()
