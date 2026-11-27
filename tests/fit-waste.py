"""Black-box fit accounting. Bounded fixtures use sets of individual addresses."""
import ipaddress as ip
import json
import os
from pathlib import Path
import random
import subprocess
import tempfile


BIN = os.environ.get("STEER", "./build/steer")
BASE = ip.IPv4Address("192.0.2.0")


def lines(spans):
    return [str(BASE + a) if a == b else f"{BASE + a}-{BASE + b}" for a, b in spans]


def cells(rows):
    result = set()
    for row in rows:
        if "-" in row:
            a, b = map(ip.IPv4Address, row.split("-"))
            result.update(range(int(a), int(b) + 1))
        else:
            result.update(map(int, ip.IPv4Network(row)))
    return result


def run(src, budget, levels, *extra):
    cmd = [BIN, "fit", "--budget", str(budget), "--levels", levels, *extra]
    r = subprocess.run(cmd, input="\n".join(src) + "\n", text=True, capture_output=True, timeout=5)
    assert r.returncode in (0, 1), (cmd, r.returncode, r.stderr)
    report = json.loads(r.stderr)
    assert report["fits"] == (r.returncode == 0)
    return r.stdout.splitlines(), report


def check(src, budget, levels, *extra):
    rows, r = run(src, budget, levels, *extra)
    before, after = cells(src), cells(rows)
    assert before <= after and not r["truncated"], (src, rows, r)
    assert r["waste_addresses"] == len(after - before), (src, levels, rows, r, len(after - before))
    assert r["kept"] == len(rows) and r["fits"] == (budget == 0 or len(rows) <= budget)
    return rows, r


def main():
    both = [(8, 18), (22, 22), (25, 25), (28, 36)]
    for spans, expected, delta in [
        ([(17, 17), (20, 20)], "192.0.2.16/28", 14),
        (both[:3], "192.0.2.8-192.0.2.31", 11),
        ([(17, 17), (20, 20), (26, 36)], "192.0.2.16-192.0.2.36", 8),
        (both, "192.0.2.8-192.0.2.36", 7),
    ]:
        rows, r = check(lines(spans), 1, "28:2")
        assert rows == [expected] and r["waste_addresses"] == delta

    # Duplicate, nested and adjacent inputs contribute only once. Stop at the
    # first rung that fits, or widen again; later rungs include earlier widening.
    src = lines(both + [(8, 18), (10, 12), (53, 53), (54, 54), (57, 57)])
    for budget, level, kept, delta in [(2, 28, 2, 20), (1, 26, 1, 39)]:
        _, r = check(src, budget, "28:2 26:2")
        assert (r["level"], r["kept"], r["waste_addresses"]) == (level, kept, delta)
    for budget, levels in [(0, "28:2"), (6, "28:2"), (1, "32:2")]:
        assert check(src, budget, levels)[1]["waste_addresses"] == 0
    # Widening singletons can cost addresses without changing element count.
    _, r = check(lines([(1, 1), (33, 33)]), 1, "28:1")
    assert not r["fits"] and r["waste_addresses"] == 30

    src = lines([(1, 1)] + both)
    with tempfile.TemporaryDirectory() as tmp:
        excl, punch = Path(tmp)/"exclude", Path(tmp)/"punch"
        excl.write_text("192.0.2.19\n192.0.2.22\n192.0.2.40\n")
        assert check(src, 1, "28:2", "--exclude", excl)[1]["waste_addresses"] == 0
        args = ["--exclude", excl, "--punch-out", punch]
        _, full = check(src, 1, "28:2", *args)
        assert not full["fits"] and full["waste_addresses"] == 7
        for trunc in (False, True):
            rows, r = run(src + ["2001:db8::/64", "bad"], 1, "28:2", *args,
                          *(["--truncate"] if trunc else []))
            assert not r["fits"] and r["truncated"] == trunc and r["malformed"] == r["v6"] == 1
            assert r["waste_addresses"] == full["waste_addresses"] and r["punched"] == 2
            assert punch.read_text() == "192.0.2.19\n192.0.2.22\n"
            assert rows[-1] == "2001:db8::/64"
            if trunc:
                # All the added addresses were in the discarded tail.
                assert rows[:-1] == ["192.0.2.1"] and r["covered_through"] == rows[0]

    # Expanding two /1 candidates and merging leaves 2**32 covered, not zero.
    rows, r = run(["0.0.0.0", "127.255.255.255", "128.0.0.1", "255.255.255.255"], 1, "1:2")
    assert rows == ["0.0.0.0/0"] and r["waste_addresses"] == 2**32 - 4
    rows, r = run(["0.0.0.0/0", "255.255.255.255"], 1, "1:1")
    assert rows == ["0.0.0.0/0"] and r["waste_addresses"] == 0

    rng = random.Random(7300)
    for _ in range(100):
        spans = [(a, a + rng.randrange(10)) for a in rng.choices(range(240), k=rng.randrange(3, 24))]
        check(lines(spans), rng.randrange(1, 7), "30:2 28:2 26:3 24:4")
    print("fit-waste: union oracle, overlap, levels, pre-truncate and /0 passed")


if __name__ == "__main__":
    main()
