#!/usr/bin/env python3
"""Проверка независимых кругов замера по наблюдениям HTTP-ответчика."""
import collections
import sys

MEMBERS = {"10.9.1.1", "10.9.2.1"}


def verify(rows, rounds):
    if any(addr not in MEMBERS for _, addr in rows):
        return False, "неизвестный адрес члена"
    rows = sorted(rows)
    groups = []
    for ts, addr in rows:
        if not groups or ts - groups[-1][-1][0] > 4_000_000_000:
            groups.append([])
        groups[-1].append((ts, addr))
    summary = []
    for group in groups:
        counts = collections.Counter(addr for _, addr in group)
        span = (group[-1][0] - group[0][0]) / 1e9
        summary.append(f"{group[0][0] / 1e9:.3f}s {dict(counts)} span={span:.3f}s")
        if counts != {addr: 3 for addr in MEMBERS} or span > 3:
            return False, "неполный или растянутый круг: " + "; ".join(summary)
    if len(groups) != rounds:
        return False, f"кругов {len(groups)}, ожидалось {rounds}: " + "; ".join(summary)
    gaps = [(groups[i][0][0] - groups[i - 1][0][0]) / 1e9 for i in range(1, len(groups))]
    if any(not 7 <= gap <= 14 for gap in gaps):
        return False, f"неверные интервалы {gaps}: " + "; ".join(summary)
    return True, "; ".join(summary) + f"; интервалы={gaps}"


def selftest():
    def make(starts):
        return [(int((t + i * .01) * 1e9), addr)
                for t in starts for addr in sorted(MEMBERS) for i in range(3)]
    good = make([100, 110, 120])
    assert verify(good, 3)[0]
    assert not verify(make([100, 100.2, 100.4]), 3)[0]  # один большой залп
    assert not verify(good[:-1], 3)[0]                  # пропущенная проба
    assert not verify([r for r in good if r[1] != "10.9.2.1"], 3)[0]
    assert not verify(make([100, 110]), 3)[0]           # пропущенный круг
    assert not verify(make([100, 105, 120]), 3)[0]      # неверный период
    assert not verify(make([100, 110, 120, 130]), 3)[0] # лишний круг
    print("yes")


if __name__ == "__main__":
    if sys.argv[1:] == ["--selftest"]:
        selftest()
    else:
        try:
            with open(sys.argv[1]) as f:
                rows = [(int(line.split()[0]), line.split()[1]) for line in f if line.strip()]
            ok, detail = verify(rows, int(sys.argv[2]))
            print(("yes" if ok else "no") + " " + detail)
            sys.exit(0 if ok else 1)
        except (ValueError, OSError, IndexError) as exc:
            print("no", exc)
            sys.exit(1)
