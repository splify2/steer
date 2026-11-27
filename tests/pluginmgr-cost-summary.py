"""Print the warm-sample table from one complete install-cost JSONL (stdin)."""
import collections
import json
import math
import sys

rows = collections.defaultdict(list)
mode, complete = "main", False
for line in sys.stdin:
    d = json.loads(line)
    mode = d.get("mode",mode)
    complete |= "finish_load" in d
    if d.get("rep",0) > 0:
        rows[d["family"],d["rev"],d["size"],d["op"]].append(d)

print("| Группа | Менеджер | Конфиг | Операция | wall p50 / p95, мс | RSS max / Σ max, МиБ | FS на входе / Δпик, КиБ |")
print("|---|---|---:|---|---:|---:|---:|")
for f in ("files","net1"):
    for v in ("v214","file","core"):
        for op in ("update","recovery","clean"):
            if op != "update" and (v == "v214" or (v == "file" and f == "net1")):
                continue
            if mode == "native" and (v != "v214" or f != "files"):
                continue
            if mode == "stream" and f != "files":
                continue
            for s in (("4K",) if mode == "stream" else ("4K","8M","64M")):
                a = rows[f,v,s,op]
                assert sorted(d["rep"] for d in a) == list(range(1,21))
                t = sorted(d["us"]/1000 for d in a)
                def q(p):
                    return t[math.ceil(p*len(t))-1]
                peak = max(d["rss_kib"] for d in a)/1024
                tree = max(d["tree_kib"] for d in a)/1024
                base = max(d["before"] for d in a)//1024
                extra = max(d["peak"]-d["before"] for d in a)//1024
                rev = {"v214":"v2.1.4*","file":"515a463","core":"544b31a"}[v]
                if mode == "native":
                    rev = "v2.1.4"
                print(f"| {f} | {rev} | {s} | {op} | {q(.5):.2f} / {q(.95):.2f} | "
                      f"{peak:.2f} / {tree:.2f} | {base} / +{extra} |")
assert complete, "run not complete"
