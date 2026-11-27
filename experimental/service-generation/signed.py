"""Single-writer, signed-tree Linux lab. No paths or program names on the wire."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
import uuid

import controller as gen
from controller import Refusal, belongs, enc, ident, mount, require, sha, syncdir


PROFILE = "steer-lab-signed-full/1"
DIRS = ("stage", "slot", "retired")
SLOT = Path("slot/full-ui")
LAB = Path("/run/e4")
FEED = LAB / "feed"
ELF = "bin/steer-ui-service"
FILES = {ELF, "MANIFEST", "MANIFEST.sig", "plugin.json", "LICENSE", "licenses/libyaml.txt",
         *("assets/" + name for name in ("app.css", "app.js", "config-model.js", "index.html",
           "fonts/Onest-OFL.txt", "fonts/onest-cyrillic.woff2", "fonts/onest-latin.woff2"))}
FOLDERS = {"bin", "licenses", "assets", "assets/fonts"}
HEX = re.compile("[0-9a-f]{64}")


def boundary(p):
    return gen.boundary(p, PROFILE, DIRS)


def inspect(tree):
    """Only descend into the fixed Full layout. Never follow a mount or link."""
    rows = {}
    mid = mount(tree.parent)

    def walk(d, rel=""):
        st = d.lstat()
        require(stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and
                not st.st_mode & 0o7022 and mount(d) == mid, "unsafe-directory")
        for f in d.iterdir():
            name = rel + f.name
            if name in FOLDERS:
                walk(f, name + "/")
                continue
            require(name in FILES, "unexpected-tree-entry")
            st = f.lstat()
            mode = 0o755 if name == ELF else 0o644
            require(st.st_mode == stat.S_IFREG | mode and st.st_nlink == 1 and
                    st.st_uid == os.getuid() and st.st_size <= 8 << 20 and mount(f) == mid,
                    "unsafe-package-file")
            rows[name] = [mode, st.st_size, sha(f.read_bytes())]

    walk(tree)
    require(rows.keys() == FILES, "incomplete-full-tree")
    meta = json.loads((tree/"plugin.json").read_bytes())
    require(isinstance(meta, dict) and meta.get("id") == "steer-ui" and isinstance(meta.get("version"), str),
            "changed-metadata")
    return {"inode": ident(tree), "manifest": rows["MANIFEST"][2], "payload": sha(enc(rows)),
            "version": meta["version"]}


def move(src, dst):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.renameat2(-100, os.fsencode(src), -100, os.fsencode(dst), 1):  # NOREPLACE
        raise OSError(ctypes.get_errno(), "rename exact tree")
    syncdir(src.parent)
    syncdir(dst.parent)


def verify(p, g, digest, prepare):
    require(isinstance(digest, str) and HEX.fullmatch(digest), "bad-archive-digest")
    archive = FEED / (digest + ".s2p")
    require(archive.is_file() and archive.stat().st_size <= 16 << 20, "wrong-archive")
    # Immutable namespace inputs, fresh empty trust store, no registry shared
    # with this owner. Only the verified output inode crosses this boundary.
    with tempfile.TemporaryDirectory(prefix="e4-verify-", dir="/tmp") as scratch:
        pm = Path(scratch)/"files"
        blob = Path(scratch)/"input.s2p"
        shutil.copyfile(archive, blob)
        require(sha(blob.read_bytes()) == digest, "wrong-archive")

        def stock(*args):
            out = subprocess.run([LAB/"steerd", "--managed-prefix", pm, "plugin", *args, "--json"],
                                 env={"PATH": "/usr/bin:/bin", "HOME": scratch}, capture_output=True, timeout=15)
            if out.returncode:
                raise Refusal("verify: " + json.loads(out.stdout)["code"])

        stock("init")
        key = pm/"keys/plugins/lab.pub"
        shutil.copyfile(FEED/"publisher.pub", key)
        stock("install", "--file", blob)
        tree = pm/"installed/steer-ui"
        info = inspect(tree)
        require(sha((tree/ELF).read_bytes()) == (LAB/"host.sha256").read_text().strip(), "wrong-service-host")
        info.update(archive=digest, key=sha(key.read_bytes()), slot=str(SLOT))
        for name in FILES:
            with (tree/name).open("rb") as f:
                os.fsync(f.fileno())
        for d in (*FOLDERS, "."):
            syncdir(tree/d)
        prepare(info)
        move(tree, p/"stage"/g[33:])


class History:
    """Replay legal events, then check physical witnesses before any mutation."""
    seal_tail = gen.Ledger.seal_tail

    def __init__(self, p, stamp):
        self.p, self.path, self.nonce = p, p/"history", stamp["nonce"]
        self.tip = self.live = self.pending = self.preparing = None
        self.bound, self.retired, self.fenced = {}, set(), set()
        self.head = sha(enc(stamp))
        self.seal = os.getxattr(self.path, gen.ATTR).decode()
        prev = None
        require(self.path.stat().st_size <= 1 << 20)
        for line in self.path.read_bytes().splitlines(keepends=True):
            event, digest = json.loads(line)
            prev = self.head
            require(isinstance(event, list) and len(event) == 3 and digest == sha(enc([prev, *event])))
            self.advance(*event)
            require(self.head == digest and line == enc([event, digest])+b"\n")
        require(self.seal in (prev, self.head), "lost-history")
        self.layout()

    def advance(self, op, g, value):
        require(g is None or belongs(self.nonce, g), "wrong-prefix-generation")
        if op == "prepare":
            require(g and g not in self.bound and self.pending is None and len(self.bound) < 32)
            require(isinstance(value, dict) and value.get("slot") == str(SLOT))
            if self.preparing:
                prior, info = self.preparing
                require(g == prior and (info | {"inode": value["inode"]}) == value, "different-preparation")
            self.preparing = [g, value]
        elif op == "bind":
            require(self.preparing and self.preparing[0] == g and value is None)
            self.bound[g] = self.preparing[1]
            self.preparing = None
        elif op == "fence":
            require(g and g == self.tip and value is None)
            self.fenced.add(g)
        elif op == "intent":
            require(g == self.tip and (not g or g in self.fenced) and self.pending is None and not self.preparing)
            require((value is None and self.live) or
                    (value in self.bound and value != g and value not in self.retired))
            self.pending = [g, value]
        else:
            require(op == "commit" and self.pending == [g, value])
            if self.live:
                self.retired.add(self.live)
            self.tip, self.live, self.pending = value or g, value, None
        self.head = sha(enc([self.head, op, g, value]))

    def record(self, op, g, value=None):
        if op == "prepare":
            require(self.path.stat().st_size < (1 << 20) - 65536, "history-full")
        self.seal_tail()
        self.advance(op, g, value)
        line = enc([[op, g, value], self.head])+b"\n"
        with self.path.open("ab", buffering=0) as f:
            require(f.write(line) == len(line))
            os.fsync(f.fileno())
        self.seal_tail()

    def locations(self):
        result = {}
        for g in self.bound:
            result[g] = SLOT if self.live == g else Path("retired" if g in self.retired else "stage")/g[33:]
        yield result.copy()
        if self.preparing:
            g = self.preparing[0]
            result[g] = Path("stage")/g[33:]
            yield result
        if self.pending:
            if self.live:
                result[self.live] = Path("retired")/self.live[33:]
                yield result.copy()
            target = self.pending[1]
            if target:
                result[target] = SLOT
                yield result

    def layout(self):
        found = {f.relative_to(self.p) for name in DIRS for f in (self.p/name).iterdir()}
        for plan in self.locations():
            if set(plan.values()) != found:
                continue
            # During replacement both endpoints contain a tree, but their
            # generation-specific stage/retired basenames disambiguate the slot.
            for g, location in plan.items():
                info = inspect(self.p/location)
                expected = self.bound[g] if g in self.bound else self.preparing[1]
                require(all(expected.get(k) == v for k,v in info.items()), "changed-tree")
            self.where = plan
            return
        raise Refusal("unaccounted-tree")

    def view(self):
        slot = next((g for g, location in self.where.items() if location == SLOT), None)
        phase = ("recover-log" if self.head != self.seal else "pending-switch" if self.pending
                 else "preparing" if self.preparing else "removed" if self.tip and not self.live
                 else "fenced" if self.tip in self.fenced else "active" if self.live else "unpublished")
        return {"phase": phase, "tip": self.tip, "live": self.live, "slot": slot,
                "pending": self.pending, "preparing": self.preparing, "fenced": self.tip in self.fenced,
                "head": self.head, "sealed": self.head == self.seal,
                "locations": {g: str(path) for g, path in self.where.items()}}


class Owner(gen.Supervisor):
    boundary = staticmethod(boundary)
    journal = History

    def __init__(self, p, checkpoint=lambda _: None):
        super().__init__(p, checkpoint)
        self.ticket = None
        self.watch = True

    def tick_needed(self):
        self.reap()
        return self.watch and not self.child

    def reconcile(self, h):
        self.reap()
        self.watch = h.live and not h.pending and h.live not in h.fenced
        if not self.child and self.watch:
            require(h.seal == h.head and h.where[h.live] == SLOT)
            self.spawn(h.live, self.p/SLOT/ELF, self.p/SLOT/"assets", h.bound[h.live]["version"])

    def fence(self, h, g):
        require(g and g == h.tip, "stale-generation")
        if g not in h.fenced:
            h.record("fence", g)
        else:
            h.seal_tail()
        if self.child:
            require(self.g == g)
            self.child.terminate()
            self.child.wait(timeout=1)
            self.reap()
        with self.lease():
            # Opaque, expiring at owner death or commit. Never read from disk.
            if self.ticket is None:
                self.ticket = [g, sha(enc(h.bound[g])), uuid.uuid4().hex]
            return {"excluded": True, "receipt": self.ticket, "head": h.head}

    def admit_first(self, h, g):
        require(h.tip is None and g in h.bound and h.preparing is None and
                (h.pending is None or h.pending == [None, g]) and not self.child, "not-first-install")
        h.seal_tail()
        with self.lease():
            self.ticket = [None, g, sha(enc(h.bound[g])), uuid.uuid4().hex]
            return {"first": g, "receipt": self.ticket, "head": h.head}

    def apply(self, h, op, args):
        self.reap()
        require(isinstance(args, list))
        if op == "status" and not args:
            return dict(h.view(), pid=self.child.pid if self.child else None)
        if op == "stage" and len(args) == 2:
            g, digest = args
            require(belongs(h.nonce, g) and not h.pending, "wrong-generation-or-pending")
            if g not in h.bound:
                require(len(h.bound) < 32, "history-full")
                require(not h.preparing or (h.preparing[0] == g and h.preparing[1]["archive"] == digest),
                        "different-preparation")
                if g not in h.where:
                    def prepare(info):
                        h.record("prepare", g, info)
                        self.checkpoint("before-stage")
                    verify(self.p, g, digest, prepare)
                self.checkpoint("after-stage")
                h.layout()
                require(h.where.get(g) == Path("stage")/g[33:])
                h.record("bind", g)
            require(h.bound[g]["archive"] == digest, "already-bound")
            return {"generation": g, "binding": h.bound[g]}
        if op == "fence" and len(args) == 1:
            return self.fence(h, args[0])
        if op == "admit" and len(args) == 1:
            return self.admit_first(h, args[0])
        require(op == "switch" and len(args) == 3, "unknown-operation")
        old, new, ticket = args
        require(old == h.tip, "stale-generation")
        require(h.pending is None or h.pending == [old, new], "different-pending-intent")
        require(self.ticket and self.ticket == ticket and
                ((old is None and new in h.bound and ticket[:-1] == [None, new, sha(enc(h.bound[new]))]) or
                 (old in h.fenced and ticket[:-1] == [old, sha(enc(h.bound[old]))])),
                "fresh-owner-receipt-required")
        require(new is None or (belongs(h.nonce, new) and new in h.bound and new != old and new not in h.retired),
                "unknown-or-retired-target")
        require(not self.child)
        # No second handler, fork or reconnect between compare and rename.
        # Also take the lease anew: a receipt alone is never rename authority.
        with self.lease():
            if not h.pending:
                h.record("intent", old, new)
            else:
                h.seal_tail()
            self.checkpoint("before-detach")
            h.layout()
            if h.live and h.where[h.live] == SLOT:
                move(self.p/SLOT, self.p/"retired"/old[33:])
            self.checkpoint("after-detach")
            h.layout()
            if new and h.where[new] != SLOT:
                move(self.p/"stage"/new[33:], self.p/SLOT)
            self.checkpoint("after-attach")
            h.layout()
            require((not h.live or h.where[h.live].parent == Path("retired"))
                    and (not new or h.where[new] == SLOT))
            h.record("commit", old, new)
            self.ticket = None
        self.reconcile(h)
        self.checkpoint("before-reply")
        return {"tip": h.tip, "live": h.live, "head": h.head}


def call(p, op, *args):
    t = boundary(p)
    reply = gen.exchange(p, t, op, list(args), timeout=35)
    if op in ("admit", "fence"):
        g, = args
        h = History(p, boundary(p))
        require(h.head == h.seal == reply.get("head") and g in h.bound, "unconfirmed-receipt")
        binding = sha(enc(h.bound[g]))
        if op == "fence":
            require(reply.get("excluded") is True and h.tip == g and g in h.fenced and
                    reply["receipt"][:-1] == [g, binding], "unconfirmed-fence")
        else:
            require(h.tip is None and reply.get("first") == g and reply["receipt"][:-1] == [None, g, binding],
                    "unconfirmed-first-install")
    return reply


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--signed-full-prefix", required=True, type=Path)
    parser.add_argument("op", choices=("init", "serve", "inspect", "stage", "status", "admit", "fence", "switch"))
    parser.add_argument("args", nargs="?", default="[]", help="JSON array; never paths")
    a = parser.parse_args()
    os.umask(0o077)
    p = a.signed_full_prefix
    if a.op == "init":
        gen.init(p, PROFILE, DIRS)
        return {"prefix_id": boundary(p)["nonce"]}
    if a.op == "inspect":  # offline, read-only; never a receipt
        return History(p, boundary(p)).view()
    if a.op == "serve":
        Owner(p).serve()
    return call(p, a.op, *json.loads(a.args))


if __name__ == "__main__":
    try:
        print(json.dumps(main()))
    except (Refusal, OSError, ValueError, TypeError, KeyError) as e:
        raise SystemExit("signed-full: refused/recovery-blocked: " + str(e))
