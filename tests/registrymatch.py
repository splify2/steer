#!/usr/bin/env python3
"""Реальные dry-run, plan, check и Apply; только стендовые файлы, Unix-сокет и nft."""
from pathlib import Path
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time


OLD = {"a": (0x200000, 301), "b": (0x100000, 300)}
NEW = {"a": (0x200000, 301), "c": (0x100000, 300)}


def mapping(lines):
    return {name: (int(mark, 16), int(table)) for name, mark, table in lines}


def assigned(text):
    return mapping(line.split() for line in text.splitlines())


def planned(text):
    return mapping(line.split()[1:4] for line in text.splitlines() if line.startswith("out "))


def spec(*names, list_path=None):
    channels = [] if list_path is None else [
        {"name": f"ch{i}", "out": name, "match": {"prefixes_files": [str(list_path)]}}
        for i, name in enumerate(names)
    ]
    return json.dumps({
        "schema": 1, "from_default": ["192.0.2.0/24"],
        "outputs": {name: {"kind": "block"} for name in names}, "channels": channels,
    }).encode()


def snapshot(*paths):
    return [(p.read_bytes(), p.stat().st_ino, p.stat().st_mtime_ns) for p in paths]


def request(sock, command, body):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(10)
        client.connect(str(sock))
        client.sendall(f"{command} {len(body)}\n".encode() + body)
        client.shutdown(socket.SHUT_WR)
        with client.makefile("rb") as f:
            return json.loads(f.readline())


def match(engine, tmp):
    # У ctl свой exe для детей и поиска сервисов; путь уникален для запуска стенда.
    binpath = tmp / "steerd"
    shutil.copy2(engine, binpath)
    tools = tmp / "bin"
    tools.mkdir()
    nft = tools / "nft"
    nft.write_text("""#!/bin/sh
case "$*" in
    '-f '*)
        printf 'load\\n' >> "$REGISTRY_TEST_TMP/nft.log"
        if [ -e "$REGISTRY_TEST_TMP/reject" ]; then exit 1; fi
        exit 0 ;;
esac
exit 1
""")
    nft.chmod(0o755)
    rt = tmp / "rt_tables.d"
    env = {
        "PATH": str(tools), "LC_ALL": "C", "STEER_PLATFORM": "openwrt",
        "STEER_NFT_TABLE": "steer_registry_test", "STEER_CTL_ENABLED": "1",
        "STEER_PLUGINS_ROOT": str(tmp / "plugins"), "STEER_PLUGINS_ETC": str(tmp / "plugins-etc"),
        "REGISTRY_TEST_RT_TABLES": str(rt), "REGISTRY_TEST_TMP": str(tmp),
    }
    state, live, candidate, bad = [tmp / n for n in ("state", "spec.json", "candidate.json", "bad.json")]
    registry, tables = state / "registry", rt / "steer.conf"
    nft_log, reject = tmp / "nft.log", tmp / "reject"
    prefixes = tmp / "prefixes.lst"
    prefixes.write_text("203.0.113.0/24\n")
    live.write_bytes(spec("a", "b"))
    candidate.write_bytes(spec("a", "c"))
    # Одинаковое имя набора (префикс + хэш); отказ build_groups уже после
    # расчёта назначений, а не ранний отказ парсера.
    bad.write_bytes(spec("registry_collision0018829", "registry_collision0020754", list_path=prefixes))

    def run(*args, path=candidate, code=0):
        p = subprocess.run([binpath, *args, "--spec", path, "--state-dir", state],
                           env=env, capture_output=True, text=True, timeout=10)
        assert p.returncode == code, (args, p.returncode, p.stdout, p.stderr)
        return p

    # Нечего сохранять: ни пустых файлов, ни каталогов от валидного/негодного плана.
    for args in [("apply", "--dry-run"), ("apply-plan",), ("apply-plan", "--start")]:
        run(*args)
        run(*args, path=bad, code=2)
        assert not state.exists() and not rt.exists() and not nft_log.exists()

    # Реестр от прежнего порядка выходов и соответствующий файл имён iproute2.
    state.mkdir()
    rt.mkdir()
    registry.write_text("a 200000 301\nb 100000 300\n")
    tables.write_text("301 steer_a\n300 steer_b\n")
    before = snapshot(registry, tables, live)
    expected = run("apply-plan").stdout
    assert planned(expected) == NEW, expected
    assert run("apply-plan").stdout == expected
    assert run("apply-plan", "--start").stdout == expected
    assert planned(run("apply-plan", path=live).stdout) == OLD
    run("apply", "--dry-run")
    run("apply", "--dry-run", path=bad, code=2)
    run("apply-plan", path=bad, code=2)
    run("apply", path=bad, code=2)
    assert snapshot(registry, tables, live) == before and not nft_log.exists()

    sock = tmp / "ctl.sock"
    with (tmp / "daemon.log").open("wb") as log, subprocess.Popen(
        [binpath, "ctl-serve", "--socket", sock, "--spec", live, "--state-dir", state,
         "--lists-dir", tmp / "lists", "--allow-uid", str(os.getuid())],
        env=env, stdout=log, stderr=log,
    ) as daemon:
        try:
            deadline = time.monotonic() + 5
            while not sock.exists() and daemon.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
            assert sock.exists(), (tmp / "daemon.log").read_text()
            assert request(sock, "check", candidate.read_bytes())["code"] == 0
            r = request(sock, "check", bad.read_bytes())
            assert r["code"] == 2 and r["ecode"] == "compile.group_name_twice", r
            r = request(sock, "apply", bad.read_bytes())
            assert r["code"] == 2 and not r["saved"] and not r["applied"], r
            assert snapshot(registry, tables, live) == before and not nft_log.exists()

            reject.touch()
            r = request(sock, "apply", candidate.read_bytes())
            assert r["code"] == 1 and not r["applied"] and r["rolled_back"], r
            assert snapshot(registry, tables) == before[:2] and live.read_bytes() == spec("a", "b")
            assert nft_log.read_text() == "load\n"

            reject.unlink()
            r = request(sock, "apply", candidate.read_bytes())
            assert r["code"] == 0 and r["saved"] and r["applied"], r
            assert assigned(registry.read_text()) == planned(expected)
            assert tables.read_text() == "301 steer_a\n300 steer_c\n"
            assert nft_log.read_text() == "load\nload\n"
            saved = snapshot(registry, tables)
            assert planned(run("apply-plan").stdout) == NEW
            assert snapshot(registry, tables) == saved
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=5)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait()

    # Standalone Apply: отказ nft не создаёт даже пустого файла. Успех создаёт
    # назначения, а повтор того же Apply не переписывает файлы.
    state = tmp / "fresh-state"
    registry = state / "registry"
    reject.touch()
    run("apply", code=1)
    assert not registry.exists() and snapshot(tables) == saved[1:]
    reject.unlink()
    fresh = planned(run("apply-plan").stdout)
    assert fresh == {"a": (0x100000, 300), "c": (0x200000, 301)}, fresh
    run("apply")
    assert assigned(registry.read_text()) == fresh
    saved = snapshot(registry, tables)
    run("apply")
    assert snapshot(registry, tables) == saved

    # Пустой реестр по-прежнему создаётся при успешном Apply без помечаемых выходов.
    state = tmp / "empty-state"
    empty = tmp / "empty.json"
    empty.write_bytes(spec())
    run("apply", "--dry-run", path=empty)
    assert not state.exists()
    run("apply", path=empty)
    assert (state / "registry").read_bytes() == b"" and tables.read_bytes() == b""


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="steer-registry-") as temp:
        match(Path(sys.argv[1]).resolve(strict=True), Path(temp))
    print("registrymatch: dry-run, plan, check, отказ и успешный Apply — ok")
