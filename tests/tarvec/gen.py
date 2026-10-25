#!/usr/bin/env python3
"""Векторы для tests/tarmatch.c: tar.gz, собранные модулем tarfile, и испорченные копии.

Запуск из корня дерева: python3 tests/tarvec/gen.py  (файлы лягут рядом, gzip с mtime=0 —
вывод детерминирован). Содержимое big.bin считает и сам стенд (pattern в tarmatch.c) — менять
формулу только в обоих местах сразу."""
import gzip, io, os, tarfile

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)))

def pattern(n):
    return bytes(((i * 31 + 7) & 0xff) for i in range(n))

def tgz(name, entries, fmt=tarfile.USTAR_FORMAT, raw=False):
    """entries: (имя, тип, данные|цель, режим). Тип: f, d, s (ссылка), h (жёсткая), c (устройство), p (fifo)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=fmt) as t:
        for (n, k, d, m) in entries:
            ti = tarfile.TarInfo(n)
            ti.mode = m
            ti.mtime = 0
            if k == "f":
                ti.size = len(d)
                t.addfile(ti, io.BytesIO(d))
            elif k == "d":
                ti.type = tarfile.DIRTYPE
                t.addfile(ti)
            elif k == "s":
                ti.type = tarfile.SYMTYPE
                ti.linkname = d
                t.addfile(ti)
            elif k == "h":
                ti.type = tarfile.LNKTYPE
                ti.linkname = d
                t.addfile(ti)
            elif k == "c":
                ti.type = tarfile.CHRTYPE
                t.addfile(ti)
            elif k == "p":
                ti.type = tarfile.FIFOTYPE
                t.addfile(ti)
    data = buf.getvalue()
    if raw:
        return data
    z = io.BytesIO()
    with gzip.GzipFile(fileobj=z, mode="wb", mtime=0, filename="") as g:
        g.write(data)
    return z.getvalue()

def put(name, data):
    with open(os.path.join(OUT, name), "wb") as f:
        f.write(data)

long100 = "d" * 60 + "/" + "e" * 60 + "/file-with-a-long-name.txt"          # 130+ знаков: префикс ustar
long300 = "/".join(["segment%03d" % i for i in range(30)]) + "/leaf.txt"     # > 255: только pax и GNU

good = [
    ("./", "d", None, 0o755),
    ("./plugin.json", "f", b'{"name":"demo"}\n', 0o644),
    ("./bin", "d", None, 0o755),
    ("./bin/run.sh", "f", b"#!/bin/sh\necho hi\n", 0o755),
    ("./empty", "f", b"", 0o600),
    ("./sub/deep/er/file.txt", "f", b"deep\n", 0o640),
    ("./locked", "d", None, 0o500),
    ("./locked/inside.txt", "f", b"in a read-only dir\n", 0o444),
    ("./link-to-file", "s", "plugin.json", 0o777),
    ("./link-to-dir", "s", "sub/deep", 0o777),
    ("./big.bin", "f", pattern(1500000), 0o644),
    ("./setuid.sh", "f", b"x", 0o4755),
]
put("good.tar.gz", tgz("good", good))
put("long-ustar.tar.gz", tgz("l", [(long100, "f", b"prefix\n", 0o644)]))
put("long-gnu.tar.gz", tgz("l", [(long300, "f", b"gnu\n", 0o644), ("s", "s", "x" * 150, 0o777)], fmt=tarfile.GNU_FORMAT))
put("long-pax.tar.gz", tgz("l", [(long300, "f", b"pax\n", 0o644)], fmt=tarfile.PAX_FORMAT))

put("dotdot.tar.gz", tgz("e", [("../evil.txt", "f", b"x", 0o644)]))
put("dotdot-mid.tar.gz", tgz("e", [("a/../../evil.txt", "f", b"x", 0o644)]))
put("dotdot-dir.tar.gz", tgz("e", [("../evildir", "d", None, 0o755)]))
put("abs.tar.gz", tgz("e", [("/tmp/steer-untar-evil.txt", "f", b"x", 0o644)]))
put("link-abs.tar.gz", tgz("e", [("l", "s", "/etc", 0o777)]))
put("link-up.tar.gz", tgz("e", [("l", "s", "../outside", 0o777)]))
put("link-up-mid.tar.gz", tgz("e", [("l", "s", "a/../../outside", 0o777)]))
put("link-then-file.tar.gz", tgz("e", [("real", "d", None, 0o755), ("l", "s", "real", 0o777), ("l/f.txt", "f", b"x", 0o644)]))
put("link-then-dir.tar.gz", tgz("e", [("real", "d", None, 0o755), ("l", "s", "real", 0o777), ("l/sub", "d", None, 0o755)]))
put("hardlink.tar.gz", tgz("e", [("a", "f", b"x", 0o644), ("b", "h", "a", 0o644)]))
put("chardev.tar.gz", tgz("e", [("dev", "c", None, 0o644)]))
put("fifo.tar.gz", tgz("e", [("fifo", "p", None, 0o644)]))
put("dup.tar.gz", tgz("e", [("a", "f", b"1", 0o644), ("a", "f", b"2", 0o644)]))
put("two.tar.gz", tgz("e", [("a.txt", "f", b"first\n", 0o644), ("b.txt", "f", b"second\n", 0o644)]))

# Порча: контрольная сумма заголовка, обрыв посреди данных, хвост gzip, обрыв gzip.
raw = bytearray(tgz("t", [("a.txt", "f", b"A" * 5000, 0o644)], raw=True))
bad = bytearray(raw); bad[0] ^= 0x01       # имя изменено — сумма не сходится
def gz(b):
    z = io.BytesIO()
    with gzip.GzipFile(fileobj=z, mode="wb", mtime=0, filename="") as g:
        g.write(bytes(b))
    return z.getvalue()
put("badsum.tar.gz", gz(bad))
put("cut.tar.gz", gz(raw[:512 + 2000]))                 # обрыв внутри данных файла
put("cut-hdr.tar.gz", gz(raw[:512 + 5120 + 100]))       # обрыв внутри второго заголовка (нет нулевых блоков)
g = bytearray(gz(raw)); g[-8] ^= 0xff                   # CRC-32 в хвосте gzip
put("badcrc.tar.gz", bytes(g))
g = bytearray(gz(raw)); g[-4] ^= 0x01                   # длина в хвосте gzip
put("badlen.tar.gz", bytes(g))
g = gz(raw)
put("cut-gz.tar.gz", g[: len(g) // 2])
put("notgz.tar.gz", b"this is not a gzip file at all, just some text\n" * 3)
