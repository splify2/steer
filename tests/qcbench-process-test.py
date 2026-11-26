#!/usr/bin/env python3
"""Run a gate as a Linux child subreaper; inspect only its own descendants."""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

if len(sys.argv) < 2:
    raise SystemExit("usage: qcbench-process-test.py command [args...]")

libc = ctypes.CDLL(None, use_errno=True)
if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
    err = ctypes.get_errno()
    raise OSError(err, os.strerror(err))

proc = None
received = None
signal_deadline = None


def forward(signum, _frame):
    global received, signal_deadline
    if received is None:
        received = signum
        signal_deadline = time.monotonic() + 10
    if proc is not None and proc.poll() is None:
        proc.send_signal(signum)


signal.signal(signal.SIGTERM, forward)
signal.signal(signal.SIGINT, forward)
proc = subprocess.Popen(sys.argv[1:])
if received is not None and proc.poll() is None:
    proc.send_signal(received)
while True:
    try:
        status = proc.wait(timeout=0.2)
        break
    except subprocess.TimeoutExpired:
        if signal_deadline is not None and time.monotonic() >= signal_deadline:
            proc.kill()
            status = proc.wait()
            break

# Only the calling thread's direct children are listed. Once the gate exits,
# subreaper adoption makes its remaining orphans our direct children.
children_file = Path(f"/proc/self/task/{os.getpid()}/children")


def children():
    return [int(pid) for pid in children_file.read_text().split()]


live = []
for pid in children():
    reaped, _ = os.waitpid(pid, os.WNOHANG)
    if not reaped:
        live.append(pid)

if live:
    for pid in live:
        print("qcbench: живой процесс после возврата:", pid, file=sys.stderr)
    # Do not leave the failed test's processes behind. Reap adopted descendants,
    # including children of the processes killed in the preceding iteration.
    while True:
        pending = children()
        if not pending:
            break
        for pid in pending:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        for pid in pending:
            os.waitpid(pid, 0)
    raise SystemExit(1)

if received is not None:
    raise SystemExit(128 + received)
if status:
    raise SystemExit(status if status > 0 else 128 - status)
print("qcbench: нет живых потомков после возврата")
