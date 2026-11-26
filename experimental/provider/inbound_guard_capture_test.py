#!/usr/bin/env python3
"""Actual bounded C capture against the real disposable managed-guard fixture."""
import errno
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main(fixture, capture):
    inner=os.stat('/proc/self/ns/net');outer=os.fstat(3)
    assert (inner.st_dev,inner.st_ino)!=(outer.st_dev,outer.st_ino)
    child=subprocess.Popen([fixture],stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True,pass_fds=(3,))
    try:
        table,marker,handle,index=child.stdout.readline().split()
        def check(mode, expected, env=None, name=table):
            result=subprocess.run([capture,name,marker,handle,index,mode,str(expected)],
                                  text=True,capture_output=True,env=env,timeout=8)
            if result.returncode!=0:
                raise RuntimeError('capture test failed: '+result.stdout+result.stderr)
            print(result.stdout.strip())
        check('normal',0)
        check('expired',errno.ETIMEDOUT)
        check('normal',errno.EIO,name='steer_wg_0000000000000000')
        check('read-error',errno.EIO)
        with tempfile.TemporaryDirectory(prefix='guard-capture-',dir='/tmp/opencode') as tmp:
            tool=Path(tmp)/'nft'
            tool.write_text('#!/bin/sh\nexec /bin/sleep 10\n');tool.chmod(0o700)
            env=dict(os.environ,PATH=tmp+':/usr/bin:/bin')
            check('short',errno.ETIMEDOUT,env=env)
            tool.write_text('#!/bin/sh\nexec /usr/bin/head -c 65537 /dev/zero\n');tool.chmod(0o700)
            check('normal',errno.EFBIG,env=env)
            tool.write_text('#!/bin/sh\nexec /bin/true\n');tool.chmod(0o700)
            check('normal',errno.EPROTO,env=env)
        print('PASS real bounded capture: normal, timeout, command/read failures, 64KiB limit')
    finally:
        if child.poll() is None:child.stdin.write('q\n');child.stdin.flush()
        assert child.wait(timeout=10)==0


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('expected fixture and capture binaries')
    main(*sys.argv[1:])
