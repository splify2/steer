#!/usr/bin/env python3
"""Real dnsd startup/batched table receipts; isolated namespace only."""
import argparse
import array
import os
from pathlib import Path
import socket
import struct
import subprocess
import tempfile
import time


def main():
    p=argparse.ArgumentParser();p.add_argument("--steerd",type=Path,required=True);a=p.parse_args()
    binary=str(a.steerd.resolve(strict=True))
    if os.stat("/proc/self/ns/net").st_ino==os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("private netns required")
    with tempfile.TemporaryDirectory(dir=os.environ.get("STEER_DNS_TEST_TMPDIR"),prefix="table-ack-") as tmp:
        root=Path(tmp)
        parent,child=socket.socketpair();parent.settimeout(5)
        parent.sendall(b"0\n0\n")
        process=subprocess.Popen([binary,"dnsd","--table-fd",str(child.fileno()),"--listen-port","15317",
                                  "--state-dir",str(root)],pass_fds=(child.fileno(),),
                                 stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        child.close()
        def records(count):
            data=b""
            while len(data)<9*count:
                part=parent.recv(9*count-len(data))
                assert part,"table socket closed"
                data+=part
            return [(struct.unpack("!Q",data[i:i+8])[0],data[i+8]) for i in range(0,len(data),9)]
        try:
            assert records(2)==[(1,1),(2,1)],"startup/buffered receipts"
            missing=root/"missing"
            rejected=f"1\nbad|out|0|4|bad|{missing}\n".encode()
            parent.sendall(rejected+b"0\n")
            assert records(2)==[(3,2),(4,1)],"rejected/accepted batch receipts"
            print("PASS startup, buffered frames, rejected and accepted batch receipts",flush=True)
        finally:
            process.terminate();_,err=process.communicate(timeout=5)
            parent.close()
            if __import__("sys").exc_info()[0]:print(err.decode(errors="replace")[-4000:],flush=True)
        # Legacy supervisor format: one-way pipe and unchanged adopt\n with
        # an SCM_RIGHTS pipe. New dnsd must never write a receipt to the pipe.
        read_fd,write_fd=os.pipe();os.write(write_fd,b"0\n")
        logfile=root/"legacy.log"
        with logfile.open("wb") as out:
            process=subprocess.Popen([binary,"dnsd","--table-fd",str(read_fd),"--listen-port","15318",
                                      "--state-dir",str(root)],pass_fds=(read_fd,),
                                     stdout=out,stderr=out,
                                     env=dict(os.environ,STEER_SYSLOG_SOCK=str(root/"no-syslog")))
        os.close(read_fd)
        def wait_for(fn):
            until=time.monotonic()+5
            while not fn():
                assert process.poll() is None and time.monotonic()<until
                time.sleep(.01)
        owner=None;logfd=None;read2=write2=-1
        try:
            wait_for(lambda:"listening on" in logfile.read_text())
            os.close(write_fd);write_fd=-1
            path=root/"dnsd-ctl.sock"
            wait_for(lambda:path.exists())
            owner=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);owner.settimeout(5);owner.connect(str(path))
            read2,write2=os.pipe()
            logfd=logfile.open("ab",buffering=0)
            rights=array.array("i",[read2,logfd.fileno()])
            owner.sendmsg([b"adopt\n"],[(socket.SOL_SOCKET,socket.SCM_RIGHTS,rights)])
            assert owner.recv(16)==b"ok\n"
            os.close(read2);read2=-1
            os.write(write2,b"0\n")
            wait_for(lambda:"таблица от демона:" in logfile.read_text())
            assert process.poll() is None
            print("PASS legacy pipe and unchanged adopt request",flush=True)
        finally:
            if owner:owner.close()
            if logfd:logfd.close()
            for fd in (write_fd,read2,write2):
                if fd>=0:os.close(fd)
            process.terminate();process.wait(timeout=5)


if __name__=="__main__":main()
