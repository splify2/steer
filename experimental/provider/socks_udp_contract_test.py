#!/usr/bin/env python3
"""Controlled independent SOCKS server for SDK receive contract; private netns."""
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading


def main():
    if len(sys.argv)!=2 or os.path.samefile("/proc/self/ns/net","/proc/1/ns/net"):
        raise SystemExit("private netns and test binary required")
    binary=str(Path(sys.argv[1]).resolve(strict=True))
    errors=[]
    ready_read,ready_write=os.pipe()
    with socket.socket() as server, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as relay:
        server.bind(("127.0.0.1",0));server.listen(1);server.settimeout(8)
        relay.bind(("127.0.0.1",0));relay.settimeout(8)
        target=("127.0.0.1",12345)
        def serve():
            try:
                with server.accept()[0] as tcp:
                    tcp.settimeout(8)
                    def exact(n):
                        result=b""
                        while len(result)<n:
                            part=tcp.recv(n-len(result))
                            if not part:raise EOFError()
                            result+=part
                        return result
                    assert exact(3)==b"\5\1\0";tcp.sendall(b"\5\0")
                    req=exact(10);assert req[:4]==b"\5\3\0\1"
                    tcp.sendall(b"\5\0\0\1"+socket.inet_aton("127.0.0.1")+relay.getsockname()[1].to_bytes(2,"big"))
                    packet,client=relay.recvfrom(65535)
                    assert packet[10:]==b"\1"
                    header=b"\0\0\0\1"+socket.inet_aton(target[0])+target[1].to_bytes(2,"big")
                    for payload in (b"A"*65000,b"B"*65001,b"C"):
                        relay.sendto(header+payload,client)
                    os.write(ready_write,b"R")
                    assert tcp.recv(1)==b""
            except Exception as exc:errors.append(exc)
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        with os.fdopen(ready_read,"rb") as ready:
            subprocess.run([binary,str(server.getsockname()[1]),str(target[1])],stdin=ready,check=True,timeout=10)
        thread.join(8);assert not thread.is_alive() and not errors,errors
    os.close(ready_write)


if __name__=="__main__":main()
