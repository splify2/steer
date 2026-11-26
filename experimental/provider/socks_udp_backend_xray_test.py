#!/usr/bin/env python3
"""Independent Xray SOCKS upstream and SDK-routed UDP echo; private netns."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
from hy2_udp_client_test import owned_udp


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1",0));return s.getsockname()[1]

def invalid_relay(binary,address,port):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1",0));listener.listen(1);listener.settimeout(5)
        errors=[]
        def serve():
            try:
                with listener.accept()[0] as tcp:
                    tcp.settimeout(5)
                    def exact(n):
                        data=b""
                        while len(data)<n:
                            chunk=tcp.recv(n-len(data))
                            if not chunk:raise RuntimeError("truncated request")
                            data+=chunk
                        return data
                    assert exact(3)==b"\5\1\0"
                    tcp.sendall(b"\5\0")
                    req=exact(10);assert req[:4]==b"\5\3\0\1"
                    tcp.sendall(b"\5\0\0\1"+socket.inet_aton(address)+port.to_bytes(2,"big"))
                    assert tcp.recv(1)==b""
            except Exception as e:errors.append(e)
        worker=threading.Thread(target=serve,daemon=True);worker.start()
        subprocess.run([binary,str(listener.getsockname()[1])],check=True,timeout=10)
        worker.join(5);assert not worker.is_alive() and not errors,errors


def main():
    if len(sys.argv)!=4 or os.path.samefile("/proc/self/ns/net","/proc/1/ns/net"):
        raise SystemExit("private netns; positive binary, negative binary, Xray required")
    positive,negative,xray=(str(Path(p).resolve(strict=True)) for p in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="socks-out-udp-") as tmp, \
         socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as echo:
        echo.bind(("127.0.0.1",0));echo.settimeout(.1)
        stopped=threading.Event();observed=[];owner=[None]
        def run_echo():
            while not stopped.is_set():
                try:
                    data,source=echo.recvfrom(65535)
                    observed.append((data,source,owned_udp(owner[0],source[1])))
                    echo.sendto(data,source)
                except socket.timeout:pass
        thread=threading.Thread(target=run_echo,daemon=True);thread.start()
        def server(udp):
            port=free_port()
            doc={"log":{"loglevel":"warning"},
                "inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"socks",
                             "settings":{"auth":"noauth","udp":udp}}],
                "outbounds":[{"protocol":"freedom","settings":{}}]}
            path=Path(tmp)/"xray.json";path.write_text(json.dumps(doc))
            p=subprocess.Popen([xray,"run","-c",str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            end=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.1):pass
                    break
                except OSError:
                    assert p.poll() is None and time.monotonic()<end
                    time.sleep(.02)
            return p,port
        proc=None
        try:
            proc,port=server(True);owner[0]=proc.pid
            subprocess.run([positive,str(port),str(echo.getsockname()[1])],check=True,timeout=15)
            assert [len(x[0]) for x in observed]==[1,1000],observed
            assert all(src[0]=="127.0.0.1" and belongs for _,src,belongs in observed),observed
            print("PASS echo source UDP socket owned by independent Xray",flush=True)
            proc.terminate();proc.communicate(timeout=5);proc=None
            proc,port=server(True);owner[0]=proc.pid
            test=subprocess.Popen([positive,str(port),str(echo.getsockname()[1]),"loss"],
                                  stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert test.stdout.readline().strip()=="WAIT-CONTROL"
            proc.terminate();proc.communicate(timeout=5);proc=None
            output,errors=test.communicate(timeout=10)
            assert test.returncode==0,(test.returncode,output,errors)
            assert [len(x[0]) for x in observed]==[1,1000,1,1000]
            assert all(belongs for _,_,belongs in observed)
            print("PASS TCP control loss cancels receive and drains",flush=True)
            proc,port=server(False);owner[0]=proc.pid
            subprocess.run([negative,str(port)],check=True,timeout=10)
            assert len(observed)==4,"disabled UDP unexpectedly reached echo"
            proc.terminate();proc.communicate(timeout=5);proc=None
            port=free_port()
            subprocess.run([negative,str(port)],check=True,timeout=10)
            assert len(observed)==4,"missing upstream unexpectedly reached echo"
            for addr,relay_port in (("0.0.0.0",12345),("192.0.2.1",12345),("127.0.0.1",0)):
                invalid_relay(negative,addr,relay_port)
        finally:
            if proc:proc.terminate();proc.communicate(timeout=5)
            stopped.set();thread.join(2)
        print("PASS UDP-disabled, absent upstream and invalid relay fail closed",flush=True)


if __name__=="__main__":main()
