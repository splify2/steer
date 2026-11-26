#!/usr/bin/env python3
"""Private-netns live reload: a held UDP reply must not poison the new cache."""
import argparse
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import tempfile
import threading
import time


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--binary",type=Path,required=True)
    args=parser.parse_args()
    binary=str(args.binary.resolve(strict=True))
    if os.stat("/proc/self/ns/net").st_ino==os.stat("/proc/1/ns/net").st_ino:
        raise RuntimeError("private network namespace required")
    with tempfile.TemporaryDirectory(dir=os.environ.get("STEER_DNS_TEST_TMPDIR"),prefix="dns-late-") as tmp:
        root=Path(tmp);state=root/"state";state.mkdir()
        (root/"names").write_text("switch.test\n")
        spec=root/"spec.yaml";ctl=root/"ctl.sock";log=root/"daemon.log"
        def configure(number):
            candidate=root/"next.yaml"
            candidate.write_text(f"""version: 2
lan: {{ devices: [lo] }}
lists:
  names: {{ domains_file: {root}/names }}
outputs:
  direct: {{ kind: direct }}
dns:
  cache: 64
  upstreams:
    selected: {{ url: "udp://127.0.0.{number}" }}
rules:
  - {{ name: chosen, to: [names], out: direct, resolve: realip, dns: selected }}
""")
            os.replace(candidate,spec)
        held=threading.Event();release=threading.Event();sent=threading.Event();stop=threading.Event()
        lock=threading.Lock();hits=[];errors=[];sockets=[]
        name="held.switch.test"
        def server(sock,address):
            sock.settimeout(.1)
            while not stop.is_set():
                try:q,peer=sock.recvfrom(4096)
                except socket.timeout:continue
                except OSError:return
                try:
                    pos=12;labels=[]
                    while q[pos]:
                        length=q[pos];pos+=1;labels.append(q[pos:pos+length].decode("ascii"));pos+=length
                    query=".".join(labels)
                    with lock:hits.append((address,query))
                    if address=="192.0.2.2" and query==name:
                        held.set()
                        if not release.wait(4):raise RuntimeError("held query not released in time")
                    answer=q[:2]+struct.pack("!5H",0x8180,1,1,0,0)+q[12:]+struct.pack("!HHHIH",0xc00c,1,1,300,4)+socket.inet_aton(address)
                    sock.sendto(answer,peer)
                    if address=="192.0.2.2" and query==name:sent.set()
                except Exception as exc:errors.append(repr(exc));return
        for i in (2,3):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind((f"127.0.0.{i}",53))
            sockets.append(s);threading.Thread(target=server,args=(s,f"192.0.2.{i}"),daemon=True).start()
        serial=0
        def ask(query,timeout=2):
            nonlocal serial
            serial+=1
            question=b"".join(bytes([len(x)])+x.encode() for x in query.split("."))+b"\0\0\1\0\1"
            packet=struct.pack("!6H",serial,256,1,0,0,0)+question
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(timeout);client.connect(("127.0.0.1",15311));client.send(packet);response=client.recv(4096)
            assert response[:2]==packet[:2],"wrong DNS transaction id"
            assert response[12:12+len(question)]==question
            if response[3]&15 or response[6:8]!=b"\0\1":
                return f"rcode={response[3]&15},answers={int.from_bytes(response[6:8],'big')}"
            return socket.inet_ntoa(response[-4:])
        configure(2)
        with log.open("w") as output:
            process=subprocess.Popen([binary,"daemon","--supervise","--allow-uid",str(os.geteuid()),"--socket",str(ctl),
                "--state-dir",str(state),"--spec",str(spec),"--dnsd-flag","--listen-port","--dnsd-flag","15311"],
                stdout=output,stderr=output)
        old=[];old_done=threading.Event()
        def old_client():
            try:old.append(("answer",ask(name,6)))
            except Exception as exc:old.append(("error",repr(exc)))
            finally:old_done.set()
        try:
            until=time.monotonic()+6
            while True:
                assert process.poll() is None,"daemon exited"
                try:
                    if ask("ready.switch.test",.2)=="192.0.2.2":break
                except (OSError,AssertionError):pass
                assert time.monotonic()<until,"resolver did not become ready"
                time.sleep(.02)
            def pid():
                pids=re.findall(r"supervise: dnsd запущен \(pid (\d+)",log.read_text())
                assert len(pids)==1,pids
                os.kill(int(pids[0]),0)
                return int(pids[0])
            resolver=pid()
            waiting=threading.Thread(target=old_client);waiting.start()
            assert held.wait(2),"A never received held request"
            configure(3)
            ack=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert ack["reload"]["dnsd"]=="table",ack
            assert ask("cold-new.switch.test")=="192.0.2.3","B not active after reload"
            assert pid()==resolver
            before_release=old_done.wait(.2)
            release.set();assert sent.wait(2),"A did not send the delayed answer"
            waiting.join(3);assert not waiting.is_alive()
            print("original pending client:",old,"completed before A release:",before_release,flush=True)
            assert len(old)==1 and old[0][0]=="answer", "original client did not receive a DNS response"
            observed=[ask(name) for _ in range(4)]
            with lock:record=list(hits)
            print("new generation answers:",observed,flush=True)
            print("upstream observations:",record,flush=True)
            print("daemon pid",process.pid,"resolver pid",resolver,flush=True)
            assert not errors,errors
            assert observed==["192.0.2.3"]*4,"old upstream reply contaminated new generation"
            assert ("192.0.2.3",name) in record,"new-generation target did not reach B"
            assert sum(x==("192.0.2.3",name) for x in record)==1,"B cache did not behave as expected"
            assert pid()==resolver
            print("PASS late old UDP answer isolated from new cache; PID stable",flush=True)
        finally:
            release.set();stop.set()
            process.terminate();process.wait(timeout=5)
            for s in sockets:s.close()
            if __import__("sys").exc_info()[0]:print(log.read_text()[-5000:],flush=True)


if __name__=="__main__":main()
