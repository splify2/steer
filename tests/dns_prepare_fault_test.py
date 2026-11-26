#!/usr/bin/env python3
"""Live table preparation ENOMEM: A remains active until the next valid B."""
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
    with tempfile.TemporaryDirectory(dir=os.environ.get("STEER_DNS_TEST_TMPDIR"),prefix="dns-prepare-") as tmp:
        root=Path(tmp);state=root/"state";state.mkdir()
        names=root/"names";names.write_text("switch.test\n")
        names_before=names.stat()
        spec=root/"spec.yaml";ctl=root/"ctl.sock";log=root/"daemon.log";arm=root/"arm"
        def configure(number):
            candidate=root/"next.yaml"
            candidate.write_text(f"""version: 2
lan: {{ devices: [lo] }}
lists:
  names: {{ domains_file: {names} }}
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
        hits=[];errors=[];lock=threading.Lock();stop=threading.Event();sockets=[];threads=[]
        def server(sock,address):
            sock.settimeout(.1)
            while not stop.is_set():
                try:q,peer=sock.recvfrom(4096)
                except socket.timeout:continue
                except OSError:return
                try:
                    pos=12;labels=[]
                    while q[pos]:
                        size=q[pos];pos+=1;labels.append(q[pos:pos+size].decode("ascii"));pos+=size
                    with lock:hits.append((address,".".join(labels)))
                    response=q[:2]+struct.pack("!5H",0x8180,1,1,0,0)+q[12:]+struct.pack("!HHHIH",0xc00c,1,1,300,4)+socket.inet_aton(address)
                    sock.sendto(response,peer)
                except Exception as exc:errors.append(repr(exc));return
        for i in (2,3):
            sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);sock.bind((f"127.0.0.{i}",53))
            sockets.append(sock);thread=threading.Thread(target=server,args=(sock,f"192.0.2.{i}"))
            thread.start();threads.append(thread)
        serial=0
        def ask(name,timeout=2):
            nonlocal serial
            serial+=1
            question=b"".join(bytes([len(x)])+x.encode() for x in name.split("."))+b"\0\0\1\0\1"
            packet=struct.pack("!6H",serial,256,1,0,0,0)+question
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as client:
                client.settimeout(timeout);client.connect(("127.0.0.1",15311));client.send(packet);response=client.recv(4096)
            assert response[:2]==packet[:2] and response[3]&15==0 and response[6:8]==b"\0\1"
            assert response[12:12+len(question)]==question
            return socket.inet_ntoa(response[-4:])
        def count(address,name):
            with lock:return hits.count((address,name))
        def wait_for(predicate,message,seconds=5):
            until=time.monotonic()+seconds
            while not predicate():
                assert process.poll() is None and time.monotonic()<until,message
                time.sleep(.01)
        configure(2)
        env=dict(os.environ,STEER_TEST_DNS_PREPARE_ARM=str(arm),STEER_SYSLOG_SOCK=str(root/"unused-syslog.sock"))
        with log.open("w") as out:
            process=subprocess.Popen([binary,"daemon","--supervise","--allow-uid",str(os.geteuid()),
                "--socket",str(ctl),"--state-dir",str(state),"--spec",str(spec),
                "--dnsd-flag","--listen-port","--dnsd-flag","15311"],stdout=out,stderr=out,env=env)
        try:
            until=time.monotonic()+6
            while True:
                assert process.poll() is None
                try:
                    if ask("ready.switch.test",.2)=="192.0.2.2":break
                except (OSError,AssertionError):pass
                assert time.monotonic()<until,"resolver readiness"
                time.sleep(.02)
            def resolver_pid():
                pids=re.findall(r"supervise: dnsd запущен \(pid (\d+)",log.read_text())
                assert len(pids)==1,pids
                os.kill(int(pids[0]),0)
                return int(pids[0])
            pid=resolver_pid()
            wait_for(lambda:"dnsd table result seq=1 accepted" in log.read_text(),"startup result missing")
            assert ask("warm.switch.test")=="192.0.2.2"
            assert ask("warm.switch.test")=="192.0.2.2"
            assert count("192.0.2.2","warm.switch.test")==1
            arm.write_text("arm")
            configure(3)
            ack1=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert ack1["reload"]["dnsd"]=="table",ack1
            assert ack1["changed"]["dnsd"] is True,ack1
            print("first B daemon ack:",ack1,flush=True)
            wait_for(lambda: "таблица отклонена, сохранена прежняя" in log.read_text(),"resolver rejection missing")
            wait_for(lambda:"dnsd table result seq=2 rejected" in log.read_text(),"rejection receipt missing")
            data=log.read_text()
            matches=re.findall(r"DNS_TEST_PREPARE_ENOMEM pid=(\d+)",data)
            assert matches==[str(pid)] and not arm.exists(),(matches,arm.exists())
            assert resolver_pid()==pid
            assert ask("cold-after.switch.test")=="192.0.2.2"
            assert ask("warm.switch.test")=="192.0.2.2"
            assert count("192.0.2.2","warm.switch.test")==1,"old cache was not preserved"
            assert count("192.0.2.2","cold-after.switch.test")==1
            assert count("192.0.2.3","cold-after.switch.test")==0
            print("after rejection: cold=A, warm=A; A cold=1, A warm=1, B cold=0",flush=True)
            before=data.count("таблица от демона:")
            unchanged_b=spec.read_bytes()
            ack2=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert ack2["reload"]["dnsd"]=="table",ack2
            assert ack2["changed"]["dnsd"] is False,ack2
            assert spec.read_bytes()==unchanged_b
            print("identical B retry daemon ack:",ack2,flush=True)
            wait_for(lambda:log.read_text().count("таблица от демона:")>before,
                     "identical B was not accepted")
            wait_for(lambda:"dnsd table result seq=3 accepted" in log.read_text(),"B acceptance receipt missing")
            assert resolver_pid()==pid
            assert ask("new-b.switch.test")=="192.0.2.3"
            assert ask("warm.switch.test")=="192.0.2.3"
            assert ask("warm.switch.test")=="192.0.2.3"
            assert count("192.0.2.3","new-b.switch.test")==1
            assert count("192.0.2.3","warm.switch.test")==1
            ack3=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert ack3["reload"]["dnsd"]=="table"
            assert ack3["changed"]["dnsd"] is False and ack3["changed"]["ruleset"] is False,ack3
            assert ask("warm.switch.test")=="192.0.2.3"
            assert count("192.0.2.3","warm.switch.test")==1,"accepted B no-op flushed warm cache"
            print("accepted B no-op daemon response:",ack3["reload"],"; warm B cache retained",flush=True)
            names_after=names.stat()
            assert names.read_text()=="switch.test\n" and (
                names_before.st_ino,names_before.st_size,names_before.st_mtime_ns
            )==(names_after.st_ino,names_after.st_size,names_after.st_mtime_ns)
            assert re.findall(r"DNS_TEST_PREPARE_ENOMEM pid=(\d+)",log.read_text())==[str(pid)]
            assert not errors,errors
            with lock:observed=list(hits)
            print("daemon ack rejected candidate:",ack1["reload"]["dnsd"],flush=True)
            print("resolver ENOMEM/rejection confirmed once; pid",pid,flush=True)
            print("resolver accepted B on direct retry",flush=True)
            print("after B: B new=1, B warm=1, repeated warm from cache",flush=True)
            print("upstream observations:",observed,flush=True)
            # Restart only the daemon. The existing resolver must be adopted,
            # and the new table session must confirm its own first frame.
            process.kill();process.wait(timeout=5)
            with log.open("a") as out:
                process=subprocess.Popen([binary,"daemon","--supervise","--allow-uid",str(os.geteuid()),
                    "--socket",str(ctl),"--state-dir",str(state),"--spec",str(spec),
                    "--dnsd-flag","--listen-port","--dnsd-flag","15311"],stdout=out,stderr=out,env=env)
            wait_for(lambda:"supervise: dnsd подхвачен (pid "+str(pid) in log.read_text(),"resolver adoption missing")
            wait_for(lambda:log.read_text().count("dnsd table result seq=1 accepted")>=2,
                     "new session did not confirm its own first frame")
            assert resolver_pid()==pid
            # A newly started daemon reconciles the ruleset. Even when the
            # table is already confirmed, replacement must force a new frame.
            prior_forced=log.read_text().count("dnsd table result seq=2 accepted")
            forced=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert forced["changed"]["ruleset"] is True and forced["changed"]["dnsd"] is False,forced
            wait_for(lambda:log.read_text().count("dnsd table result seq=2 accepted")>prior_forced,
                     "forced table reassert was not confirmed")
            assert ask("after-adopt.switch.test")=="192.0.2.3"
            assert ask("after-adopt.switch.test")=="192.0.2.3"
            assert count("192.0.2.3","after-adopt.switch.test")==1
            ack4=json.loads(subprocess.check_output([binary,"ctl","--socket",str(ctl),"reload"],timeout=5))
            assert ack4["changed"]["dnsd"] is False and ack4["changed"]["ruleset"] is False,ack4
            assert ask("after-adopt.switch.test")=="192.0.2.3"
            assert count("192.0.2.3","after-adopt.switch.test")==1
            print("PASS daemon restart adopted same resolver, new session confirmed, warm cache retained",flush=True)
            print("PASS old routing/cache after preparation failure; retry B/cache and stable PID",flush=True)
        finally:
            stop.set();process.terminate();process.wait(timeout=5)
            for thread in threads:thread.join(2)
            for sock in sockets:sock.close()
            if __import__("sys").exc_info()[0]:print(log.read_text()[-5000:],flush=True)


if __name__=="__main__":main()
