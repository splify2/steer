#!/usr/bin/env python3
"""Managed v3 SOCKS UDP generation and policy gate; private netns only."""
import copy
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
from prototype_test import core,control,free_port
from prototype_socks_outbound_test import original
from prototype_hy2_udp_test import DatagramEcho
from hy2_adapter_test import Echo
from socks_loopback_test import exact,greeting,request,response

def associate(port,credentials=None):
    tcp=socket.create_connection(("127.0.0.1",port),timeout=5)
    tcp.settimeout(5)
    if credentials:
        tcp.sendall(b"\5\1\2");assert exact(tcp,2)==b"\5\2"
        user,password=credentials
        tcp.sendall(b"\1"+bytes([len(user)])+user+bytes([len(password)])+password)
        assert exact(tcp,2)==b"\1\0"
    else:greeting(tcp)
    udp=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);udp.bind(("127.0.0.1",0));udp.settimeout(2)
    tcp.sendall(b"\5\3\0\1\0\0\0\0"+udp.getsockname()[1].to_bytes(2,"big"))
    rep=exact(tcp,10);assert rep[:4]==b"\5\0\0\1",rep
    relay=(socket.inet_ntoa(rep[4:8]),int.from_bytes(rep[8:],"big"))
    assert relay[0]=="127.0.0.1" and relay[1]
    return tcp,udp,relay

def packet(host,port,data):
    if host=="localhost":
        h=host.encode();address=b"\3"+bytes([len(h)])+h
    else:address=b"\1"+socket.inet_aton(host)
    return b"\0\0\0"+address+port.to_bytes(2,"big")+data

def exchange(udp,relay,target,data):
    wire=packet("127.0.0.1",target,data);udp.sendto(wire,relay)
    assert udp.recvfrom(65535)[0]==wire

def xray_test(binary,port,target,tmp):
    listen=free_port()
    config={"log":{"loglevel":"warning"},
        "inbounds":[{"listen":"127.0.0.1","port":listen,"protocol":"socks",
                     "settings":{"auth":"noauth","udp":True}}],
        "outbounds":[{"protocol":"socks","settings":{"servers":[{"address":"127.0.0.1","port":port}]}}]}
    path=Path(tmp)/"xray.json";path.write_text(json.dumps(config))
    process=subprocess.Popen([binary,"run","-c",str(path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    try:
        until=time.monotonic()+5
        while True:
            try: tcp,udp,relay=associate(listen);break
            except OSError:
                assert process.poll() is None and time.monotonic()<until
                time.sleep(.02)
        with tcp,udp:
            exchange(udp,relay,target,b"x")
            exchange(udp,relay,target,bytes(range(256))*16)
    finally:
        process.terminate();process.communicate(timeout=5)
    print("PASS independent Xray SOCKS outbound UDP",flush=True)

def main():
    if len(sys.argv)!=4 or os.path.samefile("/proc/self/ns/net","/proc/1/ns/net"):
        raise SystemExit("private netns, Full binary, Xray and non-Full binary required")
    binary=str(Path(sys.argv[1]).resolve(strict=True))
    xray=str(Path(sys.argv[2]).resolve(strict=True))
    minimal=str(Path(sys.argv[3]).resolve(strict=True))
    echo=DatagramEcho();denied_echo=DatagramEcho();tcp_echo=Echo()
    try:
        with tempfile.TemporaryDirectory(prefix="managed-socks-udp-") as tmp:
            port,direct=free_port(),free_port()
            while port==direct:direct=free_port()
            base=original(port,direct)
            base["routing"]["default"]="direct"
            base["routing"]["rules"].append({"name":"block-domain","match":{"inbound":["via"],"domain":["localhost"]},"outbound":"deny"})
            updated=copy.deepcopy(base);updated["inbounds"]["via"]["options"]={"udp_associate":True}
            with tempfile.TemporaryDirectory(prefix="managed-socks-minimal-") as minimal_tmp:
                with core(minimal,minimal_tmp,base) as minimal_path:
                    code,_=control(minimal_path,"VALIDATE",updated);assert code!=200
                    assert "spec_v3_socks_udp_associate_loopback_ipv4" not in control(minimal_path,"STATUS")[1]["capabilities"]
            with core(binary,tmp,base) as path:
                assert control(path,"STATUS")[1]["capabilities"]["spec_v3_socks_udp_associate_loopback_ipv4"] is True
                with socket.create_connection(("127.0.0.1",port),timeout=5) as disabled:
                    greeting(disabled);disabled.sendall(b"\5\3\0\1\0\0\0\0\0\0")
                    assert exact(disabled,10)[1]==7
                code,_=control(path,"VALIDATE",updated);assert code==200,code
                not_v4=copy.deepcopy(updated);not_v4["inbounds"]["via"]["listen"]["address"]="::1"
                assert control(path,"VALIDATE",not_v4)[0]!=200
                vpn=copy.deepcopy(updated);vpn["inbounds"]["via"]["listen"]["address"]="0.0.0.0"
                assert control(path,"VALIDATE",vpn)[0]!=200
                code,applied=control(path,"APPLY",updated,1);assert code==200,(code,applied)
                revision=applied["revision"]
                target=int(echo.address.rsplit(":",1)[1])
                xray_test(xray,port,target,tmp)
                control_tcp,udp,relay=associate(port)
                with control_tcp,udp:
                    exchange(udp,relay,target,b"x")
                    before=echo.count();denied_before=denied_echo.count()
                    denied_target=int(denied_echo.address.rsplit(":",1)[1])
                    udp.sendto(packet("localhost",denied_target,b"blocked"),relay);udp.settimeout(.3)
                    try:udp.recvfrom(65535);raise AssertionError("blocked packet received")
                    except socket.timeout:pass
                    assert echo.count()==before and denied_echo.count()==denied_before
                    udp.settimeout(2);exchange(udp,relay,target,b"allowed-again")
                    before=echo.count()
                    udp.sendto(b"\0\0\1"+packet("127.0.0.1",target,b"fragment")[3:],relay)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as foreign:
                        foreign.bind(("127.0.0.2",0))
                        foreign.sendto(packet("127.0.0.1",target,b"foreign"),relay)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as wrong_port:
                        wrong_port.bind(("127.0.0.1",0))
                        wrong_port.sendto(packet("127.0.0.1",target,b"wrong-port"),relay)
                    udp.settimeout(.2)
                    try:udp.recvfrom(65535);raise AssertionError("invalid packet received")
                    except socket.timeout:pass
                    assert echo.count()==before
                    udp.settimeout(2)
                    bad=copy.deepcopy(updated);bad["inbounds"]["via"]["options"]["udp_associate"]="invalid"
                    code,_=control(path,"APPLY",bad,revision);assert code!=200
                    exchange(udp,relay,target,b"after-rejected-apply")
                    with socket.create_connection(("127.0.0.1",port),timeout=5) as stream:
                        greeting(stream);stream.sendall(request(int(tcp_echo.address.rsplit(":",1)[1])))
                        assert response(stream)==0
                        stream.sendall(b"before");assert exact(stream,6)==b"before"
                        new=copy.deepcopy(updated);new["inbounds"]["via"]["label"]="changed-generation"
                        code,result=control(path,"APPLY",new,revision);assert code==200,(code,result)
                        assert control_tcp.recv(1)==b""
                        before=echo.count();udp.sendto(packet("127.0.0.1",target,b"retired"),relay);time.sleep(.15)
                        assert echo.count()==before
                        stream.sendall(b"after");assert exact(stream,5)==b"after"
                    new_tcp,new_udp,new_relay=associate(port)
                    with new_tcp,new_udp:
                        exchange(new_udp,new_relay,target,b"new-generation")
                        new_tcp.close();time.sleep(.15);before=echo.count()
                        new_udp.sendto(packet("127.0.0.1",target,b"closed"),new_relay)
                        time.sleep(.15);assert echo.count()==before
                until=time.monotonic()+5
                while True:
                    state=control(path,"STATUS")[1];budget=state["udpBudget"]
                    if state["retainedGenerations"]==1 and not budget["receiveSlots"] and not budget["packets"] and not budget["uploadBytes"]:break
                    assert time.monotonic()<until,(state["retainedGenerations"],budget)
                    time.sleep(.02)
                print("PASS v3 Validate/Apply, direct/block/direct, rollback, retire and CONNECT drain",flush=True)
            with tempfile.TemporaryDirectory(prefix="managed-socks-auth-") as auth_tmp:
                auth=copy.deepcopy(updated)
                auth["secrets"]={"u":{"source":"env","kind":"username","name":"STEER_TEST_S5_USER"},
                                 "p":{"source":"env","kind":"password","name":"STEER_TEST_S5_PASS"}}
                auth["inbounds"]["via"]["options"]={"udp_associate":True,"principal_id":"alice",
                    "username":{"secret":"u"},"password":{"secret":"p"}}
                with core(binary,auth_tmp,auth,extra_env={"STEER_TEST_S5_USER":"user","STEER_TEST_S5_PASS":"pass"},
                          extra_args=["--allow-socks-vpn-bind","10.8.0.1","STEER_TEST_S5_USER","STEER_TEST_S5_PASS"]) as auth_path:
                    vpn_auth=copy.deepcopy(auth);vpn_auth["inbounds"]["via"]["listen"]["address"]="10.8.0.1"
                    del vpn_auth["inbounds"]["via"]["options"]["udp_associate"]
                    assert control(auth_path,"VALIDATE",vpn_auth)[0]==200
                    vpn_auth["inbounds"]["via"]["options"]["udp_associate"]=True
                    assert control(auth_path,"VALIDATE",vpn_auth)[0]!=200
                    with socket.create_connection(("127.0.0.1",port),timeout=5) as denied:
                        denied.sendall(b"\5\1\2");assert exact(denied,2)==b"\5\2"
                        denied.sendall(b"\1\4user\3bad");assert exact(denied,2)==b"\1\1"
                    good,datagrams,rel=associate(port,(b"user",b"pass"))
                    with good,datagrams:exchange(datagrams,rel,target,b"authenticated")
                print("PASS USERPASS association and bad-credential rejection",flush=True)
    finally:
        echo.close();denied_echo.close();tcp_echo.close()

if __name__=="__main__":main()
