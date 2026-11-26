#!/usr/bin/env python3
"""Managed outbound UDP: HTTP, Xray ownership, generation and restart."""
import copy
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
from hy2_adapter_test import Echo
from prototype_socks_outbound_test import original, transfer
from prototype_socks_udp_persistence_test import http, http_bridge
import prototype_socks_udp_persistence_test as bridge
from prototype_socks_udp_test import associate, exchange, packet
from prototype_test import core, control, free_port


def main():
    if len(sys.argv)!=6 or os.path.samefile("/proc/self/ns/net","/proc/1/ns/net"):
        raise SystemExit("private netns; core xray ui-host assets nano required")
    binary,xray,ui,assets,nano=(str(Path(p).resolve(strict=True)) for p in sys.argv[1:])
    bridge.UI=(ui,assets)
    with tempfile.TemporaryDirectory(prefix="managed-socks-egress-") as tmp, \
         socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as echo:
        root=Path(tmp);state=root/"state";state.mkdir(mode=0o700)
        tcp_echo=Echo()
        echo.bind(("127.0.0.1",0));echo.settimeout(.1)
        seen=[];stopped=threading.Event();owner=[0]
        def serve():
            while not stopped.is_set():
                try:
                    data,source=echo.recvfrom(65535)
                    try:belongs=owned_udp(owner[0],source[1])
                    except FileNotFoundError:belongs=False
                    seen.append((data,source,belongs))
                    echo.sendto(data,source)
                except socket.timeout:pass
        thread=threading.Thread(target=serve,daemon=True);thread.start()
        upstream=free_port();port=free_port();direct=free_port()
        while len({upstream,port,direct})!=3:
            port,direct=free_port(),free_port()
        xconfig={"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1",
                 "port":upstream,"protocol":"socks","settings":{"auth":"noauth","udp":True}}],
                 "outbounds":[{"protocol":"freedom","settings":{}}]}
        cfg=root/"xray.json";cfg.write_text(json.dumps(xconfig))
        proc=subprocess.Popen([xray,"run","-c",str(cfg)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        owner[0]=proc.pid
        try:
            deadline=time.monotonic()+5
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",upstream),timeout=.1):break
                except OSError:
                    assert proc.poll() is None and time.monotonic()<deadline
                    time.sleep(.02)
            base=original(port,direct)
            doc=copy.deepcopy(base)
            doc["inbounds"]["via"]["options"]["udp_associate"]=True
            doc["outbounds"]["proxy"]={"plugin":"socks:bundle","flow":["stream","datagram"],
                "variant":"numeric-ipv4-udp","options":{},
                "endpoint":{"address":"127.0.0.1","port":upstream}}
            doc["routing"]["rules"].append({"name":"proxy","match":{"inbound":["via"]},"outbound":"proxy"})
            target=echo.getsockname()[1]
            with tempfile.TemporaryDirectory(prefix="socks-egress-nano-") as nano_tmp:
                with core(nano,nano_tmp,base) as path:
                    assert control(path,"VALIDATE",doc)[0]!=200
                    assert "spec_v3_socks_udp_outbound_loopback_ipv4" not in control(path,"STATUS")[1]["capabilities"]
            vpn=copy.deepcopy(doc)
            vpn["secrets"]={"u":{"source":"env","kind":"username","name":"STEER_TEST_S5_USER"},
                            "p":{"source":"env","kind":"password","name":"STEER_TEST_S5_PASS"}}
            vpn["inbounds"]["vpn"]={"plugin":"socks:bundle","listen":{"address":"10.8.0.1","port":free_port()},
                "options":{"principal_id":"vpn","username":{"secret":"u"},"password":{"secret":"p"}}}
            vpn_tcp=copy.deepcopy(vpn)
            vpn_tcp["outbounds"]["proxy"].pop("variant")
            vpn_tcp["outbounds"]["proxy"]["flow"]=["stream"]
            with tempfile.TemporaryDirectory(prefix="socks-egress-vpn-") as vpn_tmp:
                with core(binary,vpn_tmp,base,extra_env={"STEER_TEST_S5_USER":"user","STEER_TEST_S5_PASS":"pass"},
                          extra_args=["--allow-socks-vpn-bind","10.8.0.1","STEER_TEST_S5_USER","STEER_TEST_S5_PASS"]) as path:
                    assert control(path,"VALIDATE",vpn_tcp)[0]==200
                    assert control(path,"VALIDATE",vpn)[0]==422
            with core(binary,root,base,state_directory=state) as path:
                assert control(path,"STATUS")[1]["capabilities"]["spec_v3_socks_udp_outbound_loopback_ipv4"] is True
                with http_bridge(path) as web:
                    def validate(d):return http(web,"POST","/api/v1/config/validate",{"base_revision":1,"document":d})[0]
                    def apply(d,r):return http(web,"POST","/api/v1/config/apply",{"base_revision":r,"document":d})
                    assert validate(doc)==200
                    for mutate in (
                        lambda d:d["outbounds"]["proxy"]["endpoint"].update(address="127.0.0.2"),
                        lambda d:d["outbounds"]["proxy"].pop("variant"),
                        lambda d:d["outbounds"]["proxy"]["options"].update(username={"secret":"x"}),
                        lambda d:d["outbounds"]["proxy"].update(flow=["datagram"]),
                    ):
                        bad=copy.deepcopy(doc);mutate(bad);assert validate(bad)==422
                    status,result=apply(doc,1);assert status==200,(status,result)
                    status,snap=http(web,"GET","/api/v1/config");assert status==200 and snap["revision"]==2
                    saved=snap["document"];assert saved==json.loads((state/"config.json").read_text())["document"]
                    assert saved["outbounds"]["proxy"]["flow"]==["stream","datagram"]
                    assert saved["outbounds"]["proxy"]["variant"]=="numeric-ipv4-udp"
                    assert saved["outbounds"]["proxy"]["options"]=={}
                    assert type(saved["outbounds"]["proxy"]["endpoint"]["port"]) is int
                    assert saved["outbounds"]["proxy"]["endpoint"]["port"]==upstream
                    assert type(saved["inbounds"]["via"]["options"]["udp_associate"]) is bool
                    assert http(web,"POST","/api/v1/config/validate",{"base_revision":2,"document":saved})[0]==200
                    transfer(port,int(tcp_echo.address.rsplit(":",1)[1]),b"variant-stream")
                    tcp,udp,relay=associate(port)
                    with tcp,udp:
                        exchange(udp,relay,target,b"initial")
                        assert seen[-1][0]==b"initial" and seen[-1][2],seen
                        before=len(seen);udp.sendto(packet("localhost",target,b"domain-denied"),relay)
                        udp.settimeout(.3)
                        try:udp.recvfrom(65535);raise AssertionError("domain target accepted")
                        except socket.timeout:pass
                        assert len(seen)==before
                        udp.sendto(b"\0\0\0\4"+socket.inet_pton(socket.AF_INET6,"::1")+
                                   target.to_bytes(2,"big")+b"ipv6-denied",relay)
                        try:udp.recvfrom(65535);raise AssertionError("IPv6 target accepted")
                        except socket.timeout:pass
                        assert len(seen)==before
                        udp.settimeout(2)
                        bad=copy.deepcopy(saved);bad["outbounds"]["proxy"]["endpoint"]["address"]="0.0.0.0"
                        assert apply(bad,2)[0]==422
                        with socket.socket() as occupied:
                            occupied.bind(("127.0.0.1",0));occupied.listen(1)
                            conflict=copy.deepcopy(saved)
                            conflict["inbounds"]["conflict"]=copy.deepcopy(saved["inbounds"]["via"])
                            conflict["inbounds"]["conflict"]["listen"]["port"]=occupied.getsockname()[1]
                            assert http(web,"POST","/api/v1/config/validate",
                                        {"base_revision":2,"document":conflict})[0]==200
                            assert apply(conflict,2)[0]==422
                        assert apply(saved,1)[0]==409
                        exchange(udp,relay,target,b"after-rejected-stale")
                        changed=copy.deepcopy(saved);changed["inbounds"]["via"]["label"]="new generation"
                        assert apply(changed,2)[0]==200
                        assert tcp.recv(1)==b""
                        before=len(seen);udp.sendto(packet("127.0.0.1",target,b"retired"),relay)
                        time.sleep(.2);assert len(seen)==before
                    tcp,udp,relay=associate(port)
                    with tcp,udp:exchange(udp,relay,target,b"n"*4096)
                    deadline=time.monotonic()+5
                    while True:
                        status=control(path,"STATUS")[1];budget=status["udpBudget"]
                        if status["retainedGenerations"]==1 and not budget["receiveSlots"] and not budget["packets"] and not budget["uploadBytes"]:break
                        assert time.monotonic()<deadline,(status["retainedGenerations"],budget)
                        time.sleep(.02)
            with core(binary,root,"invalid source",state_directory=state,expected_revision=3) as path:
                with http_bridge(path) as web:
                    status,snap=http(web,"GET","/api/v1/config");assert status==200 and snap["revision"]==3
                    assert http(web,"POST","/api/v1/config/validate",{"base_revision":3,"document":snap["document"]})[0]==200
                    tcp,udp,relay=associate(port)
                    with tcp,udp:exchange(udp,relay,target,b"after-restart")
                    assert seen[-1][2],seen[-1]
                    proc.terminate();proc.communicate(timeout=5)
                    tcp,udp,relay=associate(port)
                    with tcp,udp:
                        before=len(seen);udp.sendto(packet("127.0.0.1",target,b"no-upstream"),relay)
                        udp.settimeout(1)
                        try:udp.recvfrom(65535);raise AssertionError("unexpected direct reply")
                        except socket.timeout:pass
                        assert len(seen)==before
            print("PASS HTTP named SOCKS UDP, upstream ownership, rollback, retirement, restart and fail-closed",flush=True)
        finally:
            if proc.poll() is None:proc.terminate();proc.communicate(timeout=5)
            stopped.set();thread.join(2)
            tcp_echo.close()


if __name__=="__main__":main()
