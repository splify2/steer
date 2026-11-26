#!/usr/bin/env python3
"""Managed experimental numeric HY2 UDP outbound; loopback-only fixture."""
import argparse
import copy
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from hy2_adapter_test import Echo, command, line
from hy2_tcp_client_test import certificate
from hy2_udp_client_test import owned_udp
from prototype_socks_outbound_test import original
from prototype_test import control, core, free_port


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--core", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--minimal", type=Path)
    args = parser.parse_args()
    binary, server, client = (str(p.resolve(strict=True)) for p in (args.core, args.server, args.client))
    with tempfile.TemporaryDirectory(dir="/tmp/opencode", prefix="hy2-managed-out-") as tmp:
        root = Path(tmp)
        ca, _, cert, key = certificate(root)
        token = "disposable-loopback-token"
        env = {"STEER_LAB_HY2_TOKEN": token, "STEER_LAB_CA_FILE": str(ca),
               "STEER_LAB_EXPECT_UDP": "1", "STEER_TEST_CA": str(ca),
               "STEER_TEST_CERT": str(cert), "STEER_TEST_KEY": str(key)}
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as target, \
             socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as reserve:
            target.bind(("127.0.0.1", 0));target.settimeout(.1)
            reserve.bind(("127.0.0.1", 0));port=reserve.getsockname()[1];reserve.close()
            cfg=root/"upstream.yaml"
            cfg.write_text(f"listen: 127.0.0.1:{port}\ntls:\n  cert: {cert}\n  key: {key}\n"
                           f"auth:\n  type: password\n  password: {token}\ndisableUDP: false\n")
            peer=subprocess.Popen([server,"--disable-update-check","-c",str(cfg),"server"],
                                  stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as disabled_reserve:
                disabled_reserve.bind(("127.0.0.1",0));disabled_port=disabled_reserve.getsockname()[1]
            disabled_cfg=root/"disabled.yaml"
            disabled_cfg.write_text(cfg.read_text().replace(f"127.0.0.1:{port}",f"127.0.0.1:{disabled_port}").replace("disableUDP: false","disableUDP: true"))
            disabled=subprocess.Popen([server,"--disable-update-check","-c",str(disabled_cfg),"server"],
                                      stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            tcp=Echo()
            stop=threading.Event();packets=[]
            def echo():
                while not stop.is_set():
                    try:data,source=target.recvfrom(2048)
                    except socket.timeout:continue
                    packets.append((data,owned_udp(peer.pid,source[1])))
                    target.sendto(data,source)
            thread=threading.Thread(target=echo);thread.start()
            process=None
            try:
                until=time.monotonic()+5
                while not owned_udp(peer.pid,port):
                    assert peer.poll() is None and time.monotonic()<until
                    time.sleep(.02)
                while not owned_udp(disabled.pid,disabled_port):
                    assert disabled.poll() is None and time.monotonic()<until
                    time.sleep(.02)
                ingress=free_port()
                base=original(free_port(),free_port())
                base["inbounds"]["hyin"]={"plugin":"hysteria2:bundle","flow":["stream","datagram"],
                    "listen":{"address":"127.0.0.1","port":ingress},
                    "options":{"principal_id":"alice","password":{"secret":"pw"}},
                    "transport":{"type":"quic"},
                    "security":{"type":"tls","certificate":{"secret":"cert"},"private_key":{"secret":"key"}}}
                base["secrets"]={
                    "pw":{"source":"env","kind":"password","name":"STEER_LAB_HY2_TOKEN"},
                    "cert":{"source":"env","kind":"certificate","name":"STEER_TEST_CERT"},
                    "key":{"source":"env","kind":"private_key","name":"STEER_TEST_KEY"},
                    "ca":{"source":"env","kind":"certificate","name":"STEER_TEST_CA"}}
                base["outbounds"]["direct"]["flow"]=["stream","datagram"]
                base["outbounds"]["deny"]["flow"]=["stream","datagram"]
                staged=copy.deepcopy(base)
                staged["outbounds"]["hy"]={"plugin":"hysteria2:bundle","flow":["stream","datagram"],
                    "variant":"numeric-udp-1000","transport":{"type":"quic"},
                    "security":{"type":"tls","server_name":"localhost","verify":True},
                    "options":{"password":{"secret":"pw"},"ca_bundle":{"secret":"ca"}},
                    "endpoint":{"address":"127.0.0.1","port":port}}
                staged["outbounds"]["unused"]=copy.deepcopy(staged["outbounds"]["hy"])
                staged["outbounds"]["unused"]["endpoint"]["port"]=disabled_port
                staged["routing"]["rules"].append({"name":"hy","match":{"inbound":["hyin"]},"outbound":"hy"})
                if args.minimal:
                    with core(str(args.minimal.resolve(strict=True)),root,original(free_port(),free_port())) as path:
                        caps=control(path,"STATUS")[1]["capabilities"]
                        assert "spec_v3_hysteria2_tcp_outbound" not in caps
                        assert "hysteria2" not in caps["providers"]
                        assert not caps["spec_v3_hysteria2"]
                        assert not any(caps["inbound"]["hysteria2"].values())
                        assert control(path,"VALIDATE",staged)[0]==422
                with core(binary,root,base,extra_env=env) as path:
                    stream_only=copy.deepcopy(staged)
                    stream_only["outbounds"]["hy"].pop("variant")
                    stream_only["outbounds"]["hy"]["flow"]=["stream"]
                    assert control(path,"VALIDATE",stream_only)[0]==422
                    assert control(path,"APPLY",stream_only,1)[0]==422
                    assert control(path,"VALIDATE",staged)[0]==200
                    assert control(path,"APPLY",staged,1)[0]==200
                    process=subprocess.Popen([client,f"127.0.0.1:{ingress}"],env=dict(os.environ,**env),
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    assert line(process)=="READY HY2 TCP"
                    command(process,"udp-cap","PASS udp-cap")
                    destination=f"127.0.0.1:{target.getsockname()[1]}"
                    command(process,f"udp-open first {destination} 1","PASS udp-open")
                    command(process,f"udp-send first {destination} 1000","PASS udp-send")
                    assert [len(p[0]) for p in packets]==[1,1000] and all(p[1] for p in packets)
                    before=len(packets)
                    command(process,f"udp-open-reject domain localhost:{target.getsockname()[1]} 1","PASS udp-open-reject")
                    command(process,f"udp-open-reject oversized {destination} 1001","PASS udp-open-reject")
                    assert len(packets)==before
                    command(process,"hold "+tcp.address,"PASS hold")
                    denied=copy.deepcopy(staged)
                    denied["outbounds"]["hy"]["endpoint"]["port"]=disabled_port
                    assert control(path,"APPLY",denied,2)[0]==200
                    command(process,"send","PASS send")
                    command(process,"quit","PASS quit");process.wait(timeout=5);process=None
                    def rejected(document,revision,label):
                        nonlocal process
                        assert control(path,"APPLY",document,revision)[0]==200
                        before=len(packets)
                        process=subprocess.Popen([client,f"127.0.0.1:{ingress}"],env=dict(os.environ,**env),
                            stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                        assert line(process)=="READY HY2 TCP"
                        command(process,f"udp-open-reject {label} {destination} 1","PASS udp-open-reject")
                        time.sleep(5.3)  # beyond the ingress open deadline
                        assert len(packets)==before,"unexpected direct fallback"
                        command(process,"quit","PASS quit");process.wait(timeout=5);process=None
                    offline=copy.deepcopy(staged)
                    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as occupied:
                        occupied.bind(("127.0.0.1",0))
                        offline["outbounds"]["hy"]["endpoint"]["port"]=occupied.getsockname()[1]
                        rejected(offline,3,"offline")
                    rejected(denied,4,"disabled")
                    assert control(path,"APPLY",staged,5)[0]==200
                    process=subprocess.Popen([client,f"127.0.0.1:{ingress}"],env=dict(os.environ,**env),
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    assert line(process)=="READY HY2 TCP"
                    command(process,f"udp-open restored {destination} 1","PASS udp-open")
                    assert packets[-1][1]
                    command(process,"quit","PASS quit");process.wait(timeout=5);process=None
                    rollback=copy.deepcopy(base)
                    rollback["routing"]["rules"].append({"name":"hy-direct","match":{"inbound":["hyin"]},"outbound":"direct"})
                    assert control(path,"APPLY",rollback,6)[0]==200
                    process=subprocess.Popen([client,f"127.0.0.1:{ingress}"],env=dict(os.environ,**env),
                        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    assert line(process)=="READY HY2 TCP"
                    command(process,f"udp-open direct {destination} 1","PASS udp-open")
                    assert not packets[-1][1]
                    command(process,"quit","PASS quit");process.wait(timeout=5);process=None
                    until=time.monotonic()+6
                    while True:
                        runtime=control(path,"STATUS")[1]
                        if runtime["retainedGenerations"]==1 and not runtime["udpBudget"]["receiveSlots"]:
                            break
                        assert time.monotonic()<until,"generation or UDP receive slot did not drain"
                        time.sleep(.02)
                    print("PASS Validate/Apply UDP upstream, TCP continuity, stream-only deny, disabled/offline fail-closed and rollback")
            finally:
                if process:
                    process.terminate()
                    out,err=process.communicate(timeout=5)
                    print("client diagnostic",process.returncode,out,err,"target packets",len(packets),flush=True)
                stop.set();thread.join(2)
                peer.terminate();peer.wait(timeout=5)
                disabled.terminate();disabled.wait(timeout=5)
                tcp.close()


if __name__=="__main__":
    main()
