#!/usr/bin/env python3
"""SOCKS UDP JSON type, GET/Validate and durable restart regression."""
import copy
from contextlib import contextmanager
from http.client import HTTPConnection
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit

from prototype_socks_udp_test import associate, exchange
from prototype_socks_outbound_test import original
from prototype_hy2_udp_test import DatagramEcho
from prototype_test import control, core, free_port
from socks_loopback_test import exact, greeting

UI=None

@contextmanager
def http_bridge(path):
    if UI is None:
        yield None
        return
    host,assets=UI
    proc=subprocess.Popen([host,"--assets",assets,"--port","0","--core-control",str(path)],
                          stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        assert select.select([proc.stdout],[],[],5)[0],"HTTP bridge startup timeout"
        url=proc.stdout.readline().strip()
        assert url.startswith("http://127.0.0.1:"),url
        yield urlsplit(url).port
    finally:
        proc.terminate();out,err=proc.communicate(timeout=5)
        assert proc.returncode==0 and not out and not err,(proc.returncode,err)

def http(port,method,path,body=None):
    c=HTTPConnection("127.0.0.1",port,timeout=5)
    headers={"Origin":f"http://127.0.0.1:{port}"}
    if body is not None:headers["Content-Type"]="application/json"
    try:
        c.request(method,path,None if body is None else json.dumps(body),headers)
        r=c.getresponse();return r.status,json.loads(r.read())
    finally:c.close()

def rejected(port):
    with socket.create_connection(("127.0.0.1",port),timeout=5) as tcp:
        greeting(tcp)
        tcp.sendall(b"\5\3\0\1\0\0\0\0\0\0")
        assert exact(tcp,10)[1]==7

def validate_raw(path,text):
    data=text.encode()
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as sock:
        sock.settimeout(5);sock.connect(str(path))
        sock.sendall(b"VALIDATE "+str(len(data)).encode()+b"\n"+data)
        header=b""
        while not header.endswith(b"\n"):header+=exact(sock,1)
        parts=header.split()
        return 200 if parts[0]==b"OK" else int(parts[1])


def check(path,state,expected,revision,label="true"):
    code,snapshot=control(path,"GET")
    assert code==200 and snapshot["revision"]==revision
    document=snapshot["document"]
    on_disk=json.loads((state/"config.json").read_text())["document"]
    opts=document["inbounds"]["via"]["options"]
    disk_opts=on_disk["inbounds"]["via"]["options"]
    if expected is None:
        assert "udp_associate" not in opts and "udp_associate" not in disk_opts
    else:
        assert type(opts["udp_associate"]) is bool and opts["udp_associate"] is expected
        assert type(disk_opts["udp_associate"]) is bool and disk_opts["udp_associate"] is expected
    assert document["inbounds"]["via"]["label"]==label
    assert on_disk["inbounds"]["via"]["label"]==label
    assert document==on_disk
    assert control(path,"VALIDATE",document)[0]==200
    with http_bridge(path) as web:
        if web is not None:
            status,snapshot=http(web,"GET","/api/v1/config")
            assert status==200 and snapshot["revision"]==revision and snapshot["document"]==document
            opts=snapshot["document"]["inbounds"]["via"]["options"]
            if expected is None:assert "udp_associate" not in opts
            else:assert type(opts["udp_associate"]) is bool and opts["udp_associate"] is expected
            status,_=http(web,"POST","/api/v1/config/validate",
                          {"base_revision":revision,"document":snapshot["document"]})
            assert status==200
    return document


def main():
    global UI
    if len(sys.argv) not in (2,4) or os.path.samefile("/proc/self/ns/net","/proc/1/ns/net"):
        raise SystemExit("private netns, Full binary and optional UI_HOST UI_ASSETS required")
    binary=str(Path(sys.argv[1]).resolve(strict=True))
    if len(sys.argv)==4:UI=tuple(str(Path(p).resolve(strict=True)) for p in sys.argv[2:])
    echo=DatagramEcho()
    try:
        with tempfile.TemporaryDirectory(prefix="socks-udp-persist-") as tmp:
            root=Path(tmp);state=root/"state";state.mkdir(mode=0o700)
            port,direct=free_port(),free_port()
            while port==direct:direct=free_port()
            base=original(port,direct);base["routing"]["default"]="direct"
            base["inbounds"]["via"]["label"]="true"
            enabled=copy.deepcopy(base);enabled["inbounds"]["via"]["options"]["udp_associate"]=True
            target=int(echo.address.rsplit(":",1)[1])
            with core(binary,root,base,state_directory=state) as path:
                # Field absence is preserved, and strings are not booleans.
                initial=control(path,"GET")[1]["document"]
                assert "udp_associate" not in initial["inbounds"]["via"]["options"]
                for value in ("true","false"):
                    invalid=copy.deepcopy(enabled);invalid["inbounds"]["via"]["options"]["udp_associate"]=value
                    assert control(path,"VALIDATE",invalid)[0]!=200
                    assert control(path,"APPLY",invalid,1)[0]!=200
                    with http_bridge(path) as web:
                        if web is not None:
                            status,_=http(web,"POST","/api/v1/config/validate",
                                          {"base_revision":1,"document":invalid})
                            assert status==422
                tagged=json.dumps(enabled).replace('"udp_associate": true','"udp_associate": !!str true')
                assert "!!str true" in tagged and validate_raw(path,tagged)!=200
                assert control(path,"VALIDATE",enabled)[0]==200
                assert control(path,"APPLY",enabled,1)[0]==200
                check(path,state,True,2)
                tcp,udp,relay=associate(port)
                with tcp,udp:exchange(udp,relay,target,b"before-restart")
            # The persisted document, not this deliberately invalid source,
            # must start and serve an independently established association.
            with core(binary,root,"invalid source",state_directory=state,expected_revision=2) as path:
                saved=check(path,state,True,2)
                tcp,udp,relay=associate(port)
                with tcp,udp:exchange(udp,relay,target,b"after-restart")
                disabled=copy.deepcopy(saved);disabled["inbounds"]["via"]["options"]["udp_associate"]=False
                disabled["inbounds"]["via"]["label"]="false"
                assert control(path,"VALIDATE",disabled)[0]==200
                assert control(path,"APPLY",disabled,2)[0]==200
                check(path,state,False,3,"false");rejected(port)
            with core(binary,root,"invalid source",state_directory=state,expected_revision=3) as path:
                saved=check(path,state,False,3,"false");rejected(port)
                del saved["inbounds"]["via"]["options"]["udp_associate"]
                assert control(path,"APPLY",saved,3)[0]==200
                check(path,state,None,4,"false");rejected(port)
            with core(binary,root,"invalid source",state_directory=state,expected_revision=4) as path:
                check(path,state,None,4,"false");rejected(port)
        print("PASS JSON true/false/absent, strings, GET/Validate, snapshot and restart UDP"+
              (" (including HTTP)" if UI else ""),flush=True)
    finally:
        echo.close()


if __name__=="__main__":main()
