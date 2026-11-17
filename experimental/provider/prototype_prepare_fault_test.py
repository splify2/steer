"""Real TLS read barrier: healthy traffic, cancel/deadline/stale slot/shutdown."""
import argparse
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import time
from hy2_adapter_test import Echo, command, line
from prototype_hy2_test import fixtures, Traffic
from prototype_test import control, free_port, listener, socks_flow
from socks_loopback_test import exact


class PatientEcho(Echo):
    def echo(self, conn):
        conn.settimeout(15)
        super().echo(conn)


def receive(sock):
    header=b""
    while not header.endswith(b"\n"):
        header+=exact(sock,1)
        assert len(header)<128
    fields=header.split()
    code=200 if fields[0]==b"OK" else int(fields[1])
    return code,json.loads(exact(sock,int(fields[-1])))


def start_request(path, operation, document, revision=None):
    body=json.dumps(document).encode()
    header=operation+(" "+str(revision) if revision is not None else "")+" "+str(len(body))+"\n"
    sock=socket.socket(socket.AF_UNIX)
    sock.settimeout(8);sock.connect(str(path));sock.sendall(header.encode()+body)
    return sock


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host",required=True,type=Path)
    parser.add_argument("--client",required=True,type=Path)
    parser.add_argument("--shim",type=Path)
    parser.add_argument("--wrapped",action="store_true",help="host linked with test-only --wrap=read")
    args=parser.parse_args()
    echo=PatientEcho();traffic=None;process=peer=None;pending=replacement=None
    notify_r,notify_w=os.pipe();release_r,release_w=os.pipe()
    try:
        with tempfile.TemporaryDirectory(prefix="steer-prepare-fault-") as temporary:
            base=Path(temporary);certificate,key,_=fixtures(base)
            config=base/"config.json";path=base/"core.sock";arm=base/"arm"
            state=base/"state";state.mkdir(mode=0o700)
            token="public-disposable-prepare-fixture"
            socks_port,hy2_port=free_port(),free_port()
            hy2={"id":"hy2","protocol":"hysteria2","listen":{"address":"127.0.0.1","port":hy2_port},
                 "auth":{"type":"password","principal_id":"alice","password_ref":"env:PREPARE_PASSWORD"},
                 "tls":{"certificate_ref":"env:PREPARE_CERT","private_key_ref":"env:PREPARE_KEY"}}
            document={"prototype":"steer-linux-v1","listeners":[listener("socks",socks_port),hy2],"routing":{"default":"direct","rules":[]}}
            config.write_text(json.dumps(document))
            client_env=dict(os.environ,STEER_LAB_HY2_TOKEN=token,STEER_LAB_CA_FILE=str(certificate))
            env=dict(client_env,PREPARE_PASSWORD=token,PREPARE_CERT=str(certificate),PREPARE_KEY=str(key),
                     STEER_TEST_TLS_READ_PATH=str(certificate),STEER_TEST_TLS_READ_ARM=str(arm),
                     STEER_TEST_TLS_READ_NOTIFY=str(notify_w),STEER_TEST_TLS_READ_RELEASE=str(release_r))
            if not args.wrapped:
                assert args.shim,"--shim or --wrapped required"
                env["LD_PRELOAD"]=str(args.shim.resolve())
            process=subprocess.Popen([str(args.host.resolve()),"--config",str(config),"--control",str(path),"--state-dir",str(state)],env=env,
                pass_fds=(notify_w,release_r),stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert line(process).startswith("READY ")
            peer=subprocess.Popen([str(args.client.resolve()),"127.0.0.1:"+str(hy2_port)],env=client_env,
                stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            assert line(peer)=="READY HY2 TCP"
            command(peer,"hold "+echo.address,"PASS hold")
            traffic=Traffic(socks_flow(socks_port,int(echo.address.rsplit(":",1)[1])))

            def reached(value):
                assert select.select([notify_r],[],[],3)[0],"TLS worker did not enter read barrier"
                assert os.read(notify_r,1)==value

            def validate_when_idle():
                deadline=time.monotonic()+3
                while time.monotonic()<deadline:
                    code,_=control(path,"VALIDATE",document)
                    if code==200:return
                    assert code==503
                    time.sleep(.01)
                raise AssertionError("prepare admission did not recover")

            abandoned=copy.deepcopy(document)
            abandoned["listeners"][0]["label"]="must-not-publish"
            arm.write_bytes(b"1")
            pending=start_request(path,"APPLY",abandoned,1);reached(b"1")
            assert control(path,"GET")[1]["document"]==document
            assert control(path,"APPLY",document,1)[0]==503
            command(peer,"send","PASS send")
            pending.close();pending=None
            # Complete GETs ensure the old control slot is free before reuse.
            for _ in range(2):assert control(path,"GET")[1]["revision"]==1
            replacement=socket.socket(socket.AF_UNIX)
            replacement.settimeout(3);replacement.connect(str(path));replacement.sendall(b"STA")
            os.write(release_w,b"g");validate_when_idle()
            assert not select.select([replacement],[],[],.1)[0],"old result reached reused control slot"
            replacement.sendall(b"TUS\n")
            assert receive(replacement)[1]["revision"]==1
            replacement.close();replacement=None
            assert control(path,"GET")[1]["document"]==document
            published=copy.deepcopy(document);published["listeners"][0]["label"]="published"
            assert control(path,"APPLY",published,1)[1]["revision"]==2

            arm.write_bytes(b"2")
            pending=start_request(path,"APPLY",abandoned,2);reached(b"2")
            assert control(path,"APPLY",document,1)[0]==409
            for _ in range(5):assert control(path,"GET")[1]["revision"]==2
            command(peer,"send","PASS send")
            # Wait for the actual owner-loop control deadline, not a sleep.
            assert pending.recv(1)==b""
            pending.close();pending=None
            command(peer,"send","PASS send")
            os.write(release_w,b"g");validate_when_idle()
            actual=control(path,"GET")[1]
            assert actual["revision"]==2 and actual["document"]==published
            assert len(traffic.times)>100 and traffic.error is None
            traffic.close();traffic=None

            arm.write_bytes(b"3")
            pending=start_request(path,"VALIDATE",document);reached(b"3")
            process.terminate();assert pending.recv(1)==b""
            pending.close();pending=None
            assert process.poll() is None,"host freed state before blocked worker returned"
            os.write(release_w,b"g")
            assert process.wait(timeout=8)==0
            assert not process.stderr.read() and not path.exists()
            command(peer,"quit","PASS quit")
            assert peer.wait(timeout=3)==0 and not peer.stderr.read()
            print("PASS blocked TLS prepare: healthy SOCKS/HY2 and GET; bounded503/stale409; cancel/reused slot, deadline rollback, stop/join barrier")
    finally:
        if pending:pending.close()
        if replacement:replacement.close()
        try:os.write(release_w,b"ggg")
        except OSError:pass
        for child in (peer,process):
            if child and child.poll() is None:
                child.kill();child.wait(timeout=3)
            if child:
                for stream in (child.stdin,child.stdout,child.stderr):
                    if stream:stream.close()
        if traffic:
            traffic.stop.set();traffic.thread.join(3);traffic.sock.close()
        for fd in (notify_r,notify_w,release_r,release_w):os.close(fd)
        echo.close()


if __name__=="__main__":main()
