"""Actual pinned HY2 UDP over shared managed routes. Disposable loopback only."""
import argparse,copy,os,secrets,select,socket,subprocess,tempfile,threading,time
from pathlib import Path
from prototype_hy2_test import fixtures,status,Traffic
from prototype_test import core,control,listener,free_port,socks_flow
from hy2_adapter_test import Echo,command,line

class DatagramEcho:
    def __init__(self):
        self.sockets=[];self.accepted=0;self.lock=threading.Lock();self.stop=threading.Event()
        first=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);first.bind(("127.0.0.1",0));self.sockets.append(first)
        port=first.getsockname()[1];self.address=f"127.0.0.1:{port}";self.domain=f"localhost:{port}"
        try:
            second=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM);second.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1);second.bind(("::1",port));self.sockets.append(second)
        except OSError:
            second.close()
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()
    def run(self):
        while not self.stop.is_set():
            for peer in select.select(self.sockets,[],[],.05)[0]:
                data,address=peer.recvfrom(65535)
                with self.lock:self.accepted+=1
                peer.sendto(data,address)
    def count(self):
        with self.lock:return self.accepted
    def close(self):
        self.stop.set();self.thread.join(2);assert not self.thread.is_alive()
        for peer in self.sockets:peer.close()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--host",type=Path,required=True);parser.add_argument("--client",type=Path,required=True);args=parser.parse_args()
    args.host=args.host.resolve(strict=True);args.client=args.client.resolve(strict=True)
    children=[];traffic=None;udp=DatagramEcho();denied=DatagramEcho();tcp=Echo()
    try:
        with tempfile.TemporaryDirectory(prefix="steer-managed-hy2-udp-") as temporary:
            directory=Path(temporary);certificate,key,_=fixtures(directory);token=secrets.token_urlsafe(24)
            env=dict(os.environ,STEER_LAB_EXPECT_UDP="1",STEER_LAB_HY2_TOKEN=token,STEER_LAB_CA_FILE=str(certificate),STEER_UDP_PASSWORD=token,STEER_UDP_CERT=str(certificate),STEER_UDP_KEY=str(key))
            port=free_port();socks=free_port()
            hy2={"id":"hy2","protocol":"hysteria2","listen":{"address":"127.0.0.1","port":port},"auth":{"type":"password","principal_id":"alice","password_ref":"env:STEER_UDP_PASSWORD"},"tls":{"certificate_ref":"env:STEER_UDP_CERT","private_key_ref":"env:STEER_UDP_KEY"}}
            document={"prototype":"steer-linux-v1","listeners":[listener("socks",socks),hy2],"routing":{"default":"direct","rules":[]}}
            def client():
                process=subprocess.Popen([str(args.client),f"127.0.0.1:{port}"],env=env,text=True,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE);children.append(process);assert line(process)=="READY HY2 TCP";command(process,"udp-cap","PASS udp-cap");return process
            with core(str(args.host),directory,document,extra_env=env) as path:
                first=client();second=client()
                try:command(first,"udp-open initial "+udp.address+" 3000","PASS udp-open")
                except Exception:
                    print("initial UDP target messages:",udp.count(),flush=True)
                    if first.poll() is not None:
                        reason=first.stderr.readline().strip()
                        if reason.startswith("panic: UDP"):print("client:",reason,flush=True)
                    raise
                # Pinned upstream ParseUDPMessage requires >=1 data byte.
                # Empty UDP messages are verified by the independent native gate.
                command(first,"udp-send initial "+udp.domain+" 3000","PASS udp-send")
                blocked=copy.deepcopy(document);blocked["routing"]["rules"]=[{"id":"blocked","inbound":"hy2","domain":"localhost","action":"block"}]
                code,result=control(path,"APPLY",blocked,1);assert code==200;revision=result["revision"]
                before=udp.count();command(second,"udp-open-reject overflow "+udp.domain+" 32","PASS udp-open-reject");assert udp.count()==before
                command(first,"udp-send initial "+udp.domain+" 256","PASS udp-send")
                # Old-generation two destinations + six new-generation sessions
                # fill the one shared eight-receive envelope across two QUIC peers.
                traffic=Traffic(socks_flow(socks,int(tcp.address.rsplit(":",1)[1])))
                for i in range(3):command(first,f"udp-open a{i} {udp.address} 512","PASS udp-open")
                for i in range(3):command(second,f"udp-open b{i} {udp.address} 512","PASS udp-open")
                before=udp.count();command(second,"udp-reject overflow "+udp.address+" 32","PASS udp-reject");assert udp.count()==before
                budget=status(path,lambda value:value["udpBudget"]["receiveSlots"]==8)["udpBudget"]
                assert budget["maxReceiveSlots"]==8 and budget["maxUploadBytes"]==262144 and budget["maxPackets"]==64
                for i in range(3):command(second,f"udp-partials partial{i} {udp.address}","PASS udp-partials")
                budget=status(path,lambda value:value["udpBudget"]["uploadBytes"]>=230000)["udpBudget"]
                assert budget["uploadBytes"]<=262144 and budget["receiveSlots"]==8
                # Existing real SOCKS stream continues with full global RX and
                # nearly saturated assembly/upload allocation envelope.
                before_samples=len(traffic.times);deadline=time.monotonic()+2
                while len(traffic.times)<before_samples+10 and time.monotonic()<deadline:time.sleep(.005)
                assert len(traffic.times)>=before_samples+10
                pressure=status(path)["udpBudget"]
                assert pressure["receiveSlots"]==8 and 230000<=pressure["uploadBytes"]<=262144
                traffic.close();traffic=None
                command(first,"quit","PASS quit");first.wait(timeout=5);assert first.returncode==0 and not first.stderr.read();children.remove(first)
                # No traffic/control polling supplies a GC wake after close.
                time.sleep(.25)
                drained=status(path)
                assert drained["activeClients"]<=3 and drained["retainedGenerations"]==1
                command(second,"udp-send overflow "+udp.address+" 1024","PASS udp-send")
                before=udp.count();command(second,"udp-reject overflow "+udp.domain+" 16","PASS udp-reject");assert udp.count()==before
                disabled=copy.deepcopy(blocked);disabled["listeners"][-1]["enabled"]=False
                code,result=control(path,"APPLY",disabled,revision);assert code==200
                command(second,"udp-send overflow "+udp.address+" 1024","PASS udp-send")
                before=denied.count();command(second,"udp-reject overflow "+denied.address+" 16","PASS udp-reject");assert denied.count()==before
                command(second,"quit","PASS quit");second.wait(timeout=5);assert second.returncode==0 and not second.stderr.read();children.remove(second)
                status(path,lambda value:not value["drainingListeners"] and not value["udpBudget"]["receiveSlots"] and not value["udpBudget"]["uploadBytes"] and not value["udpBudget"]["packets"])
    finally:
        if traffic:traffic.close()
        for child in children:
            child.terminate()
            try:child.communicate(timeout=5)
            except subprocess.TimeoutExpired:child.kill();child.communicate()
        udp.close();denied.close();tcp.close()
    print("Managed pinned HY2 UDP binary/fragment/quota/TCP/reload/retire gate PASS")
if __name__=="__main__":main()
