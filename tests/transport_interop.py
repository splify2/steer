#!/usr/bin/env python3
"""Xray TLS/REALITY interoperability on disposable loopback endpoints."""
import argparse, json, os, pathlib, selectors, socket, socketserver, ssl, subprocess, tempfile, threading, time
p=argparse.ArgumentParser()
p.add_argument("--xray")
p.add_argument("--oracle")
p.add_argument("--probe",required=True)
p.add_argument("--halfclose",action="store_true")
p.add_argument("--reality",action="store_true",help="Xray REALITY handshake with a local TLS mask")
p.add_argument("--network",choices=("xhttp","tcp","grpc"),default="xhttp")
a=p.parse_args()
if bool(a.xray)==bool(a.oracle):p.error("choose --xray or --oracle")
if a.reality and (not a.xray or a.network!="tcp"):p.error("REALITY requires --xray and --network tcp")
def read_port(process):
    os.set_blocking(process.stdout.fileno(),False)
    deadline=time.monotonic()+5;data=bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout,selectors.EVENT_READ)
        while b"\n" not in data and len(data)<64:
            remain=deadline-time.monotonic()
            if remain<=0 or not selector.select(remain):raise RuntimeError("oracle startup timeout")
            part=os.read(process.stdout.fileno(),64-len(data))
            if not part:raise RuntimeError("oracle startup EOF")
            data.extend(part)
    fields=bytes(data).strip().split()
    if len(fields)!=2 or fields[0]!=b"PORT":raise RuntimeError("oracle port framing")
    return int(fields[1])
class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        pending=bytearray()
        while True:
            data=self.request.recv(32768)
            if not data:
                if pending:self.request.sendall(pending)
                return
            if a.halfclose:
                pending.extend(data)
                if len(pending)>4096:raise RuntimeError("bounded echo input exceeded")
            else:self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
with tempfile.TemporaryDirectory(prefix="steer-xhttp-interop-") as path,Server(("127.0.0.1",0),Echo) as echo:
    work=pathlib.Path(path)
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(work/"key.pem"),"-out",str(work/"cert.pem"),"-days","1","-subj","/CN=localhost"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
    stream={"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h2"],"certificates":[{"certificateFile":str(work/"cert.pem"),"keyFile":str(work/"key.pem")}]},"xhttpSettings":{"path":"/lab","mode":"auto"}}
    if a.network!="xhttp":
        stream.pop("xhttpSettings")
        stream["network"]=a.network
        if a.network=="grpc":stream["grpcSettings"]={"serviceName":"lab"}
    mask = None
    public_key = None
    if a.reality:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(work/"cert.pem", work/"key.pem")
        context.set_alpn_protocols(["h2"])
        class Mask(socketserver.BaseRequestHandler):
            def handle(self):
                try:
                    self.request.settimeout(3)
                    with context.wrap_socket(self.request, server_side=True) as connection:
                        connection.recv(4096)
                except (OSError, ssl.SSLError):
                    pass
        mask = Server(("127.0.0.1",0), Mask)
        threading.Thread(target=mask.serve_forever, daemon=True).start()
        raw_keys = subprocess.check_output([a.xray,"x25519"], text=True)
        keys = dict(line.split(":",1) for line in raw_keys.splitlines() if ":" in line)
        public_key = (keys.get("Password (PublicKey)") or keys.get("Password") or keys.get("PublicKey") or "").strip()
        private_key = keys["PrivateKey"].strip()
        if not public_key:raise RuntimeError("Xray did not return a public key")
        stream.pop("tlsSettings")
        stream["security"] = "reality"
        stream["realitySettings"] = {"target":"127.0.0.1:"+str(mask.server_address[1]),
            "serverNames":["localhost"],"privateKey":private_key,"shortIds":["abcd"]}
    settings={"clients":[{"id":"00000000-0000-0000-0000-000000000001"}],"decryption":"none"}
    outbound={"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":str(echo.server_address[1])}]}}
    config={"log":{"loglevel":"debug" if os.environ.get("STEER_TEST_DEBUG") else "warning"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless","settings":settings,"streamSettings":stream}],"outbounds":[outbound]}
    (work/"config.json").write_text(json.dumps(config))
    with (work/"server.log").open("wb") as log:
        command=[a.xray,"run","-c",str(work/"config.json")] if a.xray else [a.oracle,"raw" if a.network=="tcp" else "http",str(work/"cert.pem"),str(work/"key.pem")]
        server=subprocess.Popen(command,stdout=log if a.xray else subprocess.PIPE,stderr=log)
        try:
            if a.oracle:port=read_port(server)
            for attempt in range(100):
                if server.poll() is not None:raise RuntimeError("Xray startup failed")
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=.1):break
                except OSError:time.sleep(.02)
            else:raise RuntimeError("Xray startup timeout")
            modes=("stream-one","stream-up") if a.halfclose else ("stream-one","stream-up","packet-up")
            if a.network!="xhttp":modes=(a.network,)
            for mode in modes:
                command=[a.probe,str(port),mode,str(echo.server_address[1]),"independent-Xray-echo"]
                if a.halfclose:command.append("halfclose")
                env=dict(os.environ)
                if public_key:env["STEER_TEST_REALITY_KEY"]=public_key
                subprocess.run(command,check=True,timeout=15,env=env)
                print(mode,"REALITY" if a.reality else "real TLS", "Xray" if a.xray else "Go oracle", "echo-after-EOF" if a.halfclose else "echo", "PASS",flush=True)
        except Exception:
            print((work/"server.log").read_text(errors="replace"),flush=True)
            raise
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
            echo.shutdown()
            if mask:mask.shutdown();mask.server_close()
