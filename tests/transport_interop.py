#!/usr/bin/env python3
"""Pinned Xray XHTTP modes over TLS; disposable loopback endpoints only."""
import argparse, json, os, pathlib, selectors, socket, socketserver, subprocess, tempfile, threading, time
p=argparse.ArgumentParser()
p.add_argument("--xray")
p.add_argument("--oracle")
p.add_argument("--probe",required=True)
p.add_argument("--halfclose",action="store_true")
p.add_argument("--prepared-engine",action="store_true",help="supply generated trust snapshot to incremental TLS test probe")
p.add_argument("--engine-negative",choices=("name","trust","records","messages","certificate","cancel-auth"))
p.add_argument("--origin-fault",choices=("flags-prepare","flags-verify","pause-prepare","pause-verify","refuse-job","close-ready","lower-release"))
p.add_argument("--network",choices=("xhttp","tcp","grpc"),default="xhttp")
a=p.parse_args()
if bool(a.xray)==bool(a.oracle):p.error("choose --xray or --oracle")
if a.engine_negative and not a.prepared_engine:p.error("engine negative requires --prepared-engine")
if a.origin_fault and (not a.prepared_engine or a.engine_negative):p.error("origin fault requires --prepared-engine and excludes --engine-negative")
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
    if a.engine_negative=="trust":
        subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",str(work/"other-key.pem"),"-out",str(work/"other-cert.pem"),"-days","1","-subj","/CN=other.invalid"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,check=True,timeout=15)
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1",0));port=reserve.getsockname()[1]
    stream={"network":"xhttp","security":"tls","tlsSettings":{"alpn":["h2"],"certificates":[{"certificateFile":str(work/"cert.pem"),"keyFile":str(work/"key.pem")}]},"xhttpSettings":{"path":"/lab","mode":"auto"}}
    if a.network!="xhttp":
        stream.pop("xhttpSettings")
        stream["network"]=a.network
        if a.network=="grpc":stream["grpcSettings"]={"serviceName":"lab"}
    settings={"clients":[{"id":"00000000-0000-0000-0000-000000000001"}],"decryption":"none"}
    outbound={"protocol":"freedom","settings":{"finalRules":[{"action":"allow","network":"tcp","ip":["127.0.0.1/32"],"port":str(echo.server_address[1])}]}}
    config={"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":port,"protocol":"vless","settings":settings,"streamSettings":stream}],"outbounds":[outbound]}
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
                if a.prepared_engine:env["STEER_TEST_ROOTS"]=str(work/"cert.pem")
                if a.engine_negative in ("name","trust"):env["STEER_TEST_ENGINE_ERROR"]="-22"
                if a.engine_negative=="name":env["STEER_TEST_NAME"]="other.invalid"
                if a.engine_negative=="trust":env["STEER_TEST_ROOTS"]=str(work/"other-cert.pem")
                if a.engine_negative in ("records","messages","certificate"):
                    env["STEER_TEST_ENGINE_LIMIT"]=a.engine_negative;env["STEER_TEST_ENGINE_ERROR"]="-13"
                if a.engine_negative=="cancel-auth":env["STEER_TEST_CANCEL_AUTH"]="1"
                if a.origin_fault:env["STEER_TLS_FAULT"]=a.origin_fault
                if a.engine_negative or a.origin_fault:
                    result=subprocess.run(command,timeout=15,env=env,capture_output=True,text=True)
                    print(result.stdout,end="",flush=True)
                    if result.stderr:print(result.stderr,end="",flush=True)
                    if result.returncode or not any(marker in result.stdout for marker in ("negative/teardown PASS","expected failure and lifecycle PASS")):
                        raise RuntimeError("negative probe did not confirm its expected failure")
                else:subprocess.run(command,check=True,timeout=15,env=env)
                if a.origin_fault:print("TLS origin",a.origin_fault,"lifecycle PASS",flush=True)
                elif a.engine_negative:print("TLS engine",a.engine_negative,"negative PASS",flush=True)
                else:print(mode,"real TLS", "Xray" if a.xray else "Go oracle", "echo-after-EOF" if a.halfclose else "echo", "PASS",flush=True)
        except Exception:
            print((work/"server.log").read_text(errors="replace"),flush=True)
            raise
        finally:
            server.terminate()
            try:server.wait(timeout=5)
            except subprocess.TimeoutExpired:server.kill();server.wait(timeout=5)
            echo.shutdown()
