#!/usr/bin/env python3
"""Isolated HY2 TCP/UDP QUIC sustained loopback profile with local revision churn."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import threading
import time
from hy2_adapter_test import Echo, command, line
from managed_baseline import control, free_port
from managed_long_budget import percentile,stats
from prototype_hy2_test import fixtures
from prototype_hy2_udp_test import DatagramEcho


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('core','client','output'):p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=620);p.add_argument('--check',action='store_true');a=p.parse_args()
    if not (10<=a.seconds<=60 if a.check else 601<=a.seconds<=900):p.error('soak 601–900 seconds; --check 10–60')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:raise RuntimeError('isolated namespace required')
    core=a.core.resolve(strict=True);client=a.client.resolve(strict=True)
    tcp=Echo();udp=DatagramEcho();stop=threading.Event();failures=[];tcp_times=[];udp_times=[];apply_times=[];connect_times=[]
    with a.output.open('x',encoding='utf8') as out,tempfile.TemporaryDirectory(prefix='steer-quic-soak-',dir='/tmp/opencode') as tmp:
        root=Path(tmp);state=root/'state';state.mkdir(mode=0o700);cert,key,_=fixtures(root);token=secrets.token_urlsafe(24);port=free_port()
        env=dict(os.environ,STEER_SOAK_PASSWORD=token,STEER_SOAK_CERT=str(cert),STEER_SOAK_KEY=str(key),STEER_LAB_HY2_TOKEN=token,STEER_LAB_CA_FILE=str(cert),STEER_LAB_EXPECT_UDP='1')
        doc={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},'plugins':{'proxy':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
            'secrets':{k:{'source':'env','kind':kind,'name':name} for k,kind,name in [('password','password','STEER_SOAK_PASSWORD'),('cert','certificate','STEER_SOAK_CERT'),('key','private_key','STEER_SOAK_KEY')]},
            'inbounds':{'hy2':{'plugin':'hysteria2:proxy','flow':['stream','datagram'],'listen':{'address':'127.0.0.1','port':port},'transport':{'type':'quic'},'options':{'principal_id':'client','password':{'secret':'password'}},'security':{'type':'tls','certificate':{'secret':'cert'},'private_key':{'secret':'key'}}}},
            'outbounds':{'net':{'type':'direct','flow':['stream','datagram']}},'routing':{'default':'net','rules':[]}}
        ctl=root/'core.sock';source=root/'source.json';source.write_text(json.dumps(doc))
        def emit(event,**kw):print(json.dumps({'event':event,'monotonic_s':time.monotonic(),**kw}),file=out,flush=True)
        emit('inputs',core_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),client_sha256=hashlib.sha256(client.read_bytes()).hexdigest(),seconds=a.seconds,netns=os.readlink('/proc/self/ns/net'))
        start=time.monotonic();proc=subprocess.Popen([str(core),'--config',str(source),'--control',str(ctl),'--state-dir',str(state)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peer=None
        try:
            assert proc.stdout.readline().startswith(b'READY ')
            emit('startup',elapsed_ms=(time.monotonic()-start)*1000,core=stats(proc.pid))
            def churn():
                revision=1
                while not stop.wait(20):
                    doc['inbounds']['hy2']['label']='soak-'+str(revision%2);t=time.perf_counter_ns();code,body=control(ctl,'APPLY',doc,revision)
                    apply_times.append((time.perf_counter_ns()-t)/1e6)
                    if code!=200 or body.get('revision')!=revision+1:failures.append('apply-'+str(code));stop.set();return
                    revision+=1
            thread=threading.Thread(target=churn);thread.start();start=time.monotonic();deadline=start+a.seconds;last=start;reconnects=0
            while not stop.is_set() and time.monotonic()<deadline:
                t=time.perf_counter_ns();peer=subprocess.Popen([str(client),f'127.0.0.1:{port}'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                assert line(peer)=='READY HY2 TCP';command(peer,'udp-cap','PASS udp-cap');connect_times.append((time.perf_counter_ns()-t)/1e6);reconnects+=1
                command(peer,'udp-open live '+udp.address+' 512','PASS udp-open')
                for _ in range(20):
                    if stop.is_set() or time.monotonic()>=deadline:break
                    t=time.perf_counter_ns();command(peer,'echo '+tcp.address+' 4096','PASS echo');tcp_times.append((time.perf_counter_ns()-t)/1e6)
                    t=time.perf_counter_ns();command(peer,'udp-send live '+udp.address+' 512','PASS udp-send');udp_times.append((time.perf_counter_ns()-t)/1e6)
                    if time.monotonic()-last>=10:
                        emit('active',elapsed_s=time.monotonic()-start,core=stats(proc.pid),tcp=len(tcp_times),udp=len(udp_times),reconnects=reconnects);last=time.monotonic()
                    stop.wait(.5)
                command(peer,'quit','PASS quit');assert peer.wait(timeout=5)==0;peer=None
            stop.set();thread.join(10);assert not thread.is_alive()
            elapsed=time.monotonic()-start
            emit('summary',elapsed_s=elapsed,core=stats(proc.pid),tcp_count=len(tcp_times),udp_count=len(udp_times),reconnects=reconnects,failures=failures,
                 tcp_payload_bytes_per_s=len(tcp_times)*4096/elapsed,udp_payload_bytes_per_s=len(udp_times)*512/elapsed,
                 tcp_ms={str(x):percentile(tcp_times,x) for x in (.5,.95,.99)},udp_ms={str(x):percentile(udp_times,x) for x in (.5,.95,.99)},
                 reconnect_ms={str(x):percentile(connect_times,x) for x in (.5,.95,.99)},apply_ms={str(x):percentile(apply_times,x) for x in (.5,.95,.99)},apply_count=len(apply_times))
            if failures or (not a.check and elapsed<601):raise RuntimeError('incomplete soak')
        finally:
            stop.set()
            if peer and peer.poll() is None:peer.kill();peer.wait(timeout=5)
            if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
            tcp.close();udp.close()

if __name__=='__main__':main()
