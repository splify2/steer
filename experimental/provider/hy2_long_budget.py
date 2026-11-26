#!/usr/bin/env python3
"""Isolated HY2 TCP/UDP QUIC windows with checked, propagated revision churn."""
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


def churn_loop(stop,doc,apply_fn,successful,failures,lock,interval=20):
    """Failures, including unexpected exceptions, fence the main workload."""
    revision=1
    try:
        while not stop.wait(interval):
            doc['inbounds']['hy2']['label']='soak-'+str(revision%2)
            started=time.perf_counter_ns()
            code,body=apply_fn(doc,revision)
            elapsed=(time.perf_counter_ns()-started)/1e6
            if code!=200 or body.get('revision')!=revision+1:
                raise RuntimeError('apply rejected or revision not advanced')
            with lock:successful.append(elapsed)
            revision+=1
    except BaseException as exc:
        with lock:failures.append('churn-'+type(exc).__name__)
        stop.set()


def check_window(elapsed,seconds,tcp_count,udp_count,reconnects,applies,check,churn):
    if elapsed<seconds or tcp_count<1 or udp_count<1 or reconnects<1:
        raise RuntimeError('incomplete time window or no verified exchanges')
    if not check and churn and applies<max(1,seconds//20-1):
        raise RuntimeError('insufficient successful revision churn')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('core','client','output'):p.add_argument('--'+arg,type=Path,required=True)
    p.add_argument('--seconds',type=int,default=900);p.add_argument('--windows',type=int,default=2)
    p.add_argument('--check',action='store_true');p.add_argument('--no-churn',action='store_true');a=p.parse_args()
    if a.windows not in (1,2):p.error('windows must be 1 or 2')
    if not (10<=a.seconds<=60 if a.check else 601<=a.seconds<=900):p.error('each soak window 601–900 seconds; --check 10–60')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:raise RuntimeError('isolated namespace required')
    core=a.core.resolve(strict=True);client=a.client.resolve(strict=True)
    tcp=Echo();udp=DatagramEcho();stop=threading.Event();lock=threading.Lock();failures=[];apply_times=[]
    with a.output.open('x',encoding='utf8') as out,tempfile.TemporaryDirectory(prefix='steer-quic-soak-',dir='/tmp/opencode') as tmp:
        root=Path(tmp);state=root/'state';state.mkdir(mode=0o700);cert,key,_=fixtures(root);token=secrets.token_urlsafe(24);port=free_port()
        env=dict(os.environ,STEER_SOAK_PASSWORD=token,STEER_SOAK_CERT=str(cert),STEER_SOAK_KEY=str(key),STEER_LAB_HY2_TOKEN=token,STEER_LAB_CA_FILE=str(cert),STEER_LAB_EXPECT_UDP='1')
        doc={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},'plugins':{'proxy':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
            'secrets':{k:{'source':'env','kind':kind,'name':name} for k,kind,name in [('password','password','STEER_SOAK_PASSWORD'),('cert','certificate','STEER_SOAK_CERT'),('key','private_key','STEER_SOAK_KEY')]},
            'inbounds':{'hy2':{'plugin':'hysteria2:proxy','flow':['stream','datagram'],'listen':{'address':'127.0.0.1','port':port},'transport':{'type':'quic'},'options':{'principal_id':'client','password':{'secret':'password'}},'security':{'type':'tls','certificate':{'secret':'cert'},'private_key':{'secret':'key'}}}},
            'outbounds':{'net':{'type':'direct','flow':['stream','datagram']}},'routing':{'default':'net','rules':[]}}
        ctl=root/'core.sock';source=root/'source.json';source.write_text(json.dumps(doc))
        def emit(event,**kw):print(json.dumps({'event':event,'monotonic_s':time.monotonic(),**kw}),file=out,flush=True)
        emit('inputs',core_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),client_sha256=hashlib.sha256(client.read_bytes()).hexdigest(),seconds=a.seconds,windows=a.windows,churn=not a.no_churn,netns=os.readlink('/proc/self/ns/net'))
        start=time.monotonic();proc=subprocess.Popen([str(core),'--config',str(source),'--control',str(ctl),'--state-dir',str(state)],env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        peer=None;thread=None
        try:
            assert proc.stdout.readline().startswith(b'READY ')
            emit('startup',elapsed_ms=(time.monotonic()-start)*1000,core=stats(proc.pid))
            if not a.no_churn:
                thread=threading.Thread(target=churn_loop,args=(stop,doc,lambda d,r:control(ctl,'APPLY',d,r),apply_times,failures,lock));thread.start()
            for window in range(1,a.windows+1):
                tcp_times=[];udp_times=[];connect_times=[];start=time.monotonic();deadline=start+a.seconds;last=start;reconnects=0
                with lock:apply_start=len(apply_times)
                emit('window_start',window=window,core=stats(proc.pid))
                while not stop.is_set() and time.monotonic()<deadline:
                    t=time.perf_counter_ns();peer=subprocess.Popen([str(client),f'127.0.0.1:{port}'],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    assert line(peer)=='READY HY2 TCP';command(peer,'udp-cap','PASS udp-cap');connect_times.append((time.perf_counter_ns()-t)/1e6);reconnects+=1
                    command(peer,'udp-open live '+udp.address+' 512','PASS udp-open')
                    for _ in range(20):
                        if stop.is_set() or time.monotonic()>=deadline:break
                        t=time.perf_counter_ns();command(peer,'echo '+tcp.address+' 4096','PASS echo');tcp_times.append((time.perf_counter_ns()-t)/1e6)
                        t=time.perf_counter_ns();command(peer,'udp-send live '+udp.address+' 512','PASS udp-send');udp_times.append((time.perf_counter_ns()-t)/1e6)
                        if time.monotonic()-last>=10:
                            with lock:current_applies=len(apply_times)
                            emit('active',window=window,elapsed_s=time.monotonic()-start,core=stats(proc.pid),tcp=len(tcp_times),udp=len(udp_times),reconnects=reconnects,successful_applies=current_applies);last=time.monotonic()
                        stop.wait(.5)
                    command(peer,'quit','PASS quit');assert peer.wait(timeout=5)==0;peer=None
                elapsed=time.monotonic()-start
                with lock:applies=apply_times[apply_start:];errors=list(failures)
                if errors:raise RuntimeError('churn thread failed: '+','.join(errors))
                check_window(elapsed,a.seconds,len(tcp_times),len(udp_times),reconnects,len(applies),a.check,not a.no_churn)
                emit('window_summary',window=window,elapsed_s=elapsed,core=stats(proc.pid),tcp_count=len(tcp_times),udp_count=len(udp_times),reconnects=reconnects,successful_applies=len(applies),
                     tcp_payload_bytes_per_s=len(tcp_times)*4096/elapsed,udp_payload_bytes_per_s=len(udp_times)*512/elapsed,
                     tcp_ms={str(x):percentile(tcp_times,x) for x in (.5,.95,.99)},udp_ms={str(x):percentile(udp_times,x) for x in (.5,.95,.99)},
                     reconnect_ms={str(x):percentile(connect_times,x) for x in (.5,.95,.99)},apply_ms={str(x):percentile(applies,x) for x in (.5,.95,.99)})
            stop.set()
            if thread:
                thread.join(10)
                if thread.is_alive():raise RuntimeError('churn thread did not stop')
            with lock:errors=list(failures);total_applies=len(apply_times)
            if errors:raise RuntimeError('churn thread failed: '+','.join(errors))
            emit('complete',windows=a.windows,successful_applies=total_applies,core=stats(proc.pid))
        except BaseException as exc:
            emit('failure',kind=type(exc).__name__)
            raise
        finally:
            stop.set()
            if thread:thread.join(10)
            if peer and peer.poll() is None:peer.kill();peer.wait(timeout=5)
            if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
            tcp.close();udp.close()

if __name__=='__main__':main()
