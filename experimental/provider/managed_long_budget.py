#!/usr/bin/env python3
"""Bounded opt-in loopback managed TCP soak; writes JSONL samples, not a release gate."""
import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from managed_baseline import EchoServer, control, free_port, read_exact, socks_connect


def stats(pid):
    root=Path('/proc')/str(pid)
    status=(root/'status').read_text().splitlines()
    roll=(root/'smaps_rollup').read_text().splitlines()
    stat=(root/'stat').read_text().rsplit(')',1)[1].split()
    return {'rss_kib':int(next(x for x in status if x.startswith('VmRSS:')).split()[1]),
            'pss_kib':int(next(x for x in roll if x.startswith('Pss:')).split()[1]),
            'fd':len(list((root/'fd').iterdir())), 'cpu_ticks':int(stat[11])+int(stat[12])}


def percentile(values,p):
    return sorted(values)[int((len(values)-1)*p)] if values else None


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core',type=Path,required=True)
    parser.add_argument('--ui',type=Path,required=True)
    parser.add_argument('--assets',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--seconds',type=int,default=620)
    parser.add_argument('--ui-reads',action='store_true',help='also issue bounded HTTP runtime reads')
    parser.add_argument('--check',action='store_true',help='short harness self-check, never a soak')
    args=parser.parse_args()
    if not (10<=args.seconds<=60 if args.check else 601<=args.seconds<=900):parser.error('soak must last 601–900 seconds; --check permits 10–60')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:raise RuntimeError('isolated network namespace required')
    core=args.core.resolve(strict=True);ui=args.ui.resolve(strict=True);assets=args.assets.resolve(strict=True)
    echo=EchoServer();echo.thread.start()
    failures=[];samples=[];connect_times=[];apply_times=[];ui_times=[];counts={'roundtrips':0,'bytes':0,'connects':0};lock=threading.Lock();stop=threading.Event()
    def emit(event,**fields):
        print(json.dumps({'event':event,'monotonic_s':round(time.monotonic(),3),**fields}),file=out,flush=True)
    with args.output.open('x',encoding='utf8') as out, tempfile.TemporaryDirectory(prefix='steer-soak-',dir='/tmp/opencode') as temp:
        root=Path(temp);state=root/'state';state.mkdir(mode=0o700)
        socks=free_port(); ui_port=free_port()
        config={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},
            'plugins':{'proxy':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
            'inbounds':{'local':{'plugin':'socks:proxy','flow':['stream'],'options':{},'listen':{'address':'127.0.0.1','port':socks}}},
            'outbounds':{'internet':{'type':'direct'},'drop':{'type':'block'}},'routing':{'default':'internet','rules':[]}}
        source,ctl=root/'source.json',root/'control.sock';source.write_text(json.dumps(config))
        emit('inputs',core_sha256=hashlib.sha256(core.read_bytes()).hexdigest(),ui_sha256=hashlib.sha256(ui.read_bytes()).hexdigest(),seconds=args.seconds,clients=4,netns=os.readlink('/proc/self/ns/net'),ticks_per_second=os.sysconf('SC_CLK_TCK'))
        t=time.monotonic();proc=subprocess.Popen([str(core),'--config',str(source),'--control',str(ctl),'--state-dir',str(state)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        host=None
        try:
            ready=proc.stdout.readline();assert ready.startswith(b'READY '),'core not ready'
            emit('core_start',elapsed_ms=(time.monotonic()-t)*1000)
            t=time.monotonic();host=subprocess.Popen([str(ui),'--assets',str(assets),'--port',str(ui_port),'--core-control',str(ctl)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            assert host.stdout.readline().startswith(b'http://127.0.0.1:'),'UI not ready'
            emit('ui_start',elapsed_ms=(time.monotonic()-t)*1000)
            held=[];failure=None
            try:
                for i in range(34):
                    try:held.append(socks_connect(socks,echo.port))
                    except (OSError,RuntimeError) as exc:failure=type(exc).__name__;break
                emit('session_probe',successful=len(held),first_failure=failure,attempted=len(held)+(1 if failure else 0))
            finally:
                for s in held:s.close()
            time.sleep(.5)
            emit('idle',core=stats(proc.pid),ui=stats(host.pid))
            deadline=time.monotonic()+args.seconds
            def worker(index):
                payload=bytes([index])*4096
                while not stop.is_set() and time.monotonic()<deadline:
                    try:
                        t0=time.perf_counter_ns()
                        with socks_connect(socks,echo.port) as stream:
                            connect_ms=(time.perf_counter_ns()-t0)/1e6
                            t1=time.perf_counter_ns();stream.sendall(payload);assert read_exact(stream,len(payload))==payload
                            elapsed=(time.perf_counter_ns()-t1)/1e6
                        with lock:connect_times.append(connect_ms);samples.append(elapsed);counts['roundtrips']+=1;counts['bytes']+=len(payload);counts['connects']+=1
                    except Exception as exc:
                        with lock:failures.append(type(exc).__name__)
                        stop.set();return
                    stop.wait(.2)
            def churn():
                revision=1
                while not stop.wait(20) and time.monotonic()<deadline:
                    config['inbounds']['local']['label']='soak-'+str(revision%2)
                    t0=time.perf_counter_ns();code,body=control(ctl,'APPLY',config,revision)
                    with lock:apply_times.append((time.perf_counter_ns()-t0)/1e6)
                    if code!=200 or body.get('revision')!=revision+1:
                        with lock:failures.append('apply-'+str(code))
                        stop.set();return
                    revision+=1
            def ui_reads():
                while not stop.is_set() and time.monotonic()<deadline:
                    connection=http.client.HTTPConnection('127.0.0.1',ui_port,timeout=5)
                    try:
                        t0=time.perf_counter_ns();connection.request('GET','/api/v1/runtime');reply=connection.getresponse()
                        data=reply.read(65537)
                        if reply.status!=200 or len(data)>65536 or json.loads(data).get('core',{}).get('connected') is not True:raise RuntimeError('UI runtime')
                        with lock:ui_times.append((time.perf_counter_ns()-t0)/1e6)
                    except Exception as exc:
                        with lock:failures.append('ui-'+type(exc).__name__)
                        stop.set();return
                    finally:connection.close()
                    stop.wait(.5)
            started=time.monotonic()
            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
                futures=[pool.submit(worker,i) for i in range(4)]+[pool.submit(churn)]
                if args.ui_reads:futures.append(pool.submit(ui_reads))
                while not stop.wait(min(10,max(0,deadline-time.monotonic()))) and time.monotonic()<deadline:
                    if proc.poll() is not None or host.poll() is not None:failures.append('process-exit');stop.set();break
                    with lock:snapshot=dict(counts)
                    emit('active',elapsed_s=time.monotonic()-started,core=stats(proc.pid),ui=stats(host.pid),**snapshot)
                stop.set()
                for f in futures:f.result(timeout=15)
            elapsed=time.monotonic()-started
            emit('summary',elapsed_s=elapsed,core=stats(proc.pid),ui=stats(host.pid),counts=counts,failures=failures,
                 payload_bytes_per_s=counts['bytes']/elapsed,roundtrip_ms={str(p):percentile(samples,p) for p in (.5,.95,.99)},
                 connect_ms={str(p):percentile(connect_times,p) for p in (.5,.95,.99)},
                 apply_ms={str(p):percentile(apply_times,p) for p in (.5,.95,.99)},apply_count=len(apply_times),
                 ui_read_ms={str(p):percentile(ui_times,p) for p in (.5,.95,.99)},ui_read_count=len(ui_times))
            if failures or (not args.check and elapsed<601):raise RuntimeError('soak did not meet duration or data correctness')
        finally:
            stop.set()
            for p in (host,proc):
                if p and p.poll() is None:
                    p.terminate()
                    try:p.wait(timeout=5)
                    except subprocess.TimeoutExpired:p.kill();p.wait(timeout=5)
            echo.stop.set();echo.thread.join(2);echo.sock.close()

if __name__=='__main__':main()
