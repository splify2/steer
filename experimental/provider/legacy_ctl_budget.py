#!/usr/bin/env python3
"""Compare the same version request on legacy Unix ctl; never measures data plane."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from managed_long_budget import stats,percentile


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',type=Path,required=True);p.add_argument('--output',type=Path,required=True);p.add_argument('--requests',type=int,default=1000);a=p.parse_args()
    if not 10<=a.requests<=5000:p.error('requests 10..5000')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:raise RuntimeError('isolated netns required')
    engine=a.engine.resolve(strict=True)
    with a.output.open('x') as out,tempfile.TemporaryDirectory(prefix='ctl-budget-',dir='/tmp/opencode') as tmp:
        root=Path(tmp);state=root/'state';state.mkdir();spec=root/'spec.json';sock=root/'ctl.sock'
        spec.write_text(json.dumps({'schema':1,'outputs':{'direct':{'kind':'direct'}},'channels':[]}))
        def emit(event,**fields):print(json.dumps({'event':event,**fields}),file=out,flush=True)
        t=time.monotonic();proc=subprocess.Popen([str(engine),'ctl-serve','--socket',str(sock),'--spec',str(spec),'--state-dir',str(state)],env=dict(os.environ,STEER_CTL_ENABLED='0'),stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:
            while not sock.exists():
                if proc.poll() is not None or time.monotonic()-t>5:raise RuntimeError('legacy ctl startup failed')
                time.sleep(.01)
            emit('startup',elapsed_ms=(time.monotonic()-t)*1000,sha256=hashlib.sha256(engine.read_bytes()).hexdigest(),idle=stats(proc.pid))
            values=[];start=time.monotonic();before=stats(proc.pid)
            for _ in range(a.requests):
                tick=time.perf_counter_ns()
                with socket.socket(socket.AF_UNIX) as s:
                    s.settimeout(5);s.connect(str(sock));s.sendall(b'version\n');chunks=bytearray()
                    while not chunks.endswith(b'\n'):
                        b=s.recv(65536)
                        if not b or len(chunks)>65536:raise RuntimeError('invalid ctl response')
                        chunks.extend(b)
                result=json.loads(chunks);assert result['v']==1 and result['cmd']=='version' and result['code']==0 and result['stdout']
                values.append((time.perf_counter_ns()-tick)/1e6)
            elapsed=time.monotonic()-start
            emit('summary',requests=len(values),elapsed_s=elapsed,requests_per_s=len(values)/elapsed,latency_ms={str(x):percentile(values,x) for x in (.5,.95,.99)},before=before,after=stats(proc.pid))
        finally:
            if proc.poll() is None:proc.terminate();proc.wait(timeout=5)
if __name__=='__main__':main()
