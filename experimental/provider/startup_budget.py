#!/usr/bin/env python3
"""Fresh managed-v3 core and UI startup/apply repetitions in disposable netns."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import select
import subprocess
import tempfile
import time
from managed_baseline import control,free_port
from managed_long_budget import percentile


def ready(proc,prefix):
    if not select.select([proc.stdout],[],[],5)[0] or not proc.stdout.readline().startswith(prefix):
        raise RuntimeError('process readiness deadline')


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('core','ui','assets','output'):p.add_argument('--'+name,type=Path,required=True)
    p.add_argument('--rounds',type=int,default=20);a=p.parse_args()
    if not 5<=a.rounds<=50:p.error('rounds 5..50')
    if os.stat('/proc/self/ns/net').st_ino==os.stat('/proc/1/ns/net').st_ino:raise RuntimeError('isolated netns required')
    core=a.core.resolve(strict=True);ui=a.ui.resolve(strict=True);assets=a.assets.resolve(strict=True)
    values={'core_ms':[],'ui_ms':[],'apply_ms':[]}
    with a.output.open('x') as out,tempfile.TemporaryDirectory(prefix='startup-budget-',dir='/tmp/opencode') as tmp:
        print(json.dumps({'event':'inputs','core_sha256':hashlib.sha256(core.read_bytes()).hexdigest(),'ui_sha256':hashlib.sha256(ui.read_bytes()).hexdigest(),'rounds':a.rounds}),file=out,flush=True)
        for i in range(a.rounds):
            d=Path(tmp)/str(i);d.mkdir(mode=0o700);state=d/'state';state.mkdir(mode=0o700);ctl=d/'core.sock';source=d/'source.json'
            doc={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},'plugins':{'proxy':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},'inbounds':{'local':{'plugin':'socks:proxy','flow':['stream'],'options':{},'listen':{'address':'127.0.0.1','port':free_port()}}},'outbounds':{'internet':{'type':'direct'}},'routing':{'default':'internet','rules':[]}}
            source.write_text(json.dumps(doc));tick=time.perf_counter_ns();proc=subprocess.Popen([str(core),'--config',str(source),'--control',str(ctl),'--state-dir',str(state)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL);host=None
            try:
                ready(proc,b'READY ');core_ms=(time.perf_counter_ns()-tick)/1e6
                tick=time.perf_counter_ns();host=subprocess.Popen([str(ui),'--assets',str(assets),'--port',str(free_port()),'--core-control',str(ctl)],stdout=subprocess.PIPE,stderr=subprocess.DEVNULL)
                ready(host,b'http://127.0.0.1:');ui_ms=(time.perf_counter_ns()-tick)/1e6
                doc['inbounds']['local']['label']='measurement';tick=time.perf_counter_ns();code,body=control(ctl,'APPLY',doc,1);apply_ms=(time.perf_counter_ns()-tick)/1e6
                if code!=200 or body.get('revision')!=2:raise RuntimeError('apply failed')
                for name,value in [('core_ms',core_ms),('ui_ms',ui_ms),('apply_ms',apply_ms)]:values[name].append(value)
                print(json.dumps({'event':'sample','round':i+1,'core_ms':core_ms,'ui_ms':ui_ms,'apply_ms':apply_ms}),file=out,flush=True)
            finally:
                for proc_ in (host,proc):
                    if proc_ and proc_.poll() is None:proc_.terminate();proc_.wait(timeout=5)
        print(json.dumps({'event':'summary','rounds':a.rounds,**{name:{str(x):percentile(v,x) for x in (.5,.95,.99)} for name,v in values.items()}}),file=out,flush=True)
if __name__=='__main__':main()
