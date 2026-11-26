#!/usr/bin/env python3
"""Common-host selected DEVICE removal in disposable network namespaces."""
import base64
import concurrent.futures
import copy
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from prototype_test import control, free_port, roundtrip, socks_flow
from socks_loopback_test import server


def main(binary, mode, shim):
    assert not os.path.samefile('/proc/self/ns/net','/proc/self/fd/3')
    def cmd(*args,input=None):
        return subprocess.run(args,input=input,text=True,check=True,capture_output=True,timeout=12).stdout
    def line(pipe):
        assert select.select([pipe],[],[],15)[0]
        value=pipe.readline();assert value
        return value.strip()
    def ping(ns):
        return subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],
                              capture_output=True,timeout=6).returncode
    cmd('ip','link','set','lo','up')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    with tempfile.TemporaryDirectory(prefix='inbound-remove-',dir='/tmp/opencode') as tmp, server() as target:
        root=Path(tmp);state=root/'state';state.mkdir(mode=0o700)
        key=base64.b64encode(bytes([1])+bytes(31)).decode()
        public=cmd('wg','pubkey',input=key+'\n').strip()
        peer_key=cmd('wg','genkey');peer_public=cmd('wg','pubkey',input=peer_key).strip()
        peer_file=root/'peer.key';peer_file.write_text(peer_key);peer_file.chmod(0o600)
        port=free_port()
        base={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},
              'plugins':{'bundle':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
              'inbounds':{'socks':{'plugin':'socks:bundle','flow':['stream'],'listen':{'address':'127.0.0.1','port':port},'options':{}}},
              'outbounds':{'net':{'type':'direct','flow':['stream']}},'routing':{'default':'net','rules':[]},'secrets':{}}
        candidate=copy.deepcopy(base);candidate['outbounds']['net']['flow']=['stream','device']
        candidate['secrets']['key']={'source':'env','name':'STEER_WG_TEST_KEY','kind':'wireguard_private_key'}
        candidate['inbounds']['vpn']={'plugin':'wireguard:bundle','flow':['device'],'device':{'name':'vpn'},
            'options':{'private_key':{'secret':'key'},'listen_port':51821,'addresses':['10.80.0.1/24'],
                       'peers':[{'public_key':peer_public,'principal_id':'alice','allowed_ips':['10.80.0.2/32']}]}}
        source=root/'seed.json';source.write_text(json.dumps(base));ctl=root/'control'
        pause=root/'pause';entered=root/'entered';file_fail=root/'file-fail';dir_fail=root/'dir-fail'
        env=dict(os.environ,STEER_WG_TEST_KEY=key,LD_PRELOAD=os.path.abspath(shim),
                 STEER_TEST_PAUSE_FILE_SYNC=str(pause),STEER_TEST_SYNC_ENTERED=str(entered),
                 STEER_TEST_PAUSE_STORE_ONLY='1',STEER_TEST_FAIL_FILE_SYNC=str(file_fail),
                 STEER_TEST_FAIL_DIRECTORY_SYNC=str(dir_fail),STEER_TEST_FAIL_STORE_PATH=str(state))
        argv=[binary,'--config',str(source),'--control',str(ctl),'--state-dir',str(state),'--experimental-wg-inbound-netns']
        peer=subprocess.Popen(['unshare','-n','sh','-c','echo READY; exec sleep 120'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        host=None
        def start(revision):
            p=subprocess.Popen(argv,env=env,pass_fds=(3,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            ready=line(p.stdout);assert ready.startswith('READY ') and json.loads(ready[6:])['revision']==revision,ready
            return p
        def stop(p):
            p.terminate();out,err=p.communicate(timeout=15);assert p.returncode==0,(p.returncode,err)
        try:
            assert line(peer.stdout)=='READY';ns=['nsenter','-t',str(peer.pid),'-n']
            cmd('ip','link','add','vethhost','type','veth','peer','name','vethpeer')
            cmd('ip','link','set','vethpeer','netns',str(peer.pid))
            cmd('ip','addr','add','192.0.2.1/24','dev','vethhost');cmd('ip','link','set','vethhost','up')
            cmd('ip','link','add','witness0','type','dummy');cmd('nft','add','table','inet','witness_table')
            cmd(*ns,'ip','link','set','lo','up');cmd(*ns,'ip','addr','add','192.0.2.2/24','dev','vethpeer');cmd(*ns,'ip','link','set','vethpeer','up')
            cmd(*ns,'ip','link','add','wgpeer','type','wireguard')
            cmd(*ns,'wg','set','wgpeer','private-key',str(peer_file),'peer',public,'endpoint','192.0.2.1:51821','allowed-ips','10.80.0.1/32')
            cmd(*ns,'ip','addr','add','10.80.0.2/24','dev','wgpeer');cmd(*ns,'ip','link','set','wgpeer','up')
            host=start(1)
            code,body=control(ctl,'APPLY',candidate,1);assert code==200 and body['revision']==2,(code,body)
            device=cmd('wg','show','interfaces').strip()
            assert ping(ns)==0 or ping(ns)==0
            if mode=='restarted':
                stop(host);host=start(2)
                cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                assert ping(ns)==0 or ping(ns)==0
            with socks_flow(port,target) as pinned:
                roundtrip(pinned,b'before-remove')
                if mode=='foreign':
                    cmd('ip','link','set','dev',device,'group','0')
                if mode=='not-renamed':file_fail.touch()
                if mode=='unsynced':dir_fail.touch()
                if mode in ('disconnect','shutdown'):
                    pause.touch()
                    wire=json.dumps(base,separators=(',',':')).encode()
                    sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(ctl))
                    sock.sendall(f'APPLY 2 {len(wire)}\n'.encode()+wire)
                    deadline=time.monotonic()+10
                    while not entered.exists():
                        assert time.monotonic()<deadline,'writer did not pause'
                        time.sleep(.01)
                    assert 'UP' not in json.loads(cmd('ip','-j','link','show','dev',device))[0]['flags']
                    assert ping(ns)!=0
                    assert control(ctl,'GET')[1]['revision']==2
                    status=control(ctl,'STATUS')[1]
                    assert status['selectedRevision']==status['runtimeGeneration']==2
                    assert not status['runtimeReady'] and status['inboundBarrier']=='closed'
                    roundtrip(pinned,b'during-remove')
                    if mode=='shutdown':
                        host.terminate();assert sock.recv(1)==b'' and host.poll() is None
                    sock.close();pause.unlink()
                    if mode=='shutdown':
                        out,err=host.communicate(timeout=15);assert host.returncode==0,(host.returncode,err);host=None
                        assert json.loads((state/'config.json').read_text())['revision']==3
                        assert not cmd('wg','show','interfaces').strip()
                        host=start(3)
                        assert control(ctl,'GET')[1]['document']==base
                        with socks_flow(port,target) as fresh:roundtrip(fresh,b'shutdown-rev3')
                        print('PASS shutdown with queued removal finishes rev3 and owned cleanup')
                        return
                    deadline=time.monotonic()+10
                    while True:
                        code,got=control(ctl,'GET')
                        if code==200 and got['revision']==3:break
                        assert time.monotonic()<deadline,'disconnected removal did not complete'
                        time.sleep(.01)
                    code,body=200,{'revision':got['revision']}
                elif mode in ('cleanup','postcommit-foreign'):
                    pause.touch()
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        future=pool.submit(control,ctl,'APPLY',base,2)
                        deadline=time.monotonic()+10
                        while not entered.exists():
                            assert time.monotonic()<deadline,'writer did not pause'
                            time.sleep(.01)
                        assert 'UP' not in json.loads(cmd('ip','-j','link','show','dev',device))[0]['flags']
                        if mode=='cleanup':
                            rules=json.loads(cmd('nft','-j','-n','list','ruleset'))
                            table=next(x['rule']['table'] for x in rules['nftables'] if x.get('rule',{}).get('chain')=='peer_0')
                            cmd('nft','delete','table','inet',table);cmd('nft','add','table','inet',table)
                        else:cmd('ip','link','set','dev',device,'group','0')
                        pause.unlink();code,body=future.result(timeout=15)
                else:code,body=control(ctl,'APPLY',base,2)
                file_fail.unlink(missing_ok=True);dir_fail.unlink(missing_ok=True)
                status=control(ctl,'STATUS')[1];disk=json.loads((state/'config.json').read_text())
                if mode in ('normal','restarted','disconnect'):
                    assert code==200 and body.get('revision')==3,(code,body)
                    assert status['selectedRevision']==status['runtimeGeneration']==3 and not status['splitFenced']
                    assert status['inboundBarrier']=='absent' and status['runtimeReady']
                    assert control(ctl,'GET')[1]['document']==base and disk['revision']==3
                    assert not cmd('wg','show','interfaces').strip()
                    assert control(ctl,'APPLY',candidate,3)[0]==422
                elif mode=='unsynced':
                    assert code==503 and not body.get('applied',False) and disk['revision']==3
                    assert status['selectedRevision'] is None and status['splitFenced'] and status['durability_uncertain'] and not status['runtimeReady']
                    assert control(ctl,'GET')[0]==503
                elif mode in ('cleanup','postcommit-foreign'):
                    assert code==503 and not body.get('applied',False) and disk['revision']==3
                    assert status['selectedRevision']==3 and status['runtimeGeneration']==2 and status['splitFenced'] and not status['runtimeReady']
                    assert status['inboundBarrier']=='unknown'
                    assert control(ctl,'GET')[1]['document']==base
                    if mode=='cleanup':cmd('nft','list','table','inet',table)
                    else:cmd('ip','link','show','dev',device)
                else:
                    assert code==503 and not body.get('applied',False) and disk['revision']==2
                    assert status['selectedRevision']==2 and status['runtimeGeneration']==2 and status['splitFenced'] and not status['runtimeReady']
                    assert control(ctl,'GET')[1]['document']==candidate
                    assert status['inboundBarrier']==('unknown' if mode=='foreign' else 'closed')
                if mode not in ('normal','restarted','disconnect'):
                    assert control(ctl,'APPLY',base,2)[0]==503
                roundtrip(pinned,b'after-remove')
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'new-after-remove')
                cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
                if mode!='foreign':assert ping(ns)!=0
            if mode in ('normal','restarted','disconnect'):
                stop(host);host=start(3)
                assert control(ctl,'GET')[1]['document']==base
                assert control(ctl,'APPLY',candidate,3)[0]==422
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'restarted-rev3')
                assert not cmd('wg','show','interfaces').strip()
                print('PASS '+mode+': rev3, WG retired, SOCKS and restart')
            elif mode=='not-renamed':
                stop(host);host=start(2)
                assert control(ctl,'GET')[1]['document']==candidate
                cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                assert ping(ns)==0 or ping(ns)==0
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'revalidated-rev2')
                print('PASS not-renamed: rev2 reopens only after checked restart')
            elif mode=='unsynced':
                stop(host);host=start(3)
                assert control(ctl,'GET')[1]['document']==base
                assert not cmd('wg','show','interfaces').strip()
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'recovered-rev3')
                print('PASS unsynced: restart reconciles store and owned journal')
            elif mode in ('cleanup','postcommit-foreign'):
                stop(host);host=None
                attempt=subprocess.run(argv,env=env,pass_fds=(3,),capture_output=True,timeout=15)
                assert attempt.returncode!=0 and not ctl.exists()
                if mode=='cleanup':cmd('nft','list','table','inet',table)
                else:cmd('ip','link','show','dev',device)
                cmd('nft','list','table','inet','witness_table')
                assert json.loads((state/'config.json').read_text())['revision']==3
                print('PASS '+mode+' ambiguity: restart refuses and preserves foreign resource')
            else:print('PASS '+mode+': refused without false success; SOCKS retained')
        finally:
            pause.unlink(missing_ok=True);file_fail.unlink(missing_ok=True);dir_fail.unlink(missing_ok=True)
            if host:
                host.terminate()
                try:host.communicate(timeout=15)
                except subprocess.TimeoutExpired:host.kill();host.communicate(timeout=5)
            peer.terminate();peer.communicate(timeout=5)


if __name__=='__main__':
    main(*sys.argv[1:])
