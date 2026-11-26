#!/usr/bin/env python3
"""Work-in-progress common-host inbound Apply gate; run only in disposable netns."""
import base64
import copy
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time

from prototype_test import control, free_port, roundtrip, socks_flow
from socks_loopback_test import server


def main(binary,mode,shim=None,normal=None):
    outer=os.fstat(3);inner=os.stat('/proc/self/ns/net')
    assert (outer.st_dev,outer.st_ino)!=(inner.st_dev,inner.st_ino)
    def cmd(*args,input=None):
        return subprocess.run(args,input=input,text=True,capture_output=True,check=True,timeout=12).stdout
    def line(p):
        assert select.select([p],[],[],15)[0]
        result=p.readline();assert result
        return result.strip()
    def set_group(name,value):
        index=socket.if_nametoindex(name)
        body=struct.pack('=BBHiII',0,0,0,index,0,0)+struct.pack('=HHI',8,27,value)
        message=struct.pack('=IHHII',16+len(body),16,5,1,0)+body
        with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as s:
            s.bind((0,0));s.send(message)
            reply=s.recv(4096);assert len(reply)>=20 and struct.unpack_from('=i',reply,16)[0]==0
    cmd('ip','link','set','lo','up')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    with tempfile.TemporaryDirectory(prefix='inbound-host-',dir='/tmp/opencode') as tmp, server() as target:
        root=Path(tmp);state=root/'state';state.mkdir(mode=0o700)
        pause=root/'pause';entered=root/'entered';fail_file=root/'fail-file';fail_dir=root/'fail-dir'
        key=base64.b64encode(bytes([1])+bytes(31)).decode()
        psk=base64.b64encode(bytes([3])*32).decode()
        public=cmd('wg','pubkey',input=key+'\n').strip()
        peer_key=cmd('wg','genkey');peer_public=cmd('wg','pubkey',input=peer_key).strip()
        peer_file=root/'peer.key';peer_file.write_text(peer_key);peer_file.chmod(0o600)
        psk_file=root/'peer.psk';psk_file.write_text(psk+'\n');psk_file.chmod(0o600)
        port=free_port()
        base={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},
              'plugins':{'bundle':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
              'inbounds':{'socks':{'plugin':'socks:bundle','flow':['stream'],'listen':{'address':'127.0.0.1','port':port},'options':{}}},
              'outbounds':{'net':{'type':'direct','flow':['stream']}},'routing':{'default':'net','rules':[]},'secrets':{}}
        candidate=copy.deepcopy(base);candidate['outbounds']['net']['flow']=['stream','device']
        candidate['secrets']['key']={'source':'env','name':'STEER_WG_TEST_KEY','kind':'wireguard_private_key'}
        candidate['secrets']['psk']={'source':'env','name':'STEER_WG_TEST_PSK','kind':'wireguard_preshared_key'}
        candidate['inbounds']['vpn']={'plugin':'wireguard:bundle','flow':['device'],'device':{'name':'vpn'},
            'options':{'private_key':{'secret':'key'},'listen_port':51821,'addresses':['10.80.0.1/24'],
                       'peers':[{'public_key':peer_public,'principal_id':'alice','allowed_ips':['10.80.0.2/32'],
                                 'preshared_key':{'secret':'psk'}}]}}
        source=root/'seed.json';source.write_text(json.dumps(base));control_path=root/'control'
        peer=subprocess.Popen(['unshare','-n','sh','-c','echo READY; exec sleep 120'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        host=None
        try:
            assert line(peer.stdout)=='READY';ns=['nsenter','-t',str(peer.pid),'-n']
            cmd('ip','link','add','vethhost','type','veth','peer','name','vethpeer')
            cmd('ip','link','set','vethpeer','netns',str(peer.pid))
            cmd('ip','addr','add','192.0.2.1/24','dev','vethhost');cmd('ip','link','set','vethhost','up')
            cmd('ip','link','add','witness0','type','dummy');cmd('nft','add','table','inet','witness_table')
            cmd(*ns,'ip','link','set','lo','up');cmd(*ns,'ip','addr','add','192.0.2.2/24','dev','vethpeer');cmd(*ns,'ip','link','set','vethpeer','up')
            cmd(*ns,'ip','link','add','wgpeer','type','wireguard')
            cmd(*ns,'wg','set','wgpeer','private-key',str(peer_file),'peer',public,'preshared-key',str(psk_file),'endpoint','192.0.2.1:51821','allowed-ips','10.80.0.1/32')
            cmd(*ns,'ip','addr','add','10.80.0.2/24','dev','wgpeer');cmd(*ns,'ip','link','set','wgpeer','up')
            env=dict(os.environ,STEER_WG_TEST_KEY=key,STEER_WG_TEST_PSK=psk)
            if mode=='shutdown-publish':
                env.update(STEER_TEST_INBOUND_PAUSE=str(pause),STEER_TEST_INBOUND_ENTERED=str(entered))
            if mode in ('shutdown','disconnect','not-renamed','unsynced'):
                assert shim
                env.update(LD_PRELOAD=os.path.abspath(shim),STEER_TEST_PAUSE_FILE_SYNC=str(pause),
                           STEER_TEST_SYNC_ENTERED=str(entered),STEER_TEST_PAUSE_STORE_ONLY='1',
                           STEER_TEST_FAIL_FILE_SYNC=str(fail_file),STEER_TEST_FAIL_DIRECTORY_SYNC=str(fail_dir),
                           STEER_TEST_FAIL_STORE_PATH=str(state))
            host=subprocess.Popen([binary,'--config',str(source),'--control',str(control_path),'--state-dir',str(state),'--experimental-wg-inbound-netns'],
                env=env,pass_fds=(3,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
            first_pid=host.pid
            ready=line(host.stdout);assert ready.startswith('READY '),ready
            assert json.loads(ready[6:])['revision']==1
            with socks_flow(port,target) as pinned:
                roundtrip(pinned,b'before')
                if mode=='shutdown-publish':
                    pause.touch();wire=json.dumps(candidate,separators=(',',':')).encode()
                    sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(control_path))
                    sock.sendall(f'APPLY 1 {len(wire)}\n'.encode()+wire)
                    until=time.monotonic()+10
                    while not entered.exists():
                        assert time.monotonic()<until,'publication did not reach open barrier'
                        time.sleep(.01)
                    host.terminate();pause.unlink()
                    out,err=host.communicate(timeout=15);assert host.returncode==0,(host.returncode,err);host=None
                    sock.close()
                    device=cmd('wg','show','interfaces').strip()
                    link=json.loads(cmd('ip','-j','link','show','dev',device))[0]
                    assert 'UP' not in link['flags'],'SIGTERM queued during publish but barrier opened'
                    assert json.loads((state/'config.json').read_text())['revision']==2
                    cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                    assert subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6).returncode!=0
                    cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
                    print('PASS shutdown during publication: durable rev2, owned link closed, peer blocked')
                    return
                if mode in ('not-renamed','unsynced'):
                    marker=fail_file if mode=='not-renamed' else fail_dir
                    marker.touch()
                    code,body=control(control_path,'APPLY',candidate,1)
                    marker.unlink()
                    assert code==503 and not body.get('applied',False),(code,body)
                    status=control(control_path,'STATUS')[1]
                    disk=json.loads((state/'config.json').read_text())
                    if mode=='not-renamed':
                        assert status['selectedRevision']==1 and not status['splitFenced']
                        assert control(control_path,'GET')[1]['document']==base and disk['revision']==1
                        assert not cmd('wg','show','interfaces').strip()
                    else:
                        assert status['selectedRevision'] is None and status['durability_uncertain'] and status['splitFenced']
                        assert control(control_path,'GET')[0]==503 and disk['revision']==2
                        assert control(control_path,'APPLY',candidate,2)[0]==503
                        assert subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6).returncode!=0
                    roundtrip(pinned,b'after-failed-store')
                    with socks_flow(port,target) as fresh:roundtrip(fresh,b'new-after-failed-store')
                    cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
                    print('PASS common host '+mode+': no false success, old SOCKS retained')
                    return
                if mode in ('shutdown','disconnect'):
                    pause.touch();wire=json.dumps(candidate,separators=(',',':')).encode()
                    sock=socket.socket(socket.AF_UNIX);sock.settimeout(10);sock.connect(str(control_path))
                    sock.sendall(f'APPLY 1 {len(wire)}\n'.encode()+wire)
                    until=time.monotonic()+10
                    while not entered.exists():
                        assert time.monotonic()<until,'store did not reach file fsync'
                        time.sleep(.01)
                    blocked=subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6)
                    assert blocked.returncode!=0
                    device=cmd('wg','show','interfaces').strip()
                    assert int(cmd('wg','show',device,'latest-handshakes').strip().split()[-1])>0
                    roundtrip(pinned,b'during-store')
                    if mode=='shutdown':
                        host.terminate();assert sock.recv(1)==b'';assert host.poll() is None
                    sock.close();pause.unlink()
                    if mode=='shutdown':
                        out,err=host.communicate(timeout=15);assert host.returncode==0,(host.returncode,err);host=None
                        disk=json.loads((state/'config.json').read_text())
                        assert disk['revision']==2 and disk['document']==candidate
                        device=cmd('wg','show','interfaces').strip()
                        link=json.loads(cmd('ip','-j','link','show','dev',device))[0]
                        assert 'UP' not in link['flags'],link
                        assert subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6).returncode!=0
                        cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
                        prior=cmd('ip','-j','link','show')
                        restart=subprocess.run([binary,'--config',str(source),'--control',str(control_path),
                            '--state-dir',str(state),'--experimental-wg-inbound-netns'],
                            env=env,pass_fds=(3,),capture_output=True,timeout=15)
                        assert restart.returncode!=0 and not control_path.exists()
                        assert cmd('ip','-j','link','show')==prior
                        print('PASS shutdown while writer paused: rev2, closed device, no peer payload')
                        print('PASS selected but unpublished shutdown journal refused at restart')
                        return
                    until=time.monotonic()+10
                    while True:
                        code,body=control(control_path,'GET')
                        if code==200 and body['revision']==2:break
                        assert time.monotonic()<until,'disconnected Apply did not complete'
                        time.sleep(.01)
                    code,body=200,{'revision':2}
                else:code,body=control(control_path,'APPLY',candidate,1)
                if mode=='fault':
                    assert code==503 and not body.get('applied',False),(code,body)
                else:assert code==200 and body.get('revision')==2,(code,body)
                assert control(control_path,'GET')[1]['document']==candidate
                status=control(control_path,'STATUS')[1]
                assert status['selectedRevision']==2
                assert not any('wireguard' in name for name in status['capabilities'])
                if mode=='fault':
                    assert status['runtimeGeneration']==1 and status['splitFenced'] and status['inboundBarrier']=='closed',status
                    assert json.loads((state/'config.json').read_text())['revision']==2
                    device=cmd('wg','show','interfaces').strip()
                    link=json.loads(cmd('ip','-j','link','show','dev',device))[0]
                    assert 'UP' not in link['flags'],link
                    rules=json.loads(cmd('nft','-j','-n','list','ruleset'))
                    assert any(x.get('rule',{}).get('chain')=='peer_0' and
                        x['rule']['expr'][-1]=={'accept':None} for x in rules['nftables'])
                    cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                    assert subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6).returncode!=0
                    assert control(control_path,'APPLY',candidate,2)[0]==503
                else:
                    assert status['runtimeGeneration']==2
                    assert control(control_path,'APPLY',candidate,2)[0]==422
                    assert control(control_path,'APPLY',base,2)[0]==422
                roundtrip(pinned,b'after')
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'new')
                cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
                if mode!='fault':
                    cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                    subprocess.run([*ns,'ping','-q','-c','2','-W','2','-I','10.80.0.2','10.80.0.1'],check=True,timeout=10)
                    echo_port=free_port()
                    code="import socket,sys;s=socket.socket();s.bind(('10.80.0.1',int(sys.argv[1])));s.listen();print('READY',flush=True);c,_=s.accept();c.sendall(c.recv(256));c.close();s.close()"
                    echo=subprocess.Popen([sys.executable,'-c',code,str(echo_port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                    try:
                        assert line(echo.stdout)=='READY'
                        client="import socket,sys;s=socket.create_connection(('10.80.0.1',int(sys.argv[1])),5);s.sendall(b'wg-echo');assert s.recv(7)==b'wg-echo'"
                        cmd(*ns,sys.executable,'-c',client,str(echo_port))
                        out,err=echo.communicate(timeout=10);assert echo.returncode==0,err
                    finally:
                        if echo.poll() is None:echo.kill();echo.communicate()
            print('PASS common host '+('post-SYNCED fault: durable rev2, closed WG, live SOCKS' if mode=='fault' else 'DEVICE Apply, WG peer TCP echo and SOCKS'))
            device=cmd('wg','show','interfaces').strip()
            if mode=='foreign-shutdown':
                cmd('ip','link','set','dev',device,'group','0')
            host.terminate();out,err=host.communicate(timeout=15)
            assert host.returncode==(1 if mode=='foreign-shutdown' else 0),(host.returncode,err)
            host=None
            link=json.loads(cmd('ip','-j','link','show','dev',device))[0]
            cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
            if mode=='foreign-shutdown':
                assert 'UP' in link['flags'],link
                assert json.loads((state/'config.json').read_text())['revision']==2
                print('PASS shutdown refuses mismatched ownership without changing or deleting link')
                return
            assert 'UP' not in link['flags'],link
            cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
            assert subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],capture_output=True,timeout=6).returncode!=0
            print('PASS active DEVICE closed after shutdown, peer payload blocked')
            before=cmd('ip','-j','link','show')
            argv=[normal if mode=='fault' else binary,'--config',str(source),'--control',str(control_path),'--state-dir',str(state),
                  '--experimental-wg-inbound-netns']
            def journal_state():
                folder=state/'wg-inbound-journal'
                return {str(p.relative_to(folder)):p.read_bytes() for p in folder.rglob('*') if p.is_file()}
            journal_before=journal_state()
            def refused(changed_env):
                links_before=cmd('ip','-j','link','show')
                restart=subprocess.run(argv,env=changed_env,pass_fds=(3,),capture_output=True,timeout=15)
                assert restart.returncode!=0 and not control_path.exists()
                assert cmd('ip','-j','link','show')==links_before,'refused restart changed links'
                assert journal_state()==journal_before,'refused restart changed journal'
                cmd('ip','link','show','dev','witness0');cmd('nft','list','table','inet','witness_table')
            if mode in ('success','fault','disconnect','crash'):
                wrong=base64.b64encode(bytes([9])*32).decode()
                refused(dict(env,STEER_WG_TEST_KEY=wrong))
                refused(dict(env,STEER_WG_TEST_PSK=wrong))
                wrong_file=root/'wrong.key';wrong_file.write_text(wrong+'\n');wrong_file.chmod(0o600)
                local_file=root/'local.key';local_file.write_text(key+'\n');local_file.chmod(0o600)
                cmd('wg','set',device,'private-key',str(wrong_file));refused(env)
                cmd('wg','set',device,'private-key',str(local_file))
                cmd('wg','set',device,'peer',peer_public,'preshared-key',str(wrong_file));refused(env)
                cmd('wg','set',device,'peer',peer_public,'preshared-key',str(psk_file))
                cmd('wg','set',device,'peer',peer_public,'allowed-ips','10.80.0.3/32');refused(env)
                cmd('wg','set',device,'peer',peer_public,'allowed-ips','10.80.0.2/32')
                cmd('wg','set',device,'listen-port','51822');refused(env)
                cmd('wg','set',device,'listen-port','51821')
                cmd('ip','link','set','dev',device,'mtu','1300');refused(env)
                cmd('ip','link','set','dev',device,'mtu','1420')
                cmd('ip','addr','del','10.80.0.1/24','dev',device)
                cmd('ip','addr','add','10.80.0.4/24','dev',device);refused(env)
                cmd('ip','addr','del','10.80.0.4/24','dev',device)
                cmd('ip','addr','add','10.80.0.1/24','dev',device)
                group=str(int(json.loads(cmd('ip','-j','link','show','dev',device))[0]['group'])&0xffffffff)
                cmd('ip','link','set','dev',device,'group','0');refused(env)
                set_group(device,int(group))
                extra_key=cmd('wg','pubkey',input=wrong+'\n').strip()
                cmd('wg','set',device,'peer',extra_key,'allowed-ips','10.80.0.3/32');refused(env)
                cmd('wg','set',device,'peer',extra_key,'remove')
                cmd('wg','set',device,'peer',peer_public,'remove')
                cmd('wg','set',device,'peer',extra_key,'allowed-ips','10.80.0.2/32');refused(env)
                cmd('wg','set',device,'peer',extra_key,'remove')
                cmd('wg','set',device,'peer',peer_public,'preshared-key',str(psk_file),'allowed-ips','10.80.0.2/32')
                cmd('wg','set',device,'peer',peer_public,'endpoint','192.0.2.2:54321')
                cmd('ip','link','set','dev',device,'up')
                up=cmd('ip','-j','link','show')
                result=subprocess.run(argv,env=env,pass_fds=(3,),capture_output=True,timeout=15)
                assert result.returncode!=0 and not control_path.exists()
                assert cmd('ip','-j','link','show')==up
                cmd('ip','link','set','dev',device,'down')
                assert cmd('ip','-j','link','show')==before
                print('PASS changed secrets, peer, AllowedIPs, port, address, MTU, group and UP link refused before cleanup')
                host=subprocess.Popen(argv,env=env,pass_fds=(3,),stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                assert host.pid!=first_pid
                ready=line(host.stdout);assert ready.startswith('READY ') and json.loads(ready[6:])['revision']==2,ready
                assert control(control_path,'GET')[1]['document']==candidate
                with socks_flow(port,target) as fresh:roundtrip(fresh,b'restart-socks')
                cmd(*ns,'ip','link','set','wgpeer','down');cmd(*ns,'ip','link','set','wgpeer','up')
                subprocess.run([*ns,'ping','-q','-c','2','-W','2','-I','10.80.0.2','10.80.0.1'],check=True,timeout=10)
                echo_port=free_port()
                code="import socket,sys;s=socket.socket();s.bind(('10.80.0.1',int(sys.argv[1])));s.listen();print('READY',flush=True);c,_=s.accept();c.sendall(c.recv(256));c.close();s.close()"
                echo=subprocess.Popen([sys.executable,'-c',code,str(echo_port)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
                try:
                    assert line(echo.stdout)=='READY'
                    client="import socket,sys;s=socket.create_connection(('10.80.0.1',int(sys.argv[1])),5);s.sendall(b'restart');assert s.recv(7)==b'restart'"
                    cmd(*ns,sys.executable,'-c',client,str(echo_port))
                    out,err=echo.communicate(timeout=10);assert echo.returncode==0,err
                finally:
                    if echo.poll() is None:echo.kill();echo.communicate()
                if mode=='crash':
                    host.kill();out,err=host.communicate(timeout=15);assert host.returncode<0;host=None
                    control_path.unlink() # fixture owns the stale socket left by SIGKILL
                    live=cmd('ip','-j','link','show')
                    result=subprocess.run(argv,env=env,pass_fds=(3,),capture_output=True,timeout=15)
                    assert result.returncode!=0 and not control_path.exists()
                    assert cmd('ip','-j','link','show')==live and journal_state()==journal_before
                    print('PASS SIGKILL with UP DEVICE refuses recovery without mutation')
                    return
                host.terminate();out,err=host.communicate(timeout=15);assert host.returncode==0,(host.returncode,err);host=None
                assert 'UP' not in json.loads(cmd('ip','-j','link','show','dev',device))[0]['flags']
                print('PASS second host process recovers durable rev2, WG peer and SOCKS')
            if mode=='success':
                fresh=root/'fresh-state';fresh.mkdir(mode=0o700)
                source_device=root/'initial-device.json';source_device.write_text(json.dumps(candidate))
                initial=subprocess.run([binary,'--config',str(source_device),'--control',str(control_path),
                    '--state-dir',str(fresh),'--experimental-wg-inbound-netns'],env=env,pass_fds=(3,),capture_output=True,timeout=15)
                assert initial.returncode!=0 and not control_path.exists() and not (fresh/'config.json').exists()
                assert cmd('ip','-j','link','show')==before
                for stored in state.rglob('*'):
                    if stored.is_file():
                        data=stored.read_bytes()
                        assert key.encode() not in data and psk.encode() not in data and peer_key.strip().encode() not in data
                print('PASS initial DEVICE refused without opening or changing links')
                snapshot=state/'config.json';saved=snapshot.read_bytes()
                altered=json.loads(saved);altered['document']['inbounds']['vpn']['label']='not-journaled'
                snapshot.write_text(json.dumps(altered,separators=(',',':')))
                journal_before=journal_state()
                refused(env)
                snapshot.write_bytes(saved)
                print('PASS stored document mismatch refused before opening or cleanup')
                rules=json.loads(cmd('nft','-j','-n','list','ruleset'))
                table=next(item['rule']['table'] for item in rules['nftables']
                           if item.get('rule',{}).get('chain')=='peer_0')
                cmd('nft','add','rule','inet',table,'peer_0','drop')
                journal_before=journal_state()
                refused(env)
                assert 'UP' not in json.loads(cmd('ip','-j','link','show','dev',device))[0]['flags']
                print('PASS changed guard refused without opening or cleanup')
        finally:
            pause.unlink(missing_ok=True)
            fail_file.unlink(missing_ok=True);fail_dir.unlink(missing_ok=True)
            if host:
                host.terminate()
                try:out,err=host.communicate(timeout=15)
                except subprocess.TimeoutExpired:
                    host.kill();out,err=host.communicate(timeout=5)
                if host.returncode:print('host exit:',host.returncode,err,file=sys.stderr)
            peer.terminate();peer.communicate(timeout=5)


if __name__=='__main__':
    main(*sys.argv[1:])
