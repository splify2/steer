#!/usr/bin/env python3
"""Real host control gate for an inbound-device validation-only profile."""
import base64
import copy
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import time
from prototype_test import control, free_port
from socks_loopback_test import exact, greeting, request, response, server


def main(full,nano):
    outer=os.fstat(3);inner=os.stat('/proc/self/ns/net')
    assert (outer.st_dev,outer.st_ino)!=(inner.st_dev,inner.st_ino)
    subprocess.run(['ip','link','set','lo','up'],check=True,timeout=5)
    Path('/proc/sys/net/ipv4/ip_forward').write_text('0\n')
    with tempfile.TemporaryDirectory(prefix='linked-inbound-validate-',dir='/tmp/opencode') as tmp:
        root=Path(tmp);os.chmod(root,0o700)
        public='3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08='
        port=free_port()
        base={'version':3,'plugin_remotes':{'local':{'url':'https://github.com/splify2/steer-protocols','trust':'steer-linked-prototype-v1'}},
              'plugins':{'bundle':{'remote':'local','package':'steer-protocols','version':'0.0.0'}},
              'inbounds':{'socks':{'plugin':'socks:bundle','flow':['stream'],'listen':{'address':'127.0.0.1','port':port},'options':{}}},
              'outbounds':{'net':{'type':'direct','flow':['stream']}},'routing':{'default':'net','rules':[]},'secrets':{}}
        candidate=copy.deepcopy(base)
        candidate['outbounds']['net']['flow']=['stream','device']
        candidate['secrets']['key']={'source':'env','name':'STEER_WG_TEST_KEY','kind':'wireguard_private_key'}
        candidate['inbounds']['vpn']={'plugin':'wireguard:bundle','flow':['device'],'device':{'name':'vpn'},
            'options':{'private_key':{'secret':'key'},'listen_port':51821,'addresses':['10.80.0.1/24'],
                       'peers':[{'public_key':public,'principal_id':'alice','allowed_ips':['10.80.0.2/32']}]}}
        env=dict(os.environ,STEER_WG_TEST_KEY=base64.b64encode(bytes(range(1,33))).decode(),
                 STEER_WG_TEST_PSK=base64.b64encode(bytes(range(2,34))).decode())
        def run(binary,optin):
            d=root/('optin' if optin else ('nano' if binary==nano else 'normal'));d.mkdir(mode=0o700)
            state=d/'state';state.mkdir(mode=0o700);source=d/'seed.json';source.write_text(json.dumps(base));path=d/'ctl.sock'
            cmd=[binary,'--config',str(source),'--control',str(path),'--state-dir',str(state)]
            if optin:cmd.append('--validate-wg-inbound-netns')
            process=subprocess.Popen(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env,pass_fds=(3,))
            started=False
            try:
                data=bytearray();deadline=time.monotonic()+10
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout,selectors.EVENT_READ)
                    while b'\n' not in data:
                        remaining=deadline-time.monotonic()
                        assert remaining>0 and selector.select(remaining),'host startup timeout'
                        chunk=os.read(process.stdout.fileno(),8192-len(data))
                        assert chunk,'host startup EOF'
                        data.extend(chunk);assert len(data)<8192
                assert data.startswith(b'READY '),'host startup failed'
                status=json.loads(data[6:]);assert status['revision']==1 and status['runtimeReady']
                started=True
                assert all('wireguard' not in key for key in status['capabilities'])
                links_before=json.loads(subprocess.check_output(['ip','-j','link','show']))
                links_before={(x['ifindex'],x['ifname']) for x in links_before}
                before=control(path,'GET');assert before[0]==200
                stored=(state/'config.json').read_bytes()
                rc,body=control(path,'VALIDATE',candidate)
                if optin:assert rc==200 and body.get('valid') is True and body.get('validationOnly') is True and body.get('candidateRuntimeReady') is False,(rc,body)
                else:assert rc==422,(rc,body)
                rc,_=control(path,'APPLY',candidate,1);assert rc==422,rc
                after=control(path,'GET');assert after==before,(before,after)
                assert (state/'config.json').read_bytes()==stored
                with server() as target, socket.create_connection(('127.0.0.1',port),timeout=5) as sock:
                    greeting(sock);sock.sendall(request(target));assert response(sock)==0
                    sock.sendall(b'after-rejected-apply');assert exact(sock,20)==b'after-rejected-apply'
                if optin:
                    with_psk=copy.deepcopy(candidate)
                    with_psk['secrets']['psk']={'source':'env','name':'STEER_WG_TEST_PSK','kind':'wireguard_preshared_key'}
                    with_psk['inbounds']['vpn']['options']['peers'][0]['preshared_key']={'secret':'psk'}
                    assert control(path,'VALIDATE',with_psk)[0]==200
                    bad=copy.deepcopy(with_psk);bad['secrets']['psk']['kind']='wireguard_private_key';assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['inbounds']['vpn']['flow']=['device','stream'];assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['inbounds']['vpn']['options']['peers'][0]['allowed_ips']=['10.80.0.0/24'];assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['secrets']['key']['kind']='password';assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['secrets']['key']['name']='STEER_WG_MISSING';assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['inbounds']['vpn']['options']['addresses']=['10.80.0.1/16'];assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(candidate);bad['inbounds']['vpn']['options']['peers'][0]['allowed_ips']=['10.81.0.2/32'];assert control(path,'VALIDATE',bad)[0]==422
                    bad=copy.deepcopy(base);bad['outbounds']['net']['flow']=['stream','device'];assert control(path,'APPLY',bad,1)[0]==422
                    bad=copy.deepcopy(candidate);bad['routing']['default']='deny';bad['outbounds']['deny']={'type':'block','flow':['stream','device']};assert control(path,'VALIDATE',bad)[0]==422
                assert not any(x.name.startswith('wg-') for x in state.iterdir())
                links_after=json.loads(subprocess.check_output(['ip','-j','link','show']))
                assert {(x['ifindex'],x['ifname']) for x in links_after}==links_before
            finally:
                process.terminate();out,err=process.communicate(timeout=10)
                if started:assert process.returncode==0,(process.returncode,err)
        run(full,True);print('PASS opt-in: DEVICE Validate only, rejected Apply retains common store revision')
        run(full,False);run(nano,False);print('PASS standard full and Nano reject DEVICE Validate and Apply')
        def refusal(binary, pass_outer):
            d=root/('badgate' if pass_outer is False else 'nanoflag');d.mkdir(mode=0o700)
            state=d/'state';state.mkdir(mode=0o700);source=d/'seed.json';source.write_text(json.dumps(base))
            cmd=[binary,'--config',str(source),'--control',str(d/'ctl.sock'),'--state-dir',str(state),'--validate-wg-inbound-netns']
            r=subprocess.run(cmd,env=env,pass_fds=(3,) if pass_outer else (),capture_output=True,timeout=5)
            assert r.returncode==2 and not (d/'ctl.sock').exists(),r.returncode
        refusal(full,False);refusal(nano,True)
        print('PASS opt-in refuses missing outer namespace; Nano rejects opt-in')
        for stored in (False,True):
            d=root/('stored-device' if stored else 'initial-device');d.mkdir(mode=0o700)
            state=d/'state';state.mkdir(mode=0o700);source=d/'seed.json'
            source.write_text(json.dumps(base if stored else candidate))
            if stored:
                snapshot=state/'config.json'
                snapshot.write_text('{"revision":1,"format":"steer-spec-v3","document":'+json.dumps(candidate,separators=(',',':'))+'}\n')
                snapshot.chmod(0o600)
            cmd=[full,'--config',str(source),'--control',str(d/'ctl.sock'),'--state-dir',str(state),'--validate-wg-inbound-netns']
            result=subprocess.run(cmd,env=env,pass_fds=(3,),capture_output=True,timeout=10)
            assert result.returncode==1 and not (d/'ctl.sock').exists(),result.returncode
        print('PASS validation-only DEVICE cannot be activated from source or stored snapshot')


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('expected full and nano binaries')
    main(*sys.argv[1:])
