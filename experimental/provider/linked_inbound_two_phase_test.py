#!/usr/bin/env python3
"""Real peer traffic and real store receipts around closed inbound staging."""
import base64
import errno
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile


def main(binary,mode):
    inner=os.stat('/proc/self/ns/net');outer=os.fstat(3)
    assert (inner.st_dev,inner.st_ino)!=(outer.st_dev,outer.st_ino)
    def command(*args,input=None):
        return subprocess.run(args,input=input,check=True,capture_output=True,text=True,timeout=12).stdout
    def line(pipe):
        assert select.select([pipe],[],[],12)[0], 'fixture readiness timeout'
        value=pipe.readline();assert value, 'fixture closed unexpectedly'
        return value.strip()
    command('ip','link','set','lo','up')
    with tempfile.TemporaryDirectory(prefix='inbound-two-phase-',dir='/tmp/opencode') as tmp:
        root=Path(tmp);journal=root/'journal';store=root/'store';journal.mkdir(mode=0o700);store.mkdir(mode=0o700)
        priv=command('wg','genkey');pub=command('wg','pubkey',input=priv).strip()
        keyfile=root/'peer.key';keyfile.write_text(priv);keyfile.chmod(0o600)
        serverkey=base64.b64encode(bytes([1])+bytes(31)).decode()+'\n'
        serverpub=command('wg','pubkey',input=serverkey).strip()
        peer=subprocess.Popen(['unshare','-n','sh','-c','echo READY; exec sleep 90'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        fixture=None
        try:
            assert line(peer.stdout)=='READY'
            ns=['nsenter','-t',str(peer.pid),'-n']
            command('ip','link','add','vethhost','type','veth','peer','name','vethpeer')
            command('ip','link','set','vethpeer','netns',str(peer.pid))
            command('ip','addr','add','192.0.2.1/24','dev','vethhost');command('ip','link','set','vethhost','up')
            command(*ns,'ip','link','set','lo','up');command(*ns,'ip','addr','add','192.0.2.2/24','dev','vethpeer');command(*ns,'ip','link','set','vethpeer','up')
            fixture=subprocess.Popen([binary,str(journal),str(store),pub],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,pass_fds=(3,))
            tokens=line(fixture.stdout).split();assert tokens[0]=='CLOSED' and len(tokens)==3,tokens
            device,table=tokens[1:]
            command(*ns,'ip','link','add','wgpeer','type','wireguard')
            command(*ns,'wg','set','wgpeer','private-key',str(keyfile),'peer',serverpub,'endpoint','192.0.2.1:51821','allowed-ips','10.80.0.1/32')
            command(*ns,'ip','addr','add','10.80.0.2/24','dev','wgpeer');command(*ns,'ip','link','set','wgpeer','up')
            def ping():return subprocess.run([*ns,'ping','-q','-c','1','-W','2','-I','10.80.0.2','10.80.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5).returncode
            assert ping()!=0,'packet passed before durable receipt'
            handshakes=command('wg','show',device,'latest-handshakes').strip().split()
            assert int(handshakes[-1])>0,'no WG handshake; drop test would be inconclusive'
            print('PASS durable intent precedes create; peer handshake, payload blocked before receipt')
            if mode=='n':
                command('ip','link','add','witness0','type','wireguard')
                command('nft','add','table','inet','witness_table')
            fixture.stdin.write(mode+'\n');fixture.stdin.flush()
            done=line(fixture.stdout).split()
            if mode=='x':
                assert done==['WINDOW','SYNCED','BEFORE','PUBLISH'],done
                out,err=fixture.communicate(timeout=10);assert fixture.returncode==0,(fixture.returncode,err)
                fixture=None
                def journal_state():return {str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()}
                before=journal_state()
                probe=subprocess.run([binary,'--probe',str(journal),str(store)],pass_fds=(3,),capture_output=True,text=True,timeout=15)
                assert probe.returncode==0 and probe.stdout==f'PROBE {errno.EPROTO} 1\n',(probe.returncode,probe.stdout,probe.stderr)
                assert journal_state()==before and ping()!=0
                command('ip','link','show','dev',device);command('nft','list','table','inet',table)
                print('PASS restart after SYNCED before PUBLISH: EPROTO, fenced, DROP and resources retained')
                return
            assert done[0]=='DONE' and len(done)==8,done
            rc,phase,error,fenced,unknown,committed,disk=map(int,done[1:])
            if mode=='s':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(0,2,0,0,0,2,2),done
                assert ping()==0,'traffic failed after synced receipt and policy publication'
                print('PASS SYNCED receipt then publication: peer traffic succeeds')
            elif mode=='n':
                assert (rc,phase,fenced,unknown,committed,disk)==(errno.EIO,0,0,0,1,1) and error,done
                assert subprocess.run(['ip','link','show','dev',device],capture_output=True).returncode!=0
                assert subprocess.run(['nft','list','table','inet',table],capture_output=True).returncode!=0
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS NOT_RENAMED: owned device/guard retired, old store remains')
            elif mode=='r':
                assert (rc,phase,fenced,unknown,committed,disk)==(errno.EIO,1,1,1,1,2) and error,done
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                print('PASS RENAMED unsynced: fenced, resources retained, traffic blocked')
            elif mode=='m':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,1,1,2),done
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                print('PASS mismatched selection after SYNCED: fenced, traffic blocked')
            elif mode=='a':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert ping()==0, 'confirmed publication must not be described as unchanged'
                print('PASS confirmed publication then error: new revision fenced; policy remains active')
            else:
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                print('PASS publish failure after SYNCED: new durable revision, fenced, traffic blocked')
            fixture.stdin.write('q\n');fixture.stdin.flush();out,err=fixture.communicate(timeout=10)
            assert fixture.returncode==0,(fixture.returncode,err)
            fixture=None
        finally:
            if fixture is not None:
                fixture.kill();fixture.communicate(timeout=5)
            peer.terminate();peer.communicate(timeout=5)


if __name__=='__main__':
    if len(sys.argv)!=3 or sys.argv[2] not in ('s','n','r','p','a','m','x'):raise SystemExit('expected fixture and s/n/r/p/a/m/x')
    main(*sys.argv[1:])
