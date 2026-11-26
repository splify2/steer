#!/usr/bin/env python3
"""Real peer traffic and real store receipts around closed inbound staging."""
import base64
import contextlib
import errno
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
from prototype_test import core, free_port, listener, roundtrip, socks_flow
from socks_loopback_test import server


def main(binary,mode,socks_binary):
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
        independent=contextlib.ExitStack()
        target=independent.enter_context(server())
        socks_port=free_port()
        seed={'prototype':'steer-linux-v1','listeners':[listener('socks',socks_port)],'routing':{'default':'direct','rules':[]}}
        independent.enter_context(core(socks_binary,root,seed))
        socks=independent.enter_context(socks_flow(socks_port,target))
        roundtrip(socks,b'before-barrier')
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
            def reset_peer():
                command(*ns,'ip','link','set','wgpeer','down')
                command(*ns,'ip','link','set','wgpeer','up')
            assert ping()!=0,'packet passed before durable receipt'
            handshakes=command('wg','show',device,'latest-handshakes').strip().split()
            assert int(handshakes[-1])>0,'no WG handshake; drop test would be inconclusive'
            roundtrip(socks,b'during-drop')
            print('PASS durable intent precedes create; peer handshake, payload blocked before receipt')
            if mode in ('n','u','j','o','f','z','v','w','t'):
                command('ip','link','add','witness0','type','wireguard')
                command('nft','add','table','inet','witness_table')
            fixture.stdin.write(mode+'\n');fixture.stdin.flush()
            done=line(fixture.stdout).split()
            if mode in ('x','k'):
                expected=['WINDOW','SYNCED','BEFORE','PUBLISH'] if mode=='x' else ['WINDOW','POLICY','CHANGED','BEFORE','OUTCOME']
                assert done==expected,done
                out,err=fixture.communicate(timeout=10)
                assert fixture.returncode==(0 if mode=='x' else -signal.SIGKILL),(fixture.returncode,err)
                fixture=None
                def journal_state():return {str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()}
                before=journal_state()
                probe=subprocess.run([binary,'--probe',str(journal),str(store)],pass_fds=(3,),capture_output=True,text=True,timeout=15)
                assert probe.returncode==0 and probe.stdout==f'PROBE {errno.EPROTO} 1\n',(probe.returncode,probe.stdout,probe.stderr)
                if mode=='k':
                    link=json.loads(command('ip','-j','link','show','dev',device))[0]
                    assert 'UP' not in link['flags'],link
                    listing=json.loads(command('nft','-j','-n','list','table','inet',table))
                    rule=next(x['rule'] for x in listing['nftables'] if 'rule' in x and x['rule']['chain']=='peer_0')
                    assert rule['expr'][-1]=={'accept':None}
                    reset_peer()
                assert journal_state()==before and ping()!=0
                command('ip','link','show','dev',device);command('nft','list','table','inet',table)
                roundtrip(socks,b'after-recovery-refusal')
                print('PASS restart at '+('SYNCED-before-PUBLISH: EPROTO, DROP' if mode=='x' else 'changed-policy-before-outcome: EPROTO, owned link DOWN')+'; resources retained')
                print('PASS independent pre-existing SOCKS stream remains usable')
                return
            assert done[0]=='DONE' and len(done)==10,done
            rc,phase,error,fenced,unknown,committed,disk,barrier,publication=map(int,done[1:])
            if mode=='s':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(0,2,0,0,0,2,2),done
                assert (barrier,publication)==(2,1),done
                # Taking the server link DOWN invalidates its WG session; force
                # a new peer handshake rather than assume seamless resumption.
                reset_peer()
                assert ping()==0 or ping()==0,'traffic failed after synced receipt and new peer handshake'
                print('PASS SYNCED receipt then publication: peer traffic succeeds after new handshake')
            elif mode in ('n','v'):
                assert (rc,phase,fenced,unknown,committed,disk)==(errno.EIO,0,1 if mode=='v' else 0,0,1,1) and error,done
                assert (barrier,publication)==(0,0),done
                assert subprocess.run(['ip','link','show','dev',device],capture_output=True).returncode!=0
                assert subprocess.run(['nft','list','table','inet',table],capture_output=True).returncode!=0
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS '+('shutdown ' if mode=='v' else '')+'NOT_RENAMED: owned device/guard retired, old store remains')
            elif mode in ('r','w'):
                assert (rc,phase,fenced,unknown,committed,disk)==(errno.EIO,1,1,1,1,2) and error,done
                assert (barrier,publication)==(0,0),done
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                if mode=='w':
                    command('ip','link','show','dev','witness0')
                    command('nft','list','table','inet','witness_table')
                print('PASS '+('shutdown ' if mode=='w' else '')+'RENAMED unsynced: fenced, resources retained, traffic blocked')
            elif mode in ('z','t'):
                assert (rc,phase,error,fenced,unknown,committed,disk)==(
                    errno.ECANCELED if mode=='z' else errno.ESTALE,2,0,1,0,2,2),done
                assert (barrier,publication)==((1,0) if mode=='z' else (0,0)),done
                reset_peer()
                assert ping()!=0
                link=json.loads(command('ip','-j','link','show','dev',device))[0]
                if mode=='z':assert 'UP' not in link['flags'],link
                command('nft','list','table','inet',table)
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS shutdown SYNCED: rev2, no publication, '+('closed' if mode=='z' else 'closure UNKNOWN')+', peer blocked')
            elif mode=='m':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,1,1,2),done
                assert (barrier,publication)==(0,0),done
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                print('PASS mismatched selection after SYNCED: fenced, traffic blocked')
            elif mode=='a':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert (barrier,publication)==(1,1),done
                reset_peer()
                assert ping()!=0, 'payload passed after confirmed nft publication error'
                link=json.loads(command('ip','-j','link','show','dev',device))[0]
                assert 'UP' not in link['flags'],link
                print('PASS confirmed publication then error: new revision fenced, link confirmed DOWN, payload blocked')
            elif mode=='u':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert (barrier,publication)==(0,1),done
                reset_peer()
                link=json.loads(command('ip','-j','link','show','dev',device))[0]
                assert 'UP' not in link['flags'] and ping()!=0
                assert json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS failed re-observation: closure reported UNKNOWN, resources retained')
            elif mode=='j':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert (barrier,publication)==(1,2),done
                reset_peer()
                link=json.loads(command('ip','-j','link','show','dev',device))[0]
                assert 'UP' not in link['flags'] and ping()!=0
                listing=json.loads(command('nft','-j','-n','list','table','inet',table))
                rule=next(x['rule'] for x in listing['nftables'] if 'rule' in x and x['rule']['chain']=='peer_0')
                assert rule['expr'][-1]=={'accept':None}
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS changed nft with unsynced outcome: publication UNKNOWN, closed, payload blocked')
            elif mode=='o':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert (barrier,publication)==(1,1),done
                reset_peer()
                link=json.loads(command('ip','-j','link','show','dev',device))[0]
                assert 'UP' not in link['flags'] and ping()!=0
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS error after actual link UP: reclosed and payload blocked')
            elif mode=='f':
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.ESTALE,2,0,1,0,2,2),done
                assert (barrier,publication)==(0,0),done
                assert ping()!=0
                command('ip','link','show','dev',device)
                command('nft','list','table','inet',table)
                command('ip','link','show','dev','witness0')
                command('nft','list','table','inet','witness_table')
                print('PASS mismatched ownership: UNKNOWN, no mutation or deletion')
            else:
                assert (rc,phase,error,fenced,unknown,committed,disk)==(errno.EIO,2,0,1,0,2,2),done
                assert (barrier,publication)==(1,0),done
                reset_peer()
                assert ping()!=0 and json.loads(command('nft','-j','list','table','inet',table))
                command('ip','link','show','dev',device)
                print('PASS publish failure after SYNCED: new durable revision, fenced, traffic blocked')
            fixture.stdin.write('q\n');fixture.stdin.flush();out,err=fixture.communicate(timeout=10)
            assert fixture.returncode==0,(fixture.returncode,err)
            fixture=None
            roundtrip(socks,b'after-barrier')
            print('PASS independent pre-existing SOCKS stream remains usable')
        finally:
            if fixture is not None:
                fixture.kill();fixture.communicate(timeout=5)
            peer.terminate();peer.communicate(timeout=5)
            independent.close()


if __name__=='__main__':
    if len(sys.argv)!=4 or sys.argv[2] not in ('s','n','r','p','a','u','j','o','f','m','x','k','z','v','w','t'):raise SystemExit('expected fixture, mode and independent SOCKS host')
    main(*sys.argv[1:])
