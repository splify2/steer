#!/usr/bin/env python3
"""Real process restarts, real journal/store and guarded resources in netns."""
import errno
import base64
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main(binary):
    inner=os.stat('/proc/self/ns/net');outer=os.fstat(3)
    assert (inner.st_dev,inner.st_ino)!=(outer.st_dev,outer.st_ino)
    def command(args):return subprocess.run(args,check=True,capture_output=True,text=True,timeout=15).stdout
    command(['ip','link','set','lo','up'])
    with tempfile.TemporaryDirectory(prefix='inbound-recovery-',dir='/tmp/opencode') as tmp:
        journal=Path(tmp)/'journal';store=Path(tmp)/'store';journal.mkdir(mode=0o700);store.mkdir(mode=0o700)
        def run(mode,expected,env=None):
            p=subprocess.run([binary,mode,str(journal),str(store)],pass_fds=(3,),text=True,capture_output=True,timeout=30,env=env)
            if p.returncode!=expected:raise RuntimeError(f'{mode}: exit {p.returncode}, stdout={p.stdout!r}, stderr={p.stderr!r}')
            return p.stdout
        def parse_device(out):
            line=next(x for x in out.splitlines() if x.startswith('DEVICE '));_,name,table,marker,handle,index=line.split()
            return name,table,marker,int(handle),int(index)
        active=parse_device(run('setup',0))
        addresses=json.loads(command(['ip','-j','addr','show','dev',active[0]]))
        assert any(a.get('local')=='10.80.0.1' and a.get('prefixlen')==24
                   for a in addresses[0]['addr_info'])
        assert run('recover',0)=='RECOVERY 0\n'
        original=command(['wg','show',active[0],'peers']).strip()
        assert original=='3p7bfXt9wbTTW2HC7OQ1Nz+DQ8hbeGdNrfx+FG+IK08='
        command(['wg','set',active[0],'peer',original,'endpoint','127.0.0.1:55555'])
        assert command(['wg','show',active[0],'endpoints']).strip().split('\t')[-1]=='127.0.0.1:55555'
        assert run('recover',0)=='RECOVERY 0\n'
        print('PASS first process restart: inbound peer, guard and roaming endpoint')
        orphan=parse_device(run('orphan',0))
        def table(t):return json.loads(command(['nft','-j','-n','list','table','inet',t]))
        def journal_state():
            return {str(p.relative_to(journal)):p.read_bytes() for p in journal.rglob('*') if p.is_file()}
        prior=table(orphan[1]);assert prior['nftables'][1]['table']['handle']==orphan[3]
        records=journal_state()
        command(['ip','link','set','dev',active[0],'down'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ENETDOWN}\n'
            assert table(orphan[1])==prior and journal_state()==records
        finally:
            command(['ip','link','set','dev',active[0],'up'])
        print('PASS owned but DOWN device refused before cleanup')
        assert run('wrong-digest',1)==f'RECOVERY {errno.EPROTO}\n'
        assert run('wrong-generation',1)==f'RECOVERY {errno.EPROTO}\n'
        assert run('wrong-role',1)==f'RECOVERY {errno.EOPNOTSUPP}\n'
        assert run('extra-policy',1)==f'RECOVERY {errno.EOPNOTSUPP}\n'
        assert run('expired',1)==f'RECOVERY {errno.ETIMEDOUT}\n'
        fake=Path(tmp)/'tools';fake.mkdir(mode=0o700);nft=fake/'nft'
        nft.write_text('#!/bin/sh\nexit 1\n');nft.chmod(0o700)
        assert run('recover',1,dict(os.environ,PATH=str(fake)+':/usr/bin:/bin'))==f'RECOVERY {errno.EIO}\n'
        assert table(orphan[1])==prior
        assert journal_state()==records, 'failure changed journal or appended cleanup'
        selected_before=table(active[1])
        different=base64.b64encode(bytes([5])*32).decode()
        assert different!=original
        command(['wg','set',active[0],'peer',different,'allowed-ips','10.80.0.3/32'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
            assert table(orphan[1])==prior and journal_state()==records
        finally:
            command(['wg','set',active[0],'peer',different,'remove'])
        command(['wg','set',active[0],'peer',original,'allowed-ips','10.80.0.2/32,10.80.0.3/32'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
            assert table(orphan[1])==prior and journal_state()==records
        finally:
            command(['wg','set',active[0],'peer',original,'allowed-ips','10.80.0.2/32'])
        print('PASS extra peer or extra AllowedIPs: ESTALE before cleanup')
        command(['wg','set',active[0],'peer',original,'remove'])
        command(['wg','set',active[0],'peer',different,'allowed-ips','10.80.0.2/32'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
            assert table(orphan[1])==prior and table(active[1])==selected_before
            assert journal_state()==records
            command(['ip','link','show','dev',orphan[0]])
        finally:
            command(['wg','set',active[0],'peer',different,'remove'])
            command(['wg','set',active[0],'peer',original,'allowed-ips','10.80.0.2/32'])
        print('PASS changed public key: ESTALE, guard and unselected resource preserved')
        command(['wg','set',active[0],'peer',original,'allowed-ips','10.80.0.3/32'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
            assert table(orphan[1])==prior and table(active[1])==selected_before
            assert journal_state()==records
            command(['ip','link','show','dev',orphan[0]])
        finally:
            command(['wg','set',active[0],'peer',original,'allowed-ips','10.80.0.2/32'])
        print('PASS changed AllowedIPs: ESTALE, guard and unselected resource preserved')
        command(['ip','link','set','dev',active[0],'name','wg_moved'])
        try:
            assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
            assert table(orphan[1])==prior
            assert journal_state()==records
            command(['ip','link','show','dev',orphan[0]])
        finally:
            command(['ip','link','set','dev','wg_moved','name',active[0]])
        print('PASS wrong generation/digest, role, policy, deadline, nft error and owned-link identity refused before cleanup')
        active_doc=table(active[1]);peer=next(x['rule'] for x in active_doc['nftables'] if 'rule' in x and x['rule']['chain']=='peer_0')
        command(['nft','replace','rule','inet',active[1],'peer_0','handle',str(peer['handle']),'counter','drop'])
        changed=table(active[1]);assert changed['nftables'][1]['table']==active_doc['nftables'][1]['table']
        assert run('recover',1)==f'RECOVERY {errno.ESTALE}\n'
        assert table(orphan[1])==prior
        assert journal_state()==records, 'guard mismatch appended cleanup'
        command(['ip','link','show','dev',orphan[0]])
        print(f'PASS second process restart: ESTALE={errno.ESTALE}, other owned link/table preserved')


if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('expected real recovery executable')
    main(sys.argv[1])
