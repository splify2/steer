#!/usr/bin/env python3
"""Exercise C comparator using the existing real kernel guard fixture."""
import json
import os
import subprocess
import sys


def main(fixture, verifier):
    assert (os.fstat(3).st_dev, os.fstat(3).st_ino) != (os.stat('/proc/self/ns/net').st_dev, os.stat('/proc/self/ns/net').st_ino)
    p = subprocess.Popen([fixture], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, pass_fds=(3,))
    try:
        table, marker, handle, index = p.stdout.readline().split()
        def nft(*args):
            return subprocess.run(['nft', *map(str, args)], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10).stdout
        def snapshot():return nft('-j', '-n', 'list', 'table', 'inet', table)
        def verify(raw, expected):
            r = subprocess.run([verifier, table, marker, handle, index, '10.80.0.2'], input=raw, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)
            assert (r.returncode == 0) == expected, (r.returncode, r.stderr.decode())
        raw = snapshot();verify(raw, True);doc=json.loads(raw)
        for kind in ('expression', 'field', 'type', 'duplicate'):
            obj=json.loads(raw)
            if kind=='expression':obj['nftables'][-1]['rule']['expr'].append({'unknown': None})
            elif kind=='field':obj['nftables'][-1]['rule']['unknown']=1
            elif kind=='type':obj['nftables'][-3]['rule']['expr'][1]['match']['right']=True
            else:
                verify(raw.replace(b'"family": "inet"', b'"family": "inet", "family": "inet"', 1),False);continue
            verify(json.dumps(obj).encode(),False)
        verify(raw+b'\n# YAML is not JSON\n',False)
        verify(raw.replace(b'\"nftables\"', b'nftables', 1),False)
        wrong=json.loads(raw)
        wrong['nftables'][4]['rule']['expr'][0]['counter']['packets']=18446744073709551616
        verify(json.dumps(wrong).encode(),False)
        assert subprocess.run([verifier,table,marker,handle,'1','10.80.0.2'],input=raw,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=10).returncode!=0
        print('PASS C: real snapshot; extra expression, field, wrong type and duplicate rejected')
        rule=next(x['rule'] for x in doc['nftables'] if 'rule' in x and x['rule']['chain']=='peer_0')
        nft('replace','rule','inet',table,'peer_0','handle',rule['handle'],'counter','packets',7,'bytes',123,'accept')
        seeded=snapshot();verify(seeded,True);doc=json.loads(seeded)
        rule=next(x['rule'] for x in doc['nftables'] if 'rule' in x and x['rule']['chain']=='peer_0')
        assert rule['expr'][0]['counter']=={'packets':7,'bytes':123}
        nft('reset','rules','table','inet',table);verify(snapshot(),True)
        print('PASS C: counter growth and reset accepted')
        nft('replace','rule','inet',table,'peer_0','handle',rule['handle'],'counter','drop')
        bad=snapshot();assert json.loads(bad)['nftables'][1]['table']==doc['nftables'][1]['table']
        verify(bad,False);print('PASS C: verdict change rejected with same table handle and marker')
    finally:
        if p.poll() is None:p.stdin.write('q\n');p.stdin.flush()
        assert p.wait(timeout=10)==0


if __name__=='__main__':
    if len(sys.argv)!=3:raise SystemExit('expected fixture and C verifier executables')
    main(*sys.argv[1:])
