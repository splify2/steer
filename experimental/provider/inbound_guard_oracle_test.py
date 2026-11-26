#!/usr/bin/env python3
"""Real kernel guard oracle fixture. Run only under an isolated network namespace."""
import copy
import json
import os
import subprocess
import sys
from inbound_guard_oracle import Rejected, validate


def nft(*args, capture=False):
    return subprocess.run(['nft', *map(str, args)], check=True, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                          stderr=subprocess.PIPE, timeout=10).stdout


def main(binary):
    if os.fstat(3).st_ino == os.stat('/proc/self/ns/net').st_ino and os.fstat(3).st_dev == os.stat('/proc/self/ns/net').st_dev:
        raise RuntimeError('must pass outer namespace as fd 3 and enter a different netns')
    child = subprocess.Popen([binary], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, pass_fds=(3,))
    try:
        fields = child.stdout.readline().split()
        if len(fields) != 4:
            raise RuntimeError('guard fixture failed to start')
        table, marker, handle_text, index_text = fields
        handle, index = int(handle_text), int(index_text)
        peer = '10.80.0.2/32'
        def read():
            raw = nft('-j', '-n', 'list', 'table', 'inet', table, capture=True)
            return raw, json.loads(raw)
        def check(raw):
            return validate(raw, table, marker, handle, index, peer)
        raw, doc = read();check(raw)
        print('PASS real guard: one peer, two chains, exact rules and marker')
        for mutate in ('extra', 'order', 'source', 'ifindex', 'hook', 'marker', 'handle', 'expression'):
            wrong = copy.deepcopy(doc)
            items = wrong['nftables']
            if mutate == 'extra':items.append({'set': {}})
            elif mutate == 'order':items[-1], items[-2] = items[-2], items[-1]
            elif mutate == 'source':items[-2]['rule']['expr'][1]['match']['right'] = '10.80.0.3'
            elif mutate == 'ifindex':items[-1]['rule']['expr'][0]['match']['right'] = 'lo'
            elif mutate == 'hook':items[3]['chain']['hook'] = 'input'
            elif mutate == 'marker':items[1]['table']['comment'] = 'foreign'
            elif mutate == 'handle':items[1]['table']['handle'] += 1
            else:items[-1]['rule']['expr'].insert(1, {'unknown': {}})
            try:check(json.dumps(wrong))
            except Rejected:pass
            else:raise AssertionError('oracle accepted changed '+mutate)
        print('PASS rejects extra objects/expressions, rule order, source, ifindex, hook, marker and handle')
        rule = next(x['rule'] for x in doc['nftables'] if 'rule' in x and x['rule']['chain'] == 'peer_0')
        nft('replace', 'rule', 'inet', table, 'peer_0', 'handle', rule['handle'], 'counter', 'packets', 7, 'bytes', 123, 'accept')
        before_raw, before = read();check(before_raw)
        rule = next(x['rule'] for x in before['nftables'] if 'rule' in x and x['rule']['chain'] == 'peer_0')
        assert rule['expr'][0]['counter'] == {'packets': 7, 'bytes': 123}
        nft('reset', 'rules', 'table', 'inet', table)
        after_raw, after = read();check(after_raw)
        original = copy.deepcopy(before)
        for item in original['nftables']:
            if 'rule' in item:
                for expr in item['rule']['expr']:
                    if 'counter' in expr:expr['counter'] = {'packets': 0, 'bytes': 0}
        assert original == after, 'reset changed more than counters'
        print('PASS counter-only reset with identical handles and rules')
        nft('replace', 'rule', 'inet', table, 'peer_0', 'handle', rule['handle'], 'counter', 'drop')
        bad_raw, bad = read()
        assert bad['nftables'][1]['table'] == after['nftables'][1]['table'], 'table identity changed'
        try:check(bad_raw)
        except Rejected as exc:print('PASS rejects same table/marker/handle with changed verdict:', exc)
        else:raise AssertionError('oracle accepted changed verdict')
    finally:
        if child.poll() is None:
            child.stdin.write('q\n');child.stdin.flush()
        if child.wait(timeout=10):raise RuntimeError('fixture cleanup failed')


if __name__ == '__main__':
    if len(sys.argv) != 2:raise SystemExit('usage: inbound_guard_oracle_test.py /absolute/path/to/fixture')
    main(sys.argv[1])
