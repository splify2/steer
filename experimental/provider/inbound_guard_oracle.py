#!/usr/bin/env python3
"""Test-only, fail-closed nft JSON oracle: one IPv4 /32 peer, empty policy, DIRECT.

Not a production recovery verifier. Input is a structured nft table listing;
expected geometry is generated from trusted fixture arguments, not a snapshot.
"""
import argparse
import ipaddress
import json
import re
import socket
import subprocess
import sys


class Rejected(ValueError):
    pass


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Rejected('duplicate JSON field')
        result[key] = value
    return result


def positive(number):
    return type(number) is int and number > 0


def same(a, b):
    return json.dumps(a, sort_keys=True, separators=(',', ':')) == json.dumps(b, sort_keys=True, separators=(',', ':'))


def validate(raw, table, marker, table_handle, ifindex, peer):
    address = ipaddress.ip_network(peer, strict=True)
    if (address.version != 4 or address.prefixlen != 32 or not positive(table_handle) or not positive(ifindex)
            or not re.fullmatch(r'steer_wg_[0-9a-f]{16}', table)
            or not re.fullmatch(r'steer-wg:[0-9a-f]{32}', marker)):
        raise Rejected('unsupported profile')
    doc = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(doc, dict) or set(doc) != {'nftables'} or not isinstance(doc['nftables'], list):
        raise Rejected('invalid document')
    objects = doc['nftables']
    if len(objects) != 8 or any(not isinstance(item, dict) or len(item) != 1 for item in objects):
        raise Rejected('unexpected object count or shape')
    meta = objects[0].get('metainfo')
    if (not isinstance(meta, dict) or set(meta) != {'version', 'release_name', 'json_schema_version'}
            or type(meta['json_schema_version']) is not int or meta['json_schema_version'] != 1 or not isinstance(meta['version'], str)
            or not isinstance(meta['release_name'], str)):
        raise Rejected('unsupported nft metadata')
    expected_table = {'family': 'inet', 'name': table, 'handle': table_handle, 'comment': marker}
    if not same(objects[1], {'table': expected_table}):
        raise Rejected('table identity mismatch')
    common = {'family': 'inet', 'table': table}
    chains = {}
    rules = {'ingress': [], 'peer_0': []}
    handles = set()
    for entry in objects[2:]:
        if 'chain' in entry:
            c = entry['chain']
            if not isinstance(c, dict) or c.get('name') not in rules or c['name'] in chains or not positive(c.get('handle')):
                raise Rejected('unexpected chain')
            want = {**common, 'name': c['name'], 'handle': c['handle']}
            if c['name'] == 'ingress':
                want.update(type='filter', hook='prerouting', prio=-160, policy='accept')
            if not same(c, want):
                raise Rejected('unexpected chain attributes')
            chains[c['name']] = c
        elif 'rule' in entry:
            r = entry['rule']
            if not isinstance(r, dict) or set(r) != {'family', 'table', 'chain', 'handle', 'expr'}:
                raise Rejected('unexpected rule fields')
            if r['family'] != 'inet' or r['table'] != table or r['chain'] not in rules or not positive(r['handle']) or r['handle'] in handles:
                raise Rejected('unexpected rule identity')
            handles.add(r['handle'])
            if not isinstance(r['expr'], list):
                raise Rejected('unexpected expressions')
            normalized = []
            for expr in r['expr']:
                if isinstance(expr, dict) and set(expr) == {'counter'}:
                    count = expr['counter']
                    if (not isinstance(count, dict) or set(count) != {'packets', 'bytes'}
                            or any(type(count[k]) is not int or count[k] < 0 for k in ('packets', 'bytes'))):
                        raise Rejected('invalid counter')
                    normalized.append({'counter': None})
                else:
                    normalized.append(expr)
            rules[r['chain']].append(normalized)
        else:
            raise Rejected('unexpected nft object')
    if set(chains) != set(rules):
        raise Rejected('missing chain')
    # nft may resolve numeric iif to its current interface name even with -n.
    # The expected index is independent of the listing; verify resolution now.
    try:
        ifname = socket.if_indextoname(ifindex)
        if socket.if_nametoindex(ifname) != ifindex:
            raise Rejected('interface index changed')
    except OSError as exc:
        raise Rejected('interface missing') from exc
    iif = {'match': {'op': '==', 'left': {'meta': {'key': 'iif'}}, 'right': ifname}}
    invalid = {'match': {'op': 'in', 'left': {'ct': {'key': 'state'}}, 'right': 1}}
    source = {'match': {'op': '==', 'left': {'payload': {'protocol': 'ip', 'field': 'saddr'}}, 'right': str(address.network_address)}}
    expected = {'peer_0': [[{'counter': None}, {'accept': None}]],
                'ingress': [[iif, invalid, {'drop': None}],
                            [iif, source, {'goto': {'target': 'peer_0'}}],
                            [iif, {'counter': None}, {'drop': None}]]}
    if not same(rules, expected):
        raise Rejected('rule contents or order mismatch')
    return doc


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--table', required=True);p.add_argument('--marker', required=True)
    p.add_argument('--handle', type=int, required=True);p.add_argument('--ifindex', type=int, required=True)
    p.add_argument('--peer', required=True)
    a = p.parse_args()
    try:
        raw = subprocess.run(['nft', '-j', '-n', 'list', 'table', 'inet', a.table],
                             check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5).stdout
        if len(raw) > 1024 * 1024:
            raise Rejected('listing too large')
        validate(raw, a.table, a.marker, a.handle, a.ifindex, a.peer)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('REJECT:', type(exc).__name__, str(exc), file=sys.stderr)
        return 1
    print('PASS inbound guard oracle')
    return 0


if __name__ == '__main__':
    sys.exit(main())
