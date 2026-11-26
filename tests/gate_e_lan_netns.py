"""Worker for gate_e_lan_netns.sh. Real kernel peers; one client for all phases."""
from pathlib import Path
import json
import os
import subprocess
import sys

import gate_e_supervised as g


def cmd(*args, **kwargs):
    return subprocess.run(args, check=True, timeout=15, **kwargs)


def output(*args):
    return cmd(*args, text=True, stdout=subprocess.PIPE).stdout.strip()


PEER = ['ip', 'netns', 'exec', 'upstream']
DEST = '198.51.100.42'
PORT = '28081'


def topology():
    cmd('ip', 'link', 'set', 'lo', 'up')
    Path('/proc/sys/net/ipv4/ip_forward').write_text('1\n')
    for ns, dev, prefix in [('client', 'br-lan', '10.17.0'), ('upstream', 'underlay', '192.0.2')]:
        cmd('ip', 'netns', 'add', ns)
        cmd('ip', 'link', 'add', dev, 'type', 'veth', 'peer', 'name', 'eth0', 'netns', ns)
        cmd('ip', 'addr', 'add', prefix + '.1/24', 'dev', dev)
        cmd('ip', 'link', 'set', dev, 'up')
        cmd('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        cmd('ip', '-n', ns, 'addr', 'add', prefix + '.2/24', 'dev', 'eth0')
        cmd('ip', '-n', ns, 'link', 'set', 'eth0', 'up')
    cmd('ip', '-n', 'client', 'route', 'add', 'default', 'via', '10.17.0.1')
    cmd(*PEER, 'ip', 'addr', 'add', DEST + '/32', 'dev', 'lo')
    keys = []
    for name in ['router', 'peer']:
        path = Path('/tmp') / name
        path.write_bytes(cmd('wg', 'genkey', stdout=subprocess.PIPE).stdout)
        keys.append((path, cmd('wg', 'pubkey', input=path.read_bytes(), stdout=subprocess.PIPE)
                     .stdout.decode().strip()))
    for i, (ns, dev, ip, allowed) in enumerate([
            ([], 'wg0', '192.0.2.2', DEST + '/32'),
            (PEER, 'wg-peer', '192.0.2.1', '10.17.0.0/24')]):
        cmd(*ns, 'ip', 'link', 'add', dev, 'type', 'wireguard')
        cmd(*ns, 'wg', 'set', dev, 'private-key', keys[i][0], 'listen-port', '42002',
            'peer', keys[1-i][1], 'endpoint', ip + ':42002', 'allowed-ips', allowed)
        cmd(*ns, 'ip', 'link', 'set', dev, 'up')
    cmd(*PEER, 'ip', 'route', 'add', '10.17.0.0/24', 'dev', 'wg-peer')
    for path in Path('/proc/sys/net/ipv4/conf').glob('*/rp_filter'):
        path.write_text('0\n')


CLIENT = """
import os, socket, sys
try:
    with socket.create_connection((sys.argv[1], int(sys.argv[2])), 1.5) as s:
        b = os.urandom(4096); s.sendall(b)
        assert s.makefile('rb').read(len(b)) == b
except OSError:
    sys.exit(23)
"""

SERVER = """
import socket, sys
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'wg-peer')
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen()
print('ready', flush=True)
while True:
    c, _ = s.accept()
    with c:
        c.settimeout(2)
        c.sendall(c.makefile('rb').read(4096))
"""


def probe(ok):
    proc = subprocess.run(['ip', 'netns', 'exec', 'client', sys.executable, '-c',
                           CLIENT, DEST, PORT], timeout=5)
    assert proc.returncode == (0 if ok else 23), proc.returncode


def tx():
    return int(output('wg', 'show', 'wg0', 'transfer').split()[2])


def positive():
    before = tx()
    probe(True)
    assert tx() > before and int(output('wg', 'show', 'wg0', 'latest-handshakes').split()[1]) > 0
    assert 'dev wg0' in output('ip', '-4', 'route', 'show', 'table', '300')


def clean():
    assert not output('nft', 'list', 'tables') and 'fwmark' not in output('ip', '-4', 'rule')
    probe(False)


def phases():
    root = Path('/mnt')
    prefix, work = root / 'prefix', root / 'work'
    for p in [prefix, work]:
        p.mkdir(mode=0o700)
    core = prefix / 'active/core'
    raw = g.LEGACY_FIXTURE.read_bytes()
    a = g.install(prefix, *g.make_bundle(root, 'legacy', root / 'old', 'steer-legacy-v2.1.4',
                                         {'spec.json': raw}))
    old = g.state_dir(prefix)
    args = ['--spec', old / 'spec.json', '--state-dir', old]
    clean()
    cmd(core, 'apply', *args)
    positive()
    cmd(core, 'down', '--state-dir', old)
    clean()
    registry = (old / 'registry').read_bytes()
    convert = [sys.executable, '-B', g.BUNDLE.with_name('convert_lan.py')]
    flags = ['--prefix', prefix, '--work', work, '--backend', root / 'backend']
    cmd(*convert, 'plan', *flags)
    assert g.bundle_cli(prefix, 'status') == a
    plan = json.loads((work / 'bundle/state/plan.json').read_bytes())
    assert plan['source_sha256'] == g.digest(old / 'spec.json')
    # Even whitespace-only source drift invalidates approval before selection.
    (old / 'spec.json').write_bytes(raw + b' ')
    assert subprocess.run([*convert, 'switch', *flags]).returncode != 0
    assert g.bundle_cli(prefix, 'status') == a
    (old / 'spec.json').write_bytes(raw)
    backed_up = work / 'backup/registry'
    backed_up.unlink()
    assert subprocess.run([*convert, 'switch', *flags]).returncode != 0
    assert g.bundle_cli(prefix, 'status') == a
    backed_up.write_bytes(registry)
    cmd(*convert, 'switch', *flags)
    new = g.state_dir(prefix)
    assert new != old and not (new / 'spec.json').exists()
    assert (new / 'registry').read_bytes() == registry
    # The active pair must no longer need the staging or input executables.
    work.rename(root / 'retained-backup')
    (root / 'backend').unlink()
    # A writable seed isn't a second, unchecked control plane.
    seed = (new / 'plan.json').read_bytes()
    (new / 'plan.json').write_bytes(seed.replace(b'br-lan', b'not-lan'))
    assert subprocess.run([core, 'apply']).returncode != 0
    clean()
    (new / 'plan.json').write_bytes(seed)
    cmd(core, 'apply')
    positive()
    # Offer a real alternative plaintext path. Count *any* attempted bypass
    # at the peer while deliberately dropping the encrypted transport there.
    cmd('ip', 'route', 'add', DEST + '/32', 'via', '192.0.2.2')
    cmd(*PEER, 'nft', '-f', '-', input=(
        'table inet control { chain input { type filter hook input priority -100; policy accept;\n'
        f'iifname "eth0" ip daddr {DEST} tcp dport {PORT} counter drop\n'
        'udp dport 42002 counter drop\n}\n}\n').encode())
    probe(False)
    def counters():
        chain = json.loads(output(*PEER, 'nft', '-j', 'list', 'chain', 'inet', 'control', 'input'))
        return [expr['counter']['packets'] for obj in chain['nftables']
                for expr in obj.get('rule', {}).get('expr', []) if 'counter' in expr]

    plaintext, encrypted = counters()
    assert plaintext == 0 and encrypted > 0, (plaintext, encrypted)
    # Traffic originating on the router isn't captured. It must hit the
    # plaintext tripwire via main, proving that zero was observable above.
    assert subprocess.run([sys.executable, '-c', CLIENT, DEST, PORT], timeout=5).returncode == 23
    assert counters()[0] > 0
    cmd(*PEER, 'nft', 'delete', 'table', 'inet', 'control')
    cmd('ip', 'route', 'del', DEST + '/32')
    positive()
    cmd(core, 'down')
    clean()
    (old / 'registry').write_bytes(registry.replace(b'300', b'301'))
    back = [*convert, 'rollback', '--prefix', prefix]
    assert subprocess.run(back).returncode != 0 and g.state_dir(prefix) == new
    (old / 'registry').write_bytes(registry)
    assert output(*back) == a and g.state_dir(prefix) == old
    assert g.digest(core) == g.digest(root / 'old') and (old / 'spec.json').read_bytes() == raw
    assert (old / 'registry').read_bytes() == registry
    cmd(core, 'apply', *args)
    positive()
    print('PASS same LAN client: v2 -> source-bound legacy-gateway-v2 -> offline v2; '
          'real WG byte echo, blocked transport, zero plaintext bypass')


if __name__ == '__main__':
    assert not os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net')
    assert not os.path.samefile('/etc', '/proc/1/root/etc') and Path.cwd() == Path('/mnt')
    os.umask(0o077)
    topology()
    with subprocess.Popen([*PEER, sys.executable, '-c', SERVER, DEST, PORT],
                          stdout=subprocess.PIPE) as srv:
        try:
            assert srv.stdout.readline() == b'ready\n'
            phases()
        finally:
            srv.terminate()
