"""Private namespace worker; the client never calls either engine's Apply."""
from contextlib import contextmanager, ExitStack
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time

import gate_e_lan_netns as lan
import gate_e_supervised as g

ROOT = Path('/mnt')
PREFIX, WORK = ROOT / 'prefix', ROOT / 'work'
CLI = [sys.executable, '-B', g.BUNDLE.with_name('lan_service.py'), '--prefix', PREFIX]
FLAGS = ['--work', WORK, '--backend', ROOT / 'backend']


def call(*args, ok=True):
    p = subprocess.run([*CLI, *args], capture_output=True, timeout=35)
    assert (p.returncode == 0) == ok, (p.stdout, p.stderr)
    return json.loads(p.stdout)


@contextmanager
def supervisor(degraded=False):
    p = subprocess.Popen([*CLI, 'serve'])
    try:
        end = time.monotonic() + 10
        while not (PREFIX / 'service.sock').is_socket():
            assert p.poll() is None and time.monotonic() < end
            time.sleep(.02)
        yield
    finally:
        p.terminate()
        assert p.wait(timeout=12) == int(degraded)


def serving(result, name):
    assert result['phase'] == 'running', result
    pid = result['daemon_pid']
    gen = PREFIX / result['selected']
    assert os.path.samefile(f'/proc/{pid}/exe', gen / name)
    args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    assert b'--apply' in args and b'daemon' in args
    assert args[args.index(b'--state-dir') + 1] == os.fsencode(PREFIX / 'states' / gen.name)
    lan.positive()
    return pid


@contextmanager
def traffic():
    script = """
import socket, sys, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b'gate-e', (sys.argv[1], 28082))
print('ready', flush=True)
while True:
    s.sendto(b'gate-e', (sys.argv[1], 28082))
    time.sleep(.002)
"""
    with subprocess.Popen(['ip', 'netns', 'exec', 'client', sys.executable, '-c', script, lan.DEST],
                          stdout=subprocess.PIPE) as proc:
        try:
            assert proc.stdout.readline() == b'ready\n'
            yield proc
        finally:
            proc.terminate()


def phases(stack):
    for path in (PREFIX, WORK):
        path.mkdir(mode=0o700)
    original = g.install(PREFIX, *g.make_bundle(ROOT, 'old', ROOT / 'old', 'steer-legacy-v2.1.4',
        {'spec.json': g.LEGACY_FIXTURE.read_bytes(), 'registry': b'vpn 100000 300\n'}))
    lan.cmd(sys.executable, '-B', g.BUNDLE.with_name('convert_lan.py'), 'plan', '--prefix', PREFIX, *FLAGS)
    # Keep an independently usable main route throughout the transition. Count
    # *arrivals*, not echo successes (our echo deliberately binds to wg-peer).
    lan.cmd('ip', 'route', 'add', lan.DEST + '/32', 'via', '192.0.2.2')
    lan.cmd(*lan.PEER, 'nft', '-f', '-', input=(
        'table inet leak { chain observe { type filter hook input priority -100; policy accept;\n'
        f'iifname "eth0" ip daddr {lan.DEST} counter drop\n}}\n}}\n').encode())

    def leaked():
        obj = json.loads(lan.output(*lan.PEER, 'nft', '-j', 'list', 'chain', 'inet', 'leak', 'observe'))
        return next(e['counter']['packets'] for item in obj['nftables']
                    for e in item.get('rule', {}).get('expr', []) if 'counter' in e)

    def blocked():
        n = leaked()
        lan.probe(False)
        assert leaked() == n

    lan.probe(False)
    start = leaked()
    assert start > 0  # calibrate the very same client and tripwire
    with supervisor():
        old_pid = serving(call('status'), 'core')
        load = stack.enter_context(traffic())
        # A real bind conflict causes only the candidate daemon to exit.
        sock = PREFIX / 'compat.sock'
        with socket.socket(socket.AF_UNIX) as busy:
            busy.bind(str(sock))
            busy.listen()
            recovered = call('upgrade', *FLAGS, ok=False)
            assert recovered['selected'] == original and 'restored predecessor' in recovered['detail']
            assert serving(recovered, 'core') != old_pid
        sock.unlink()
        new = call('upgrade', *FLAGS)
        g.bundle_cli(PREFIX, 'rollback', ok=False)  # valid predecessor, but owned by service
        first = serving(new, 'legacy-gateway-v2')
        lan.cmd(*lan.PEER, 'nft', '-f', '-', input=(
            'table inet cut { chain input { type filter hook input priority -101; policy accept;\n'
            'udp dport 42002 drop\n}\n}\n').encode())
        blocked()
        assert call('status')['daemon_pid'] == first
        lan.cmd(*lan.PEER, 'nft', 'delete', 'table', 'inet', 'cut')
        lan.positive()
        assert call('stop')['phase'] == 'stopped'
    blocked()
    assert not Path(f'/proc/{first}').exists()
    assert 'fwmark' not in lan.output('ip', '-4', 'rule')
    assert json.loads((PREFIX / 'service-state.json').read_bytes())['phase'] == 'stopped'
    WORK.rename(ROOT / 'offline-work')
    (ROOT / 'backend').rename(ROOT / 'offline-backend')
    with supervisor():
        resumed = call('status')
        assert resumed['selected'] == new['selected']
        assert serving(resumed, 'legacy-gateway-v2') != first
        restored = call('rollback')
        assert restored['selected'] == original
        assert g.digest(PREFIX / 'active/core') == g.digest(ROOT / 'old')
        serving(restored, 'core')
    blocked()
    (ROOT / 'offline-work').rename(WORK)
    (ROOT / 'offline-backend').rename(ROOT / 'backend')
    with supervisor(degraded=True):
        serving(call('status'), 'core')
        # Neither candidate nor restored predecessor can serve this profile.
        peer = lan.output('wg', 'show', 'wg0', 'peers')
        lan.cmd('wg', 'set', 'wg0', 'peer', peer, 'remove')
        bad = call('upgrade', *FLAGS, ok=False)
        assert bad['phase'] == 'degraded' and bad['daemon_pid'] is None, bad
        assert bad['selected'] == original and 'recovery:' in bad['detail']
        blocked()
    assert json.loads((PREFIX / 'service-state.json').read_bytes())['phase'] == 'degraded'
    assert subprocess.run([*CLI, 'serve'], capture_output=True, timeout=4).returncode != 0
    blocked()
    assert load.poll() is None and leaked() == start
    print('PASS daemon boot, guarded service switch, failed bind + authenticated recovery, '
          'cold supervisor restart, offline rollback and fail-closed degraded state')


if __name__ == '__main__':
    assert not os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net')
    assert not os.path.samefile('/etc', '/proc/1/root/etc') and Path.cwd() == ROOT
    os.umask(0o077)
    lan.topology()
    with subprocess.Popen([*lan.PEER, sys.executable, '-c', lan.SERVER, lan.DEST, lan.PORT],
                          stdout=subprocess.PIPE) as server:
        try:
            assert server.stdout.readline() == b'ready\n'
            with ExitStack() as stack:
                phases(stack)
        finally:
            server.terminate()
