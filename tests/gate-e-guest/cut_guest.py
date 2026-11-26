"""Acceptance inside the disposable guest router; the host cuts VM power."""
from contextlib import contextmanager
import errno
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path

import guest as lab
from guest import lan

BASE = Path('/run/plaintext-baseline')


def journal():
    return json.loads((lab.PREFIX / 'service-state.json').read_bytes())


def tripwire():
    lan.cmd('ip', 'route', 'add', lan.DEST + '/32', 'via', '192.0.2.2')
    lan.cmd(*lan.PEER, 'nft', '-f', '-', input=(
        'table inet leak {\n chain observe { type filter hook input priority -100; policy accept;\n'
        f'iifname "eth0" ip daddr {lan.DEST} counter drop\n}}\n}}\n').encode())
    assert subprocess.run([sys.executable, '-c', lan.CLIENT, lan.DEST, lan.PORT], timeout=5).returncode == 23
    assert leaked() > 0  # unmarked traffic really reaches the alternate path
    BASE.write_text(str(leaked()))


def traffic():
    # ip netns exec uses a private mount namespace but shares the router's
    # /run tmpfs. Counter plus this heartbeat distinguish silence from no leak.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        while True:
            s.sendto(b'gate-e', (lan.DEST, 28082))
            Path('/run/traffic-heartbeat').touch()
            time.sleep(.01)


def no_bypass():
    heartbeat = Path('/run/traffic-heartbeat')
    before = heartbeat.stat().st_mtime_ns
    deadline = time.monotonic() + 1
    while heartbeat.stat().st_mtime_ns == before:
        assert time.monotonic() < deadline
        time.sleep(.01)
    assert leaked() == int(BASE.read_text())


def leaked():
    chain = json.loads(lan.output(*lan.PEER, 'nft', '-j', 'list', 'chain', 'inet', 'leak', 'observe'))
    return next(e['counter']['packets'] for item in chain['nftables']
                for e in item.get('rule', {}).get('expr', []) if 'counter' in e)


def blocked():
    before = leaked()
    lan.probe(False)
    assert before == leaked()
    assert 'steer_hold_' in lan.output('nft', 'list', 'tables')
    no_bypass()


def admit(choice):
    # Called before explicit recovery in the new boot, with guard and topology up.
    assert 'EXT4-fs (vda): recovery complete' in lan.output('dmesg')
    rec = journal()
    assert rec['boot_id'] != lab.BOOT.read_text().strip()
    blocked()
    raw = (lab.PREFIX / 'service-state.json').read_bytes()

    def refused(*action, diagnostic):
        p = subprocess.run([*lab.CLI, *action], capture_output=True, timeout=5)
        assert p.returncode and diagnostic in p.stderr, (action, p.returncode, p.stderr)
        assert (lab.PREFIX / 'service-state.json').read_bytes() == raw
        assert str(os.readlink(lab.PREFIX / 'active')) == rec['selected']
        blocked()

    refused('serve', diagnostic=b'unclean service state')
    refused('recover', 'selected' if choice == 'previous' else 'previous',
            diagnostic=b'no reviewed recovery')
    # A correct journal and pointer alone cannot authorize a corrupt state.
    state = lab.PREFIX / 'states' / Path(rec['selected']).name
    path = state / 'registry'
    registry = path.read_bytes()
    path.write_bytes(registry.replace(b'300', b'301'))
    try:
        refused('recover', choice, diagnostic=b'compatibility pair changed')
    finally:
        path.write_bytes(registry)
    print('GATE_E_ADMIT', hashlib.sha256(raw).hexdigest(), 'replay guarded refusal', flush=True)


@contextmanager
def echo():
    with subprocess.Popen([*lan.PEER, sys.executable, '-c', lan.SERVER, lan.DEST, lan.PORT],
                          stdout=subprocess.PIPE) as proc:
        try:
            assert proc.stdout.readline() == b'ready\n'
            yield
        finally:
            proc.terminate()


def serving(engine):
    rec = lab.ctl('status')
    assert rec['phase'] == 'running' and rec['boot_id'] == lab.BOOT.read_text().strip()
    assert os.path.samefile(f"/proc/{rec['daemon_pid']}/exe", lab.PREFIX / rec['selected'] / engine)
    before = leaked()
    lan.positive()
    assert before == leaked()
    no_bypass()


def witness(point):
    raw = (lab.PREFIX / 'service-state.json').read_bytes()
    j = json.loads(raw)
    assert j['phase'] == point and j['selected'] == os.readlink(lab.PREFIX / 'active')
    print('GATE_E_CUT', json.dumps(dict(phase=point, boot=j['boot_id'], selected=j['selected'],
          journal=hashlib.sha256(raw).hexdigest())), flush=True)
    # No shutdown, sync, signal to the service or successful test exit here.
    # If the host doesn't cut power, fail rather than recording a pass.
    time.sleep(15)
    raise AssertionError('external cut did not arrive')


def run(point):
    if point.startswith('recover-'):
        engine = 'core' if point == 'recover-starting' else 'legacy-gateway-v2'
        with echo():
            serving(engine)
        print('GATE_E_RESTORED', point, lab.BOOT.read_text().strip(), engine, flush=True)
        return
    with echo():
        serving('core')
        if point == 'running':
            lab.ctl('upgrade', *lab.FLAGS)
            serving('legacy-gateway-v2')
            witness(point)
        assert point == 'starting'
        # Saturate the real compatibility daemon's AF_UNIX listen probe. It
        # blocks in connect before boot Apply; no production pause/failpoint.
        with socket.socket(socket.AF_UNIX) as busy, socket.socket(socket.AF_UNIX) as queued:
            path = str(lab.PREFIX / 'compat.sock')
            busy.bind(path)
            busy.listen(0)
            queued.connect(path)
            with socket.socket(socket.AF_UNIX) as check:
                check.setblocking(False)
                assert check.connect_ex(path) == errno.EAGAIN
            with subprocess.Popen([*lab.CLI, 'upgrade', *lab.FLAGS]) as upgrade:
                deadline = time.monotonic() + 5
                while journal()['phase'] != point:
                    assert time.monotonic() < deadline and upgrade.poll() is None
                    time.sleep(.01)
                # "starting" is durable before Popen. First observe the
                # blocked LAN probe and only then sample the actual process.
                blocked()
                engine = lab.PREFIX / 'active/legacy-gateway-v2'
                exes = []
                for p in Path('/proc').glob('[0-9]*/exe'):
                    try:
                        exes.append(os.readlink(p))
                    except (FileNotFoundError, ProcessLookupError):
                        pass
                assert str(engine.resolve()) in exes
                assert 'fwmark' not in lan.output('ip', '-4', 'rule')
                assert 'table inet steer\n' not in lan.cmd('nft', 'list', 'tables', stdout=subprocess.PIPE).stdout.decode()
                assert upgrade.poll() is None
                witness(point)


if __name__ == '__main__':
    if not __debug__ or 'gate_e_guest=1' not in Path('/proc/cmdline').read_text().split() or \
            os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net'):
        sys.exit('requires isolated acceptance guest')
    if sys.argv[1] == 'admit':
        admit(sys.argv[2])
    elif sys.argv[1] == 'tripwire':
        tripwire()
    elif sys.argv[1] == 'traffic':
        traffic()
    else:
        run(sys.argv[1])
