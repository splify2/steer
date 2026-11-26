"""Systemd guest-only provisioning, acceptance client and shutdown request."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import gate_e_lan_netns as lan
import gate_e_supervised as g

LAB = Path('/lab')
PREFIX, KEYS, WORK = (LAB / s for s in ('prefix', 'keys', 'work'))
SERVICE = g.BUNDLE.with_name('lan_service.py')
CLI = [sys.executable, '-B', SERVICE, '--prefix', PREFIX]
FLAGS = ['--work', WORK, '--backend', LAB / 'backend']
BOOT = Path('/proc/sys/kernel/random/boot_id')
WITNESS = LAB / 'expected.json'
HISTORY = LAB / 'passed-boots.json'


def save(path, value):
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value, sort_keys=True))
    temp.replace(path)


def peers():
    identities = []
    for ns, dev in [([], 'wg0'), (lan.PEER, 'wg-peer')]:
        # Never export showconf, private-key, or the private key file.
        identities.append([lan.output(*ns, 'wg', 'show', dev, field)
                           for field in ('public-key', 'peers')])
    assert identities[0] == identities[1][::-1]
    return identities


def hashes(state, names):
    return {name: g.digest(state / name) for name in names}


def provision():
    first = not WITNESS.exists()
    if first:
        for directory in (PREFIX, WORK, KEYS):
            directory.mkdir(mode=0o700)
        for name in ('router', 'peer'):
            with (KEYS / name).open('xb') as f:
                subprocess.run(['wg', 'genkey'], stdout=f, check=True)
        raw = g.LEGACY_FIXTURE.read_bytes()
        generation = g.install(PREFIX, *g.make_bundle(LAB, 'old', LAB / 'old',
            'steer-legacy-v2.1.4', {'spec.json': raw, 'registry': b'vpn 100000 300\n'}))
        lan.cmd(sys.executable, '-B', g.BUNDLE.with_name('convert_lan.py'), 'plan',
                '--prefix', PREFIX, *FLAGS)
    # This precedes creation of br-lan, its client and forwarding, including
    # on a dirty boot where normal serve will refuse the stale service state.
    lan.cmd(*CLI, 'arm')
    lan.topology(KEYS)
    lan.cmd('ip', '-n', 'client', 'link', 'set', 'eth0', 'address', '02:00:00:17:00:02')
    actual = peers()
    if first:
        save(WITNESS, {'peers': actual, 'original': generation, 'old_core': g.digest(LAB / 'old'),
                       'legacy': hashes(g.state_dir(PREFIX), ['spec.json', 'registry', 'FORMAT']),
                       'plan': g.digest(WORK / 'bundle/state/plan.json'),
                       'backend': g.digest(LAB / 'backend')})
        for path in (KEYS / 'router', KEYS / 'peer', WITNESS, KEYS, LAB):
            fd = os.open(path, os.O_RDONLY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)
    assert actual == json.loads(WITNESS.read_bytes())['peers']
    assert all((KEYS / n).stat().st_mode & 0o077 == 0 for n in ('router', 'peer'))


def ctl(*args):
    return json.loads(lan.output(*CLI, *args))


def check():
    expected = json.loads(WITNESS.read_bytes())
    history = json.loads(HISTORY.read_bytes()) if HISTORY.exists() else []
    phase = len(history)
    boot = str(uuid.UUID(BOOT.read_text().strip()))
    assert phase < 3 and boot not in history and peers() == expected['peers']
    client = json.loads(lan.output('ip', '-j', '-n', 'client', 'addr', 'show', 'dev', 'eth0'))[0]
    assert client['address'] == '02:00:00:17:00:02'
    assert any(addr['local'] == '10.17.0.2' for addr in client['addr_info'])
    # No test Apply or start. Query the already booted, selected daemon.
    result = ctl('status')
    assert result['ok'] and result['phase'] == 'running'
    target = result['selected']
    state = PREFIX / 'states' / Path(target).name
    old = PREFIX / 'states' / Path(expected['original']).name
    assert hashes(old, expected['legacy']) == expected['legacy']
    assert (old / 'spec.json').read_bytes() == g.LEGACY_FIXTURE.read_bytes()
    assert (old / 'registry').read_bytes() == b'vpn 100000 300\n'
    assert (PREFIX / 'active').resolve() == PREFIX / target
    if phase == 1:
        assert target == expected['candidate'] and g.digest(state / 'plan.json') == expected['plan']
        plan = json.loads((state / 'plan.json').read_bytes())
        assert plan['source_sha256'] == expected['legacy']['spec.json']
        assert g.digest(state / 'registry') == expected['legacy']['registry']
        exe, digest = PREFIX / target / 'legacy-gateway-v2', expected['backend']
    else:
        assert target == expected['original']
        exe, digest = PREFIX / target / 'core', expected['old_core']
    pid = result['daemon_pid']
    assert os.path.samefile(f'/proc/{pid}/exe', exe) and g.digest(exe) == digest
    args = Path(f'/proc/{pid}/cmdline').read_bytes().split(b'\0')
    assert b'daemon' in args and b'--apply' in args
    assert args[args.index(b'--state-dir') + 1] == os.fsencode(state)
    with subprocess.Popen([*lan.PEER, sys.executable, '-c', lan.SERVER, lan.DEST, lan.PORT],
                          stdout=subprocess.PIPE) as server:
        try:
            assert server.stdout.readline() == b'ready\n'
            lan.positive()
            if phase == 0:
                new = ctl('upgrade', *FLAGS)
                assert new['phase'] == 'running' and new['selected'] != target
                expected['candidate'] = new['selected']
                save(WITNESS, expected)
                # Subsequent boots and rollback cannot consult the staging inputs.
                (LAB / 'backend').unlink()
                WORK.rename(LAB / 'retained-backup')
                lan.positive()
            elif phase == 1:
                restored = ctl('rollback')
                assert restored['phase'] == 'running' and restored['selected'] == expected['original']
                lan.positive()
        finally:
            server.terminate()
    save(HISTORY, [*history, boot])
    os.sync()
    print('GATE_E_BOOT', phase, boot, ('legacy', 'compat', 'restored')[phase], flush=True)


def outer():
    # Independent boot verification unit: enter the service namespaces, never
    # create them here. Inner PID 1 is the private init, not guest systemd.
    assert Path('/proc/1/comm').read_text().strip() == 'systemd'
    assert set(p.name for p in Path('/sys/class/net').iterdir()) == {'lo'}
    assert Path('/').stat().st_dev == Path('/dev/vda').stat().st_rdev
    assert any(line.split()[1:3] == ['/', 'ext4'] for line in Path('/proc/mounts').read_text().splitlines())
    words = Path('/proc/cmdline').read_text().split()
    stage = next((w.split('=', 1)[1] for w in words if w.startswith('gate_e_cut=')), None)
    action = (['recover', 'previous' if stage == 'recover-starting' else 'selected']
              if stage and stage.startswith('recover-') else ['serve'])
    until = time.monotonic() + 30
    while time.monotonic() < until:
        matches = []
        for p in Path('/proc').glob('[0-9]*/cmdline'):
            try:
                args = p.read_bytes().split(b'\0')
            except (FileNotFoundError, ProcessLookupError):
                continue
            if args[1:] == [b'-B', os.fsencode(SERVICE), b'--prefix', os.fsencode(PREFIX),
                            *map(os.fsencode, action), b'']:
                matches.append(p.parent.name)
        if len(matches) == 1 and (PREFIX / 'service.sock').is_socket():
            state = PREFIX / 'service-state.json'
            if state.exists() and json.loads(state.read_bytes())['boot_id'] == BOOT.read_text().strip():
                break
        time.sleep(.05)
    else:
        raise RuntimeError('boot unit did not launch private supervisor')
    test = Path(__file__).with_name('cut_guest.py') if stage else __file__
    subprocess.run(['nsenter', '--target', matches[0], '--mount', '--net', '--pid', '--',
                    sys.executable, '-B', test, stage or 'check'], check=True, timeout=90)
    target = 'poweroff.target' if stage or len(json.loads(HISTORY.read_bytes())) == 3 else 'reboot.target'
    subprocess.run(['systemctl', '--no-block', 'start', target], check=True)


if __name__ == '__main__':
    if not __debug__ or 'gate_e_guest=1' not in Path('/proc/cmdline').read_text().split():
        sys.exit('requires the Gate E guest and enabled acceptance assertions')
    if sys.argv[1] != 'outer' and (os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net')
                                    or os.path.samefile('/etc', '/proc/1/root/etc')):
        sys.exit('requires the private guest router')
    os.umask(0o077)
    {'provision': provision, 'check': check, 'outer': outer}[sys.argv[1]]()
