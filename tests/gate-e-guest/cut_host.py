"""Host-side power-cut controller. No API to signal a guest or arbitrary host PID."""
import hashlib
import json
import os
from pathlib import Path
import re
import select
import signal
import subprocess
import time
import uuid


def cut(command, env, phase):
    buf = b''
    with subprocess.Popen(command, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as vm:
        try:
            until = time.monotonic() + 60
            while time.monotonic() < until:
                if not select.select([vm.stdout], [], [], 1)[0]:
                    continue
                more = os.read(vm.stdout.fileno(), 8192)
                if not more:
                    break
                buf = (buf + more)[-65536:]
                match = re.search(rb'(?m)^GATE_E_CUT (\{[^\r\n]+\})\r?$', buf)
                if match:
                    record = json.loads(match[1])
                    assert record['phase'] == phase and vm.poll() is None
                    vm.kill()  # SIGKILL to this QEMU child, not ACPI, QMP quit, or guest shutdown
                    assert vm.wait(timeout=10) == -signal.SIGKILL
                    return record
            raise RuntimeError('no guest cut witness:\n' + buf.decode(errors='replace')[-4000:])
        finally:
            if vm.poll() is None:
                vm.kill()


def disk_read(disk, name):
    return subprocess.check_output(['debugfs', '-R', 'cat /lab/' + name, disk], stderr=subprocess.DEVNULL)


def copy(src, dest):
    subprocess.run(['cp', '--sparse=always', '--reflink=auto', src, dest], check=True)


def replay_copy(args, disk, witness):
    sb = subprocess.check_output(['dumpe2fs', '-h', disk], stderr=subprocess.DEVNULL,
                                 env=dict(os.environ, LC_ALL='C'))
    assert re.search(rb'^Filesystem features:.*\bneeds_recovery\b', sb, re.M)
    replay = disk.with_suffix('.replay')
    copy(disk, replay)  # leave the actual guest disk dirty for the kernel
    subprocess.run(['e2fsck', '-p', '-E', 'journal_only', replay], check=True)
    subprocess.run(['e2fsck', '-fn', replay], check=True)
    raw = disk_read(replay, 'prefix/service-state.json')
    j = json.loads(raw)
    assert hashlib.sha256(raw).hexdigest() == witness['journal']
    assert (j['phase'], j['boot_id'], j['selected']) == (witness['phase'], witness['boot'], witness['selected'])
    assert re.fullmatch(r'generations/stage-[a-z0-9_-]+', j['selected'])
    # The pointer itself, not just the journal's claimed selection.
    st = subprocess.check_output(['debugfs', '-R', 'stat /lab/prefix/active', replay], stderr=subprocess.DEVNULL)
    assert ('Fast link dest: "' + j['selected'] + '"').encode() in st
    gen = 'prefix/' + j['selected']
    assert hashlib.sha256(disk_read(replay, gen + '/.manifest')).hexdigest() == j['manifest_sha256']
    previous = disk_read(replay, gen + '/.previous').decode()
    assert re.fullmatch(r'generations/stage-[a-z0-9_-]+', previous) and previous != j['selected']
    baseline = json.loads(disk_read(replay, 'expected.json'))
    assert previous == baseline['original']
    old = 'prefix/states/' + Path(previous).name
    new = 'prefix/states/' + Path(gen).name
    plan = disk_read(replay, new + '/plan.json')
    source = (Path(__file__).resolve().parents[1] / 'fixtures/gate-e/legacy-v2-lan.json').read_bytes()
    assert hashlib.sha256(plan).hexdigest() == baseline['plan']
    assert disk_read(replay, old + '/spec.json') == source
    assert hashlib.sha256(source).hexdigest() == json.loads(plan)['source_sha256']
    assert disk_read(replay, old + '/registry') == disk_read(replay, new + '/registry') == b'vpn 100000 300\n'
    assert disk_read(replay, gen + '/legacy-gateway-v2') == args.backend.read_bytes()
    assert disk_read(replay, 'prefix/' + previous + '/core') == args.legacy.read_bytes()
    replay.unlink()
    return previous


def exercise(args, pristine, env, vm_command):
    if not __debug__:
        raise RuntimeError('acceptance assertions must be enabled')
    boots = {uuid.UUID(Path('/proc/sys/kernel/random/boot_id').read_text().strip())}
    for phase, engine in [('running', 'legacy-gateway-v2'), ('starting', 'core')]:
        disk = pristine.with_name(phase + '.ext4')
        copy(pristine, disk)
        record = cut(vm_command(args, disk, 'gate_e_cut=' + phase), env, phase)
        previous = replay_copy(args, disk, record)
        result = subprocess.run(vm_command(args, disk, 'gate_e_cut=recover-' + phase), env=env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=75, check=True)
        serial = result.stdout.decode(errors='replace')
        m = re.search(r'GATE_E_RESTORED recover-' + phase + r' ([a-f0-9-]{36}) ' + engine, serial)
        if not m or 'GATE_E_ADMIT ' + record['journal'] + ' replay guarded refusal' not in serial:
            raise RuntimeError('missing guest recovery evidence:\n' + serial[-5000:])
        for boot in [record['boot'], m[1]]:
            assert uuid.UUID(boot) not in boots
            boots.add(uuid.UUID(boot))
        final = json.loads(disk_read(disk, 'prefix/service-state.json'))
        assert final['phase'] == 'stopped' and final['boot_id'] == m[1]
        assert final['selected'] == (previous if phase == 'starting' else record['selected'])
        decision = json.loads(disk_read(disk, 'prefix/service-recovery.json'))
        assert decision['source_record_sha256'] == record['journal'] and decision['source_boot_id'] == record['boot']
        assert decision['source_generation'] == record['selected'] and decision['source_phase'] == phase
        assert decision['boot_id'] == m[1] and decision['requested_generation'] == final['selected']
        assert decision['choice'] == ('previous' if phase == 'starting' else 'selected')
        check = subprocess.run(['e2fsck', '-fn', disk], env=dict(os.environ, LC_ALL='C'),
                               capture_output=True, check=True)
        assert b'Fix?' not in check.stdout and b'Free blocks count wrong' not in check.stdout
        print(f"PASS SIGKILL {phase} {record['boot']} {record['selected']}; "
              f"ext4 replay, guarded recovery {m[1]} {engine}", flush=True)
        disk.unlink()
