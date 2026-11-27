"""Stock Linux prefix gate. See docs/managed-prefix.md for inputs and invocation."""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import pwd
import shutil
import signal
import socket
import stat
import subprocess as sp
import sys


def isolate(inputs):
    nobody = pwd.getpwnam('nobody')
    script = '''
        mount -t tmpfs -o noatime tmpfs /run
        cp "$1" /run/test.py; cp "$2"/steerd "$2"/*.so.* /run
        cp "$3" /run/steer; cp "$4" /run/v214; cp "$5" /run/pinned
        cp "$6" /run/ui.s2p; cp "$7" /run/ui.pub; cp "$8" /run/s2p; cp "$9" /run/cut.so
        ln /run/steerd /run/steer-tools
        for d in /etc /var /tmp; do mount -t tmpfs -o noatime tmpfs "$d"; done
        mount -t sysfs -o ro sysfs /sys
        chmod 1777 /tmp
        cd /tmp
        exec python3 -Bu /run/test.py --init "${10}" "${11}"
    '''
    os.execvp('unshare', ['unshare', '-mpnf', '--mount-proc', '--propagation', 'private',
                          'sh', '-ec', script, 'sh', str(Path(__file__).resolve()),
                          *map(os.path.abspath, inputs), str(nobody.pw_uid), str(nobody.pw_gid)])


P = Path('/tmp/home/new')
UI = '/run/ui.s2p'
ID = 'steer-ui'
ENV = dict(PATH='/usr/bin:/bin', HOME='/tmp/home', LD_LIBRARY_PATH='/run')
SELECT = ['--managed-prefix', P]
LOCK = P/'installed/.lock'
PENDING = P/'installed/.install-in-progress'
REG = P/'etc/registry.json'
VIEW = P/'etc/state.json'
libc = ctypes.CDLL(None, use_errno=True)


def run(args, env=None):
    return sp.run(args, env=ENV | (env or {}), timeout=18, capture_output=True, stdin=sp.DEVNULL)


def expect(args, code=None, env=None):
    r = run(args, env)
    assert r.returncode == int(bool(code)), (args, r.returncode, r.stdout, r.stderr)
    reply = json.loads(r.stdout)
    assert reply.get('code') == code, (args, reply)
    return reply


def pm(*args, **kwargs):
    return expect(['/run/steerd', *SELECT, 'plugin', *args, '--json'], **kwargs)


def inventory(p):
    rows = []
    for f in [p, *sorted(p.rglob('*'))]:
        s = f.lstat()
        content = hashlib.sha256(f.read_bytes()).digest() if stat.S_ISREG(s.st_mode) else None
        rows.append((f, s.st_mode, s.st_ino, s.st_uid, s.st_gid, s.st_nlink,
                     s.st_size, s.st_mtime_ns, s.st_ctime_ns, content))
    return rows


class NoWrites:
    """Include transient writes, not only final content."""
    def __init__(self, path=P):
        self.path = path

    def __enter__(self):
        self.before = inventory(self.path)
        self.fd = libc.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC)
        assert self.fd >= 0
        for f, mode, *_ in self.before:
            if stat.S_ISDIR(mode):
                assert libc.inotify_add_watch(self.fd, os.fsencode(f), 0xfce) >= 0

    def __exit__(self, *_):
        try:
            try:
                events = os.read(self.fd, 65536)
            except BlockingIOError:
                events = b''
            assert not events and self.before == inventory(self.path), (self.path, events)
        finally:
            os.close(self.fd)


def legacy(p, binary, *args, **kwargs):
    env = {'STEER_PLUGIN_'+k: str(p/v) for k, v in dict(
        DIR='installed', ETC='etc', RUN='run', TMP='tmp', KEYS='keys', SEED='seed',
        SYSROOT='sysroot', KEEPD='keep/plugins', INITD='no-init', SPEC='etc/spec',
        PANEL_DIR='etc/panel').items()}
    env.update(STEER_PLUGINS_ROOT=str(p/'installed'), STEER_PLUGINS_ETC=str(p/'etc'),
               STEER_SOCKET=str(p/'run/ctl'), STEER_SPEC=str(p/'etc/spec'), TMPDIR=str(p/'tmp'),
               STEER_PLUGIN_ARCH='x86_64', STEER_PLUGIN_HOST_API='', STEER_PLUGIN_SPLIFY2='')
    return expect(['/run/'+binary, 'plugin', *args, '--json'], env=env, **kwargs)


def old_barrier(pending=False):
    for binary in ('v214', 'pinned', 'steerd'):
        with NoWrites():
            for args in (['list'], ['status'], ['search'], ['repo', 'list']):
                code = 'plugin.install_degraded' if pending and binary != 'v214' and args[0] in ('list', 'status') else None
                reply = legacy(P, binary, *args, code=code)
                if args[0] == 'repo':
                    assert reply['repos'] == []
            for args in (['install', '--file', UI], ['install', '--job', '--file', UI],
                         ['ensure', ID], ['migrate'], ['remove', ID, '--force'], ['update', '--auto']):
                legacy(P, binary, *args, code='plugin.busy')
    print('PASS old writer barrier incl. transient writes; pending:', pending)


def signed_service():
    root = P.parent/'service'
    root.mkdir()
    (root/'plugin.json').write_text(json.dumps({
        'schema': 1, 'id': 'fixture', 'version': '1.0.0', 'name': 'fixture', 'arch': 'all',
        'compat': {'steer-api': '^1.2'}, 'steer': {'services': [{'name': 'worker', 'prog': 'worker'}]}}))
    (root/'worker').write_text('#!/bin/sh\ntouch /tmp/unexpected-launch\n')
    (root/'worker').chmod(0o755)
    key = P.parent/'test'
    for args in (['keygen', '-o', key], ['build', root, '--key', key.with_suffix('.sec'), '-o', P.parent]):
        r = run(['/run/s2p', *args])
        assert not r.returncode, (r.stdout, r.stderr)
    shutil.copyfile(key.with_suffix('.pub'), P/'keys/plugins/service.pub')
    return next(P.parent.glob('fixture-*.s2p'))


def main():
    assert os.getuid() != 0 and os.getppid() == 1 and not os.access('/proc/1/environ', os.R_OK)
    assert socket.if_nameindex() == [(1, 'lo')] and not int(Path('/sys/class/net/lo/flags').read_text(), 16) & 1
    P.parent.mkdir(mode=0o700)
    print('uid:', os.geteuid(), 'package SHA256:', hashlib.sha256(Path(UI).read_bytes()).hexdigest())
    P.mkdir()
    with NoWrites(P.parent):
        pm('init', code='plugin.prefix_invalid')
    P.rmdir()
    legacy_tmp = Path('/tmp/steer-plugins')
    legacy_tmp.mkdir(mode=0o700)
    with NoWrites(legacy_tmp):
        expect(['/run/steerd', '--managed-prefix', legacy_tmp/'new', 'plugin', 'init', '--json'],
               code='plugin.prefix_conflict')
    with NoWrites(P.parent):
        pm('list', code='plugin.prefix_invalid')
        pm('init', env={'STEER_PLUGINS_ROOT': '/tmp/wrong'}, code='plugin.prefix_conflict')
    cmd = ['/run/steerd', *SELECT, 'plugin', 'init', '--json']
    racers = [sp.Popen(cmd, env=ENV, stdout=sp.DEVNULL, stderr=sp.DEVNULL) for _ in range(4)]
    assert sorted(r.wait(timeout=5) for r in racers) == [0, 1, 1, 1]
    assert list(P.parent.iterdir()) == [P]
    with NoWrites(P.parent):
        pm('init', code='plugin.prefix_invalid')
        expect(['/run/steerd', '--managed-prefix', P/'tmp/nested', 'plugin', 'init', '--json'],
               code='plugin.prefix_invalid')
    with NoWrites(Path('/tmp/bind-test')):
        expect(['/run/steerd', '--managed-prefix', '/tmp/bind-test/p', 'plugin', 'list', '--json'],
               code='plugin.prefix_invalid')
    empty = REG.read_bytes()
    assert json.loads(empty) == json.loads(VIEW.read_bytes()) == {'schema': 1, 'plugins': {}}
    assert (LOCK/'writer').is_file() and (P/'etc/repos.d').is_file()
    print('PASS exclusive publication, absent/existing/conflicting destinations')
    pm('list')
    pm('install', '--file', UI, code='plugin.signed_unknown_key')  # no trusted key yet
    shutil.copyfile('/run/ui.pub', P/'keys/plugins/ui.pub')
    source = P/'etc/sources.d/local.json'
    source.write_text('[')
    pm('list', code='plugin.repo_unreadable')
    source.write_text('{"id":"local","official":true,"url":"http://127.0.0.1:9"}')
    old_barrier()
    pm('install', '--file', UI)
    one, = pm('status', ID)['plugins']
    assert one['id'] == ID and one['files_ok'] and one['enabled'] and not one['unsigned']
    assert ID in json.loads(REG.read_bytes())['plugins'] and VIEW.read_bytes() == empty
    old_barrier()
    pm('remove', ID)
    assert not (P/'installed'/ID).exists() and pm('list')['plugins'] == []
    print('PASS managed signed UI install, status, remove')
    service = signed_service()
    before = REG.read_bytes()
    pm('install', '--file', service, code='plugin.prefix_package')
    assert not (P/'installed/fixture').exists() and not PENDING.exists() and REG.read_bytes() == before
    assert not list((P/'installed/.stage').iterdir())
    with NoWrites():
        for args in (['install', 'fixture'], ['install', '--file', UI, '--file', service],
                     ['update'], ['ensure', 'fixture'], ['migrate'], ['enable', 'fixture'],
                     ['import', service], ['install', '--file', UI, '--unsigned'], ['search']):
            pm(*args, code='plugin.prefix_operation')
        for var in ('STEER_PLUGIN_SEED', 'STEER_PLUGIN_RUN', 'STEER_PLUGIN_JOB_DIR',
                    'STEER_PLUGINS_ETC', 'STEER_SOCKET', 'TMPDIR'):
            pm('list', env={var: '/tmp/wrong'}, code='plugin.prefix_conflict')
        for binary, args in (('steerd', [*SELECT, 'daemon', '--supervise']),
                             ('steerd', [*SELECT, 'ctl-serve']), ('steerd', [*SELECT, 'worker']),
                             ('steer', [*SELECT, 'plugin-install-file', UI]),
                             ('steer-tools', [*SELECT, 'plugin', 'list']),
                             ('steerd', ['--state-dir', '/tmp/wrong', *SELECT, 'plugin', 'list'])):
            r = run(['/run/'+binary, *args])
            assert r.returncode == 2 and b'--managed-prefix' in r.stderr, (args, r.stdout, r.stderr)
    assert not Path('/tmp/unexpected-launch').exists() and not Path('/tmp/wrong').exists()
    print('PASS signed service refused, alternative entries and path conflicts rejected')
    for had_dir in (False, True):
        if had_dir:
            pm('install', '--file', UI)
        prior = REG.read_bytes()
        r = run(['/run/steerd', *SELECT, 'plugin', 'install', '--file', UI], {'LD_PRELOAD': '/run/cut.so'})
        assert r.returncode == -signal.SIGKILL and PENDING.is_file(), (r.returncode, r.stderr)
        marker = PENDING.read_bytes()
        assert marker.startswith(b'M1 ') and marker.split(b'\n', 1)[1] == prior
        assert (P/'installed/.prev'/ID).exists() == had_dir
        old_barrier(True)
        for rel in ('installed/.lock', 'installed/.lock/writer', 'etc/repos.d', 'etc/sources.d',
                    'etc/state.json', 'etc/registry.json', 'run/state', 'seed', 'tmp'):
            path = P/rel
            spare = path.with_name(path.name+'.saved')
            path.rename(spare)
            with NoWrites():
                pm('list', code='plugin.prefix_invalid')
            path.symlink_to(spare)
            with NoWrites():
                pm('remove', ID, code='plugin.prefix_invalid')
            path.unlink()
            spare.rename(path)
        for path in (VIEW, REG, P/'etc/repos.d'):
            saved = path.read_bytes()
            path.write_bytes(b'{}')
            with NoWrites():
                pm('status', code='plugin.prefix_invalid')
            path.write_bytes(saved)
        with socket.socket(socket.AF_UNIX) as s:
            s.bind(str(P/'run/ctl'))
            with NoWrites():
                pm('list', code='plugin.prefix_invalid')
        (P/'run/ctl').unlink()
        PENDING.write_bytes(marker[1:])  # legacy record must not be replayed here
        pm('list', code='plugin.install_degraded')
        assert PENDING.read_bytes() == marker[1:] and (P/'installed'/ID).is_dir()
        header = marker.split(b'\n', 1)[0]
        assert b' 600 ' in header
        for invalid in (header.replace(b' 600 ', b' 000 ') + b'\n', header + b'\n{}'):
            PENDING.write_bytes(invalid)
            pm('status', code='plugin.install_degraded')
            assert PENDING.read_bytes() == invalid and (P/'installed'/ID).is_dir()
        PENDING.write_bytes(marker)
        # Refuse restoring a service-bearing manifest even if it is in .prev.
        candidate = (P/'installed/.prev' if had_dir else P/'installed')/ID/'plugin.json'
        original = candidate.read_bytes()
        m = json.loads(original)
        m['steer'] = {'services': [{'name': 'worker', 'prog': 'worker'}]}
        candidate.write_text(json.dumps(m))
        active = REG.read_bytes()
        pm('list', code='plugin.install_degraded')
        assert PENDING.read_bytes() == marker and REG.read_bytes() == active and candidate.is_file()
        candidate.write_bytes(original)
        plugins = pm('list')['plugins']
        assert len(plugins) == int(had_dir) and REG.read_bytes() == prior and VIEW.read_bytes() == empty
        assert not PENDING.exists() and (P/'installed'/ID).exists() == had_dir
        if had_dir:
            assert pm('status', ID)['plugins'][0]['files_ok']
            pm('remove', ID)
    print('PASS real pending before commit, first install and .prev replacement; damaged layout stops replay')
    for binary in ('steerd', 'pinned', 'v214'):
        p = P.parent/('legacy-'+binary)
        (p/'keys/plugins').mkdir(parents=True)
        shutil.copyfile('/run/ui.pub', p/'keys/plugins/ui.pub')
        (p/'etc/repos.d').mkdir(parents=True)
        with NoWrites():
            legacy(p, binary, 'install', '--file', UI)
            for b in ('steerd', 'v214', 'pinned'):
                entry, = legacy(p, b, 'status', ID)['plugins']
                assert entry['enabled'] and entry['files_ok'] and not entry['unsigned']
            legacy(p, binary, 'remove', ID)
        assert legacy(p, binary, 'list')['plugins'] == [] and (p/'installed/.lock').is_file()
        if binary != 'v214':
            legacy(p, binary, 'install', '--file', UI)
            marker = p/'installed/.install-in-progress'
            marker.write_bytes(b'1 steer-ui 0.0.0 0 1 000 1\n')
            assert legacy(p, binary, 'list')['plugins'] == [] and not marker.exists()
    print('PASS disjoint legacy non-root signed UI, all three writers/readers')


if __name__ == '__main__':
    if len(sys.argv) == 9:
        isolate(sys.argv[1:])
    assert len(sys.argv) == 4 and sys.argv[1] == '--init' and os.getuid() == 0 and os.getpid() == 1
    # Only PID 1 can prepare the same-filesystem bind. Both init and validation are non-root.
    uid, gid = map(int, sys.argv[2:])
    bind = Path('/tmp/bind-test')
    bind.mkdir(mode=0o700)
    os.chown(bind, uid, gid)
    for action in ('init', 'list'):
        sp.run(['/run/steerd', '--managed-prefix', bind/'p', 'plugin', action], env=ENV,
               user=uid, group=gid, extra_groups=[], check=True)
    sp.run(['mount', '--bind', bind/'p/seed', bind/'p/tmp'], check=True)
    child = os.fork()
    if child:
        sys.exit(os.waitstatus_to_exitcode(os.waitpid(child, 0)[1]))
    os.setgroups([])
    os.setgid(int(sys.argv[3]))
    os.setuid(int(sys.argv[2]))
    main()
