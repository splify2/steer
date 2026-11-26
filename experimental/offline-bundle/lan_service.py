#!/usr/bin/env python3
"""Foreground supervisor for a dedicated Gate E router namespace."""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time

import bundle
import convert_lan as migration
from lan_profile import ENGINE, FORMAT, decode, encode, engine_env, lower, require, sha

ERRORS = (OSError, ValueError, KeyError, TypeError, migration.SourceError, subprocess.SubprocessError)


def command(*args, **kwargs):
    kwargs.setdefault('env', {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LC_ALL': 'C'})
    return subprocess.run(args, capture_output=True, check=True, timeout=8, **kwargs).stdout


def rules(family):
    return command('ip', '-N', family, 'rule', 'show').decode()


def clean():
    require(b'table inet steer\n' not in command('nft', 'list', 'tables'), 'legacy nft table remains')
    for family in ('-4', '-6'):
        require('fwmark' not in rules(family), 'policy rule remains')
        routes = decode(command('ip', '-N', '-j', family, 'route', 'show', 'table', 'all'))
        require(not any(str(r.get('table')) == '300' for r in routes), 'policy route remains')


def candidate(gen, state, tmp):
    manifest = bundle.manifest(gen / '.manifest')
    names = {'FORMAT', 'plan.json', 'registry', 'recovery.json'}
    require(set(manifest) == {'core', ENGINE} | {'state/' + n for n in names} and
            {p.name for p in state.iterdir()} == names, 'unknown compatibility pair')
    seed = {}
    for name, digest in manifest.items():
        data = (bundle.read_file(state, name[6:]) if name.startswith('state/')
                else bundle.read_file(gen, name))
        require(sha(data) == digest, 'compatibility pair changed')
        if name.startswith('state/'):
            seed[name[6:]] = data
    plan = decode(seed['plan.json'])
    spec = lower(plan)
    require(seed['registry'] == (plan['egress']['id'] + ' 100000 300\n').encode(),
            'foreign registry')
    path = tmp / 'backend.json'
    path.write_bytes(encode(spec))
    return gen / ENGINE, path, 'compat'


def publish_record(prefix, name, data):
    with tempfile.NamedTemporaryFile(dir=prefix, delete=False) as f:
        f.write(encode(data))
        f.flush()
        os.fsync(f.fileno())
    os.replace(f.name, prefix / name)
    bundle.syncdir(prefix)


class Service:
    def __init__(self, prefix, tmp):
        self.prefix, self.tmp = prefix, tmp
        self.proc = self.backend = None
        self.legacy_inventory = None
        self.phase = 'starting'
        self.guard = 'steer_hold_' + sha(os.fsencode(prefix))[:16]
        self.env = engine_env(tmp / 'empty')
        for sub in ('empty', 'lists'):
            (tmp / sub).mkdir()

    def hold(self):
        # One atomic transaction; this reserved table survives backend down and
        # supervisor exit. The dedicated router has no other owner of this name.
        t = self.guard
        command('nft', '-f', '-', input=(f'table inet {t}\ndelete table inet {t}\n'
            f'table inet {t} {{\nchain pause {{ type filter hook forward priority -300; '
            'policy accept;\niifname "br-lan" counter drop\n}\n}\n').encode())

    def record(self, phase, detail=''):
        self.phase = phase
        selected = bundle.active(self.prefix)
        self.status = {'phase': phase, 'selected': selected,
                       'boot_id': boot_id(), 'manifest_sha256': (
                           manifest_hash(self.prefix, selected) if phase in ('starting', 'running') else None),
                       'daemon_pid': self.proc.pid if self.proc and self.proc.poll() is None else None,
                       'detail': detail}
        publish_record(self.prefix, 'service-state.json', self.status)

    def start(self):
        clean()  # Kernel readiness below cannot be satisfied by the former pair.
        current = bundle.active(self.prefix)
        gen = self.prefix / current
        state = bundle.state_path(self.prefix, current)
        fmt = bundle.read_file(state, 'FORMAT')
        if fmt == migration.LEGACY_FORMAT:
            blobs, self.legacy_inventory, _ = migration.inspect(self.prefix, current)
            doc, _ = migration.legacy_plan(blobs)
            exe, spec, mode = gen / 'core', state / 'spec.json', 'legacy'
            require(migration.effective(exe, blobs['spec.json'], self.tmp / 'empty') == doc,
                    'legacy parser mismatch')
        elif fmt == (FORMAT + '\n').encode():
            exe, spec, mode = candidate(gen, state, self.tmp)
        else:
            raise ValueError('unknown service format')
        require(Path('/sys/class/net/br-lan').exists() and
                command('wg', 'show', 'wg0', 'peers').strip(), 'external devices not provisioned')
        ctl = self.prefix / (mode + '.sock')
        self.backend = (exe, state, current)
        self.proc = subprocess.Popen([exe, 'daemon', '--apply', '--spec', spec, '--state-dir', state,
            '--socket', ctl, '--lists-dir', self.tmp / 'lists'], cwd=self.tmp, env=self.env,
            stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            require(self.proc.poll() is None, mode + ' daemon exited before readiness')
            if ctl.is_socket() and b'table inet steer\n' in command('nft', 'list', 'tables'):
                info = decode(command(exe, 'ctl', '--socket', ctl, 'version', env=self.env))
                routes = decode(command('ip', '-j', '-4', 'route', 'show', 'table', '300'))
                if (info.get('state_dir') == str(state) and info.get('spec_path') == str(spec)
                    and re.search(r'fwmark 0x100000/0xff00000 lookup 300\b', rules('-4'))
                    and any(r.get('dst') == 'default' and r.get('dev') == 'wg0' for r in routes)):
                    require(self.proc.poll() is None, 'daemon exited during startup')
                    command('nft', 'delete', 'table', 'inet', self.guard)
                    self.record('running')
                    return
            time.sleep(.04)
        raise ValueError(mode + ' boot readiness timed out')

    def stop(self):
        self.hold()  # Never stop/down first and then try to close the direct path.
        if self.proc is not None:
            if self.proc.poll() is None:
                self.proc.terminate()
                require(self.proc.wait(timeout=8) == 0, 'uncertain daemon shutdown')
            self.proc = None
        if self.backend:
            exe, state, current = self.backend
            require(bundle.active(self.prefix) == current, 'active pointer changed during service')
            # down trusts the registry for the marks/tables to remove. Never
            # hand a corrupt paired state or substituted executable to down.
            if exe.name == ENGINE:
                candidate(self.prefix / current, state, self.tmp)
            else:
                _, inventory, _ = migration.inspect(self.prefix, current)
                require(inventory == self.legacy_inventory, 'running predecessor changed')
            command(exe, 'down', '--state-dir', state, cwd=self.tmp, env=self.env)
            self.backend = None
        clean()

    def degrade(self, reason):
        try:
            self.stop()
        except ERRORS as exc:
            reason += '; guard/down not confirmed: ' + str(exc)
        self.record('degraded', reason)

    def shutdown(self):
        try:
            self.stop()
            if self.phase != 'degraded':
                self.record('stopped')
        except ERRORS as exc:
            self.record('degraded', 'shutdown guard/down not confirmed: ' + str(exc))

    def transition(self, request):
        verb = request['command']
        require(self.phase == 'running', 'service is not running')
        original = bundle.active(self.prefix)
        compat = self.backend[0].name == ENGINE
        require((verb == 'upgrade' and not compat) or (verb == 'rollback' and compat),
                'operation not valid for selected format')
        self.record('stopping', verb)
        try:
            self.stop()
            self.record('switching', verb)
            if verb == 'upgrade':
                _, inventory, _ = migration.inspect(self.prefix, original)
                require(inventory == self.legacy_inventory, 'running predecessor changed')
                args = argparse.Namespace(command='switch', prefix=self.prefix,
                                          work=Path(request['work']), backend=Path(request['backend']))
                migration.convert_locked(args)
            else:
                migration.rollback_locked(self.prefix)
            self.record('starting', verb)
            self.start()
            return True
        except ERRORS as primary:
            failed_at = self.phase
            try:
                # Don't run a second engine if stop/down or ownership was uncertain.
                require(verb == 'upgrade' and failed_at in ('switching', 'starting'),
                        'no automatic fallback for this failure')
                self.record('recovering', str(primary))
                self.stop()
                if bundle.active(self.prefix) != original:
                    require(migration.rollback_locked(self.prefix) == original, 'wrong predecessor')
                _, inventory, _ = migration.inspect(self.prefix, original)
                require(inventory == self.legacy_inventory, 'running predecessor changed')
                self.start()
                self.record('running', 'restored predecessor: ' + str(primary))
            except ERRORS as recovery:
                self.degrade(f'{verb}/{failed_at}: {primary}; recovery: {recovery}')
            return False


def boot_id():
    return Path('/proc/sys/kernel/random/boot_id').read_text().strip()


def manifest_hash(prefix, selected):
    return sha(bundle.read_file(prefix / selected, '.manifest')) if selected else None


def private_router():
    require(not os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net') and
            not os.path.samefile('/proc/self/ns/mnt', '/proc/1/ns/mnt') and
            all(not os.path.samefile(p, '/proc/1/root' + p) for p in ('/etc', '/tmp', '/var', '/run')),
            'requires dedicated private router namespaces and mounts')
    outer_pidns = bundle.read_file(Path('/run'), 'steer-lab.outer-pidns').decode().strip()
    require(re.fullmatch(r'pid:\[\d+\]', outer_pidns) and
            outer_pidns != os.readlink('/proc/self/ns/pid') and
            os.readlink('/proc/self') == str(os.getpid()), 'requires a private PID namespace and procfs')


def stale_socket(path, kind):
    try:
        st = path.lstat()
    except FileNotFoundError:
        return
    require(stat.S_ISSOCK(st.st_mode) and st.st_uid == os.geteuid(), 'unexpected control endpoint')
    with socket.socket(socket.AF_UNIX, kind) as probe:
        probe.settimeout(.3)
        try:
            probe.connect(str(path))
        except ConnectionRefusedError:
            path.unlink()
            return
    raise ValueError('control endpoint is still live')


def recover_locked(svc, disposition):
    """Admission only, with lock and drop guard held; never signal or adopt a recorded PID."""
    prefix = svc.prefix
    clean()
    raw = bundle.read_file(prefix, 'service-state.json')
    record = decode(raw)
    current = bundle.active(prefix)
    require(current and record['selected'] == current and record['manifest_sha256'] ==
            manifest_hash(prefix, current), 'selection and journal disagree')
    require(re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', record['boot_id'])
            and record['boot_id'] != boot_id(), 'requires a different kernel boot')
    require((disposition == 'selected' and record['phase'] == 'running') or
            (disposition == 'previous' and record['phase'] == 'starting' and record['detail'] == 'upgrade'),
            'no reviewed recovery for this phase and choice')
    gen = prefix / current
    state = bundle.state_path(prefix, current)
    require(bundle.read_file(state, 'FORMAT') == (FORMAT + '\n').encode(), 'not a compatibility pair')
    candidate(gen, state, svc.tmp)
    previous = migration.verified_previous(prefix)
    old, _, _ = migration.inspect(prefix, previous)
    _, plan = migration.legacy_plan(old)
    require(encode(plan) == bundle.read_file(state, 'plan.json') and
            old['registry'] == bundle.read_file(state, 'registry'), 'plan differs from predecessor')
    for name, kind in [('service.sock', socket.SOCK_SEQPACKET), ('legacy.sock', socket.SOCK_STREAM),
                       ('compat.sock', socket.SOCK_STREAM)]:
        stale_socket(prefix / name, kind)
    # Preserve the admitted cut and the operator's decision even after normal
    # startup replaces service-state.json. This is intent, not health or
    # permission to resume a second interruption during recovery.
    publish_record(prefix, 'service-recovery.json', {
        'source_boot_id': record['boot_id'], 'source_phase': record['phase'],
        'source_generation': current, 'source_record_sha256': sha(raw),
        'source_manifest_sha256': record['manifest_sha256'], 'boot_id': boot_id(),
        'choice': disposition, 'requested_generation': previous if disposition == 'previous' else current,
    })
    if disposition == 'previous':
        bundle.switch(prefix, previous)


def serve(prefix, disposition=None):
    private_router()
    quitting = False

    def quit_service(*_):
        nonlocal quitting
        quitting = True

    with bundle.locked(prefix), tempfile.TemporaryDirectory(dir='/run') as run, \
            socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as listener:
        svc = Service(prefix, Path(run))
        path = prefix / 'service.sock'
        # A crashed supervisor may have left a live daemon; never adopt or
        # signal a PID from a file, or silently start a second writer.
        if disposition:
            svc.hold()
            recover_locked(svc, disposition)
        elif (prefix / 'service-state.json').exists():
            require(decode(bundle.read_file(prefix, 'service-state.json'))['phase'] == 'stopped',
                    'unclean service state: isolate and inspect before restart')
        listener.bind(str(path))
        listener.listen(4)
        listener.settimeout(.2)
        signal.signal(signal.SIGTERM, quit_service)
        signal.signal(signal.SIGINT, quit_service)
        try:
            svc.hold()
            svc.record('starting')
            try:
                svc.start()
            except ERRORS as exc:
                svc.degrade('cold start: ' + str(exc))
            while not quitting:
                if svc.phase == 'running' and svc.proc.poll() is not None:
                    svc.degrade('selected daemon exited')
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                with conn:
                    conn.settimeout(2)
                    try:
                        req = decode(conn.recv(8192))
                        if req['command'] == 'status':
                            ok = True
                        elif req['command'] == 'stop':
                            quitting = True
                            svc.shutdown()
                            ok = svc.phase == 'stopped'
                        else:
                            ok = svc.transition(req)
                        conn.sendall(encode(dict(svc.status, ok=ok)))
                    except ERRORS as exc:
                        try:
                            conn.sendall(encode(dict(svc.status, ok=False, error=str(exc))))
                        except OSError:
                            pass
        finally:
            if svc.phase != 'stopped':
                svc.shutdown()
            path.unlink(missing_ok=True)
        return svc.phase == 'stopped'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--prefix', required=True, type=Path)
    sub = ap.add_subparsers(dest='command', required=True)
    for name in ('serve', 'arm', 'recover', 'status', 'stop', 'rollback', 'upgrade'):
        parser = sub.add_parser(name)
        if name == 'upgrade':
            for flag in ('work', 'backend'):
                parser.add_argument('--' + flag, required=True)
        elif name == 'recover':
            parser.add_argument('disposition', choices=['selected', 'previous'])
    args = ap.parse_args()
    bundle.private_dir(args.prefix)
    if args.command == 'serve':
        return serve(args.prefix)
    if args.command == 'recover':
        return serve(args.prefix, args.disposition)
    if args.command == 'arm':
        private_router()
        with bundle.locked(args.prefix), tempfile.TemporaryDirectory(dir='/run') as tmp:
            Service(args.prefix, Path(tmp)).hold()
        return True
    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as ctl:
        ctl.settimeout(90)
        ctl.connect(str(args.prefix / 'service.sock'))
        ctl.sendall(encode({k: v for k, v in vars(args).items() if k != 'prefix'}))
        response = decode(ctl.recv(8192))
        print(json.dumps(response))
        return response['ok']


if __name__ == '__main__':
    os.umask(0o077)
    try:
        sys.exit(0 if main() else 1)
    except ERRORS as error:
        sys.exit('lan service: ' + str(error))
