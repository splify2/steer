#!/usr/bin/python3
"""Build a disposable x86_64 ext4 root and boot it three times using local QEMU/KVM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]


def image(root, args):
    def copy(src, dest=None):
        src = Path(src)
        out = root / str(dest or src).lstrip('/')
        out.parent.mkdir(parents=True, exist_ok=True)
        if not out.exists():
            shutil.copyfile(src, out)
            out.chmod(src.stat().st_mode & 0o755)

    def link(path, target):
        p = root / path
        p.parent.mkdir(exist_ok=True, parents=True)
        p.symlink_to(target)

    def text(path, data):
        p = root / path
        p.parent.mkdir(exist_ok=True, parents=True)
        p.write_text(data)
        p.chmod(0o644)

    def elf(src, dest=None):
        copy(src, dest)
        result = subprocess.run(['ldd', src], capture_output=True, text=True)
        if result.returncode and 'not a dynamic executable' not in result.stderr + result.stdout:
            raise RuntimeError('cannot inspect: ' + str(src))
        if 'not found' in result.stdout:
            raise RuntimeError('missing library: ' + str(src))
        for lib in re.findall(r'(?:=> |^\s*)(/\S+) \(', result.stdout, re.M):
            copy(lib)

    for path in ('dev', 'sys', 'proc', 'var', 'run', 'tmp', 'etc', 'lab', 'root'):
        (root / path).mkdir()
    (root / 'lab').chmod(0o700)
    (root / 'tmp').chmod(0o1777)
    for name in ('bin', 'sbin', 'lib', 'lib64'):
        (root / 'usr' / name).mkdir(parents=True)
        link(name, 'usr/' + name)
    link('var/run', '/run')
    copy('/usr/bin/busybox')
    for applet in ('cat', 'ls', 'ln', 'grep', 'readlink'):
        link('usr/bin/' + applet, 'busybox')
    link('usr/bin/sh', 'dash')
    for name in ('dash', 'ip', 'nft', 'wg', 'unshare', 'nsenter', 'mount', 'umount', 'kmod', 'systemctl'):
        elf(Path(shutil.which(name)).resolve())
    link('usr/sbin/modprobe', '../bin/kmod')
    for name in ('systemd', 'systemd-executor', 'systemd-shutdown'):
        elf('/usr/lib/systemd/' + name)
    link('usr/sbin/init', '/usr/lib/systemd/systemd')
    py = Path(sys.executable).resolve()
    elf(py, '/usr/bin/' + py.name)
    link('usr/bin/python3', py.name)
    stdlib = Path('/usr/lib') / f'python{sys.version_info.major}.{sys.version_info.minor}'
    shutil.copytree(stdlib, root / str(stdlib).lstrip('/'), symlinks=True,
                    ignore=shutil.ignore_patterns('__pycache__', 'sitecustomize.py', 'config-*'))
    for ext in (stdlib / 'lib-dynload').glob('*.so'):
        elf(ext)
    # Only matching kernel modules and indices; never copy build/source symlinks,
    # host /etc, machine-id, initrd configuration, network state or credentials.
    mods = Path('/lib/modules') / args.kernel.name.removeprefix('vmlinuz-')
    for part in [mods / 'kernel', *mods.glob('modules.*')]:
        if part.is_dir():
            shutil.copytree(part, root / str(part).lstrip('/'))
        else:
            copy(part)
    text('etc/os-release', 'ID=gate-e\nNAME="Gate E disposable guest"\n')
    text('etc/machine-id', '')
    text('etc/passwd', 'root:x:0:0:root:/root:/bin/sh\n')
    text('etc/group', 'root:x:0:\n')
    units = '/usr/lib/systemd/system/'
    for unit in ('reboot.target', 'poweroff.target', 'shutdown.target', 'umount.target', 'final.target',
                 'systemd-reboot.service', 'systemd-poweroff.service'):
        copy(units + unit)
    scope = 'etc/systemd/system/'
    text(scope + 'gate-e.target', '[Unit]\nDescription=Gate E guest boot\nDefaultDependencies=no\n'
         'Wants=gate-e-router.service gate-e-check.service\n')
    header = '[Unit]\nDefaultDependencies=no\nConflicts=shutdown.target\nBefore=shutdown.target\n'
    io = 'StandardOutput=tty\nStandardError=tty\nTTYPath=/dev/ttyS0\n'
    text(scope + 'gate-e-router.service', header + '[Service]\nType=simple\n' + io +
         'ExecStart=/bin/sh /lab/src/tests/gate-e-guest/router.sh\n'
         'ExecStop=/usr/bin/python3 -B /lab/src/experimental/offline-bundle/lan_service.py --prefix /lab/prefix stop\n')
    text(scope + 'gate-e-check.service', header + 'After=gate-e-router.service\nFailureAction=poweroff-force\n'
         '[Service]\nType=oneshot\nSuccessExitStatus=SIGTERM\n' + io +
         'ExecStart=/usr/bin/python3 -B /lab/src/tests/gate-e-guest/guest.py outer\n')
    for rel in ('tests/gate_e_lan_netns.py', 'tests/gate_e_supervised.py',
                'tests/fixtures/gate-e/legacy-v2-lan.json', 'tools/gate_e_preflight.py',
                'tests/gate-e-guest/router.sh', 'tests/gate-e-guest/guest.py',
                *('experimental/offline-bundle/' + n for n in
                  ('bundle.py', 'convert_lan.py', 'lan_profile.py', 'lan_service.py'))):
        copy(REPO / rel, 'lab/src/' + rel)
    elf(args.legacy, 'lab/old')
    elf(args.backend, 'lab/backend')


def inspect_disk(disk, boots, args):
    def read(path):
        return subprocess.check_output(['debugfs', '-R', 'cat /lab/' + path, disk],
                                       stderr=subprocess.DEVNULL)

    def verify(ok, reason):
        if not ok:
            raise RuntimeError('offline disk check: ' + reason)

    verify(json.loads(read('passed-boots.json')) == [boot for _, boot, _ in boots], 'boot history')
    expected = json.loads(read('expected.json'))
    final = json.loads(read('prefix/service-state.json'))
    verify(final['phase'] == 'stopped' and final['daemon_pid'] is None
           and final['selected'] == expected['original'], 'unclean final service stop')
    names = []
    for key in ('original', 'candidate'):
        gen = expected[key]
        verify(re.fullmatch(r'generations/stage-[a-z0-9_-]+', gen), 'invalid generation')
        names.append('prefix/states/' + gen.split('/')[1] + '/')
    old, new = names
    raw = (REPO / 'tests/fixtures/gate-e/legacy-v2-lan.json').read_bytes()
    plan = read(new + 'plan.json')
    verify(read(old + 'spec.json') == raw and json.loads(plan)['source_sha256'] ==
           hashlib.sha256(raw).hexdigest() and hashlib.sha256(plan).hexdigest() == expected['plan'],
           'source spec or converted plan')
    verify(read(old + 'registry') == read(new + 'registry') == b'vpn 100000 300\n', 'registry')
    for gen, file, source in [('original', '/core', args.legacy),
                              ('candidate', '/legacy-gateway-v2', args.backend)]:
        verify(read('prefix/' + expected[gen] + file) == source.read_bytes(), 'engine identity')
    sb = subprocess.check_output(['dumpe2fs', '-h', disk], stderr=subprocess.DEVNULL,
                                 env=dict(os.environ, LC_ALL='C'), text=True)
    verify(re.search(r'^Filesystem state:\s+clean$', sb, re.M), 'ext4 not cleanly unmounted')
    subprocess.run(['e2fsck', '-fn', disk], check=True)


def main(args):
    os.umask(0o077)
    # No loop devices, host mounts or host boot configuration changes.
    with tempfile.TemporaryDirectory(dir=args.work, prefix='private-guest-') as directory:
        base = Path(directory)
        root = base / 'root'
        root.mkdir()
        image(root, args)
        disk = base / 'guest.ext4'
        with disk.open('xb') as stream:
            stream.truncate(512 * 1024**2)
        subprocess.run(['mkfs.ext4', '-q', '-F', '-d', root, disk], check=True)
        shutil.rmtree(root)
        log = base / 'serial.log'
        env = dict(os.environ)
        if args.libdir:
            env['LD_LIBRARY_PATH'] = str(args.libdir)
        with log.open('wb') as console:
            try:
                subprocess.run([args.qemu, '-no-user-config', '-nodefaults', '-machine', 'pc,accel=kvm',
                    '-cpu', 'host', '-smp', '2', '-m', '512', '-nic', 'none', '-display', 'none',
                    '-monitor', 'none', '-serial', 'stdio', '-L', args.roms, '-bios', args.bios,
                    '-kernel', args.kernel, '-append', 'root=/dev/vda rw rootfstype=ext4 console=ttyS0 '
                    'quiet panic=0 gate_e_guest=1 systemd.unit=gate-e.target systemd.log_target=console',
                    '-drive', f'if=none,id=root,format=raw,file={disk}', '-device', 'virtio-blk-pci,drive=root'],
                    stdin=subprocess.DEVNULL, stdout=console, stderr=console, env=env, check=True, timeout=120)
            except (subprocess.SubprocessError, OSError):
                print(log.read_text(errors='replace')[-7000:], file=sys.stderr)
                raise
        serial = log.read_text(errors='replace')
        boots = re.findall(r'GATE_E_BOOT (\d) ([a-f0-9-]{36}) (legacy|compat|restored)', serial)
        if ([(i, mode) for i, _, mode in boots] != list(zip('012', ('legacy', 'compat', 'restored')))
                or len({uuid.UUID(b) for _, b, _ in boots}) != 3
                or Path('/proc/sys/kernel/random/boot_id').read_text().strip() in {b for _, b, _ in boots}):
            print(serial[-7000:], file=sys.stderr)
            raise RuntimeError('missing distinct kernel boot witnesses: ' + repr(boots))
        inspect_disk(disk, boots, args)
        for i, boot, mode in boots:
            print(f'PASS guest boot {i}: {boot} {mode}')
        print('PASS offline ext4: clean shutdown, boot history, binaries, spec/plan and registries')


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    for name in ('work', 'kernel', 'qemu', 'roms', 'bios', 'legacy', 'backend', 'libdir'):
        ap.add_argument('--' + name, type=Path, required=name != 'libdir')
    main(ap.parse_args())
