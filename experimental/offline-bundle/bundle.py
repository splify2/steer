#!/usr/bin/env python3
"""Offline, private-prefix software bundle switcher; not a service installer."""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile

MAX_FILE = 128 * 1024 * 1024
MAX_FILES = 1024


def fail(message):
    raise ValueError(message)


def syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_dir(path):
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.geteuid() or st.st_mode & 0o077:
        fail('prefix must be an existing private directory owned by the caller')
    if path.resolve() != path:
        fail('prefix must not contain symlinks or ..')


def read_file(root, name):
    # Each directory component is opened without following symlinks.
    parts = name.split('/')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        f = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            st = os.fstat(f)
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE:
                fail('artifact is not a bounded regular file: ' + name)
            with os.fdopen(f, 'rb', closefd=False) as stream:
                data = stream.read(MAX_FILE + 1)
            if len(data) > MAX_FILE:
                fail('artifact too large: ' + name)
            return data
        finally:
            os.close(f)
    finally:
        os.close(fd)


def manifest(path):
    raw = path.read_bytes()
    if len(raw) > 256 * 1024:
        fail('manifest too large')
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                fail('duplicate manifest key')
            result[key] = value
        return result
    obj = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(obj, dict) or not 1 <= len(obj) <= MAX_FILES:
        fail('manifest must be a bounded path-to-sha256 object')
    for name, digest in obj.items():
        p = PurePosixPath(name)
        if (not name or p.is_absolute() or str(p) != name or
                any(x in ('.', '..') for x in name.split('/')) or
                not (name in ('core', 'ui') or name.startswith('assets/') or
                     name.startswith('state/')) or
                not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            fail('invalid manifest entry: ' + name)
    if 'core' not in obj:
        fail('manifest requires core')
    has_ui = 'ui' in obj or any(name.startswith('assets/') for name in obj)
    if has_ui and not {'ui', 'assets/index.html'} <= obj.keys():
        fail('UI bundles require ui and assets/index.html')
    state_files = {name for name in obj if name.startswith('state/')}
    if state_files and 'state/FORMAT' not in state_files:
        fail('state bundle requires state/FORMAT')
    return obj


def active(prefix):
    link = prefix / 'active'
    if not link.is_symlink():
        if link.exists():
            fail('active is not a managed symlink')
        return None
    target = os.readlink(link)
    if not re.fullmatch(r'generations/[a-z0-9_-]+', target):
        fail('invalid active pointer')
    gen = prefix / target
    if gen.is_symlink() or not gen.is_dir():
        fail('active generation is missing or invalid')
    return target


def switch(prefix, target):
    # A unique temporary link cannot overwrite unrelated files.
    temp = prefix / ('.switch-' + os.urandom(12).hex())
    os.symlink(target, temp)
    try:
        os.replace(temp, prefix / 'active')
        syncdir(prefix)
    finally:
        if temp.is_symlink():
            temp.unlink()


def state_path(prefix, target):
    generation = prefix / target
    fmt = read_file(generation, '.state-format').decode('ascii')
    if not fmt:
        fail('generation has no paired state')
    name = target.split('/', 1)[1]
    states = prefix / 'states'
    if states.is_symlink() or not states.is_dir():
        fail('paired state directory is missing')
    private_dir(states)
    state = states / name
    if state.is_symlink() or not state.is_dir():
        fail('paired state snapshot is missing')
    private_dir(state)
    if read_file(state, 'FORMAT').decode('ascii') != fmt:
        fail('paired state format mismatch')
    return state


def copy_state(prefix, generation_name, expected, bundle):
    entries = {name: digest for name, digest in expected.items() if name.startswith('state/')}
    if not entries:
        return ''
    state_root = prefix / 'states'
    state_root.mkdir(mode=0o700, exist_ok=True)
    private_dir(state_root)
    target = state_root / generation_name
    target.mkdir(mode=0o700)
    try:
        for name, digest in sorted(entries.items()):
            data = read_file(bundle, name)
            if hashlib.sha256(data).hexdigest() != digest:
                fail('SHA256 mismatch: ' + name)
            relative = name[len('state/'):]
            dest = target / relative
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with dest.open('xb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            dest.chmod(0o400 if relative == 'FORMAT' else 0o600)
        for root, dirs, files in os.walk(target, topdown=False):
            syncdir(root)
            os.chmod(root, 0o700)
        syncdir(state_root)
        fmt = read_file(target, 'FORMAT').decode('ascii')
        if not re.fullmatch(r'[a-z0-9][a-z0-9._-]{0,63}\n?', fmt):
            fail('invalid state format identifier')
        return fmt
    except BaseException:
        for root, dirs, files in os.walk(target):
            os.chmod(root, 0o700)
        shutil.rmtree(target)
        raise


def install(prefix, bundle, manifest_path):
    expected = manifest(manifest_path)
    if bundle.is_symlink() or not bundle.is_dir():
        fail('bundle must be a directory, not a symlink')
    found = set()
    for root, dirs, files in os.walk(bundle, followlinks=False):
        for name in dirs:
            if (Path(root) / name).is_symlink():
                fail('bundle contains a symlink')
        for name in files:
            found.add((Path(root) / name).relative_to(bundle).as_posix())
            if len(found) > MAX_FILES:
                fail('too many bundle files')
    if found != set(expected):
        fail('bundle files differ from manifest')
    previous = active(prefix)
    gens = prefix / 'generations'
    gens.mkdir(mode=0o700, exist_ok=True)
    private_dir(gens)
    stage = Path(tempfile.mkdtemp(prefix='stage-', dir=gens))
    state_created = False
    try:
        state_format = copy_state(prefix, stage.name, expected, bundle)
        state_created = bool(state_format)
        if state_created:
            syncdir(prefix)
        for name, digest in sorted(expected.items()):
            if name.startswith('state/'):
                continue
            data = read_file(bundle, name)
            if hashlib.sha256(data).hexdigest() != digest:
                fail('SHA256 mismatch: ' + name)
            dest = stage / name
            dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            with dest.open('xb') as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            dest.chmod(0o500 if name in ('core', 'ui') else 0o400)
        meta = stage / '.previous'
        with meta.open('x') as f:
            f.write(previous or '')
            f.flush()
            os.fsync(f.fileno())
        meta.chmod(0o400)
        state_meta = stage / '.state-format'
        with state_meta.open('x') as f:
            f.write(state_format)
            f.flush()
            os.fsync(f.fileno())
        state_meta.chmod(0o400)
        with (stage / '.manifest').open('x') as f:
            json.dump(expected, f, sort_keys=True)
            f.flush()
            os.fsync(f.fileno())
        (stage / '.manifest').chmod(0o400)
        # Flush directory entries before publishing the sole selection pointer.
        for root, dirs, files in os.walk(stage, topdown=False):
            syncdir(root)
            os.chmod(root, 0o500)
        syncdir(gens)
        switch(prefix, 'generations/' + stage.name)
    except BaseException:
        # Never remove a generation after it has become active.
        if active(prefix) != 'generations/' + stage.name:
            for root, dirs, files in os.walk(stage):
                os.chmod(root, 0o700)
            shutil.rmtree(stage)
            if state_created:
                state = prefix / 'states' / stage.name
                for root, dirs, files in os.walk(state):
                    os.chmod(root, 0o700)
                shutil.rmtree(state)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--prefix', required=True, help='existing absolute private directory')
    sub = parser.add_subparsers(dest='command', required=True)
    inst = sub.add_parser('install', help='verify and select a local bundle')
    inst.add_argument('bundle', type=Path)
    inst.add_argument('--manifest', required=True, type=Path, help='operator-trusted SHA256 JSON manifest')
    sub.add_parser('status')
    sub.add_parser('rollback')
    sub.add_parser('state-dir')
    args = parser.parse_args()
    prefix = Path(args.prefix)
    if not args.prefix or not prefix.is_absolute() or str(prefix) != args.prefix or prefix == Path('/'):
        fail('prefix must be an explicit absolute non-root path')
    private_dir(prefix)
    lock = os.open(prefix / '.bundle.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(lock).st_mode):
            fail('invalid lock file')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.command == 'install':
            install(prefix, args.bundle, args.manifest)
        elif args.command == 'rollback':
            current = active(prefix)
            if not current:
                fail('no active generation')
            previous = read_file(prefix / current, '.previous').decode()
            if not re.fullmatch(r'generations/[a-z0-9_-]+', previous):
                fail('no previous generation')
            path = prefix / previous
            if path.is_symlink() or not path.is_dir():
                fail('previous generation unavailable')
            expected = manifest(path / '.manifest')
            for name, digest in expected.items():
                if name.startswith('state/'):
                    continue
                if hashlib.sha256(read_file(path, name)).hexdigest() != digest:
                    fail('previous generation SHA256 mismatch: ' + name)
            if read_file(path, '.state-format'):
                state_path(prefix, previous)
            switch(prefix, previous)
        elif args.command == 'state-dir':
            current = active(prefix)
            if not current:
                fail('no active generation')
            print(state_path(prefix, current))
            return
        print(active(prefix) or 'none')
    finally:
        os.close(lock)


if __name__ == '__main__':
    try:
        main()
    except (OSError, ValueError, UnicodeError) as exc:
        print('offline-bundle:', exc, file=sys.stderr)
        sys.exit(1)
