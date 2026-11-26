#!/usr/bin/env python3
"""Convert a stopped, private-prefix Gate E generation; never runs Apply."""
import argparse
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

import bundle
from lan_profile import ENGINE, FORMAT, decode, encode, engine_env, lift, lower, require, sha

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tools'))
from gate_e_preflight import source_snapshot, source_still_matches, SourceError

HERE = Path(__file__).resolve().parent
LEGACY_FORMAT = b'steer-legacy-v2.1.4\n'


def inspect(prefix, current):
    require(current and re.fullmatch(r'generations/[a-z0-9_-]+', current), 'no legacy generation')
    gen = prefix / current
    require(gen.resolve() == gen, 'invalid legacy generation')
    require({p.name for p in gen.iterdir()} == {'core', '.manifest', '.previous', '.state-format'},
            'requires plain legacy generation')
    state = bundle.state_path(prefix, current)
    expected = bundle.manifest(gen / '.manifest')
    require({'core', 'state/FORMAT', 'state/spec.json'} <= expected.keys() <=
            {'core', 'state/FORMAT', 'state/spec.json', 'state/registry'},
            'requires a core-only legacy installation')
    require(set(p.name for p in state.iterdir()) == {'FORMAT', 'spec.json', 'registry'},
            'requires stopped legacy state with populated registry and no extra files')
    files = {'core': gen / 'core', **{name: state / name for name in ('FORMAT', 'spec.json', 'registry')}}
    blobs, inventory, identities = {}, {}, {}
    for name, path in files.items():
        raw, sig = source_snapshot(path)
        _, _, mode, links, uid, gid, *_ = sig
        require(uid == os.geteuid() and links == 1, 'foreign owner or hard link')
        blobs[name] = raw
        inventory[name] = {'uid': uid, 'gid': gid, 'mode': stat.S_IMODE(mode), 'sha256': sha(raw)}
        identities[path] = sig
    require(inventory['core']['sha256'] == expected['core'] and blobs['FORMAT'] == LEGACY_FORMAT
            and inventory['FORMAT']['sha256'] == expected['state/FORMAT'],
            'foreign legacy binary or state format')
    return blobs, {'generation': current, 'files': inventory}, identities


def effective(binary, raw, empty):
    env = engine_env(empty)
    env['PATH'] = ''
    version = subprocess.run([binary, 'version', '--json'], check=True, capture_output=True,
                             env=env, cwd=empty, timeout=20)
    require(decode(version.stdout).get('core') == '2.1.4', 'requires the reviewed v2 engine family')
    result = subprocess.run([binary, 'spec', 'convert', '--json', '--spec', '-'],
                            input=raw, capture_output=True, env=env, cwd=empty, timeout=20)
    require(result.returncode == 0, 'legacy parser rejected plan or source')
    return decode(result.stdout)


def write(root, files):
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with path.open('xb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())


def verified_previous(prefix):
    # The generic rollback intentionally doesn't authenticate writable state.
    # For this stopped profile *all* legacy bytes/modes must match the inventory.
    current = bundle.active(prefix)
    require(current, 'no active candidate')
    gen = prefix / current
    expected = bundle.manifest(gen / '.manifest')
    require(ENGINE in expected and 'state/recovery.json' in expected,
            'active generation is not a LAN compatibility candidate')
    state = bundle.state_path(prefix, current)
    require(bundle.read_file(state, 'FORMAT') == (FORMAT + '\n').encode(), 'foreign format')
    previous = bundle.read_file(gen, '.previous').decode()
    _, inventory, identities = inspect(prefix, previous)
    require(sha(encode(inventory)) == expected['state/recovery.json'] and
            all(source_still_matches(p, sig) for p, sig in identities.items()),
            'legacy recovery pair changed; inspect private backup before retrying')
    return previous


def rollback_locked(prefix):
    previous = verified_previous(prefix)
    bundle.switch(prefix, previous)
    return previous


def legacy_plan(blobs):
    doc = decode(blobs['spec.json'])
    plan = lift(doc, sha(blobs['spec.json']))
    require(blobs['registry'] == (plan['egress']['id'] + ' 100000 300\n').encode(),
            'only the first default legacy mark/table allocation is supported')
    return doc, plan


def convert_locked(args):
    prefix, work = args.prefix, args.work
    bundle.private_dir(prefix)
    bundle.private_dir(work)
    require(not (prefix.is_relative_to(work) or work.is_relative_to(prefix)),
            'work must be separate from prefix')
    blobs, inventory, ids = inspect(prefix, bundle.active(prefix))
    doc, plan = legacy_plan(blobs)
    backend = bundle.read_file(args.backend.parent, args.backend.name)
    with tempfile.TemporaryDirectory(dir=work) as tmp:
        empty = Path(tmp) / 'empty'
        empty.mkdir()
        for name, image, spec in [('source', blobs['core'], blobs['spec.json']),
                                  ('target', backend, encode(lower(plan)))]:
            exe = Path(tmp) / name
            exe.write_bytes(image)
            exe.chmod(0o500)
            require(effective(exe, spec, empty) == doc, 'normalized semantics differ')
    files = {'core': (HERE / 'lan_profile.py').read_bytes(), ENGINE: backend,
             'state/FORMAT': (FORMAT + '\n').encode(), 'state/plan.json': encode(plan),
             'state/registry': blobs['registry'], 'state/recovery.json': encode(inventory)}
    expected = {k: sha(v) for k, v in files.items()}
    meta = {'inventory.json': encode(inventory), 'manifest.json': encode(expected)}
    require(all(source_still_matches(path, sig) for path, sig in ids.items()),
            'source changed during conversion')
    if args.command == 'plan':
        require(not any(work.iterdir()), 'plan needs an empty private work directory')
        write(work / 'backup', blobs)
        write(work / 'bundle', files)
        write(work, meta)
        for directory, _, _ in os.walk(work, topdown=False):
            bundle.syncdir(directory)
    else:
        # Re-derive the reviewed manifest from the still-active legacy source
        # under the switcher's lock; do not trust an editable staging manifest.
        for root, entries in [(work, meta), (work / 'backup', blobs)]:
            require(all(bundle.read_file(root, n) == v for n, v in entries.items()),
                    'backup, input or reviewed manifest changed; plan again')
        with tempfile.TemporaryDirectory(dir=work) as temp:
            trusted = Path(temp) / 'manifest'
            trusted.write_bytes(meta['manifest.json'])
            bundle.install(prefix, work / 'bundle', trusted)
    return {'engine': ENGINE, 'source_sha256': plan['source_sha256'], 'selected': bundle.active(prefix)}


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    sub = ap.add_subparsers(dest='command', required=True)
    for action in ('plan', 'switch', 'rollback'):
        parser = sub.add_parser(action)
        parser.add_argument('--prefix', required=True, type=Path)
        if action != 'rollback':
            parser.add_argument('--work', required=True, type=Path)
            parser.add_argument('--backend', required=True, type=Path)
    os.umask(0o077)
    try:
        args = ap.parse_args()
        with bundle.locked(args.prefix):
            if args.command == 'rollback':
                print(rollback_locked(args.prefix))
            else:
                print(encode(convert_locked(args)).decode().strip())
    except (OSError, ValueError, TypeError, KeyError, RecursionError, SourceError,
            subprocess.SubprocessError) as exc:
        sys.exit('LAN conversion refused: ' + str(exc))
