"""Offline Linux x86_64 gate. Arguments: fresh output directory and local UI, protocols, SDK checkouts.

Builds their HEADs and the committed core HEAD; requires PyYAML and private netns with loopback.
The output directory keeps both clean builds, extracted archives and the logs.
"""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tarfile

import yaml


def git(repo, *args):
    return subprocess.check_output(['git', '-C', repo, *args], text=True).strip()


def isolated(command, cwd, env, mask, log):
    with log.open('w') as output:
        subprocess.run(['unshare', '-n', 'sh', '-ec', 'ip link set lo up; exec "$@"', 'sh', *command],
                       cwd=cwd, env=env, umask=mask, stdout=output, stderr=subprocess.STDOUT,
                       timeout=300, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'ui', 'protocols', 'sdk'):
        parser.add_argument(name, type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        parser.error('Linux x86_64 required')
    root = args.output.resolve()
    root.mkdir()  # No reuse of an existing binary, stage or archive.
    sources = {'.': Path(__file__).resolve().parents[1], '.nano-ui': args.ui.resolve(),
               '.nano-protocols': args.protocols.resolve(), '.plugin-sdk': args.sdk.resolve()}
    revs = {d: git(repo, 'rev-parse', 'HEAD') for d, repo in sources.items()}
    epoch = int(git(sources['.'], 'show', '-s', '--format=%ct', revs['.']))
    provenance = ''.join(f'{key}={revs[d]}\n' for key, d in zip(
        ('steer', 'steer-ui', 'steer-protocols', 'plugin-sdk'), sources)).encode()
    first = {}
    for label, mask in [('a', 0o022), ('b', 0o077)]:
        run = root / label
        run.mkdir()
        src, tmp = run / 'src', run / 'tmp'
        tmp.mkdir()
        for d, repo in sources.items():
            subprocess.run(['git', 'clone', '-q', '--local', '--no-checkout', repo, src / d],
                           check=True, umask=mask)
            subprocess.run(['git', '-C', src / d, 'checkout', '-q', '--detach', revs[d]],
                           check=True, umask=mask)
        steps = yaml.safe_load((src / '.github/workflows/release.yml').read_text())['jobs']['build']['steps']
        step, = (s for s in steps if s.get('name') == 'Собрать и проверить Nano (Linux x86_64)')
        script = run / 'nano-step.sh'
        script.write_text(step['run'])
        version = (src / 'VERSION').read_text().strip()
        env = dict(PATH=os.environ['PATH'], HOME=str(run), TMPDIR=str(tmp), RUNNER_TEMP=str(tmp), VERSION=version)
        isolated(['bash', '-e', script], src, env, mask, run / 'build.log')

        for binary in ('steer-nano', 'steer-ui-nano'):
            ui = binary == 'steer-ui-nano'
            archive = src / 'out' / f'{binary}-{version}-linux-x86_64.tar.gz'
            files = {binary, 'LICENSE', 'README.md', 'SOURCE-REVISIONS'}
            if ui:
                files.update(['assets', *('assets/' + f for f in
                             ('index.html', 'app.js', 'app.css', 'config-model.js'))])
            with tarfile.open(archive, 'r:gz') as tar:
                assert sorted(tar.getnames()) == sorted(files)
                for m in tar:
                    assert (m.uid, m.gid, m.mtime) == (0, 0, epoch)
                    assert (m.isdir() if m.name == 'assets' else m.isfile())
                    assert m.mode == (0o755 if m.name in (binary, 'assets') else 0o644)
                assert tar.extractfile('SOURCE-REVISIONS').read() == provenance
                assert tar.extractfile('LICENSE').read() == ((src / '.nano-ui' if ui else src) / 'LICENSE').read_bytes()
                tar.extractall(run / binary, filter='data')
            data = archive.read_bytes()
            print(label, archive.name, hashlib.sha256(data).hexdigest(), flush=True)
            if label == 'a':
                first[binary] = data
            else:
                assert data == first[binary], f'{binary}: archive differs across clean builds'
        env['PYTHONPATH'] = str(src / '.nano-protocols/tests')
        isolated(['python3', '-B', src / '.nano-ui/tests/core_persistence.py',
                  '--core', run / 'steer-nano/steer-nano', '--ui', run / 'steer-ui-nano/steer-ui-nano',
                  '--assets', run / 'steer-ui-nano/assets'], src, env, mask, run / 'unpacked.log')
    print('PASS both clean release-step builds, archive bytes, provenance, modes and unpacked persistence')


if __name__ == '__main__':
    main()
