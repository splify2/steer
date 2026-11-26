import hashlib
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

CLI = Path(__file__).with_name('bundle.py')


class OfflineTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.prefix = self.root / 'prefix'
        self.prefix.mkdir(mode=0o700)
        self.state = self.prefix / 'user-state.json'
        self.state.write_text('{"legacy":"untouched"}')

    def tearDown(self):
        # Generations are deliberately read-only to the owner.
        for root, dirs, files in os.walk(self.root):
            os.chmod(root, 0o700)
        self.tmp.cleanup()

    def fixture(self, version, state_format=None):
        bundle = self.root / ('bundle' + version)
        (bundle / 'assets').mkdir(parents=True)
        for name in ('core', 'ui', 'assets/index.html', 'assets/app.js'):
            (bundle / name).write_text(version + name)
        if state_format:
            (bundle / 'state').mkdir()
            (bundle / 'state/FORMAT').write_text(state_format + '\n')
            (bundle / 'state/config.json').write_text('{"generation":"' + version + '"}')
            if state_format.startswith('steer-v3'):
                (bundle / 'state/wg-linked-journal').write_text('v3 journal fixture')
        manifest = self.root / ('manifest' + version + '.json')
        manifest.write_text(json.dumps({p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in bundle.rglob('*') if p.is_file()}))
        return bundle, manifest

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(CLI), '--prefix', str(self.prefix), *map(str, args)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result.stdout.strip()

    def old_installer_generation(self, name='old-software'):
        # Independent representation of 68adcc1: no state bundle and no
        # .state-format, with the old on-disk .manifest and .previous files.
        generations = self.prefix / 'generations'
        generations.mkdir(mode=0o700)
        generation = generations / name
        generation.mkdir(mode=0o700)
        files = {'core': b'old-core', 'ui': b'old-ui',
                 'assets/index.html': b'old-index'}
        (generation / 'assets').mkdir(mode=0o700)
        for path, data in files.items():
            dest = generation / path
            dest.write_bytes(data)
            dest.chmod(0o500 if path in ('core', 'ui') else 0o400)
        manifest = {path: hashlib.sha256(data).hexdigest()
                    for path, data in files.items()}
        (generation / '.manifest').write_text(json.dumps(manifest))
        (generation / '.manifest').chmod(0o400)
        (generation / '.previous').write_text('')
        (generation / '.previous').chmod(0o400)
        for root, dirs, _ in os.walk(generation, topdown=False):
            os.chmod(root, 0o500)
        os.symlink('generations/' + name, self.prefix / 'active')
        return 'generations/' + name

    def test_rollback_accepts_independent_old_software_only_generation(self):
        old = self.old_installer_generation()
        b, mb = self.fixture('b', 'steer-v3-linked-wg-v1')
        self.cli('install', b, '--manifest', mb)
        self.assertEqual(self.cli('rollback'), old)
        self.assertEqual((self.prefix / 'active/core').read_text(), 'old-core')
        self.assertEqual(self.cli('status'), old)

    def test_install_failure_rollback_and_state(self):
        a, ma = self.fixture('a', 'steer-v2.1.4')
        b, mb = self.fixture('b', 'steer-v3-linked-wg-v1')
        self.assertEqual(self.cli('status'), 'none')
        first = self.cli('install', a, '--manifest', ma)
        first_state = Path(self.cli('state-dir'))
        self.assertEqual((first_state / 'FORMAT').read_text(), 'steer-v2.1.4\n')
        self.assertFalse((first_state / 'wg-linked-journal').exists())
        (b / 'ui').write_text('corrupt')
        self.cli('install', b, '--manifest', mb, ok=False)
        self.assertEqual(self.cli('status'), first)
        self.assertEqual(self.cli('state-dir'), str(first_state))
        (b / 'ui').write_text('bui')
        second = self.cli('install', b, '--manifest', mb)
        self.assertNotEqual(first, second)
        self.assertEqual((self.prefix / 'active/core').read_text(), 'bcore')
        second_state = Path(self.cli('state-dir'))
        self.assertNotEqual(first_state, second_state)
        self.assertEqual((second_state / 'FORMAT').read_text(), 'steer-v3-linked-wg-v1\n')
        self.assertEqual((second_state / 'wg-linked-journal').read_text(), 'v3 journal fixture')
        self.assertEqual(self.cli('rollback'), first)
        self.assertEqual((self.prefix / 'active/core').read_text(), 'acore')
        self.assertEqual(self.cli('state-dir'), str(first_state))
        self.assertFalse((first_state / 'wg-linked-journal').exists())
        self.assertTrue((second_state / 'wg-linked-journal').exists())
        self.assertEqual(self.state.read_text(), '{"legacy":"untouched"}')

    def test_pair_format_mismatch_blocks_rollback(self):
        a, ma = self.fixture('a', 'steer-v2.1.4')
        b, mb = self.fixture('b', 'steer-v3-linked-wg-v1')
        first = self.cli('install', a, '--manifest', ma)
        second = self.cli('install', b, '--manifest', mb)
        second_state = self.cli('state-dir')
        first_state = Path(self.prefix / 'states' / first.split('/')[-1])
        first_state.chmod(0o700)
        (first_state / 'FORMAT').chmod(0o600)
        (first_state / 'FORMAT').write_text('steer-v3-linked-wg-v1\n')
        self.cli('rollback', ok=False)
        self.assertEqual(self.cli('status'), second)
        self.assertEqual(self.cli('state-dir'), second_state)

    def test_pair_without_state_marker_blocks_rollback(self):
        a, ma = self.fixture('a', 'steer-v2.1.4')
        b, mb = self.fixture('b', 'steer-v3-linked-wg-v1')
        first = self.cli('install', a, '--manifest', ma)
        second = self.cli('install', b, '--manifest', mb)
        old_generation = self.prefix / first
        old_generation.chmod(0o700)
        (old_generation / '.state-format').unlink()
        old_generation.chmod(0o500)
        self.cli('rollback', ok=False)
        self.assertEqual(self.cli('status'), second)

    def test_paths_and_extra_files_rejected(self):
        a, ma = self.fixture('a')
        (a / 'extra').write_text('x')
        self.cli('install', a, '--manifest', ma, ok=False)
        (a / 'extra').unlink()
        (a / 'ui').unlink()
        (a / 'ui').symlink_to(a / 'core')
        self.cli('install', a, '--manifest', ma, ok=False)
        self.assertEqual(self.cli('status'), 'none')

    def test_tampered_previous_rejected(self):
        a, ma = self.fixture('a')
        b, mb = self.fixture('b')
        first = self.cli('install', a, '--manifest', ma)
        second = self.cli('install', b, '--manifest', mb)
        path = self.prefix / first / 'core'
        path.chmod(0o700)
        path.write_text('tampered')
        self.cli('rollback', ok=False)
        self.assertEqual(self.cli('status'), second)

    def test_busy_lock_fails_without_waiting(self):
        with (self.prefix / '.bundle.lock').open('w') as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            self.cli('status', ok=False)


if __name__ == '__main__':
    unittest.main()
