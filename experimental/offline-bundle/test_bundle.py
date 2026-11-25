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

    def fixture(self, version):
        bundle = self.root / ('bundle' + version)
        (bundle / 'assets').mkdir(parents=True)
        for name in ('core', 'ui', 'assets/index.html', 'assets/app.js'):
            (bundle / name).write_text(version + name)
        manifest = self.root / ('manifest' + version + '.json')
        manifest.write_text(json.dumps({p.relative_to(bundle).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                                        for p in bundle.rglob('*') if p.is_file()}))
        return bundle, manifest

    def cli(self, *args, ok=True):
        result = subprocess.run([sys.executable, str(CLI), '--prefix', str(self.prefix), *map(str, args)],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        return result.stdout.strip()

    def test_install_failure_rollback_and_state(self):
        a, ma = self.fixture('a')
        b, mb = self.fixture('b')
        self.assertEqual(self.cli('status'), 'none')
        first = self.cli('install', a, '--manifest', ma)
        (b / 'ui').write_text('corrupt')
        self.cli('install', b, '--manifest', mb, ok=False)
        self.assertEqual(self.cli('status'), first)
        (b / 'ui').write_text('bui')
        second = self.cli('install', b, '--manifest', mb)
        self.assertNotEqual(first, second)
        self.assertEqual((self.prefix / 'active/core').read_text(), 'bcore')
        self.assertEqual(self.cli('rollback'), first)
        self.assertEqual((self.prefix / 'active/core').read_text(), 'acore')
        self.assertEqual(self.state.read_text(), '{"legacy":"untouched"}')

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
