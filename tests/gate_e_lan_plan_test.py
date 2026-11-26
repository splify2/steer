#!/usr/bin/env python3
"""Offline admission checks with real source/target parsers, no network operations."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

import gate_e_supervised as g


def main(old_core, backend):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        prefix, work = root / 'prefix', root / 'work'
        for p in [prefix, work]:
            p.mkdir(mode=0o700)
        source = g.LEGACY_FIXTURE.read_bytes().replace(b'vpn', b'office').replace(
            b'lan-default', b'office-catch-all')
        registry = b'office 100000 300\n'
        try:
            old = g.install(prefix, *g.make_bundle(root, 'old', old_core, 'steer-legacy-v2.1.4',
                {'spec.json': source, 'registry': registry}))
            state = g.state_dir(prefix)
            spec = state / 'spec.json'
            args = [sys.executable, '-B', g.BUNDLE.with_name('convert_lan.py'), 'plan',
                    '--prefix', prefix, '--work', work, '--backend', backend]

            def rejected():
                p = subprocess.run(args, capture_output=True, timeout=10)
                assert p.returncode and not p.stdout and b'Traceback' not in p.stderr
                assert g.bundle_cli(prefix, 'status') == old and not any(work.iterdir())

            for mutation in [
                    source.replace(b'"version": 2', b'"version": 2.0'),
                    source.replace(b'"version": 2', b'"version": 1, "version": 2'),
                    source.replace(b'"version": 2', b'"version": 2, "dns": {}'),
                    source.replace(b'"kind":', b'"on_fail": "direct", "kind":'),
                    source.replace(b'"to":', b'"from":"all", "to":'),
                    source.replace(b'"out": "office"', b'"out": "other"'),
                    source.replace(b'"wg0"', b'"eth0"')]:
                spec.write_bytes(mutation)
                rejected()
            spec.write_bytes(source)
            (state / 'spec.yaml').touch()
            rejected()
            (state / 'spec.yaml').unlink()
            (state / 'registry').write_bytes(registry + b'stale 200000 301\n')
            rejected()
            (state / 'registry').write_bytes(registry)
            subprocess.run(args, check=True)
            plan = json.loads((work / 'bundle/state/plan.json').read_bytes())
            assert plan['route'] == {'id': 'office-catch-all', 'destination': 'all', 'output': 'office'}
            assert plan['egress']['id'] == 'office' and plan['source_sha256'] == g.digest(spec)
            assert (work / 'backup/spec.json').read_bytes() == source
            assert (work / 'backup/registry').read_bytes() == registry
            assert g.bundle_cli(prefix, 'status') == old
        finally:
            # The generic switcher intentionally makes code generations read-only.
            for directory, _, _ in os.walk(root):
                os.chmod(directory, 0o700)
    print('PASS exact JSON/registry/state inventory; named output and rule survive conversion')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit('usage: gate_e_lan_plan_test.py V2_1_4_STEERD TARGET_LEGACY_STEERD')
    main(*(Path(p).resolve(strict=True) for p in sys.argv[1:]))
