#!/usr/bin/env python3
"""Offline checks of the actual release workflow ordering and channel predicates."""
import pathlib
import os
import subprocess
import unittest
import yaml

workflow = yaml.safe_load(pathlib.Path('.github/workflows/release.yml').read_text())
steps = workflow['jobs']['build']['steps']
by_name = {step.get('name'): i for i, step in enumerate(steps) if 'name' in step}
stable = ['Зафиксировать версию в репозитории', 'Выложить пакеты роутера в ветку dist',
          'Выложить сборки VPS в ветку dist-vps', 'Опубликовать плагины протоколов в splify2/plugins']
publish = stable + ['Опубликовать релиз', 'Опубликовать в splify2/releases']
gates = ['Стенды', 'Собрать пакеты', 'Убедиться, что ни одна архитектура не отвалилась',
         'Стенды расширенной части на настоящей wolfSSL (внутри образа сборки)',
         'Текст выпуска', 'Собрать и проверить Nano (Linux x86_64)', 'Проверить отсутствие тега выпуска']

class ReleaseWorkflow(unittest.TestCase):
    def test_predicates_and_order(self):
        for name in stable:
            self.assertEqual(steps[by_name[name]].get('if'), '${{ !inputs.prerelease }}')
        self.assertEqual(steps[by_name[gates[-2]]]['if'], 'inputs.nano')
        self.assertLess(max(by_name[n] for n in gates), min(by_name[n] for n in publish))
        release = steps[by_name['Опубликовать релиз']]['with']
        self.assertEqual(release['target_commitish'], '${{ steps.release_commit.outputs.sha }}')
        self.assertIn('git ls-remote --tags', steps[by_name[gates[-1]]]['run'])

    def test_strict_pluginmgr_gate(self):
        step = steps[by_name['Стенды расширенной части на настоящей wolfSSL (внутри образа сборки)']]
        self.assertFalse(step.get('continue-on-error', False))
        for fragment in ('-v "$PWD:/input:ro"', '-v "$gate_dir/s2p:/opt/s2p:ro"',
                         'install -m 0555 "$S2P" "$gate_dir/s2p"',
                         'cp -R /input/. /src/', '-e S2P=/opt/s2p', '-e PM_STRICT=1',
                         'set -o pipefail', '--network none', '--cap-drop ALL',
                         '--cap-add SYS_ADMIN', '--cap-add NET_ADMIN', '--security-opt no-new-privileges'):
            self.assertIn(fragment, step['run'])
        self.assertNotIn('|| true', step['run'])
        image_script = pathlib.Path('build/ext-test-image.sh').read_text()
        self.assertIn('STEER_NGTCP2="$NSRC"', image_script)
        self.assertIn('[ "${PM_STRICT:-0}" = 1 ] && [ ! -f "$NSRC/lib/ngtcp2_brutal.c" ]', image_script)
        env = dict(os.environ, S2P='/nonexistent/steer-s2p', PM_STRICT='1')
        result = subprocess.run(['sh', 'tests/pluginmgrmatch.sh'], env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('strict', result.stderr)
        env['PM_STRICT'] = '0'
        result = subprocess.run(['sh', 'tests/pluginmgrmatch.sh'], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('ПРОПУСК', result.stdout)
        env.update(S2P='/bin/true', PM_STRICT='1', PM_INNER='1')
        env.pop('PM_PARENT_NETNS', None)
        result = subprocess.run(['sh', 'tests/pluginmgrmatch.sh', '/bin/true'],
                                env=env, capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('не изолирован', result.stderr)

    def test_simulated_failures(self):
        # Inject failure at every step; record only publication steps actually reached.
        for preview in (False, True):
            for nano in (False, True):
                if nano and not preview:
                    continue
                for failure in range(len(steps) + 1):
                    if not nano and failure == by_name[gates[-2]]: continue
                    writes = []
                    for i, step in enumerate(steps):
                        name = step.get('name')
                        if name in stable and preview: continue
                        if name == gates[-2] and not nano: continue
                        if i == failure: break
                        if name in publish: writes.append(name)
                    if preview:
                        self.assertFalse(set(writes) & set(stable))
                    if failure <= max(by_name[n] for n in gates):
                        self.assertFalse(writes, (preview, nano, failure, writes))

if __name__ == '__main__': unittest.main()
