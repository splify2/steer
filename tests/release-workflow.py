#!/usr/bin/env python3
"""Offline checks of the actual release workflow ordering and channel predicates."""
import pathlib
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
