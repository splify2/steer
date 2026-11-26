#!/usr/bin/env python3
"""Hash stripped core/UI and the actual full/Nano asset trees; no package claim."""
import argparse
import hashlib
import json
from pathlib import Path


def item(path):
    path=path.resolve(strict=True)
    if not path.is_file():raise ValueError('expected a regular file')
    return {'path':str(path),'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def main():
    p=argparse.ArgumentParser(description=__doc__)
    for arg in ('full-core','full-ui','full-assets','nano-core','nano-ui','nano-assets','output'):
        p.add_argument('--'+arg,type=Path,required=True)
    a=p.parse_args();result={'scope':'logical file bytes; excludes packaging, installer and shared system libraries'}
    for variant in ('full','nano'):
        core=item(getattr(a,variant+'_core'));ui=item(getattr(a,variant+'_ui'))
        directory=getattr(a,variant+'_assets').resolve(strict=True)
        files={str(x.relative_to(directory)):item(x) for x in sorted(directory.rglob('*')) if x.is_file()}
        required={'index.html','app.css','app.js','config-model.js'}
        if not required.issubset(files):raise ValueError('incomplete supplied asset tree')
        if variant=='nano' and any(name.startswith('fonts/') for name in files):raise ValueError('unexpected fonts in Nano assets')
        result[variant]={'core':core,'ui':ui,'assets':files,'assets_bytes':sum(x['bytes'] for x in files.values()),
                         'logical_bytes':core['bytes']+ui['bytes']+sum(x['bytes'] for x in files.values())}
    with a.output.open('x',encoding='utf8') as out:json.dump(result,out,indent=2);out.write('\n')

if __name__=='__main__':main()
