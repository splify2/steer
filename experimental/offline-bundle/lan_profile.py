#!/usr/bin/python3 -I
"""Private-netns one-shot gateway. Installed as core beside legacy-gateway-v2."""
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

FORMAT = 'steer-linux-lan-compat-v1'
ENGINE = 'legacy-gateway-v2'


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def decode(raw):
    def unique(pairs):
        obj = dict(pairs)
        require(len(obj) == len(pairs), 'duplicate key')
        return obj
    return json.loads(raw, object_pairs_hook=unique)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode(obj):
    return (json.dumps(obj, sort_keys=True, separators=(',', ':')) + '\n').encode()


def identifier(value):
    require(isinstance(value, str) and re.fullmatch('[a-z][a-z0-9_-]{0,30}', value),
            'unsupported identifier')
    return value


def lift(doc, source_hash):
    require(isinstance(doc, dict) and doc.keys() == {'version', 'lan', 'outputs', 'rules'}
            and type(doc['version']) is int and doc['version'] == 2, 'unsupported document')
    require(doc['lan'] == {'devices': ['br-lan']}, 'requires explicit br-lan')
    outputs = doc['outputs']
    require(isinstance(outputs, dict) and len(outputs) == 1, 'requires one output')
    name = identifier(next(iter(outputs)))
    require(outputs[name] == {'kind': 'interface', 'device': 'wg0'}, 'requires external wg0')
    rules = doc['rules']
    require(isinstance(rules, list) and len(rules) == 1 and isinstance(rules[0], dict)
            and rules[0].keys() == {'name', 'to', 'out'} and rules[0]['to'] == 'all'
            and rules[0]['out'] == name, 'requires one named catch-all to that output')
    return {'format': FORMAT, 'engine': ENGINE, 'source_sha256': source_hash,
            'capture_device': doc['lan']['devices'][0],
            'route': {'id': identifier(rules[0]['name']), 'destination': 'all',
                      'output': name},
            'egress': {'id': name, 'external_device': outputs[name]['device'], 'on_fail': 'drop'}}


def lower(plan):
    route, egress = plan['route'], plan['egress']
    spec = {'version': 2, 'lan': {'devices': [plan['capture_device']]},
            'outputs': {egress['id']: {'kind': 'interface', 'device': egress['external_device']}},
            'rules': [{'name': route['id'], 'to': route['destination'], 'out': route['output']}]}
    digest = plan['source_sha256']
    require(isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest)
            and lift(spec, digest) == plan, 'invalid gateway plan')
    spec['outputs'][egress['id']]['on_fail'] = egress['on_fail']
    return spec


def engine_env(empty):
    return dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin', HOME=str(empty), LC_ALL='C',
                STEER_PLUGIN_AUTO='0', **{key: str(empty) for key in (
                    'STEER_PLUGIN_DIR', 'STEER_PLUGIN_ETC', 'STEER_PLUGIN_SEED',
                    'STEER_PLUGIN_PANEL_DIR', 'STEER_PLUGINS_ROOT', 'STEER_PLUGINS_ETC')})


def run(action):
    require(action in ('apply', 'down'), 'expected apply or down')
    # A network namespace alone does not isolate the legacy iproute2 names file.
    require(not os.path.samefile('/proc/self/ns/net', '/proc/1/ns/net') and
            not os.path.samefile('/proc/self/ns/mnt', '/proc/1/ns/mnt') and
            not os.path.samefile('/etc', '/proc/1/root/etc'), 'requires isolated router netns and private /etc')
    gen = Path(__file__).resolve().parent
    prefix = gen.parent.parent
    require(gen.parent.name == 'generations', 'requires an installed gateway generation')
    with (prefix / '.bundle.lock').open('rb') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        require((prefix / 'active').resolve() == gen, 'inactive gateway generation')
        run_selected(gen, prefix, action)


def run_selected(gen, prefix, action):
    state = prefix / 'states' / gen.name
    require(state.resolve() == state and set(p.name for p in state.iterdir()) ==
            {'FORMAT', 'plan.json', 'registry', 'recovery.json'}, 'unexpected gateway state')
    manifest = decode((gen / '.manifest').read_bytes())
    seed = {}
    for name in ('FORMAT', 'registry', 'plan.json', 'recovery.json'):
        path = state / name
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 8192,
                'gateway artifact or state changed')
        seed[name] = path.read_bytes()
        require(sha(seed[name]) == manifest['state/' + name], 'gateway artifact or state changed')
    backend = gen / ENGINE
    require(backend.is_file() and not backend.is_symlink() and sha(backend.read_bytes()) == manifest[ENGINE],
            'legacy gateway backend changed')
    require(seed['FORMAT'] == (FORMAT + '\n').encode(), 'foreign state format')
    spec = lower(decode(seed['plan.json']))
    # A killed one-shot must not leave a half-written spec in the state inventory.
    with tempfile.TemporaryDirectory(dir='/tmp') as tmp:
        env = engine_env(tmp)
        args = [backend, action, '--state-dir', state]
        if action == 'apply':
            # External devices and peers belong to the operator, not this profile.
            require(Path('/sys/class/net/br-lan').exists() and subprocess.run(
                ['wg', 'show', 'wg0', 'peers'], env=env, capture_output=True,
                check=True).stdout.strip(), 'requires provisioned br-lan and WireGuard peer')
            path = Path(tmp) / 'spec.json'
            path.write_bytes(encode(spec))
            args += ['--spec', path]
        subprocess.run(args, cwd=tmp, env=env, check=True)


if __name__ == '__main__':
    try:
        require(len(sys.argv) == 2, 'usage: core apply|down')
        run(sys.argv[1])
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        sys.exit('lan gateway: ' + str(exc))
