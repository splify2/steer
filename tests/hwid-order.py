"""Run: python3 tests/hwid-order.py build/steer (Linux tmpfs, no host identifiers)."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

binary = Path(sys.argv[1]).resolve(strict=True)
physical = dict(eth10='10:00:00:00:00:10', eth2='10:00:00:00:00:02',
                lan0='10:00:00:00:00:aa', wan0='10:00:00:00:00:bb',
                eno1='10:00:00:00:00:cc')
virtual = [f'veth{i:03d}' for i in range(70)]
ports = [f'eth9{i:02d}' for i in range(70)]
physical.update({name: f'10:00:00:00:01:{i:02x}' for i, name in enumerate(ports)})


def ids(name):
    if name is None:
        return '', ''
    mac = physical[name].encode()
    return ('splify2-' + hashlib.sha256(b'splify2:' + mac).hexdigest()[:20],
            'sp-' + hashlib.pbkdf2_hmac('sha256', b'splify2-telemetry:' + mac,
                                        b'splify2-telemetry-id/1', 600000, 16).hex())


def case(label, order, best, old):
    with tempfile.TemporaryDirectory(dir='/dev/shm', prefix='hwid-order-') as tmp:
        net = Path(tmp) / 'net'
        net.mkdir()
        # Linux tmpfs enumerates in reverse creation order. Verify the actual
        # cutoff rather than assuming that creation order is readdir order.
        for name in reversed(order):
            port = net / name
            port.mkdir()
            (port / 'address').write_text(physical.get(name, '10:00:00:00:00:ff') + '\n')
            if name in physical:
                (port / 'device').touch()
        first = set(os.listdir(net)[:64])
        priority = ['eth10', 'eth2', *ports, 'lan0', 'wan0', 'eno1']
        assert next((n for n in priority if n in first), None) == old, 'fixture order'
        env = dict(PATH=os.defpath, STEER_SYSNET=str(net), STEER_SYSINFO_MODEL=tmp+'/model',
                   STEER_OPENWRT_RELEASE=tmp+'/release', STEER_SOCKET=tmp+'/no.sock')
        actual = tuple(json.loads(subprocess.check_output([binary, cmd], env=env))[key]
                       for cmd, key in [('sub-hwid', 'hwid'), ('dev-id', 'tid')])
        print(f'{label}: first64={old} expected={best} hwid={actual[0]!r} tid={actual[1]!r}')
        return actual == ids(best)


base_ports = ['eth10', 'eth2', 'lan0', 'wan0', 'eno1']
good = all([
    case('preferred first', [*base_ports, *virtual], 'eth10', 'eth10'),
    case('other first', ['lan0', *virtual, 'eth2', 'wan0', 'eno1', 'eth10'], 'eth10', 'lan0'),
    case('physical late', [*virtual, *base_ports], 'eth10', None),
    case('many eligible', [*ports, 'eth10'], 'eth10', ports[0]),
    case('64 names', [*virtual[:59], *reversed(base_ports)], 'eth10', 'eth10'),
    case('lan before wan and other', ['eno1', 'wan0', 'lan0'], 'lan0', 'lan0'),
    case('wan before other', ['eno1', 'wan0'], 'wan0', 'wan0'),
    case('other physical', ['eno1'], 'eno1', 'eno1'),
    case('all virtual', virtual, None, None),
])
sys.exit(0 if good else 1)
