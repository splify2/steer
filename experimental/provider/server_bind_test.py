"""Root-only disposable netns gate for explicit IPv4/IPv6 server listeners."""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve()
sys.path.insert(0, str(HERE.parents[3] / 'steer-ui' / 'tests'))
from core_integration import child, wait_socket, port, echo, require


def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def main():
    binary = str(Path(sys.argv[1]).resolve(strict=True))
    if os.environ.get('STEER_BIND_NS') != '1':
        if os.geteuid() != 0:
            raise SystemExit('root required for isolated namespace test')
        env = dict(os.environ, STEER_BIND_NS='1')
        raise SystemExit(subprocess.run(['unshare', '-n', sys.executable, str(HERE), binary], env=env).returncode)
    run('ip', 'link', 'set', 'lo', 'up')
    with child(['unshare', '-n', 'sleep', '60']) as peer:
        time.sleep(0.1)
        enter = ['nsenter', '-t', str(peer.pid), '-n']
        run('ip', 'link', 'add', 'servernet', 'type', 'veth', 'peer', 'name', 'clientnet')
        run('ip', 'link', 'set', 'clientnet', 'netns', str(peer.pid))
        for prefix, device, ipv4, ipv6 in (([], 'servernet', '192.0.2.1/24', '2001:db8::1/64'),
                                          (enter, 'clientnet', '192.0.2.2/24', '2001:db8::2/64')):
            run(*prefix, 'ip', 'link', 'set', 'lo', 'up')
            run(*prefix, 'ip', 'addr', 'add', ipv4, 'dev', device)
            run(*prefix, 'ip', '-6', 'addr', 'add', ipv6, 'dev', device, 'nodad')
            run(*prefix, 'ip', 'link', 'set', device, 'up')
        listener_port = port()
        config = {'prototype': 'steer-linux-v1', 'listeners': [
            {'id': name, 'protocol': 'socks', 'listen': {'address': address, 'port': listener_port},
             'auth': {'type': 'none'}} for name, address in [('ipv4', '0.0.0.0'), ('ipv6', '::')]],
                  'routing': {'default': 'direct', 'rules': []}}
        with tempfile.TemporaryDirectory(prefix='steer-server-bind-') as temp:
            directory = Path(temp)
            source, control = directory / 'config.json', directory / 'control.sock'
            source.write_text(json.dumps(config))
            with child([binary, '--config', str(source), '--control', str(control)]) as core:
                wait_socket(control, core)
                with echo('127.0.0.1') as target:
                    client = '''import socket,struct,sys
def exact(s,n):
 data=b''
 while len(data)<n:
  chunk=s.recv(n-len(data))
  assert chunk,'unexpected EOF'
  data+=chunk
 return data
with socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=3) as s:
 s.sendall(b'\\x05\\x01\\x00');assert exact(s,2)==b'\\x05\\x00'
 s.sendall(b'\\x05\\x01\\x00\\x01\\x7f\\x00\\x00\\x01'+struct.pack('!H',int(sys.argv[3])))
 h=exact(s,4);assert h[:3]==b'\\x05\\x00\\x00';exact(s,6 if h[3]==1 else 18)
 payload=bytes(range(256))*4;s.sendall(payload);assert exact(s,len(payload))==payload
 s.shutdown(socket.SHUT_WR);assert s.recv(1)==b''
'''
                    for address in ('192.0.2.1', '2001:db8::1'):
                        subprocess.run(enter + [sys.executable, '-c', client, address, str(listener_port),
                                               str(target[0])], check=True, timeout=10)
                        require(core.poll() is None, 'core died during external flow')
                        print('PASS separate client namespace to wildcard listener via', address)
    print('PASS IPv4 and IPv6 share a port with separate listener ownership; namespaces cleaned')


if __name__ == '__main__':
    main()
