#!/usr/bin/env python3
"""Offline regression: real CLI, fake v1 Unix socket and an exec spy."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

client = os.path.abspath(sys.argv[1])
with tempfile.TemporaryDirectory(prefix='steer-cli-') as tmp:
    p = pathlib.Path(tmp)
    spec, state, sock, spy, calls = (p / n for n in ('spec.json', 'state', 's', 'spy', 'calls'))
    state.mkdir()
    spec.write_text('x' * 1000000)
    spy.write_text('#!/bin/sh\necho invoked >> "$SPY_CALLS"\nexit 42\n')
    spy.chmod(0o755)
    env = dict(os.environ, STEER_SOCKET=str(sock), STEER_ENGINE=str(spy), SPY_CALLS=str(calls))
    def invoke(cmd):
        return subprocess.run([client, cmd, '--spec', str(spec), '--state-dir', str(state)],
                              env=env, capture_output=True, timeout=30)
    def run(mode, command='apply'):
        calls.unlink(missing_ok=True)
        server = socket.socket(socket.AF_UNIX)
        server.bind(str(sock)); server.listen(8)
        seen = []
        def serve():
            try:
                conn, _ = server.accept()
                with conn:
                    assert conn.recv(1024) == b'version\n'
                    conn.sendall((json.dumps(dict(spec_path=str(spec), state_dir=str(state)))+'\n').encode())
                if mode == 'preconnect':
                    server.close(); return
                for _ in range(101 if mode.startswith('busy') else 1):
                    conn, _ = server.accept()
                    with conn:
                        if mode == 'partial':
                            seen.append(conn.recv(32)); continue
                        data = b''
                        while b'\n' not in data:
                            part = conn.recv(4096)
                            if not part: break
                            data += part
                        line, _, body = data.partition(b'\n')
                        if line.startswith(b'apply '):
                            n = int(line.split()[1])
                            while len(body) < n:
                                part = conn.recv(min(65536, n-len(body)))
                                if not part: break
                                body += part
                            assert len(body) == n
                        seen.append(line)
                        if mode == 'invalid': conn.sendall(b'{"code":0,}\n')
                        elif mode == 'nocode': conn.sendall(b'{"error":"internal"}\n')
                        elif mode.startswith('busy'):
                            conn.sendall((b'{"error":"busy","code":"ctl.busy"}\n' if mode == 'busy-string' else b'{"error":"busy"}\n'))
                        elif mode == 'ok': conn.sendall(b'{"code":0,"stdout":"ok"}\n')
            except (BrokenPipeError, ConnectionResetError):
                pass
        thread = threading.Thread(target=serve, daemon=True); thread.start()
        result = invoke(command)
        thread.join(3); server.close(); sock.unlink(missing_ok=True)
        assert not thread.is_alive(), mode
        return result, len(seen), calls.exists()
    r = invoke('apply'); assert r.returncode == 42 and calls.exists(), ('offline', r)
    for mode in ('drop', 'invalid', 'nocode', 'partial'):
        r, n, fallback = run(mode)
        assert r.returncode == 4 and n == 1 and not fallback and 'неизвест' in r.stderr.decode(), (mode, r, n, fallback)
    r, n, fallback = run('preconnect'); assert r.returncode == 42 and not n and fallback
    r, n, fallback = run('drop', 'status'); assert r.returncode == 42 and n == 1 and fallback
    r, n, fallback = run('nocode', 'status'); assert r.returncode == 42 and n == 1 and fallback
    r, n, fallback = run('ok', 'status'); assert r.returncode == 0 and n == 1 and not fallback and r.stdout == b'ok'
    r, n, fallback = run('ok'); assert r.returncode == 0 and n == 1 and not fallback and r.stdout == b'ok'
    for mode in ('busy', 'busy-string'):
        r, n, fallback = run(mode)
        assert r.returncode != 0 and r.returncode != 4 and n == 101 and not fallback and 'занят' in r.stderr.decode(), (mode, r, n, fallback)
print('client delivery: OK')
