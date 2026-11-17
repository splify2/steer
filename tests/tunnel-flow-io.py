#!/usr/bin/env python3
"""Real TCP lifecycle checks; invoked inside the task-owned network namespace."""
import concurrent.futures, hashlib, os, socket, struct, sys, threading, time
DATA = bytes((i * 17 + i // 251) % 256 for i in range(393216))
TARGET = "203.0.113.81"
errors, completed = [], []
lock = threading.Lock()
def receive(s):
    out = bytearray()
    while True:
        chunk = s.recv(16384)
        if not chunk: return bytes(out)
        out.extend(chunk)
def serve_one(s, mode):
    try:
        s.settimeout(18)
        if mode == 19001:
            assert receive(s) == DATA[:65536]
            time.sleep(5.3)
            s.sendall(DATA[:65536]); s.shutdown(socket.SHUT_WR)
        elif mode == 19002:
            s.sendall(b"ready"); s.shutdown(socket.SHUT_WR)
            assert receive(s) == DATA
        elif mode == 19003:
            s.sendall(DATA); s.shutdown(socket.SHUT_WR)
            assert receive(s) == b""
        elif mode == 19004:
            request = receive(s); s.sendall(request); s.shutdown(socket.SHUT_WR)
        elif mode == 19006:
            assert receive(s) == b""
            s.sendall(b"empty-request-response"); s.shutdown(socket.SHUT_WR)
        else:
            s.sendall(b"before-reset")
            s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        with lock: completed.append(mode)
    except Exception as e:
        with lock: errors.append((mode, repr(e)))
    finally: s.close()
def accept_loop(listener, mode):
    while True:
        try: s, _ = listener.accept()
        except OSError: return
        threading.Thread(target=serve_one, args=(s,mode), daemon=True).start()
listeners=[]
for port in range(19001,19007):
    s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    s.bind(("127.0.0.2",port)); s.listen(64); listeners.append(s)
    threading.Thread(target=accept_loop,args=(s,port),daemon=True).start()
def client(mode, index=0, target=TARGET):
    with socket.create_connection((target,mode),timeout=18) as s:
        s.settimeout(18)
        if mode == 19001:
            start=time.monotonic(); s.sendall(DATA[:65536]); s.shutdown(socket.SHUT_WR)
            assert receive(s)==DATA[:65536]
            assert time.monotonic()-start>5
        elif mode == 19002:
            assert receive(s)==b"ready"
            s.sendall(DATA); s.shutdown(socket.SHUT_WR)
        elif mode == 19003:
            start=time.monotonic(); out=bytearray()
            while True:
                chunk=s.recv(4096)
                if not chunk: break
                out.extend(chunk); time.sleep(.075)
            assert time.monotonic()-start>5
            assert hashlib.sha256(out).digest()==hashlib.sha256(DATA).digest()
            s.shutdown(socket.SHUT_WR)
        elif mode == 19004:
            request=("flow-%d:"%index).encode()+DATA[:4096]
            s.sendall(request); s.shutdown(socket.SHUT_WR); assert receive(s)==request
        elif mode == 19006:
            s.shutdown(socket.SHUT_WR)
            assert receive(s) == b"empty-request-response"
        else:
            reset=False
            try: receive(s)
            except ConnectionResetError: reset=True
            assert reset, "reset was misreported as clean EOF"
with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
    futures=[pool.submit(client,p) for p in (19001,19002,19003,19005,19006)]
    futures += [pool.submit(client,19004,i) for i in range(32)]
    for f in futures: f.result(timeout=24)
# Actual nft GETSETELEM mappings and the immutable file fallback, both families.
for i, target in enumerate(("198.18.0.1", "198.18.0.2", "fdfe:dcba:9876::c612:1", "fdfe:dcba:9876::c612:2")):
    client(19004, 100+i, target)
# A non-regular state source must never block the dataplane. An older worker-side
# fopen on this FIFO hangs; the new refresh thread rejects it without opening IO.
os.unlink(sys.argv[1]); os.mkfifo(sys.argv[1]); os.utime(sys.argv[1], (time.time()+10, time.time()+10))
def missing(i):
    try:
        with socket.create_connection(("198.18.0.99",19004),timeout=3) as s:
            s.settimeout(3); s.sendall(b"missing"); receive(s)
    except (ConnectionResetError, BrokenPipeError): return
    raise AssertionError("unresolved Fake-IP was accepted")
with concurrent.futures.ThreadPoolExecutor(max_workers=72) as pool:
    missing_flows=[pool.submit(missing,i) for i in range(64)]
    time.sleep(.02)
    start=time.monotonic()
    ordinary=[pool.submit(client,19004,200+i) for i in range(8)]
    for f in ordinary: f.result(timeout=2)
    assert time.monotonic()-start<1.5, "Fake-IP admissions starved numeric TCP"
    for f in missing_flows: f.result(timeout=4)
deadline=time.monotonic()+3
while len(completed)<49 and not errors and time.monotonic()<deadline: time.sleep(.01)
assert not errors, errors
assert len(completed)==49, completed
print("PASS: 49 real TCP flows +64 missing Fake-IP admissions; >5s FIN response, receiver-first upload, slow exact checksum, reset and cross-flow isolation")
