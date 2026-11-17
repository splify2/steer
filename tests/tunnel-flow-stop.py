#!/usr/bin/env python3
"""Hold accepted Fake-IP admissions across the worker shutdown barrier."""
import os, socket, sys, time
connections=[]
for i in range(64):
    s=socket.create_connection(("198.18.0.99",19004),timeout=3)
    s.settimeout(4); s.sendall(b"pending")
    connections.append(s)
with open(sys.argv[1],"w") as f: f.write("ready")
# TUN removal also removes the client source address: reset delivery cannot
# establish fd ownership afterwards. Wait for the process join barrier instead.
deadline=time.monotonic()+5
while not os.path.exists(sys.argv[1]+".stopped") and time.monotonic()<deadline: time.sleep(.01)
assert os.path.exists(sys.argv[1]+".stopped"), "host did not finish its worker barrier"
for s in connections: s.close()
print("PASS: shutdown completed while client admissions remained open")
