"""Independent IPv4/IPv6 QUIC peer-family gate inside isolated netns only."""
import argparse
from pathlib import Path
import subprocess
from qcendpoint_test import line


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server",type=Path,required=True)
    parser.add_argument("--client",type=Path,required=True)
    args=parser.parse_args()
    assert Path("/proc/self/ns/net").stat().st_ino!=Path("/proc/1/ns/net").stat().st_ino, "isolated network namespace required"
    host=subprocess.Popen([str(args.server.resolve())],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        ready=line(host,3).split();assert len(ready)==2 and ready[0]=="PORT"
        for address in ("127.0.0.1:"+ready[1],"[::1]:"+ready[1]):
            subprocess.run([str(args.client.resolve()),address,"once"],check=True,timeout=5)
        host.stdin.write("stats\n");host.stdin.flush();assert line(host,3)=="STATS 1 1 0"
        host.stdin.write("quit\n");host.stdin.flush();assert host.wait(timeout=3)==0
        print("PASS explicit V6ONLY: IPv4/IPv6 wildcard endpoints share UDP port; genuine source families preserved; exact stream/datagram echoes")
    finally:
        if host.poll() is None:host.kill();host.wait(timeout=3)
        for stream in (host.stdin,host.stdout,host.stderr):stream.close()


if __name__=="__main__":main()
