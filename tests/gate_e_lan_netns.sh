#!/bin/sh
# Private PID 1 remains outside the inner router (also lets core reject host use).
set -eu
worker=gate_e_lan_netns.py
if [ "${1:-}" = --service ]; then worker=gate_e_lan_service.py; shift; fi
test "$#" -eq 2 || { echo "usage: sh $0 [--service] V2_1_4_STEERD CANDIDATE_LEGACY_STEERD" >&2; exit 2; }
root=$(cd "$(dirname "$0")/.." && pwd)
outer_pidns=$(readlink /proc/self/ns/pid)
exec unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private \
  sh -c '"$@"; exit $?' init \
  unshare --mount --net --fork --propagation private sh -eu -c '
    test "$(readlink /proc/self/ns/net)" != "$(readlink /proc/1/ns/net)"
    test "$(readlink /proc/self/ns/pid)" != "$5"
    mount -t tmpfs tmpfs /mnt
    mkdir /mnt/src
    mount --bind "$1" /mnt/src
    mount -o remount,bind,ro /mnt/src
    cp -- "$2" /mnt/old
    cp -- "$3" /mnt/backend
    cd /mnt
    for path in /etc /run /var /tmp; do mount -t tmpfs tmpfs "$path"; done
    printf "%s\n" "$5" > /run/steer-lab.outer-pidns
    ln -s /run /var/run
    mount -t sysfs sysfs /sys
    exec env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LC_ALL=C HOME=/mnt \
        python3 -B "/mnt/src/tests/$4"
  ' sh "$root" "$(realpath "$1")" "$(realpath "$2")" "$worker" "$outer_pidns"
