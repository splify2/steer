#!/bin/sh
# Executed only by the disposable guest's systemd. No host unit is installed.
set -eu
grep -qw gate_e_guest=1 /proc/cmdline
test "$(cat /proc/1/comm)" = systemd
test "$(ls /sys/class/net)" = lo
export PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=/lab PYTHONDONTWRITEBYTECODE=1
outer=$(readlink /proc/self/ns/pid)
exec unshare --mount --net --pid --fork --kill-child --mount-proc --propagation private \
  sh -c '"$@"; exit $?' init \
  unshare --mount --net --fork --propagation private sh -eu -c '
    for path in /etc /run /var /tmp; do mount -t tmpfs tmpfs "$path"; done
    ln -s /run /var/run
    printf "%s\n" "$1" > /run/steer-lab.outer-pidns
    mount -t sysfs sysfs /sys
    umask 077
    python3 -B /lab/src/tests/gate-e-guest/guest.py provision
    case " $(cat /proc/cmdline) " in
      *" gate_e_cut="*)
        python3 -B /lab/src/tests/gate-e-guest/cut_guest.py tripwire
        ip netns exec client python3 -B /lab/src/tests/gate-e-guest/cut_guest.py traffic &
        ;;
    esac
    set -- serve
    case " $(cat /proc/cmdline) " in
      *" gate_e_cut=recover-running "*) set -- recover selected ;;
      *" gate_e_cut=recover-starting "*) set -- recover previous ;;
    esac
    if [ "$1" = recover ]; then
        python3 -B /lab/src/tests/gate-e-guest/cut_guest.py admit "$2"
    fi
    exec python3 -B /lab/src/experimental/offline-bundle/lan_service.py --prefix /lab/prefix "$@"
  ' sh "$outer"
