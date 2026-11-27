#!/bin/sh
# From the repository root. Compatible host build: steer, steerd, pkhooks.
set -eu
case ${2:-} in supdmatch|supervisematch) ;; *) exit 2 ;; esac
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    mount -t tmpfs tmpfs /run
    mkdir /run/core /run/bin
    mount --bind . /run/core
    mount -o remount,bind,ro /run/core
    cp "$1"/steer "$1"/steerd "$1"/pkhooks /run/bin/
    cp -L "$(command -v awk)" /run/bin/awk
    cd /run/core
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    export PATH="/run/bin:$PATH" STEER=/run/bin/steer SUPD_INNER=1
    exec sh "tests/$2.sh"
' sh "$(realpath "$1")" "$2"
