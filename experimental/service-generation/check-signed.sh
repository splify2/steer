#!/bin/sh
# UI checkout at 6195d89 with sibling steer and plugin-sdk, s2p, steerd libs.
set -eu
test_script=check_signed.py
compat=
old=
musl=
if [ "$#" != 3 ]; then
    case "$4:$#" in
        --native-supd:5) compat=$(realpath "$5"); test_script=check_native.py ;;
        --exact-remove:6) compat=$(realpath "$5"); old=$(realpath "$6"); test_script=check_remove.py ;;
        --first-install:4) test_script=check_first.py ;;
        --first-install-musl:5) test_script=check_first.py; musl=$(realpath "$5") ;;
        *) exit 2 ;;
    esac
fi
ui=$(realpath "$1")
test "$(git -C "$ui" rev-parse HEAD)" = 6195d89589f347c15538c64fb2179cafdd9f7225
test -z "$(git -C "$ui" status --porcelain --untracked-files=no)"
src=$(cd "$(dirname "$0")" && pwd)
exec unshare -mpnf --mount-proc --propagation private sh -ec '
    umask 022
    mount -t tmpfs tmpfs /run
    mkdir -m 755 /run/e4 /run/e4/feed
    cd /run/e4
    make -s -C "$1" BUILD=/run/e4/build NANO=0 LDFLAGS=-static service-host
    mkdir -p pkg/bin pkg/licenses
    cp build/steer-ui-service pkg/bin/
    sha256sum pkg/bin/steer-ui-service | cut -d" " -f1 > host.sha256
    cp -R "$1/assets" "$1/LICENSE" "$1/experimental/linux-s2p/plugin.json" pkg/
    cp "$1/../steer/src/third_party/libyaml/LICENSE" pkg/licenses/libyaml.txt
    cp "$2" s2p
    cp "$3"/steerd "$3"/libsteer*.so.* "$4"/controller.py "$4"/signed.py "$4"/check_signed.py .
    if [ "$5" = check_native.py ]; then
        cp "$4"/native_manager.py "$4"/check_native.py .
        cp "$6" steerd-compatible
        if cmp -s steerd steerd-compatible; then echo "expected a distinct compatible build" >&2; exit 2; fi
    fi
    if [ "$5" = check_remove.py ]; then
        cp "$4"/native_manager.py "$4"/check_remove.py .
        mkdir prior v214
        cp "$6"/steerd "$6"/libsteer*.so.* prior/
        cp "$7"/steerd "$7"/libsteer*.so.* v214/
        cc -Wall -Wextra -Werror -shared -fPIC "$4/remove-cut.c" -o cut.so
    fi
    if [ "$5" = check_first.py ]; then
        cp "$4/check_first.py" .
        cc -Wall -Wextra -Werror -shared -fPIC -nostdlib "$4/first-cut.c" -o first-cut.so
        if [ -n "$8" ]; then
            # Mount-private loader at PT_INTERP of the unchanged delivery ELF.
            lib=$(realpath /lib)
            mkdir upper work
            mount -t overlay overlay -o "lowerdir=$lib,upperdir=$PWD/upper,workdir=$PWD/work" "$lib"
            cp --remove-destination "$8" "$lib/ld-musl-x86_64.so.1"
        fi
    fi
    for d in /etc /var /tmp; do mount -t tmpfs tmpfs "$d"; done
    chmod 1777 /tmp
    ip link set lo up
    ldconfig -X -f /dev/null /run/e4
    if [ -n "$8" ]; then echo /run/e4 >/etc/ld-musl-x86_64.path; fi
    fixtures=fixtures
    if [ "$5" = check_first.py ]; then fixtures=first-fixtures; fi
    python3 -B check_signed.py "$fixtures"
    rm -r build pkg
    exec setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs \
        env -i PATH=/usr/bin:/bin HOME=/tmp python3 -Bu "$5"
' sh "$ui" "$(realpath "$2")" "$(realpath "$3")" "$src" "$test_script" "$compat" "$old" "$musl"
