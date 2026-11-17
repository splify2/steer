#!/bin/sh
# OLD_LIBS is a separately compiled frozen baseline, never current headers.
set -eu
cd "$(dirname "$0")/.."
. build/sources.sh
OLD="${OLD_LIBS:?set OLD_LIBS to a frozen baseline distribution}"
NEW="${NEW_LIBS:?set NEW_LIBS to the candidate distribution}"
OLD="$(realpath "$OLD")"; NEW="$(realpath "$NEW")"
old_path="$OLD/plugins/net1/lib:$OLD"
new_path="$NEW/plugins/net1/lib:$NEW"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT INT TERM
for name in $(profile_var PLUGINS_NET1); do
    binary="$OLD/plugins/$name/bin/$name"
    [ -x "$binary" ] || { echo "missing baseline program: $name"; exit 1; }
    sha256sum "$binary" > "$work/before"
    LD_BIND_NOW=1 STEER_LIB_PROBE=1 LD_LIBRARY_PATH="$old_path" "$binary" > "$work/old" 2>&1
    LD_BIND_NOW=1 STEER_LIB_PROBE=1 LD_LIBRARY_PATH="$new_path" "$binary" > "$work/new" 2>&1
    sha256sum "$binary" > "$work/after"
    cmp "$work/before" "$work/after"
    grep -q 'подходит' "$work/old"; grep -q 'подходит' "$work/new"
    echo "PASS frozen $name: old and candidate provider, unchanged binary"
done
for name in vless hysteria2; do
    nm -D -u "$OLD/plugins/$name/bin/$name" | grep -Eq 's2p_(pool_run|stack_run)@'
    if nm -D -u "$OLD/plugins/$name/bin/$name" | grep -Eq 's2p_(pool_run|stack_run)_ex'; then
        echo "baseline $name unexpectedly uses new entrypoint"; exit 1
    fi
done
for name in $(profile_var PLUGINS_NET1); do
    binary="$NEW/plugins/$name/bin/$name"
    LD_BIND_NOW=1 STEER_LIB_PROBE=1 LD_LIBRARY_PATH="$new_path" "$binary" > "$work/new" 2>&1
    if LD_BIND_NOW=1 STEER_LIB_PROBE=1 LD_LIBRARY_PATH="$old_path" "$binary" > "$work/reject" 2>&1; then
        echo "candidate $name incorrectly accepted old provider"; exit 1
    fi
    echo "PASS candidate $name: new provider accepted, old provider rejected"
done
nm -D -u "$NEW/plugins/vless/bin/vless" | grep -q 's2p_pool_run_ex@'
nm -D -u "$NEW/plugins/hysteria2/bin/hysteria2" | grep -q 's2p_stack_run_ex@'
echo "PASS real VLESS/HY2 module entries import the explicit flow extension path"
