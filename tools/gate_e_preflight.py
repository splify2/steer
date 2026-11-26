#!/usr/bin/env python3
"""Offline, read-only Gate E inventory for a narrowly supported v2 subset.

This is deliberately a preflight, not a v2->v3 converter or installer.
"""

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
import tempfile


SCHEMA = "steer.gate-e.preflight.v1"
MAX_SOURCE_BYTES = 16 * 1024 * 1024


class SourceError(Exception):
    pass


def signature(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_nlink, st.st_uid, st.st_gid,
            st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def source_snapshot(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        raise SourceError("source_unavailable") from None
    try:
        try:
            before = os.fstat(fd)
        except OSError:
            raise SourceError("source_unavailable") from None
        if not stat.S_ISREG(before.st_mode):
            raise SourceError("source_not_regular")
        if before.st_size > MAX_SOURCE_BYTES:
            raise SourceError("source_too_large")
        chunks = []
        size = 0
        try:
            while True:
                chunk = os.read(fd, min(1024 * 1024, MAX_SOURCE_BYTES + 1 - size))
                if not chunk:
                    break
                chunks.append(chunk)
                size += len(chunk)
                if size > MAX_SOURCE_BYTES:
                    raise SourceError("source_too_large")
            data = b"".join(chunks)
            after = os.fstat(fd)
        except OSError:
            raise SourceError("source_unavailable") from None
        if signature(before) != signature(after):
            raise SourceError("source_changed")
        return data, signature(after)
    finally:
        try:
            os.close(fd)
        except OSError:
            pass


def source_still_matches(path, expected):
    try:
        current = os.stat(path, follow_symlinks=False)
    except OSError:
        return False
    return stat.S_ISREG(current.st_mode) and signature(current) == expected


def block(blockers, code, semantic):
    blockers.add((code, semantic))


def inventory(doc, effective):
    supported = set()
    blockers = set()
    if not isinstance(doc, dict):
        block(blockers, "not_object", "document")
        return supported, blockers

    supported.add("legacy_v2_schema")
    # `spec convert` resolves the legacy default LAN even when the source does
    # not spell it out. It is a packet-capture selector, never a loopback SOCKS
    # inbound. An explicit selector is equally non-transferable.
    if "lan" in doc:
        block(blockers, "legacy_capture_not_equivalent", "lan_capture")
    elif isinstance(effective, dict) and effective.get("lan"):
        if set(doc) == {"version"}:
            # The v2 implicit LAN has no effect in a truly empty, no-route spec.
            supported.add("empty_no_route_intent")
        else:
            block(blockers, "legacy_capture_not_equivalent", "lan_capture")
    for key in doc:
        if key == "version":
            continue
        value = doc[key]
        if key == "lan":
            # Already classified against the target profile above.
            continue
        elif key == "outputs":
            if not isinstance(value, dict):
                block(blockers, "outputs_shape", "outputs")
                continue
            for output in value.values():
                if not isinstance(output, dict):
                    block(blockers, "output_shape", "outputs")
                    continue
                kind = output.get("kind")
                allowed = {
                    "direct": {"kind"},
                    "block": {"kind"},
                }.get(kind)
                if allowed is None or not set(output) <= allowed:
                    block(blockers, "output_semantics_unreviewed", "outputs")
                else:
                    supported.add("output_" + kind)
        elif key == "rules":
            if not isinstance(value, list):
                block(blockers, "rules_shape", "rules")
            elif value:
                # Legacy rules select captured LAN/client traffic. v3
                # linked-SOCKS rules select an inbound identity; `to: all`
                # is not an equivalent selector.
                block(blockers, "legacy_rule_selector_not_equivalent", "rules")
        elif key in ("clients", "lists", "dns", "from_default"):
            block(blockers, "semantic_requires_explicit_mapping", key)
        else:
            block(blockers, "unknown_semantic", "other")
    return supported, blockers


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--steer", required=True, help="absolute or relative path to the pinned steer CLI")
    parser.add_argument("--spec", required=True, help="legacy v2 spec to inspect")
    args = parser.parse_args()
    steer = os.path.abspath(args.steer)
    spec = os.path.abspath(args.spec)
    if not os.path.isfile(steer) or not os.access(steer, os.X_OK):
        parser.error("--steer must name an executable")
    try:
        raw, source_identity = source_snapshot(spec)
    except SourceError as exc:
        report = {
            "schema": SCHEMA,
            "tool_version": "unknown",
            "source_sha256": None,
            "input_unchanged": False,
            "preflight_only": True,
            "conversion_performed": False,
            "status": "rejected",
            "supported_semantics": [],
            "blocking_semantics": [{"code": str(exc), "semantic": "source"}],
        }
        print(json.dumps(report, sort_keys=True))
        return 2

    before = hashlib.sha256(raw).hexdigest()
    report = {
        "schema": SCHEMA,
        "source_sha256": before,
        "preflight_only": True,
        "conversion_performed": False,
    }

    # `spec convert --spec -` reads stdin as LOAD_HUMAN, so the trusted CLI
    # parses the exact bytes inventoried below without reopening the caller path.
    # This mode does not execute plugin hooks. Empty cwd and plugin roots also
    # prevent environment-dependent plugin discovery for unsupported inputs.
    try:
        with tempfile.TemporaryDirectory(prefix="gate-e-preflight-") as isolated:
            empty_dirs = {
                name: os.path.join(isolated, name)
                for name in ("cwd", "home", "tmp", "plugin-dir", "plugin-etc",
                             "plugin-seed", "plugin-panel", "plugins-root",
                             "plugins-etc")
            }
            for path in empty_dirs.values():
                os.mkdir(path, 0o700)
            env = {
                "PATH": "",
                "HOME": empty_dirs["home"],
                "TMPDIR": empty_dirs["tmp"],
                "LC_ALL": "C",
                "LANG": "C",
                "STEER_PLUGIN_DIR": empty_dirs["plugin-dir"],
                "STEER_PLUGIN_ETC": empty_dirs["plugin-etc"],
                "STEER_PLUGIN_SEED": empty_dirs["plugin-seed"],
                "STEER_PLUGIN_PANEL_DIR": empty_dirs["plugin-panel"],
                "STEER_PLUGINS_ROOT": empty_dirs["plugins-root"],
                "STEER_PLUGINS_ETC": empty_dirs["plugins-etc"],
                "STEER_PLUGIN_AUTO": "0",
            }
            version_run = subprocess.run(
                [steer, "--version"], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, text=True, env=env,
                cwd=empty_dirs["cwd"],
                check=False, timeout=30,
            )
            cli_version = version_run.stdout.strip() if version_run.returncode == 0 else "unknown"
            parsed = subprocess.run(
                [steer, "spec", "convert", "--json", "--spec", "-"],
                input=raw, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                env=env, cwd=empty_dirs["cwd"], check=False, timeout=30,
            )
    except (OSError, subprocess.TimeoutExpired):
        parsed = None
        cli_version = "unknown"

    report["tool_version"] = cli_version
    unchanged = source_still_matches(spec, source_identity)
    report["input_unchanged"] = unchanged
    if not unchanged:
        report.update(status="rejected", supported_semantics=[],
                      blocking_semantics=[{"code": "input_changed", "semantic": "source"}])
        print(json.dumps(report, sort_keys=True))
        return 2
    if parsed is None or parsed.returncode != 0:
        report.update(status="rejected", supported_semantics=[],
                      blocking_semantics=[{"code": "legacy_parser_rejected", "semantic": "document"}])
        print(json.dumps(report, sort_keys=True))
        return 2
    try:
        effective = json.loads(parsed.stdout)
        stripped = raw.lstrip()
        if not stripped.startswith(b"{"):
            report.update(status="rejected", supported_semantics=[],
                          blocking_semantics=[{"code": "source_format_not_exactly_inspectable",
                                               "semantic": "document"}])
            print(json.dumps(report, sort_keys=True))
            return 2
        doc = json.loads(raw)
    except (TypeError, ValueError, UnicodeError):
        report.update(status="rejected", supported_semantics=[],
                      blocking_semantics=[{"code": "source_json_invalid", "semantic": "document"}])
        print(json.dumps(report, sort_keys=True))
        return 2

    supported, blockers = inventory(doc, effective)
    report["supported_semantics"] = sorted(supported)
    report["blocking_semantics"] = [
        {"code": code, "semantic": semantic}
        for code, semantic in sorted(blockers)
    ]
    # Even an empty blocker set is not approval to install or a converted spec:
    # this first iteration inventories a conservative subset only.
    report["status"] = "blocked" if blockers else "preflight_subset"
    report["target_profile"] = "linked-socks-v1-loopback"
    print(json.dumps(report, sort_keys=True))
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
