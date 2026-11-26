#!/usr/bin/env python3
"""Offline, read-only Gate E inventory for a narrowly supported v2 subset.

This is deliberately a preflight, not a v2->v3 converter or installer.
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys


SCHEMA = "steer.gate-e.preflight.v1"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as src:
        for chunk in iter(lambda: src.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


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
    if not os.path.isfile(spec):
        parser.error("--spec must name an existing file")

    before = sha256(spec)
    # The existing CLI parser/converter is authoritative for v2 syntax. JSON is
    # also parsed from the original bytes below: spec convert normalizes defaults
    # and can omit explicit default-valued fields, so its output is not a safe
    # source for a lossless inventory. YAML is rejected until exact source-level
    # inspection is available. An empty PATH rules out helpers/fetchers.
    env = dict(os.environ)
    env["PATH"] = ""
    version_run = subprocess.run(
        [steer, "--version"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, env=env, check=False,
    )
    cli_version = version_run.stdout.strip() if version_run.returncode == 0 else "unknown"
    parsed = subprocess.run(
        [steer, "spec", "convert", "--json", "--spec", spec],
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, env=env,
        check=False,
    )
    after = sha256(spec)
    report = {
        "schema": SCHEMA,
        "tool_version": cli_version,
        "source_sha256": before,
        "input_unchanged": before == after,
        "preflight_only": True,
        "conversion_performed": False,
    }
    if before != after:
        report.update(status="rejected", supported_semantics=[],
                      blocking_semantics=[{"code": "input_changed", "semantic": "source"}])
        print(json.dumps(report, sort_keys=True))
        return 2
    if parsed.returncode != 0:
        report.update(status="rejected", supported_semantics=[],
                      blocking_semantics=[{"code": "legacy_parser_rejected", "semantic": "document"}])
        print(json.dumps(report, sort_keys=True))
        return 2
    try:
        effective = json.loads(parsed.stdout)
        with open(spec, "rb") as src:
            raw = src.read()
        stripped = raw.lstrip()
        if not stripped.startswith(b"{"):
            report.update(status="rejected", supported_semantics=[],
                          blocking_semantics=[{"code": "source_format_not_exactly_inspectable",
                                               "semantic": "document"}])
            print(json.dumps(report, sort_keys=True))
            return 2
        doc = json.loads(raw)
    except (TypeError, ValueError):
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
