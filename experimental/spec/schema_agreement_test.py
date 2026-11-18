#!/usr/bin/env python3
"""Compare handwritten C validation with the SDK DNS and ingress schemas."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from jsonschema import Draft202012Validator

schema = json.loads((Path(__file__).resolve().parents[3] / "plugin-sdk/schema/draft/spec-v3-dns-settings.schema.json").read_text())
settings_validator = Draft202012Validator(schema)
options_validator = Draft202012Validator({"$ref": "#/$defs/resolve_rule_options", "$defs": schema["$defs"]})
base = {"version": 3, "plugin_remotes": {}, "plugins": {}, "inbounds": {},
        "outbounds": {"direct": {"type": "direct"}}, "routing": {"default": "direct", "rules": []},
        "dns": {"servers": {"local": {"type": "local"}}, "default": "local", "rules": []}}
minimum_schema = json.loads((Path(__file__).resolve().parents[3] / "plugin-sdk/schema/draft/spec-v3.schema.json").read_text())
minimum_validator = Draft202012Validator(minimum_schema)
assert not minimum_validator.is_valid(base)  # full DNS stays outside minimum scope
count = 0

with tempfile.TemporaryDirectory(prefix="steer-spec-dns-") as directory:
    path = Path(directory) / "case.json"

    def compile_intent(document):
        path.write_text(json.dumps(document))
        result = subprocess.run([sys.argv[1], str(path)], capture_output=True, text=True, timeout=5)
        assert result.returncode in (65, 78), (result.returncode, result.stderr)
        observed = json.loads(result.stdout)
        assert not observed["runtime_ready"]  # no executor inventory is forged
        return observed

    def agree(value, rule=False):
        global count
        document = copy.deepcopy(base)
        if rule:
            document["dns"]["rules"] = [{"name": "r", "match": {}, "server": "local", **value}]
        else:
            document["dns"].update(value)
        expected = (options_validator if rule else settings_validator).is_valid(value)
        observed = compile_intent(document)
        assert observed["syntax_valid"] == expected, (value, expected, observed)
        count += 1

    for value in ["ipv4_only", "ipv6_only", "prefer_ipv4", "prefer_ipv6", "unknown", {}, True, 1]:
        agree({"strategy": value})
        agree({"strategy": value}, rule=True)
    for value in [True, False, {}, "true", 1, None]:
        agree({"reverse_mapping": value})
    for value in [0, 1, 131072, 131073, -1, "1024", {}, {"capacity": 1024},
                  {"capacity": 1024, "persistent": True}, {"capacity": 0, "persistent": False},
                  {"capacity": 1, "persistent": {}}, {"capacity": 1, "unknown": 1}]:
        agree({"cache": value})
    for unit, bound in [("ms", 604800000), ("s", 604800), ("m", 10080), ("h", 168)]:
        for number in [0, 1, bound - 1, bound, bound + 1, 999999999999999999999]:
            agree({"cache_timeout": str(number) + unit}, rule=True)
    for value in [{}, 1, None, "1.5s", "-1s", "1d", "1S", "1s\n", "000168h", "0000000000ms"]:
        agree({"cache_timeout": value}, rule=True)

    print(f"C/SDK DNS settings agreement: {count} cases PASS")

    ingress = {k: v for k, v in base.items() if k != "dns"}
    ingress["plugin_remotes"] = {"local": {"url": "https://example.invalid", "trust": "local"}}
    ingress["plugins"] = {"main": {"remote": "local", "package": "protocols", "version": "0.0.0"}}
    ingress["outbounds"] = {"deny": {"type": "block", "flow": ["stream", "datagram", "device"]}}
    ingress["routing"] = {"default": "deny", "rules": [
        {"name": "private", "match": {"inbound": ["vpn"]}, "outbound": "deny"},
    ]}
    device = {"flow": ["device"], "device": {"name": "gateway"}}
    listen = {"listen": {"address": "127.0.0.1", "port": 51820}}
    cases = [
        (listen, True),
        ({**listen, "flow": ["datagram", "stream"]}, True),
        (device, True),
        ({**device, "variant": "kernel"}, True),
        ({**device, "device": {"name": "n" * 63}}, True),
        ({**device, "device": {"name": "n" * 64}}, False),
        ({"flow": ["device"]}, False),
        ({"device": device["device"]}, False),
        ({**device, **listen}, False),
        ({**device, "flow": ["device", "stream"]}, False),
        ({**device, "flow": ["device", "device"]}, False),
        ({**device, "flow": ["datagram"]}, False),
        ({**device, "flow": "device"}, False),
        ({**device, "device": {"name": "bad/name"}}, False),
        ({**device, "device": {"name": "gateway", "index": 7}}, False),
        ({**device, "transport": {"type": "udp"}}, False),
        ({**device, "security": {"type": "none"}}, False),
    ]
    for fields, expected in cases:
        ingress["inbounds"] = {"vpn": {"plugin": "wireguard:main", "options": {}, **fields}}
        assert minimum_validator.is_valid(ingress) == expected, fields
        observed = compile_intent(ingress)
        assert observed["syntax_valid"] == expected, (fields, observed)
        if expected:
            assert observed["topology_valid"], (fields, observed)
    print(f"C/SDK ingress agreement: {len(cases)} cases PASS")
