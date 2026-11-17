#!/usr/bin/env python3
"""Compare handwritten C DNS setting validation with the SDK type fragment."""
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
assert not Draft202012Validator(minimum_schema).is_valid(base)  # full DNS stays outside minimum scope
count = 0

with tempfile.TemporaryDirectory(prefix="steer-spec-dns-") as directory:
    path = Path(directory) / "case.json"

    def agree(value, rule=False):
        global count
        document = copy.deepcopy(base)
        if rule:
            document["dns"]["rules"] = [{"name": "r", "match": {}, "server": "local", **value}]
        else:
            document["dns"].update(value)
        expected = (options_validator if rule else settings_validator).is_valid(value)
        path.write_text(json.dumps(document))
        result = subprocess.run([sys.argv[1], str(path)], capture_output=True, text=True, timeout=5)
        assert result.returncode in (65, 78), (result.returncode, result.stderr)
        observed = json.loads(result.stdout)
        assert observed["syntax_valid"] == expected, (value, expected, observed)
        assert not observed["runtime_ready"]  # no executor inventory is forged
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
