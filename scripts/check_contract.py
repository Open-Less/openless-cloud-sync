#!/usr/bin/env python3
"""Validate actual HTTP fixture responses against the checked-in OpenAPI contract."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

import jsonschema
import yaml

root = Path(__file__).resolve().parents[1]
spec = yaml.safe_load((root / "docs/openapi.yaml").read_text(encoding="utf-8"))
with tempfile.TemporaryDirectory(prefix="openless-contract-") as temporary:
    path = Path(temporary) / "responses.json"
    subprocess.run(["cargo", "test", "--locked", "--test", "openapi_samples"], cwd=root,
                   env={**os.environ, "SYNC_CONTRACT_SAMPLES": str(path)}, check=True)
    samples = json.loads(path.read_text(encoding="utf-8"))
    for sample in samples:
        response = spec["paths"][sample["path"]][sample["method"]]["responses"][sample["status"]]
        if "content" in response:
            schema = {"components": spec["components"], **response["content"]["application/json"]["schema"]}
            jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker()).validate(sample["body"])
        else:
            assert sample["body"] is None
        for name, header in response.get("headers", {}).items():
            value = sample["headers"].get(name.lower())
            assert value is not None, f"Missing response header {name}"
            schema = {"components": spec["components"], **header["schema"]}
            if schema.get("type") == "integer":
                value = int(value)
            jsonschema.Draft202012Validator(schema).validate(value)
    print(f"PASS: {len(samples)} actual responses match OpenAPI, including all vault states")
