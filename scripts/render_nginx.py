#!/usr/bin/env python3
"""Render an isolated HTTPS virtual host; writes only to stdout."""
import argparse
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("domain")
parser.add_argument("certificate")
parser.add_argument("certificate_key")
args = parser.parse_args()
if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?", args.domain) or "." not in args.domain:
    parser.error("invalid DNS domain")
for path in [args.certificate, args.certificate_key]:
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", path):
        parser.error("certificate paths must be absolute and contain no nginx metacharacters")
template = Path(__file__).resolve().parents[1] / "deploy/nginx.conf.template"
print(template.read_text().replace("__DOMAIN__", args.domain).replace("__CERTIFICATE__", args.certificate).replace("__CERTIFICATE_KEY__", args.certificate_key))
