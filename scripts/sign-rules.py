#!/usr/bin/env python3
"""
Signs a signatures.json so the checker accepts it as an override.

    scripts/sign-rules.py path/to/signatures.json [--key ~/.config/moon-signing/rules-ed25519.pem]

Writes signatures.json.sig (base64 Ed25519 signature over the file's exact bytes).
Ship both files next to MoonCheck.exe. Keep the private key off servers and out of git.
"""
import argparse
import base64
import pathlib

from cryptography.hazmat.primitives import serialization

parser = argparse.ArgumentParser()
parser.add_argument("rules")
parser.add_argument("--key", default=str(pathlib.Path.home() / ".config/moon-signing/rules-ed25519.pem"))
args = parser.parse_args()
key = serialization.load_pem_private_key(pathlib.Path(args.key).read_bytes(), password=None)
data = pathlib.Path(args.rules).read_bytes()
out = pathlib.Path(args.rules + ".sig")
out.write_text(base64.b64encode(key.sign(data)).decode() + "\n", encoding="ascii")
print(f"wrote {out}")
