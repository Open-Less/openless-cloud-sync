#!/usr/bin/env python3
"""Independent reference-Argon2/libsodium fixtures. TEST VALUES ONLY, never client code."""
import argparse
import base64
import hashlib
import json
import struct
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_encrypt as encrypt,
    crypto_aead_xchacha20poly1305_ietf_decrypt as decrypt,
)

ROOT = Path(__file__).resolve().parents[1]


def b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def compact(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def vector(password: str, index: int) -> dict:
    normalized = unicodedata.normalize("NFC", password)
    salt = bytes(range(index, index + 16))
    nonce = bytes(range(index, index + 24))
    key = hash_secret_raw(normalized.encode(), salt, 3, 65536, 4, 32, Type.ID, 19)
    snapshot = {
        "protocolVersion": 1, "payloadSchemaVersion": 1, "ownerGithubId": "12345",
        "vaultId": "be406ca5-37fa-4b26-9a9a-74c1aad48eae",
        "keyId": "7250d1bd-5a3e-42b0-91dc-df0cb0608221",
        "baseRevision": "9007199254740992", "revision": "9007199254740993",
        "operationId": "e1d8c32e-d209-4e56-8735-bc66b8684c71", "kind": "snapshot",
        "cryptoProfile": "argon2id-xchacha20poly1305-v1",
        "kdf": {"name": "argon2id", "version": 19, "memoryKiB": 65536,
                "iterations": 3, "parallelism": 4, "salt": b64(salt)},
        "aead": "xchacha20poly1305-ietf", "codec": "json-pad64k-v1", "nonce": b64(nonce),
    }
    aad = compact([
        "openless-cloud-sync", 1, "snapshot", snapshot["ownerGithubId"], snapshot["vaultId"],
        snapshot["keyId"], snapshot["baseRevision"], snapshot["revision"], snapshot["operationId"],
        snapshot["kind"], 1, snapshot["cryptoProfile"], "argon2id", 19, 65536, 3, 4, b64(salt),
        snapshot["aead"], snapshot["codec"],
    ])
    document = {
        "schemaVersion": 1, "exportedAt": "2026-09-23T00:00:00Z",
        "sourceDevice": {"id": "fixture-device", "os": "test", "arch": "test", "appVersion": "0.1.0"},
        "documents": [{"id": "main", "kind": "preferences", "schemaVersion": 1,
                       "value": {"language": "zh-CN", "testText": "云同步 café"}}], "tombstones": [],
    }
    plaintext_json = compact(document)
    padding_length = 65536 - 4 - len(plaintext_json)
    padding = bytes(i % 251 for i in range(padding_length))
    framed = struct.pack(">I", len(plaintext_json)) + plaintext_json + padding
    ciphertext = encrypt(framed, aad, nonce, key)
    assert decrypt(ciphertext, aad, nonce, key) == framed
    snapshot["ciphertext"] = b64(ciphertext)
    snapshot["ciphertextSha256"] = hashlib.sha256(ciphertext).hexdigest()
    return {
        "name": f"unicode-{index}", "testOnly": True, "passwordInput": password,
        "passwordNfc": normalized, "passwordUtf8Hex": normalized.encode().hex(), "derivedKeyHex": key.hex(),
        "aadUtf8Hex": aad.hex(), "plaintextJsonUtf8Hex": plaintext_json.hex(), "recoveredJson": document,
        "padding": {"pattern": "index-mod-251", "length": padding_length, "sha256": hashlib.sha256(padding).hexdigest()},
        "snapshot": snapshot,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Regenerate fixed public TEST fixtures")
    args = parser.parse_args()
    expected = {"formatVersion": 1, "vectors": [vector("云同步Cafe\u0301-Vector2026!", 0), vector("测试A9-Interoperability!", 1)]}
    path = ROOT / "tests/vectors/v1.json"
    if args.write:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(expected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    else:
        assert json.loads(path.read_text(encoding="utf-8")) == expected, "Independent implementation disagrees with fixture"
    print("PASS: reference Argon2 + libsodium; 2 fixed v1 vectors")


if __name__ == "__main__":
    main()
