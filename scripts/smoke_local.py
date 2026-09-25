#!/usr/bin/env python3
"""Exercise a real service process with temporary, synthetic data and no GitHub calls."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sqlite3
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    executable = ROOT / "target/release/openless-cloud-sync"
    if not executable.exists():
        raise SystemExit("Build the release binary first")
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    token = secrets.token_urlsafe(32)
    origin = f"http://127.0.0.1:{port}"
    fixture = json.loads((ROOT / "tests/vectors/v1.json").read_text(encoding="utf-8"))["vectors"][0]
    snapshot = fixture["snapshot"].copy()
    # Use the actual encrypted fixture without changing AAD. Seed its high revision in this disposable DB.
    with tempfile.TemporaryDirectory(prefix="openless-smoke-") as temporary:
        root = Path(temporary)
        database = root / "sync.db"
        logfile = root / "service.log"
        environment = {**os.environ, "SYNC_BIND": f"127.0.0.1:{port}", "SYNC_DATABASE": str(database),
                       "SYNC_GITHUB_CLIENT_ID": "synthetic_test_app", "SYNC_GITHUB_CLIENT_SECRET": "synthetic-test-only-client-secret",
                       "SYNC_ALLOW_LOCAL_HTTP": "true", "SYNC_ACCESS_MODE": "restricted", "SYNC_ALLOWED_GITHUB_IDS": "12345"}

        def request(path, method="GET", body=None, headers=None, authenticated=True):
            wire = None if body is None else json.dumps(body, ensure_ascii=False, separators=(",", ":")).encode()
            request_headers = {"Authorization": f"Bearer {token}"} if authenticated else {}
            if wire is not None:
                request_headers["Content-Type"] = "application/json"
            request_headers.update(headers or {})
            req = urllib.request.Request(origin + path, data=wire, headers=request_headers, method=method)
            try:
                response = urllib.request.urlopen(req, timeout=10)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                data = response.read()
                return response.status, response.headers, json.loads(data) if data else None

        def start():
            output = logfile.open("ab")
            process = subprocess.Popen([str(executable)], env=environment, stdout=output, stderr=subprocess.STDOUT)
            output.close()
            for _ in range(100):
                if process.poll() is not None:
                    raise RuntimeError("service exited during startup")
                try:
                    if request("/healthz", authenticated=False)[0] == 200:
                        return process
                except OSError:
                    pass
                time.sleep(0.05)
            process.terminate()
            process.wait(timeout=10)
            raise RuntimeError("startup timeout")

        process = start()
        try:
            assert request("/v1/capabilities", authenticated=False)[0] == 200
            assert request("/v1/me/vault", authenticated=False)[0] == 401
            # Tests seed a short-lived session; production has no fake identity route or flag.
            with sqlite3.connect(database) as db:
                db.execute("INSERT INTO sessions VALUES(?,?,?)", (hashlib.sha256(token.encode()).hexdigest(), "12345", int(time.time()) + 900))
                metadata = {"protocolVersion": 1, "state": "active", "ownerGithubId": "12345", "revision": snapshot["baseRevision"],
                            "vaultId": snapshot["vaultId"], "keyId": snapshot["keyId"], "updatedAt": "2026-09-23T00:00:00Z",
                            "payloadSchemaVersion": 1, "ciphertextBytes": 65552, "ciphertextSha256": snapshot["ciphertextSha256"],
                            "lastOperationId": "fcad3073-29cc-4dbe-a764-e9de3f5daa7a"}
                db.execute("INSERT INTO vaults VALUES(?,?,?)", ("12345", json.dumps(metadata), json.dumps(snapshot).encode()))
            status, headers, _ = request("/v1/me/vault")
            assert status == 200
            upload_headers = {"If-Match": headers["ETag"], "Idempotency-Key": snapshot["operationId"]}
            wire = json.dumps(snapshot, ensure_ascii=False, separators=(",", ":")).encode()
            # Send a complete request, then deliberately discard its response.
            with socket.create_connection(("127.0.0.1", port), timeout=10) as connection:
                header = (f"PUT /v1/me/vault/snapshot HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {token}\r\n"
                          f"If-Match: {headers['ETag']}\r\nIdempotency-Key: {snapshot['operationId']}\r\n"
                          f"Content-Type: application/json\r\nContent-Length: {len(wire)}\r\nConnection: close\r\n\r\n")
                connection.sendall(header.encode() + wire)
                while connection.recv(65536):
                    pass  # Response intentionally never parsed or recorded by this client.
            status, _, receipt = request(f"/v1/me/operations/{snapshot['operationId']}")
            assert status == 200 and receipt["committedRevision"] == snapshot["revision"]
            status, headers, replay = request("/v1/me/vault/snapshot", "PUT", snapshot, upload_headers)
            assert status == 200 and headers["Idempotency-Replayed"] == "true" and replay == receipt
            process.terminate()
            process.wait(timeout=15)
            process = start()
            status, headers, metadata = request("/v1/me/vault")
            assert status == 200 and metadata["revision"] == snapshot["revision"]
            assert request("/v1/me/vault/snapshot", headers={"If-Match": headers["ETag"]})[2] == snapshot
            assert request("/v1/auth/session", "DELETE")[0] == 204
            assert request("/v1/me/vault")[0] == 401
        finally:
            process.terminate()
            process.wait(timeout=15)
        logs = logfile.read_text(encoding="utf-8")
        for forbidden in [token, snapshot["ciphertext"], "synthetic-test-only-client-secret", fixture["passwordInput"], fixture["derivedKeyHex"]]:
            assert forbidden not in logs, "sensitive value in service log"
            if forbidden != snapshot["ciphertext"]:
                assert forbidden.encode() not in database.read_bytes(), "credential persisted unexpectedly"
        print("PASS: real HTTP process, discarded response, idempotent retry, restart persistence, logout, log redaction")


if __name__ == "__main__":
    main()
