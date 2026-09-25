#!/usr/bin/env python3
"""Validate the shipped nginx template and real HTTPS proxy with disposable test credentials."""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nginx", default="nginx")
    args = parser.parse_args()
    api_port, tls_port = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="openless-nginx-") as temporary:
        directory = Path(temporary)
        # Some nginx packages drop root to www-data; static files must be traversable.
        directory.chmod(0o755)
        source = directory / "public-source"
        source.mkdir(mode=0o755)
        for name, origin in [("index.html", ROOT / "deploy/service-index.html"),
                             ("LICENSE", ROOT / "LICENSE"),
                             ("THIRD_PARTY_NOTICES.md", ROOT / "THIRD_PARTY_NOTICES.md")]:
            shutil.copyfile(origin, source / name)
        (source / "REVISION").write_text("0" * 40 + "\n")
        (source / "source.tar.gz").write_bytes(b"test-only-source-archive")
        cert, key = directory / "cert.pem", directory / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
                        "-keyout", str(key), "-out", str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        config = subprocess.check_output(["python3", str(ROOT / "scripts/render_nginx.py"), "sync.localhost", str(cert), str(key),
                                          "--https-port", str(tls_port), "--upstream-port", str(api_port)], text=True)
        config = config.replace(f"listen {tls_port} ssl;", f"listen 127.0.0.1:{tls_port} ssl;").replace(f"listen [::]:{tls_port} ssl;", "")
        config = config.replace("/var/log/nginx/openless-cloud-sync-error.log", str(directory / "error.log"))
        config = config.replace("/opt/openless-cloud-sync/current", str(source))
        config = f"daemon off; worker_processes 1; pid {directory}/nginx.pid; error_log {directory}/main-error.log;\nevents {{ worker_connections 64; }}\nhttp {{\n" + f"client_body_temp_path {directory}/body; proxy_temp_path {directory}/proxy; fastcgi_temp_path {directory}/fastcgi; uwsgi_temp_path {directory}/uwsgi; scgi_temp_path {directory}/scgi;\n" + config + "\n}\n"
        path = directory / "nginx.conf"
        path.write_text(config)
        subprocess.run([args.nginx, "-e", "stderr", "-t", "-p", str(directory) + "/", "-c", str(path)], check=True)
        environment = {**os.environ, "SYNC_BIND": f"127.0.0.1:{api_port}", "SYNC_DATABASE": str(directory / "sync.db"),
                       "SYNC_GITHUB_CLIENT_ID": "synthetic_test_app", "SYNC_GITHUB_CLIENT_SECRET": "synthetic-test-only-client-secret",
                       "SYNC_ALLOW_LOCAL_HTTP": "false", "SYNC_ACCESS_MODE": "restricted", "SYNC_ALLOWED_GITHUB_IDS": "12345"}
        log = (directory / "output.log").open("wb")
        api = subprocess.Popen([str(ROOT / "target/release/openless-cloud-sync")], env=environment, stdout=log, stderr=log)
        nginx = subprocess.Popen([args.nginx, "-e", "stderr", "-p", str(directory) + "/", "-c", str(path)], stdout=log, stderr=log)
        context = ssl.create_default_context(cafile=str(cert))
        try:
            for _ in range(100):
                try:
                    with urllib.request.urlopen(f"https://localhost:{tls_port}/v1/capabilities", context=context, timeout=2) as response:
                        assert json.load(response)["protocolVersion"] == 1
                        assert response.headers["Strict-Transport-Security"] == "max-age=31536000"
                        assert response.headers.get_all("Cache-Control") == ["no-store"]
                    break
                except OSError:
                    if api.poll() is not None or nginx.poll() is not None:
                        raise RuntimeError("test service or nginx exited")
                    time.sleep(0.05)
            else:
                raise RuntimeError("HTTPS startup timed out")
            for path, expected in [("/", b"/source.tar.gz"), ("/license", b"GNU AFFERO GENERAL PUBLIC LICENSE"),
                                   ("/revision", b"0" * 40), ("/source.tar.gz", b"test-only-source-archive"),
                                   ("/third-party-notices", b"AGPL-3.0-only")]:
                try:
                    with urllib.request.urlopen(f"https://localhost:{tls_port}{path}", context=context, timeout=5) as response:
                        assert expected in response.read(), path
                        assert response.headers["Cache-Control"] == "no-store"
                except urllib.error.HTTPError as error:
                    raise AssertionError(f"static endpoint {path}: HTTP {error.code}") from error
            for path, headers, status, code in [
                ("/v1/me/vault", {}, 401, "unauthenticated"),
                ("/v1/me/vault/snapshot", {"Content-Length": "25165825"}, 413, "payload_too_large"),
            ]:
                request = urllib.request.Request(f"https://localhost:{tls_port}{path}", headers=headers)
                try:
                    urllib.request.urlopen(request, context=context, timeout=5)
                    raise AssertionError("unexpected success")
                except urllib.error.HTTPError as response:
                    assert response.code == status
                    payload = json.load(response)
                    assert payload["error"]["code"] == code
                    assert uuid.UUID(payload["error"]["requestId"]).version == 4
                    assert response.headers["Cache-Control"] == "no-store"
        finally:
            nginx.terminate()
            api.terminate()
            nginx.wait(timeout=15)
            api.wait(timeout=15)
            log.close()
        print("PASS: nginx syntax, HTTPS forwarding, private authentication, JSON edge errors, no-store, license/source access")


if __name__ == "__main__":
    main()
