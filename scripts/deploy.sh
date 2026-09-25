#!/usr/bin/env bash
# Fetch the reviewed public commit on the server, then build and install it there.
set -euo pipefail
if [[ $# -lt 4 || $# -gt 7 ]]; then
    echo 'Usage: bash scripts/deploy.sh SSH_HOST DOMAIN CERTIFICATE_PATH CERTIFICATE_KEY_PATH [COMMIT_SHA] [HTTPS_PORT] [UPSTREAM_PORT]' >&2
    exit 2
fi
sync_host=$1
sync_domain=$2
sync_cert=$3
sync_key=$4
[[ "$sync_host" =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.@-]*$ ]] || { echo 'Invalid SSH host' >&2; exit 2; }
[[ "$sync_domain" =~ ^[a-z0-9][a-z0-9.-]*$ && "$sync_cert" =~ ^/[a-zA-Z0-9_./-]+$ && "$sync_key" =~ ^/[a-zA-Z0-9_./-]+$ ]] || { echo 'Invalid deployment arguments' >&2; exit 2; }
sync_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$sync_source"
sync_revision=${5:-$(git rev-parse HEAD)}
sync_https_port=${6:-443}
sync_upstream_port=${7:-8787}
for sync_port in "$sync_https_port" "$sync_upstream_port"; do
    [[ "$sync_port" =~ ^[1-9][0-9]{0,4}$ ]] && (( sync_port <= 65535 )) || { echo 'Invalid port' >&2; exit 2; }
done
[[ "$sync_revision" =~ ^[a-f0-9]{40}$ ]] || { echo 'Use a full published commit SHA' >&2; exit 2; }
[[ "$sync_revision" == "$(git rev-parse HEAD)" ]] || { echo 'Check out the requested commit before deployment' >&2; exit 2; }
[[ -z "$(git status --porcelain)" ]] || { echo 'Commit and publish source changes before deployment' >&2; exit 2; }
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
sync_destination="/opt/openless-cloud-sync/source/$(date -u +%Y%m%dT%H%M%SZ)-${sync_revision:0:12}"
ssh -o BatchMode=yes "$sync_host" "set -eu; install -d -m 0755 /opt/openless-cloud-sync/source; git clone --no-checkout https://github.com/Open-Less/openless-cloud-sync.git '$sync_destination'; cd '$sync_destination'; git checkout --detach '$sync_revision'; export PATH=\"\$HOME/.cargo/bin:\$PATH\"; cargo test --locked; cargo build --release --locked; bash scripts/install_server.sh '$sync_domain' '$sync_cert' '$sync_key' '$sync_https_port' '$sync_upstream_port'"
