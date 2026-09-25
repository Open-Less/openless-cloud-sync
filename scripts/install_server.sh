#!/usr/bin/env bash
# Run as root from a reviewed source tree after tests and a native release build.
set -euo pipefail
umask 077
if [[ ${EUID} -ne 0 || $# -lt 3 || $# -gt 5 ]]; then
    echo 'Usage: sudo bash scripts/install_server.sh DOMAIN CERTIFICATE CERTIFICATE_KEY [HTTPS_PORT] [UPSTREAM_PORT]' >&2
    exit 2
fi
sync_domain=$1
sync_cert=$2
sync_key=$3
sync_https_port=${4:-443}
sync_upstream_port=${5:-8787}
for sync_port in "$sync_https_port" "$sync_upstream_port"; do
    [[ "$sync_port" =~ ^[1-9][0-9]{0,4}$ ]] && (( sync_port <= 65535 )) || { echo 'Invalid port' >&2; exit 2; }
done
[[ "$sync_https_port" != "$sync_upstream_port" ]] || { echo 'HTTPS and upstream ports must differ' >&2; exit 2; }
sync_source=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
sync_root=/opt/openless-cloud-sync
sync_env=/etc/openless-cloud-sync/sync.env
sync_unit=openless-cloud-sync.service
sync_site=/etc/nginx/sites-available/openless-cloud-sync
sync_enabled=/etc/nginx/sites-enabled/openless-cloud-sync
for command in systemctl nginx python3 curl install sha256sum git; do command -v "$command" >/dev/null; done
[[ -z "$(git -C "$sync_source" status --porcelain)" ]] || {
    echo 'Install from a clean committed source tree so the published archive matches the build.' >&2
    exit 1
}
[[ -s "$sync_env" && -s "$sync_cert" && -s "$sync_key" && -x "$sync_source/target/release/openless-cloud-sync" ]] || {
    echo 'Missing environment file, certificate, key, or release binary. See docs/deployment.md.' >&2
    exit 1
}
if grep -q 'REPLACE_WITH' "$sync_env"; then
    echo 'Configure dedicated OAuth credentials before installation.' >&2
    exit 1
fi
[[ $(stat -c '%a' "$sync_env") == 600 && $(stat -c '%U' "$sync_env") == root ]] || {
    echo 'Environment file must be owned by root with mode 0600.' >&2
    exit 1
}
python3 - "$sync_env" "$sync_upstream_port" <<'PY'
import pathlib, sys
lines = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
expected = "SYNC_BIND=127.0.0.1:" + sys.argv[2]
if [line.strip() for line in lines if line.strip().startswith("SYNC_BIND=")] != [expected]:
    sys.exit("SYNC_BIND must match the configured IPv4 loopback upstream port")
PY
getent passwd openless-sync >/dev/null || useradd --system --home /var/lib/openless-cloud-sync --shell /usr/sbin/nologin openless-sync
install -d -m 0700 -o openless-sync -g openless-sync /var/lib/openless-cloud-sync /var/backups/openless-cloud-sync
install -d -m 0755 "$sync_root/releases"
sync_release="$sync_root/releases/$(date -u +%Y%m%dT%H%M%SZ)-$(sha256sum "$sync_source/target/release/openless-cloud-sync" | cut -c1-12)"
install -d -m 0755 "$sync_release"
install -m 0755 "$sync_source/target/release/openless-cloud-sync" "$sync_release/openless-cloud-sync"
install -m 0644 "$sync_source/scripts/backup.py" "$sync_release/backup.py"
install -m 0644 "$sync_source/LICENSE" "$sync_release/LICENSE"
install -m 0644 "$sync_source/THIRD_PARTY_NOTICES.md" "$sync_release/THIRD_PARTY_NOTICES.md"
install -m 0644 "$sync_source/deploy/service-index.html" "$sync_release/index.html"
git -C "$sync_source" archive --format=tar.gz --output="$sync_release/source.tar.gz" HEAD
git -C "$sync_source" rev-parse HEAD > "$sync_release/REVISION"
chmod 0644 "$sync_release/source.tar.gz" "$sync_release/REVISION"
sync_previous=$(readlink "$sync_root/current" || true)
sync_stage=$(mktemp -d)
sync_had_site=false
sync_had_enabled=false
sync_previous_enabled=$(readlink "$sync_enabled" || true)
sync_had_unit=false
[[ ! -f "$sync_site" ]] || { cp "$sync_site" "$sync_stage/nginx.previous"; sync_had_site=true; }
[[ ! -L "$sync_enabled" ]] || sync_had_enabled=true
[[ ! -f /etc/systemd/system/$sync_unit ]] || { cp "/etc/systemd/system/$sync_unit" "$sync_stage/unit.previous"; sync_had_unit=true; }
sync_activated=false
cleanup() {
    sync_status=$?
    trap - EXIT
    if [[ $sync_status -ne 0 && $sync_activated == true ]]; then
        echo 'Deployment failed; restoring previous service and proxy configuration.' >&2
        if [[ -n "$sync_previous" ]]; then
            ln -sfn "$sync_previous" "$sync_root/current.restore"
            mv -Tf "$sync_root/current.restore" "$sync_root/current"
        else
            systemctl stop "$sync_unit" || true
            rm -f "$sync_root/current"
        fi
        if [[ $sync_had_site == true ]]; then cp "$sync_stage/nginx.previous" "$sync_site"; else rm -f "$sync_site"; fi
        if [[ $sync_had_enabled == false ]]; then rm -f "$sync_enabled"; else ln -sfn "$sync_previous_enabled" "$sync_enabled"; fi
        if [[ $sync_had_unit == true ]]; then cp "$sync_stage/unit.previous" "/etc/systemd/system/$sync_unit"; else rm -f "/etc/systemd/system/$sync_unit"; fi
        systemctl daemon-reload
        if [[ -n "$sync_previous" ]]; then systemctl restart "$sync_unit" || true; fi
        if nginx -t; then systemctl reload nginx; fi
    fi
    rm -rf -- "$sync_stage"
    exit "$sync_status"
}
trap cleanup EXIT
python3 "$sync_source/scripts/render_nginx.py" "$sync_domain" "$sync_cert" "$sync_key" --https-port "$sync_https_port" --upstream-port "$sync_upstream_port" > "$sync_stage/nginx.new"
sync_activated=true
install -m 0644 "$sync_stage/nginx.new" "$sync_site"
ln -sfn "$sync_site" "$sync_enabled"
nginx -t
install -m 0644 "$sync_source/deploy/$sync_unit" "/etc/systemd/system/$sync_unit"
ln -sfn "$sync_release" "$sync_root/current.next"
mv -Tf "$sync_root/current.next" "$sync_root/current"
systemctl daemon-reload
systemctl restart "$sync_unit"
curl --fail --silent --show-error --retry 10 --retry-connrefused --retry-delay 1 --max-time 5 "http://127.0.0.1:$sync_upstream_port/healthz" > /dev/null
systemctl reload nginx
sync_origin="https://$sync_domain"
[[ "$sync_https_port" == 443 ]] || sync_origin="$sync_origin:$sync_https_port"
curl --fail --silent --show-error --max-time 15 --resolve "$sync_domain:$sync_https_port:127.0.0.1" "$sync_origin/v1/capabilities" > /dev/null
curl --fail --silent --show-error --max-time 15 --resolve "$sync_domain:$sync_https_port:127.0.0.1" "$sync_origin/source.tar.gz" -o "$sync_stage/published-source.tar.gz"
cmp "$sync_release/source.tar.gz" "$sync_stage/published-source.tar.gz"
for sync_file in openless-cloud-sync-backup.service openless-cloud-sync-backup.timer openless-cloud-sync-prune.service openless-cloud-sync-prune.timer; do
    install -m 0644 "$sync_source/deploy/$sync_file" "/etc/systemd/system/$sync_file"
done
systemctl daemon-reload
systemctl start openless-cloud-sync-prune.service openless-cloud-sync-backup.service
systemctl enable "$sync_unit"
systemctl enable --now openless-cloud-sync-backup.timer openless-cloud-sync-prune.timer
echo "Deployment healthy: $sync_origin/v1/capabilities"
echo "Release: $sync_release"
