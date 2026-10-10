#!/usr/bin/env bash
# Download a reviewed, pinned release and launch its interactive installer.
set -Eeuo pipefail
umask 077
repo='Hips13/info'
ref='main'
action='install'
usage() {
  cat <<'EOF'
Usage: sudo bash install.sh --repo OWNER/REPO [--ref main] [-- ACTION ARGS...]
Default action: install (interactive selection, preview, apply, restart, site check/rollback).
Example read-only preview: sudo bash install.sh --repo OWNER/REPO --ref main -- dry-run
No packages are installed. Dependencies: bash, curl, python3, systemctl.
EOF
}
while (($#)); do
  case "$1" in
    --repo) repo="${2:?Missing OWNER/REPO}"; shift 2 ;;
    --ref) ref="${2:?Missing release ref}"; shift 2 ;;
    --) shift; break ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage; exit 2 ;;
  esac
done
[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Provide --repo OWNER/REPO' >&2; exit 2; }
[[ "$ref" =~ ^[A-Za-z0-9_.-]+$ && "$ref" != '.' && "$ref" != '..' ]] || { echo 'Use a tag or full commit SHA without slashes.' >&2; exit 2; }
(( EUID == 0 )) || { echo 'Run with sudo or as root.' >&2; exit 2; }
for tool in curl python3 systemctl mktemp install cmp; do
  command -v "$tool" >/dev/null || { printf 'Missing dependency: %s. Nothing installed.\n' "$tool" >&2; exit 2; }
done
if (($#)); then action="$1"; shift; fi
case "$action" in install|dry-run|apply|verify|rollback) ;; *) echo 'Unknown patch action.' >&2; exit 2;; esac
base="https://raw.githubusercontent.com/${repo}/${ref}/scripts/dns-proxy"
stage=$(mktemp -d /var/tmp/dns-proxy-download.XXXXXXXX)
cleanup() {
  # Only our freshly allocated, fixed-prefix temporary directory is removed.
  case "$stage" in /var/tmp/dns-proxy-download.*) rm -rf -- "$stage" ;; esac
}
trap cleanup EXIT
files=(dns_proxy.py config.json providers.json)
for file in "${files[@]}"; do
  curl --proto '=https' --tlsv1.2 -fLsS --connect-timeout 15 --max-time 90 --retry 2 \
    "${base}/${file}" -o "${stage}/${file}"
done
python3 - "$stage" <<'PY'
import ast,json,sys
from pathlib import Path
p=Path(sys.argv[1])
ast.parse((p/'dns_proxy.py').read_text(encoding='utf-8'))
for name in ['config.json','providers.json']:json.loads((p/name).read_text(encoding='utf-8'))
PY
if [[ -e /usr/local/lib/dns-proxy ]]; then
  [[ -d /usr/local/lib/dns-proxy && ! -L /usr/local/lib/dns-proxy ]] || { echo 'Unsafe installation directory.' >&2; exit 2; }
else
  install -d -m 700 /usr/local/lib/dns-proxy
fi
# Allocate a fresh saved package; no SHA manifest is downloaded or checked.
target=$(mktemp -d /usr/local/lib/dns-proxy/package.XXXXXXXX)
for file in "${files[@]}"; do install -m 600 "${stage}/${file}" "${target}/${file}"; done

printf 'Source: %s @ %s\nSaved installer: %s\n' "$repo" "$ref" "$target"
python3 "${target}/dns_proxy.py" "$action" "$@"
