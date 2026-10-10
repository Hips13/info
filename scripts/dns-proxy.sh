#!/usr/bin/env bash
# Standalone DNS-Proxy installer for Hips13/info; never run by all-scripts.sh.
set -Eeuo pipefail
url='https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/dns-proxy/install.sh'
if ! installer=$(curl --proto '=https' --tlsv1.2 -fLsS --connect-timeout 15 --max-time 90 "$url"); then
  echo 'Не удалось загрузить установщик dns-proxy.' >&2
  exit 2
fi
bash -c "$installer" dns-proxy-install --repo Hips13/info --ref main "$@"
