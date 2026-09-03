#!/bin/bash

set -e

echo "=== Установка Cloudflare WARP ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/install-warp.sh)"

echo "=== Добавление обновления и рестарт в cron ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/update-restart.sh)"

echo "=== Настройка SSH ключей ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/setup-ssh.sh)"

echo "=== Все скрипты успешно выполнены! ==="
