#!/bin/bash

set -e

echo "=== Настройка SSH ключей ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/setup-ssh.sh)"

echo "=== Установка Cloudflare WARP ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/install-warp.sh)"

echo "=== Обновление конфигурации Xray ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/change-xray-config.sh)"

echo "=== Добавление обновления и рестарт в cron ==="
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/update-restart.sh)"

echo "=== Все скрипты успешно выполнены! ==="
