#!/bin/bash
set -e

echo "Начинаем установку Cloudflare WARP..."

# Добавляем GPG ключ и репозиторий
curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg | sudo gpg --yes --dearmor --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" | sudo tee /etc/apt/sources.list.d/cloudflare-client.list

# Обновляем пакеты и устанавливаем warp и net-tools
sudo apt-get update
sudo apt-get install -y cloudflare-warp net-tools

# Настраиваем и подключаем WARP
echo "Регистрация и запуск WARP..."
yes | warp-cli registration new
warp-cli mode proxy
warp-cli connect

# Проверяем порты
echo "Проверка запущенного сервиса:"
sudo netstat -tulpn | grep warp-svc

echo "Установка Cloudflare WARP успешно завершена!"
