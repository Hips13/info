#!/bin/bash
set -e

echo "========================================================================="
echo "                 ПОДГОТОВКА К УСТАНОВКЕ                                "
echo "========================================================================="

# Запрашиваем ключ сразу, чтобы потом не отвлекать пользователя
echo "Вставьте вашу ПУБЛИЧНУЮ часть SSH-ключа:"
read -r SSH_KEY

if [ -z "$SSH_KEY" ]; then
    echo "Ошибка: Ключ не был введен. Отмена операции."
    exit 1
fi
echo "Ключ принят! Начинаем автоматическую настройку..."
echo ""

echo "========================================================================="
echo "                 1. УСТАНОВКА CLOUDFLARE WARP                          "
echo "========================================================================="

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
echo ""

echo "========================================================================="
echo "                 2. НАСТРОЙКА БЕЗОПАСНОГО SSH                          "
echo "========================================================================="

# Добавление ключа в authorized_keys
echo "Добавление ключа в ~/.ssh/authorized_keys..."
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "$SSH_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Настройка параметров SSH в отдельном .conf файле
echo "Настройка конфигурации SSH (отключение паролей, включение ключей)..."
sudo bash -c 'cat > /etc/ssh/sshd_config.d/99-custom-security.conf <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
EOF'

# Перезапуск службы SSH
echo "Перезагрузка службы SSH..."
sudo systemctl restart ssh || sudo systemctl restart sshd

# Вывод предупреждающего сообщения
echo ""
echo "========================================================================="
echo "ВНИМАНИЕ! Настройки применены, а служба SSH перезапущена."
echo ""
echo "НЕ ЗАКРЫВАЙТЕ ЭТО ОКНО ТЕРМИНАЛА!"
echo "Откройте НОВОЕ окно терминала и попытайтесь подключиться к серверу."
echo "Если подключиться не удастся (например, ключ скопирован с ошибкой),"
echo "вы сможете всё исправить из этого окна, удалив созданный файл командой:"
echo "sudo rm /etc/ssh/sshd_config.d/99-custom-security.conf && sudo systemctl restart ssh"
echo "========================================================================="
