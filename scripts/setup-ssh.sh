#!/bin/bash
set -e

echo "Настройка безопасного доступа по SSH..."

# 1. Запрос публичного ключа у пользователя
echo "Вставьте вашу ПУБЛИЧНУЮ часть SSH-ключа:"
read -r SSH_KEY

if [ -z "$SSH_KEY" ]; then
    echo "Ошибка: Ключ не был введен. Отмена операции."
    exit 1
fi

# 2. Добавление ключа в authorized_keys
echo "Добавление ключа в ~/.ssh/authorized_keys..."
mkdir -p ~/.ssh
chmod 700 ~/.ssh
echo "$SSH_KEY" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# 3. Настройка параметров SSH в отдельном .conf файле
echo "Настройка конфигурации SSH (отключение паролей, включение ключей)..."
sudo bash -c 'cat > /etc/ssh/sshd_config.d/99-custom-security.conf <<EOF
PubkeyAuthentication yes
PasswordAuthentication no
EOF'

# 4. Перезапуск службы SSH
echo "Перезагрузка службы SSH..."
# Используем || на случай, если служба называется sshd (как в RHEL/CentOS), а не ssh (как в Ubuntu/Debian)
sudo systemctl restart ssh || sudo systemctl restart sshd

# 5. Вывод предупреждающего сообщения
echo ""
echo "========================================================================="
echo "ВНИМАНИЕ! Настройки применены, а служба SSH перезапущена."
echo ""
echo "НЕ ЗАКРЫВАЙТЕ ЭТО ОКНО ТЕРМИНАЛА!"
echo "Откройте НОВОЕ окно терминала и попытайтесь подключиться к серверу с помощью SSH ключа."
echo "Если подключиться не удастся (например, ключ скопирован с ошибкой),"
echo "вы сможете всё исправить из этого окна, удалив созданный файл командой:"
echo "sudo rm /etc/ssh/sshd_config.d/99-custom-security.conf && sudo systemctl restart ssh"
echo "========================================================================="
