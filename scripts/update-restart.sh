#!/bin/bash

# Проверка наличия прав root
if [ "$EUID" -ne 0 ]; then
  echo "Ошибка: Этот скрипт необходимо запускать с правами root (используйте sudo)."
  exit 1
fi

CRON_FILE="/etc/cron.d/weekly_auto_update"

# Команда для cron
# Формат: Минуты Часы ДеньМесяца Месяц ДеньНедели Пользователь Команда
CRON_JOB="0 3 * * 2 root apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y && shutdown -r now"

# Запись задачи в системный cron
echo "$CRON_JOB" > "$CRON_FILE"

# Установка правильных прав доступа к файлу
chmod 644 "$CRON_FILE"

cat /etc/cron.d/weekly_auto_update

echo "Задача успешно добавлена!"
echo "Система будет обновляться и перезагружаться каждый вторник в 03:00 ночи."
