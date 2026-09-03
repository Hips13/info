# Все скрипты разом
```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/all-scripts.sh)"
```
`setup-ssh.sh` `install-warp.sh` `update-restart.sh`

---

# Установка и настройка Cloudflare WARP
```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/install-warp.sh)"
```
# Обновление и рестарт в cron
добавление задачи в cron каждый вторник в 03:00 запуск apt update -y && apt upgrade -y && shutdown -r now 
```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/update-restart.sh)"
```
# Настройка подключения по SSH ключу
```
bash -c "$(curl -fsSL https://raw.githubusercontent.com/Hips13/info/refs/heads/main/scripts/setup-ssh.sh)"
```

