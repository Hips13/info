#!/bin/bash
set -Eeuo pipefail
umask 077

if [[ $EUID -ne 0 ]]; then
    echo "Запустите скрипт от root."
    exit 1
fi

DB=/etc/x-ui/x-ui.db
BIN_DIR=/usr/local/x-ui/bin
RUNTIME_CONFIG="$BIN_DIR/config.json"

[[ -f "$DB" ]] || {
    echo "Сначала установите панель 3x-ui."
    exit 1
}

echo "Устанавливаем Cloudflare WARP..."

apt-get update
apt-get install -y curl gnupg lsb-release python3

curl -fsSL https://pkg.cloudflareclient.com/pubkey.gpg |
    gpg --yes --dearmor \
        --output /usr/share/keyrings/cloudflare-warp-archive-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/cloudflare-warp-archive-keyring.gpg] https://pkg.cloudflareclient.com/ $(lsb_release -cs) main" \
    > /etc/apt/sources.list.d/cloudflare-client.list

apt-get update
apt-get install -y cloudflare-warp net-tools
systemctl enable --now warp-svc

# При повторном запуске сохраняем существующую регистрацию.
if ! warp-cli --accept-tos registration show >/dev/null 2>&1; then
    warp-cli --accept-tos registration new
fi

warp-cli --accept-tos mode proxy
warp-cli --accept-tos proxy port 40000
warp-cli --accept-tos connect

echo "Проверяем соединение через WARP..."
warp_ready=false

for attempt in {1..15}; do
    if curl -fsS \
        --connect-timeout 5 --max-time 10 \
        --proxy socks5h://127.0.0.1:40000 \
        https://www.cloudflare.com/cdn-cgi/trace |
        grep -Eq '^warp=(on|plus)\r?$'; then
        warp_ready=true
        break
    fi
    sleep 2
done

if [[ "$warp_ready" != true ]]; then
    echo "WARP не готов. Настройки Xray не изменены."
    exit 1
fi

# Находим установленный исполняемый файл Xray.
XRAY=""
for candidate in "$BIN_DIR"/xray-linux-*; do
    if [[ -f "$candidate" && -x "$candidate" ]]; then
        XRAY="$candidate"
        break
    fi
done

[[ -n "$XRAY" ]] || {
    echo "Исполняемый файл Xray не найден в $BIN_DIR."
    exit 1
}

BACKUP="${DB}.before-warp-$(date +%Y%m%d-%H%M%S)-$$"
WORK_DIR=$(mktemp -d)
PANEL_STOPPED=false
DB_CHANGED=false

cleanup() {
    rm -f -- "$WORK_DIR/template.json" "$WORK_DIR/test.json"
    rmdir -- "$WORK_DIR" 2>/dev/null || true
}

rollback() {
    local status=$?
    trap - ERR
    echo "Ошибка настройки Xray."

    if [[ "$DB_CHANGED" == true ]]; then
        echo "Восстанавливаем базу: $BACKUP"
        # Восстанавливаем через SQLite, учитывая WAL-журнал.
        python3 - "$BACKUP" "$DB" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source:
    with sqlite3.connect(sys.argv[2]) as target:
        source.backup(target)
PY
    fi

    if [[ "$PANEL_STOPPED" == true ]]; then
        systemctl restart x-ui || true
    fi
    exit "$status"
}

trap cleanup EXIT
trap rollback ERR

echo "Готовим настройки Xray..."
systemctl stop x-ui
PANEL_STOPPED=true

# Создаём согласованную резервную копию базы.
python3 - "$DB" "$BACKUP" <<'PY'
import sqlite3
import sys

with sqlite3.connect(sys.argv[1]) as source:
    with sqlite3.connect(sys.argv[2]) as target:
        source.backup(target)
PY

python3 - "$DB" "$RUNTIME_CONFIG" "$WORK_DIR" <<'PY'
import copy
import json
import pathlib
import sqlite3
import sys

db_path, runtime_path, work_path = sys.argv[1:]
work = pathlib.Path(work_path)
runtime_file = pathlib.Path(runtime_path)

runtime = None
if runtime_file.is_file():
    runtime = json.loads(runtime_file.read_text(encoding="utf-8"))

with sqlite3.connect(db_path) as db:
    rows = db.execute(
        "SELECT value FROM settings WHERE key = ?",
        ("xrayTemplateConfig",),
    ).fetchall()

if len(rows) > 1:
    raise RuntimeError("В базе несколько записей xrayTemplateConfig")

if rows and rows[0][0]:
    config = json.loads(rows[0][0])
else:
    if runtime is None:
        raise RuntimeError(
            "Не найдены ни сохранённый шаблон, ни bin/config.json. "
            "Запустите Xray из панели и повторите установку."
        )
    config = copy.deepcopy(runtime)

# Клиентские входы панель формирует отдельно из таблицы inbounds.
api_tag = config.get("api", {}).get("tag", "api")
config["inbounds"] = [
    inbound for inbound in config.get("inbounds", [])
    if inbound.get("tag") == api_tag
]

if not config["inbounds"]:
    raise RuntimeError("API-вход панели не найден")

outbounds = config.get("outbounds", [])
direct = [o for o in outbounds if o.get("tag") == "direct"]

if len(direct) != 1:
    raise RuntimeError("Ожидался единственный outbound direct")

config["outbounds"] = [
    direct[0],
    {
        "tag": "warp",
        "protocol": "socks",
        "settings": {
            "servers": [{"address": "127.0.0.1", "port": 40000}]
        },
    },
    *[
        o for o in outbounds
        if o.get("tag") not in ("direct", "warp")
    ],
]

if not any(
    o.get("tag") == "blocked" for o in config["outbounds"]
):
    config["outbounds"].append({
        "tag": "blocked",
        "protocol": "blackhole",
        "settings": {},
    })

old_domains = [
    r"regexp:.*\.xn--p1ai$",
    r"regexp:.*\.ru$",
    r"regexp:.*\.su$",
]
warp_domains = ["geosite:category-ru", *old_domains]

replaceable = [
    ("direct", ["geosite:youtube"]),
    ("warp", old_domains),
    ("warp", warp_domains),
]

routing = config.setdefault("routing", {})
routing["domainStrategy"] = "IPIfNonMatch"

remaining = [
    rule for rule in routing.get("rules", [])
    if not any(
        rule.get("outboundTag") == tag
        and set(rule.get("domain", [])) == set(domains)
        and set(rule).issubset({"type", "outboundTag", "domain"})
        for tag, domains in replaceable
    )
]

# API и существующие блокировки сохраняют приоритет.
priority = [
    rule for rule in remaining
    if rule.get("outboundTag") in (api_tag, "blocked")
]
other = [
    rule for rule in remaining
    if rule.get("outboundTag") not in (api_tag, "blocked")
]

routing["rules"] = [
    *priority,
    {
        "type": "field",
        "outboundTag": "warp",
        "domain": warp_domains,
    },
    *other,
]

config.setdefault("dns", {}).update({
    "servers": ["1.1.1.1", "8.8.8.8"],
    "queryStrategy": "UseIPv4",
    "tag": "dns_inbound",
    "enableParallelQuery": False,
})

sniffing_patch = {
    "enabled": True,
    "destOverride": ["http", "tls", "quic"],
    "metadataOnly": False,
    "routeOnly": True,
}

# Проверяем также клиентские входы из текущего runtime-конфига.
test_config = copy.deepcopy(config)
if runtime is not None:
    for inbound in runtime.get("inbounds", []):
        if inbound.get("tag") == api_tag:
            continue
        inbound = copy.deepcopy(inbound)
        if inbound.get("protocol") in (
            "vless", "vmess", "trojan", "shadowsocks"
        ):
            inbound.setdefault("sniffing", {}).update(sniffing_patch)
        test_config["inbounds"].append(inbound)

for filename, data in (
    ("template.json", config),
    ("test.json", test_config),
):
    (work / filename).write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
PY

echo "Проверяем конфигурацию установленным Xray..."
(
    cd "$BIN_DIR"
    XRAY_LOCATION_ASSET="$BIN_DIR" \
        "$XRAY" run -test -config "$WORK_DIR/test.json"
)

# Флаг устанавливается заранее, чтобы откатить и частичный сбой записи.
DB_CHANGED=true

python3 - "$DB" "$WORK_DIR/template.json" <<'PY'
import json
import pathlib
import sqlite3
import sys

template = pathlib.Path(sys.argv[2]).read_text(encoding="utf-8")
json.loads(template)

with sqlite3.connect(sys.argv[1]) as db:
    count = db.execute(
        "SELECT COUNT(*) FROM settings WHERE key = ?",
        ("xrayTemplateConfig",),
    ).fetchone()[0]

    if count == 0:
        db.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?)",
            ("xrayTemplateConfig", template),
        )
    elif count == 1:
        db.execute(
            "UPDATE settings SET value = ? WHERE key = ?",
            (template, "xrayTemplateConfig"),
        )
    else:
        raise RuntimeError("Несколько записей xrayTemplateConfig")

    rows = db.execute(
        "SELECT id, sniffing FROM inbounds "
        "WHERE protocol IN ('vless', 'vmess', 'trojan', 'shadowsocks')"
    ).fetchall()

    for inbound_id, raw in rows:
        sniffing = json.loads(raw) if raw else {}
        sniffing.update({
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
            "metadataOnly": False,
            "routeOnly": True,
        })
        db.execute(
            "UPDATE inbounds SET sniffing = ? WHERE id = ?",
            (json.dumps(sniffing), inbound_id),
        )
PY

systemctl start x-ui
sleep 5
systemctl is-active --quiet x-ui

trap - ERR
echo
echo "WARP установлен, настройки Xray сохранены."
echo "Через WARP: category-ru, .ru, .su, .рф."
echo "Остальной трафик по умолчанию: direct."
echo "Резервная копия базы: $BACKUP"
echo "Проверьте статус ядра Xray в панели."
