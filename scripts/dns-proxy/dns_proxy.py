#!/usr/bin/env python3
"""dns-proxy: guided install, explicit warnings and field-level rollback."""
import argparse
import copy
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
import uuid
import time
from urllib.parse import urlsplit

PROTOCOLS = {'vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'mixed'}
NETWORKS = {'tcp', 'raw', 'ws', 'xhttp', 'grpc', 'httpupgrade', 'http', 'h2', 'kcp', 'quic'}
FORMAT = 'dns-proxy-v1'
VERSION = '0.2.3'

class Refuse(Exception):
    pass

def encode(v):
    return json.dumps(v, ensure_ascii=False, separators=(',', ':'), sort_keys=True)

def connect(path, write=False):
    p = Path(path).resolve()
    if not p.is_file():
        raise Refuse('Database does not exist; refusing to create it.')
    c = sqlite3.connect(p.as_uri() + ('?mode=rw' if write else '?mode=ro'), uri=True, timeout=10)
    c.row_factory = sqlite3.Row
    return c

def schema(c):
    required = {'settings': {'id', 'key', 'value'}, 'inbounds': {'id', 'enable', 'protocol', 'tag', 'port', 'sniffing', 'stream_settings', 'node_id'}}
    for table, cols in required.items():
        have = {r['name'] for r in c.execute('PRAGMA table_info(' + table + ')')}
        if not cols <= have:
            raise Refuse('Unsupported database schema: ' + table)
    if c.execute("SELECT count(*) FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0] != 1:
        raise Refuse('Expected exactly one xrayTemplateConfig setting.')
    if not c.execute("SELECT json_valid(value) FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0]:
        raise Refuse('Invalid template JSON.')
    if c.execute("SELECT count(*) FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('settings','inbounds')").fetchone()[0]:
        raise Refuse('Database has custom triggers on patched tables; manual review required.')
    if c.execute("SELECT json_type(value,'$.routing') FROM settings WHERE key='xrayTemplateConfig'").fetchone()[0] != 'object':
        raise Refuse('Expected an existing routing object.')

def varint(b, p):
    n = shift = 0
    while p < len(b) and shift <= 63:
        x = b[p]; p += 1; n |= (x & 127) << shift
        if x < 128:
            return n, p
        shift += 7
    raise Refuse('Invalid GeoSite varint.')

def fields(b):
    p = 0
    while p < len(b):
        key, p = varint(b, p); wire = key & 7
        if wire == 2:
            size, p = varint(b, p)
            if p + size > len(b):
                raise Refuse('Truncated GeoSite.')
            v = b[p:p + size]; p += size
        elif wire == 0:
            v, p = varint(b, p)
        elif wire in (1, 5):
            size = 8 if wire == 1 else 4
            if p + size > len(b):
                raise Refuse('Truncated GeoSite.')
            v = b[p:p + size]; p += size
        else:
            raise Refuse('Unsupported GeoSite wire type.')
        yield key >> 3, v

def check_geosite(path, code):
    if not Path(path).is_file():
        raise Refuse('GeoSite file not found.')
    for k, v in fields(Path(path).read_bytes()):
        if k == 1:
            entry = list(fields(v))
            if any(f == 1 and x.decode().lower() == code.lower() for f, x in entry):
                if not any(f == 2 for f, x in entry):
                    raise Refuse('GeoSite group is empty.')
                return
    raise Refuse('Requested GeoSite group is absent.')

def validate_address(address):
    if not isinstance(address, str) or address != address.strip() or any(x.isspace() for x in address):
        raise Refuse('Введите один полный DoH URL или один IPv4 адрес DNS-сервера.')
    try:
        if isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
            return address
    except ValueError:
        pass
    url = urlsplit(address)
    try:
        port = url.port
    except ValueError as exc:
        raise Refuse('Некорректный порт в DoH URL.') from exc
    if url.scheme != 'https' or not url.hostname or not url.path or url.path == '/' or url.username or url.password or url.fragment:
        raise Refuse('Для DoH нужен полный https://имя/путь; для обычного DNS — один IPv4 без порта. Не вводите адрес сайта, DoT-имя или список IP.')
    return address

def config(path):
    cfg = json.loads(Path(path).read_text(encoding='utf-8-sig'))
    validate_address(cfg['dns_url'])
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', cfg['geosite']):
        raise Refuse('Invalid GeoSite code.')
    if not isinstance(cfg.get('timeout_ms', 4000), int) or cfg.get('timeout_ms', 4000) < 1:
        raise Refuse('Invalid timeout_ms.')
    return cfg

def path_value(c, path):
    row = c.execute("SELECT json_type(value,?),json_extract(value,?) FROM settings WHERE key='xrayTemplateConfig'", (path, path)).fetchone()
    kind, value = row
    if kind in ('object', 'array'):
        value = json.loads(value)
    elif kind == 'true':
        value = True
    elif kind == 'false':
        value = False
    return {'exists': kind is not None, 'value': value}

def inbound_rows(c):
    # Only JSON projections are read; client settings, REALITY keys and TLS files are never selected.
    sql = """SELECT id,enable,protocol,tag,port,node_id,sniffing,
        json_extract(stream_settings,'$.network') AS network,
        json_extract(stream_settings,'$.security') AS security FROM inbounds ORDER BY id"""
    return [dict(r) for r in c.execute(sql)]

def identity(r):
    return {k: r[k] for k in ('id', 'enable', 'protocol', 'tag', 'port', 'node_id', 'network', 'security')}

def make_plan(c, cfg, ids=None, tags=None):
    schema(c)
    rows = inbound_rows(c)
    targets = []
    for r in rows:
        requested = (ids is not None and r['id'] in ids) or (tags is not None and r['tag'] in tags)
        supported = r['protocol'] in PROTOCOLS and (r['network'] or 'tcp') in NETWORKS
        local = r['node_id'] in (None, 0)
        if requested and (not supported or not local or not r['enable']):
            raise Refuse('Explicit target is disabled, remote, Hysteria or unsupported: ID ' + str(r['id']))
        if r['enable'] and supported and local and ((ids is None and tags is None) or requested):
            targets.append(r)
    if ids is not None and not ids <= {r['id'] for r in targets}:
        raise Refuse('Some requested IDs were not found.')
    if tags is not None and not tags <= {r['tag'] for r in targets}:
        raise Refuse('Some requested tags were not found.')
    if not targets:
        raise Refuse('No supported enabled local inbounds selected.')
    plan = {'format': FORMAT, 'targets': [identity(r) for r in targets], 'sniffing': [], 'template': [], 'warnings': []}
    def warn(message):
        plan['warnings'].append(message)
    for r in targets:
        before = r['sniffing']
        s = json.loads(before) if before and before.strip() else {}
        if not isinstance(s, dict):
            raise Refuse('Invalid sniffing object: ID ' + str(r['id']))
        after = copy.deepcopy(s)
        overrides = after.setdefault('destOverride', [])
        if not isinstance(overrides, list):
            raise Refuse('Invalid sniffing destOverride.')
        for protocol in ['http', 'tls']:
            if protocol not in overrides:
                overrides.append(protocol)
        after['enabled'] = True
        # Missing flags already default to false; avoid cosmetic changes on working inbounds.
        for flag in ['metadataOnly', 'routeOnly']:
            if flag in after:
                after[flag] = False
        if s != after:
            plan['sniffing'].append({'identity': identity(r), 'before': before, 'after': encode(after)})

    guards = {}
    def get(path):
        val = path_value(c, path); guards[path] = val
        return val['value']
    def change(path, after):
        before = path_value(c, path); guards[path] = before
        if not before['exists'] or before['value'] != after:
            plan['template'].append({'path': path, 'before': before, 'after': {'exists': True, 'value': after}})

    dns = get('$.dns')
    if dns is None:
        dns = {}
    if not isinstance(dns, dict):
        raise Refuse('Invalid DNS object.')
    servers = copy.deepcopy(dns.get('servers', []))
    if not isinstance(servers, list):
        raise Refuse('Invalid DNS servers.')
    match = 'geosite:' + cfg['geosite']
    matches = []
    mixed = False
    for index, server in enumerate(servers):
        if isinstance(server, str) and server == cfg['dns_url']:
            raise Refuse('Proxy DNS is already a global DNS server; manual review required.')
        if isinstance(server, dict):
            domains = server.get('domains', [])
            if match in domains:
                if domains != [match]:
                    mixed = True
                    warn('DNS-правило %d объединяет Gemini с другими доменами. Gemini будет выделен в отдельное правило, остальные домены сохранят прежний DNS.' % index)
                matches.append(index)
            elif server.get('tag') in ('geohide', 'dns-proxy', 'gemini-proxy-dns'):
                warn('DNS-тег %s принадлежит другому правилу. Оно сохраняется; новому правилу Gemini будет выбран свободный тег.' % server.get('tag'))
            elif server.get('address') == cfg['dns_url']:
                warn('Выбранный DNS-Proxy уже используется вне Gemini. Это существующее правило сохраняется.')
            elif domains:
                warn('Дополнительное DNS-правило %d может пересекаться с Gemini. Оно сохраняется; работоспособность нужно проверить клиентом.' % index)
            if urlsplit(server.get('address', '')).username or urlsplit(server.get('address', '')).password:
                raise Refuse('DNS URLs containing credentials are not supported.')
    if len(matches) > 1:
        warn('Найдено несколько DNS-правил Gemini: %s. Они будут объединены в одно; правила остальных доменов сохранятся.' % ', '.join(map(str, matches)))
    if not any(isinstance(s, str) or (isinstance(s, dict) and not s.get('domains') and not s.get('skipFallback', False)) for s in servers):
        if servers:
            raise Refuse('No ordinary fallback DNS server; manual review required.')
        servers.extend(cfg['regular_dns'])
    wanted = {'address': cfg['dns_url'], 'domains': [match], 'skipFallback': True, 'finalQuery': True,
              'queryStrategy': 'UseIPv4', 'disableCache': True, 'timeoutMs': cfg.get('timeout_ms', 4000)}
    if len(matches) == 1 and not mixed:
        server = servers[matches[0]]
        if server.get('expectedIPs') or server.get('unexpectedIPs') or server.get('expectIPs'):
            raise Refuse('Gemini DNS has custom IP filters; manual review required.')
        server.update(wanted)
    elif matches:
        remaining = []
        for i, server in enumerate(servers):
            if i not in matches:
                remaining.append(server)
            else:
                rest = [d for d in server.get('domains', []) if d != match]
                if rest:
                    server['domains'] = rest
                    remaining.append(server)
        used_tags = {s.get('tag') for s in remaining if isinstance(s, dict)}
        tag = 'dns-proxy'
        suffix = 1
        while tag in used_tags:
            suffix += 1; tag = 'dns-proxy-%d' % suffix
        servers = [dict(wanted, tag=tag)] + remaining
    else:
        used_tags = {s.get('tag') for s in servers if isinstance(s, dict)}
        tag = 'dns-proxy'; suffix = 1
        while tag in used_tags:
            suffix += 1; tag = 'dns-proxy-%d' % suffix
        servers.append(dict(wanted, tag=tag))
    desired_dns = copy.deepcopy(dns)
    desired_dns.update(servers=servers, queryStrategy='UseIPv4', disableFallbackIfMatch=True)
    change('$.dns', desired_dns)
    change('$.routing.domainStrategy', 'IPIfNonMatch')

    # Outbound fields are projected in SQL; SOCKS/WireGuard credentials are never read.
    outs = c.execute("""SELECT CAST(j.key AS INTEGER) AS idx,json_extract(j.value,'$.tag') AS tag,
        json_extract(j.value,'$.protocol') AS protocol FROM settings s,json_each(s.value,'$.outbounds') j
        WHERE s.key='xrayTemplateConfig'""").fetchall()
    direct = [r for r in outs if r['tag'] == cfg['direct_tag']]
    if not direct:
        candidates = [r for r in outs if r['protocol'] == 'freedom']
        if len(candidates) != 1:
            raise Refuse('Не найден однозначный freedom outbound. Укажите его тег в config.json; существующие outbound автоматически не создаются.')
        direct = candidates
        warn('Outbound с тегом %s отсутствует. UseIPv4 будет установлен у единственного freedom outbound с тегом %s; тег и порядок не меняются.' % (cfg['direct_tag'], direct[0]['tag']))
    if len(direct) != 1 or direct[0]['protocol'] != 'freedom':
        raise Refuse('Ожидаемый direct outbound не является однозначным freedom; нельзя безопасно заменить его протокол.')
    index = direct[0]['idx']
    if c.execute("SELECT json_type(value,?) FROM settings WHERE key='xrayTemplateConfig'", ('$.outbounds[%d].settings' % index,)).fetchone()[0] != 'object':
        raise Refuse('Expected an existing freedom settings object.')
    guards['$.outbounds[%d].tag' % index] = path_value(c, '$.outbounds[%d].tag' % index)
    guards['$.outbounds[%d].protocol' % index] = path_value(c, '$.outbounds[%d].protocol' % index)
    change('$.outbounds[%d].settings.domainStrategy' % index, 'UseIPv4')

    rules = get('$.routing.rules') or []
    if not isinstance(rules, list):
        raise Refuse('Invalid routing rules.')
    # Preserve every route. Refuse possible conflicting domain rules instead of silently rewriting them.
    for rule in rules:
        if not isinstance(rule, dict):
            raise Refuse('Invalid routing rule.')
        # Deployment precondition: Gemini -> WARP is already absent or disabled.
        # Do not inspect its enabled flag, disable it or make it a patch blocker.
        if rule.get('outboundTag') == 'warp' and rule.get('domain') == [match]:
            continue
        if rule.get('enabled', True) is False:
            continue
        if rule.get('outboundTag') == direct[0]['tag']:
            continue
        scope = rule.get('inboundTag', [])
        if scope and not set(scope) & {r['tag'] for r in targets}:
            continue
        if rule.get('domain'):
            safe_ru = {'geosite:category-ru', 'regexp:.*\\.ru$', 'regexp:.*\\.su$', 'regexp:.*\\.xn--p1ai$'}
            if not set(rule['domain']) <= safe_ru:
                warn('Активный domain-маршрут %s → %s может перехватить Gemini. Маршрут сохраняется; при продолжении доступ к Gemini не гарантируется.' % (', '.join(rule['domain']), rule.get('outboundTag', '<balancer>')))
        elif rule.get('outboundTag') not in ('api', 'blocked'):
            warn('Общий маршрут к %s может перехватить Gemini. Он сохраняется.' % rule.get('outboundTag', '<balancer>'))
    if not outs or outs[0]['tag'] != direct[0]['tag']:
        warn('Первый/default outbound %s отличается от freedom %s. Порядок сохраняется; после установки проверьте Gemini.' % (outs[0]['tag'] if outs else '<none>', direct[0]['tag']))
    plan['guards'] = guards
    return plan

def check_xray(binary, geosite, cfg):
    version = subprocess.run([binary, 'version'], capture_output=True, text=True, timeout=15, check=True).stdout
    m = re.search(r'Xray (\d+)\.(\d+)\.(\d+)', version)
    if not m or tuple(map(int, m.groups())) < (26, 9, 9):
        raise Refuse('Xray >= 26.9.9 required; older versions have not been validated.')
    probe = {'log': {'loglevel': 'error'}, 'inbounds': [],
             'outbounds': [{'tag': 'direct', 'protocol': 'freedom', 'settings': {'domainStrategy': 'UseIPv4'}}],
             'dns': {'servers': [dict(address=cfg['dns_url'], domains=['geosite:' + cfg['geosite']],
                                      skipFallback=True, finalQuery=True, queryStrategy='UseIPv4')],
                     'queryStrategy': 'UseIPv4', 'disableFallbackIfMatch': True},
             'routing': {'domainStrategy': 'IPIfNonMatch', 'rules': []}}
    env = dict(os.environ, XRAY_LOCATION_ASSET=str(Path(geosite).resolve().parent))
    # Linux /dev/stdin avoids writing test configuration or accessing production key files.
    test = subprocess.run([binary, 'run', '-test', '-format', 'json', '-c', '/dev/stdin'],
                          input=encode(probe), capture_output=True, text=True, env=env, timeout=30)
    if test.returncode or 'Configuration OK' not in test.stdout + test.stderr:
        raise Refuse('Xray compatibility probe failed; production configuration has not been touched.')
    return version.splitlines()[0]

def write_state(path, value):
    p = Path(path)
    if not p.parent.is_dir():
        raise Refuse('Create a private state directory first.')
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(value, f, ensure_ascii=False, indent=2); f.flush(); os.fsync(f.fileno())

def update_template(c, path, val):
    if val['exists']:
        c.execute("UPDATE settings SET value=json_set(value,?,json(?)) WHERE key='xrayTemplateConfig'", (path, encode(val['value'])))
    else:
        c.execute("UPDATE settings SET value=json_remove(value,?) WHERE key='xrayTemplateConfig'", (path,))

def apply(c, cfg, args, plan):
    if not plan['sniffing'] and not plan['template']:
        print('Already configured; no database writes or state files.'); return
    if not args.state:
        raise Refuse('--state FILE is required for apply.')
    if plan.get('warnings') and not getattr(args, 'accept_warnings', False):
        raise Refuse('План содержит предупреждения. Используйте install для подтверждения или apply --accept-warnings после dry-run.')
    c.execute('BEGIN IMMEDIATE')
    try:
        live = make_plan(c, cfg, args.ids, args.tags)
        if live != plan:
            raise Refuse('Configuration changed since planning; rerun dry-run.')
        state = {'format': FORMAT, 'database': str(Path(args.db).resolve()),
                 'created_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'plan': plan}
        # The undo record is durably written BEFORE any DB update. It contains no clients, keys or certificates.
        write_state(args.state, state)
        for item in plan['sniffing']:
            c.execute('UPDATE inbounds SET sniffing=? WHERE id=?', (item['after'], item['identity']['id']))
        for item in plan['template']:
            update_template(c, item['path'], item['after'])
        remaining = make_plan(c, cfg, args.ids, args.tags)
        if remaining['sniffing'] or remaining['template']:
            raise Refuse('Post-write verification failed.')
        c.commit()
    except BaseException:
        c.rollback(); raise
    print('Database changes committed. Undo record:', args.state)
    print('Services were not restarted. Activate through the panel or a separately approved x-ui restart.')

def rollback(c, args):
    if not args.state:
        raise Refuse('--state FILE is required for rollback.')
    state = json.loads(Path(args.state).read_text(encoding='utf-8'))
    if state.get('format') not in (FORMAT, 'gemini-dns-patch-v1') or state.get('database') != str(Path(args.db).resolve()):
        raise Refuse('Undo record does not belong to this database.')
    plan = state['plan']; c.execute('BEGIN IMMEDIATE')
    try:
        schema(c); rows = {r['id']: r for r in inbound_rows(c)}
        for target in plan['targets']:
            if target['id'] not in rows or identity(rows[target['id']]) != target:
                raise Refuse('Inbound identity changed; automatic rollback refused.')
        for item in plan['sniffing']:
            if rows[item['identity']['id']]['sniffing'] != item['after']:
                raise Refuse('Sniffing changed after apply; automatic rollback refused.')
        for item in plan['template']:
            if path_value(c, item['path']) != item['after']:
                raise Refuse('Patched setting changed after apply; automatic rollback refused.')
        for path, val in plan['guards'].items():
            if path not in {i['path'] for i in plan['template']} and path_value(c, path) != val:
                raise Refuse('Related configuration changed; automatic rollback refused.')
        for item in plan['sniffing']:
            c.execute('UPDATE inbounds SET sniffing=? WHERE id=?', (item['before'], item['identity']['id']))
        for item in reversed(plan['template']):
            update_template(c, item['path'], item['before'])
        c.commit()
    except BaseException:
        c.rollback(); raise
    print('Only patched fields restored. Services were not restarted.')

def ask(prompt, choices=None, default=None):
    while True:
        try:
            if sys.stdin.isatty():
                answer = input(prompt).strip()
            else:
                with open('/dev/tty', 'r+', encoding='utf-8') as tty:
                    tty.write(prompt); tty.flush(); answer = tty.readline().strip()
                    if not answer and default is None:
                        raise Refuse('Терминал закрыт. Неподтверждённые действия не выполняются.')
        except (EOFError, OSError) as exc:
            raise Refuse('Нужен интерактивный терминал. Для диагностики используйте dry-run.') from exc
        if not answer and default is not None:
            answer = default
        if choices is None or answer in choices:
            return answer
        print('Выберите один из показанных вариантов.')

def choose_provider(cfg, providers_path):
    providers = json.loads(Path(providers_path).read_text(encoding='utf-8-sig'))['providers']
    print('\nКакой DNS-Proxy использовать? (По умолчанию — для Gemini)')
    for i, provider in enumerate(providers, 1):
        print('%d — %s: %s' % (i, provider['name'], provider['doh']))
    custom = str(len(providers) + 1)
    print(custom + ' — Свой DNS-Proxy')
    selected = ask('Вариант [1]: ', {str(i) for i in range(1, len(providers) + 2)}, '1')
    if selected != custom:
        provider = providers[int(selected) - 1]
        print('Источник адресов: ' + provider['source'])
        if provider.get('primary_ipv4'):
            print('1 — DoH: полный HTTPS URL (рекомендуется)')
            print('2 — Обычный DNS: основной IPv4 %s; дополнительный %s здесь автоматически не используется' % (provider['primary_ipv4'], provider.get('secondary_ipv4', 'не указан')))
            kind = ask('Протокол [1]: ', {'1', '2'}, '1')
            address = provider['doh'] if kind == '1' else provider['primary_ipv4']
        else:
            address = provider['doh']
    else:
        print('1 — DNS-over-HTTPS: полный URL из раздела DoH, например https://dns.bezmezhau.com/dns-query')
        print('2 — Обычный DNS-over-UDP: один IPv4 из раздела IPv4 DNS, например 143.20.64.55')
        print('Не вводите URL главной страницы, DoT-имя, IPv6, IP прокси из hosts или IP, полученный в ответе для Gemini.')
        print('Если опубликованы Primary и Secondary: здесь вводится только Primary. Не вводите два адреса через запятую.')
        kind = ask('Тип адреса [1]: ', {'1', '2'}, '1')
        while True:
            address = ask('Полный DoH URL: ' if kind == '1' else 'Основной IPv4 DNS: ')
            try:
                validate_address(address)
                if (kind == '1') != address.startswith('https://'):
                    raise Refuse('Адрес не соответствует выбранному типу.')
                break
            except Refuse as exc:
                print(str(exc))
    validate_address(address)
    cfg = copy.deepcopy(cfg); cfg['dns_url'] = address
    print('Выбран DNS-Proxy: ' + address)
    print('Патч направляет сюда только google-gemini; обычные DNS сохраняются.')
    return cfg

def show_plan(plan):
    print('\nВыбранные локальные inbound:', ', '.join(str(r['id']) + ':' + r['protocol'] + '/' + str(r['network'] or 'tcp') for r in plan['targets']))
    print('Изменения sniffing:', ', '.join(str(r['identity']['id']) for r in plan['sniffing']) or 'нет')
    print('Общие изменения:', ', '.join(r['path'] for r in plan['template']) or 'нет')
    for i, warning in enumerate(plan.get('warnings', []), 1):
        print('ПРЕДУПРЕЖДЕНИЕ %d: %s' % (i, warning))
    if plan['template']:
        print('DNS/direct общие для Xray: изменения могут затронуть Hysteria и другие исключённые inbound.')
    print('Пользователи, ключи, сертификаты, порты и существующие маршруты не обновляются.')

def service_active(service):
    result = subprocess.run(['systemctl', 'is-active', '--quiet', service], timeout=15)
    return result.returncode == 0

def restart_service(service):
    print('Активация: перезапуск ' + service)
    subprocess.run(['systemctl', 'restart', service], check=True, timeout=90)
    print('Ожидание запуска Xray: до 30 секунд')
    # Refresh MainPID on every attempt: the panel may still be starting.
    for attempt in range(30):
        if service_active(service):
            result = subprocess.run(['systemctl', 'show', service, '--property=MainPID', '--value'], capture_output=True, text=True, check=True, timeout=15)
            pid = result.stdout.strip()
            if pid.isdigit() and int(pid) > 0:
                try:
                    children = Path('/proc/%s/task/%s/children' % (pid, pid))
                    for child in children.read_text().split():
                        try:
                            if 'xray' in Path('/proc/%s/comm' % child).read_text().lower():
                                return
                        except (FileNotFoundError, ProcessLookupError):
                            continue
                except (FileNotFoundError, ProcessLookupError):
                    pass
        time.sleep(1)
    if not service_active(service):
        raise Refuse('Сервис не запустился после активации за 30 секунд.')
    raise Refuse('Панель запущена, но процесс Xray не подтверждён за 30 секунд. Требуется откат или диагностика.')

def install(c, cfg, args):
    if os.geteuid() != 0:
        raise Refuse('Установка требует root: sudo python3 dns_proxy.py install')
    if not service_active(args.service):
        raise Refuse('Сервис не был активен до установки. Автоматическое применение отменено.')
    plan = make_plan(c, cfg, args.ids, args.tags)
    show_plan(plan)
    if not plan['sniffing'] and not plan['template']:
        print('Уже настроено. БД не записывается, сервис не перезапускается.')
        print('Проверьте Gemini, Gmail, YouTube и GitHub. Нового применения и новой записи отката нет.'); return
    print('Gemini → WARP считается заранее отключённым или отсутствующим; патч эти правила не управляет.')
    if plan.get('warnings'):
        print('Продолжение означает принятие всех показанных предупреждений. Конфликтующие маршруты не исправляются автоматически.')
    if ask('Применить план и перезапустить сервис? 1 — да, 2 — отмена [2]: ', {'1', '2'}, '2') != '1':
        print('Отменено. Настройки сервера не изменены.'); return
    args.accept_warnings = True
    if not args.state:
        directory = Path(args.db).resolve().parent / 'dns-proxy-state'
        if directory.is_symlink():
            raise Refuse('Каталог отката не должен быть символической ссылкой.')
        directory.mkdir(mode=0o700, exist_ok=True)
        if directory.stat().st_uid != 0 or directory.stat().st_mode & 0o077:
            raise Refuse('Каталог отката должен принадлежать root и иметь права 0700.')
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        args.state = str(directory / (stamp + '-' + uuid.uuid4().hex[:8] + '.json'))
    apply(c, cfg, args, plan)
    import shlex
    script = str(Path(__file__).resolve())
    manual = 'sudo python3 ' + shlex.quote(script) + ' rollback --restart --db ' + shlex.quote(args.db) + ' --state ' + shlex.quote(args.state) + ' --service ' + shlex.quote(args.service)
    print('Команда последующего отката:', manual)
    def undo_and_activate():
        rollback(c, args)
        restart_service(args.service)
        print('Откат завершён и активирован. Запись отката сохранена для аудита.')
    try:
        restart_service(args.service)
        live = make_plan(c, cfg, args.ids, args.tags)
        if live['sniffing'] or live['template']:
            raise Refuse('Настройки изменились во время активации.')
    except (Refuse, OSError, subprocess.SubprocessError) as exc:
        print('Ошибка активации:', exc)
        print('Возвращаем только поля этого применения, затем повторно запускаем сервис.')
        undo_and_activate()
        raise Refuse('Установка отменена из-за ошибки активации; выполнен откат.')
    print('\nПроверьте реальным клиентом каждый нужный inbound:')
    print('gemini.google.com, mail.google.com, www.youtube.com, github.com')
    print('Полностью перезапустите браузер при переключении inbound.')
    print('1 — Всё работает, завершить')
    print('2 — Сайты не работают: откатить изменения и перезапустить сервис')
    print('3 — Проверю позже: оставить настройки и сохранить команду отката')
    print('Для последующего отката:', manual)
    try:
        answer = ask('Результат проверки [3]: ', {'1', '2', '3'}, '3')
    except (Refuse, KeyboardInterrupt):
        print('Проверка не завершена; настройки оставлены. Команда отката:', manual); return
    if answer == '2':
        undo_and_activate()
    elif answer == '1':
        print('Установка завершена. Пользователь подтвердил проверку сайтов.')
    else:
        print('Настройки оставлены. Клиентская проверка ещё не подтверждена.')

def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('action', choices=['install', 'dry-run', 'apply', 'verify', 'rollback'])
    p.add_argument('--db', default='/etc/x-ui/x-ui.db')
    p.add_argument('--config', default=str(Path(__file__).with_name('config.json')))
    p.add_argument('--geosite', default='/usr/local/x-ui/bin/geosite.dat')
    p.add_argument('--xray', default='/usr/local/x-ui/bin/xray-linux-amd64')
    p.add_argument('--state')
    p.add_argument('--providers', default=str(Path(__file__).with_name('providers.json')))
    p.add_argument('--dns', help='Один полный DoH URL или один IPv4 DNS; в install заменяет меню провайдеров')
    p.add_argument('--accept-warnings', action='store_true', help='Только apply: явное принятие предупреждений плана')
    p.add_argument('--restart', action='store_true', help='apply/rollback: активировать изменения через перезапуск')
    p.add_argument('--service', default='x-ui')
    selection = p.add_mutually_exclusive_group()
    selection.add_argument('--ids', help='Comma-separated local inbound IDs')
    selection.add_argument('--tags', help='Comma-separated local inbound tags')
    args = p.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_@][A-Za-z0-9_.@-]*', args.service):
        raise Refuse('Некорректное имя systemd-сервиса.')
    args.ids = set(map(int, args.ids.split(','))) if args.ids else None
    args.tags = set(args.tags.split(',')) if args.tags else None
    if args.action == 'install':
        cfg = config(args.config)
        if args.dns:
            cfg['dns_url'] = validate_address(args.dns)
        else:
            cfg = choose_provider(cfg, args.providers)
    with connect(args.db, args.action in ('install', 'apply', 'rollback')) as c:
        if args.action == 'rollback':
            rollback(c, args)
            if args.restart:
                restart_service(args.service)
            return
        if args.action != 'install':
            cfg = config(args.config)
            if args.dns:
                cfg['dns_url'] = validate_address(args.dns)
        check_geosite(args.geosite, cfg['geosite'])
        print(check_xray(args.xray, args.geosite, cfg))
        if args.action == 'install':
            install(c, cfg, args); return
        plan = make_plan(c, cfg, args.ids, args.tags)
        show_plan(plan)
        if args.action == 'apply':
            apply(c, cfg, args, plan)
            if args.restart and (plan['sniffing'] or plan['template']):
                restart_service(args.service)
        elif args.action == 'verify' and (plan['sniffing'] or plan['template']):
            raise Refuse('Saved database configuration is not fully configured.')
        elif args.action == 'verify':
            print('Saved database settings verified; this is not a live traffic test.')

if __name__ == '__main__':
    try:
        main()
    except (Refuse, ValueError, KeyError, TypeError, OSError, sqlite3.Error, subprocess.SubprocessError) as exc:
        print('REFUSED:', str(exc), file=sys.stderr); sys.exit(2)
