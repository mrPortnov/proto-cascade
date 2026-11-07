#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Origin: https://github.com/anten-ka/kaskad
# Upstream declares MIT in README.md at commit
# 68885d518e60a6e6dd9f52f4f06c6e63baa0dc23; see UPSTREAM-NOTICE.md.
# Unofficial reimplementation; not an upstream release.
#
# MIT License
#
# Copyright (c) anten-ka (upstream kaskad)
# Copyright (c) 2026 mrPortnov (new implementation and modifications)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
# associated documentation files (the "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
# following conditions:
#
# The above copyright notice and this permission notice shall be included in all copies or substantial
# portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT
# LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO
# EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
# USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# proto-cascade: standalone IPv4/IPv6 forwarding manager.
# Runtime: Ubuntu 24.04 / Debian 12+, Bash and Python 3. No downloaded code.
set -Eeuo pipefail
export PATH='/usr/sbin:/usr/bin:/sbin:/bin'
case "${1:-}" in
    --install|install)
        [[ $(uname -s) == Linux && $EUID -eq 0 ]] || {
            printf '%s\n' 'Установка требует Linux и root (sudo bash install-proto-cascade.sh --install).' >&2
            exit 1
        }
        if ! command -v python3 >/dev/null || ! command -v iptables >/dev/null || ! command -v ip >/dev/null; then
            command -v apt-get >/dev/null || { printf '%s\n' 'Нужны python3, iptables и iproute2.' >&2; exit 1; }
            apt-get update -qq
            DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 iptables iproute2
        fi
        ;;
esac
command -v python3 >/dev/null || {
    printf '%s\n' 'Не найден Python 3. Установка: sudo bash install-proto-cascade.sh --install' >&2
    exit 1
}
PROTO_CASCADE_SOURCE=$(readlink -f -- "${BASH_SOURCE[0]}")
exec python3 - "$PROTO_CASCADE_SOURCE" "$@" 3<&0 <<'PROTO_CASCADE_PYTHON'
"""Self-contained manager. Importable without root for compiler/transaction tests."""
import argparse
import copy
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shlex
import signal
import shutil
import subprocess
import sys
import tempfile
import textwrap
from contextlib import contextmanager

VERSION = '3.0.0'
DIRECTORY = Path('/etc/proto-cascade')
CONFIG = DIRECTORY / 'rules.json'
BACKUP = DIRECTORY / 'rules.previous.json'
STATE = Path('/run/proto-cascade-state.json')
BIN = Path('/usr/local/bin/proto-cascade')
SYSCTL = Path('/etc/sysctl.d/99-proto-cascade.conf')
TAG = 'proto-cascade:v1'
CHAINS = {'filter': ['proto-cascade-FORWARD'], 'nat': ['proto-cascade-DNAT', 'proto-cascade-SNAT']}
PROTOCOLS = {'tcp': 6, 'udp': 17, 'sctp': 132, 'dccp': 33,
             'icmp': 1, 'icmpv6': 58, 'gre': 47, 'esp': 50, 'ah': 51}
PORT_PROTOCOLS = {'tcp', 'udp', 'sctp', 'dccp'}
COLOR = sys.stdout.isatty() and not os.environ.get('NO_COLOR') and os.environ.get('TERM') != 'dumb'


class Error(Exception):
    pass


def say(message, kind='info'):
    colors = {'info': '36', 'ok': '32', 'error': '31', 'warn': '33'}
    labels = {'info': '·', 'ok': '✓ Готово', 'error': '× Ошибка', 'warn': '! Важно'}
    label = labels[kind]
    if COLOR:
        label = '\033[' + colors[kind] + 'm' + label + '\033[0m'
    print(f'  {label}  {message}', file=sys.stderr if kind == 'error' else sys.stdout, flush=True)


def paint(value, code='36'):
    return f'\033[{code}m{value}\033[0m' if COLOR else str(value)


def width():
    return max(46, min(74, shutil.get_terminal_size((80, 24)).columns - 4))


def heading(title, subtitle=None):
    inner = width() - 2
    print('\n  ' + paint('╭' + '─' * inner + '╮', '2;36'))
    for text in (title, subtitle):
        if text:
            for line in textwrap.wrap(text, inner - 4):
                print('  ' + paint('│', '2;36') + '  ' + paint(line.ljust(inner - 4), '1;37') + '  ' + paint('│', '2;36'))
    print('  ' + paint('╰' + '─' * inner + '╯', '2;36'))


def section(title, hint=None):
    print('\n  ' + paint(title, '1;36'))
    if hint:
        for line in textwrap.wrap(hint, width() - 2):
            print('  ' + paint(line, '2'))


def endpoint(ip, port=None):
    host = f'[{ip}]' if ':' in ip else ip
    return host + (f':{port}' if port is not None else '')


def display_rule(rule):
    print('  ' + paint(rule['id'], '1;37') + '  ' + paint(rule['protocol'].upper(), '36'))
    route = endpoint(rule['listen'], rule.get('in_port')) + '  →  ' + endpoint(rule['target'], rule.get('out_port'))
    for line in textwrap.wrap(route, width() - 4, break_long_words=False, break_on_hyphens=False):
        print('    ' + line)
    scope = 'все порты' if 'in_port' not in rule else 'перенаправление порта'
    detail = f'{rule["interface"]} · {scope} · источник {rule["source"]}'
    for line in textwrap.wrap(detail, width() - 4):
        print('    ' + paint(line, '2'))
    if rule.get('snat', 'masquerade') == 'none':
        print('    ' + paint('Сохранение IP клиента · нужен обратный маршрут', '33'))


def run(argv, data=None, ok=True):
    try:
        result = subprocess.run([str(a) for a in argv], input=data, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                encoding='utf-8', errors='replace', timeout=90)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Error(f'{argv[0]}: {exc}') from exc
    if ok and result.returncode:
        raise Error(f'{shlex.join([str(a) for a in argv])}: {result.stderr.strip() or result.stdout.strip()}')
    return result


def root():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise Error('Для изменения сети нужны Linux и root. Запустите команду через sudo.')


@contextmanager
def locked():
    root()
    import fcntl
    with open('/run/lock/proto-cascade.lock', 'a', encoding='utf-8') as stream:
        try:
            fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Error('Другая операция proto-cascade уже выполняется.') from exc
        yield


def atomic_write(path, text, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '.', dir=path.parent)
    try:
        with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def dump(config):
    return json.dumps(config, ensure_ascii=False, indent=2) + '\n'


def empty_config():
    return {'version': 2, 'protected_tcp_ports': [22], 'rules': []}


def port(value):
    if isinstance(value, bool) or not re.fullmatch(r'[0-9]{1,5}', str(value)):
        raise Error('Порт должен быть целым числом от 1 до 65535.')
    result = int(str(value), 10)
    if not 1 <= result <= 65535:
        raise Error('Порт должен быть в диапазоне 1–65535.')
    return result


def address(value):
    if not isinstance(value, str) or '%' in value:
        raise Error('IP-адрес должен быть строкой без zone ID.')
    try:
        value = ipaddress.ip_address(value)
    except ValueError as exc:
        raise Error(f'Некорректный IP-адрес: {value}') from exc
    if value.is_unspecified or value.is_multicast or value.is_loopback or value.is_link_local:
        raise Error(f'Нужен unicast IP без loopback/link-local: {value}')
    if value.version == 4 and int(value) == 0xffffffff:
        raise Error('Широковещательный адрес недопустим.')
    if value.version == 6 and value.ipv4_mapped:
        raise Error('Используйте обычный IPv4, а не IPv4-mapped IPv6.')
    return value


def protocols(value, family):
    value = str(value).lower()
    if value == 'all':
        return [None]
    if value == 'tcp+udp':
        return [6, 17]
    if value in PROTOCOLS:
        number = PROTOCOLS[value]
    elif re.fullmatch(r'[0-9]{1,3}', value) and 1 <= int(value) <= 255:
        number = int(value)
    else:
        raise Error('Протокол: all, tcp, udp, tcp+udp, sctp, dccp, icmp, icmpv6, gre, esp, ah или 1–255.')
    if (family == 4 and number == 58) or (family == 6 and number == 1):
        raise Error('ICMP относится к IPv4, ICMPv6 — к IPv6.')
    if family == 6 and number in {43, 44, 59, 60}:
        raise Error('Заголовки расширения IPv6 не являются транспортным протоколом. Используйте all.')
    return [number]


def validate(config):
    if not isinstance(config, dict) or config.get('version') != 2:
        raise Error('Ожидается JSON-конфигурация version=2.')
    if set(config) - {'version', 'protected_tcp_ports', 'rules'}:
        raise Error('Неизвестное поле конфигурации.')
    result = empty_config()
    protected = config.get('protected_tcp_ports', [22])
    if not isinstance(protected, list):
        raise Error('protected_tcp_ports должен быть списком портов.')
    result['protected_tcp_ports'] = sorted({port(p) for p in protected})
    rules = config.get('rules', [])
    if not isinstance(rules, list) or len(rules) > 500:
        raise Error('rules должен быть списком не более чем из 500 правил.')
    seen = set()
    for index, item in enumerate(rules, 1):
        if not isinstance(item, dict):
            raise Error(f'Правило {index} должно быть объектом.')
        required = {'id', 'interface', 'listen', 'target', 'protocol'}
        allowed = required | {'source', 'in_port', 'out_port', 'snat'}
        if required - set(item) or set(item) - allowed:
            raise Error(f'Правило {index}: проверьте обязательные и неизвестные поля.')
        rule = dict(item)
        name = rule['id']
        if not isinstance(name, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,32}', name) or name in seen:
            raise Error('ID должен быть уникальным и содержать 1–32 буквы, цифры, _ или -.')
        seen.add(name)
        if not isinstance(rule['interface'], str) or not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', rule['interface']):
            raise Error(f'{name}: некорректное имя интерфейса.')
        if rule['interface'] == 'lo' or re.match(r'^(docker|br-|veth)', rule['interface']):
            raise Error(f'{name}: вход через loopback/Docker bridge не поддерживается.')
        listen, target = address(rule['listen']), address(rule['target'])
        if listen.version != target.version or listen == target:
            raise Error(f'{name}: нужны разные адреса одной семьи IPv4 или IPv6.')
        rule['listen'], rule['target'] = str(listen), str(target)
        rule['protocol'] = str(rule['protocol']).lower()
        proto = protocols(rule['protocol'], listen.version)
        try:
            source = ipaddress.ip_network(rule.get('source', '0.0.0.0/0' if listen.version == 4 else '::/0'), strict=False)
        except ValueError as exc:
            raise Error(f'{name}: некорректная сеть источника.') from exc
        if source.version != listen.version:
            raise Error(f'{name}: сеть источника относится к другой семье IP.')
        rule['source'] = str(source)
        rule['snat'] = rule.get('snat', 'masquerade')
        if rule['snat'] not in ('masquerade', 'none'):
            raise Error(f'{name}: snat должен быть masquerade или none.')
        if 'in_port' in rule or 'out_port' in rule:
            if proto not in ([6], [17], [132], [33], [6, 17]):
                raise Error(f'{name}: порты допустимы только для TCP, UDP, SCTP и DCCP.')
            if 'in_port' not in rule:
                raise Error(f'{name}: не указан in_port.')
            rule['in_port'] = port(rule['in_port'])
            rule['out_port'] = port(rule.get('out_port', rule['in_port']))
            if 6 in proto and rule['in_port'] in result['protected_tcp_ports']:
                raise Error(f'{name}: TCP {rule["in_port"]} зарезервирован для управления сервером.')
        result['rules'].append(rule)
    # Reject intersecting selectors. Rule order must never silently shadow another target.
    for i, left in enumerate(result['rules']):
        for right in result['rules'][i + 1:]:
            if (left['interface'], left['listen']) != (right['interface'], right['listen']):
                continue
            if not ipaddress.ip_network(left['source']).overlaps(ipaddress.ip_network(right['source'])):
                continue
            family = ipaddress.ip_address(left['listen']).version
            lp, rp = protocols(left['protocol'], family), protocols(right['protocol'], family)
            if None not in lp + rp and not set(lp).intersection(rp):
                continue
            if 'in_port' in left and 'in_port' in right and left['in_port'] != right['in_port']:
                continue
            raise Error(f'Пересекаются правила {left["id"]} и {right["id"]}. Разделите адреса, сети или порты.')
    return result


def load(path=None):
    path = CONFIG if path is None else path
    try:
        return validate(json.loads(Path(path).read_text(encoding='utf-8')))
    except (OSError, ValueError, TypeError) as exc:
        raise Error(f'Не удалось прочитать {path}: {exc}') from exc


def families(config):
    return {4} | {ipaddress.ip_address(r['listen']).version for r in config['rules']}


def xtables_join(parts):
    # iptables-restore is not a shell. In particular, shell single quotes around
    # an IPv6 [address]:port may be interpreted literally by its parser.
    return ' '.join(json.dumps(str(p), ensure_ascii=False)
                    if re.search(r'[\s"\\]', str(p)) else str(p) for p in parts)


def compile_rules(config, family):
    """Compile only owned chain contents. No shell, policy changes or global flushes."""
    config = validate(config)
    rows = {chain: [] for group in CHAINS.values() for chain in group}

    def add(chain, parts):
        rows[chain].append(xtables_join(['-A', chain] + [str(p) for p in parts]))

    selected = [r for r in config['rules'] if ipaddress.ip_address(r['listen']).version == family]
    for rule in selected:
        iface, listen, target = rule['interface'], rule['listen'], rule['target']
        host = listen + ('/32' if family == 4 else '/128')
        selector = ['-i', iface, '-d', host]
        if ipaddress.ip_network(rule['source']).prefixlen:
            selector += ['-s', rule['source']]
        # Management ports are protected even in all-protocol / all-port mode.
        for protected in config['protected_tcp_ports']:
            add('proto-cascade-DNAT', selector + ['-p', 'tcp', '-m', 'tcp', '--dport', protected,
                '-m', 'comment', '--comment', TAG + ':ssh', '-j', 'RETURN'])
        # Preserve IPv6 neighbour discovery and router advertisements.
        if family == 6:
            for kind in range(133, 138):
                add('proto-cascade-DNAT', selector + ['-p', 'ipv6-icmp', '-m', 'icmp6', '--icmpv6-type', kind,
                    '-m', 'comment', '--comment', TAG + ':ndp', '-j', 'RETURN'])
        for proto in protocols(rule['protocol'], family):
            incoming = selector.copy()
            if proto is not None:
                incoming += ['-p', proto]
            destination = target
            if 'in_port' in rule:
                module = {6: 'tcp', 17: 'udp', 132: 'sctp', 33: 'dccp'}[proto]
                incoming += ['-m', module, '--dport', rule['in_port']]
                destination = f'[{target}]:{rule["out_port"]}' if family == 6 else f'{target}:{rule["out_port"]}'
            comment = ['-m', 'comment', '--comment', TAG + ':' + rule['id']]
            add('proto-cascade-DNAT', incoming + comment + ['-j', 'DNAT', '--to-destination', destination])
            # Original and reply tuples bind ACCEPT/SNAT to the exact DNAT mapping.
            # No packet/connection marks are reserved or overwritten.
            ct = ['-m', 'conntrack', '--ctstate', 'DNAT', '--ctorigdst', listen, '--ctreplsrc', target]
            if ipaddress.ip_network(rule['source']).prefixlen:
                ct += ['--ctorigsrc', rule['source']]
            if proto is not None:
                ct += ['--ctproto', proto]
            if 'in_port' in rule:
                ct += ['--ctorigdstport', rule['in_port'], '--ctreplsrcport', rule['out_port']]
            add('proto-cascade-FORWARD', ['-i', iface] + ct + ['--ctdir', 'ORIGINAL'] + comment + ['-j', 'ACCEPT'])
            add('proto-cascade-FORWARD', ['-o', iface] + ct + ['--ctdir', 'REPLY'] + comment + ['-j', 'ACCEPT'])
            if rule['snat'] == 'masquerade':
                add('proto-cascade-SNAT', ct + ['--ctdir', 'ORIGINAL'] + comment + ['-j', 'MASQUERADE'])
    return rows


def binary(family):
    return 'iptables' if family == 4 else 'ip6tables'


def snapshot(family, table):
    raw = run([binary(family) + '-save', '-t', table]).stdout
    declarations, lines, hooks, docker_nat_indices = set(), [], [], []
    indexes = {}
    for line in raw.splitlines():
        if line.startswith(':'):
            declarations.add(line.split()[0][1:])
        if not line.startswith('-A '):
            continue
        tokens = shlex.split(line)
        parent = tokens[1]
        indexes[parent] = indexes.get(parent, 0) + 1
        if parent == 'PREROUTING' and '-j' in tokens and tokens[tokens.index('-j') + 1] == 'DOCKER':
            docker_nat_indices.append(indexes[parent])
        if parent in CHAINS[table]:
            if '--comment' not in tokens or not tokens[tokens.index('--comment') + 1].startswith(TAG):
                raise Error(f'В {parent} найдены чужие правила. Изменение остановлено.')
            lines.append(line)
        elif '-j' in tokens and tokens[tokens.index('-j') + 1] in CHAINS[table]:
            hooks.append((indexes[parent], line))
    return {'chains': declarations, 'lines': lines, 'hooks': hooks, 'docker_nat_indices': docker_nat_indices}


def payload(table, current, rows=None, previous=None):
    """One table transaction; restore only our chains and references to them."""
    lines = ['*' + table] + [f':{c} - [0:0]' for c in CHAINS[table]]
    lines += ['-F ' + c for c in CHAINS[table]]
    for _, line in current['hooks']:
        lines.append('-D ' + line[3:])
    if previous is not None:
        lines += previous['lines']
        for index, line in previous['hooks']:
            tokens = shlex.split(line)
            lines.append(xtables_join(['-I', tokens[1], str(index)] + tokens[2:]))
        lines += ['-X ' + c for c in CHAINS[table] if c not in previous['chains']]
    else:
        for chain in CHAINS[table]:
            lines += rows[chain]
        active = bool(rows['proto-cascade-FORWARD'])
        if active and table == 'nat':
            # Appending after Docker DNAT gives published container ports priority.
            lines.append(f'-A PREROUTING -m addrtype --dst-type LOCAL -m comment --comment {TAG} -j proto-cascade-DNAT')
            lines.append(f'-A POSTROUTING -m comment --comment {TAG} -j proto-cascade-SNAT')
        if active and table == 'filter':
            lines.append(f'-I FORWARD 1 -m comment --comment {TAG} -j proto-cascade-FORWARD')
            if 'DOCKER-USER' in current['chains']:
                lines.append(f'-I DOCKER-USER 1 -m comment --comment {TAG} -j proto-cascade-FORWARD')
    return '\n'.join(lines + ['COMMIT', ''])


def restore(family, text, test=False):
    args = [binary(family) + '-restore', '--wait', '10', '--noflush']
    if test:
        args.append('--test')
    run(args, data=text)


def check_managed_firewall():
    # Ubuntu can keep ufw.service active (exited) even when UFW is disabled.
    if shutil.which('ufw'):
        status = run(['env', 'LC_ALL=C', 'ufw', 'status'], ok=False)
        if status.returncode:
            raise Error('Не удалось проверить ufw status. Изменение сети остановлено.')
        if re.search(r'^Status:\s+active\s*$', status.stdout, re.M):
            raise Error('Активен UFW. Сначала согласуйте правила маршрутизации с этим firewall; он не будет отключён.')
    if shutil.which('systemctl') and run(['systemctl', 'is-active', '--quiet', 'firewalld'], ok=False).returncode == 0:
        raise Error('Активен firewalld. Сначала согласуйте правила маршрутизации с этим firewall; он не будет отключён.')


def reject_legacy_chains(snapshot):
    # Historical names are required to identify installations predating the rename.
    if re.search(r'^:KASKAD2?-(?:DNAT|SNAT|INPUT|FORWARD|POSTROUTING)\s', snapshot, re.M):
        raise Error('Найдены цепочки предыдущей установки. Выполните переход по docs/MIGRATION.md перед установкой proto-cascade.')


def check_legacy_services():
    if not shutil.which('systemctl') or not Path('/run/systemd/system').exists():
        return
    units = ['kaskad.service', 'kaskad-v2.service', 'kaskad-v2-reconcile.timer']
    # Here ANY active/enabled old unit is intentionally a conflict.
    for action in ('is-active', 'is-enabled'):
        if run(['systemctl', action, '--quiet', *units], ok=False).returncode == 0:
            raise Error('Активна или включена служба предыдущей установки. Сначала выполните docs/MIGRATION.md.')


def environment(config, selected):
    for command in ['ip', 'sysctl'] + [binary(f) + suffix for f in selected for suffix in ('', '-save', '-restore')]:
        if not shutil.which(command):
            raise Error(f'Не найдена команда {command}. Сначала выполните --install.')
    versions = {f: run([binary(f), '--version']).stdout for f in selected}
    if len({'nft' if 'nf_tables' in v else 'legacy' for v in versions.values()}) != 1:
        raise Error('IPv4 и IPv6 используют разные firewall backend. Автопереключение запрещено.')
    check_managed_firewall()
    check_legacy_services()
    docker_file = Path('/etc/docker/daemon.json')
    if docker_file.exists():
        try:
            docker = json.loads(docker_file.read_text(encoding='utf-8'))
            if docker.get('firewall-backend') == 'nftables':
                raise Error('Docker native nftables пока не поддерживается. Нужен Docker с backend iptables.')
        except (ValueError, AttributeError) as exc:
            raise Error('Некорректный /etc/docker/daemon.json. Файл не изменён.') from exc
    if shutil.which('nft'):
        tables = run(['nft', 'list', 'tables'], ok=False).stdout
        if re.search(r'table ip6? docker-bridges\b', tables):
            raise Error('Обнаружен Docker native nftables. Нельзя обходить его DROP через iptables.')
    # Detect command-line Docker backend settings as well as daemon.json.
    for process in Path('/proc').glob('[0-9]*/cmdline'):
        try:
            args = process.read_bytes().split(b'\0')
        except (OSError, PermissionError):
            continue
        if args and Path(os.fsdecode(args[0])).name == 'dockerd':
            words = [os.fsdecode(a) for a in args]
            if '--firewall-backend=nftables' in words or any(words[i:i+2] == ['--firewall-backend', 'nftables'] for i in range(len(words))):
                raise Error('dockerd запущен с native nftables. Такая конфигурация не поддерживается.')
    for family in selected:
        alternate = binary(family) + ('-legacy-save' if 'nf_tables' in versions[family] else '-nft-save')
        if shutil.which(alternate):
            other = run([alternate], ok=False).stdout
            if re.search(r'^:(?:DOCKER\S*|KASKAD\S*|proto-cascade-\S*)\s', other, re.M):
                raise Error(f'В другом backend ({alternate}) найдены Docker/proto-cascade цепочки. Нужна ручная миграция.')
        existing = run([binary(family) + '-save'], ok=True).stdout
        reject_legacy_chains(existing)
    interfaces = json.loads(run(['ip', '-j', 'address', 'show']).stdout)
    local = {}
    for entry in interfaces:
        local[entry['ifname']] = {a['local'] for a in entry.get('addr_info', []) if 'local' in a}
    all_local = {ipaddress.ip_address(a) for values in local.values() for a in values}
    for rule in config['rules']:
        if rule['listen'] not in local.get(rule['interface'], set()):
            raise Error(f'{rule["id"]}: адрес {rule["listen"]} не назначен интерфейсу {rule["interface"]}.')
        if ipaddress.ip_address(rule['target']) in all_local:
            raise Error(f'{rule["id"]}: цель должна находиться на другой машине.')
        family = ipaddress.ip_address(rule['target']).version
        route = json.loads(run(['ip', '-j', f'-{family}', 'route', 'get', rule['target']]).stdout)
        if not route or not route[0].get('dev') or route[0].get('type') in ('unreachable', 'blackhole', 'prohibit', 'broadcast', 'multicast', 'local'):
            raise Error(f'{rule["id"]}: нет маршрута до цели.')
        if re.match(r'^(docker|br-|veth)', route[0]['dev']):
            raise Error(f'{rule["id"]}: цель находится в Docker-сети. Этот менеджер предназначен для других машин.')
    return versions


def forwarding_settings(config):
    settings = {'net.ipv4.ip_forward': '1'} if config['rules'] else {}
    ipv6_ifaces = {r['interface'] for r in config['rules'] if ':' in r['listen']}
    if ipv6_ifaces:
        # Enabling forwarding normally disables SLAAC. Preserve RA on receiving interfaces.
        interfaces = Path('/proc/sys/net/ipv6/conf')
        was_router = run(['sysctl', '-n', 'net.ipv6.conf.all.forwarding']).stdout.strip() == '1'
        if not was_router:
            if interfaces.exists():
                ipv6_ifaces |= {p.name for p in interfaces.iterdir() if p.name not in ('all', 'default', 'lo')
                               and not re.match(r'^(docker|br-|veth)', p.name)}
            for iface in sorted(ipv6_ifaces):
                # Slash form also supports VLAN interface names containing dots.
                key = f'net/ipv6/conf/{iface}/accept_ra'
                if run(['sysctl', '-n', key]).stdout.strip() == '1':
                    settings[key] = '2'
        settings['net.ipv6.conf.all.forwarding'] = '1'
    return settings


def signature(snapshots):
    values = []
    for key, snap in sorted(snapshots.items()):
        values.append([key, snap['lines'], [line for _, line in snap['hooks']]])
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def apply(config, persist=False, test=False, quiet=False):
    config = validate(config)
    prior = load() if CONFIG.exists() else empty_config()
    selected = families(config) | families(prior)
    # A removed IPv6 configuration must still have its old kernel chains cleared.
    if STATE.exists():
        try:
            selected |= set(json.loads(STATE.read_text(encoding='utf-8')).get('families', []))
        except (ValueError, OSError):
            pass
    environment(config, selected)
    original = {(f, t): snapshot(f, t) for f in sorted(selected) for t in CHAINS}
    rows = {f: compile_rules(config, f) for f in selected}
    scripts = {key: payload(key[1], snap, rows[key[0]]) for key, snap in original.items()}
    # Kernel parser checks every family/table before the first packet-changing commit.
    for (family, _), text in scripts.items():
        restore(family, text, test=True)
    if test:
        say('Конфигурация и проверка iptables-restore --test пройдены.', 'ok')
        return
    settings = forwarding_settings(config)
    old_sysctl = {key: run(['sysctl', '-n', key]).stdout.strip() for key in settings}
    old_sysctl_file = SYSCTL.read_text(encoding='utf-8') if SYSCTL.exists() else None
    # Do not disable shared forwarding when a family/rule is removed later.
    retained = {} if old_sysctl_file is None else dict(line.split('=', 1)
                for line in old_sysctl_file.splitlines() if '=' in line and not line.startswith('#'))
    retained.update(settings)
    sysctl_text = '# Managed by proto-cascade\n' + '\n'.join(f'{k}={v}' for k, v in retained.items()) + '\n'
    committed = []
    changed_sysctl = []
    try:
        # Filter first; NAT last. Existing Docker chains are never declared/flushed.
        for key, text in scripts.items():
            committed.append(key)  # Include an interrupted/partially failed restore in rollback.
            restore(key[0], text)
        for key, value in settings.items():
            if old_sysctl[key] != value:
                changed_sysctl.append(key)
                run(['sysctl', '-q', '-w', f'{key}={value}'])
        if settings:
            atomic_write(SYSCTL, sysctl_text, 0o644)
        if persist:
            # Backup failure also rolls back the kernel. Atomic config replace is last.
            if CONFIG.exists():
                atomic_write(BACKUP, dump(prior))
            atomic_write(CONFIG, dump(config))
    except BaseException as cause:
        failures = []
        for key in reversed(committed):
            try:
                restore(key[0], payload(key[1], snapshot(*key), previous=original[key]))
            except Error as exc:
                failures.append(str(exc))
        for key in reversed(changed_sysctl):
            try:
                run(['sysctl', '-q', '-w', f'{key}={old_sysctl[key]}'])
            except Error as exc:
                failures.append(str(exc))
        try:
            if old_sysctl_file is None:
                SYSCTL.unlink(missing_ok=True)
            else:
                atomic_write(SYSCTL, old_sysctl_file, 0o644)
        except OSError as exc:
            failures.append(str(exc))
        suffix = ' Откат завершён.' if not failures else ' Ошибки отката: ' + '; '.join(failures)
        raise Error(f'Применение прервано: {cause}.{suffix}') from cause
    try:
        actual = {key: snapshot(*key) for key in original}
        atomic_write(STATE, dump({'families': sorted(selected), 'config': config, 'signature': signature(actual)}))
    except (Error, OSError) as exc:
        say(f'Правила применены; состояние мониторинга не записано: {exc}', 'warn')
    if not quiet:
        say(f'Конфигурация применена · правил: {len(config["rules"])}.', 'ok')


def reconcile(config):
    if STATE.exists():
        try:
            saved = json.loads(STATE.read_text(encoding='utf-8'))
            selected = set(saved['families']) | families(config)
            current = {(f, t): snapshot(f, t) for f in sorted(selected) for t in CHAINS}
            healthy = saved['config'] == config and saved['signature'] == signature(current)
            for family in selected:
                filtering = current[(family, 'filter')]
                if 'DOCKER-USER' in filtering['chains'] and any('proto-cascade-FORWARD' in line for line in filtering['lines']):
                    healthy &= any(index == 1 and shlex.split(line)[1] == 'DOCKER-USER'
                                   for index, line in filtering['hooks'])
                nat = current[(family, 'nat')]
                positions = [index for index, line in nat['hooks'] if shlex.split(line)[1] == 'PREROUTING']
                if positions and nat['docker_nat_indices']:
                    healthy &= min(positions) > max(nat['docker_nat_indices'])
            if healthy:
                return
        except (ValueError, KeyError, OSError):
            pass
    apply(config, quiet=True)


def install(source):
    root()
    if not shutil.which('systemctl') or not Path('/run/systemd/system').exists():
        raise Error('Установка службы требует systemd.')
    config = load() if CONFIG.exists() else empty_config()
    if not CONFIG.exists():
        ports = set(config['protected_tcp_ports'])
        ssh_connection = os.environ.get('SSH_CONNECTION', '').split()
        if len(ssh_connection) == 4:
            ports.add(port(ssh_connection[3]))
        if shutil.which('sshd'):
            for line in run(['sshd', '-T'], ok=False).stdout.splitlines():
                if re.fullmatch(r'port [0-9]+', line):
                    ports.add(port(line.split()[1]))
        config['protected_tcp_ports'] = sorted(ports)
    # Detect legacy installations / incompatible backends before installing files.
    environment(config, families(config))
    DIRECTORY.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(DIRECTORY, 0o700)
    if not CONFIG.exists():
        atomic_write(CONFIG, dump(config))
    if Path(source).resolve() != BIN.resolve():
        atomic_write(BIN, Path(source).read_text(encoding='utf-8'), 0o755)
    units = {
        'proto-cascade.service': '''[Unit]
Description=proto-cascade isolated IP forwarding
Wants=network-online.target
After=network-online.target docker.service netfilter-persistent.service nftables.service
ConditionPathExists=/etc/proto-cascade/rules.json
[Service]
Type=oneshot
ExecStart=/usr/local/bin/proto-cascade --apply
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
''',
        'proto-cascade-reconcile.service': '''[Unit]
Description=Restore proto-cascade hooks after firewall or Docker changes
After=network-online.target docker.service proto-cascade.service
ConditionPathExists=/etc/proto-cascade/rules.json
[Service]
Type=oneshot
ExecStart=/usr/local/bin/proto-cascade --reconcile
''',
        'proto-cascade-reconcile.timer': '''[Unit]
Description=Check proto-cascade owned chains every 45 seconds
[Timer]
OnActiveSec=45s
OnUnitActiveSec=45s
AccuracySec=5s
Unit=proto-cascade-reconcile.service
[Install]
WantedBy=timers.target
'''}
    for name, text in units.items():
        atomic_write(Path('/etc/systemd/system') / name, text, 0o644)
    run(['systemctl', 'daemon-reload'])
    run(['systemctl', 'enable', 'proto-cascade.service', 'proto-cascade-reconcile.timer'])


def finish_install():
    # The service runs --apply and acquires the same lock. Start after releasing it.
    run(['systemctl', 'restart', 'proto-cascade.service'])
    # Reset the first check relative to activation, including updates long after boot.
    run(['systemctl', 'restart', 'proto-cascade-reconcile.timer'])
    say('Установлено. Открыть меню: sudo proto-cascade', 'ok')


def show(config):
    heading(f'proto-cascade  {VERSION}', 'Перенаправление трафика')
    protected = ', '.join(map(str, config['protected_tcp_ports'])) or 'не задана'
    print('\n  ' + paint(f'Правил: {len(config["rules"])}', '1;37') + '    ' + paint(f'Защита SSH: TCP {protected}', '2'))
    section('ПРАВИЛА')
    if not config['rules']:
        print('  Перенаправлений пока нет. Начните с пункта 1.')
    for rule in config['rules']:
        display_rule(rule)
        print()


def diagnose(config):
    show(config)
    section('ДИАГНОСТИКА', 'Конфигурация: ' + str(CONFIG))
    for family in sorted(families(config)):
        print(f'  IPv{family}')
        for args in ([binary(family), '--version'], ['sysctl', '-n', 'net.ipv4.ip_forward' if family == 4 else 'net.ipv6.conf.all.forwarding']):
            result = run(args, ok=False)
            print('    ' + (result.stdout.strip() or result.stderr.strip()))
        for table, chains in CHAINS.items():
            for chain in chains:
                result = run([binary(family), '-w', '10', '-t', table, '-nvL', chain], ok=False)
                print(result.stdout.strip() or f'    {chain}: не применена')
    if shutil.which('systemctl'):
        result = run(['systemctl', '--no-pager', '--full', 'status', 'proto-cascade.service', 'proto-cascade-reconcile.timer'], ok=False)
        print(result.stdout)


def ask(text, default=None):
    suffix = f' [{default}]' if default is not None else ''
    value = input(f'  {paint("›", "36")} {text}{suffix}: ').strip()
    return value or default or ''


def discover_ingress():
    """Read this machine's enabled ingress interfaces; never infer a public NAT IP."""
    entries = json.loads(run(['ip', '-j', 'address', 'show']).stdout)
    interfaces = []
    for entry in entries:
        name = entry.get('ifname', '')
        if not re.fullmatch(r'[a-zA-Z0-9_.:-]{1,15}', name) or name == 'lo' or re.match(r'^(docker|br-|veth)', name):
            continue
        if 'UP' not in entry.get('flags', []):
            continue
        addresses = {}
        for item in entry.get('addr_info', []):
            if item.get('family') not in ('inet', 'inet6'):
                continue
            if any(item.get(flag) or flag in item.get('flags', []) for flag in ('tentative', 'dadfailed', 'deprecated')):
                continue
            if item.get('valid_life_time') == 0 or item.get('preferred_life_time') == 0:
                continue
            try:
                ip = address(item.get('local'))
            except Error:
                continue
            if (ip.version == 4) != (item['family'] == 'inet'):
                continue
            prefix = item.get('prefixlen')
            if type(prefix) is not int or not 0 <= prefix <= ip.max_prefixlen:
                continue
            addresses[str(ip)] = {'ip': str(ip), 'prefix': prefix, 'family': ip.version}
        if addresses:
            interfaces.append({'name': name, 'state': entry.get('operstate', 'UNKNOWN'),
                               'addresses': sorted(addresses.values(), key=lambda a: (a['family'], int(ipaddress.ip_address(a['ip']))))})
    return interfaces


def choose_ingress():
    while True:
        interfaces = discover_ingress()
        section('ВХОДЯЩИЙ ИНТЕРФЕЙС', 'Включённые интерфейсы этой ВМ с пригодными IPv4/IPv6-адресами.')
        for index, iface in enumerate(interfaces, 1):
            print('  ' + paint(str(index), '1;36') + '  ' + paint(iface['name'], '1;37') + '  ' + paint(iface['state'], '2'))
            for item in iface['addresses']:
                print(f'     IPv{item["family"]}  {item["ip"]}/{item["prefix"]}')
        if not interfaces:
            say('Подходящих интерфейсов с IP-адресами пока нет. Можно обновить список.', 'warn')
        print('  r  Обновить список\n  0  Отменить добавление\n')
        choice = ask('Номер интерфейса', '1' if len(interfaces) == 1 else None).lower()
        if choice == '0':
            return None
        if choice == 'r':
            continue
        if not re.fullmatch(r'[0-9]{1,6}', choice) or not 1 <= int(choice) <= len(interfaces):
            say('Выберите номер интерфейса из списка, r или 0.', 'warn')
            continue
        iface = interfaces[int(choice) - 1]
        while True:
            section('IP-АДРЕС ИНТЕРФЕЙСА ' + iface['name'], 'Выберите адрес, на который будет приходить трафик.')
            for index, item in enumerate(iface['addresses'], 1):
                print('  ' + paint(str(index), '1;36') + f'  IPv{item["family"]}  {item["ip"]}/{item["prefix"]}')
            print('  r  Обновить список интерфейсов\n  0  Назад к интерфейсам\n')
            choice = ask('Номер IP-адреса', '1' if len(iface['addresses']) == 1 else None).lower()
            if choice in ('0', 'r'):
                break
            if re.fullmatch(r'[0-9]{1,6}', choice) and 1 <= int(choice) <= len(iface['addresses']):
                return iface['name'], iface['addresses'][int(choice) - 1]['ip']
            say('Выберите номер IP-адреса из списка, r или 0.', 'warn')


def interactive_add(config):
    section('НОВОЕ ПЕРЕНАПРАВЛЕНИЕ', 'SSH другой машины: входящий порт 2222 → порт назначения 22.')
    name = ask('Название (латиница, цифры, _ или -)')
    selected = choose_ingress()
    if selected is None:
        say('Добавление отменено.')
        return
    iface, listen = selected
    target = ask(f'IP другой машины (IPv{ipaddress.ip_address(listen).version})')
    proto = ask('Протокол (all, tcp, udp, tcp+udp, icmp, gre...)', 'tcp+udp').lower()
    rule = {'id': name, 'interface': iface, 'listen': listen, 'target': target, 'protocol': proto}
    rule['source'] = ask('Сеть клиентов', '::/0' if ':' in listen else '0.0.0.0/0')
    if proto in PORT_PROTOCOLS | {'tcp+udp'}:
        incoming = ask('Входящий порт (пусто = все порты)')
        if incoming:
            rule['in_port'] = port(incoming)
            rule['out_port'] = port(ask('Порт назначения', incoming))
    rule['snat'] = ask('SNAT (masquerade или none)', 'masquerade')
    candidate = copy.deepcopy(config)
    candidate['rules'].append(rule)
    candidate = validate(candidate)
    section('ПРОВЕРЬТЕ ПРАВИЛО')
    display_rule(candidate['rules'][-1])
    print()
    if ask('Применить это правило? да/нет', 'нет').lower() in ('да', 'yes', 'y'):
        apply(candidate, persist=True)


def menu(source):
    if not sys.stdin.isatty():
        raise Error('Меню требует терминал. Справка: --help; установка: --install.')
    while True:
        config = load() if CONFIG.exists() else empty_config()
        show(config)
        section('УПРАВЛЕНИЕ')
        for key, label in [('1', 'Добавить перенаправление'), ('2', 'Удалить правило'),
                           ('3', 'Проверить и применить'), ('4', 'Диагностика'),
                           ('5', 'Очистить правила'), ('6', 'Откатить конфигурацию'),
                           ('7', 'Установить или обновить'), ('0', 'Выход')]:
            print('  ' + paint(key, '1;36') + '  ' + label)
        print()
        choice = ask('Выбор')
        if choice == '0':
            return
        try:
            with locked():
                config = load() if CONFIG.exists() else empty_config()
                if choice == '1':
                    interactive_add(config)
                elif choice == '2':
                    section('УДАЛЕНИЕ ПРАВИЛА', 'Введите название из списка. Enter — отмена.')
                    name = ask('ID удаляемого правила (пусто = отмена)')
                    if name:
                        candidate = copy.deepcopy(config)
                        candidate['rules'] = [r for r in candidate['rules'] if r['id'] != name]
                        if len(candidate['rules']) == len(config['rules']):
                            raise Error('Правило с таким ID не найдено.')
                        apply(candidate, persist=True)
                elif choice == '3':
                    section('ПРИМЕНЕНИЕ КОНФИГУРАЦИИ')
                    apply(config)
                elif choice == '4':
                    diagnose(config)
                elif choice == '5':
                    section('ОЧИСТКА ПРАВИЛ', 'Будут удалены перенаправления proto-cascade.')
                    if ask('Удалить все правила proto-cascade? Введите УДАЛИТЬ') == 'УДАЛИТЬ':
                        candidate = copy.deepcopy(config)
                        candidate['rules'] = []
                        apply(candidate, persist=True)
                elif choice == '6':
                    candidate = load(BACKUP)
                    section('ВОССТАНОВЛЕНИЕ ПРЕДЫДУЩЕЙ КОНФИГУРАЦИИ')
                    show(candidate)
                    if ask('Применить предыдущую конфигурацию? да/нет', 'нет') == 'да':
                        apply(candidate, persist=True)
                elif choice == '7':
                    section('УСТАНОВКА И ОБНОВЛЕНИЕ')
                    install(source)
                else:
                    say('Выберите пункт от 0 до 7.', 'warn')
            if choice == '7':
                finish_install()
        except (Error, OSError) as exc:
            say(str(exc), 'error')
        input('\n  Enter — вернуться в меню ')


def main():
    source = sys.argv[1]
    args = sys.argv[2:]
    aliases = {'--install': 'install', '--apply': 'apply', '--diagnose': 'diagnose',
               '--reconcile': 'reconcile', '--check': 'check', '--list': 'list'}
    if args:
        args[0] = aliases.get(args[0], args[0])
    parser = argparse.ArgumentParser(description='proto-cascade: изолированный IPv4/IPv6 DNAT без изменения Docker.')
    sub = parser.add_subparsers(dest='command')
    for name in ('install', 'apply', 'check', 'list', 'diagnose', 'reconcile', 'rollback'):
        sub.add_parser(name)
    plan = sub.add_parser('plan', help='Вывести правила без изменения сети')
    plan.add_argument('--file', type=Path, default=CONFIG)
    add = sub.add_parser('add', help='Добавить правило и применить конфигурацию')
    for flag in ('id', 'interface', 'listen', 'target', 'protocol'):
        add.add_argument('--' + flag, required=True)
    add.add_argument('--source')
    add.add_argument('--in-port', type=port)
    add.add_argument('--out-port', type=port)
    add.add_argument('--snat', choices=['masquerade', 'none'], default='masquerade')
    remove = sub.add_parser('remove')
    remove.add_argument('id')
    clear = sub.add_parser('clear')
    clear.add_argument('--yes', action='store_true', required=True)
    options = parser.parse_args(args)
    if options.command is None:
        menu(source)
        return
    if options.command == 'plan':
        config = load(options.file)
        for family in sorted(families(config)):
            rows = compile_rules(config, family)
            for table in CHAINS:
                print(f'# IPv{family} / {table}')
                print(payload(table, {'chains': set(), 'lines': [], 'hooks': []}, rows))
        return
    if options.command == 'list':
        show(load() if CONFIG.exists() else empty_config())
        return
    if options.command == 'install':
        with locked():
            install(source)
        finish_install()
        return
    with locked():
        config = load()
        if options.command == 'add':
            item = {k: v for k, v in vars(options).items() if k != 'command' and v is not None}
            config['rules'].append(item)
            apply(config, persist=True)
        elif options.command == 'remove':
            candidate = [r for r in config['rules'] if r['id'] != options.id]
            if len(candidate) == len(config['rules']):
                raise Error('Правило с таким ID не найдено.')
            config['rules'] = candidate
            apply(config, persist=True)
        elif options.command == 'clear':
            config['rules'] = []
            apply(config, persist=True)
        elif options.command == 'rollback':
            apply(load(BACKUP), persist=True)
        elif options.command == 'check':
            apply(config, test=True)
        elif options.command == 'apply':
            apply(config)
        elif options.command == 'reconcile':
            reconcile(config)
        elif options.command == 'diagnose':
            diagnose(config)


if __name__ == '__main__':
    try:
        # The here-document supplies Python source; fd 3 retains the user's terminal.
        sys.stdin = os.fdopen(3, 'r', encoding='utf-8')
        def terminated(signum, frame):
            raise Error('Получен сигнал завершения.')
        signal.signal(signal.SIGTERM, terminated)
        main()
    except (Error, OSError, ValueError, TypeError) as exc:
        say(str(exc), 'error')
        sys.exit(1)
    except (KeyboardInterrupt, EOFError):
        print('\n  Выход.')
        sys.exit(130)
PROTO_CASCADE_PYTHON
