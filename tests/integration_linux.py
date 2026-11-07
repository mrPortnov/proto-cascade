"""Real Linux packet smoke test in disposable network namespaces.

Run: sudo python3 tests/integration_linux.py
No host firewall or production /etc/proto-cascade changes. Requires iproute2,
iptables/ip6tables, ping, Python 3, and CAP_NET_ADMIN. Docker chains are simulated;
this does not certify any particular Docker daemon/version.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time

from test_proto_cascade import manager

HERE = Path(__file__).resolve()


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, **kwargs).stdout


def server(family, protocol, label, ready):
    af = socket.AF_INET if family == '4' else socket.AF_INET6
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(af, kind) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if af == socket.AF_INET6:
            listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        listener.bind(('0.0.0.0' if family == '4' else '::', 8080))
        if protocol == 'tcp':
            listener.listen()
        Path(ready).touch()
        while True:
            if protocol == 'tcp':
                client, peer = listener.accept()
                with client:
                    client.recv(100)
                    client.sendall((label + ' ' + peer[0]).encode())
            else:
                data, peer = listener.recvfrom(100)
                listener.sendto((label + ' ' + peer[0]).encode(), peer)


def client(family, protocol, host, port):
    af = socket.AF_INET if family == '4' else socket.AF_INET6
    kind = socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM
    with socket.socket(af, kind) as connection:
        connection.settimeout(10)
        connection.connect((host, int(port)))
        connection.send(b'probe')
        print(connection.recv(100).decode())


def router(directory, mode):
    m = manager()
    m.CONFIG = Path(directory) / 'rules.json'
    m.BACKUP = Path(directory) / 'previous.json'
    m.STATE = Path(directory) / 'state.json'
    m.SYSCTL = Path(directory) / 'sysctl.conf'
    c = m.empty_config()
    if mode in ('ports', 'all'):
        for family in (4, 6):
            listen = '192.0.2.1' if family == 4 else '2001:db8:1::1'
            target = '198.51.100.2' if family == 4 else '2001:db8:2::2'
            item = {'id': 'vpn' + str(family), 'interface': 'r-c', 'listen': listen,
                    'target': target, 'protocol': 'all' if mode == 'all' else 'tcp+udp'}
            if mode == 'ports':
                item.update(in_port=18080, out_port=8080)
            c['rules'].append(item)
    if mode == 'reconcile':
        m.reconcile(m.load())
    else:
        m.apply(c, persist=True)


def integration():
    if sys.platform != 'linux' or os.geteuid() != 0:
        raise SystemExit('Requires Linux root and network namespace support.')
    for command in ('ip', 'iptables', 'ip6tables', 'ping', 'sysctl'):
        if not shutil.which(command):
            raise SystemExit('Missing dependency: ' + command)
    prefix = 'proto-cascade-test-' + str(os.getpid()) + '-'
    names = {role: prefix + role for role in ('client', 'router', 'target', 'container')}
    created, processes = [], []
    with tempfile.TemporaryDirectory(prefix='proto-cascade-netns-') as directory:
        def ns(role, args):
            return run(['ip', 'netns', 'exec', names[role]] + list(args))

        def ip(role, *args):
            return run(['ip', '-n', names[role]] + list(args))

        def apply(mode):
            print(ns('router', [sys.executable, HERE, 'router', directory, mode]), end='')

        def probe(family, protocol, port, expected):
            host = '192.0.2.1' if family == 4 else '2001:db8:1::1'
            result = ns('client', [sys.executable, HERE, 'client', str(family), protocol, host, str(port)]).strip()
            if result != expected:
                raise AssertionError(f'{family}/{protocol}/{port}: {result!r} != {expected!r}')

        def docker_fingerprint():
            values = []
            for binary in ('iptables-save', 'ip6tables-save'):
                for line in ns('router', [binary]).splitlines():
                    if line.startswith(':DOCKER') or line.startswith('-A DOCKER'):
                        if 'proto-cascade-' not in line:
                            values.append(line)
            return values

        try:
            for name in names.values():
                run(['ip', 'netns', 'add', name])
                created.append(name)
            for role in names:
                ip(role, 'link', 'set', 'lo', 'up')
            links = [('client', 'c-r', 'r-c', '192.0.2.2/24', '192.0.2.1/24', '2001:db8:1::2/64', '2001:db8:1::1/64'),
                     ('target', 't-r', 'r-t', '198.51.100.2/24', '198.51.100.1/24', '2001:db8:2::2/64', '2001:db8:2::1/64'),
                     ('container', 'd-r', 'r-d', '172.19.0.2/24', '172.19.0.1/24', '2001:db8:3::2/64', '2001:db8:3::1/64')]
            for role, edge, peer, edge4, router4, edge6, router6 in links:
                # Create both ends directly in the router namespace, then move one.
                ip('router', 'link', 'add', peer, 'type', 'veth', 'peer', 'name', edge)
                ip('router', 'link', 'set', edge, 'netns', names[role])
                for endpoint, device, addr4, addr6 in ((role, edge, edge4, edge6), ('router', peer, router4, router6)):
                    ip(endpoint, 'address', 'add', addr4, 'dev', device)
                    ip(endpoint, '-6', 'address', 'add', addr6, 'dev', device, 'nodad')
                    ip(endpoint, 'link', 'set', device, 'up')
                ip(role, 'route', 'add', 'default', 'via', router4.split('/')[0])
                ip(role, '-6', 'route', 'add', 'default', 'via', router6.split('/')[0])
            for binary, listen, target in (('iptables', '192.0.2.1', '172.19.0.2'),
                                            ('ip6tables', '2001:db8:1::1', '2001:db8:3::2')):
                ns('router', [binary, '-N', 'DOCKER-USER'])
                ns('router', [binary, '-A', 'DOCKER-USER', '-j', 'RETURN'])
                ns('router', [binary, '-N', 'DOCKER-FORWARD'])
                ns('router', [binary, '-A', 'DOCKER-FORWARD', '-d', target, '-j', 'ACCEPT'])
                ns('router', [binary, '-A', 'DOCKER-FORWARD', '-s', target, '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', '-j', 'ACCEPT'])
                ns('router', [binary, '-A', 'DOCKER-FORWARD', '-j', 'DROP'])
                ns('router', [binary, '-A', 'FORWARD', '-j', 'DOCKER-USER'])
                ns('router', [binary, '-A', 'FORWARD', '-j', 'DOCKER-FORWARD'])
                ns('router', [binary, '-P', 'FORWARD', 'DROP'])
                ns('router', [binary, '-t', 'nat', '-N', 'DOCKER'])
                ns('router', [binary, '-t', 'nat', '-A', 'PREROUTING', '-j', 'DOCKER'])
                destination = f'[{target}]:8080' if ':' in target else target + ':8080'
                ns('router', [binary, '-t', 'nat', '-A', 'DOCKER', '-i', 'r-c', '-d', listen,
                              '-p', 'tcp', '--dport', '28080', '-j', 'DNAT', '--to-destination', destination])
            for role in ('target', 'container'):
                for family in (4, 6):
                    for protocol in ('tcp', 'udp'):
                        ready = Path(directory) / f'{role}-{family}-{protocol}.ready'
                        processes.append(subprocess.Popen(['ip', 'netns', 'exec', names[role], sys.executable,
                            str(HERE), 'server', str(family), protocol, role, str(ready)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE))
                        deadline = time.monotonic() + 45
                        while not ready.exists():
                            if processes[-1].poll() is not None:
                                raise RuntimeError(processes[-1].stderr.read().decode())
                            if time.monotonic() >= deadline:
                                raise RuntimeError('Server startup timed out.')
                            time.sleep(0.02)
            before = docker_fingerprint()
            apply('ports')
            for family in (4, 6):
                snat = '198.51.100.1' if family == 4 else '2001:db8:2::1'
                source = '192.0.2.2' if family == 4 else '2001:db8:1::2'
                for protocol in ('tcp', 'udp'):
                    probe(family, protocol, 18080, 'target ' + snat)
                probe(family, 'tcp', 28080, 'container ' + source)
            apply('all')
            for family in (4, 6):
                snat = '198.51.100.1' if family == 4 else '2001:db8:2::1'
                source = '192.0.2.2' if family == 4 else '2001:db8:1::2'
                for protocol in ('tcp', 'udp'):
                    probe(family, protocol, 8080, 'target ' + snat)
                probe(family, 'tcp', 28080, 'container ' + source)
                host = '192.0.2.1' if family == 4 else '2001:db8:1::1'
                ns('client', ['ping', f'-{family}', '-c', '1', '-W', '2', host])
            # Simulate Docker recreating its user chain, then repair references.
            ns('router', ['iptables', '-F', 'DOCKER-USER'])
            ns('router', ['iptables', '-A', 'DOCKER-USER', '-j', 'RETURN'])
            apply('reconcile')
            if 'proto-cascade-FORWARD' not in ns('router', ['iptables', '-S', 'DOCKER-USER']):
                raise AssertionError('Reconciliation did not restore DOCKER-USER hook.')
            apply('clear')
            for family in (4, 6):
                source = '192.0.2.2' if family == 4 else '2001:db8:1::2'
                probe(family, 'tcp', 28080, 'container ' + source)
            if docker_fingerprint() != before:
                raise AssertionError('Docker rules were modified.')
            print('PASS: IPv4/IPv6 TCP, UDP, ICMP; port mapping; SNAT on a second interface;')
            print('      Docker DNAT priority; reconciliation; clear preserves Docker rules.')
        finally:
            for process in processes:
                process.terminate()
            for process in processes:
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            for name in reversed(created):
                subprocess.run(['ip', 'netns', 'delete', name], check=False, capture_output=True)


if __name__ == '__main__':
    if len(sys.argv) == 1:
        integration()
    elif sys.argv[1] == 'server':
        server(*sys.argv[2:])
    elif sys.argv[1] == 'client':
        client(*sys.argv[2:])
    elif sys.argv[1] == 'router':
        router(*sys.argv[2:])
    else:
        raise SystemExit('Unknown test mode.')
