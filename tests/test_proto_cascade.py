"""Offline tests: python3 -m unittest discover -s tests -v (standard library only)."""
import copy
from contextlib import contextmanager, redirect_stdout
import io
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
import uuid
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / 'install-proto-cascade.sh'


def manager():
    source = SCRIPT.read_text(encoding='utf-8').split("<<'PROTO_CASCADE_PYTHON'\n", 1)[1].rsplit('\nPROTO_CASCADE_PYTHON', 1)[0]
    module = types.ModuleType('proto_cascade_test_module')
    exec(compile(source, str(SCRIPT), 'exec'), module.__dict__)
    return module


def rule(**overrides):
    result = {'id': 'vpn', 'interface': 'eth0', 'listen': '192.0.2.1',
              'target': '198.51.100.2', 'protocol': 'tcp+udp', 'in_port': 443, 'out_port': 8443}
    result.update(overrides)
    return result


def config(*rules):
    return {'version': 2, 'protected_tcp_ports': [22], 'rules': list(rules)}


class ValidationTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()

    def rejected(self, value):
        with self.assertRaises(self.m.Error):
            self.m.validate(value)

    def test_decimal_ports(self):
        self.assertEqual(self.m.port('0080'), 80)
        for value in ('0', '-1', '65536', '1; reboot', '3.2', '', True, '9' * 30):
            with self.subTest(value=value), self.assertRaises(self.m.Error):
                self.m.port(value)

    def test_bad_addresses(self):
        for ip in ('999.1.2.3', '01.2.3.4', '127.0.0.1', '0.0.0.0', '224.0.0.1',
                   '255.255.255.255', 'fe80::1', 'ff02::1', '::', '::1', '::ffff:192.0.2.1',
                   '2001:db8::1%eth0', '1.2.3.4; reboot', 123):
            with self.subTest(ip=ip):
                self.rejected(config(rule(target=ip)))

    def test_mixed_families_and_self_target(self):
        self.rejected(config(rule(target='2001:db8::1')))
        self.rejected(config(rule(target='192.0.2.1')))

    def test_ids_interfaces_and_unknown_fields(self):
        for overrides in ({'id': 'x;reboot'}, {'interface': 'eth+'}, {'interface': 'docker0'},
                          {'interface': 'lo'}, {'interface': 'br-abc'}, {'unexpected': True}):
            with self.subTest(overrides=overrides):
                self.rejected(config(rule(**overrides)))

    def test_duplicate_ids(self):
        self.rejected(config(rule(), rule(in_port=444)))

    def test_portless_protocols_and_numeric(self):
        for proto in ('all', 'icmp', 'gre', 'esp', 'ah', '253'):
            r = rule(protocol=proto)
            self.rejected(config(r))
            del r['in_port'], r['out_port']
            self.assertEqual(self.m.validate(config(r))['rules'][0]['protocol'], proto)

    def test_unknown_protocol(self):
        for proto in ('invalid', '-1', '256', '0', 'tcp -j ACCEPT'):
            self.rejected(config(rule(protocol=proto)))

    def test_icmp_family(self):
        r = rule(protocol='icmpv6', listen='2001:db8:1::1', target='2001:db8:2::2')
        del r['in_port'], r['out_port']
        self.m.validate(config(r))
        self.rejected(config(dict(r, protocol='icmp')))
        self.rejected(config(dict(r, protocol='44')))

    def test_sources(self):
        self.rejected(config(rule(source='::/0')))
        self.rejected(config(rule(source='192.0.2.0/99')))
        self.assertEqual(self.m.validate(config(rule(source='203.0.113.9/24')))['rules'][0]['source'], '203.0.113.0/24')

    def test_management_port(self):
        self.rejected(config(rule(protocol='tcp', in_port=22)))
        self.m.validate(config(rule(protocol='udp', in_port=22)))

    def test_remote_ssh_uses_unprotected_incoming_port(self):
        c = config(rule(id='ssh_target', protocol='tcp', in_port=2222, out_port=22))
        value = self.m.validate(c)
        lines = self.m.compile_rules(value, 4)['proto-cascade-DNAT']
        forwarding = next(line for line in lines if '-j DNAT' in line)
        self.assertIn('--dport 2222', forwarding)
        self.assertIn('--to-destination 198.51.100.2:22', forwarding)
        self.assertIn('--dport 22', lines[0])
        self.assertIn('-j RETURN', lines[0])

    def test_overlap_catchall(self):
        catchall = rule(id='all', protocol='all')
        del catchall['in_port'], catchall['out_port']
        self.rejected(config(rule(), catchall))

    def test_overlap_networks(self):
        self.rejected(config(rule(source='203.0.113.0/24'), rule(id='other', source='203.0.113.0/25')))

    def test_nonoverlapping_rules(self):
        self.m.validate(config(rule(source='203.0.113.0/25'), rule(id='other', source='203.0.113.128/25')))
        self.m.validate(config(rule(protocol='tcp'), rule(id='other', protocol='udp')))
        self.m.validate(config(rule(), rule(id='other', listen='192.0.2.10')))
        self.m.validate(config(rule(), rule(id='other', in_port=444)))

    def test_bad_schema(self):
        for value in ([], {}, {'version': 1}, {'version': 2, 'rules': {}},
                      {'version': 2, 'protected_tcp_ports': '22'}, config(None)):
            self.rejected(value)


class CompilerTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()

    def test_tcp_udp_port_mapping(self):
        rows = self.m.compile_rules(config(rule()), 4)
        nat = '\n'.join(rows['proto-cascade-DNAT'])
        forward = '\n'.join(rows['proto-cascade-FORWARD'])
        self.assertIn('-i eth0 -d 192.0.2.1/32', nat)
        self.assertEqual(nat.count('-j DNAT'), 2)
        self.assertIn('--to-destination 198.51.100.2:8443', nat)
        self.assertIn('--ctorigdstport 443 --ctreplsrcport 8443', forward)
        self.assertIn('--ctdir ORIGINAL', forward)
        self.assertIn('--ctdir REPLY', forward)
        for line in rows['proto-cascade-SNAT']:
            self.assertIn('--ctstate DNAT', line)
            self.assertIn('--ctorigdst 192.0.2.1 --ctreplsrc 198.51.100.2', line)
            self.assertNotIn('-o eth0', line)  # Egress may differ from ingress.

    def test_all_has_no_protocol_filter(self):
        r = rule(protocol='all')
        del r['in_port'], r['out_port']
        rows = self.m.compile_rules(config(r), 4)
        dnat = [line for line in rows['proto-cascade-DNAT'] if '-j DNAT' in line]
        self.assertEqual(len(dnat), 1)
        self.assertNotIn('-p ', dnat[0])
        self.assertNotIn('--dport', dnat[0])
        self.assertNotIn('--ctproto', '\n'.join(rows['proto-cascade-FORWARD']))

    def test_ssh_bypass_precedes_catchall(self):
        r = rule(protocol='all')
        del r['in_port'], r['out_port']
        lines = self.m.compile_rules(config(r), 4)['proto-cascade-DNAT']
        self.assertIn('--dport 22', lines[0])
        self.assertIn('-j RETURN', lines[0])
        self.assertIn('-j DNAT', lines[-1])

    def test_ipv6_and_neighbour_discovery(self):
        r = rule(listen='2001:db8:1::1', target='2001:db8:2::2')
        lines = self.m.compile_rules(config(r), 6)['proto-cascade-DNAT']
        self.assertIn('--to-destination [2001:db8:2::2]:8443', '\n'.join(lines))
        self.assertEqual(sum('--icmpv6-type' in line for line in lines), 5)
        self.assertEqual(self.m.compile_rules(config(r), 4)['proto-cascade-DNAT'], [])

    def test_source_match_and_snat_disabled(self):
        rows = self.m.compile_rules(config(rule(source='203.0.113.0/24', snat='none')), 4)
        self.assertIn('-s 203.0.113.0/24', '\n'.join(rows['proto-cascade-DNAT']))
        self.assertIn('--ctorigsrc 203.0.113.0/24', '\n'.join(rows['proto-cascade-FORWARD']))
        self.assertEqual(rows['proto-cascade-SNAT'], [])

    def test_hook_positions_and_isolation(self):
        snap = {'chains': {'DOCKER-USER'}, 'lines': [], 'hooks': []}
        rows = self.m.compile_rules(config(rule()), 4)
        nat = self.m.payload('nat', snap, rows)
        filt = self.m.payload('filter', snap, rows)
        self.assertIn('-A PREROUTING -m addrtype --dst-type LOCAL', nat)
        self.assertIn('-I DOCKER-USER 1', filt)
        self.assertNotIn('-F DOCKER', filt)
        self.assertNotIn('-F FORWARD', filt)
        self.assertNotIn('-P ', filt)
        self.assertNotIn(':DOCKER', filt)

    def test_no_mutation_of_input(self):
        c = config(rule())
        original = copy.deepcopy(c)
        self.m.compile_rules(c, 4)
        self.assertEqual(c, original)


class FirewallEnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()

    def test_inactive_ufw_is_allowed_when_service_is_active(self):
        calls=[]
        def run(argv, **kwargs):
            calls.append(argv)
            if 'ufw' in argv:
                return subprocess.CompletedProcess(argv,0,'Status: inactive\n','')
            return subprocess.CompletedProcess(argv,3,'','')
        with patch.object(self.m.shutil,'which',lambda name:'/usr/bin/'+name),patch.object(self.m,'run',run):
            self.m.check_managed_firewall()
        self.assertFalse(any(argv[0]=='systemctl' and 'ufw' in argv for argv in calls))

    def test_enabled_ufw_is_rejected(self):
        with patch.object(self.m.shutil,'which',lambda name:'/usr/bin/'+name), \
                patch.object(self.m,'run',lambda argv,**kw:subprocess.CompletedProcess(argv,0,'Status: active\n','')), \
                self.assertRaisesRegex(self.m.Error,'Активен UFW'):
            self.m.check_managed_firewall()

    def test_active_firewalld_is_rejected(self):
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv,0,'Status: inactive\n' if 'ufw' in argv else '','')
        with patch.object(self.m.shutil,'which',lambda name:'/usr/bin/'+name),patch.object(self.m,'run',run), \
                self.assertRaisesRegex(self.m.Error,'Активен firewalld'):
            self.m.check_managed_firewall()


class CommandTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()

    def test_plan_example_is_offline_and_valid(self):
        argv = ['python', str(SCRIPT), 'plan', '--file', str(SCRIPT.parent / 'examples' / 'rules.example.json')]
        output = io.StringIO()
        with patch.object(sys, 'argv', argv), patch.object(self.m, 'run', side_effect=AssertionError('offline only')), redirect_stdout(output):
            self.m.main()
        text = output.getvalue()
        self.assertIn('# IPv4 / nat', text)
        self.assertIn('# IPv6 / nat', text)
        self.assertIn('--to-destination 198.51.100.2:8443', text)
        self.assertNotIn("'[2001:", text)

    def test_install_starts_services_after_lock_is_released(self):
        state = {'held': False}
        @contextmanager
        def lock():
            state['held'] = True
            try:
                yield
            finally:
                state['held'] = False
        def install(source):
            self.assertTrue(state['held'])
        def finish():
            self.assertFalse(state['held'])
        with patch.object(sys, 'argv', ['python', str(SCRIPT), '--install']), \
                patch.object(self.m, 'locked', lock), patch.object(self.m, 'install', install), \
                patch.object(self.m, 'finish_install', finish):
            self.m.main()


class Firewall:
    """Small stateful xtables adapter for transaction/rollback contract tests.

    This is not a kernel parser. Real packet checks live in integration_linux.py.
    """
    def __init__(self):
        self.tables = {}
        self.commits = 0
        self.tests = 0
        self.fail_commit = None
        self.fail_test = None
        for family in (4, 6):
            self.tables[(family, 'filter')] = {
                'INPUT': [], 'FORWARD': ['-j DOCKER-USER', '-j DOCKER-FORWARD'], 'OUTPUT': [],
                'DOCKER-USER': ['-j RETURN'], 'DOCKER-FORWARD': ['-j DROP']}
            self.tables[(family, 'nat')] = {
                'PREROUTING': ['-m addrtype --dst-type LOCAL -j DOCKER'], 'POSTROUTING': [], 'OUTPUT': [],
                'DOCKER': ['-p tcp -m tcp --dport 8443 -j DNAT --to-destination 172.18.0.2:443']}

    def run(self, argv, data=None, ok=True):
        family = 6 if argv[0].startswith('ip6') else 4
        if argv[0].endswith('-save'):
            table = argv[-1]
            state = self.tables[(family, table)]
            output = '*' + table + '\n'
            output += '\n'.join(':' + c + ' - [0:0]' for c in state) + '\n'
            output += '\n'.join('-A ' + c + ' ' + line for c, lines in state.items() for line in lines)
            return subprocess.CompletedProcess(argv, 0, output + '\nCOMMIT\n', '')
        if not argv[0].endswith('-restore'):
            raise AssertionError(f'Unexpected command: {argv}')
        if '--noflush' not in argv or '--wait' not in argv:
            raise AssertionError('Every restore must preserve foreign rules and wait for xtables lock.')
        table = data.splitlines()[0][1:]
        candidate = copy.deepcopy(self.tables[(family, table)])
        for line in data.splitlines()[1:]:
            if not line or line == 'COMMIT':
                continue
            if line.startswith(':'):
                candidate.setdefault(line.split()[0][1:], [])
                continue
            words = shlex.split(line)
            action, chain = words[:2]
            if action == '-F':
                candidate[chain] = []
            elif action == '-X':
                del candidate[chain]
            elif action == '-A':
                candidate[chain].append(' '.join(words[2:]))
            elif action == '-I':
                candidate[chain].insert(int(words[2]) - 1, ' '.join(words[3:]))
            elif action == '-D':
                expected = words[2:]
                found = next(i for i, v in enumerate(candidate[chain]) if shlex.split(v) == expected)
                candidate[chain].pop(found)
            else:
                raise AssertionError('Unexpected xtables action: ' + action)
        if '--test' in argv:
            self.tests += 1
            if self.tests == self.fail_test:
                raise RuntimeError('kernel rejected extension')
        else:
            self.commits += 1
            self.tables[(family, table)] = candidate
            if self.commits == self.fail_commit:
                raise RuntimeError('injected restore failure after partial commit')
        return subprocess.CompletedProcess(argv, 0, '', '')


class TransactionTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()
        directory = SCRIPT.parent / ('.proto-cascade-test-' + uuid.uuid4().hex)
        directory.mkdir(mode=0o777)
        self.tmp = types.SimpleNamespace(name=str(directory))
        self.addCleanup(lambda: shutil.rmtree(directory))
        self.m.CONFIG = Path(self.tmp.name) / 'rules.json'
        self.m.BACKUP = Path(self.tmp.name) / 'previous.json'
        self.m.STATE = Path(self.tmp.name) / 'state.json'
        self.m.SYSCTL = Path(self.tmp.name) / 'sysctl.conf'
        self.m.CONFIG.write_text(self.m.dump(self.m.empty_config()), encoding='utf-8')
        self.fw = Firewall()
        for name, value in [('run', self.fw.run), ('environment', lambda c, f: None),
                            ('forwarding_settings', lambda c: {}), ('say', lambda *a: None)]:
            mock = patch.object(self.m, name, value)
            mock.start()
            self.addCleanup(mock.stop)

    def test_success_and_idempotence_preserve_docker(self):
        before = copy.deepcopy(self.fw.tables)
        c = config(rule())
        self.m.apply(c, persist=True)
        first = copy.deepcopy(self.fw.tables)
        self.m.apply(c)
        self.assertEqual(self.fw.tables, first)
        self.assertEqual(self.m.load(), self.m.validate(c))
        for key, state in before.items():
            for chain in ('DOCKER', 'DOCKER-FORWARD'):
                if chain in state:
                    self.assertEqual(self.fw.tables[key][chain], state[chain])
        self.assertEqual(self.fw.tables[(4, 'nat')]['PREROUTING'][0], before[(4, 'nat')]['PREROUTING'][0])

    def test_preflight_failure_changes_nothing(self):
        before = copy.deepcopy(self.fw.tables)
        self.fw.fail_test = 2
        with self.assertRaises(RuntimeError):
            self.m.apply(config(rule()), persist=True)
        self.assertEqual(self.fw.tables, before)
        self.assertEqual(self.fw.commits, 0)
        self.assertEqual(self.m.load()['rules'], [])

    def test_partial_commit_rolls_back_only_owned_chains(self):
        before = copy.deepcopy(self.fw.tables)
        self.fw.fail_commit = 2
        with self.assertRaisesRegex(self.m.Error, 'Откат завершён'):
            self.m.apply(config(rule()), persist=True)
        self.assertEqual(self.fw.tables, before)
        self.assertEqual(self.m.load()['rules'], [])

    def test_file_write_failure_rolls_back_kernel(self):
        before = copy.deepcopy(self.fw.tables)
        real_write = self.m.atomic_write
        def broken(path, *args):
            if path == self.m.CONFIG:
                raise OSError('disk full')
            return real_write(path, *args)
        with patch.object(self.m, 'atomic_write', broken), self.assertRaisesRegex(self.m.Error, 'Откат завершён'):
            self.m.apply(config(rule()), persist=True)
        self.assertEqual(self.fw.tables, before)
        self.assertEqual(self.m.load()['rules'], [])

    def test_config_failure_restores_sysctl_and_its_file(self):
        values = {'net.ipv4.ip_forward': '0'}
        self.m.SYSCTL.write_text('# previous\n', encoding='utf-8')
        real_write = self.m.atomic_write
        def write(path, *args):
            if path == self.m.CONFIG:
                raise OSError('disk full')
            return real_write(path, *args)
        def run(argv, **kwargs):
            if argv[0] != 'sysctl':
                return self.fw.run(argv, **kwargs)
            if '-n' in argv:
                return subprocess.CompletedProcess(argv, 0, values[argv[-1]] + '\n', '')
            key, value = argv[-1].split('=')
            values[key] = value
            return subprocess.CompletedProcess(argv, 0, '', '')
        with patch.object(self.m, 'atomic_write', write), patch.object(self.m, 'run', run), \
                patch.object(self.m, 'forwarding_settings', lambda c: {'net.ipv4.ip_forward': '1'}), \
                self.assertRaisesRegex(self.m.Error, 'Откат завершён'):
            self.m.apply(config(rule()), persist=True)
        self.assertEqual(values['net.ipv4.ip_forward'], '0')
        self.assertEqual(self.m.SYSCTL.read_text(encoding='utf-8'), '# previous\n')

    def test_sysctl_failure_restores_earlier_changes(self):
        before = copy.deepcopy(self.fw.tables)
        values = {'net/ipv6/conf/eth0/accept_ra': '1', 'net.ipv6.conf.all.forwarding': '0'}
        def run(argv, **kwargs):
            if argv[0] != 'sysctl':
                return self.fw.run(argv, **kwargs)
            if '-n' in argv:
                return subprocess.CompletedProcess(argv, 0, values[argv[-1]] + '\n', '')
            key, value = argv[-1].split('=')
            if key == 'net.ipv6.conf.all.forwarding' and value == '1':
                raise self.m.Error('sysctl failure')
            values[key] = value
            return subprocess.CompletedProcess(argv, 0, '', '')
        c = config(rule(listen='2001:db8:1::1', target='2001:db8:2::2'))
        desired = {'net/ipv6/conf/eth0/accept_ra': '2', 'net.ipv6.conf.all.forwarding': '1'}
        with patch.object(self.m, 'run', run), patch.object(self.m, 'forwarding_settings', lambda c: desired), \
                self.assertRaisesRegex(self.m.Error, 'Откат завершён'):
            self.m.apply(c, persist=True)
        self.assertEqual(values['net/ipv6/conf/eth0/accept_ra'], '1')
        self.assertEqual(values['net.ipv6.conf.all.forwarding'], '0')
        self.assertEqual(self.fw.tables, before)

    def test_clear_restores_docker_paths_and_keeps_backup(self):
        self.m.apply(config(rule()), persist=True)
        self.m.apply(self.m.empty_config(), persist=True)
        for table in ('filter', 'nat'):
            for chain in self.m.CHAINS[table]:
                self.assertEqual(self.fw.tables[(4, table)][chain], [])
        self.assertEqual(len(self.m.load(self.m.BACKUP)['rules']), 1)
        self.assertFalse(any('proto-cascade-' in line for line in self.fw.tables[(4, 'filter')]['FORWARD']))

    def test_ipv6_cleanup_when_last_ipv6_rule_removed(self):
        c = config(rule(listen='2001:db8:1::1', target='2001:db8:2::2'))
        self.m.apply(c, persist=True)
        self.m.apply(self.m.empty_config(), persist=True)
        self.assertEqual(self.fw.tables[(6, 'nat')]['proto-cascade-DNAT'], [])
        self.assertEqual(self.fw.tables[(6, 'nat')]['PREROUTING'], ['-m addrtype --dst-type LOCAL -j DOCKER'])

    def test_foreign_chain_contents_are_not_overwritten(self):
        self.fw.tables[(4, 'filter')]['proto-cascade-FORWARD'] = ['-j ACCEPT']
        before = copy.deepcopy(self.fw.tables)
        with self.assertRaisesRegex(self.m.Error, 'чужие правила'):
            self.m.apply(config(rule()))
        self.assertEqual(self.fw.tables, before)

    def test_reconcile_is_quiet_when_unchanged(self):
        self.m.apply(config(rule()), persist=True)
        commits = self.fw.commits
        self.m.reconcile(self.m.load())
        self.assertEqual(self.fw.commits, commits)

    def test_reconcile_repairs_deleted_hook(self):
        self.m.apply(config(rule()), persist=True)
        self.fw.tables[(4, 'filter')]['DOCKER-USER'] = ['-j RETURN']
        self.m.reconcile(self.m.load())
        self.assertIn('proto-cascade-FORWARD', self.fw.tables[(4, 'filter')]['DOCKER-USER'][0])

    def test_reconcile_restores_docker_nat_priority(self):
        self.m.apply(config(rule()), persist=True)
        parent = self.fw.tables[(4, 'nat')]['PREROUTING']
        docker = parent.pop(0)
        parent.append(docker)
        self.m.reconcile(self.m.load())
        self.assertIn('-j DOCKER', self.fw.tables[(4, 'nat')]['PREROUTING'][0])
        self.assertIn('proto-cascade-DNAT', self.fw.tables[(4, 'nat')]['PREROUTING'][-1])

    def test_reconcile_moves_hook_before_return(self):
        self.m.apply(config(rule()), persist=True)
        parent = self.fw.tables[(4, 'filter')]['DOCKER-USER']
        parent.append(parent.pop(0))
        self.m.reconcile(self.m.load())
        self.assertIn('proto-cascade-FORWARD', self.fw.tables[(4, 'filter')]['DOCKER-USER'][0])

    def test_reconcile_adds_hook_when_docker_starts_later(self):
        self.fw.tables[(4, 'filter')].pop('DOCKER-USER')
        self.fw.tables[(4, 'filter')]['FORWARD'] = []
        self.m.apply(config(rule()), persist=True)
        self.fw.tables[(4, 'filter')]['DOCKER-USER'] = ['-j RETURN']
        self.fw.tables[(4, 'filter')]['FORWARD'].insert(0, '-j DOCKER-USER')
        self.m.reconcile(self.m.load())
        self.assertIn('proto-cascade-FORWARD', self.fw.tables[(4, 'filter')]['DOCKER-USER'][0])


if __name__ == '__main__':
    unittest.main()
