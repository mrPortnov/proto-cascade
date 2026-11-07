"""Discovery and interactive selection of this VM's actual ingress addresses."""
import copy
from contextlib import redirect_stdout
import io
import json
import subprocess
import unittest
from unittest.mock import patch

from test_proto_cascade import manager, config


def iface(name='ens3', *addresses, flags=None, state='UP'):
    return {'ifname': name, 'flags': ['UP'] if flags is None else flags,
            'operstate': state, 'addr_info': list(addresses)}


def addr(ip='192.0.2.10', prefix=24, family='inet', **extra):
    return dict(local=ip, prefixlen=prefix, family=family, **extra)


class NetworkMenuTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()
        self.output = io.StringIO()
        self.console = redirect_stdout(self.output)
        self.console.__enter__()
        self.addCleanup(self.console.__exit__, None, None, None)

    def discovery(self, entries):
        return patch.object(self.m, 'run', return_value=subprocess.CompletedProcess(
            [], 0, json.dumps(entries), ''))

    def test_discovers_private_ipv4_ipv6_and_unknown_state_tunnel(self):
        entries = [iface('ens160', addr('10.20.0.8'), addr('fd42::10', 64, 'inet6'),
                         addr('2001:db8:0:0::5', 64, 'inet6'), addr('2001:db8::5', 64, 'inet6')),
                   iface('wg0', addr('10.30.0.1'), state='UNKNOWN')]
        with self.discovery(entries):
            found = self.m.discover_ingress()
        self.assertEqual([i['name'] for i in found], ['ens160', 'wg0'])
        self.assertEqual([a['ip'] for a in found[0]['addresses']], ['10.20.0.8', '2001:db8::5', 'fd42::10'])

    def test_excludes_down_loopback_docker_invalid_and_unaddressed_interfaces(self):
        entries = [iface(n, addr()) for n in ('lo', 'docker0', 'br-abc', 'veth123', 'bad;name')]
        entries += [iface('ens3', addr(), flags=['BROADCAST']), iface('ens4'), iface('ens5', addr())]
        with self.discovery(entries):
            self.assertEqual([i['name'] for i in self.m.discover_ingress()], ['ens5'])

    def test_excludes_unusable_and_unready_addresses(self):
        invalid = [addr(ip) for ip in ('127.0.0.1', '169.254.1.1', '224.0.0.1', '0.0.0.0', 'not-an-ip')]
        invalid += [addr(ip, 64, 'inet6') for ip in ('::1', 'fe80::1', 'ff02::1', '::ffff:192.0.2.1')]
        invalid += [addr('192.0.2.2', **{flag: True}) for flag in ('tentative', 'dadfailed', 'deprecated')]
        invalid += [addr('192.0.2.3', flags=['tentative']), addr('192.0.2.4', valid_life_time=0),
                    addr('192.0.2.5', preferred_life_time=0), addr('192.0.2.6', prefix=33),
                    addr('192.0.2.7', prefix=True), addr('192.0.2.8', family='inet6')]
        with self.discovery([iface('ens3', *invalid, addr())]):
            self.assertEqual([a['ip'] for a in self.m.discover_ingress()[0]['addresses']], ['192.0.2.10'])

    def test_selects_exact_interface_and_ipv6_from_multiple_addresses(self):
        entries = [iface('ens3', addr()), iface('ens4', addr('10.20.0.1'), addr('fd42::1', 64, 'inet6'))]
        with self.discovery(entries), patch('builtins.input', side_effect=['2', '2']):
            self.assertEqual(self.m.choose_ingress(), ('ens4', 'fd42::1'))

    def test_invalid_numbers_and_names_never_select_a_different_entry(self):
        with self.discovery([iface('ens3', addr())]), patch('builtins.input', side_effect=[
                'ens3', '-1', '2', '9' * 5000, '1', '192.0.2.10', '-1', '2', '1']):
            self.assertEqual(self.m.choose_ingress(), ('ens3', '192.0.2.10'))

    def test_refresh_reloads_interfaces_after_network_change(self):
        snapshots = [[], [iface('ens192', addr('10.50.0.7'))]]
        def run(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 0, json.dumps(snapshots.pop(0)), '')
        with patch.object(self.m, 'run', side_effect=run), patch('builtins.input', side_effect=['r', '', '']):
            self.assertEqual(self.m.choose_ingress(), ('ens192', '10.50.0.7'))
        self.assertFalse(snapshots)

    def test_back_and_cancel_do_not_apply_or_modify_configuration(self):
        original = config()
        expected = copy.deepcopy(original)
        with self.discovery([iface('ens3', addr())]), patch.object(self.m, 'apply') as apply, \
                patch('builtins.input', side_effect=['cancelled', '1', '0', '0']):
            self.m.interactive_add(original)
        apply.assert_not_called()
        self.assertEqual(original, expected)

    def test_empty_inventory_can_be_cancelled_without_manual_ip_fallback(self):
        with self.discovery([]), patch('builtins.input', side_effect=['0']):
            self.assertIsNone(self.m.choose_ingress())
        self.assertIn('Подходящих интерфейсов', self.output.getvalue())

    def test_ip_command_failure_never_falls_back_to_eth0(self):
        with patch.object(self.m, 'run', side_effect=self.m.Error('ip failed')), patch('builtins.input') as ask:
            with self.assertRaisesRegex(self.m.Error, 'ip failed'):
                self.m.choose_ingress()
        ask.assert_not_called()

    def test_interactive_add_passes_selected_ipv6_and_default_source_to_apply(self):
        original = config()
        with self.discovery([iface('ens7', addr('fd42::1', 64, 'inet6'))]), \
                patch.object(self.m, 'apply') as apply, patch('builtins.input', side_effect=[
                    'ssh6', '', '', 'fd42::2', 'tcp', '', '2222', '22', '', 'да']):
            self.m.interactive_add(original)
        candidate = apply.call_args.args[0]
        self.assertEqual(candidate['rules'][0], {'id':'ssh6','interface':'ens7','listen':'fd42::1',
            'target':'fd42::2','protocol':'tcp','source':'::/0','in_port':2222,'out_port':22,'snat':'masquerade'})
        self.assertEqual(apply.call_args.kwargs, {'persist': True})
        self.assertEqual(original['rules'], [])


if __name__ == '__main__':
    unittest.main()
