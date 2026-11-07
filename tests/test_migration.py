"""Prevent two managers from installing competing forwarding rules after a rename."""
import subprocess
import unittest
from unittest.mock import patch

from test_proto_cascade import manager


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.m = manager()

    def test_both_previous_chain_names_are_rejected(self):
        for name in ('KASKAD-DNAT', 'KASKAD2-DNAT', 'KASKAD2-FORWARD', 'KASKAD2-SNAT'):
            with self.subTest(name=name), self.assertRaisesRegex(self.m.Error, 'предыдущей установки'):
                self.m.reject_legacy_chains('*nat\n:' + name + ' - [0:0]\nCOMMIT\n')

    def test_new_owned_and_docker_chains_are_allowed(self):
        self.m.reject_legacy_chains(':proto-cascade-DNAT - [0:0]\n:proto-cascade-FORWARD - [0:0]\n:DOCKER - [0:0]\n')

    def test_active_previous_service_is_rejected(self):
        with patch.object(self.m.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(self.m.Path, 'exists', return_value=True), \
                patch.object(self.m, 'run', return_value=subprocess.CompletedProcess([], 0, '', '')), \
                self.assertRaisesRegex(self.m.Error, 'предыдущей установки'):
            self.m.check_legacy_services()

    def test_disabled_but_active_and_enabled_but_inactive_are_conflicts(self):
        for statuses in ((0, 1), (3, 0)):
            def run(argv, **kwargs):
                return subprocess.CompletedProcess(argv, statuses[0] if 'is-active' in argv else statuses[1], '', '')
            with self.subTest(statuses=statuses), patch.object(self.m.shutil, 'which', return_value='/bin/systemctl'), \
                    patch.object(self.m.Path, 'exists', return_value=True), patch.object(self.m, 'run', side_effect=run), \
                    self.assertRaises(self.m.Error):
                self.m.check_legacy_services()

    def test_old_services_disabled_and_inactive_are_allowed(self):
        with patch.object(self.m.shutil, 'which', return_value='/bin/systemctl'), \
                patch.object(self.m.Path, 'exists', return_value=True), \
                patch.object(self.m, 'run', return_value=subprocess.CompletedProcess([], 3, '', '')):
            self.m.check_legacy_services()


if __name__ == '__main__': unittest.main()
