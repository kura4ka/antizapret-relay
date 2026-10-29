"""Role dispatch must never remove an unrelated role on a shared VPS."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'


class RoleDispatchTests(unittest.TestCase):
    def run_command(self, command, roles=('client', 'server')):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            for role in roles:
                (state / (role + '.conf')).write_text('# state\n')
            script = r'''
source "$COMMON_SOURCE"
source "$MAIN_SOURCE"
STATE_DIR=$TEST_STATE
CLIENT_DOMAINS=/unused
client_firewall() { printf 'CLIENT_FW_%s\n' "$1"; }
server_firewall() { printf 'SERVER_FW_%s\n' "$1"; }
client_uninstall() { printf 'CLIENT_UNINSTALL\n'; rm -- "$STATE_DIR/client.conf"; }
server_uninstall() { printf 'SERVER_UNINSTALL\n'; rm -- "$STATE_DIR/server.conf"; }
systemctl() { :; }
wg() { :; }
config_tool() { :; }
'''
            result = subprocess.run([BASH, '-c', script + '\n' + command],
                                    text=True, capture_output=True, env={
                                        **os.environ,
                                        'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
                                        'MAIN_SOURCE': (ROOT / 'lib/main.sh').as_posix(),
                                        'TEST_STATE': state.as_posix(),
                                    })
            remaining = {role for role in roles if (state / (role + '.conf')).exists()}
            return result, remaining

    def test_firewall_down_for_donor_does_not_remove_client_guard(self):
        result, _ = self.run_command('firewall_command down server')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'SERVER_FW_down')

    def test_client_scoped_hook_and_legacy_all_dispatch(self):
        result, _ = self.run_command('firewall_command up client; firewall_command up')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['CLIENT_FW_up', 'SERVER_FW_up', 'CLIENT_FW_up'])

    def test_two_roles_require_explicit_uninstall_selection(self):
        result, remaining = self.run_command('uninstall_command')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Both roles', result.stderr)
        self.assertEqual(remaining, {'client', 'server'})

    def test_removing_one_role_preserves_the_other(self):
        for role in ('client', 'server'):
            with self.subTest(role=role):
                result, remaining = self.run_command('uninstall_command --role ' + role)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(remaining, {'client', 'server'} - {role})

    def test_single_role_uninstall_remains_backwards_compatible(self):
        result, remaining = self.run_command('uninstall_command', roles=('server',))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(remaining, set())

    def test_status_displays_both_roles(self):
        result, _ = self.run_command('relay_status')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Role: DONOR', result.stdout)
        self.assertIn('Role: CLIENT', result.stdout)

    def test_uninstall_all_runs_client_before_donor(self):
        result, remaining = self.run_command('uninstall_command --role all')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertLess(result.stdout.index('CLIENT_UNINSTALL'), result.stdout.index('SERVER_UNINSTALL'))
        self.assertEqual(remaining, set())

    def test_invalid_role_cannot_change_either_role(self):
        result, remaining = self.run_command('uninstall_command --role typo')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(remaining, {'client', 'server'})


if __name__ == '__main__':
    unittest.main()
