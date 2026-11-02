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

    def test_upgrade_reapplies_existing_client_guard_after_migration_without_service_restart(self):
        for roles in (('client',), ('server',), ('client', 'server')):
            with self.subTest(roles=roles):
                result, remaining = self.run_command(r'''
OPERATION_LOCK_FILE=$STATE_DIR/operation.lock
require_root() { :; }
require_commands() { :; }
flock() { :; }
install_dependencies() { printf 'DEPENDENCIES\n'; }
install_self() { printf 'INSTALL_SELF\n'; }
client_upgrade_exclusions() { printf 'MIGRATE_EXCLUSIONS\n'; }
systemctl() { die "Upgrade restarted a service: $*"; }
relay_main upgrade
''', roles=roles)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                events = result.stdout.splitlines()
                self.assertEqual(events[:3], ['DEPENDENCIES', 'INSTALL_SELF', 'MIGRATE_EXCLUSIONS'])
                self.assertEqual(events.count('CLIENT_FW_up'), int('client' in roles))
                self.assertFalse(any('SERVER_FW_' in event for event in events))
                if 'client' in roles:
                    self.assertLess(events.index('MIGRATE_EXCLUSIONS'), events.index('CLIENT_FW_up'))
                self.assertEqual(remaining, set(roles))

    def test_failed_guard_reapply_makes_upgrade_fail_without_mutating_other_role(self):
        result, remaining = self.run_command(r'''
OPERATION_LOCK_FILE=$STATE_DIR/operation.lock
require_root() { :; }
require_commands() { :; }
flock() { :; }
install_dependencies() { :; }
install_self() { :; }
client_upgrade_exclusions() { :; }
client_firewall() { printf 'CLIENT_GUARD_FAILED\n'; return 1; }
relay_main upgrade
''')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('CLIENT_GUARD_FAILED', result.stdout)
        self.assertNotIn('Installer and firewall hooks upgraded', result.stdout)
        self.assertEqual(remaining, {'client', 'server'})

    def test_upgrade_help_describes_guard_reapply(self):
        result, _ = self.run_command('usage')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('client guards are reapplied without restarting AntiZapret', result.stdout)
        self.assertNotIn('reconnects WARP', result.stdout)


if __name__ == '__main__':
    unittest.main()
