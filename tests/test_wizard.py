"""Rootless checks of interactive role setup and secure donor imports."""

import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest

if os.name != 'nt':
    import pty


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'


def donor_bundle():
    key = lambda value: base64.b64encode(bytes([value]) * 32).decode('ascii')
    return {
        'version': 1,
        'endpoint': '8.8.8.8:51888',
        'server_public_key': key(1),
        'antizapret_private_key': key(2),
        'antizapret_address': '10.203.240.2/32',
        'vpn_private_key': key(3),
        'vpn_address': '10.203.240.3/32',
    }


HARNESS = r'''
source "$COMMON_SOURCE"
source "$WIZARD_SOURCE"
STATE_DIR=$TEST_STATE
AZ_DIR=$TEST_AZ
SERVER_BUNDLE=$TEST_SERVER_BUNDLE
WIZARD_IMPORT=$TEST_IMPORT
require_root() { :; }
install_dependencies() { :; }
client_compatibility() { [[ $TEST_COMPATIBLE == y ]] || die 'Unsupported AntiZapret fixture'; }
install_self() { :; }
python3() { "$PYTHON_EXE" "$@"; }
config_tool() { "$PYTHON_EXE" "$CONFIG_SOURCE" "$@"; }
server_install() {
    printf 'SERVER %s\n' "$*" >> "$TEST_EVENTS"
    printf '# installed donor\n' > "$STATE_DIR/server.conf"
    cp -- "$TEST_LOCAL_BUNDLE" "$STATE_DIR/donor.json"
    cp -- "$TEST_LOCAL_BUNDLE" "$SERVER_BUNDLE"
}
client_install() {
    [[ $1 == --bundle && -f $2 ]] || die 'Missing donor connection file'
    config_tool validate-bundle "$2" > /dev/null || return 1
    printf 'CLIENT\n' >> "$TEST_EVENTS"
    printf '# installed client\n' > "$STATE_DIR/client.conf"
}
scp() {
    local destination
    printf 'SCP %s\n' "$*" >> "$TEST_EVENTS"
    for destination in "$@"; do :; done
    if [[ $TEST_SCP_FAIL == y ]]; then printf 'partial download\n' > "$destination"; return 1; fi
    cp -- "$TEST_REMOTE_BUNDLE" "$destination"
}
'''


class WizardTests(unittest.TestCase):
    def run_wizard(self, command, replies='', *, roles=(), imported=False,
                   scp_fails=False, remote=None, local=None, terminal=False,
                   compatible=True):
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory)
            state = sandbox / 'state'
            antizapret = sandbox / 'antizapret'
            config = antizapret / 'config'
            state.mkdir()
            config.mkdir(parents=True)
            temporary_downloads = sandbox / 'downloads'
            temporary_downloads.mkdir()
            include = config / 'include-warp-hosts.txt'
            exclude = config / 'exclude-warp-hosts.txt'
            include.write_text('existing.example.com\n', encoding='utf-8')
            exclude.write_text('except.example.com\n', encoding='utf-8')
            for role in roles:
                (state / (role + '.conf')).write_text('# original ' + role + '\n', encoding='utf-8')
            remote_bundle = sandbox / 'remote.json'
            remote_bundle.write_text(json.dumps(donor_bundle() if remote is None else remote), encoding='utf-8')
            local_bundle = sandbox / 'local.json'
            if local is None:
                local = donor_bundle()
                local['endpoint'] = '1.1.1.1:51888'
                local['server_public_key'] = base64.b64encode(bytes([4]) * 32).decode('ascii')
            local_bundle.write_text(json.dumps(local), encoding='utf-8')
            if 'server' in roles:
                (state / 'donor.json').write_text(json.dumps(local), encoding='utf-8')
                (sandbox / 'export.json').write_text(json.dumps(local), encoding='utf-8')
            imported_file = sandbox / 'import.json'
            if imported:
                imported_file.write_bytes(remote_bundle.read_bytes())
            events = sandbox / 'events.txt'
            env = {
                **os.environ,
                'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
                'WIZARD_SOURCE': (ROOT / 'lib/wizard.sh').as_posix(),
                'CONFIG_SOURCE': (ROOT / 'lib/config.py').as_posix(),
                'PYTHON_EXE': Path(sys.executable).as_posix(),
                'TEST_STATE': state.as_posix(),
                'TEST_AZ': antizapret.as_posix(),
                'TEST_SERVER_BUNDLE': (sandbox / 'export.json').as_posix(),
                'TEST_IMPORT': imported_file.as_posix(),
                'TEST_REMOTE_BUNDLE': remote_bundle.as_posix(),
                'TEST_LOCAL_BUNDLE': local_bundle.as_posix(),
                'TEST_EVENTS': events.as_posix(),
                'TEST_SCP_FAIL': 'y' if scp_fails else 'n',
                'TEST_COMPATIBLE': 'y' if compatible else 'n',
                'TMPDIR': temporary_downloads.as_posix(),
            }
            if terminal:
                master, slave = pty.openpty()
                try:
                    process = subprocess.Popen([BASH, '-c', HARNESS + '\n' + command],
                                               stdin=slave, stdout=subprocess.PIPE,
                                               stderr=subprocess.PIPE, text=True, env=env)
                    os.close(slave)
                    slave = None
                    os.write(master, replies.encode('utf-8'))
                    try:
                        stdout, stderr = process.communicate(timeout=15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        stdout, stderr = process.communicate()
                        self.fail('Wizard did not finish: ' + stdout + stderr)
                    result = subprocess.CompletedProcess(process.args, process.returncode, stdout, stderr)
                finally:
                    if slave is not None:
                        os.close(slave)
                    os.close(master)
            else:
                completed = subprocess.run([BASH, '-c', HARNESS + '\n' + command],
                                           input=replies.encode('utf-8'), capture_output=True,
                                           env=env, timeout=15)
                result = subprocess.CompletedProcess(completed.args, completed.returncode,
                                                     completed.stdout.decode('utf-8', errors='replace'),
                                                     completed.stderr.decode('utf-8', errors='replace'))
            return SimpleNamespace(
                process=result,
                events=events.read_text(encoding='utf-8').splitlines() if events.exists() else [],
                state={path.name: path.read_text(encoding='utf-8') for path in state.glob('*.conf')},
                include=include.read_text(encoding='utf-8'),
                exclude=exclude.read_text(encoding='utf-8'),
                imported=imported_file.exists(),
                temporary_downloads=list(temporary_downloads.iterdir()),
            )

    def assert_success(self, result):
        self.assertEqual(result.process.returncode, 0, result.process.stdout + result.process.stderr)
        self.assertEqual(result.include, 'existing.example.com\n')
        self.assertEqual(result.exclude, 'except.example.com\n')
        self.assertEqual(result.temporary_downloads, [], 'Temporary donor keys must be removed')
        for field in ('antizapret_private_key', 'vpn_private_key'):
            self.assertNotIn(donor_bundle()[field], result.process.stdout + result.process.stderr)

    def test_noninteractive_wizard_fails_before_installing_any_role(self):
        result = self.run_wizard('interactive_install', replies='2\n1.1.1.1\n\n')
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {})

    def test_donor_defaults_and_validation_before_installation(self):
        result = self.run_wizard('wizard_server', replies='127.0.0.1\n1.1.1.1\ninvalid\n70000\n\n')
        self.assert_success(result)
        self.assertEqual(result.events, ['SERVER --endpoint 1.1.1.1 --port 51888'])
        self.assertEqual(set(result.state), {'server.conf'})

    def test_input_eof_stops_without_changing_existing_client(self):
        result = self.run_wizard('wizard_server', roles=('client',))
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {'client.conf': '# original client\n'})

    def test_existing_import_uses_validated_file_without_ssh(self):
        result = self.run_wizard('wizard_client n', imported=True)
        self.assert_success(result)
        self.assertEqual(result.events, ['CLIENT'])
        self.assertEqual(set(result.state), {'client.conf'})

    def test_client_retrieves_bundle_with_normal_ssh_host_verification(self):
        result = self.run_wizard('wizard_client n', replies='8.8.8.8\n\n')
        self.assert_success(result)
        self.assertEqual(len(result.events), 2)
        self.assertTrue(result.events[0].startswith('SCP '))
        self.assertIn('root@8.8.8.8:/root/antizapret-relay-donor.json', result.events[0])
        self.assertNotIn('StrictHostKeyChecking=no', result.events[0])
        self.assertNotIn('UserKnownHostsFile=/dev/null', result.events[0])
        self.assertEqual(result.events[1], 'CLIENT')

    def test_failed_ssh_does_not_install_client_or_change_existing_donor(self):
        result = self.run_wizard('wizard_client n', replies='8.8.8.8\n\n',
                                 roles=('server',), scp_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertTrue(any(event.startswith('SCP ') for event in result.events))
        self.assertNotIn('CLIENT', result.events)
        self.assertEqual(result.state, {'server.conf': '# original server\n'})
        self.assertFalse(result.imported)
        self.assertEqual(result.temporary_downloads, [], 'Partial downloads must be removed')
        self.assertEqual(result.include, 'existing.example.com\n')
        self.assertEqual(result.exclude, 'except.example.com\n')

    def test_invalid_download_is_rejected_before_installing_client(self):
        result = self.run_wizard('wizard_client n', replies='8.8.8.8\n\n',
                                 remote={'secret': 'do-not-print-this-value'})
        self.assertNotEqual(result.process.returncode, 0)
        self.assertNotIn('CLIENT', result.events)
        self.assertFalse(result.imported)
        self.assertEqual(result.temporary_downloads, [], 'Invalid imported keys must be removed')
        self.assertEqual(result.state, {})
        self.assertNotIn('do-not-print-this-value', result.process.stdout + result.process.stderr)

    def test_downloaded_bundle_must_match_requested_donor_ip(self):
        remote = donor_bundle()
        remote['endpoint'] = '1.1.1.1:51888'
        result = self.run_wizard('wizard_client n', replies='8.8.8.8\n\n', remote=remote)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertNotIn('CLIENT', result.events)
        self.assertEqual(result.state, {})
        self.assertEqual(result.temporary_downloads, [], 'Keys for an unexpected donor must be removed')

    def test_client_cannot_import_its_own_donor_keys(self):
        result = self.run_wizard('wizard_client n', roles=('server',),
                                 imported=True, local=donor_bundle())
        self.assertNotEqual(result.process.returncode, 0)
        self.assertNotIn('CLIENT', result.events)
        self.assertEqual(result.state, {'server.conf': '# original server\n'})

    def test_both_can_defer_client_until_other_donor_is_ready(self):
        result = self.run_wizard('wizard_client y', replies='\n', roles=('server',))
        self.assert_success(result)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {'server.conf': '# original server\n'})

    def test_existing_roles_are_skipped_by_setup_helpers(self):
        result = self.run_wizard('wizard_server; wizard_client n', roles=('client', 'server'))
        self.assert_success(result)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {'client.conf': '# original client\n', 'server.conf': '# original server\n'})

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_client_uses_existing_import_and_shows_native_domain_instructions(self):
        result = self.run_wizard('interactive_install', replies='1\n', imported=True, terminal=True)
        self.assert_success(result)
        self.assertEqual(result.events, ['CLIENT'])
        output = result.process.stdout + result.process.stderr
        self.assertIn('/root/antizapret/config/include-warp-hosts.txt', output)
        self.assertIn('/root/antizapret/config/exclude-warp-hosts.txt', output)
        self.assertIn('/root/antizapret/parse.sh', output)

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_rejects_invalid_choice_then_installs_donor(self):
        result = self.run_wizard('interactive_install', replies='9\n2\n1.1.1.1\n\n', terminal=True)
        self.assert_success(result)
        self.assertEqual(result.events, ['SERVER --endpoint 1.1.1.1 --port 51888'])
        self.assertEqual(set(result.state), {'server.conf'})

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_both_installs_donor_first_and_then_remote_client(self):
        result = self.run_wizard('interactive_install', replies='3\n1.1.1.1\n\n8.8.8.8\n\n', terminal=True)
        self.assert_success(result)
        self.assertTrue(result.events[0].startswith('SERVER '))
        self.assertTrue(result.events[1].startswith('SCP '))
        self.assertEqual(result.events[2], 'CLIENT')
        self.assertEqual(set(result.state), {'client.conf', 'server.conf'})

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_both_preserves_existing_roles_without_reinstalling(self):
        result = self.run_wizard('interactive_install', replies='3\n', roles=('client', 'server'), terminal=True)
        self.assert_success(result)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {'client.conf': '# original client\n', 'server.conf': '# original server\n'})

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_both_can_install_donor_and_explicitly_defer_client(self):
        result = self.run_wizard('interactive_install', replies='3\n1.1.1.1\n\n\n', terminal=True)
        self.assert_success(result)
        self.assertEqual(result.events, ['SERVER --endpoint 1.1.1.1 --port 51888'])
        self.assertEqual(set(result.state), {'server.conf'})
        self.assertIn('Client setup deferred', result.process.stdout)
        self.assertIn('CLIENT: not installed here', result.process.stdout)

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_both_keeps_created_donor_when_ssh_fetch_fails(self):
        result = self.run_wizard('interactive_install', replies='3\n1.1.1.1\n\n8.8.8.8\n\n',
                                 terminal=True, scp_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertTrue(result.events[0].startswith('SERVER '))
        self.assertTrue(result.events[1].startswith('SCP '))
        self.assertNotIn('CLIENT', result.events)
        self.assertEqual(result.state, {'server.conf': '# installed donor\n'})
        self.assertEqual(result.temporary_downloads, [])

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_both_checks_antizapret_before_creating_donor(self):
        result = self.run_wizard('interactive_install', replies='3\n', terminal=True, compatible=False)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {})

    @unittest.skipIf(os.name == 'nt', 'Full TTY interaction requires a POSIX pseudo-terminal')
    def test_menu_eof_does_not_install_roles(self):
        result = self.run_wizard('interactive_install', replies='\x04', terminal=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, {})


if __name__ == '__main__':
    unittest.main()
