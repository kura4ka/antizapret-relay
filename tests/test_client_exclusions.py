"""Client lifecycle checks for automatic exclusions of upstream WARP defaults."""

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


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'


def bundle():
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
source "$CLIENT_SOURCE"
STATE_DIR=$TEST_STATE
AZ_DIR=$TEST_AZ
CLIENT_DOMAINS=$TEST_DOMAINS
CLIENT_EXCLUDES=$TEST_EXCLUDES
CLIENT_DROPIN=$TEST_DROPIN
APP=$TEST_APP
require_root() { :; }
install_dependencies() { :; }
client_compatibility() { :; }
install_self() { mkdir -p "$STATE_DIR"; }
python3() { "$PYTHON_EXE" "$@"; }
config_tool() { "$PYTHON_EXE" "$CONFIG_SOURCE" "$@"; }
ip() { printf '[]\n'; }
systemctl() { printf 'SYSTEMCTL %s\n' "$*" >> "$TEST_EVENTS"; }
client_firewall() { printf 'CLIENT_FIREWALL %s\n' "$*" >> "$TEST_EVENTS"; }
'''


class ClientDefaultExclusionTests(unittest.TestCase):
    original_excludes = '# existing exclusions\nkeep.example\n'
    original_includes = '# own donor choices\nown.example\n'
    original_setup = 'ANTIZAPRET_WARP=1\nVPN_WARP=1\nUNRELATED=preserve\n'

    def run_client(self, command, *, installed=False, both=False,
                   parse_fails=False, defaults=None):
        with tempfile.TemporaryDirectory() as directory:
            sandbox = Path(directory)
            state = sandbox / 'state'
            az = sandbox / 'antizapret'
            config = az / 'config'
            download = az / 'download'
            for path in (state, config, download):
                path.mkdir(parents=True, exist_ok=True)
            setup = az / 'setup'
            setup.write_text(self.original_setup, encoding='utf-8', newline='\n')
            excludes = config / 'exclude-warp-hosts.txt'
            excludes.write_text(self.original_excludes, encoding='utf-8', newline='\n')
            includes = config / 'include-warp-hosts.txt'
            includes.write_text(self.original_includes, encoding='utf-8', newline='\n')
            defaults = defaults if defaults is not None else {
                'include-warp-hosts.txt': '# bundled\ncloudflare.com\nstun.cloudflare.com\n',
                'extra-include-warp-hosts.txt': 'stun.cloudflare.com\nstun.example.net\n',
            }
            for filename, contents in defaults.items():
                (download / filename).write_text(contents, encoding='utf-8', newline='\n')
            original_download = {path.name: path.read_bytes() for path in download.iterdir()}
            parse = az / 'parse.sh'
            parse.write_text('#!/usr/bin/env bash\nprintf "PARSE\\n" >> "$TEST_EVENTS"\n'
                             '[[ ${TEST_PARSE_FAIL:-n} != y ]]\n',
                             encoding='utf-8', newline='\n')
            os.chmod(parse, 0o755)
            input_bundle = sandbox / 'input.json'
            input_bundle.write_text(json.dumps(bundle()), encoding='utf-8')
            donor_files = {}
            if both:
                donor_files = {
                    state / 'server.conf': 'RELAY_SUBNET=10.203.241.0/24\n',
                    sandbox / 'donor.json': '{"private": "preserve donor export"}\n',
                    sandbox / 'az-relay.conf': '[Interface]\nPrivateKey=keep-donor-key\n',
                }
                for path, value in donor_files.items():
                    path.write_text(value, encoding='utf-8', newline='\n')
            if installed:
                (state / 'client.conf').write_text('prefix=10\nonly=n\n', encoding='utf-8')
                changes = state / 'client-values.json'
                changes.write_text(json.dumps({'ANTIZAPRET_WARP': '4', 'VPN_WARP': '3',
                                               'WARP_PROTECTION': 'y'}), encoding='utf-8')
                (state / 'setup.snapshot').write_bytes(setup.read_bytes())
                subprocess.run([sys.executable, str(ROOT / 'lib/config.py'), 'apply',
                                str(setup), str(state / 'setup.before.json'), str(changes)],
                               check=True, capture_output=True)
                (config / 'relay-include-warp-hosts.txt').write_text('own.example\n', encoding='utf-8')
                (sandbox / 'dropins').mkdir()
                (sandbox / 'dropins' / 'client.conf').write_text('[Service]\n', encoding='utf-8')
            before_state = {path.name: path.read_bytes() for path in state.iterdir()}
            before_setup = setup.read_bytes()
            events = sandbox / 'events.txt'
            env = {
                **os.environ,
                'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
                'CLIENT_SOURCE': (ROOT / 'lib/client.sh').as_posix(),
                'CONFIG_SOURCE': (ROOT / 'lib/config.py').as_posix(),
                'PYTHON_EXE': Path(sys.executable).as_posix(),
                'TEST_STATE': state.as_posix(),
                'TEST_AZ': az.as_posix(),
                'TEST_DOMAINS': (config / 'relay-include-warp-hosts.txt').as_posix(),
                'TEST_EXCLUDES': excludes.as_posix(),
                'TEST_DROPIN': (sandbox / 'dropins' / 'client.conf').as_posix(),
                'TEST_APP': (sandbox / 'antizapret-relay').as_posix(),
                'TEST_BUNDLE': input_bundle.as_posix(),
                'TEST_EVENTS': events.as_posix(),
                'TEST_PARSE_FAIL': 'y' if parse_fails else 'n',
            }
            process = subprocess.run([BASH, '-c', HARNESS + '\n' + command],
                                     env=env, text=True, capture_output=True, timeout=25)
            for path, value in donor_files.items():
                self.assertEqual(path.read_text(encoding='utf-8'), value,
                                 'Client domain migration must preserve the local donor')
            self.assertEqual({path.name: path.read_bytes() for path in download.iterdir()},
                             original_download, 'Downloaded upstream lists must be left intact')
            self.assertEqual(includes.read_text(encoding='utf-8'), self.original_includes)
            output = process.stdout + process.stderr
            for name in ('antizapret_private_key', 'vpn_private_key'):
                self.assertNotIn(bundle()[name], output, 'Private keys must never be logged')
            return SimpleNamespace(
                process=process,
                output=output,
                excludes=excludes.read_text(encoding='utf-8') if excludes.exists() else None,
                setup=setup.read_text(encoding='utf-8'),
                before_setup=before_setup.decode('utf-8'),
                state={path.name: path.read_bytes() for path in state.iterdir()},
                before_state=before_state,
                relay_domains=(config / 'relay-include-warp-hosts.txt').read_text(encoding='utf-8')
                if (config / 'relay-include-warp-hosts.txt').exists() else None,
                events=events.read_text(encoding='utf-8').splitlines() if events.exists() else [],
            )

    def assert_success(self, result):
        self.assertEqual(result.process.returncode, 0, result.output)

    def test_fresh_install_excludes_all_bundled_domains_and_preserves_own_choices(self):
        result = self.run_client('client_install --bundle "$TEST_BUNDLE" --domain chosen.example', both=True)
        self.assert_success(result)
        self.assertTrue(result.excludes.startswith(self.original_excludes))
        for domain in ('cloudflare.com', 'stun.cloudflare.com', 'stun.example.net'):
            self.assertEqual(result.excludes.splitlines().count(domain), 1)
        self.assertNotIn('own.example', result.excludes)
        self.assertNotIn('chosen.example', result.excludes)
        self.assertIn('chosen.example', result.relay_domains)
        self.assertIn('default-exclusions.json', result.state)
        self.assertEqual(result.events.count('PARSE'), 1)

    def test_invalid_default_is_rejected_before_stopping_or_changing_antizapret(self):
        result = self.run_client('client_install --bundle "$TEST_BUNDLE"', both=True,
                                 defaults={'include-warp-hosts.txt': '.\n'})
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.excludes, self.original_excludes)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, result.before_state)

    def test_failed_fresh_install_restores_exact_previous_exclusions_and_donor(self):
        result = self.run_client('client_install --bundle "$TEST_BUNDLE"', both=True, parse_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.excludes, self.original_excludes)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertIsNone(result.relay_domains)
        self.assertIn('PARSE', result.events)

    def test_upgrade_migrates_existing_client_once_without_changing_keys_or_roles(self):
        result = self.run_client('client_upgrade_exclusions; client_upgrade_exclusions',
                                 installed=True, both=True)
        self.assert_success(result)
        self.assertEqual(result.setup, result.before_setup)
        for filename, original in result.before_state.items():
            self.assertEqual(result.state[filename], original)
        self.assertIn('default-exclusions.json', result.state)
        for domain in ('cloudflare.com', 'stun.cloudflare.com', 'stun.example.net'):
            self.assertEqual(result.excludes.splitlines().count(domain), 1)
        self.assertEqual(result.events.count('PARSE'), 1)
        self.assertFalse(any(event.startswith('SYSTEMCTL stop') for event in result.events))

    def test_upgrade_does_not_readd_exclusion_that_user_removed_to_opt_in(self):
        command = r'''
client_upgrade_exclusions
python3 - "$CLIENT_EXCLUDES" <<'PY'
import sys
from pathlib import Path
path = Path(sys.argv[1])
lines = path.read_text(encoding='utf-8').splitlines(keepends=True)
path.write_text(''.join(line for line in lines if line.strip() != 'cloudflare.com'), encoding='utf-8')
PY
client_upgrade_exclusions
'''
        result = self.run_client(command, installed=True)
        self.assert_success(result)
        self.assertNotIn('cloudflare.com', result.excludes.splitlines())
        self.assertIn('stun.cloudflare.com', result.excludes.splitlines())
        self.assertEqual(result.events.count('PARSE'), 1)
        self.assertEqual(result.setup, result.before_setup)

    def test_failed_upgrade_restores_exclusions_and_retains_prior_client_and_donor(self):
        result = self.run_client('client_upgrade_exclusions', installed=True, both=True, parse_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.excludes, self.original_excludes)
        self.assertEqual(result.setup, result.before_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertIn('PARSE', result.events)

    def test_uninstall_removes_automatic_exclusions_but_keeps_later_user_entries(self):
        command = r'''
client_upgrade_exclusions
printf '\n# added later by user\nlater.example\n' >> "$CLIENT_EXCLUDES"
client_uninstall
'''
        result = self.run_client(command, installed=True, both=True)
        self.assert_success(result)
        self.assertEqual(result.excludes, self.original_excludes + '\n# added later by user\nlater.example\n')
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(set(result.state), {'server.conf'})
        self.assertIsNone(result.relay_domains)

    def test_server_only_upgrade_does_not_create_client_exclusions(self):
        result = self.run_client('client_upgrade_exclusions', both=True)
        self.assert_success(result)
        self.assertEqual(result.excludes, self.original_excludes)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(result.events, [])


if __name__ == '__main__':
    unittest.main()
