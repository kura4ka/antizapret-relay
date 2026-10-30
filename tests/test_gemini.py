"""Optional Gemini routing must preserve native lists and installed roles."""

import base64
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'
SPEC = importlib.util.spec_from_file_location('gemini_config', ROOT / 'lib/config.py')
config = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(config)
DOMAINS = tuple('''gemini.google.com
generativelanguage.googleapis.com
lh5.googleusercontent.com
googleapis.com
ssl.gstatic.com
fonts.googleapis.com
play.google.com
ogs.google.com
apis.google.com
jnn-pa.googleapis.com
waa-pa.clients6.google.com
i.ytimg.com
yt3.ggpht.com
googleusercontent.com
maps.gstatic.com
lh3.google.com
ogads-pa.clients6.google.com
csp.withgoogle.com
googletagmanager.com
maps.googleapis.com
static.doubleclick.net
gstatic.com
td.doubleclick.net
googleads.g.doubleclick.net
google-analytics.com
optimizationguide-pa.googleapis.com
encrypted-tbn0.gstatic.com
encrypted-tbn1.gstatic.com
encrypted-tbn2.gstatic.com
encrypted-tbn3.gstatic.com
streetviewpixels-pa.googleapis.com
content-autofill.googleapis.com
accounts.google.com
gemini.gstatic.com
geminiweb-pa.clients6.google.com
signaler-pa.clients6.google.com
robinfrontend-pa.googleapis.com
notifications-pa.googleapis.com
oauth2.googleapis.com
oauthaccountmanager.googleapis.com
signaler-pa.googleapis.com
accountcapabilities-pa.googleapis.com
fonts.gstatic.com
inappcheck.itunes.apple.com
mzstorekit.itunes.apple.com
subscriptionsfirstparty-pa.googleapis.com
firebaseinstallations.googleapis.com'''.splitlines())


class GeminiConfigTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.target = self.root / 'include-warp-hosts.txt'
        self.metadata = self.root / 'before.json'

    def test_preset_matches_all_requested_domains_and_documented_list(self):
        self.assertEqual(len(DOMAINS), 47)
        self.assertEqual(len(set(DOMAINS)), 47)
        self.assertEqual(tuple(config.GEMINI_DOMAINS), DOMAINS)
        documented = (ROOT / 'docs/gemini-domains.txt').read_text(encoding='utf-8').splitlines()
        self.assertEqual(documented, list(DOMAINS))

    def test_staging_is_read_only_and_appends_the_full_requested_preset(self):
        original = b'# My routing\ncustom.example\n'
        self.target.write_bytes(original)
        self.assertEqual(config.prepare_gemini(self.target, self.metadata), len(DOMAINS))
        self.assertEqual(self.target.read_bytes(), original)
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), original + ('\n'.join(DOMAINS) + '\n').encode())

    def test_case_comments_and_duplicate_entries_are_preserved_without_duplication(self):
        original = b'# Gemini\n GEMINI.GOOGLE.COM # chosen\ngemini.google.com\n'
        self.target.write_bytes(original)
        self.assertEqual(config.prepare_gemini(self.target, self.metadata), len(DOMAINS) - 1)
        config.apply_gemini(self.target, self.metadata)
        expected = original + ('\n'.join(DOMAINS[1:]) + '\n').encode()
        self.assertEqual(self.target.read_bytes(), expected)
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), expected)

    def test_existing_two_domain_preset_gains_only_missing_entries_and_is_repeatable(self):
        original = b'# My routing\ngemini.google.com\n# Existing API choice\ngenerativelanguage.googleapis.com\ncustom.example\n'
        self.target.write_bytes(original)
        self.assertEqual(config.prepare_gemini(self.target, self.metadata), 45)
        config.apply_gemini(self.target, self.metadata)
        expected = original + ('\n'.join(DOMAINS[2:]) + '\n').encode()
        self.assertEqual(self.target.read_bytes(), expected)
        self.metadata.unlink()
        self.assertEqual(config.prepare_gemini(self.target, self.metadata), 0)
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), expected)

    def test_crlf_and_missing_final_newline_survive_exact_rollback(self):
        for original in (b'# Windows list\r\ncustom.example\r\n', b'# no final newline'):
            with self.subTest(original=original):
                self.target.write_bytes(original)
                config.prepare_gemini(self.target, self.metadata)
                config.apply_gemini(self.target, self.metadata)
                self.assertTrue(self.target.read_bytes().startswith(original))
                if b'\r\n' in original:
                    self.assertNotIn(b'\n', self.target.read_bytes().replace(b'\r\n', b''))
                config.rollback_gemini(self.target, self.metadata)
                self.assertEqual(self.target.read_bytes(), original)
                self.metadata.unlink()

    def test_missing_original_file_is_removed_on_rollback(self):
        config.prepare_gemini(self.target, self.metadata)
        self.assertFalse(self.target.exists())
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_text().splitlines(), list(DOMAINS))
        config.rollback_gemini(self.target, self.metadata)
        self.assertFalse(self.target.exists())

    def test_all_domains_already_present_produce_no_file_write(self):
        original = ('# keep\n' + '\n'.join(DOMAINS)).encode()
        self.target.write_bytes(original)
        self.assertEqual(config.prepare_gemini(self.target, self.metadata), 0)
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), original)

    def test_concurrent_edit_is_not_overwritten_by_apply_or_rollback(self):
        self.target.write_bytes(b'original.example\n')
        config.prepare_gemini(self.target, self.metadata)
        self.target.write_bytes(b'edited.example\n')
        with self.assertRaises(config.ConfigError):
            config.apply_gemini(self.target, self.metadata)
        with self.assertRaises(config.ConfigError):
            config.rollback_gemini(self.target, self.metadata)
        self.assertEqual(self.target.read_bytes(), b'edited.example\n')
        self.assertTrue(self.metadata.exists())

    def test_pending_snapshot_and_wrong_target_are_rejected(self):
        config.prepare_gemini(self.target, self.metadata)
        with self.assertRaises(config.ConfigError):
            config.prepare_gemini(self.target, self.metadata)
        with self.assertRaises(config.ConfigError):
            config.apply_gemini(self.root / 'another.txt', self.metadata)
        self.assertFalse(self.target.exists())

    @unittest.skipIf(os.name == 'nt', 'POSIX permissions are not represented on Windows')
    def test_file_permissions_are_preserved_and_symlink_is_rejected(self):
        self.target.write_bytes(b'custom.example\n')
        self.target.chmod(0o640)
        config.prepare_gemini(self.target, self.metadata)
        config.apply_gemini(self.target, self.metadata)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        config.rollback_gemini(self.target, self.metadata)
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o640)
        self.metadata.unlink()
        other = self.root / 'other.txt'
        self.target.rename(other)
        self.target.symlink_to(other)
        with self.assertRaises(config.ConfigError):
            config.prepare_gemini(self.target, self.metadata)
        self.assertEqual(other.read_bytes(), b'custom.example\n')


HARNESS = r'''
source "$COMMON_SOURCE"
source "$PRESETS_SOURCE"
source "$CLIENT_SOURCE"
STATE_DIR=$TEST_STATE
AZ_DIR=$TEST_AZ
CLIENT_INCLUDES=$TEST_INCLUDES
CLIENT_EXCLUDES=$TEST_EXCLUDES
CLIENT_DOMAINS=$TEST_DOMAINS
CLIENT_DROPIN=$TEST_DROPIN
APP=$TEST_APP
require_root() { :; }
install_dependencies() { :; }
client_compatibility() { :; }
install_self() { mkdir -p "$STATE_DIR"; }
python3() { "$PYTHON_EXE" "$@"; }
config_tool() {
    if [[ $1 == rollback-gemini ]]; then printf 'ROLLBACK_GEMINI\n' >> "$TEST_EVENTS"; fi
    "$PYTHON_EXE" "$CONFIG_SOURCE" "$@"
}
ip() { printf '[]\n'; }
systemctl() { printf 'SYSTEMCTL %s\n' "$*" >> "$TEST_EVENTS"; }
client_firewall() { printf 'FIREWALL %s\n' "$*" >> "$TEST_EVENTS"; }
'''


class GeminiLifecycleTests(unittest.TestCase):
    original_include = b'# Own domains\r\ncustom.example\r\n'
    original_exclude = b'# User exclusions\ngemini.google.com\n'
    original_setup = b'ANTIZAPRET_WARP=1\nVPN_WARP=1\nUNRELATED=keep\n'

    def run_command(self, command, *, installed=True, parse_fails=False, includes=None,
                    parse_edits=False):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            state, az, temp = root / 'state', root / 'antizapret', root / 'tmp'
            for path in (state, az / 'config', az / 'download', temp):
                path.mkdir(parents=True, exist_ok=True)
            include = az / 'config/include-warp-hosts.txt'
            include.write_bytes(self.original_include if includes is None else includes)
            exclude = az / 'config/exclude-warp-hosts.txt'
            exclude.write_bytes(self.original_exclude)
            setup = az / 'setup'
            setup.write_bytes(self.original_setup)
            (az / 'download/include-warp-hosts.txt').write_bytes(b'cloudflare.com\n')
            donor_files = {
                state / 'server.conf': b'RELAY_SUBNET=10.203.241.0/24\n',
                state / 'donor.json': b'{"private":"keep donor key"}\n',
                root / 'az-relay.conf': b'[Interface]\nPrivateKey=keep-donor-key\n',
            }
            if installed:
                donor_files[state / 'client.conf'] = b'prefix=10\nonly=n\n'
                donor_files[state / 'client-values.json'] = b'{"private":"keep client keys"}\n'
            for path, value in donor_files.items():
                path.write_bytes(value)
            before_state = {p.name: p.read_bytes() for p in state.iterdir()}
            parse = az / 'parse.sh'
            parse.write_text('#!/usr/bin/env bash\nprintf "PARSE\\n" >> "$TEST_EVENTS"\n'
                             'if [[ ${TEST_PARSE_EDIT:-n} == y ]]; then '
                             'printf "user-concurrent.example\\n" >> "$TEST_INCLUDES"; fi\n'
                             '[[ ${TEST_PARSE_FAIL:-n} != y ]]\n', encoding='utf-8', newline='\n')
            parse.chmod(0o755)
            key = lambda n: base64.b64encode(bytes([n]) * 32).decode('ascii')
            bundle = root / 'bundle.json'
            bundle.write_text(json.dumps({
                'version': 1, 'endpoint': '8.8.8.8:51888', 'server_public_key': key(1),
                'antizapret_private_key': key(2), 'antizapret_address': '10.203.240.2/32',
                'vpn_private_key': key(3), 'vpn_address': '10.203.240.3/32',
            }), encoding='utf-8')
            events = root / 'events'
            environment = {
                **os.environ,
                'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
                'PRESETS_SOURCE': (ROOT / 'lib/presets.sh').as_posix(),
                'CLIENT_SOURCE': (ROOT / 'lib/client.sh').as_posix(),
                'CONFIG_SOURCE': (ROOT / 'lib/config.py').as_posix(),
                'PYTHON_EXE': Path(sys.executable).as_posix(),
                'TEST_STATE': state.as_posix(), 'TEST_AZ': az.as_posix(),
                'TEST_INCLUDES': include.as_posix(), 'TEST_EXCLUDES': exclude.as_posix(),
                'TEST_DOMAINS': (az / 'config/relay-include-warp-hosts.txt').as_posix(),
                'TEST_DROPIN': (root / 'dropins/client.conf').as_posix(),
                'TEST_APP': (root / 'antizapret-relay').as_posix(),
                'TEST_EVENTS': events.as_posix(), 'TEST_BUNDLE': bundle.as_posix(),
                'TEST_PARSE_FAIL': 'y' if parse_fails else 'n',
                'TEST_PARSE_EDIT': 'y' if parse_edits else 'n', 'TMPDIR': temp.as_posix(),
            }
            result = subprocess.run([BASH, '-c', HARNESS + '\n' + command], env=environment,
                                    text=True, capture_output=True, timeout=25)
            for path, original in donor_files.items():
                self.assertEqual(path.read_bytes(), original, 'Existing keys and roles must be unchanged')
            return SimpleNamespace(
                process=result, output=result.stdout + result.stderr,
                include=include.read_bytes(), exclude=exclude.read_bytes(), setup=setup.read_bytes(),
                state={p.name: p.read_bytes() for p in state.iterdir()}, before_state=before_state,
                events=events.read_text().splitlines() if events.exists() else [],
                temporary=list(temp.iterdir()),
                snapshots=[p.read_bytes() for p in temp.rglob('gemini.before.json')],
            )

    def test_existing_client_preset_is_idempotent_and_preserves_exclusions_and_keys(self):
        result = self.run_command('preset_command gemini; preset_command gemini')
        self.assertEqual(result.process.returncode, 0, result.output)
        self.assertTrue(result.include.startswith(self.original_include))
        for domain in DOMAINS:
            self.assertEqual(result.include.decode().splitlines().count(domain), 1)
        self.assertEqual(result.exclude, self.original_exclude)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(result.events, ['PARSE'])
        self.assertEqual(result.temporary, [])

    def test_existing_two_domain_client_preset_upgrades_without_reinstalling(self):
        original = b'# Existing Gemini choices\ngemini.google.com\ngenerativelanguage.googleapis.com\ncustom.example\n'
        result = self.run_command('preset_command gemini; preset_command gemini', includes=original)
        self.assertEqual(result.process.returncode, 0, result.output)
        self.assertEqual(result.include, original + ('\n'.join(DOMAINS[2:]) + '\n').encode())
        self.assertEqual(result.exclude, self.original_exclude)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(result.events, ['PARSE'])
        self.assertEqual(result.temporary, [])

    def test_existing_complete_preset_does_not_reload_or_rewrite(self):
        original = ('\n'.join(DOMAINS)).encode()
        result = self.run_command('preset_command gemini', includes=original)
        self.assertEqual(result.process.returncode, 0, result.output)
        self.assertEqual(result.include, original)
        self.assertEqual(result.events, [])
        self.assertEqual(result.temporary, [])

    def test_preset_parse_failure_restores_exact_original_list(self):
        result = self.run_command('preset_command gemini', parse_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.include, self.original_include)
        self.assertEqual(result.exclude, self.original_exclude)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(result.events, ['PARSE', 'ROLLBACK_GEMINI', 'PARSE'])
        self.assertEqual(result.temporary, [])

    def test_preset_requires_client_before_touching_lists(self):
        result = self.run_command('preset_command gemini', installed=False)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.include, self.original_include)
        self.assertEqual(result.events, [])
        self.assertEqual(result.state, result.before_state)

    def test_unsafe_rollback_preserves_concurrent_edit_and_recovery_snapshot(self):
        result = self.run_command('preset_command gemini', parse_fails=True, parse_edits=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertIn(b'user-concurrent.example\n', result.include)
        self.assertTrue(result.include.startswith(self.original_include))
        self.assertEqual(result.exclude, self.original_exclude)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(len(result.snapshots), 1)
        self.assertEqual(json.loads(result.snapshots[0])['original'].encode(), self.original_include)
        self.assertIn('Gemini recovery snapshot is kept', result.output)

    def test_fresh_client_flag_adds_domains_and_removes_transaction_snapshot(self):
        result = self.run_command('client_install --bundle "$TEST_BUNDLE" --gemini', installed=False)
        self.assertEqual(result.process.returncode, 0, result.output)
        self.assertTrue(result.include.startswith(self.original_include))
        self.assertEqual(result.include.decode().splitlines()[-len(DOMAINS):], list(DOMAINS))
        self.assertNotIn('gemini.before.json', result.state)
        self.assertTrue(result.exclude.startswith(self.original_exclude))
        self.assertEqual(result.events.count('PARSE'), 1)

    def test_fresh_client_failure_restores_native_lists_and_original_donor(self):
        result = self.run_command('client_install --bundle "$TEST_BUNDLE" --gemini',
                                  installed=False, parse_fails=True)
        self.assertNotEqual(result.process.returncode, 0)
        self.assertEqual(result.include, self.original_include)
        self.assertEqual(result.exclude, self.original_exclude)
        self.assertEqual(result.setup, self.original_setup)
        self.assertEqual(result.state, result.before_state)
        self.assertEqual(result.temporary, [])

    def test_fresh_client_without_flag_leaves_main_include_untouched(self):
        result = self.run_command('client_install --bundle "$TEST_BUNDLE"', installed=False)
        self.assertEqual(result.process.returncode, 0, result.output)
        self.assertEqual(result.include, self.original_include)


if __name__ == '__main__':
    unittest.main()
