"""Model ordered FORWARD rules across native restarts and partial failures."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'

MOCK = r'''
import json, os, sys
from pathlib import Path
path = Path(os.environ['RULES'])
rules = json.loads(path.read_text())
args = sys.argv[1:]
assert args[:4] == ['-w', '-t', 'filter', args[3]]
operation, chain = args[3:5]
assert chain == 'FORWARD'
rule = args[5:]
if operation == '-C':
    sys.exit(0 if rule in rules else 1)
if operation == '-I':
    assert rule.pop(0) == '1'
    if os.environ.get('FAIL_INSERT') == 'y' and 'az-relay-client' in rule:
        sys.exit(2)
    rules.insert(0, rule)
elif operation == '-D':
    rules.remove(rule)
else:
    raise AssertionError(operation)
# Once installed, temporary protection must cover the replacement gap too.
if os.environ.get('REQUIRE_COVERAGE') == 'y':
    prefix = os.environ['PREFIX']
    protected = [prefix + '.29.0.0/16']
    if os.environ['ONLY'] == 'n':
        protected.append(prefix + '.28.0.0/16')
    for source in protected:
        for current in rules:
            if current == ['NATIVE_ACCEPT']:
                raise AssertionError('Native ACCEPT precedes relay guard for ' + source)
            if source in current and current[-1] == 'DROP':
                break
        else:
            raise AssertionError('Missing guard for ' + source)
path.write_text(json.dumps(rules))
'''


class ClientGuardOrderTests(unittest.TestCase):
    def run_guard(self, folder, action='up', **options):
        script = r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
STATE_DIR=$TEST_STATE
firewall_lock() { :; }
stat() { printf '0\n'; }
iptables() { "$PYTHON_EXE" "$MOCK_SCRIPT" "$@"; }
client_firewall "$ACTION"
'''
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True, env={
            **os.environ,
            'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
            'CLIENT_SOURCE': (ROOT / 'lib/client.sh').as_posix(),
            'PYTHON_EXE': Path(sys.executable).as_posix(),
            'TEST_STATE': folder.as_posix(),
            'MOCK_SCRIPT': (folder / 'mock.py').as_posix(),
            'RULES': (folder / 'rules.json').as_posix(),
            'ACTION': action,
            **options,
        })

    @staticmethod
    def verdict(rules, source, mark, interface):
        for rule in rules:
            if rule == ['NATIVE_ACCEPT']:
                return 'ACCEPT'
            if (source in rule and mark == '0x2'
                    and rule[rule.index('-o') + 1] != interface):
                return rule[-1]
        return 'ACCEPT'

    def test_restart_repositions_guards_without_unprotected_replacement_gap(self):
        for prefix, only in (('10', 'n'), ('172', 'n'), ('10', 'y')):
            with self.subTest(prefix=prefix, only=only), tempfile.TemporaryDirectory() as directory:
                folder = Path(directory)
                (folder / 'client.conf').write_text(f'prefix={prefix}\nonly={only}\n')
                (folder / 'mock.py').write_text(MOCK)
                path = folder / 'rules.json'
                path.write_text('[]')
                result = self.run_guard(folder)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for _ in range(2):
                    # Native up.sh puts its forward-ips ACCEPT before old guards.
                    rules = [['NATIVE_ACCEPT']] + json.loads(path.read_text())
                    # Also clean up duplicate rules left by older hooks.
                    rules.append(next(rule for rule in rules if 'az-relay-client' in rule))
                    path.write_text(json.dumps(rules))
                    result = self.run_guard(folder)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    rules = json.loads(path.read_text())
                    count = 2 if only == 'n' else 1
                    self.assertEqual(sum('az-relay-client' in r for r in rules), count)
                    self.assertFalse(any('az-relay-client-rebuild' in r for r in rules))
                    for suffix, interface in (('29', 'warp-antizapret'), ('28', 'warp-vpn')):
                        source = f'{prefix}.{suffix}.0.0/16'
                        expected = 'ACCEPT' if only == 'y' and suffix == '28' else 'DROP'
                        self.assertEqual(self.verdict(rules, source, '0x2', 'eth0'), expected)
                        self.assertEqual(self.verdict(rules, source, '0x2', interface), 'ACCEPT')
                        self.assertEqual(self.verdict(rules, source, '0x0', 'eth0'), 'ACCEPT')
                    # Check every mutation during a repeat leaves both sources guarded.
                    result = self.run_guard(folder, REQUIRE_COVERAGE='y', PREFIX=prefix, ONLY=only)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                result = self.run_guard(folder, 'down')
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertEqual(json.loads(path.read_text()), [['NATIVE_ACCEPT'], ['NATIVE_ACCEPT']])

    def test_failed_replacement_retains_temporary_drop_until_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            folder = Path(directory)
            (folder / 'client.conf').write_text('prefix=10\nonly=y\n')
            (folder / 'mock.py').write_text(MOCK)
            path = folder / 'rules.json'
            path.write_text(json.dumps([['NATIVE_ACCEPT']]))
            result = self.run_guard(folder, FAIL_INSERT='y')
            self.assertNotEqual(result.returncode, 0)
            rules = json.loads(path.read_text())
            self.assertIn('az-relay-client-rebuild', rules[0])
            self.assertEqual(self.verdict(rules, '10.29.0.0/16', '0x2', 'eth0'), 'DROP')
            result = self.run_guard(folder)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rules = json.loads(path.read_text())
            self.assertEqual(len(rules), 2)
            self.assertIn('az-relay-client', rules[0])


if __name__ == '__main__':
    unittest.main()
