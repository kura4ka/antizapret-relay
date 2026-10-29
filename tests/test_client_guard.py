"""Rootless checks that failed tunnel routing cannot fall through to the uplink."""
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"


class ClientGuardTests(unittest.TestCase):
    def test_guard_is_scoped_idempotent_and_removed_for_both_prefixes(self):
        for prefix, only in (("10", "n"), ("172", "n"), ("10", "y")):
            with self.subTest(prefix=prefix, only=only), tempfile.TemporaryDirectory() as directory:
                state = Path(directory)
                (state / "client.conf").write_text(f"prefix={prefix}\nonly={only}\n", encoding="utf-8")
                script = r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
STATE_DIR=$TEST_STATE
declare -A mock_rules=()
stat() { printf '0\n'; }
iptables() {
    local table=filter op chain key
    [[ $1 != -w ]] || shift
    if [[ $1 == -t ]]; then table=$2; shift 2; fi
    op=$1; chain=$2; shift 2
    [[ $op != -I || ${1:-} != 1 ]] || shift
    key="$table|$chain|$*"
    case $op in
        -C) [[ -n ${mock_rules[$key]+yes} ]] ;;
        -I) mock_rules[$key]=$(( ${mock_rules[$key]:-0} + 1 )) ;;
        -D) unset 'mock_rules[$key]' ;;
        *) die "Unexpected iptables operation: $op" ;;
    esac
}
client_firewall up
for rule in "${!mock_rules[@]}"; do printf '%s\n' "$rule"; done
first_count=${#mock_rules[@]}
client_firewall up
[[ ${#mock_rules[@]} == "$first_count" ]] || die 'Duplicate rule keys'
for rule in "${!mock_rules[@]}"; do
    [[ ${mock_rules[$rule]} == 1 ]] || die 'Duplicate rule insertion'
done
client_firewall down
[[ ${#mock_rules[@]} == 0 ]] || die 'Rules left behind'
printf 'CLEANED\n'
'''
                result = subprocess.run([BASH, "-c", script], env={
                    **os.environ,
                    "COMMON_SOURCE": (ROOT / "lib/common.sh").as_posix(),
                    "CLIENT_SOURCE": (ROOT / "lib/client.sh").as_posix(),
                    "TEST_STATE": state.as_posix(),
                }, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                rules = result.stdout.splitlines()
                self.assertIn("CLEANED", rules)
                expected = {f"filter|FORWARD|-s {prefix}.29.0.0/16 -m mark --mark 0x2 ! -o warp-antizapret -m comment --comment az-relay-client -j DROP"}
                if only == "n":
                    expected.add(f"filter|FORWARD|-s {prefix}.28.0.0/16 -m mark --mark 0x2 ! -o warp-vpn -m comment --comment az-relay-client -j DROP")
                self.assertEqual(set(rules) - {"CLEANED"}, expected)
                self.assertFalse(any("--ctstate NEW" in rule for rule in rules), "Established connections must also be protected")
                self.assertFalse(any("nat|" in rule or "raw|" in rule or "OUTPUT" in rule or "--dport 53" in rule for rule in rules))


if __name__ == "__main__":
    unittest.main()
