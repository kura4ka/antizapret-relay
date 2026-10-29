"""Rootless checks that failed tunnel routing cannot fall through to the uplink."""
import os
import json
import shutil
import subprocess
import sys
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

    def test_client_uninstall_and_failed_install_preserve_active_donor(self):
        for operation in ("uninstall", "rollback"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as directory:
                sandbox = Path(directory)
                state = sandbox / "state"
                antizapret = sandbox / "antizapret"
                stage = sandbox / "stage"
                for folder in (state, antizapret, stage):
                    folder.mkdir()
                setup = antizapret / "setup"
                setup.write_text("ANTIZAPRET_WARP=1\nUNRELATED=preserve\n", encoding="utf-8")
                (antizapret / "parse.sh").write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
                os.chmod(antizapret / "parse.sh", 0o755)
                (state / "client.conf").write_text("prefix=10\nonly=n\n", encoding="utf-8")
                (state / "setup.snapshot").write_bytes(setup.read_bytes())
                changes = state / "client-values.json"
                changes.write_text(json.dumps({"ANTIZAPRET_WARP": "4", "WARP_PROTECTION": "y"}), encoding="utf-8")
                subprocess.run([sys.executable, str(ROOT / "lib/config.py"), "apply", str(setup), str(state / "setup.before.json"), str(changes)], check=True)
                client_dropin = sandbox / "client-dropin.conf"
                client_dropin.write_text("[Service]\nExecStartPost=relay firewall up client\n", encoding="utf-8")
                client_domains = antizapret / "relay-include-warp-hosts.txt"
                client_domains.write_text("example.com\n", encoding="utf-8")
                donor_files = {
                    state / "server.conf": "RELAY_SUBNET=10.203.241.0/24\n",
                    sandbox / "az-relay.conf": "[Interface]\nPrivateKey=donor-key-preserved\n",
                    sandbox / "donor-dropin.conf": "[Service]\nExecStartPost=relay firewall up server\n",
                }
                for path, value in donor_files.items():
                    path.write_text(value, encoding="utf-8")
                script = r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
STATE_DIR=$TEST_STATE
AZ_DIR=$TEST_AZ
CLIENT_DROPIN=$TEST_CLIENT_DROPIN
CLIENT_DOMAINS=$TEST_CLIENT_DOMAINS
declare -A mock_rules=()
donor_rule='filter|FORWARD|-i az-relay -m comment --comment az-relay-forward -j AZRELAY-FWD'
mock_rules[$donor_rule]=1
trap 'declare -p mock_rules > "$RULE_DUMP"' EXIT
stat() { printf '0\n'; }
config_tool() { "$PYTHON_EXE" "$CONFIG_SOURCE" "$@"; }
iptables() {
    local table=filter op chain key
    [[ $1 != -w ]] || shift
    if [[ $1 == -t ]]; then table=$2; shift 2; fi
    op=$1; chain=$2; shift 2
    [[ $op != -I || ${1:-} != 1 ]] || shift
    key="$table|$chain|$*"
    case $op in
        -C) [[ -n ${mock_rules[$key]+yes} ]] ;;
        -I) mock_rules[$key]=1 ;;
        -D) unset 'mock_rules[$key]' ;;
        *) die "Unexpected iptables operation: $op" ;;
    esac
}
systemctl() {
    if [[ $1 == start ]]; then
        # Model the two role-specific ExecStartPost hooks after a native restart.
        if [[ -f $TEST_DONOR_DROPIN ]]; then printf 'DONOR_HOOK\n'; fi
        if [[ -f $CLIENT_DROPIN ]]; then client_firewall up; fi
    fi
    return 0
}
client_firewall up
if [[ $TEST_OPERATION == uninstall ]]; then
    client_uninstall
else
    client_install_rollback "$TEST_STAGE"
fi
'''
                dump = sandbox / "rules.txt"
                result = subprocess.run([BASH, "-c", script], env={
                    **os.environ,
                    "COMMON_SOURCE": (ROOT / "lib/common.sh").as_posix(),
                    "CLIENT_SOURCE": (ROOT / "lib/client.sh").as_posix(),
                    "CONFIG_SOURCE": (ROOT / "lib/config.py").as_posix(),
                    "PYTHON_EXE": Path(sys.executable).as_posix(),
                    "TEST_STATE": state.as_posix(),
                    "TEST_AZ": antizapret.as_posix(),
                    "TEST_STAGE": stage.as_posix(),
                    "TEST_CLIENT_DROPIN": client_dropin.as_posix(),
                    "TEST_CLIENT_DOMAINS": client_domains.as_posix(),
                    "TEST_DONOR_DROPIN": (sandbox / "donor-dropin.conf").as_posix(),
                    "TEST_OPERATION": operation,
                    "RULE_DUMP": dump.as_posix(),
                }, text=True, capture_output=True)
                self.assertEqual(result.returncode, 0 if operation == "uninstall" else 1, result.stdout + result.stderr)
                self.assertIn("DONOR_HOOK", result.stdout)
                for path, value in donor_files.items():
                    self.assertEqual(path.read_text(encoding="utf-8"), value)
                self.assertFalse((state / "client.conf").exists())
                self.assertFalse(client_dropin.exists())
                self.assertFalse(client_domains.exists())
                self.assertEqual(setup.read_text(encoding="utf-8"), "ANTIZAPRET_WARP=1\nUNRELATED=preserve\n")
                rules = dump.read_text(encoding="utf-8")
                self.assertIn("az-relay-forward", rules)
                self.assertNotIn("az-relay-client", rules)


if __name__ == "__main__":
    unittest.main()
