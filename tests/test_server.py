"""Meaningful, rootless checks of exit-server firewall isolation and lifecycle."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"


class ServerFirewallTests(unittest.TestCase):
    def test_transit_subnet_reserves_host_addresses_and_excludes_antizapret(self):
        cases = {
            "10.203.240.0/24": True,
            "172.16.7.0/24": True,
            "192.168.70.0/24": True,
            "10.28.1.0/24": False,
            "10.30.1.0/24": False,
            "172.29.1.0/24": False,
            "192.0.2.0/24": False,
            "10.203.240.0/16": False,
            "10.203.240.5/24": False,
        }
        for subnet, accepted in cases.items():
            with self.subTest(subnet=subnet):
                result = subprocess.run(
                    [BASH, "-c", 'source "$SERVER_SOURCE"; python3() { "$PYTHON_EXE" "$@"; }; server_validate_subnet "$SUBNET"'],
                    env={
                        **os.environ,
                        "SERVER_SOURCE": (ROOT / "lib/server.sh").as_posix(),
                        "PYTHON_EXE": Path(sys.executable).as_posix(),
                        "SUBNET": subnet,
                    },
                    text=True,
                    capture_output=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stdout + result.stderr)
                if accepted:
                    prefix = subnet.rsplit(".", 1)[0]
                    self.assertEqual(result.stdout.splitlines(), [prefix + suffix for suffix in (".0", ".1", ".2", ".3")])

    def test_scoped_rules_survive_repeat_and_are_removed_on_uninstall(self):
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "server.conf").write_text("# Mock state\n", encoding="utf-8")
            script = r'''
set -euo pipefail
source "$SERVER_SOURCE"
STATE_DIR=$TEST_STATE
WG_IF=az-relay
declare -A mock_rules=() mock_chains=()
require_root() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
server_load_state() {
    RELAY_UPLINK=eth0
    RELAY_PORT=51888
    RELAY_SERVER_IP=10.203.240.1
    RELAY_ANTIZAPRET_IP=10.203.240.2
    RELAY_VPN_IP=10.203.240.3
}
ip() { return 0; }
iptables() {
    local table=filter op chain key rule
    [[ $1 != -w ]] || shift
    if [[ $1 == -t ]]; then table=$2; shift 2; fi
    op=$1; chain=$2; shift 2
    [[ $op != -I || ${1:-} != 1 ]] || shift
    key="$table|$chain|$*"
    case $op in
        -C) [[ -n ${mock_rules[$key]+yes} ]] ;;
        -D) unset 'mock_rules[$key]' ;;
        -A|-I) mock_rules[$key]=1 ;;
        -N) mock_chains["$table|$chain"]=1 ;;
        -S) [[ -n ${mock_chains["$table|$chain"]+yes} ]] ;;
        -F) for rule in "${!mock_rules[@]}"; do
                if [[ $rule == "$table|$chain|"* ]]; then unset 'mock_rules[$rule]'; fi
            done ;;
        -X) unset 'mock_chains[$table|$chain]' ;;
        *) die "Unexpected iptables operation: $op" ;;
    esac
}
server_firewall up
count_first=${#mock_rules[@]}
for rule in "${!mock_rules[@]}"; do printf '%s\n' "$rule"; done
printf 'FIRST_COUNT=%s\n' "$count_first"
server_firewall up
[[ ${#mock_rules[@]} == "$count_first" ]] || die 'Duplicate firewall rules after reinstall'
server_firewall down
[[ ${#mock_rules[@]} == 0 ]] || die 'Firewall rules left behind'
[[ ${#mock_chains[@]} == 0 ]] || die 'Firewall chains left behind'
printf 'CLEANED\n'
'''
            result = subprocess.run(
                [BASH, "-c", script],
                env={
                    **os.environ,
                    "SERVER_SOURCE": (ROOT / "lib/server.sh").as_posix(),
                    "TEST_STATE": state.as_posix(),
                },
                text=True,
                capture_output=True,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            rules = result.stdout.splitlines()
            self.assertIn("CLEANED", rules)
            for peer in ("10.203.240.2", "10.203.240.3"):
                self.assertIn(f"filter|AZRELAY-FWD|-s {peer}/32 -o eth0 -j ACCEPT", rules)
                self.assertIn(f"nat|AZRELAY-NAT|-s {peer}/32 -j MASQUERADE", rules)
                self.assertIn(
                    f"filter|AZRELAY-RETURN|-i eth0 -d {peer}/32 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT",
                    rules,
                )
            self.assertIn("filter|AZRELAY-FWD|-d 169.254.0.0/16 -j REJECT --reject-with icmp-admin-prohibited", rules)
            self.assertIn("filter|AZRELAY-FWD|-j DROP", rules)
            self.assertIn("filter|AZRELAY-RETURN|-j DROP", rules)
            self.assertIn("filter|AZRELAY-INPUT|-j DROP", rules)
            self.assertFalse(any("raw|" in line for line in rules), "AntiZapret raw protection must remain in force")
            self.assertFalse(any("-s 0.0.0.0/0" in line for line in rules))


if __name__ == "__main__":
    unittest.main()
