"""Meaningful, rootless checks of exit-server firewall isolation and lifecycle."""

import os
import ipaddress
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash") or r"C:\Program Files\Git\bin\bash.exe"


class ServerFirewallTests(unittest.TestCase):
    def choose_subnet(self, endpoint="1.1.1.1", port="51888", routes=None):
        return subprocess.run(
            [BASH, "-c", 'source "$SERVER_SOURCE"; python3() { "$PYTHON_EXE" "$@"; }; server_choose_subnet "$ENDPOINT" "$PORT" "$ROUTES_JSON"'],
            env={
                **os.environ,
                "SERVER_SOURCE": (ROOT / "lib/server.sh").as_posix(),
                "PYTHON_EXE": Path(sys.executable).as_posix(),
                "ENDPOINT": endpoint,
                "PORT": port,
                "ROUTES_JSON": json.dumps([] if routes is None else routes),
            },
            text=True,
            capture_output=True,
        )

    def test_automatic_transit_subnet_is_stable_and_varies_with_endpoint(self):
        first = self.choose_subnet()
        repeated = self.choose_subnet()
        other_endpoint = self.choose_subnet(endpoint="8.8.8.8")
        other_port = self.choose_subnet(port="51889")
        for result in (first, repeated, other_endpoint, other_port):
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            network = ipaddress.ip_network(result.stdout.strip())
            self.assertEqual(network.prefixlen, 24)
            self.assertTrue(network.subnet_of(ipaddress.ip_network("10.64.0.0/10")))
        self.assertEqual(first.stdout, repeated.stdout)
        self.assertNotEqual(first.stdout, other_endpoint.stdout)
        self.assertNotEqual(first.stdout, other_port.stdout)

    def test_automatic_subnet_skips_occupied_local_and_policy_routes(self):
        initial = self.choose_subnet()
        self.assertEqual(initial.returncode, 0, initial.stderr)
        blocked = ipaddress.ip_network(initial.stdout.strip())
        # One /32 is enough to reserve the entire candidate transit network.
        host_route = {"dst": str(blocked.network_address + 2) + "/32", "table": "local"}
        first_retry = self.choose_subnet(routes=[host_route, {"dst": "default"}, {"dst": "0.0.0.0/0"}])
        self.assertEqual(first_retry.returncode, 0, first_retry.stderr)
        self.assertFalse(ipaddress.ip_network(first_retry.stdout.strip()).overlaps(blocked))
        broad = blocked.supernet(prefixlen_diff=2)
        second_retry = self.choose_subnet(routes=[{"dst": str(broad), "table": 2000}])
        self.assertEqual(second_retry.returncode, 0, second_retry.stderr)
        self.assertFalse(ipaddress.ip_network(second_retry.stdout.strip()).overlaps(broad))

    def test_automatic_subnet_fails_if_every_candidate_is_occupied(self):
        exhausted = self.choose_subnet(routes=[{"dst": "10.64.0.0/10", "table": 2000}])
        self.assertNotEqual(exhausted.returncode, 0)
        self.assertEqual(exhausted.stdout, "")
        self.assertIn("No free transit subnet", exhausted.stderr)
        self.assertNotIn("10.64.0.0", exhausted.stderr, "Do not print private route inventories")

    def test_donor_hooks_only_dispatch_donor_firewall(self):
        source = (ROOT / "lib/server.sh").read_text(encoding="utf-8")
        self.assertIn("PostUp = $APP firewall up server\n", source)
        self.assertIn("PostDown = $APP firewall down server\n", source)
        self.assertIn("ExecStartPost=-%s firewall up server", source)
        self.assertNotIn('[[ ! -e "$STATE_DIR/client.conf" ]]', source)
        self.assertNotIn("/root/antizapret-relay-client.json", source)
        self.assertIn("SERVER_BUNDLE=/root/antizapret-relay-donor.json", source)

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
            client_metadata = {
                "client.conf": "prefix=10\nonly=n\n",
                "client-values.json": '{"ANTIZAPRET_WARP": "4"}\n',
                "setup.before.json": '{"ANTIZAPRET_WARP": "1"}\n',
                "antizapret-relay-import.json": '{"old_import": true}\n',
                "antizapret-relay-client.json": '{"legacy_import": true}\n',
            }
            for name, content in client_metadata.items():
                (state / name).write_text(content, encoding="utf-8")
            script = r'''
set -euo pipefail
source "$SERVER_SOURCE"
STATE_DIR=$TEST_STATE
WG_IF=az-relay
WG_CONF=$STATE_DIR/az-relay.conf
SERVER_BUNDLE=$STATE_DIR/antizapret-relay-donor.json
printf 'mock donor config\n' > "$WG_CONF"
printf 'mock donor bundle\n' > "$SERVER_BUNDLE"
declare -A mock_rules=() mock_chains=()
client_guard='filter|FORWARD|-s 10.29.0.0/16 -m mark --mark 0x2 ! -o warp-antizapret -m comment --comment az-relay-client -j DROP'
mock_rules[$client_guard]=1
require_root() { :; }
die() { printf '%s\n' "$*" >&2; exit 1; }
log() { :; }
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
[[ ${#mock_rules[@]} == 1 && -n ${mock_rules[$client_guard]+yes} ]] || die 'Donor teardown removed the client guard or left donor rules'
[[ ${#mock_chains[@]} == 0 ]] || die 'Firewall chains left behind'
# Exercise donor removal on a combined host. Absolute installation paths are
# mocked, while real temporary role metadata must remain untouched.
systemctl() {
    case "$*" in
        'disable --now wg-quick@az-relay'|'daemon-reload') : ;;
        *) die "Donor uninstall touched another service: $*" ;;
    esac
}
rm() {
    local item
    for item in "$@"; do
        [[ $item != -* ]] || continue
        case $item in
            "$STATE_DIR/server.conf"|"$WG_CONF"|"$SERVER_BUNDLE") command rm -f -- "$item" ;;
            /etc/sysctl.d/98-antizapret-relay.conf|/etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf) : ;;
            *) die "Donor uninstall touched another role: $item" ;;
        esac
    done
}
server_firewall up
server_uninstall
[[ ${#mock_rules[@]} == 1 && -n ${mock_rules[$client_guard]+yes} ]] || die 'Donor uninstall removed client guard'
[[ ! -f $STATE_DIR/server.conf && ! -f $WG_CONF ]] || die 'Donor metadata left behind'
[[ ! -f $SERVER_BUNDLE ]] || die 'Donor export left behind'
[[ -f $STATE_DIR/client.conf && -f $STATE_DIR/client-values.json && -f $STATE_DIR/setup.before.json ]] || die 'Client metadata removed'
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
            for name, content in client_metadata.items():
                self.assertEqual((state / name).read_text(encoding="utf-8"), content)


if __name__ == "__main__":
    unittest.main()
