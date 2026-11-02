"""Firewall rebuilds serialize independently of the install operation lock."""

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which('bash') or r'C:\Program Files\Git\bin\bash.exe'


class FirewallLockTests(unittest.TestCase):
    def setUp(self):
        detected = subprocess.run([BASH, '-c', 'command -v flock'], capture_output=True, text=True)
        if detected.returncode:
            self.skipTest('POSIX flock is unavailable in this shell.')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.state = Path(temporary.name)
        (self.state / 'server.conf').write_text('# synthetic donor state\n')
        (self.state / 'client.conf').write_text('prefix=10\nonly=n\n')

    def run_script(self, script):
        return subprocess.run([BASH, '-c', script], capture_output=True, text=True, timeout=10, env={
            **os.environ,
            'COMMON_SOURCE': (ROOT / 'lib/common.sh').as_posix(),
            'CLIENT_SOURCE': (ROOT / 'lib/client.sh').as_posix(),
            'SERVER_SOURCE': (ROOT / 'lib/server.sh').as_posix(),
            'MAIN_SOURCE': (ROOT / 'lib/main.sh').as_posix(),
            'TEST_STATE': self.state.as_posix(),
        })

    def test_concurrent_client_and_donor_calls_wait_on_same_lock_and_release_after_failure(self):
        result = self.run_script(r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
source "$SERVER_SOURCE"
STATE_DIR=$TEST_STATE
FIREWALL_LOCK_FILE=$STATE_DIR/firewall.lock
require_root() { :; }
stat() { printf '0\n'; }
server_load_state() { return 0; }
iptables() {
    local role=CLIENT
    [[ $* != *az-relay-rebuild* ]] || role=SERVER
    if ! mkdir "$STATE_DIR/in-firewall"; then die 'Concurrent firewall mutation'; fi
    printf '%s_BEGIN\n' "$role" >> "$STATE_DIR/events"
    if [[ $role == SERVER ]]; then
        : > "$STATE_DIR/server-entered"
        while [[ ! -f $STATE_DIR/release-server ]]; do sleep 0.01; done
    fi
    printf '%s_END\n' "$role" >> "$STATE_DIR/events"
    rmdir "$STATE_DIR/in-firewall"
    # Stop each synthetic rebuild after its first iptables command.
    exit 0
}
server_firewall up &
server_pid=$!
while [[ ! -f $STATE_DIR/server-entered ]]; do sleep 0.01; done
client_firewall up &
client_pid=$!
sleep 0.05
[[ $(wc -l < "$STATE_DIR/events") == 1 ]] || die 'Client did not wait for donor lock'
touch "$STATE_DIR/release-server"
wait "$server_pid"
wait "$client_pid"
cat "$STATE_DIR/events"
# Process failure must release the kernel lock too.
( firewall_lock; exit 19 ) &
failed_pid=$!
wait "$failed_pid" || [[ $? == 19 ]]
( firewall_lock; printf 'LOCK_RELEASED\n' )
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            'SERVER_BEGIN', 'SERVER_END', 'CLIENT_BEGIN', 'CLIENT_END', 'LOCK_RELEASED'])

    def test_native_hook_can_rebuild_while_parent_installer_holds_operation_lock(self):
        result = self.run_script(r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
source "$MAIN_SOURCE"
STATE_DIR=$TEST_STATE
OPERATION_LOCK_FILE=$STATE_DIR/operation.lock
FIREWALL_LOCK_FILE=$STATE_DIR/firewall.lock
require_root() { :; }
stat() { printf '0\n'; }
iptables() { printf 'HOOK_REBUILT\n'; exit 0; }
server_firewall() { :; }
exec 9>"$OPERATION_LOCK_FILE"
flock -n 9
firewall_command up client
flock -n 9 || die 'Firewall released the parent install lock'
printf 'INSTALL_LOCK_RETAINED\n'
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['HOOK_REBUILT', 'INSTALL_LOCK_RETAINED'])

    def test_absent_roles_return_without_creating_firewall_lock(self):
        (self.state / 'server.conf').unlink()
        (self.state / 'client.conf').unlink()
        result = self.run_script(r'''
source "$COMMON_SOURCE"
source "$CLIENT_SOURCE"
source "$SERVER_SOURCE"
STATE_DIR=$TEST_STATE
FIREWALL_LOCK_FILE=$STATE_DIR/firewall.lock
require_root() { :; }
server_firewall up
client_firewall up
[[ ! -e $FIREWALL_LOCK_FILE ]] || die 'Absent role created a lock'
''')
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == '__main__':
    unittest.main()
