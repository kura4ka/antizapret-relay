#!/usr/bin/env bash
# This file is compiled into install.sh by tools/build.py.
set -Eeuo pipefail
umask 077
VERSION=0.2.0
STATE_DIR=/etc/antizapret-relay
APP=/usr/local/sbin/antizapret-relay
WG_IF=az-relay
WG_CONF=/etc/wireguard/az-relay.conf
AZ_DIR=/root/antizapret
log() { printf '[antizapret-relay] %s\n' "$*"; }
die() { printf '[antizapret-relay] ERROR: %s\n' "$*" >&2; exit 1; }
require_root() { [[ $EUID -eq 0 ]] || die 'Run as root (sudo bash install.sh ...).'; }
require_commands() {
    local command_name
    for command_name in "$@"; do
        command -v "$command_name" >/dev/null || die "Required command: $command_name";
    done
}
install_dependencies() {
    require_root
    [[ -d /run/systemd/system ]] || die 'A Linux host booted with systemd is required.'
    # shellcheck disable=SC1091
    source /etc/os-release
    [[ ${ID:-} == debian || ${ID:-} == ubuntu ]] || die 'Supported: Debian and Ubuntu.'
    if ! command -v wg >/dev/null || ! command -v wg-quick >/dev/null || ! command -v ip >/dev/null || ! command -v iptables >/dev/null || ! command -v python3 >/dev/null || ! command -v curl >/dev/null; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools iptables iproute2 python3 curl
    fi
    require_commands wg wg-quick ip iptables python3 curl systemctl flock
}
validate_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    ipaddress.IPv4Address(sys.argv[1])
except ValueError:
    sys.exit('A numeric IPv4 address is required.')
PY
}
validate_public_ipv4() {
    python3 - "$1" <<'PY'
import ipaddress, sys
try:
    address = ipaddress.IPv4Address(sys.argv[1])
    if not address.is_global or address.is_multicast:
        raise ValueError()
except ValueError:
    sys.exit('A public, numeric IPv4 address is required.')
PY
}
validate_port() { [[ $1 =~ ^[0-9]{1,5}$ ]] && (( 10#$1 >= 1024 && 10#$1 <= 65535 )); }
install_self() {
    [[ -f $SCRIPT_FILE ]] || die 'Download install.sh to a file before running it.'
    if [[ $(readlink -f "$SCRIPT_FILE") != "$APP" ]]; then
        install -m 0755 "$SCRIPT_FILE" "$APP"
    fi
    install -d -m 0700 "$STATE_DIR"
    # Older installations called firewall for both roles from each hook. Scope
    # those hooks before a second role is added, without restarting tunnels.
    config_tool scope-hooks "$STATE_DIR" "$WG_CONF" "$APP" /etc/systemd/system/antizapret.service.d
    systemctl daemon-reload
}
ipt_add() {
    local table=$1 chain=$2; shift 2
    iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null || iptables -w -t "$table" -I "$chain" 1 "$@"
}
ipt_del() {
    local table=$1 chain=$2; shift 2
    while iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -w -t "$table" -D "$chain" "$@"
    done
}
