# German exit server. This file is concatenated into install.sh by build.py.

server_load_state() {
    [[ -f "$STATE_DIR/server.conf" && ! -L "$STATE_DIR/server.conf" ]] || die 'Exit server is not installed.'
    [[ $(stat -c %u "$STATE_DIR/server.conf") == 0 ]] || die 'Server state must be owned by root.'
    # This is a root-owned file generated with printf %q, never a downloaded bundle.
    # shellcheck disable=SC1091
    source "$STATE_DIR/server.conf"
    [[ ${RELAY_UPLINK:-} =~ ^[a-zA-Z0-9_.:-]{1,15}$ ]] || die 'Invalid uplink in server state.'
    validate_port "${RELAY_PORT:-}"
    validate_ipv4 "${RELAY_SERVER_IP:-}"
    validate_ipv4 "${RELAY_ANTIZAPRET_IP:-}"
    validate_ipv4 "${RELAY_VPN_IP:-}"
}

server_iptables_remove() {
    local table=$1 chain=$2
    shift 2
    while iptables -w -t "$table" -C "$chain" "$@" 2>/dev/null; do
        iptables -w -t "$table" -D "$chain" "$@"
    done
}

server_firewall() {
    require_root
    local action=${1:-}
    [[ $action == up || $action == down ]] || die 'Usage: firewall up|down'
    [[ -f "$STATE_DIR/server.conf" ]] || return 0
    server_load_state

    # Keep tunnel traffic closed while rebuilding our chains. If any command
    # fails, these guards stay in place until a successful retry or uninstall.
    local guard_chain guard_direction guard_comment
    for guard_chain in INPUT FORWARD; do
        guard_direction=-i
        guard_comment="az-relay-rebuild-$guard_chain-in"
        if [[ $action == up ]] && ! iptables -w -C "$guard_chain" "$guard_direction" "$WG_IF" -m comment --comment "$guard_comment" -j DROP 2>/dev/null; then
            iptables -w -I "$guard_chain" 1 "$guard_direction" "$WG_IF" -m comment --comment "$guard_comment" -j DROP
        fi
    done
    if [[ $action == up ]] && ! iptables -w -C FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP 2>/dev/null; then
        iptables -w -I FORWARD 1 -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
    fi

    # Reinsert our hooks when AntiZapret has prepended its own rules on restart.
    server_iptables_remove filter INPUT -i "$RELAY_UPLINK" -p udp --dport "$RELAY_PORT" -m comment --comment az-relay-listen -j ACCEPT
    server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-input -j AZRELAY-INPUT
    server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-forward -j AZRELAY-FWD
    server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-return -j AZRELAY-RETURN
    server_iptables_remove nat POSTROUTING -o "$RELAY_UPLINK" -m comment --comment az-relay-nat -j AZRELAY-NAT
    server_iptables_remove mangle FORWARD -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -m comment --comment az-relay-mss -j TCPMSS --clamp-mss-to-pmtu

    local chain
    for chain in AZRELAY-INPUT AZRELAY-FWD AZRELAY-RETURN; do
        if iptables -w -t filter -S "$chain" >/dev/null 2>&1; then
            iptables -w -t filter -F "$chain"
            if [[ $action == down ]]; then iptables -w -t filter -X "$chain"; fi
        elif [[ $action == up ]]; then
            iptables -w -t filter -N "$chain"
        fi
    done
    if iptables -w -t nat -S AZRELAY-NAT >/dev/null 2>&1; then
        iptables -w -t nat -F AZRELAY-NAT
        if [[ $action == down ]]; then iptables -w -t nat -X AZRELAY-NAT; fi
    elif [[ $action == up ]]; then
        iptables -w -t nat -N AZRELAY-NAT
    fi
    if [[ $action == down ]]; then
        server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-rebuild-INPUT-in -j DROP
        server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-in -j DROP
        server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
        return 0
    fi
    # A stopped tunnel must never leave a new public forwarding path behind.
    ip link show dev "$WG_IF" >/dev/null 2>&1 || return 0

    iptables -w -A AZRELAY-INPUT -m conntrack --ctstate INVALID -j DROP
    iptables -w -A AZRELAY-FWD -m conntrack --ctstate INVALID -j DROP
    iptables -w -A AZRELAY-RETURN -m conntrack --ctstate INVALID -j DROP

    local peer destination
    # The relay is an Internet exit, not a route into the destination VPS network.
    # This also prevents forwarding to the other WireGuard peers or metadata IPs.
    for destination in \
        0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
        172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 \
        198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4; do
        iptables -w -A AZRELAY-FWD -d "$destination" -j REJECT --reject-with icmp-admin-prohibited
    done
    for peer in "$RELAY_ANTIZAPRET_IP" "$RELAY_VPN_IP"; do
        iptables -w -A AZRELAY-INPUT -s "$peer/32" -d "$RELAY_SERVER_IP/32" -p icmp --icmp-type echo-request -j ACCEPT
        iptables -w -A AZRELAY-FWD -s "$peer/32" -o "$RELAY_UPLINK" -j ACCEPT
        iptables -w -A AZRELAY-RETURN -i "$RELAY_UPLINK" -d "$peer/32" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        iptables -w -t nat -A AZRELAY-NAT -s "$peer/32" -j MASQUERADE
    done
    iptables -w -A AZRELAY-INPUT -j DROP
    iptables -w -A AZRELAY-FWD -j DROP
    iptables -w -A AZRELAY-RETURN -j DROP
    # POSTROUTING cannot match -i: peer /32 sources are authenticated by WireGuard
    # AllowedIPs, checked in FORWARD, and cannot overlap any pre-existing route.
    iptables -w -I INPUT 1 -i "$RELAY_UPLINK" -p udp --dport "$RELAY_PORT" -m comment --comment az-relay-listen -j ACCEPT
    iptables -w -I INPUT 1 -i "$WG_IF" -m comment --comment az-relay-input -j AZRELAY-INPUT
    iptables -w -I FORWARD 1 -i "$WG_IF" -m comment --comment az-relay-forward -j AZRELAY-FWD
    iptables -w -I FORWARD 1 -o "$WG_IF" -m comment --comment az-relay-return -j AZRELAY-RETURN
    iptables -w -t nat -I POSTROUTING 1 -o "$RELAY_UPLINK" -m comment --comment az-relay-nat -j AZRELAY-NAT
    iptables -w -t mangle -I FORWARD 1 -i "$WG_IF" -p tcp --tcp-flags SYN,RST SYN -m comment --comment az-relay-mss -j TCPMSS --clamp-mss-to-pmtu
    server_iptables_remove filter INPUT -i "$WG_IF" -m comment --comment az-relay-rebuild-INPUT-in -j DROP
    server_iptables_remove filter FORWARD -i "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-in -j DROP
    server_iptables_remove filter FORWARD -o "$WG_IF" -m comment --comment az-relay-rebuild-FORWARD-out -j DROP
}

server_validate_subnet() {
    python3 - "$1" <<'PY'
import ipaddress
import sys
try:
    subnet = ipaddress.IPv4Network(sys.argv[1], strict=True)
    private = [ipaddress.IPv4Network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
    if subnet.prefixlen != 24 or not any(subnet.subnet_of(n) for n in private):
        raise ValueError('Transit subnet must be an RFC1918 IPv4 /24.')
    for reserved in ('10.28.0.0/14', '172.28.0.0/14'):
        if subnet.overlaps(ipaddress.IPv4Network(reserved)):
            raise ValueError('Transit subnet overlaps an AntiZapret client or fake address range.')
except ValueError as exc:
    print(str(exc), file=sys.stderr)
    sys.exit(1)
print(subnet.network_address)
print(subnet.network_address + 1)
print(subnet.network_address + 2)
print(subnet.network_address + 3)
PY
}

server_install() (
    set -Eeuo pipefail
    require_root
    local endpoint='' port=51888 uplink='' subnet=10.203.240.0/24
    while (($#)); do
        case $1 in
            --endpoint) (($# >= 2)) || die '--endpoint requires an IPv4 address'; endpoint=$2; shift 2 ;;
            --port) (($# >= 2)) || die '--port requires a number'; port=$2; shift 2 ;;
            --uplink) (($# >= 2)) || die '--uplink requires an interface'; uplink=$2; shift 2 ;;
            --subnet) (($# >= 2)) || die '--subnet requires an RFC1918 /24'; subnet=$2; shift 2 ;;
            *) die "Unknown server option: $1" ;;
        esac
    done
    if [[ -z $endpoint ]]; then
        [[ -t 0 ]] || die 'Specify --endpoint with the German VPS public IPv4 address.'
        read -r -p 'German VPS public IPv4 address: ' endpoint
    fi
    [[ ! -e "$STATE_DIR/client.conf" ]] || die 'This host is already configured as the Japan client.'
    [[ ! -e "$STATE_DIR/server.conf" && ! -e "$WG_CONF" ]] || die 'Exit server already installed, or az-relay.conf exists. Use status; existing keys are kept.'
    [[ ! -e /root/antizapret-relay-client.json ]] || die '/root/antizapret-relay-client.json already exists; preserve or move it before installation.'
    [[ ! -e /etc/sysctl.d/98-antizapret-relay.conf ]] || die 'Relay sysctl file already exists.'
    [[ ! -e /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf ]] || die 'Relay systemd override already exists.'
    install_dependencies
    require_commands ip iptables wg wg-quick python3 systemctl sysctl ss stat
    validate_public_ipv4 "$endpoint" || die 'A public IPv4 endpoint is required.'
    validate_port "$port" || die 'UDP port must be an integer between 1024 and 65535.'
    [[ ! -e "/sys/class/net/$WG_IF" ]] || die "Interface $WG_IF already exists."
    local check_chain
    for check_chain in AZRELAY-INPUT AZRELAY-FWD AZRELAY-RETURN; do
        if iptables -w -t filter -S "$check_chain" >/dev/null 2>&1; then
            die "Firewall chain already exists: $check_chain"
        fi
    done
    if iptables -w -t nat -S AZRELAY-NAT >/dev/null 2>&1; then
        die 'Firewall chain already exists: AZRELAY-NAT'
    fi
    [[ -z $(ss -H -lun "sport = :$port") ]] || die "UDP port $port is already in use."
    if [[ -z $uplink ]]; then
        uplink=$(ip -4 route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}')
    fi
    [[ $uplink =~ ^[a-zA-Z0-9_.:-]{1,15}$ && $uplink != lo && $uplink != "$WG_IF" && $uplink != warp-* ]] || die 'Could not select a physical Internet uplink; use --uplink.'
    ip link show dev "$uplink" >/dev/null 2>&1 || die "Uplink does not exist: $uplink"
    local subnet_values
    subnet_values=$(server_validate_subnet "$subnet") || die 'Invalid transit subnet.'
    local server_ip antizapret_ip vpn_ip
    { read -r _; read -r server_ip; read -r antizapret_ip; read -r vpn_ip; } <<<"$subnet_values"
    [[ $endpoint != "$server_ip" && $endpoint != "$antizapret_ip" && $endpoint != "$vpn_ip" ]] || die 'Endpoint must not be in the transit subnet.'
    local routes
    routes=$(ip -j -4 route show table all)
    python3 - "$subnet" "$routes" <<'PY' || die 'Transit subnet overlaps an existing route; choose another --subnet.'
import ipaddress
import json
import sys
subnet = ipaddress.ip_network(sys.argv[1])
for route in json.loads(sys.argv[2]):
    destination = route.get('dst', 'default')
    if destination == 'default':
        continue
    try:
        existing = ipaddress.ip_network(destination, strict=False)
    except ValueError:
        continue
    if existing.overlaps(subnet):
        print('Conflicting route: ' + destination, file=sys.stderr)
        sys.exit(1)
PY
    local transaction
    transaction=$(mktemp -d /tmp/antizapret-relay.XXXXXXXX)
    chmod 700 "$transaction"
    local installed=0 success=0 forward_before
    forward_before=$(sysctl -n net.ipv4.ip_forward)
    server_install_cleanup() {
        local result=$?
        if (( ! success && installed )); then
            systemctl disable --now "wg-quick@$WG_IF" >/dev/null 2>&1 || true
            server_firewall down >/dev/null 2>&1 || true
            rm -f -- "$WG_CONF" "$STATE_DIR/server.conf" /root/antizapret-relay-client.json \
                /etc/sysctl.d/98-antizapret-relay.conf \
                /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
            systemctl daemon-reload >/dev/null 2>&1 || true
            sysctl -q -w "net.ipv4.ip_forward=$forward_before" >/dev/null 2>&1 || true
        fi
        rm -rf -- "$transaction"
        exit "$result"
    }
    trap server_install_cleanup EXIT
    local server_private server_public antizapret_private antizapret_public vpn_private vpn_public
    server_private=$(wg genkey)
    server_public=$(printf '%s\n' "$server_private" | wg pubkey)
    antizapret_private=$(wg genkey)
    antizapret_public=$(printf '%s\n' "$antizapret_private" | wg pubkey)
    vpn_private=$(wg genkey)
    vpn_public=$(printf '%s\n' "$vpn_private" | wg pubkey)
    cat >"$transaction/az-relay.conf" <<EOF
[Interface]
Address = $server_ip/24
PrivateKey = $server_private
ListenPort = $port
MTU = 1280
Table = off
PostUp = $APP firewall up
PostDown = $APP firewall down

[Peer]
# Japan: AntiZapret clients
PublicKey = $antizapret_public
AllowedIPs = $antizapret_ip/32

[Peer]
# Japan: full VPN clients (distinct key required)
PublicKey = $vpn_public
AllowedIPs = $vpn_ip/32
EOF
    {
        printf 'RELAY_ENDPOINT=%q\n' "$endpoint:$port"
        printf 'RELAY_UPLINK=%q\n' "$uplink"
        printf 'RELAY_PORT=%q\n' "$port"
        printf 'RELAY_SUBNET=%q\n' "$subnet"
        printf 'RELAY_SERVER_IP=%q\n' "$server_ip"
        printf 'RELAY_ANTIZAPRET_IP=%q\n' "$antizapret_ip"
        printf 'RELAY_VPN_IP=%q\n' "$vpn_ip"
        printf 'RELAY_IP_FORWARD_BEFORE=%q\n' "$forward_before"
    } >"$transaction/server.conf"
    # Private keys go through stdin, never through process arguments or log output.
    printf '%s\n' "$endpoint:$port" "$server_public" "$antizapret_private" "$antizapret_ip/32" "$vpn_private" "$vpn_ip/32" |
        python3 -c 'import json,sys; values=sys.stdin.read().splitlines(); json.dump(dict(zip(("version","endpoint","server_public_key","antizapret_private_key","antizapret_address","vpn_private_key","vpn_address"),(1,*values))),sys.stdout,indent=2); print()' >"$transaction/client.json"
    install_self
    install -d -m 700 "$STATE_DIR"
    install -d -m 700 /etc/wireguard
    install -d -m 755 /etc/systemd/system/antizapret.service.d
    installed=1
    install -m 600 "$transaction/server.conf" "$STATE_DIR/server.conf"
    install -m 600 "$transaction/az-relay.conf" "$WG_CONF"
    install -m 600 "$transaction/client.json" /root/antizapret-relay-client.json
    printf 'net.ipv4.ip_forward=1\n' >/etc/sysctl.d/98-antizapret-relay.conf
    chmod 644 /etc/sysctl.d/98-antizapret-relay.conf
    # Do not make a firewall-repair failure take the existing VPN service offline.
    printf '[Service]\nExecStartPost=-%s firewall up\n' "$APP" >/etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    chmod 644 /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    sysctl -q -w net.ipv4.ip_forward=1
    systemctl daemon-reload
    systemctl enable --now "wg-quick@$WG_IF"
    success=1
    log "Exit server is ready at $endpoint:$port (UDP)."
    log 'Copy /root/antizapret-relay-client.json securely to the Japan VPS; it contains private keys.'
    log 'Allow this UDP port in the VPS provider firewall, if the provider uses one.'
)

server_uninstall() {
    require_root
    server_load_state
    systemctl disable --now "wg-quick@$WG_IF"
    server_firewall down
    rm -f -- "$WG_CONF" /etc/sysctl.d/98-antizapret-relay.conf /etc/systemd/system/antizapret.service.d/90-antizapret-relay-server.conf
    rm -f -- /root/antizapret-relay-client.json "$STATE_DIR/server.conf"
    systemctl daemon-reload
    log 'Exit server removed. Other VPN interfaces and firewall rules are kept.'
    log 'Runtime IPv4 forwarding is kept enabled because the existing AntiZapret may require it.'
}
