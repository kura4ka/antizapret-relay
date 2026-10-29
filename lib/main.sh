usage() {
    cat <<'HELP'
AntiZapret Relay: use your own WireGuard VPS instead of Cloudflare WARP.

Client VPS (Server 1): users connect to its AntiZapret.
Donor VPS (Server 2): selected domains use its public IP.
One VPS can run BOTH roles. Tunnel subnets and keys are selected automatically.
Download install.sh to both servers, then run as root:
  # On Server 2:
  bash install.sh server --endpoint SERVER2_PUBLIC_IPV4 [--port 51888] [--uplink eth0]
  # On Server 1, after copying the bundle from Server 2:
  bash install.sh client --bundle /root/antizapret-relay-import.json --domain example.com

Donor creates /root/antizapret-relay-donor.json (SECRET). Copy it privately to
the client as /root/antizapret-relay-import.json. Never publish private keys.
Client replaces WARP peers for both AntiZapret and full VPN custom-domain mode.
Use --antizapret-only to leave the full VPN WARP peer unchanged. DNS WARP stays
unchanged. Existing shared WARP include/exclude lists continue to apply.

After installation:
  antizapret-relay domain add example.com
  antizapret-relay domain remove example.com
  antizapret-relay domain list
  antizapret-relay status
  antizapret-relay uninstall
  antizapret-relay uninstall --role client
  antizapret-relay uninstall --role server
  antizapret-relay uninstall --role all

Upgrade an existing installation without restarting its tunnels:
  bash install.sh upgrade
HELP
}

relay_status() {
    local found=n
    if [[ -f $STATE_DIR/server.conf ]]; then
        found=y
        log 'Role: DONOR (server): other VPS use this host as their exit.'
        systemctl --no-pager status wg-quick@az-relay.service || true
        wg show az-relay || true
    fi
    if [[ -f $STATE_DIR/client.conf ]]; then
        found=y
        log 'Role: CLIENT: selected domains from this AntiZapret use another donor.'
        systemctl --no-pager status antizapret.service || true
        wg show warp-antizapret || true
        wg show warp-vpn || true
        log 'Relay domain file (also see native WARP include/exclude lists):'
        config_tool domain-list "$CLIENT_DOMAINS"
        log 'Handshake age and RX bytes confirm connectivity; an interface alone does not.'
    fi
    [[ $found == y ]] || die 'Relay is not installed on this host.'
}

firewall_command() {
    local action=${1:-} role=${2:-all}
    [[ $# -le 2 && ( $action == up || $action == down ) ]] || die 'Usage: firewall up|down [client|server|all]'
    case "$role" in
        server) server_firewall "$action" ;;
        client) client_firewall "$action" ;;
        all) server_firewall "$action"; client_firewall "$action" ;;
        *) die 'Firewall role must be client, server or all.' ;;
    esac
}

uninstall_command() {
    local role=''
    if (($#)); then
        [[ $# -eq 2 && $1 == --role ]] || die 'Usage: uninstall [--role client|server|all]'
        role=$2
    elif [[ -f $STATE_DIR/client.conf && -f $STATE_DIR/server.conf ]]; then
        die 'Both roles are installed. Choose uninstall --role client, --role server or --role all.'
    elif [[ -f $STATE_DIR/client.conf ]]; then role=client
    elif [[ -f $STATE_DIR/server.conf ]]; then role=server
    else die 'Relay is not installed.'
    fi
    case "$role" in
        client) [[ -f $STATE_DIR/client.conf ]] || die 'Client role is not installed.'; client_uninstall ;;
        server) [[ -f $STATE_DIR/server.conf ]] || die 'Donor role is not installed.'; server_uninstall ;;
        all)
            [[ -f $STATE_DIR/client.conf || -f $STATE_DIR/server.conf ]] || die 'Relay is not installed.'
            if [[ -f $STATE_DIR/client.conf ]]; then client_uninstall; fi
            if [[ -f $STATE_DIR/server.conf ]]; then server_uninstall; fi
            ;;
        *) die 'Uninstall role must be client, server or all.' ;;
    esac
    log "Removed role: $role. The installer remains available."
}

relay_main() {
    local command_name=${1:-help}
    shift || true
    case "$command_name" in
        help|-h|--help) usage; return ;;
        --version|version) printf '%s\n' "$VERSION"; return ;;
    esac
    require_root
    require_commands flock
    exec 9>/run/lock/antizapret-relay.lock
    # Firewall is also called synchronously by systemd while install holds fd 9.
    if [[ $command_name != firewall ]]; then flock -n 9 || die 'Another relay operation is running.'; fi
    case "$command_name" in
        server) server_install "$@" ;;
        client) client_install "$@" ;;
        firewall) firewall_command "$@" ;;
        domain) domain_command "$@" ;;
        status) relay_status ;;
        uninstall) uninstall_command "$@" ;;
        upgrade)
            [[ $# -eq 0 ]] || die 'Usage: upgrade'
            [[ -f $STATE_DIR/client.conf || -f $STATE_DIR/server.conf ]] || die 'Install a role first.'
            install_dependencies
            install_self
            log 'Installer and firewall hooks upgraded. Existing keys and tunnel addresses are kept.'
            ;;
        *) usage >&2; die "Unknown command: $command_name" ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    SCRIPT_FILE=$(readlink -f "${BASH_SOURCE[0]}")
    relay_main "$@"
fi
