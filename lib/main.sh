usage() {
    cat <<'HELP'
AntiZapret Relay: use your own WireGuard VPS instead of Cloudflare WARP.

Download install.sh to a file, then run as root:
  bash install.sh server --endpoint GERMANY_PUBLIC_IPV4 [--port 51888] [--uplink eth0]
  bash install.sh client --bundle /root/antizapret-relay-client.json --domain old.yummyani.me

Server creates /root/antizapret-relay-client.json (SECRET). Copy it privately to
the Japan VPS using scp. Never upload this file or WireGuard keys to GitHub.
Client replaces WARP peers for both AntiZapret and full VPN custom-domain mode.
Use --antizapret-only to leave the full VPN WARP peer unchanged. DNS WARP stays
unchanged. Existing shared WARP include/exclude lists continue to apply.

After installation:
  antizapret-relay domain add old.yummyani.me
  antizapret-relay domain remove old.yummyani.me
  antizapret-relay domain list
  antizapret-relay status
  antizapret-relay uninstall
HELP
}

relay_status() {
    if [[ -f $STATE_DIR/server.conf ]]; then
        log 'Role: server (exit VPS)'
        systemctl --no-pager status wg-quick@az-relay.service || true
        wg show az-relay || true
    elif [[ -f $STATE_DIR/client.conf ]]; then
        log 'Role: client (AntiZapret entry VPS)'
        systemctl --no-pager status antizapret.service || true
        wg show warp-antizapret || true
        wg show warp-vpn || true
        log 'Relay domain file (also see native WARP include/exclude lists):'
        config_tool domain-list "$CLIENT_DOMAINS"
        log 'Handshake age and RX bytes confirm connectivity; an interface alone does not.'
    else
        die 'Relay is not installed on this host.'
    fi
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
        firewall)
            [[ ${1:-} == up || ${1:-} == down ]] || die 'firewall up|down required'
            server_firewall "$1"
            client_firewall "$1"
            ;;
        domain) domain_command "$@" ;;
        status) relay_status ;;
        uninstall)
            if [[ -f $STATE_DIR/client.conf ]]; then client_uninstall
            elif [[ -f $STATE_DIR/server.conf ]]; then server_uninstall
            else die 'Relay is not installed.'; fi
            log 'Relay removed. The installer remains available for a future installation.'
            ;;
        *) usage >&2; die "Unknown command: $command_name" ;;
    esac
}

SCRIPT_FILE=$(readlink -f "${BASH_SOURCE[0]}")
relay_main "$@"
