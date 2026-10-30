# Interactive setup; the explicit client/server commands remain available.
WIZARD_IMPORT=${WIZARD_IMPORT:-/root/antizapret-relay-import.json}

wizard_read() {
    local target=$1 prompt=$2 default=${3:-} reply
    printf '%s' "$prompt" >&2
    if ! read -r reply; then
        printf '\n' >&2
        die 'Input ended. Run bash install.sh again from an interactive SSH terminal.'
    fi
    printf -v "$target" '%s' "${reply:-$default}"
}

wizard_server() {
    if [[ -f $STATE_DIR/server.conf ]]; then
        log 'Server / donor role is already installed; keeping its keys and settings.'
        return 0
    fi
    local endpoint port
    log 'Set up THIS VPS as a server / donor for another VPS.'
    while true; do
        wizard_read endpoint 'Public IPv4 of THIS donor VPS: '
        if validate_public_ipv4 "$endpoint" 2>/dev/null; then break; fi
        log 'Enter a public IPv4 address, for example 1.2.3.4.'
    done
    while true; do
        wizard_read port 'WireGuard UDP port [51888]: ' 51888
        if validate_port "$port"; then break; fi
        log 'Enter a UDP port from 1024 to 65535.'
    done
    port=$((10#$port))
    # Keep these calls outside conditionals: backends depend on errexit/ERR traps.
    server_install --endpoint "$endpoint" --port "$port"
}

gemini_install_prompt() {
    local target=$1 answer
    while true; do
        wizard_read answer 'Route Gemini through the donor? [y/N]: ' n
        case "${answer,,}" in
            y|yes) printf -v "$target" '%s' y; return ;;
            n|no) printf -v "$target" '%s' n; return ;;
        esac
        log 'Enter y or n.'
    done
}

wizard_client() (
    local gemini=n
    if [[ -f $STATE_DIR/client.conf ]]; then
        log 'Client role is already installed; keeping its donor and settings.'
        gemini_install_prompt gemini
        if [[ $gemini == y ]]; then gemini_enable; fi
        return 0
    fi
    local allow_defer=${1:-n} bundle='' donor_ip='' ssh_port='' wizard_stage='' own_bundle=''
    trap 'if [[ -n $wizard_stage ]]; then rm -f -- "$wizard_stage/donor.json"; rmdir -- "$wizard_stage"; fi' EXIT
    if [[ -f $WIZARD_IMPORT ]]; then
        bundle=$WIZARD_IMPORT
        log "Using the existing imported connection file: $bundle"
    else
        log 'Connect THIS AntiZapret VPS to ANOTHER server / donor.'
        if [[ $allow_defer == y ]]; then
            log 'If the other donor is not ready, press Enter to connect the client later.'
        fi
        while true; do
            wizard_read donor_ip 'Public IPv4 of the OTHER donor VPS: '
            if [[ -z $donor_ip && $allow_defer == y ]]; then
                log 'Client setup deferred. Run bash install.sh again and choose 1 when the other donor is ready.'
                return 0
            fi
            if validate_public_ipv4 "$donor_ip" 2>/dev/null; then break; fi
            log 'Enter the public IPv4 of the donor, not this client VPS.'
        done
        while true; do
            wizard_read ssh_port 'SSH port on the donor [22]: ' 22
            if [[ $ssh_port =~ ^[0-9]{1,5}$ ]] && ((10#$ssh_port >= 1 && 10#$ssh_port <= 65535)); then break; fi
            log 'Enter an SSH port from 1 to 65535.'
        done
        ssh_port=$((10#$ssh_port))
        if ! command -v scp >/dev/null; then
            apt-get update
            DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-client
        fi
        require_commands scp
        wizard_stage=$(mktemp -d)
        chmod 0700 "$wizard_stage"
        bundle=$wizard_stage/donor.json
        log 'Downloading connection keys over SSH as root on the donor.'
        log 'Verify the SSH host fingerprint if asked. A password prompt is for the DONOR VPS.'
        if ! scp -P "$ssh_port" -o ConnectTimeout=15 -o StrictHostKeyChecking=ask -- \
            "root@$donor_ip:/root/antizapret-relay-donor.json" "$bundle"; then
            die 'Could not fetch donor keys. Set up the donor first and check root SSH access, or copy the bundle manually and use client --bundle FILE.'
        fi
    fi
    # validate-bundle prints private keys; never let its output reach the terminal.
    config_tool validate-bundle "$bundle" >/dev/null
    if [[ -f $STATE_DIR/server.conf && -f $SERVER_BUNDLE ]]; then own_bundle=$SERVER_BUNDLE; fi
    python3 - "$bundle" "$donor_ip" "$own_bundle" <<'PY'
import json
import sys
from pathlib import Path

bundle = json.loads(Path(sys.argv[1]).read_text(encoding='utf-8'))
if sys.argv[2] and bundle['endpoint'].split(':')[0] != sys.argv[2]:
    sys.exit('Donor endpoint differs from the entered IP. Check the donor configuration, or transfer the correct bundle manually.')
if sys.argv[3]:
    try:
        own = json.loads(Path(sys.argv[3]).read_text(encoding='utf-8'))
    except (OSError, ValueError):
        sys.exit('Cannot read the local donor export. Repair it before connecting another donor.')
    if not isinstance(own, dict) or 'server_public_key' not in own:
        sys.exit('Local donor export is invalid. Repair it before connecting another donor.')
    if own.get('server_public_key') == bundle['server_public_key']:
        sys.exit('This is the local donor bundle. Enter the IP or import the keys of ANOTHER donor VPS.')
PY
    gemini_install_prompt gemini
    local -a client_options=(--bundle "$bundle")
    if [[ $gemini == y ]]; then client_options+=(--gemini); fi
    log 'Connecting the client to the donor. AntiZapret will restart briefly.'
    client_install "${client_options[@]}"
)

wizard_done() {
    printf '\n'
    if [[ -f $STATE_DIR/server.conf ]]; then
        log 'SERVER / DONOR: installed. Open its chosen WireGuard UDP port in the hosting provider firewall.'
        log 'On the other VPS, run bash install.sh and choose 1 to connect to this donor.'
    fi
    if [[ -f $STATE_DIR/client.conf ]]; then
        log 'CLIENT: installed. Manage domains ON THIS CLIENT VPS:'
        if [[ -f $STATE_DIR/default-exclusions.json ]]; then
            log 'Bundled WARP defaults are excluded in the marked block of exclude-warp-hosts.txt.'
        fi
    else
        log 'CLIENT: not installed here. Manage domains ON THE CLIENT VPS after connecting it:'
    fi
    log 'Send through donor: /root/antizapret/config/include-warp-hosts.txt'
    log 'Exceptions:         /root/antizapret/config/exclude-warp-hosts.txt'
    log 'Use one domain per line, without https:// or paths. Domain entries include subdomains.'
    log 'After editing either file, apply ON THE CLIENT: /root/antizapret/parse.sh'
    log 'Check installed roles: antizapret-relay status'
}

interactive_install() (
    [[ -t 0 ]] || die 'Interactive setup needs a terminal. Download install.sh, then run bash install.sh over SSH; use --help for unattended commands.'
    local choice
    trap 'if [[ $? != 0 ]]; then log "Setup stopped. Already installed roles are kept; fix the error and run bash install.sh again."; fi' EXIT
    printf '\nAntiZapret Relay setup\n'
    printf '  1) Client - selected domains use another donor VPS\n'
    printf '  2) Server / donor - let another VPS use this public IP\n'
    printf '  3) Both - install server / donor and client on this VPS\n\n'
    while true; do
        wizard_read choice 'Choose a role [1/2/3]: '
        case "$choice" in 1|2|3) break ;; esac
        log 'Choose 1, 2 or 3.'
    done
    install_dependencies
    if [[ ( $choice == 1 || $choice == 3 ) && ! -f $STATE_DIR/client.conf ]]; then
        client_compatibility
    fi
    case "$choice" in
        1) wizard_client n ;;
        2) wizard_server ;;
        3) wizard_server; wizard_client y ;;
    esac
    wizard_done
)
