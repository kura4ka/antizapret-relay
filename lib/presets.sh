# Optional domain presets use the normal user-owned AntiZapret include list.
CLIENT_INCLUDES=/root/antizapret/config/include-warp-hosts.txt

gemini_domains() {
    config_tool gemini-domains
}

gemini_enable() (
    [[ -f $STATE_DIR/client.conf ]] || die 'Install the client role before enabling a domain preset.'
    client_compatibility
    local preset_stage added
    preset_stage=$(mktemp -d)
    trap 'rm -rf -- "$preset_stage"' EXIT
    added=$(config_tool prepare-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json")
    [[ $added =~ ^[0-9]+$ ]] || die 'Could not prepare the Gemini domain list.'
    if [[ $added == 0 ]]; then
        log 'Gemini website and API domains are already in the native include list. Existing exclusions still apply.'
        return 0
    fi
    trap 'gemini_enable_rollback "$preset_stage"' ERR
    config_tool apply-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json"
    (trap - ERR; cd "$AZ_DIR" && ./parse.sh)
    trap - ERR
    log 'Added Gemini website and API domains to /root/antizapret/config/include-warp-hosts.txt and applied the lists.'
    log 'Existing exclusions are kept. Remove any matching Gemini exclusions if you want these domains to use the donor.'
)

gemini_enable_rollback() {
    local preset_stage=$1
    trap - ERR
    if config_tool rollback-gemini "$CLIENT_INCLUDES" "$preset_stage/gemini.before.json"; then
        (cd "$AZ_DIR" && ./parse.sh) || log 'Could not reload the restored list; rerun /root/antizapret/parse.sh after resolving the error.'
    else
        # Do not discard the only recovery snapshot when the user edited the list.
        trap - EXIT
        log "Gemini recovery snapshot is kept at $preset_stage/gemini.before.json."
    fi
    die 'Could not apply the Gemini preset. Existing donor settings and keys are kept.'
}

preset_command() {
    [[ $# -eq 1 && $1 == gemini ]] || die 'Usage: antizapret-relay preset gemini'
    gemini_enable
}
