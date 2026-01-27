# Bash completion for wgm (WireGuard Manager)
# Install: source /opt/wgm/completions/wgm.bash

_wgm_get_clients() {
    local clients_file="/opt/wgm/clients.json"
    if [[ -f "$clients_file" ]]; then
        # Extract client names from JSON keys
        jq -r 'keys[]' "$clients_file" 2>/dev/null
    fi
}

_wgm_completions() {
    local cur prev words cword
    _init_completion || return

    local commands="add config remove list apply restrict"
    local add_opts="--full-tunnel --full --split-tunnel --split --exclude-public-ips --exclude-ip --restrict-to"
    local config_opts="--show-qr --qrcode"
    local remove_opts="--yes -y"
    local restrict_opts="--allow --deny --clear"
    local global_opts="-c --config -v --verbose -h --help"

    # Handle command completion
    if [[ $cword -eq 1 ]]; then
        COMPREPLY=($(compgen -W "$commands $global_opts" -- "$cur"))
        return
    fi

    local command="${words[1]}"

    case "$command" in
        add)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$add_opts $global_opts" -- "$cur"))
            fi
            ;;
        config)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$config_opts $global_opts" -- "$cur"))
            elif [[ $cword -eq 2 ]]; then
                # Complete client names
                local clients=$(_wgm_get_clients)
                COMPREPLY=($(compgen -W "$clients" -- "$cur"))
            fi
            ;;
        remove)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$remove_opts $global_opts" -- "$cur"))
            elif [[ $cword -eq 2 ]]; then
                # Complete client names
                local clients=$(_wgm_get_clients)
                COMPREPLY=($(compgen -W "$clients" -- "$cur"))
            fi
            ;;
        restrict)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$restrict_opts $global_opts" -- "$cur"))
            elif [[ $cword -eq 2 ]]; then
                # Complete client names
                local clients=$(_wgm_get_clients)
                COMPREPLY=($(compgen -W "$clients" -- "$cur"))
            fi
            ;;
        list|apply)
            if [[ "$cur" == -* ]]; then
                COMPREPLY=($(compgen -W "$global_opts" -- "$cur"))
            fi
            ;;
        -c|--config)
            # Complete config file paths
            _filedir yaml
            ;;
    esac
}

complete -F _wgm_completions wgm
