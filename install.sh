#!/bin/bash
set -euo pipefail

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly NC='\033[0m'

log() {
    echo -e "=> $1"
}

error() {
    echo -e "${RED}Error: $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}Warning: $1${NC}" >&2
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root"
    fi
}

check_distribution() {
    if [[ ! -f /etc/os-release ]]; then
        error "Cannot detect operating system"
    fi

    source /etc/os-release

    # Check if Debian-based
    if [[ ! "$ID" =~ ^(debian|ubuntu)$ ]] && [[ ! "$ID_LIKE" =~ debian ]]; then
        error "Unsupported distribution: $ID. Only Debian/Ubuntu based systems are supported."
    fi

    # Check version
    local version_id="${VERSION_ID:-0}"
    case "$ID" in
        debian)
            if (( $(echo "$version_id < 11" | bc -l 2>/dev/null || echo 0) )); then
                error "Debian version too old. Minimum required: 11 (Bullseye)"
            fi
            ;;
        ubuntu)
            if (( $(echo "$version_id < 20.04" | bc -l 2>/dev/null || echo 0) )); then
                error "Ubuntu version too old. Minimum required: 20.04 (Focal)"
            fi
            ;;
    esac

    log "Detected: $PRETTY_NAME"
}

install_dependencies() {
    log "Installing dependencies..."

    export DEBIAN_FRONTEND=noninteractive

    # Update package list
    apt-get update -qq || error "Failed to update package lists"

    # Install packages
    local packages=(
        python3-pip
        python3-yaml
        python3-qrcode
        python3-rich
        python3-click
        wireguard
        jq
        qrencode
        catimg
        iptables-persistent
        dnsmasq
        bc
        dnsutils
    )

    apt-get install -y "${packages[@]}" || error "Failed to install dependencies"
}

setup_symlink() {
    log "Creating symlink for wgm..."

    if [[ ! -f /opt/wgm/wireguard.py ]]; then
        error "wireguard.py not found in /opt/wgm/"
    fi

    chmod +x /opt/wgm/wireguard.py
    ln -sf /opt/wgm/wireguard.py /usr/local/bin/wgm
}

configure_dnsmasq() {
    log "Configuring dnsmasq to depend on WireGuard..."

    mkdir -p /etc/systemd/system/dnsmasq.service.d

    cat > /etc/systemd/system/dnsmasq.service.d/override.conf << 'EOF'
[Unit]
After=wg-quick@wg0.service network-online.target
Wants=wg-quick@wg0.service network-online.target
Before=
[Install]
WantedBy=multi-user.target
EOF
}

get_dns_domain() {
    # Try to read dns_domain from config.yaml
    local config_file="/opt/wgm/config.yaml"
    local domain="vpn.local"  # default

    if [[ -f "$config_file" ]]; then
        # Extract dns_domain from YAML (simple grep approach)
        local config_domain=$(grep -E "^dns_domain:" "$config_file" | sed -E "s/^dns_domain:\s*['\"]?([^'\"]+)['\"]?/\1/" | tr -d "'" | tr -d '"' | xargs)
        if [[ -n "$config_domain" ]]; then
            domain="$config_domain"
        fi
    fi

    echo "$domain"
}

update_resolv_conf() {
    local dns_domain=$(get_dns_domain)

    log "Configuring /etc/resolv.conf with DNS domain: $dns_domain"

    # Remove immutable flag if present
    chattr -i /etc/resolv.conf 2>/dev/null || true

    # Replace symlinked resolv.conf with static one
    if [[ -L /etc/resolv.conf ]]; then
        rm -f /etc/resolv.conf
    fi

    cat > /etc/resolv.conf << EOF
nameserver 127.0.0.1
search $dns_domain
nameserver 1.1.1.1
EOF

    # Make it immutable to prevent services from modifying it
    chattr +i /etc/resolv.conf 2>/dev/null || warn "Could not make resolv.conf immutable"
}

disable_systemd_resolved() {
    if systemctl is-active --quiet systemd-resolved.service; then
        log "Disabling systemd-resolved to prevent DNS port conflict..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        update_resolv_conf
    fi
}

restart_services() {
    log "Reloading systemd and restarting dnsmasq..."
    systemctl daemon-reload
    systemctl restart dnsmasq || error "Failed to restart dnsmasq"
}

create_config() {
    log "Creating initial configuration..."

    if [[ ! -f /opt/wgm/config.example.yaml ]]; then
        error "config.example.yaml not found in /opt/wgm/"
    fi

    # Only create if it doesn't exist (idempotent)
    if [[ ! -f /opt/wgm/config.yaml ]]; then
        cp /opt/wgm/config.example.yaml /opt/wgm/config.yaml
        log "Configuration file created at /opt/wgm/config.yaml"
    else
        log "Configuration file already exists, skipping"
    fi
}

main() {
    log "Starting WireGuard Manager installation..."

    check_root
    check_distribution
    install_dependencies
    setup_symlink
    configure_dnsmasq
    disable_systemd_resolved
    restart_services
    create_config

    # Update resolv.conf after config is created (in case dns_domain is customized)
    update_resolv_conf

    echo
    log "${GREEN}Installation complete!${NC}"
    log "Edit /opt/wgm/config.yaml to customize settings"
    log "Then run: wgm -h"
}

main "$@"