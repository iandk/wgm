#!/bin/bash
set -euo pipefail

log() {
    echo "=> $1"
}

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        log "This script must be run as root."
        exit 1
    fi
}

main() {
    export DEBIAN_FRONTEND=noninteractive
    check_root
    
    log "Installing dependencies..."
    apt-get update
    apt-get install -y \
        python3-pip \
        python3-yaml \
        python3-qrcode \
        python3-rich \
        python3-click \
        wireguard \
        jq \
        qrencode \
        catimg \
        iptables-persistent \
        dnsmasq

    log "Creating symlink for wgm..."
    ln -sf /opt/wgm/wireguard.py /usr/local/bin/wgm

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

    if systemctl is-active --quiet systemd-resolved.service; then
        log "Disabling systemd-resolved to prevent DNS port conflict..."
        systemctl stop systemd-resolved
        systemctl disable systemd-resolved
        # Replace symlinked resolv.conf with a static one
        rm -f /etc/resolv.conf
        echo "nameserver 1.1.1.1" > /etc/resolv.conf
        echo "nameserver 8.8.8.8" >> /etc/resolv.conf
    fi

    log "Reloading systemd and restarting dnsmasq..."
    systemctl daemon-reload
    systemctl restart dnsmasq

    log "Initializing wgm..."
    wgm init

    log "Installation complete! Please run 'wgm -h' to get started."
    log "See the configuration file at /opt/wgm/config.yaml for more information."
}

main "$@"