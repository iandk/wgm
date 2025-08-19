#!/bin/bash

# Install dependencies
apt install python3-pip python3-yaml python3-qrcode python3-rich python3-click wireguard jq qrencode catimg iptables-persistent dnsmasq

# Create symlink for wgm
ln -s /opt/wgm/wireguard.py /usr/local/bin/wgm

# Initialize wgm
wgm init

echo "Installation complete! Please run 'wgm -h' to get started. Also see the configuration file at /opt/wgm/config.yaml for more information."