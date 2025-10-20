#!/usr/bin/env python3
import subprocess
import ipaddress
from pathlib import Path
import qrcode
import base64
import logging
import time
import json
import socket
import sys
import os
import yaml
import requests
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, asdict, field
from rich import box
from rich.console import Console
from rich.syntax import Syntax
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Confirm
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)
console = Console()


@dataclass
class WireGuardConfig:
    """WireGuard server configuration."""
    ipv4_subnet: str = '10.99.99.0/24'
    ipv6_subnet: str = 'fd99:99::/64'
    wg_interface: str = 'wg0'
    server_port: int = 51820
    config_dir: str = '/etc/wireguard'
    qr_dir: str = '/opt/wgm/qr_codes'
    interface_name: str = 'eth0'
    server_public_key: str = ''
    server_private_key: str = ''
    endpoint: str = ''
    full_tunnel: bool = False
    dns_domain: str = ''
    dns_overrides: Dict[str, str] = field(default_factory=dict)
    dnsmasq_read_etc_hosts: bool = True

    @classmethod
    def from_dict(cls, config_dict: Dict) -> 'WireGuardConfig':
        return cls(**{k: v for k, v in config_dict.items() if k in cls.__annotations__})


@dataclass
class WireGuardClient:
    """WireGuard client configuration."""
    name: str
    public_key: str
    ipv4: str
    ipv6: str
    allowed_ips: List[str]
    restricted_ips: List[str] = field(default_factory=list)  # IPv4 restrictions
    restricted_ip6s: List[str] = field(default_factory=list)  # IPv6 restrictions
    created_at: str = ''


class WireGuardManager:
    """Manages WireGuard VPN server and clients."""

    def __init__(self, config_path: str = 'config.yaml'):
        # Get the directory where the script is located, following symlinks
        self.script_dir = Path(os.path.realpath(__file__)).parent.resolve()

        # Use absolute paths based on script location
        self.config_path = (self.script_dir / config_path).resolve()
        self.clients_file = self.script_dir / 'clients.json'
        self.config_hash_file = self.script_dir / '.config_hash'

        # Strict check: verify system dependencies exist
        self._verify_system_dependencies()

        # Soft check: load or bootstrap configuration
        self.config = self._load_or_create_config()
        self.clients: Dict[str, WireGuardClient] = {}
        self._load_clients()

        # Check if config changed and update if needed
        self._check_config_changes()

    def _verify_system_dependencies(self) -> None:
        """Verify critical system dependencies are installed."""
        missing = []

        if not Path('/usr/bin/wg').exists():
            missing.append("wireguard")
        if not Path('/usr/sbin/dnsmasq').exists():
            missing.append("dnsmasq")

        if missing:
            console.print(f"[red]Error: Required packages not installed: {', '.join(missing)}[/red]")
            console.print("\n[yellow]Please run the installation script:[/yellow]")
            console.print("  bash /opt/wgm/install.sh")
            sys.exit(1)

    def _load_or_create_config(self) -> WireGuardConfig:
        """Load existing config or create from example template."""
        # If config.yaml doesn't exist, copy from example
        if not self.config_path.exists():
            example_path = self.script_dir / 'config.example.yaml'
            if not example_path.exists():
                console.print(f"[red]Error: Example configuration file not found: {example_path}[/red]")
                console.print("\n[yellow]Please ensure config.example.yaml exists or run:[/yellow]")
                console.print("  bash /opt/wgm/install.sh")
                sys.exit(1)

            console.print("[yellow]No configuration found. Creating config.yaml from example...[/yellow]")
            import shutil
            shutil.copy(example_path, self.config_path)

        # Load the config
        try:
            with open(self.config_path) as f:
                config = WireGuardConfig.from_dict(yaml.safe_load(f) or {})
        except Exception as e:
            logger.error(f"Failed to load config: {e}")
            sys.exit(1)

        # Smart bootstrap: auto-fill missing critical runtime values
        needs_save = False

        if not config.server_private_key:
            console.print("[yellow]Generating server keypair...[/yellow]")
            private_key, public_key = self._generate_keypair()
            config.server_private_key = private_key
            config.server_public_key = public_key
            needs_save = True

        if not config.endpoint:
            console.print("[yellow]Auto-detecting server endpoint...[/yellow]")
            config.endpoint = self._get_server_endpoint()
            console.print(f"[green]Detected endpoint: {config.endpoint}[/green]")
            needs_save = True

        if not config.dns_domain:
            console.print("[yellow]Auto-detecting DNS domain...[/yellow]")
            config.dns_domain = self._get_dns_domain()
            console.print(f"[green]Using DNS domain: {config.dns_domain}[/green]")
            needs_save = True

        # Ensure critical directories exist
        Path(config.config_dir).mkdir(mode=0o700, parents=True, exist_ok=True)
        Path(config.qr_dir).mkdir(mode=0o755, parents=True, exist_ok=True)

        # Save if we made changes
        if needs_save:
            self._save_config_internal(config)
            console.print("[green]Configuration initialized successfully![/green]")

        # Ensure WireGuard interface is set up
        self._ensure_interface_ready(config)

        return config

    def _save_config_internal(self, config: WireGuardConfig) -> None:
        """Internal method to save config preserving comments from example."""
        try:
            # Read the current config (which should be a copy of example with comments)
            with open(self.config_path, 'r') as f:
                lines = f.readlines()

            # Update values while preserving comments and structure
            config_dict = asdict(config)
            new_lines = []

            for line in lines:
                stripped = line.strip()

                # Preserve comments and empty lines
                if stripped.startswith('#') or not stripped:
                    new_lines.append(line)
                    continue

                # Update values
                if ':' in line:
                    key = line.split(':')[0].strip()
                    if key in config_dict:
                        value = config_dict[key]
                        # Format the value properly
                        if isinstance(value, str):
                            new_lines.append(f"{key}: '{value}'\n")
                        elif isinstance(value, bool):
                            new_lines.append(f"{key}: {'true' if value else 'false'}\n")
                        elif isinstance(value, list):
                            if value:
                                new_lines.append(f"{key}: {value}\n")
                            else:
                                new_lines.append(f"{key}: []\n")
                        else:
                            new_lines.append(f"{key}: {value}\n")
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            # Write back
            with open(self.config_path, 'w') as f:
                f.writelines(new_lines)

        except Exception as e:
            logger.error(f"Failed to save config: {e}")
            sys.exit(1)

    def _ensure_interface_ready(self, config: WireGuardConfig) -> None:
        """Ensure WireGuard interface and basic networking is configured."""
        try:
            # Enable IP forwarding if not already enabled
            ipv4_forward = Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()
            ipv6_forward = Path('/proc/sys/net/ipv6/conf/all/forwarding').read_text().strip()

            if ipv4_forward != '1' or ipv6_forward != '1':
                console.print("[yellow]Enabling IP forwarding...[/yellow]")
                with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                    f.write('1\n')
                with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                    f.write('1\n')

                # Make forwarding persistent
                sysctl_conf = Path('/etc/sysctl.d/99-wireguard.conf')
                sysctl_conf.write_text(
                    "net.ipv4.ip_forward=1\n"
                    "net.ipv6.conf.all.forwarding=1\n"
                )
        except Exception as e:
            logger.warning(f"Could not ensure interface ready: {e}")

    def _compute_config_hash(self) -> str:
        """Compute hash of config fields that affect DNS/client configs."""
        # Only hash fields that matter for DNS and client configs
        relevant_fields = {
            'dns_domain': self.config.dns_domain,
            'endpoint': self.config.endpoint,
            'server_port': self.config.server_port,
            'dns_overrides': self.config.dns_overrides,
            'dnsmasq_read_etc_hosts': self.config.dnsmasq_read_etc_hosts,
        }
        config_str = json.dumps(relevant_fields, sort_keys=True)
        return hashlib.sha256(config_str.encode()).hexdigest()

    def _check_config_changes(self) -> None:
        """Check if config changed and update DNS/client configs if needed."""
        try:
            current_hash = self._compute_config_hash()

            # Read stored hash
            if self.config_hash_file.exists():
                stored_hash = self.config_hash_file.read_text().strip()

                if stored_hash != current_hash:
                    console.print("[yellow]Configuration changes detected, updating...[/yellow]")

                    # Update DNS configuration
                    if self.clients:
                        self._update_dns_config()

                        # Regenerate client configs if endpoint or port changed
                        self._regenerate_client_configs()

                    # Save new hash
                    self.config_hash_file.write_text(current_hash)
                    console.print("[green]Configuration updated successfully![/green]")
            else:
                # First run, save hash
                self.config_hash_file.write_text(current_hash)

        except Exception as e:
            logger.warning(f"Failed to check config changes: {e}")

    def _regenerate_client_configs(self) -> None:
        """Regenerate all client configuration files with updated endpoint/domain."""
        try:
            console.print("[yellow]Regenerating client configurations...[/yellow]")

            for name, client in self.clients.items():
                # Read the private key from existing config
                config_path = Path(self.config.config_dir) / f"{name}.conf"
                if not config_path.exists():
                    logger.warning(f"Config file not found for client {name}, skipping")
                    continue

                # Extract private key from existing config
                config_content = config_path.read_text()
                private_key = None
                for line in config_content.split('\n'):
                    if line.startswith('PrivateKey'):
                        private_key = line.split('=')[1].strip()
                        break

                if not private_key:
                    logger.warning(f"Could not find private key for client {name}, skipping")
                    continue

                # Generate new config with updated endpoint/domain
                new_config = self._create_client_config(client, private_key)
                config_path.write_text(new_config)

                # Regenerate QR code
                qr_path = Path(self.config.qr_dir) / f"{name}_qr.png"
                try:
                    self._run_command([
                        'qrencode',
                        '-t', 'png',
                        '-o', str(qr_path),
                        '-s', '2',
                        '-m', '1'
                    ], input_data=new_config)
                except Exception as e:
                    logger.warning(f"Failed to regenerate QR code for {name}: {e}")

            console.print(f"[green]Regenerated configs for {len(self.clients)} client(s)[/green]")

        except Exception as e:
            logger.error(f"Failed to regenerate client configs: {e}")

    def _save_config(self) -> None:
        """Save configuration to file preserving comments."""
        self._save_config_internal(self.config)

    def _load_clients(self) -> None:
        """Load clients from JSON file."""
        if self.clients_file.exists():
            try:
                clients_data = json.loads(self.clients_file.read_text())
                self.clients = {
                    name: WireGuardClient(**data)
                    for name, data in clients_data.items()
                }
            except Exception as e:
                logger.error(f"Failed to load clients: {e}")
                self.clients = {}

    def _save_clients(self) -> None:
        """Save clients to JSON file."""
        try:
            clients_data = {
                name: asdict(client)
                for name, client in self.clients.items()
            }
            self.clients_file.write_text(json.dumps(clients_data, indent=2))
        except Exception as e:
            logger.error(f"Failed to save clients: {e}")

    def _run_command(self, cmd: List[str], input_data: str = None,
                     timeout: int = 30) -> str:
        """Run system command with timeout."""
        try:
            if input_data:
                result = subprocess.run(
                    cmd,
                    input=input_data.encode(),
                    capture_output=True,
                    timeout=timeout
                )
            else:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    timeout=timeout
                )

            if result.returncode != 0:
                raise subprocess.CalledProcessError(
                    result.returncode, cmd, result.stdout, result.stderr
                )

            return result.stdout.decode().strip()
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout}s: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Command failed: {' '.join(cmd)}, Error: {e}")
            raise

    def _generate_keypair(self) -> Tuple[str, str]:
        """Generate WireGuard keypair."""
        private_key = self._run_command(['wg', 'genkey'])
        public_key = self._run_command(['wg', 'pubkey'], input_data=private_key)
        return private_key, public_key

    def _get_server_endpoint(self) -> str:
        """Get server endpoint (FQDN or IP)."""
        try:
            # Try FQDN first
            fqdn = socket.getfqdn()
            if fqdn and fqdn != 'localhost' and '.' in fqdn:
                return fqdn

            # Fallback to public IP
            response = requests.get(
                'https://getip.sh',
                timeout=5
            )
            ip = response.json()['ip'] or None
            
            if not ip:
                raise ValueError("Failed to get public IP")
            
            return ip
        except Exception as e:
            logger.warning(f"Failed to get server endpoint: {e}")
            raise e
            

    def _get_dns_domain(self) -> str:
        """Get a default DNS domain if not set."""
        return 'vpn.local'

    def _get_next_available_ips(self) -> Dict[str, str]:
        """Get next available IPs for a new client."""
        ipv4_net = ipaddress.ip_network(self.config.ipv4_subnet)
        ipv6_net = ipaddress.ip_network(self.config.ipv6_subnet)

        used_ipv4s = {client.ipv4.split('/')[0] for client in self.clients.values()}
        used_ipv6s = {client.ipv6.split('/')[0] for client in self.clients.values()}

        # Skip first IP (reserved for server)
        for ip in list(ipv4_net.hosts())[1:]:
            if str(ip) not in used_ipv4s:
                next_ipv4 = f"{ip}/{ipv4_net.prefixlen}"
                break
        else:
            raise ValueError(f"No available IPv4s in subnet {self.config.ipv4_subnet}")

        next_ip = ipv6_net.network_address + 2
        while str(next_ip) in used_ipv6s:
            next_ip += 1
            if next_ip not in ipv6_net:
                raise ValueError(f"No available IPv6s in subnet {self.config.ipv6_subnet}")

        next_ipv6 = f"{next_ip}/{ipv6_net.prefixlen}"
        return {'ipv4': next_ipv4, 'ipv6': next_ipv6}

    def initialize(self) -> None:
        """Initialize WireGuard server."""
        try:
            # Install WireGuard if needed
            if not Path('/usr/bin/wg').exists():
                self._run_command(['apt', 'update'])
                self._run_command(['apt', 'install', '-y', 'wireguard'])

            # Create config directory
            Path(self.config.config_dir).mkdir(mode=0o700, parents=True, exist_ok=True)

            # Generate server keys if needed
            if not self.config.server_private_key:
                private_key, public_key = self._generate_keypair()
                self.config.server_private_key = private_key
                self.config.server_public_key = public_key

            # Set endpoint if not configured
            if not self.config.endpoint:
                self.config.endpoint = self._get_server_endpoint()
                logger.info(f"Detected server endpoint: {self.config.endpoint}")

            # Set DNS domain if not configured
            if not self.config.dns_domain:
                self.config.dns_domain = self._get_dns_domain()
                logger.info(f"Detected DNS domain: {self.config.dns_domain}")

            # Ensure forwarding is enabled
            with open('/proc/sys/net/ipv4/ip_forward', 'w') as f:
                f.write('1\n')
            with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
                f.write('1\n')

            # Make forwarding persistent
            sysctl_conf = Path('/etc/sysctl.d/99-wireguard.conf')
            sysctl_conf.write_text(
                "net.ipv4.ip_forward=1\n"
                "net.ipv6.conf.all.forwarding=1\n"
            )

            self._ensure_persistent_firewall()
            self._save_config()
            self._update_server_config()

            # Verify interface is up
            if not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                raise RuntimeError("Failed to create WireGuard interface")

            console.print("[green]Server initialized successfully[/green]")
        except Exception as e:
            logger.error(f"Failed to initialize server: {e}")
            sys.exit(1)

    def _ensure_persistent_firewall(self) -> None:
        """Ensure firewall rules persist across reboots."""
        rules_file = Path('/etc/iptables/rules.v4')
        rules_file6 = Path('/etc/iptables/rules.v6')

        try:
            # Install iptables-persistent if needed
            if not rules_file.parent.exists():
                self._run_command(['apt', 'install', '-y', 'iptables-persistent'])
                rules_file.parent.mkdir(parents=True, exist_ok=True)

            # Save current rules
            self._run_command(['iptables-save'], timeout=5)
            self._run_command(['ip6tables-save'], timeout=5)

        except Exception as e:
            logger.warning(f"Failed to ensure persistent firewall: {e}")

    def _flush_forward_rules(self) -> None:
        """Flush all WireGuard-related FORWARD rules to prevent duplication."""
        logger.debug("Flushing old WireGuard FORWARD rules using iptables-restore.")
        try:
            # For IPv4
            iptables_dump = self._run_command(['iptables-save'])
            # Keep all lines except those that are FORWARD rules for our wg interface
            filtered_rules = [
                line for line in iptables_dump.split('\n')
                if not (line.startswith('-A FORWARD') and self.config.wg_interface in line)
            ]
            self._run_command(['iptables-restore'], input_data='\n'.join(filtered_rules))
            logger.debug("Successfully flushed old IPv4 FORWARD rules.")

            # For IPv6
            ip6tables_dump = self._run_command(['ip6tables-save'])
            filtered_rules_6 = [
                line for line in ip6tables_dump.split('\n')
                if not (line.startswith('-A FORWARD') and self.config.wg_interface in line)
            ]
            self._run_command(['ip6tables-restore'], input_data='\n'.join(filtered_rules_6))
            logger.debug("Successfully flushed old IPv6 FORWARD rules.")

        except Exception as e:
            logger.error(f"Failed to flush old FORWARD rules: {e}")
            raise  # Re-raise, as this is critical for preventing rule duplication

    def _update_client_firewall_rules(self, client: WireGuardClient) -> None:
        """Update firewall rules for a specific client."""
        try:
            client_ip = client.ipv4.split('/')[0]
            client_ip6 = client.ipv6.split('/')[0]

            # Clean up existing IPv4 rules
            try:
                iptables_list = self._run_command(['iptables', '-L', 'FORWARD', '--line-numbers'])
                for line in reversed(iptables_list.split('\n')):
                    if client_ip in line:
                        rule_num = line.split()[0]
                        self._run_command(['iptables', '-D', 'FORWARD', rule_num])
            except Exception as e:
                logger.warning(f"Error cleaning up old IPv4 rules: {e}")

            # Clean up existing IPv6 rules
            try:
                ip6tables_list = self._run_command(['ip6tables', '-L', 'FORWARD', '--line-numbers'])
                for line in reversed(ip6tables_list.split('\n')):
                    if client_ip6 in line:
                        rule_num = line.split()[0]
                        self._run_command(['ip6tables', '-D', 'FORWARD', rule_num])
            except Exception as e:
                logger.warning(f"Error cleaning up old IPv6 rules: {e}")

            # Add IPv4 restrictions
            if client.restricted_ips:
                for dest_ip in client.restricted_ips:
                    self._run_command([
                        'iptables', '-A', 'FORWARD',
                        '-i', self.config.wg_interface,
                        '-s', client_ip,
                        '-d', dest_ip,
                        '-j', 'ACCEPT'
                    ])

                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip,
                    '-j', 'DROP'
                ])

            # Add IPv6 restrictions
            if client.restricted_ip6s:
                for dest_ip in client.restricted_ip6s:
                    self._run_command([
                        'ip6tables', '-A', 'FORWARD',
                        '-i', self.config.wg_interface,
                        '-s', client_ip6,
                        '-d', dest_ip,
                        '-j', 'ACCEPT'
                    ])

                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip6,
                    '-j', 'DROP'
                ])

        except Exception as e:
            logger.error(f"Failed to update firewall rules for client {client.name}: {e}")
            raise

    def _update_server_config(self) -> None:
        """Update WireGuard server configuration."""
        try:
            # First try to clean up existing interface
            if Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                try:
                    # Stop interface if running
                    self._run_command(['wg-quick', 'down', self.config.wg_interface])
                except Exception as e:
                    logger.warning(f"Failed to bring down interface: {e}")

            # Build server config
            config_lines = [
                '[Interface]',
                f'PrivateKey = {self.config.server_private_key}',
                f'Address = {self._get_server_ips()}',
                f'ListenPort = {self.config.server_port}',
                '# Enable IP forwarding and NAT',
                'PostUp = sysctl -w net.ipv4.ip_forward=1; '
                'sysctl -w net.ipv6.conf.all.forwarding=1; '
                f'iptables -A FORWARD -i %i -o {self.config.interface_name} -j ACCEPT; '
                f'iptables -A FORWARD -i {self.config.interface_name} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; '
                f'ip6tables -A FORWARD -i %i -o {self.config.interface_name} -j ACCEPT; '
                f'ip6tables -A FORWARD -i {self.config.interface_name} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; '
                f'iptables -t nat -A POSTROUTING -s {self.config.ipv4_subnet} -d {self.config.ipv4_subnet} -o %i -j MASQUERADE; '
                f'ip6tables -t nat -A POSTROUTING -s {self.config.ipv6_subnet} -d {self.config.ipv6_subnet} -o %i -j MASQUERADE; '
                f'iptables -t nat -A POSTROUTING -o {self.config.interface_name} -j MASQUERADE; '
                f'ip6tables -t nat -A POSTROUTING -o {self.config.interface_name} -j MASQUERADE',
                'PostDown = '
                f'iptables -D FORWARD -i %i -o {self.config.interface_name} -j ACCEPT; '
                f'iptables -D FORWARD -i {self.config.interface_name} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; '
                f'ip6tables -D FORWARD -i %i -o {self.config.interface_name} -j ACCEPT; '
                f'ip6tables -D FORWARD -i {self.config.interface_name} -o %i -m state --state RELATED,ESTABLISHED -j ACCEPT; '
                f'iptables -t nat -D POSTROUTING -s {self.config.ipv4_subnet} -d {self.config.ipv4_subnet} -o %i -j MASQUERADE; '
                f'ip6tables -t nat -D POSTROUTING -s {self.config.ipv6_subnet} -d {self.config.ipv6_subnet} -o %i -j MASQUERADE; '
                f'iptables -t nat -D POSTROUTING -o {self.config.interface_name} -j MASQUERADE; '
                f'ip6tables -t nat -D POSTROUTING -o {self.config.interface_name} -j MASQUERADE'
            ]

            # Add peer configs if any clients exist
            if self.clients:
                for client in self.clients.values():
                    config_lines.extend([
                        '',
                        '[Peer]',
                        f'PublicKey = {client.public_key}',
                        f'AllowedIPs = {client.ipv4.split("/")[0]}/32, {client.ipv6.split("/")[0]}/128',
                        'PersistentKeepalive = 25'
                    ])

            # Add final newline
            config_lines.append('')

            # Write config file
            config_path = Path(self.config.config_dir) / f"{self.config.wg_interface}.conf"
            config_path.write_text('\n'.join(config_lines))
            config_path.chmod(0o600)

            # Flush all old FORWARD rules before adding new ones
            self._flush_forward_rules()

            # Start interface
            self._run_command(['wg-quick', 'up', self.config.wg_interface])

            # Add default forward rules (only for unrestricted clients)
            unrestricted_clients = [client for client in self.clients.values()
                                    if not client.restricted_ips and not client.restricted_ip6s]

            for client in unrestricted_clients:
                client_ip = client.ipv4.split('/')[0]
                client_ip6 = client.ipv6.split('/')[0]

                # Add IPv4 rules
                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip,
                    '-j', 'ACCEPT'
                ])
                self._run_command([
                    'iptables', '-A', 'FORWARD',
                    '-o', self.config.wg_interface,
                    '-d', client_ip,
                    '-j', 'ACCEPT'
                ])

                # Add IPv6 rules
                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-i', self.config.wg_interface,
                    '-s', client_ip6,
                    '-j', 'ACCEPT'
                ])
                self._run_command([
                    'ip6tables', '-A', 'FORWARD',
                    '-o', self.config.wg_interface,
                    '-d', client_ip6,
                    '-j', 'ACCEPT'
                ])

            # Update firewall rules for all restricted clients
            restricted_clients = [client for client in self.clients.values()
                                  if client.restricted_ips or client.restricted_ip6s]
            for client in restricted_clients:
                self._update_client_firewall_rules(client)

            # Verify interface is up
            if not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                raise RuntimeError("Failed to create WireGuard interface")

            # Update DNS configuration AFTER interface is up and verified
            self._update_dns_config()

        except Exception as e:
            logger.error(f"Failed to update server config: {e}")
            raise

    def _get_server_ips(self) -> str:
        """Get server IPs from subnet."""
        ipv4_net = ipaddress.ip_network(self.config.ipv4_subnet)
        ipv6_net = ipaddress.ip_network(self.config.ipv6_subnet)

        return (
            f"{next(ipv4_net.hosts())}/{ipv4_net.prefixlen}, "
            f"{ipv6_net.network_address + 1}/{ipv6_net.prefixlen}"
        )

    def update_client_restrictions(self, name: str,
                                   add_ips: Optional[List[str]] = None,
                                   remove_ips: Optional[List[str]] = None,
                                   add_ip6s: Optional[List[str]] = None,
                                   remove_ip6s: Optional[List[str]] = None,
                                   clear_all: bool = False) -> None:
        """Update IP restrictions for a client."""
        try:
            if name not in self.clients:
                console.print(f"[red]Client {name} not found[/red]")
                return

            client = self.clients[name]

            if clear_all:
                client.restricted_ips = []
                client.restricted_ip6s = []
                console.print(f"[yellow]Cleared all restrictions for client {name}[/yellow]")
            else:
                # Handle IPv4 restrictions
                if add_ips:
                    for ip in add_ips:
                        try:
                            ipaddress.ip_network(ip)
                            if ip not in client.restricted_ips:
                                client.restricted_ips.append(ip)
                        except ValueError as e:
                            console.print(f"[red]Invalid IPv4 address/network: {ip}[/red]")

                if remove_ips:
                    client.restricted_ips = [ip for ip in client.restricted_ips if ip not in remove_ips]

                # Handle IPv6 restrictions
                if add_ip6s:
                    for ip in add_ip6s:
                        try:
                            ipaddress.ip_network(ip)
                            if ip not in client.restricted_ip6s:
                                client.restricted_ip6s.append(ip)
                        except ValueError as e:
                            console.print(f"[red]Invalid IPv6 address/network: {ip}[/red]")

                if remove_ip6s:
                    client.restricted_ip6s = [ip for ip in client.restricted_ip6s if ip not in remove_ip6s]

            # Update firewall rules and save changes
            self._update_client_firewall_rules(client)
            self._save_clients()

            console.print(f"[green]Successfully updated restrictions for client {name}[/green]")
            if client.restricted_ips or client.restricted_ip6s:
                if client.restricted_ips:
                    console.print("[yellow]IPv4 restrictions: " + ", ".join(client.restricted_ips))
                if client.restricted_ip6s:
                    console.print("[yellow]IPv6 restrictions: " + ", ".join(client.restricted_ip6s))
            else:
                console.print("[yellow]No IP restrictions active[/yellow]")

        except Exception as e:
            logger.error(f"Failed to update client restrictions: {e}")
            raise

    def _create_install_command(self, client_config: str, interface_name: str = 'wg0') -> str:
        """Create installation command using base64 encoding with line wrapping."""
        install_script = (
            f"apt update && "
            f"apt install -y wireguard resolvconf && "
            f"resolvconf -u &&"
            f"wg-quick down {interface_name} 2>/dev/null || true && "
            f"rm -f /etc/wireguard/{interface_name}.conf && "
            f"cat > /etc/wireguard/{interface_name}.conf << EOF\n"
            f"{client_config}\n"
            f"EOF\n"
            f"chmod 600 /etc/wireguard/{interface_name}.conf && "
            f"systemctl enable wg-quick@{interface_name} && "
            f"wg-quick up {interface_name}"
        )

        # Encode the script and wrap at 50 characters
        encoded = base64.b64encode(install_script.encode()).decode()
        wrapped = '\\\n'.join([encoded[i:i+50] for i in range(0, len(encoded), 50)])

        # Return wrapped command
        return f"echo \\\n{wrapped} | base64 -d | bash"

    def add_client(self, name: str, full_tunnel: Optional[bool] = None,
                   restricted_ips: Optional[List[str]] = None,
                   restricted_ip6s: Optional[List[str]] = None) -> None:
        """Add a new WireGuard client."""
        try:
            if name in self.clients:
                console.print(f"[red]Client {name} already exists[/red]")
                return

            # Validate IP restrictions if provided
            if restricted_ips:
                for ip in restricted_ips:
                    try:
                        ipaddress.ip_network(ip)
                    except ValueError as e:
                        raise ValueError(f"Invalid IPv4 address/network: {ip}")

            if restricted_ip6s:
                for ip in restricted_ip6s:
                    try:
                        ipaddress.ip_network(ip)
                    except ValueError as e:
                        raise ValueError(f"Invalid IPv6 address/network: {ip}")

            # Generate client keys and get IPs
            private_key, public_key = self._generate_keypair()
            ips = self._get_next_available_ips()

            # Set tunnel mode
            use_full_tunnel = full_tunnel if full_tunnel is not None else self.config.full_tunnel
            allowed_ips = ['0.0.0.0/0', '::/0'] if use_full_tunnel else [
                self.config.ipv4_subnet,
                self.config.ipv6_subnet
            ]

            # Create client
            client = WireGuardClient(
                name=name,
                public_key=public_key,
                ipv4=ips['ipv4'],
                ipv6=ips['ipv6'],
                allowed_ips=allowed_ips,
                restricted_ips=restricted_ips or [],
                restricted_ip6s=restricted_ip6s or [],
                created_at=datetime.now().isoformat()
            )

            # Generate client config
            config_content = self._create_client_config(client, private_key)

            # Save client config
            config_path = Path(self.config.config_dir) / f"{name}.conf"
            config_path.write_text(config_content)
            config_path.chmod(0o600)

            # Ensure QR directory exists
            Path(self.config.qr_dir).mkdir(parents=True, exist_ok=True)

            # Generate QR code using qrencode
            qr_path = Path(self.config.qr_dir) / f"{name}_qr.png"
            try:
                self._run_command([
                    'qrencode',
                    '-t', 'png',
                    '-o', str(qr_path),
                    '-s', '2',
                    '-m', '1'
                ], input_data=config_content)
            except Exception as e:
                logger.warning(f"Failed to generate QR code: {e}. Please install qrencode package.")

            # Update system configurations
            self.clients[name] = client
            self._save_clients()
            self._update_client_firewall_rules(client)
            self._update_server_config()

            # Print success and show configuration
            console.print(f"\n[bold green]Successfully created client {name}[/bold green]")
            self.show_client_config(name, config_content, show_qr=True)

        except Exception as e:
            logger.error(f"Failed to add client: {e}")
            raise

    def _check_hosts_conflicts(self) -> None:
        """Check for conflicts between VPN names and /etc/hosts."""
        try:
            if not Path('/etc/hosts').exists():
                return

            # Read /etc/hosts
            hosts_content = Path('/etc/hosts').read_text()

            # Build list of VPN hostnames we're using
            vpn_names = set()
            dns_domain = self.config.dns_domain

            # Add server name
            if dns_domain:
                dns_domain_short = dns_domain.split('.')[0]
                vpn_names.add(dns_domain_short)
                vpn_names.add(dns_domain)

            # Add client names
            for client in self.clients.values():
                vpn_names.add(client.name)
                if dns_domain:
                    vpn_names.add(f"{client.name}.{dns_domain}")

            # Check for conflicts
            conflicts = []
            for line in hosts_content.split('\n'):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                parts = line.split()
                if len(parts) < 2:
                    continue

                ip = parts[0]
                hostnames = parts[1:]

                for hostname in hostnames:
                    if hostname in vpn_names:
                        conflicts.append(f"{hostname} ({ip})")

            if conflicts:
                console.print("\n[yellow]⚠️  Warning: Conflicting entries found in /etc/hosts:[/yellow]")
                for conflict in conflicts:
                    console.print(f"  • {conflict}")
                console.print("\n[yellow]These may cause DNS resolution issues for VPN clients.[/yellow]")
                console.print("[yellow]Consider setting 'dnsmasq_read_etc_hosts: false' in config.yaml[/yellow]\n")

        except Exception as e:
            logger.warning(f"Failed to check /etc/hosts conflicts: {e}")

    def _update_dns_config(self) -> None:
        """Update DNS configuration for client name resolution."""
        try:
            # Check for conflicts if reading /etc/hosts
            if self.config.dnsmasq_read_etc_hosts:
                self._check_hosts_conflicts()

            # Wait for WireGuard interface to be up
            retries = 5
            while retries > 0 and not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                time.sleep(1)

            if not Path(f"/sys/class/net/{self.config.wg_interface}").exists():
                logger.warning(f"WireGuard interface {self.config.wg_interface} not found")
                return

            # Install dnsmasq if not present
            if not Path('/usr/sbin/dnsmasq').exists():
                raise ValueError("dnsmasq is not installed")

            # Create dnsmasq config directory
            dnsmasq_dir = Path('/etc/dnsmasq.d')
            dnsmasq_dir.mkdir(parents=True, exist_ok=True)

            dns_domain = self.config.dns_domain
            if not dns_domain:
                raise ValueError("DNS domain is not set in config.yaml")
            dns_domain_short = dns_domain.split('.')[0]

            # Generate dnsmasq configuration
            config_lines = [
                '# WireGuard VPN DNS configuration',
                f'listen-address={self._get_server_ips().split(",")[0].split("/")[0]}',
                'port=53',
                f'interface={self.config.wg_interface}',
                'bind-interfaces',
                f'domain={dns_domain}',
                'expand-hosts',
                'domain-needed',
                'bogus-priv',
                'no-resolv',
                'no-poll',
                'server=1.1.1.1',
                'server=1.0.0.1',
            ]

            # Add no-hosts option if configured
            if not self.config.dnsmasq_read_etc_hosts:
                config_lines.insert(5, 'no-hosts')  # Insert after 'bind-interfaces'

            # Add DNS overrides from config
            if self.config.dns_overrides:
                for domain, ip in self.config.dns_overrides.items():
                    config_lines.append(f"address=/{domain}/{ip}")

            config_lines.append('')  # End with newline
            
            # Add client host entries
            hosts_lines = []
            server_ip = self._get_server_ips().split(',')[0].split('/')[0]
            # Add server entry with short name (expand-hosts will add .ian.coffee)
            hosts_lines.append(f"{server_ip} {dns_domain_short}")

            for client in self.clients.values():
                client_ip = client.ipv4.split('/')[0]
                client_ip6 = client.ipv6.split('/')[0]
                # Use short names - expand-hosts will automatically add domain suffix
                hosts_lines.extend([
                    f"{client_ip} {client.name}",
                    f"{client_ip6} {client.name}"
                ])
            hosts_lines.append('')  # End with newline

            # Clean up old config files
            config_path = dnsmasq_dir / 'wireguard.conf'
            hosts_path = Path('/etc/hosts.wireguard')

            # Write new config files
            config_path.write_text('\n'.join(config_lines))
            hosts_path.write_text('\n'.join(hosts_lines))

            # Update main dnsmasq configuration
            dnsmasq_conf = Path('/etc/dnsmasq.conf')
            if dnsmasq_conf.exists():
                current_config = dnsmasq_conf.read_text()
                # Remove any existing WireGuard related config
                new_lines = [line for line in current_config.splitlines()
                             if not any(x in line for x in ['WireGuard', str(hosts_path), str(config_path)])]

                # Add our configuration
                new_lines.extend([
                    '',
                    '# WireGuard VPN configuration',
                    f'addn-hosts={hosts_path}',
                    f'conf-file={config_path}',
                    ''  # End with newline
                ])

                dnsmasq_conf.write_text('\n'.join(new_lines))
            else:
                dnsmasq_conf.write_text('\n'.join([
                    '# WireGuard VPN configuration',
                    f'addn-hosts={hosts_path}',
                    f'conf-file={config_path}',
                    ''  # End with newline
                ]))

            # Restart dnsmasq with proper error handling
            try:
                self._run_command(['systemctl', 'restart', 'dnsmasq'])
                time.sleep(1)  # Give it time to settle

                # Verify it's running
                status = self._run_command(['systemctl', 'is-active', 'dnsmasq'])
                if status != 'active':
                    raise RuntimeError(f"dnsmasq failed to start, status: {status}")

            except Exception as e:
                logger.error(f"Failed to restart dnsmasq: {e}")
                # Try to get more detailed error information
                try:
                    status = self._run_command(['systemctl', 'status', 'dnsmasq'])
                    logger.error(f"dnsmasq status: {status}")
                except Exception:
                    pass
                raise

        except Exception as e:
            logger.error(f"Failed to update DNS configuration: {e}")
            raise

    def _create_client_config(self, client: WireGuardClient, private_key: str) -> str:
        """Create client configuration."""
        # Get server IP for DNS
        server_ip = self._get_server_ips().split(',')[0].split('/')[0]

        return '\n'.join([
            '[Interface]',
            f'PrivateKey = {private_key}',
            f'Address = {client.ipv4}, {client.ipv6}',
            f'DNS = {server_ip}',  # Point to WireGuard server for DNS
            '',
            '[Peer]',
            f'PublicKey = {self.config.server_public_key}',
            f'AllowedIPs = {", ".join(client.allowed_ips)}',
            f'Endpoint = {self.config.endpoint}:{self.config.server_port}',
            'PersistentKeepalive = 10',
            ''  # Add empty string to create final newline
        ])

    def show_client_config(self, name: str, config_content: Optional[str] = None, show_qr: bool = False) -> None:
        """Show configuration details for a client.

        Args:
            name: Client name
            config_content: Optional pre-generated config content (for new clients)
            show_header: Whether to show the header (can be disabled for add_client)
        """
        try:
            # Get client config path
            config_path = Path(self.config.config_dir) / f"{name}.conf"
            qr_path = Path(self.config.qr_dir) / f"{name}_qr.png"

            # For existing clients, read config from file if not provided
            if config_content is None:
                if not config_path.exists():
                    console.print(f"[red]Configuration file not found: {config_path}[/red]")
                    return
                config_content = config_path.read_text()

            # Generate installation command
            install_command = self._create_install_command(config_content)

            # Print configuration details
            console.print("\n[bold blue]Configuration Files:[/bold blue]")
            console.print(f"Config file: {config_path}")
            console.print(f"QR code: {qr_path}")

            # Also display QR code in terminal
            if show_qr:
                try:
                    console.print("\n[bold blue]QR Code:[/bold blue]")
                    qr_terminal = subprocess.run(
                        ['qrencode', '-t', 'ansiutf8', '-m', '1'],
                        input=config_content.encode(),
                        capture_output=True,
                        text=False
                    )
                    print(qr_terminal.stdout.decode())
                except Exception as e:
                    logger.warning(f"Failed to generate terminal QR code: {e}")

            console.print("\n[bold blue]Installation Command:[/bold blue]")
            # print(install_command)
            # console.print(Syntax(install_command, "bash", word_wrap=False, theme="github-dark"))
            # console.print(Syntax(install_command, "bash", word_wrap=False, line_numbers=False))
            console.print(install_command, style="white on black")
            # console.print(install_command)

            console.print("\n[bold blue]Configuration Content:[/bold blue]")
            config_content = config_content.rstrip()
            console.print(Syntax(config_content, "ini", theme="github-dark"))

            # Show restrictions if client exists
            if name in self.clients:
                client = self.clients[name]
                if client.restricted_ips or client.restricted_ip6s:
                    restrictions = []
                    restrictions.extend(client.restricted_ips)
                    restrictions.extend(client.restricted_ip6s)
                    console.print("\n[yellow]IP restrictions:[/yellow] " +
                                  ", ".join(restrictions))

        except Exception as e:
            logger.error(f"Failed to show client configuration: {e}")
            raise

    def remove_client(self, name: str, skip_confirm: bool = False) -> None:
        """Remove a WireGuard client."""
        try:
            if name not in self.clients:
                console.print(f"[red]Client {name} not found[/red]")
                return

            # Confirm deletion unless skip_confirm is True
            if not skip_confirm and not Confirm.ask(f"Are you sure you want to remove client {name}?"):
                return

            # Remove client config file
            config_path = Path(self.config.config_dir) / f"{name}.conf"
            if config_path.exists():
                config_path.unlink()

            # Remove QR code if exists
            qr_path = Path(self.config.qr_dir) / f"{name}_qr.png"
            if qr_path.exists():
                qr_path.unlink()

            # Remove client and update
            del self.clients[name]
            self._save_clients()
            self._update_server_config()

            console.print(f"[green]Successfully removed client {name}[/green]")

        except Exception as e:
            logger.error(f"Failed to remove client: {e}")
            raise

    def _get_client_status(self) -> Dict[str, Dict[str, str]]:
        """Get status information for all clients from wg command."""
        try:
            wg_output = self._run_command(['wg', 'show', self.config.wg_interface])
            current_peer = None
            peer_info = {}

            for line in wg_output.split('\n'):
                line = line.strip()
                if line.startswith('peer:'):
                    current_peer = line.split(':')[1].strip()
                    peer_info[current_peer] = {'status': 'Offline', 'last_seen': 'Never'}
                elif current_peer and 'latest handshake:' in line.lower():
                    handshake_time = line.split(':')[1].strip()
                    if handshake_time != 'Never':
                        # Consider client online if last handshake was within 3 minutes
                        if 'minutes' not in handshake_time or int(handshake_time.split()[0]) <= 3:
                            peer_info[current_peer]['status'] = 'Online'
                        peer_info[current_peer]['last_seen'] = handshake_time

            return peer_info
        except Exception as e:
            logger.warning(f"Failed to get client status: {e}")
            return {}

    def list_clients(self) -> None:
        """List all WireGuard clients."""
        try:
            if not self.clients:
                console.print("[yellow]No clients found[/yellow]")
                return

            # Get current status for all clients
            client_status = self._get_client_status()

            table = Table(
                title="WireGuard Clients",
                show_header=True,
                box=box.SIMPLE,
                expand=True,
                header_style="bold",
                show_lines=True,
            )

            table.add_column("Name", style="bold blue")
            table.add_column("Status", style="")
            table.add_column("Addresses", style="")
            table.add_column("Tunnel Mode", style="")
            table.add_column("Restrictions", style="", max_width=40)
            table.add_column("Last Seen", style="")
            table.add_column("Created", style="dim")

            # Create a mapping of public keys to client names
            pubkey_to_name = {client.public_key: name for name, client in self.clients.items()}

            for name, client in sorted(self.clients.items()):
                tunnel_mode = "[blue]Full[/blue]" if "0.0.0.0/0" in client.allowed_ips else "[yellow]Split[/yellow]"
                # in german format
                created = datetime.fromisoformat(client.created_at).strftime("%d.%m.%Y %H:%M") if client.created_at else "Unknown"

                # Get status info for this client
                status = "Unknown"
                last_seen = "Never"
                for pubkey, info in client_status.items():
                    if pubkey == client.public_key:
                        status = info['status']
                        last_seen = info['last_seen']
                        break

                # Format restrictions
                restrictions = []
                if client.restricted_ips:
                    restrictions.extend(client.restricted_ips)
                if client.restricted_ip6s:
                    restrictions.extend(client.restricted_ip6s)
                restriction_text = ", ".join(restrictions) if restrictions else "[dim]None[/dim]"

                # Set status style
                status_display = f"● {status}"
                if status == "Online":
                    status_display = f"[green]{status_display}[/green]"
                else:
                    status_display = f"[red]{status_display}[/red]"

                # Addresses
                addresses = []
                if client.ipv4:
                    addresses.append(client.ipv4)
                if client.ipv6:
                    addresses.append(client.ipv6)

                addresses_text = "\n".join(addresses) if addresses else "Unknown"

                table.add_row(
                    name,
                    status_display,
                    addresses_text,
                    tunnel_mode,
                    restriction_text,
                    last_seen,
                    created
                )

            console.print(table)

        except Exception as e:
            logger.error(f"Failed to list clients: {e}")
            raise


def main():
    parser = argparse.ArgumentParser(description="WireGuard VPN Manager")
    parser.add_argument("-c", "--config", default="config.yaml", help="Path to config file")

    subparsers = parser.add_subparsers(dest="command", required=True)

    # Add client command
    add_parser = subparsers.add_parser("add", help="Add a new client")
    add_parser.add_argument("name", help="Client name")
    add_parser.add_argument("--full-tunnel", action="store_true", help="Use full tunnel mode")
    add_parser.add_argument("--split-tunnel", action="store_true", help="Use split tunnel mode")
    add_parser.add_argument("--restrict-to", nargs="+", metavar="IP",
                            help="List of IP addresses/networks this client can access (both IPv4 and IPv6)")

    # Show config command
    config_parser = subparsers.add_parser("config", help="Show client configuration details")
    config_parser.add_argument("name", help="Client name")
    config_parser.add_argument("--show-qr", action="store_true", help="Show QR code in terminal")
    # Remove client command
    remove_parser = subparsers.add_parser("remove", help="Remove a client")
    remove_parser.add_argument("name", help="Client name")
    remove_parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")

    # List clients command
    subparsers.add_parser("list", help="List all clients")

    # Manage restrictions command
    restrict_parser = subparsers.add_parser("restrict", help="Manage client IP restrictions")
    restrict_parser.add_argument("name", help="Client name")
    restrict_parser.add_argument("--allow", nargs="+", metavar="IP",
                                 help="Add IP addresses/networks to allowed list")
    restrict_parser.add_argument("--deny", nargs="+", metavar="IP",
                                 help="Remove IP addresses/networks from allowed list")
    restrict_parser.add_argument("--clear", action="store_true",
                                 help="Remove all IP restrictions")

    args = parser.parse_args()

    try:
        manager = WireGuardManager(args.config)

        if args.command == "add":
            if args.full_tunnel and args.split_tunnel:
                console.print("[red]Cannot specify both --full-tunnel and --split-tunnel[/red]")
                sys.exit(1)
            full_tunnel = True if args.full_tunnel else False if args.split_tunnel else None

            # Split IPs into v4 and v6 automatically
            if args.restrict_to:
                ipv4_list = []
                ipv6_list = []
                for ip in args.restrict_to:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            ipv4_list.append(ip)
                        else:
                            ipv6_list.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)
                manager.add_client(args.name, full_tunnel, ipv4_list, ipv6_list)
            else:
                manager.add_client(args.name, full_tunnel)

        elif args.command == "config":
            manager.show_client_config(args.name, show_qr=args.show_qr)

        elif args.command == "remove":
            manager.remove_client(args.name, skip_confirm=args.yes)

        elif args.command == "list":
            manager.list_clients()

        elif args.command == "restrict":
            if not any([args.allow, args.deny, args.clear]):
                console.print("[red]Please specify at least one action: --allow, --deny, or --clear[/red]")
                sys.exit(1)

            # Process restrictions
            add_ipv4 = []
            add_ipv6 = []
            remove_ipv4 = []
            remove_ipv6 = []

            if args.allow:
                for ip in args.allow:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            add_ipv4.append(ip)
                        else:
                            add_ipv6.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)

            if args.deny:
                for ip in args.deny:
                    try:
                        parsed_ip = ipaddress.ip_network(ip)
                        if parsed_ip.version == 4:
                            remove_ipv4.append(ip)
                        else:
                            remove_ipv6.append(ip)
                    except ValueError as e:
                        console.print(f"[red]Invalid IP address/network: {ip}[/red]")
                        sys.exit(1)

            manager.update_client_restrictions(
                args.name,
                add_ips=add_ipv4,
                remove_ips=remove_ipv4,
                add_ip6s=add_ipv6,
                remove_ip6s=remove_ipv6,
                clear_all=args.clear
            )

    except Exception as e:
        console.print(f"[red]Error: {str(e)}[/red]")
        sys.exit(1)


if __name__ == "__main__":
    main()
