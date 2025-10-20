# WireGuard Manager

Simple CLI tool for managing WireGuard VPN servers with integrated DNS.

## Install

```bash
git clone https://github.com/iandk/wgm.git /opt/wgm && cd /opt/wgm && bash install.sh
```

Config created at `/opt/wgm/config.yaml` during install. Customize before first use if needed.

## Usage

```bash
# List clients with status
wgm

# Add client (split tunnel - VPN subnet only)
wgm add laptop

# Add client (full tunnel - all traffic)
wgm add phone --full-tunnel

# Add client (full tunnel with public IP exclusion)
# Preserves direct access to client via its public IPs
wgm add server --full-tunnel --exclude-public-ips

# Show client config, QR code & install command
wgm config laptop

# Remove client
wgm remove laptop
```

## Full Tunnel with Public IP Exclusion

For servers that need full tunnel VPN while remaining accessible via their public IP:

```bash
# Add server with full tunnel that preserves direct access
wgm add myserver --full-tunnel --exclude-public-ips
```

This dynamically excludes the client's public IPv4 and IPv6 addresses from VPN routing using policy routing rules, allowing:
- ✅ All outbound traffic routes through VPN
- ✅ Direct access to the server via its public IP(s)
- ✅ Automatic detection of both IPv4 and IPv6 public IPs

**Use cases:**
- Remote servers that need VPN access but must remain SSH-accessible
- Services that need to be directly reachable while routing all other traffic through VPN

## IP Restrictions

Restrict clients to specific destination IPs:

```bash
# Create client restricted to specific IP(s) only
wgm add client1 --restrict-to 192.168.1.100
# or 
wgm add client2 --restrict-to 192.168.1.200 10.0.5.0/24

# Modify restrictions after creation
wgm restrict client1 --allow 192.168.1.200
wgm restrict client1 --deny 192.168.1.100
wgm restrict client1 --clear
```

## DNS Features

### Internal DNS Resolution

Clients automatically resolve by hostname:
- **Short names:** `ping laptop` → `10.99.99.2`
- **FQDN:** `ping laptop.vpn.local` → `10.99.99.2`

### DNS Overrides

Override DNS resolution for specific domains in `config.yaml`:

```yaml
dns_overrides:
  # Block ads/trackers
  ads.tracker.com: 0.0.0.0

  # Override endpoints for testing
  api.production.com: 192.168.1.50

  # Wildcard support (quoted)
  "*.dev.local": 10.0.0.1
  "*.staging.internal": 192.168.100.5
```

Changes apply automatically on next `wgm` command.

### Conflict Detection

Warns if `/etc/hosts` entries conflict with VPN names:

```bash
$ wgm list
⚠️  Warning: Conflicting entries found in /etc/hosts:
  • vpn.local (127.0.1.1)

Consider setting 'dnsmasq_read_etc_hosts: false' in config.yaml
```

## Configuration

Edit `/opt/wgm/config.yaml` - changes auto-apply:

**Network:**
- `ipv4_subnet` / `ipv6_subnet` - VPN subnets (default: `10.99.99.0/24`, `fd99:99::/64`)
- `interface_name` - Physical interface for routing (usually `eth0`)
- `endpoint` - Public IP/domain for clients to connect

**DNS:**
- `dns_domain` - Internal domain for VPN clients (default: `vpn.local`)
- `dns_overrides` - Map domains to IPs (supports wildcards)
- `dnsmasq_read_etc_hosts` - Whether to read `/etc/hosts` (default: `true`)

**Clients:**
- `full_tunnel` - Default mode for new clients (default: `false`)

### Auto-Update on Config Changes

Changes to `endpoint`, `dns_domain`, `dns_overrides`, or `dnsmasq_read_etc_hosts` automatically:
- Regenerate all client configs
- Update DNS configuration
- Restart dnsmasq

No manual intervention needed!
