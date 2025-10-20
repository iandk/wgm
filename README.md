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

Restrict clients to access only specific destinations using firewall rules. Perfect for limiting access to specific services or hosts.

### Basic Usage

```bash
# Restrict to single IP
wgm add client1 --restrict-to 10.99.99.3

# Restrict to multiple IPs/networks
wgm add client2 --restrict-to 10.99.99.3 192.168.1.0/24

# Mix IPv4 and IPv6 restrictions
wgm add client3 --restrict-to 10.99.99.3 fd99:99::5
```

### Behavior

**Gateway Auto-Allowed:**
- VPN gateway (e.g., `10.99.99.1` and `fd99:99::1`) is automatically accessible for DNS
- Not stored in restriction list, dynamically added to firewall rules
- Works with custom subnets configured in `config.yaml`

**IPv4-only restrictions:**
```bash
wgm add client1 --restrict-to 10.99.99.3
```
- ✅ Allows: `10.99.99.3` (specified), `10.99.99.1` (gateway)
- ❌ Blocks: All other IPv4 traffic
- ❌ Blocks: **All IPv6 traffic** (except gateway `fd99:99::1`)

**IPv6-only restrictions:**
```bash
wgm add client2 --restrict-to fd99:99::5
```
- ✅ Allows: `fd99:99::5` (specified), `fd99:99::1` (gateway)
- ❌ Blocks: All other IPv6 traffic
- ❌ Blocks: **All IPv4 traffic** (except gateway `10.99.99.1`)

**Mixed IPv4/IPv6 restrictions:**
```bash
wgm add client3 --restrict-to 10.99.99.3 fd99:99::5
```
- ✅ IPv4: `10.99.99.3` + gateway
- ✅ IPv6: `fd99:99::5` + gateway
- ❌ All other traffic blocked

### Modifying Restrictions

```bash
# Add more allowed destinations
wgm restrict client1 --allow 10.99.99.5 192.168.1.100

# Remove allowed destinations
wgm restrict client1 --deny 10.99.99.3

# Clear all restrictions (client becomes unrestricted)
wgm restrict client1 --clear
```

**Note:** Modifications trigger a full server config rebuild to ensure correct firewall rule ordering.

### Network Notation

```bash
# Single IP (implicit /32 for IPv4, /128 for IPv6)
--restrict-to 10.99.99.3              # Same as 10.99.99.3/32
--restrict-to fd99:99::5              # Same as fd99:99::5/128

# Network ranges
--restrict-to 192.168.1.0/24          # Entire subnet
--restrict-to fd99:99::/64            # IPv6 subnet
```

### Use Cases

**Database Server Access:**
```bash
# Only allow access to database server
wgm add db-client --restrict-to 10.99.99.10
```

**Multi-Service Access:**
```bash
# Access to web and database servers
wgm add app-client --restrict-to 10.99.99.10 10.99.99.20
```

**Subnet Access:**
```bash
# Access entire internal network
wgm add admin-client --restrict-to 192.168.0.0/16
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
