#!/bin/bash
# wg-mtu-find - find optimal WireGuard MTU
set -euo pipefail

TARGET="${1:-10.99.99.1}"
PINGS="${2:-3}"

low=1200
high=1472  # Increased - allows finding optimal on clean paths (1420 MTU = 1392 payload)
best=$low

# Colors (disable if not terminal)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    NC='\033[0m'
else
    GREEN=''; RED=''; YELLOW=''; NC=''
fi

# Detect OS and set ping command
if [[ "$OSTYPE" == "darwin"* ]]; then
    WG_IF=$(ifconfig 2>/dev/null | grep -B2 "inet 10\." | grep "^utun" | awk -F: '{print $1}' | head -1)
    [ -n "$WG_IF" ] && CURRENT_MTU=$(ifconfig "$WG_IF" 2>/dev/null | awk '/mtu/{print $NF}')
    ping_cmd() { ping -D -c "$PINGS" -W 1 -s "$1" "$TARGET" 2>/dev/null | grep -q " 0.0% packet loss"; }
else
    WG_IF=$(ip -o link show type wireguard 2>/dev/null | awk -F': ' '{print $2}' | head -1)
    [ -n "$WG_IF" ] && CURRENT_MTU=$(ip link show "$WG_IF" 2>/dev/null | grep -oP 'mtu \K\d+')
    ping_cmd() { ping -M do -c "$PINGS" -W 1 -s "$1" "$TARGET" 2>/dev/null | grep -q " 0% packet loss"; }
fi

echo "WireGuard MTU Finder"
echo "===================="
echo "Target: $TARGET"
echo "Interface: ${WG_IF:-unknown}"
echo "Current MTU: ${CURRENT_MTU:-unknown}"
echo ""

# Verify target is reachable
printf "Checking connectivity... "
if ping_cmd 64; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "Error: Cannot reach $TARGET - is WireGuard connected?"
    exit 1
fi

echo ""
echo "Testing ($PINGS pings per size)..."
echo ""

while [ $low -le $high ]; do
    mid=$(( (low + high) / 2 ))
    printf "  Payload %4d bytes... " $mid
    if ping_cmd $mid; then
        echo -e "${GREEN}OK${NC}"
        best=$mid
        low=$((mid + 1))
    else
        echo -e "${RED}FAIL${NC}"
        high=$((mid - 1))
    fi
done

mtu=$((best + 28))

echo ""
echo "===================="
echo "Results:"
echo "  Max payload:   $best bytes"
echo "  Optimal MTU:   $mtu"
echo "  Current MTU:   ${CURRENT_MTU:-unknown}"

if [ -n "${CURRENT_MTU:-}" ]; then
    diff=$((CURRENT_MTU - mtu))
    if [ $diff -gt 0 ]; then
        echo -e "  Status:        ${RED}Current MTU is $diff bytes too high${NC}"
    elif [ $diff -lt 0 ]; then
        echo -e "  Status:        ${GREEN}Current MTU is OK ($((-diff)) bytes margin)${NC}"
    else
        echo -e "  Status:        ${GREEN}Current MTU is optimal${NC}"
    fi
fi

echo "===================="
echo ""
echo "Add to WireGuard config:"
echo "  MTU = $mtu"

# Suggest safe value for unknown networks
if [ $mtu -lt 1400 ]; then
    echo ""
    echo -e "${YELLOW}Note:${NC} Your path has reduced MTU (mobile/PPPoE?)."
    echo "  Safe universal value: MTU = 1320"
    echo "  Optimal for this path: MTU = $mtu"
fi