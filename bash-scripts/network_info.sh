#!/usr/bin/env bash
#
# Cybersecurity Toolkit
# Tool: Network Information
#
# Shows local network details: interfaces, gateway, DNS, routes and
# (optionally) listening ports and public IP.
#
# Usage:
#   ./network_info.sh              basic info
#   ./network_info.sh --ports      also show listening ports
#   ./network_info.sh --public     also look up public IP (contacts ifconfig.me)
#   ./network_info.sh --all        everything
#   ./network_info.sh --help

set -uo pipefail

SHOW_PORTS=0
SHOW_PUBLIC=0

usage() {
    sed -n '3,14p' "$0" | sed 's/^# \{0,1\}//'
}

section() {
    echo
    echo "--- $1 ---"
}

have() { command -v "$1" >/dev/null 2>&1; }

for arg in "$@"; do
    case "$arg" in
        --ports)  SHOW_PORTS=1 ;;
        --public) SHOW_PUBLIC=1 ;;
        --all)    SHOW_PORTS=1; SHOW_PUBLIC=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $arg" >&2; usage; exit 1 ;;
    esac
done

if ! have ip; then
    echo "Error: 'ip' command not found (please install iproute2)." >&2
    exit 1
fi

echo "================================"
echo "       NETWORK INFORMATION"
echo "================================"
echo "Host : $(hostname)"
echo "Date : $(date '+%Y-%m-%d %H:%M:%S')"

section "Local IP Addresses"
ip -brief address | grep -v '^lo ' || echo "No active interfaces found"

section "Default Gateway"
ip route show default || true
[ -z "$(ip route show default)" ] && echo "No default gateway found (offline?)"

section "DNS Servers"
if have resolvectl; then
    resolvectl dns 2>/dev/null || true
elif [ -r /etc/resolv.conf ]; then
    grep '^nameserver' /etc/resolv.conf || echo "No nameserver found"
fi

section "MAC Addresses"
ip -brief link | grep -v '^lo ' || true

section "Routing Table"
ip route

if [ "$SHOW_PORTS" -eq 1 ]; then
    section "Listening Ports (TCP/UDP)"
    if have ss; then
        ss -tulpn 2>/dev/null || ss -tuln
    else
        echo "'ss' command not found, skipping"
    fi
fi

if [ "$SHOW_PUBLIC" -eq 1 ]; then
    section "Public IP"
    if have curl; then
        curl -fsS --max-time 5 https://ifconfig.me 2>/dev/null \
            && echo || echo "Failed to retrieve public IP (offline?)"
    else
        echo "'curl' is not installed"
    fi
fi

echo
echo "================================"
