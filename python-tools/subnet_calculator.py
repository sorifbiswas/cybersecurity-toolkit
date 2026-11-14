#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Subnet Calculator

Shows network details for an IPv4 or IPv6 CIDR range, and can split a
network into smaller subnets.

Examples:
    python subnet_calculator.py 192.168.1.0/24
    python subnet_calculator.py 192.168.1.10/255.255.255.0
    python subnet_calculator.py 10.0.0.0/24 --split 26
    python subnet_calculator.py 192.168.1.0/24 --contains 192.168.1.77
    python subnet_calculator.py 2001:db8::/48 --json
"""

import argparse
import ipaddress
import json
import sys


def describe(net) -> dict:
    info = {
        "network": str(net),
        "version": net.version,
        "network_address": str(net.network_address),
        "netmask": str(net.netmask),
        "prefix_length": net.prefixlen,
        "total_addresses": net.num_addresses,
        "type": "Private" if net.is_private else "Public",
    }
    if net.version == 4:
        info["wildcard_mask"] = str(net.hostmask)
        info["broadcast"] = str(net.broadcast_address)
        if net.prefixlen <= 30:
            info["first_host"] = str(net.network_address + 1)
            info["last_host"] = str(net.broadcast_address - 1)
            info["usable_hosts"] = net.num_addresses - 2
        elif net.prefixlen == 31:
            info["first_host"] = str(net.network_address)
            info["last_host"] = str(net.broadcast_address)
            info["usable_hosts"] = 2  # point-to-point link (RFC 3021)
        else:
            info["first_host"] = info["last_host"] = str(net.network_address)
            info["usable_hosts"] = 1
    else:
        info["first_host"] = str(net.network_address)
        info["last_host"] = str(net.broadcast_address)
        info["usable_hosts"] = net.num_addresses
    return info


def show(info: dict) -> None:
    labels = [
        ("network", "Network"), ("netmask", "Netmask"),
        ("wildcard_mask", "Wildcard mask"), ("prefix_length", "Prefix length"),
        ("broadcast", "Broadcast"), ("first_host", "First host"),
        ("last_host", "Last host"), ("usable_hosts", "Usable hosts"),
        ("total_addresses", "Total addresses"), ("type", "Type"),
    ]
    for key, label in labels:
        if key in info:
            print(f"{label:<16}: {info[key]}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Subnet calculator.")
    parser.add_argument("network", help="CIDR (10.0.0.0/24) or IP/netmask")
    parser.add_argument("--split", type=int, metavar="PREFIX",
                        help="Split into subnets with this prefix length")
    parser.add_argument("--contains", metavar="IP",
                        help="Check whether an IP is inside the network")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    try:
        net = ipaddress.ip_network(args.network, strict=False)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

    output = {"info": describe(net)}

    if args.contains:
        try:
            inside = ipaddress.ip_address(args.contains) in net
        except ValueError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1
        output["contains"] = {"ip": args.contains, "inside": inside}

    if args.split is not None:
        if not net.prefixlen < args.split <= net.max_prefixlen:
            print(f"Error: split prefix must be between {net.prefixlen + 1} "
                  f"and {net.max_prefixlen}", file=sys.stderr)
            return 1
        count = 2 ** (args.split - net.prefixlen)
        if count > 1024:
            print(f"Error: that would create {count} subnets (limit 1024).",
                  file=sys.stderr)
            return 1
        output["subnets"] = [str(s) for s in net.subnets(new_prefix=args.split)]

    if args.json:
        print(json.dumps(output, indent=2))
        return 0

    print("=" * 32)
    print("       SUBNET CALCULATOR")
    print("=" * 32)
    show(output["info"])
    if "contains" in output:
        c = output["contains"]
        word = "IS" if c["inside"] else "is NOT"
        print(f"\n[{'+' if c['inside'] else '-'}] {c['ip']} {word} in {net}")
    if "subnets" in output:
        print(f"\nSubnets (/{args.split}): {len(output['subnets'])}")
        for s in output["subnets"]:
            print(f"  {s}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
