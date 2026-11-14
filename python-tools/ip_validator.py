#!/usr/bin/env python3
"""
Cybersecurity Toolkit - IP Address Validator

Validate IPv4/IPv6 addresses and CIDR ranges and show their properties.

Examples:
    python ip_validator.py 192.168.1.10 8.8.8.8 ::1
    python ip_validator.py 10.0.0.0/24
    python ip_validator.py --file ips.txt --json
    python ip_validator.py                     (interactive mode)
"""

import argparse
import ipaddress
import json
import sys
from pathlib import Path


def classify(addr) -> str:
    """Return a human-readable type for an IP address object."""
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_multicast:
        return "Multicast"
    if addr.is_private:
        return "Private"
    if addr.is_reserved or addr.is_unspecified:
        return "Reserved"
    return "Public"


def inspect(value: str) -> dict:
    """Validate one IP or CIDR string and return its details."""
    value = value.strip()
    result = {"input": value, "valid": False}
    try:
        if "/" in value:
            net = ipaddress.ip_network(value, strict=False)
            result.update(
                valid=True, kind="network", version=net.version,
                network=str(net), netmask=str(net.netmask),
                total_addresses=net.num_addresses,
                type="Private" if net.is_private else "Public",
            )
            if net.version == 4 and net.num_addresses > 2:
                result["first_host"] = str(net.network_address + 1)
                result["last_host"] = str(net.broadcast_address - 1)
        else:
            addr = ipaddress.ip_address(value)
            result.update(valid=True, kind="address",
                          version=addr.version, type=classify(addr))
    except ValueError:
        result["error"] = "Invalid IP address or network"
    return result


def show(r: dict) -> None:
    if not r["valid"]:
        print(f"[-] {r['input']}: {r['error']}")
        return
    print(f"[+] {r['input']}: Valid IPv{r['version']} {r['kind']} ({r['type']})")
    if r["kind"] == "network":
        print(f"    Network : {r['network']}  Netmask: {r['netmask']}")
        print(f"    Total   : {r['total_addresses']} addresses")
        if "first_host" in r:
            print(f"    Hosts   : {r['first_host']} - {r['last_host']}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate IPs and CIDR ranges.")
    parser.add_argument("targets", nargs="*", help="IPs or CIDR ranges")
    parser.add_argument("--file", type=Path,
                        help="File with one IP/CIDR per line")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    items = list(args.targets)
    if args.file:
        if not args.file.is_file():
            print(f"Error: file paoa jayni: {args.file}", file=sys.stderr)
            return 1
        items += [l for l in args.file.read_text().splitlines()
                  if l.strip() and not l.lstrip().startswith("#")]
    if not items:
        items = [input("Enter an IP address: ")]

    results = [inspect(i) for i in items]
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("=" * 30)
        print("     IP ADDRESS VALIDATOR")
        print("=" * 30)
        for r in results:
            show(r)
    return 0 if all(r["valid"] for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
