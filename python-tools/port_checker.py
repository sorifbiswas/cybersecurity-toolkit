#!/usr/bin/env python3
"""
Cybersecurity Toolkit - Port Checker

Checks whether specific TCP ports are open on ONE host, using a simple
connection attempt. Meant for auditing your own machines and servers.

LEGAL NOTICE: Only check hosts you own or have written permission to test.
Unauthorized port scanning may be illegal and can violate provider rules.

Safety limits built in:
  - one host per run (no ranges or CIDR)
  - at most 100 ports per run
  - hosts outside private/loopback ranges need the --authorized flag

Examples:
    python port_checker.py 127.0.0.1
    python port_checker.py 192.168.1.1 -p 22,80,443
    python port_checker.py localhost -p 8000-8050
    python port_checker.py myserver.example.com -p 22,443 --authorized
"""

import argparse
import ipaddress
import json
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

MAX_PORTS = 100
MAX_WORKERS = 20
DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389,
                 5432, 8080]
# Ports that are risky when exposed to the internet
RISKY = {21: "FTP (unencrypted)", 23: "Telnet (unencrypted)",
         445: "SMB", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL"}


def parse_ports(spec: str) -> list[int]:
    ports = set()
    try:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                lo, hi = part.split("-", 1)
                ports.update(range(int(lo), int(hi) + 1))
            else:
                ports.add(int(part))
    except ValueError:
        raise ValueError(f"invalid port list: {spec!r} (use 22,80 or 8000-8050)")
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"too many ports ({len(ports)}), limit is {MAX_PORTS}")
    return sorted(ports)


def check_port(ip: str, port: int, timeout: float) -> dict:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        code = s.connect_ex((ip, port))
    try:
        service = socket.getservbyport(port, "tcp")
    except OSError:
        service = "unknown"
    return {"port": port, "open": code == 0, "service": service}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Check TCP ports on a host you own or may test.")
    parser.add_argument("host", help="Hostname or IP address")
    parser.add_argument("-p", "--ports",
                        help="Ports, e.g. 22,80,443 or 8000-8050 "
                             "(default: common ports)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0,
                        help="Seconds to wait per port (default 1.0)")
    parser.add_argument("--authorized", action="store_true",
                        help="Confirm you have permission to test a "
                             "non-private host")
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = parser.parse_args()

    try:
        ports = parse_ports(args.ports) if args.ports else DEFAULT_PORTS
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
    if not 0.1 <= args.timeout <= 10:
        print("Error: --timeout must be between 0.1 and 10.", file=sys.stderr)
        return 2

    try:
        ip = socket.getaddrinfo(args.host, None)[0][4][0]
        addr = ipaddress.ip_address(ip)
    except (socket.gaierror, ValueError):
        print(f"Error: cannot resolve host: {args.host}", file=sys.stderr)
        return 2

    internal = addr.is_private or addr.is_loopback or addr.is_link_local
    if not internal and not args.authorized:
        print(f"Refused: {args.host} ({ip}) is not a private or local address.\n"
              "Only test systems you own or have written permission to test.\n"
              "If that is the case, run again with --authorized.",
              file=sys.stderr)
        return 2

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
        results = list(pool.map(
            lambda p: check_port(ip, p, args.timeout), ports))
    open_ports = [r for r in results if r["open"]]

    if args.json:
        print(json.dumps({"host": args.host, "ip": ip,
                          "checked": len(ports), "open": open_ports}, indent=2))
        return 0

    print("=" * 32)
    print("         PORT CHECKER")
    print("=" * 32)
    print(f"Target  : {args.host} ({ip})")
    print(f"Checked : {len(ports)} TCP port(s)\n")
    for r in open_ports:
        print(f"[+] {r['port']:<5} open   {r['service']}")
    if not open_ports:
        print("[-] No open ports found among those checked.")
    print(f"\n{len(open_ports)} open, {len(ports) - len(open_ports)} "
          "closed or filtered")

    warnings = [f"{r['port']} {RISKY[r['port']]}" for r in open_ports
                if r["port"] in RISKY]
    if warnings:
        print("\n[!] Review these open ports; close or firewall them if unused:")
        for w in warnings:
            print(f"    {w}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
