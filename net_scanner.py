#!/usr/bin/env python3
"""net-scan: find the devices on your own network, the way arp-scan does.

Built line by line in the MUKULAH Dev course "Network scanning".
For learning, and only on networks you own or may test.
"""

from __future__ import annotations

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from scapy.all import ARP, Ether, srp

VERSION = "2.0.0"

# The broadcast name tag: a frame sent here reaches every card on the street.
BROADCAST = "ff:ff:ff:ff:ff:ff"

# Bigger than a /22 (1,024 addresses) is not a home lab any more.
MAX_ADDRESSES = 1024

# The first half of a MAC names the maker (the OUI). A few we meet in the lab.
VENDORS = {
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "08:00:27": "VirtualBox",
    "b8:27:eb": "Raspberry Pi",
}

# Doors we met with nmap in part 3, and the program usually behind each one.
SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    111: "rpcbind",
    139: "netbios-ssn",
    443: "https",
    445: "microsoft-ds",
    512: "exec",
    513: "login",
    514: "shell",
    3306: "mysql",
    5432: "postgresql",
    5900: "vnc",
}


# ---------------------------------------------------------------- colours


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"


def paint(text: str, *codes: str) -> str:
    """Wrap text in terminal colour codes."""
    return "".join(codes) + text + Color.RESET


# ---------------------------------------------------------------- devices


@dataclass
class Device:
    """One device that answered: its house number and its name tag."""

    ip: str
    mac: str


def vendor_of(mac: str) -> str:
    """Guess the maker from the first three pairs, like arp-scan does."""
    first = int(mac[:2], 16)
    # The local bit: set by software (our MAC changer), so no maker inside.
    if first & 0b10:
        return "random (set by software)"
    return VENDORS.get(mac[:8].lower(), "unknown")


# ---------------------------------------------------------------- the street


def lab_network(cidr: str) -> ipaddress.IPv4Network:
    """Turn '192.168.230.0/24' into a network, and refuse unsafe ones."""
    network = ipaddress.ip_network(cidr, strict=False)
    if network.version != 4:
        raise ValueError("ARP only works on IPv4 networks.")
    if not network.is_private:
        raise ValueError(f"{network} is not private. Scan only your own.")
    if network.num_addresses > MAX_ADDRESSES:
        raise ValueError(f"{network} is too big: max {MAX_ADDRESSES}.")
    return network


# ---------------------------------------------------------------- ARP


def arp_request(network: ipaddress.IPv4Network) -> Ether:
    """The envelope and the letter from Wireshark: who has these addresses?"""
    envelope = Ether(dst=BROADCAST)
    letter = ARP(pdst=str(network))
    return envelope / letter


def arp_scan(cidr: str, timeout: float = 2.0) -> list[Device]:
    """Ask every house on the street, and collect who answered."""
    request = arp_request(lab_network(cidr))
    answered, _ = srp(request, timeout=timeout, verbose=False)
    devices = [Device(ip=reply.psrc, mac=reply.hwsrc) for _, reply in answered]
    return sorted(devices, key=lambda d: ipaddress.ip_address(d.ip))


# ---------------------------------------------------------------- report


def show_devices(devices: list[Device]) -> None:
    """Print the devices as a table, like arp-scan."""
    print(paint(f"{'IP':<17}{'MAC':<19}MAKER", Color.BOLD))
    for device in devices:
        ip = paint(f"{device.ip:<17}", Color.CYAN)
        mac = paint(f"{device.mac:<19}", Color.YELLOW)
        print(f"{ip}{mac}{vendor_of(device.mac)}")
    print(paint(f"{len(devices)} devices answered.", Color.GREEN, Color.BOLD))


# ---------------------------------------------------------------- ports


def lab_host(ip: str) -> str:
    """One house on our own street: refuse any public address."""
    address = ipaddress.ip_address(ip)
    if not address.is_private:
        raise ValueError(f"{address} is not private. Scan only your own.")
    return str(address)


@dataclass
class Port:
    """One door we knocked on, and what happened."""

    number: int
    state: str  # "open", "closed" or "filtered", like nmap


def knock(ip: str, port: int, timeout: float = 1.0) -> Port:
    """Knock on one door, like nmap: open, closed or filtered."""
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return Port(port, "open")
    except ConnectionRefusedError:
        return Port(port, "closed")
    except OSError:  # no answer at all: a firewall swallowed the knock
        return Port(port, "filtered")


def port_scan(ip: str, ports: list[int], workers: int = 100) -> list[Port]:
    """Knock on many doors at the same time, with a pool of threads."""
    host = lab_host(ip)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda port: knock(host, port), ports))
    return sorted(results, key=lambda p: p.number)


def show_ports(ports: list[Port]) -> None:
    """Print the open doors like nmap, and count the others."""
    for state in ("closed", "filtered"):
        count = sum(1 for p in ports if p.state == state)
        if count:
            print(paint(f"Not shown: {count} {state} ports", Color.DIM))
    print(paint(f"{'PORT':<10}{'STATE':<10}SERVICE", Color.BOLD))
    for port in ports:
        if port.state != "open":
            continue
        door = paint(f"{port.number}/tcp".ljust(10), Color.CYAN)
        state = paint("open".ljust(10), Color.GREEN)
        print(f"{door}{state}{SERVICES.get(port.number, 'unknown')}")


# ---------------------------------------------------------------- command line


def parse_ports(text: str) -> list[int]:
    """Turn '22,80,1000-1024' into a sorted list of door numbers."""
    ports = set()
    for part in text.split(","):
        first, _, last = part.partition("-")
        ports.update(range(int(first), int(last or first) + 1))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports go from 1 to 65535.")
    return sorted(ports)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="net-scan",
        description="Find devices and open ports on your own lab network.",
        epilog="Example: sudo net-scan scan 192.168.230.0/24",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {VERSION}"
    )
    commands = parser.add_subparsers(
        dest="command", required=True, metavar="COMMAND"
    )
    scan = commands.add_parser("scan", help="find the devices (ARP)")
    scan.add_argument("network", help="for example 192.168.230.0/24")
    ports = commands.add_parser("ports", help="knock on one device's doors")
    ports.add_argument("ip", help="for example 192.168.230.133")
    ports.add_argument(
        "-p", "--ports", default="1-1024", help="e.g. 22,80 (default 1-1024)"
    )
    ports.add_argument(
        "-w", "--workers", type=int, default=100, help="knocks at once"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "scan":
            show_devices(arp_scan(args.network))
        else:
            ports = parse_ports(args.ports)
            show_ports(port_scan(args.ip, ports, args.workers))
    except PermissionError:
        print(paint("✗ Sending packets needs root: use sudo.", Color.RED))
        return 1
    except ValueError as error:
        print(paint(f"✗ {error}", Color.RED, Color.BOLD), file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
