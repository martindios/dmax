from dataclasses import dataclass
import argparse
import ipaddress
import os
import sys
import requests
import logging
import time
from typing import Optional, Union, Dict, Iterable
from ipaddress import ip_address, IPv4Address, IPv6Address, _BaseNetwork
from pprint import pprint
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache

from scapy.all import (
    srp, Ether, ARP, sr1, IP, ICMP, conf, get_if_list
)

IPAddress = Union[IPv4Address, IPv6Address]


@dataclass
class Host:
    ip: IPAddress
    mac: str
    vendor: Optional[str] = None
    reachable: bool = False
    ttl: Optional[int] = None
    os_guess: Optional[str] = None


def subnet_type(value: str) -> ipaddress._BaseNetwork:
    """
    Parse and validate a subnet argument for argparse.
    """
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError("Not a valid IPv4/IPv6 network"):
        raise argparse.ArgumentTypeError(
                f"Invalid subnet: {value}."
                )


def check_root() -> None:
    if os.name != "nt":
        try:
            if os.geteuid() != 0:
                logging.error("This script must be run as root.")
                sys.exit(1)
        except AttributeError:
            pass  # non-POSIX platform doesn't have geteuid()
    else:
        logging.warning("On Windows make sure to run as Administrator.")


def arp_broadcast(iface: str, subnet: _BaseNetwork, timeout: int = 2) -> Dict[IPAddress, Host]:
    """Broadcast ARP on the requested subnet and return discovered hosts."""
    hosts: Dict[IPAddress, Host] = {}

    try:
        ans, _unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
                timeout=timeout,
                iface=iface,
                verbose=0
                )

    except Exception as e:
        logging.error("ARP scan failed: %s", e)
        return hosts

    for _, rcv in ans:
        try:
            ip = ip_address(rcv.psrc)
        except Exception:
            continue
        mac = rcv.hwsrc
        vendor = None
        hosts[ip] = Host(ip=ip, mac=mac, vendor=vendor)
    return hosts


@lru_cache(maxsize=1024)
def lookup_mac_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor name for a given MAC address.
    """
    url = f"https://api.macvendors.com/{mac}"

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            text = response.text.strip()
            return text if text else None
        logging.debug("Vendor lookup returned %s for %s", response.status_code, mac)

    except requests.RequestException:
        logging.debug("Vendor lookup failed for %s", mac)

    return None


def icmp_ping(ip: str, timeout: int = 2) -> Optional[int]:
    """
    Send one ICMP echo and return the TTL on reply (or None).
    """
    try:
        pkt = IP(dst=ip) / ICMP()
        reply = sr1(pkt, timeout=timeout, verbose=0)
        if reply and IP in reply:
            return int(reply[IP].ttl)

    except Exception as e:
        logging.debug("ICMP ping error for %s: %s", ip, e)
    return None


def ttl_to_os(ttl: int) -> str:
    candidates = {
            64: "Linux / Unix / BSD",
            128: "Windows",
            255: "Cisco / Network device"
            }
    best = min(candidates.keys(), key=lambda k: abs(k - ttl))
    return candidates[best]


def hosts_icmp(hosts: Dict[IPAddress, Host], timeout: int = 2, workers: int = 16, show_progress: bool = True) -> None:
    """
    Probe hosts concurrently with ICMP to set reachable/ttl/os_guess fields.
    """
    if not hosts:
        return

    total = len(hosts)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(icmp_ping, str(ip), timeout): ip for ip in hosts.keys()}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                ttl = fut.result()
                host = hosts[ip]
                if ttl is not None:
                    host.reachable = True
                    host.ttl = ttl
                    host.os_guess = ttl_to_os(ttl)
                else:
                    host.reachable = False
                    host.ttl = None
                    host.os_guess = None
            except Exception as e:
                logging.debug("Error probing %s: %s", ip, e)
                hosts[ip].reachable = False
            completed += 1
            if show_progress and logging.getLogger().isEnabledFor(logging.INFO):
                logging.info("ICMP probes: %d/%d completed", completed, total)

# Output helpers

def sort_hosts(hosts: Dict[IPAddress, Host]) -> list[Host]:
    return [hosts[k] for k in sorted(hosts.keys())]


def format_table(hosts: Iterable[Host]) -> str:
    rows = [[
        str(h.ip),
        h.mac,
        h.vendor or "-",
        "yes" if h.reachable else "no",
        str(h.ttl) if h.ttl is not None else "-",
        h.os_guess or "-",
        ] for h in hosts]

    headers = ["IP", "MAC", "Vendor", "Reachable", "TTL", "OS Guess"]

    cols = list(zip(*([headers] + rows))) if rows else [tuple(headers)]
    widths = [max(len(str(cell)) for cell in col) for col in cols]

    def render_row(row: Iterable[str]) -> str:
        return "  ".join(str(cell).ljust(w) for cell, w in zip(row, widths))

    lines = [render_row(headers), render_row(["-" * w for w in widths])]
    lines += [render_row(r) for r in rows]
    return "\n".join(lines)


def parse_args():
    p = argparse.ArgumentParser(description="dmax - network discovery")
    p.add_argument("-i", "--interface", required=True, help="Network interface (e.g. eth0)")
    p.add_argument("-s", "--subnet", type=subnet_type, required=True, help="Subnet to discover (e.g. 192.168.1.0/24)")
    p.add_argument("-t", "--timeout", type=int, default=2, help="ICMP timeout seconds")
    p.add_argument("-w", "--workers", type=int, default=16, help="Parallel ICMP workers")
    p.add_argument("-v", "--verbose", action="count", default=0)
    p.add_argument("--no-vendor", action="store_true", help="Skip MAC vendor lookups (faster, offline)")
    p.add_argument("--output", choices=["table", "json", "csv"], default="table", help="Output format")
    return p.parse_args()


def main():

    args = parse_args()

    lvl = logging.WARNING
    if args.verbose == 1:
        lvl = logging.INFO
    elif args.verbose >= 2:
        lvl = logging.DEBUG

    logging.basicConfig(level=lvl, format="%(levelname)s: %(message)s")

    check_root()

    if args.interface not in get_if_list():
        logging.error("Interface '%s' not found. Available: %s", args.interface, ", ".join(get_if_list()))
        return 2

    conf.verb = 0

    start = time.perf_counter()

    logging.info("Starting ARP discovery on %s (%s)", args.interface, args.subnet)
    hosts = arp_broadcast(args.interface, args.subnet)
    logging.info("Discovered %d hosts via ARP", len(hosts))

    if not hosts:
        logging.info("No hosts discovered. Exiting.")
        return 0

    hosts_icmp(hosts, timeout=args.timeout, workers=args.workers)

    if not args.no_vendor:
        for h in hosts.values():
            # To anonymize the MAC address by removing the device-specific part
            anonymized_mac = h.mac.lower().rsplit(":", 3)[0] + ":ff:ff:ff"
            try:
                h.vendor = lookup_mac_vendor(anonymized_mac)
            except Exception:
                h.vendor = None

    sorted_list = sort_hosts(hosts)

    if args.output == "table":
        print(format_table(sorted_list))

    elapsed = time.perf_counter() - start
    reachable = sum(1 for h in hosts.values() if h.reachable)
    logging.info("Summary: %d/%d reachable. Elapsed: %.2fs", reachable, len(hosts), elapsed)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Exiting on user interrupt.")
        sys.exit(0)
