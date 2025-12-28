from dataclasses import dataclass
import argparse
import ipaddress
import os
import sys
import requests
import logging
import time
import socket
from typing import Optional, Union, Dict, Iterable, List
from ipaddress import ip_address, IPv4Address, IPv6Address, _BaseNetwork
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import lru_cache
import json
import csv
import io

from scapy.all import (
    srp, Ether, ARP, sr1, srp1, IP, ICMP, conf, get_if_list
)

try:
    from pyfiglet import Figlet
    PYFIGLET_AVAILABLE = True
except ImportError:
    PYFIGLET_AVAILABLE = False

IPAddress = Union[IPv4Address, IPv6Address]


@dataclass
class Host:
    ip: IPAddress
    mac: str
    vendor: Optional[str] = None
    hostname: Optional[str] = None
    reachable: bool = False
    ttl: Optional[int] = None
    os_guess: Optional[str] = None


def show_banner(version: str = "1.0.0") -> None:
    """
    Display ASCII art banner using pyfiglet.
    """
    if PYFIGLET_AVAILABLE:
        try:
            f = Figlet(font='slant')
            print(f.renderText('dmax'))
            print(f"Network Discovery Tool v{version}")
            print(f"{'-' * 40}\n")
        except Exception:
            print(f"\n=== dmax - Network Discovery Tool v{version} ===\n")
    else:
        print(f"\n=== dmax - Network Discovery Tool v{version} ===\n")



def subnet_type(value: str) -> ipaddress._BaseNetwork:
    """
    Parse and validate a subnet argument for argparse.
    """
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(f"Invalid subnet: {value}.")


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

    time.sleep(0.25)  # rate limit

    try:
        response = requests.get(url, timeout=5)

        if response.status_code == 200:
            text = response.text.strip()
            return text if text else None
        logging.debug("Vendor lookup returned %s for %s", response.status_code, mac)

    except requests.RequestException:
        logging.debug("Vendor lookup failed for %s", mac)

    return None


def icmp_ping(ip: str, mac: Optional[str], timeout: int = 2, retries: int = 1) -> Optional[int]:
    """
    Send one ICMP echo and return the TTL on reply (or None).
    """
    for attempt in range(retries + 1):
        try:
            if mac:
                pkt = Ether(dst=mac) / IP(dst=ip) / ICMP()
                reply = srp1(pkt, timeout=timeout, verbose=0)
            else:
                pkt = IP(dst=ip) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0)

            if reply and IP in reply:
                return int(reply[IP].ttl)

        except Exception as e:
            if attempt == retries:
                logging.debug("ICMP ping error for %s: %s", ip, e)
        if attempt < retries:
            time.sleep(0.1)

    return None


def ttl_to_os(ttl: int) -> str:
    candidates = {
            64: "Linux / Unix / BSD",
            128: "Windows",
            255: "Cisco / Network device"
            }
    best = min(candidates.keys(), key=lambda k: abs(k - ttl))
    return candidates[best]


def hosts_icmp(hosts: Dict[IPAddress, Host], timeout: int = 2, workers: int = 16, retry: int = 1, show_progress: bool = True) -> None:
    """
    Probe hosts concurrently with ICMP to set reachable/ttl/os_guess fields.
    """
    if not hosts:
        return

    total = len(hosts)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(icmp_ping, str(ip), hosts[ip].mac, timeout, retry): ip for ip in hosts.keys()}
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


def resolve_hostname(ip: str, timeout: int = 2) -> Optional[str]:
    """
    Resolve hostname for given IP address using reverse DNS lookup.
    """
    try:
        socket.setdefaulttimeout(timeout)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror, socket.timeout):
        logging.debug("Hostname resolution failed for %s", ip)
    except Exception as e:
        logging.debug("Hostname resolution error for %s: %s", ip, e)
    finally:
        socket.setdefaulttimeout(None)

    return None


def hosts_resolve_hostnames(hosts: Dict[IPAddress, Host], timeout: int = 2, workers: int = 16, show_progress: bool = True) -> None:
    """
    Resolve hostnames for discovered hosts concurrently.
    """
    if not hosts:
        return

    total = len(hosts)
    completed = 0

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {ex.submit(resolve_hostname, str(ip), timeout): ip for ip in hosts.keys()}
        for fut in as_completed(future_map):
            ip = future_map[fut]
            try:
                hostname = fut.result()
                hosts[ip].hostname = hostname
            except Exception as e:
                logging.debug("Error resolving hostname for %s: %s", ip, e)
            completed += 1
            if show_progress and logging.getLogger().isEnabledFor(logging.INFO):
                logging.info("Hostname resolution: %d/%d completed", completed, total)


# Output helpers


def sort_hosts(hosts: Dict[IPAddress, Host]) -> List[Host]:
    return [hosts[k] for k in sorted(hosts.keys())]


def format_table(hosts: Iterable[Host]) -> str:
    rows = [[
        str(h.ip),
        h.mac,
        h.hostname or "-",
        h.vendor or "-",
        "yes" if h.reachable else "no",
        str(h.ttl) if h.ttl is not None else "-",
        h.os_guess or "-",
        ] for h in hosts]

    headers = ["IP", "MAC", "Hostname", "Vendor", "Reachable", "TTL", "OS Guess"]

    cols = list(zip(*([headers] + rows))) if rows else [tuple(headers)]
    widths = [max(len(str(cell)) for cell in col) for col in cols]

    def render_row(row: Iterable[str]) -> str:
        return "  ".join(str(cell).ljust(w) for cell, w in zip(row, widths))

    lines = [render_row(headers), render_row(["-" * w for w in widths])]
    lines += [render_row(r) for r in rows]
    return "\n".join(lines)


def output_table(hosts: Iterable[Host], out_file: Optional[str] = None) -> None:
    s = format_table(hosts)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(s)
        logging.info("Wrote table output to %s", out_file)
    else:
        print(s)


def output_json(hosts: Iterable[Host], out_file: Optional[str] = None) -> None:
    data = [
        {
            "ip": str(h.ip),
            "mac": h.mac,
            "hostname": h.hostname,
            "vendor": h.vendor,
            "reachable": h.reachable,
            "ttl": h.ttl,
            "os_guess": h.os_guess,
        }
        for h in hosts
    ]
    s = json.dumps(data, indent=2)
    if out_file:
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(s)
        logging.info("Wrote JSON output to %s", out_file)
    else:
        print(s)


def output_csv(hosts: Iterable[Host], out_file: Optional[str] = None) -> None:
    fieldnames = ["ip", "mac", "hostname", "vendor", "reachable", "ttl", "os_guess"]
    
    rows = [
        {
            "ip": str(h.ip),
            "mac": h.mac,
            "hostname": h.hostname or "",
            "vendor": h.vendor or "",
            "reachable": "yes" if h.reachable else "no",
            "ttl": str(h.ttl) if h.ttl is not None else "",
            "os_guess": h.os_guess or "",
        }
        for h in hosts
    ]

    if out_file:
        with open(out_file, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        logging.info("Wrote CSV output to %s", out_file)
    else:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
        print(output.getvalue(), end="")


def parse_args():
    p = argparse.ArgumentParser(description="dmax - network discovery")

    # Required flags
    p.add_argument("-i", "--interface", required=True,
                   help="Network interface (e.g. eth0)")
    p.add_argument("-s", "--subnet", type=subnet_type, required=True,
                   help="Subnet to discover (e.g. 192.168.1.0/24)")

    # Feature flags
    features = p.add_argument_group('feature toggles')
    features.add_argument("--no-icmp", action="store_true",
                          help="Skip ICMP probing (faster ARP-only scan)")
    features.add_argument("--no-resolve-hostnames", action="store_true",
                          help="Skip reverse DNS lookups for hostnames")
    features.add_argument("--no-vendor", action="store_true",
                          help="Skip MAC vendor lookups (faster, offline)")

    # Timing and concurrency (applies to ICMP and hostname resolution)
    timing = p.add_argument_group('timing and concurrency options')
    timing.add_argument("-t", "--timeout", type=int, default=2,
                        help="Timeout in seconds for network operations (ICMP, DNS)")
    timing.add_argument("-w", "--workers", type=int, default=16,
                        help="Number of parallel workers for probing operations")

    # ICMP-specific options
    icmp_opts = p.add_argument_group('ICMP-specific options (ignored if --no-icmp is set)')
    icmp_opts.add_argument("-r", "--retry", type=int, default=1,
                          help="Number of ICMP retry attempts")

    # Output options
    output_opts = p.add_argument_group('output options')
    output_opts.add_argument("--output", choices=["table", "json", "csv"], default="table",
                             help="Output format")
    output_opts.add_argument("--out-file",
                             help="Write output to file instead of stdout")
    output_opts.add_argument("-v", "--verbose", action="count", default=0,
                             help="Increase verbosity (-v for INFO, -vv for DEBUG)")
    output_opts.add_argument("--no-banner", action="store_true",
                          help="Suppress ASCII art banner")

    args = p.parse_args()

    if args.no_icmp and args.retry != 1:
        p.error("--retry option is only applicable when ICMP probing is enabled (don't use with --no-icmp)")

    return args


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
        logging.error("Interface '%s' not found. Available: %s",
                      args.interface, ", ".join(get_if_list()))
        return 2

    conf.verb = 0

    if not args.no_banner and not args.out_file:
        show_banner()

    start = time.perf_counter()

    logging.info("Starting ARP discovery on %s (%s)", args.interface, args.subnet)
    hosts = arp_broadcast(args.interface, args.subnet)
    logging.info("Discovered %d hosts via ARP", len(hosts))

    if not hosts:
        logging.info("No hosts discovered. Exiting.")
        return 0

    if not args.no_icmp:
        hosts_icmp(hosts, timeout=args.timeout, workers=args.workers, retry=args.retry)

    if not args.no_resolve_hostnames:
        logging.info("Resolving hostnames...")
        hosts_resolve_hostnames(hosts, timeout=args.timeout, workers=args.workers)

    if not args.no_vendor:
        logging.info("Looking up MAC vendors...")
        for h in hosts.values():
            # To anonymize the MAC address by removing the device-specific part
            mac_parts = h.mac.split(":")
            if len(mac_parts) >= 3:
                anonymized_mac = ":".join(mac_parts[:3]) + ":ff:ff:ff"
            else:
                anonymized_mac = h.mac

            try:
                h.vendor = lookup_mac_vendor(anonymized_mac)
            except Exception:
                h.vendor = None

    sorted_list = sort_hosts(hosts)

    if args.output == "table":
        output_table(sorted_list, out_file=args.out_file)
    elif args.output == "json":
        output_json(sorted_list, out_file=args.out_file)
    elif args.output == "csv":
        output_csv(sorted_list, out_file=args.out_file)

    elapsed = time.perf_counter() - start
    reachable = sum(1 for h in hosts.values() if h.reachable)
    logging.info("Summary: %d/%d reachable. Elapsed: %.2fs",
                 reachable, len(hosts), elapsed)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Exiting on user interrupt.")
        sys.exit(0)
