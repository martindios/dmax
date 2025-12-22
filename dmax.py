from dataclasses import dataclass
from scapy.all import *
import argparse
import ipaddress
import signal
import os
import sys
import requests
import logging
from typing import Optional, Union
from ipaddress import ip_address
from pprint import pprint
from ipaddress import IPv4Address, IPv6Address, _BaseNetwork
from concurrent.futures import ThreadPoolExecutor, as_completed

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
    except ValueError:
        raise argparse.ArgumentTypeError(
                f"Invalid subnet: {value}."
                )


def check_root() -> None:
    if os.name != "nt":
        if os.geteuid() != 0:
            logging.error("This script must be run as root.")
            sys.exit(1)
    else:
        logging.warning("On Windows make sure to run as Administrator.")


def signal_handler(sig, frame):
    print("Exiting gracefully")
    exit(0)


def arp_broadcast(iface: str, subnet: _BaseNetwork) -> dict[IPAddress, Host]:
    """Broadcast ARP on the requested subnet and return discovered hosts."""
    hosts: Dict[IPAddress, Host] = {}

    try:
        ans, _unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
                timeout=2,
                iface=iface,
                verbose=0
                )

    except Exception as e:
        logging.error("ARP scan failed: %s", e)
        return hosts

    for _, rcv in ans:
        ip = ip_address(rcv.psrc)
        mac = rcv.hwsrc
        vendor = None
        try:
            vendor = lookup_mac_vendor(mac)
        except Exception:
            vendor = None

        hosts[ip] = Host(ip=ip, mac=mac, vendor=vendor)
    return hosts


def lookup_mac_vendor(mac: str) -> Optional[str]:
    """
    Look up the vendor name for a given MAC address.
    """
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        return response.text
    else:
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
    candidates = {64: "Linux / Unix / BSD", 128: "Windows", 255: "Cisco / Network device"}
    best = min(candidates.keys(), key=lambda k: abs(k - ttl))
    return candidates[best]


def hosts_icmp(hosts: Dict[IPAddress, Host], timeout: int = 2, workers: int = 16) -> None:
    """
    Probe hosts concurrently with ICMP to set reachable/ttl/os_guess fields.
    """
    if not hosts:
        return

    with ThreadPoolExecutor(max_workers=workers) as ex:
        future_map = {
                ex.submit(icmp_ping, str(ip), timeout):
                    ip for ip in hosts.keys()
                }
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


def main():
    signal.signal(signal.SIGINT, signal_handler)

    lvl = logging.WARNING
    logging.basicConfig(level=lvl, format="%(levelname)s: %(message)s")

    check_root()

    conf.verb = 0

    parser = argparse.ArgumentParser(
        description="""
        dmax is a script for discovering hosts in a network.
        """
    )

    parser.add_argument(
            "-i", "--interface",
            required=True,
            help="Network interface name")

    parser.add_argument(
            "-s", "--subnet",
            type=subnet_type,
            required=True,
            help="Subnet to discover")

    args = parser.parse_args()

    hosts = arp_broadcast(args.interface, args.subnet)

    hosts_icmp(hosts)

    pprint(hosts)


if __name__ == "__main__":
    main()
