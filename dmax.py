from scapy.all import srp, Ether, ARP, conf, IP, ICMP, sr1, UDP, sr, DNS, DNSQR
import argparse
import ipaddress
import signal
import requests
from typing import Optional, Union
from ipaddress import ip_address
from pprint import pprint
from dataclasses import dataclass
from ipaddress import IPv4Address, IPv6Address

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


def signal_handler(sig, frame):
    print("Exiting gracefully")
    exit(0)


def arp_broadcast(iface: str, subnet: str) -> dict[str, Host]:
    """
    Perform an ARP broadcast on a subnet to discover alive hosts.
    """
    hosts = {}

    ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
            timeout=2,
            iface=iface
            )

    for _, rcv in ans:
        ip = ip_address(rcv.psrc)
        mac = rcv.hwsrc
        vendor = lookup_mac_vendor(mac)

        hosts[ip] = Host(
                ip=ip,
                mac=mac,
                vendor=vendor
                )

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
    pkt = IP(dst=ip) / ICMP()
    reply = sr1(pkt, timeout=timeout, verbose=0)

    if reply and IP in reply:
        return reply[IP].ttl
    return None


def hosts_icmp(hosts: dict):
    for ip, host in hosts.items():
        ttl = icmp_ping(str(ip))
        if ttl is not None:
            host.reachable = True
            host.ttl = ttl

            if ttl <= 64:
                host.os_guess = "Linux / Unix"
            elif ttl <= 128:
                host.os_guess = "Windows"
            elif ttl <= 255:
                host.os_guess = "Cisco / BSD / Network Device"
            else:
                host.os_guess = "Unknown"

        else:
            host.reachable = False
            host.ttl = None
            host.os_guess = None


def main():
    signal.signal(signal.SIGINT, signal_handler)

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
