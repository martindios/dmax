from scapy.all import srp, Ether, ARP, conf
import argparse
import ipaddress
import signal
import requests
from typing import Optional


def subnet_type(value: str):
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
                f"Invalid subnet: {value}."
                )


def signal_handler(sig, frame):
    print("Exiting gracefully")
    exit(0)


def arp_broadcast(iface: str, subnet: str):
    ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet)),
            timeout=2,
            iface=iface
            )

    for snd, rcv in ans:
        print(f"{rcv.psrc} is at {rcv.hwsrc}")
        print(f"The vendor of {rcv.hwsrc} is: {lookup_mac_vendor(rcv.hwsrc)}")


def lookup_mac_vendor(mac: str) -> Optional[str]:
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url, timeout=5)

    if response.status_code == 200:
        return response.text
    else:
        return None



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

    arp_broadcast(args.interface, args.subnet)


if __name__ == "__main__":
    main()
