#!/usr/bin/env python3
"""
dhcpv6_rogue_detector.py — Phase 6 : detecte un serveur DHCPv6 pirate.
Alerte des qu'une reponse serveur DHCPv6 (Advertise/Reply, UDP sport 547) provient
d'une MAC autre que celle du serveur Kea legitime.
Exemple :
  sudo python3 detection/dhcpv6_rogue_detector.py --iface bridge-lan --trusted-mac <mac_kea>
MAC de Kea : docker exec clab-projet10-ipv6-dhcp6 cat /sys/class/net/eth1/address
"""
import argparse
from scapy.all import sniff, Ether, IPv6
from scapy.layers.dhcp6 import DHCP6_Advertise, DHCP6_Reply


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--trusted-mac", required=True, help="MAC du serveur Kea legitime")
    args = p.parse_args()
    trusted = args.trusted_mac.lower()

    def handle(pkt):
        if (DHCP6_Advertise in pkt or DHCP6_Reply in pkt) and Ether in pkt:
            src_mac = pkt[Ether].src.lower()
            if src_mac != trusted:
                src_ip = pkt[IPv6].src if IPv6 in pkt else "?"
                kind = "Advertise" if DHCP6_Advertise in pkt else "Reply"
                print(f"[ALERTE] DHCPv6 pirate : {kind} depuis MAC {src_mac} (IP {src_ip}) != Kea {trusted}")

    print(f"Detecteur DHCPv6-pirate a l'ecoute sur {args.iface} "
          f"(MAC de confiance {trusted}). Ctrl+C pour arreter.")
    sniff(iface=args.iface, filter="udp port 547", prn=handle, store=False)


if __name__ == "__main__":
    main()