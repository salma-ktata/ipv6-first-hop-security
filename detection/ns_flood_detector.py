#!/usr/bin/env python3
"""
ns_flood_detector.py — Phase 6 : detecte une saturation du cache de voisins.
Compte les Neighbor Solicitation (NS) sur une fenetre glissante et alerte au-dessus d'un seuil.
Exemple : sudo python3 detection/ns_flood_detector.py --iface bridge-lan
"""
import argparse
import time
import collections
from scapy.all import sniff, IPv6, ICMPv6ND_NS


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--window", type=float, default=5.0, help="fenetre en secondes")
    p.add_argument("--threshold", type=int, default=100, help="NS/fenetre avant alerte")
    args = p.parse_args()

    times = collections.deque()
    alerted = False

    def handle(pkt):
        nonlocal alerted
        if ICMPv6ND_NS in pkt:
            now = time.time()
            times.append(now)
            while times and now - times[0] > args.window:
                times.popleft()
            if len(times) >= args.threshold:
                if not alerted:
                    src = pkt[IPv6].src if IPv6 in pkt else "?"
                    print(f"[ALERTE] flood NS : {len(times)} NS en {args.window:.0f}s (dernier src {src})")
                    alerted = True
            else:
                alerted = False

    print(f"Detecteur NS-flood a l'ecoute sur {args.iface} "
          f"(seuil {args.threshold} NS / {args.window:.0f}s). Ctrl+C pour arreter.")
    sniff(iface=args.iface, filter="icmp6", prn=handle, store=False)


if __name__ == "__main__":
    main()