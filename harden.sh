#!/bin/sh
# Phase 4 — durcissement (manuel, sans Ansible).
# A lancer depuis la racine du depot :  sudo sh harden.sh
mkdir -p firewall
cat > firewall/after.nft <<'NFT'
#!/usr/sbin/nft -f
# RA Guard / DHCPv6 Guard / filtrage ND + limitation de debit + anti-contournement.
# Interfaces de confiance du pont : x1 = routeur, x2 = dhcp6
table bridge filter {
  chain forward {
    type filter hook forward priority 0; policy accept;

    ip6 nexthdr 44 drop comment "ND fragmente rejete (RFC 6980)"

    ip6 nexthdr { 0, 60, 43 } icmpv6 type nd-router-advert iifname != "x1" drop
    ip6 nexthdr { 0, 60, 43 } udp sport 547 iifname != "x2" drop
    ip6 nexthdr { 0, 60, 43 } log prefix "ND-EXTHDR-SUSPECT: " drop

    icmpv6 type nd-router-advert iifname != "x1" drop
    udp sport 547 iifname != "x2" drop
    icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 saddr { ::/128, ff00::/8 } drop
    icmpv6 type nd-neighbor-solicit limit rate over 20/second burst 10 packets drop
    icmpv6 type nd-router-solicit limit rate over 5/second drop

    counter accept
  }
}
NFT

echo ">>> Chargement des regles nftables sur le pont bridge-lan..."
nft delete table bridge filter 2>/dev/null
if nft -f firewall/after.nft; then
  echo "    OK : regles RA Guard / DHCPv6 Guard / ND chargees."
else
  echo "    ECHEC du chargement nftables." >&2
  exit 1
fi

echo ">>> Durcissement adressage (RFC 7217/8981) + cache de voisins sur hote-a et hote-b..."
for H in hote-a hote-b; do
  docker exec clab-projet10-ipv6-$H sysctl -w net.ipv6.conf.eth1.use_tempaddr=2
  docker exec clab-projet10-ipv6-$H sysctl -w net.ipv6.conf.eth1.addr_gen_mode=3
  docker exec clab-projet10-ipv6-$H sysctl -w net.ipv6.neigh.default.gc_thresh1=512
  docker exec clab-projet10-ipv6-$H sysctl -w net.ipv6.neigh.default.gc_thresh2=1024
  docker exec clab-projet10-ipv6-$H sysctl -w net.ipv6.neigh.default.gc_thresh3=2048
done

echo ">>> Ruleset charge (compteurs a 0 attendus, normal avant rejeu) :"
nft -a list table bridge filter
echo ">>> Phase 4 terminee."
