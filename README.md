# Projet 10 — Sécurité du segment local IPv6

LAN IPv6 d'entreprise (SLAAC / ND / DHCPv6) déployé **sans protection**, attaqué en
laboratoire, puis **sécurisé** (RA Guard, DHCPv6 Guard, filtrage ND, limitation de
débit, anti-contournement, durcissement RFC 7217/8981) et **ré-attaqué** pour prouver
l'efficacité. Topologie **Containerlab** : `routeur` (radvd + FRR, Alpine), `dhcp6`
(Kea, Ubuntu), `hote-a`, `hote-b`, `attaquant` (scapy), et un pont Linux `bridge-lan`
sur la VM hôte qui porte le filtrage `nftables` (famille `bridge`).

## ⚠️ Pièges connus (à lire avant tout)

- **`bridge-lan` disparaît à chaque reboot / `containerlab destroy`** : le recréer
  **avant** `deploy` :
  ```bash
  sudo ip link add name bridge-lan type bridge
  sudo ip link set bridge-lan up
  ```
- **`bridge-lan` n'est pas un conteneur** : le filtrage s'y charge **localement sur la
  VM hôte** (`harden.sh` / `sudo nft -f`), jamais via `docker`.
- **Interfaces de confiance du pont** : `x1` = routeur, `x2` = dhcp6
  (`ip link show master bridge-lan`).
- **Aucun conteneur n'a systemd** : services lancés par commande directe.
  FRR : jamais `frrinit.sh restart` → `zebra -d` à froid, `frr-reload.py` pour recharger.
  Kea exige `/run/kea`, radvd exige `/run/radvd`.
- **Adresses d'attaque en hexa valide** : `2001:db8:bad::` (jamais `evil`).
- **`collect_metrics.sh` tourne sur l'hôte** et interroge la victime via `docker exec`.
- **Les scripts d'attaque vivent dans le conteneur attaquant** : `docker cp` avant usage.
  Le conteneur `attaquant` (Kali) n'a pas `tcpdump`/`pkill` par défaut :
  `docker exec clab-projet10-ipv6-attaquant apt-get install -y tcpdump procps`.

## Mise en route

```bash
# 1) Pont + topologie
sudo ip link add name bridge-lan type bridge && sudo ip link set bridge-lan up
sudo containerlab deploy -t topo/topo.clab.yml
ip link show master bridge-lan            # x1..x5 presents

# 2) Base vulnerable (radvd/FRR/Kea) via Ansible
cd ansible && sudo python3 deploy.py vulnerable && cd ..

# 3) Validation
docker exec clab-projet10-ipv6-hote-a ip -6 addr show dev eth1
docker exec clab-projet10-ipv6-hote-a ping6 -c3 2001:db8:10:1::1
docker exec clab-projet10-ipv6-dhcp6 ps aux | grep kea
```

> **Ansible** sert uniquement au **déploiement de la base vulnérable**
> (`deploy.py vulnerable`). Le **durcissement se fait avec `harden.sh`**, pas via
> Ansible (`bridge-lan` étant géré directement sur la VM hôte).

## Les 6 phases

| Phase | But | Commande clé | Test de sortie |
|------:|-----|--------------|----------------|
| 0 | Dépôt + topologie | `containerlab deploy` | tous les nœuds `running` |
| 1 | LAN vulnérable | `deploy.py vulnerable` | SLAAC OK, routeur répond, aucun filtrage |
| 2 | Mesure de référence | `sudo ./mesures/collect_metrics.sh avant reference` | 1 ligne dans `indicateurs.csv` |
| 3 | Campagne d'attaques | scripts `attaques/*.py` + `collect_metrics.sh avant <scenario>` | effet visible côté victime |
| 4 | Durcissement | `sudo sh harden.sh` | règles chargées (compteurs 0), ping légitime OK |
| 5 | Rejeu + non-régression | rejeu + `collect_metrics.sh apres <scenario>` ; `tests/test_non_regression.sh` | compteurs nftables > 0, non-rég = 0 |
| 6 | Analyse + rapport | capture + `tshark` ; `python3 generate_report.py` | pcap + `docs/rapport_audit_final.md` |

Les 4 attaques (Phase 3) : **RA frauduleux**, **usurpation NA (MITM)**, **serveur
DHCPv6 pirate**, **saturation du cache de voisins**. Phase 5 ajoute les **tentatives de
contournement** (en-têtes d'extension / fragmentation).

### Détail — Phase 3 (attaques)
```bash
# copier les scripts + scapy dans l'attaquant
for f in fake_ra na_spoof_mitm rogue_dhcpv6 neighbor_cache_exhaustion; do
  docker cp "attaques/$f.py" "clab-projet10-ipv6-attaquant:/$f.py"; done
docker exec clab-projet10-ipv6-attaquant apt-get install -y python3-scapy
# exemple : RA frauduleux
docker exec clab-projet10-ipv6-attaquant python3 /fake_ra.py --iface eth1 --count 10
sudo ./mesures/collect_metrics.sh avant ra_frauduleux
```

### Détail — Phase 4 (durcissement)
```bash
sudo sh harden.sh                        # depuis la racine du depot
sudo nft -a list table bridge filter     # RA Guard / DHCPv6 Guard / ND, compteurs a 0
```
`harden.sh` charge `firewall/after.nft` sur le pont (RA Guard, DHCPv6 Guard, filtrage
ND, limitation de débit, anti-contournement — chaque règle avec compteur) et applique
le durcissement d'adressage RFC 7217/8981 + cache (sysctl sur `hote-a`/`hote-b`).

### Détail — Phase 6 (analyse + rapport)
```bash
# capture d'un RA frauduleux cote attaquant
docker exec -d clab-projet10-ipv6-attaquant tcpdump -i eth1 -c 10 -w /cap.pcapng 'icmp6 && ip6[40] == 134'
docker exec clab-projet10-ipv6-attaquant python3 /fake_ra.py --iface eth1 --count 10
docker cp clab-projet10-ipv6-attaquant:/cap.pcapng analyse/attaque_ra_bloquee.pcapng
tshark -r analyse/attaque_ra_bloquee.pcapng -q -z io,phs
# rapport final
python3 generate_report.py               # -> docs/rapport_audit_final.md
```
(Wireshark en GUI peut planter sur cette VM ; `tshark` fait la même analyse en ligne
de commande. Filtres : `icmpv6.type==134`, `icmpv6.type==135 || icmpv6.type==136`,
`udp.port==547`.)

## Arborescence

```
topo/            topologie Containerlab
routeur/         radvd.conf, frr.conf
dhcpv6/          kea-dhcp6.conf
firewall/        before.nft (vulnerable), after.nft (durci : RA/DHCPv6 Guard + ND
                 + limitation debit + anti-contournement, chaque regle avec compteur)
attaques/        fake_ra.py, na_spoof_mitm.py, rogue_dhcpv6.py,
                 neighbor_cache_exhaustion.py, bypass_extheaders_fragmentation.py
detection/       ns_flood_detector.py, dhcpv6_rogue_detector.py
mesures/         collect_metrics.sh, indicateurs.csv
tests/           test_non_regression.sh
analyse/         *.pcapng, compteurs_nftables.txt, resume_protocoles.txt, ra_frauduleux.txt
docs/            adressage.md, rapport_audit_final.md
ansible/         deploy.py + roles radvd/frr/kea (deploiement de la base vulnerable)
harden.sh        durcissement du pont (nftables) + adressage (sysctl)
generate_report.py  rapport d'audit depuis indicateurs.csv
```