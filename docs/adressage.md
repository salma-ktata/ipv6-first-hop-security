# Plan d'adressage — Projet 10

- **Préfixe de site :** `2001:db8:10::/48`
- **VLAN utilisateurs (LAN de test) :** `2001:db8:10:1::/64`
- **Adresse du routeur :** `2001:db8:10:1::1`
- **Plage DHCPv6 (Kea) :** `2001:db8:10:1::1000` → `2001:db8:10:1::2000`
- **DNS (option DHCPv6) :** `2001:db8:10:1::53`

## Ports de confiance / non fiables (pont Linux bridge-lan)
Noms réels des interfaces côté hôte, vérifiés avec `ip link show master bridge-lan` :

| Interface (côté bridge-lan) | Nœud raccordé | Rôle | Confiance |
|---|---|---|---|
| `x1` | routeur | radvd + FRR | **Confiance** |
| `x2` | dhcp6 | Kea | **Confiance** |
| `x3` | hote-a | Hôte client | Non fiable |
| `x4` | hote-b | Hôte client | Non fiable |
| `x5` | attaquant | Machine d'attaque (labo) | Non fiable |

Ces noms viennent de l'ordre des liens dans `topo/topo.clab.yml`. Si vous
modifiez la topologie, revérifiez avec `ip link show master bridge-lan`
avant de toucher à `firewall/after.nft`.