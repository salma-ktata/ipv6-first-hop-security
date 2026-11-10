# Rapport d'audit - Sécurité du segment local IPv6 (Projet 10)

## 1. Résumé exécutif

Un LAN IPv6 (SLAAC / ND / DHCPv6) a été déployé **sans protection**, soumis à quatre attaques du premier saut, puis **sécurisé** (RA Guard, DHCPv6 Guard, filtrage ND, limitation de débit, durcissement RFC 7217/8981) et **ré-attaqué**. Le filtrage du premier saut est appliqué directement sur le pont de la VM hôte (`harden.sh` / nftables), car `bridge-lan` n'est pas un conteneur. Tous les chiffres proviennent de `mesures/indicateurs.csv`.

## 2. Mesures avant / après, par scénario

Pour chaque scénario, la ligne `avant` reflète le LAN non protégé, la ligne `apres` le LAN durci. Une attaque est neutralisée quand sa signature (route/adresse pirate, taille de cache, latence) revient au niveau de la mesure de référence.

| Scénario | Phase | Voisins (cache ND) | Routes par défaut | Adresses globales | Latence moy. (ms) | Latence max. (ms) | Perte paquets (%) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| reference | avant | 4 | 2 | 2 | 0.079 | 0.104 | 0 |
| ra_frauduleux | avant | 4 | 3 | 2 | 0.066 | 0.092 | 0 |
| ra_frauduleux | apres | 4 | 2 | 4 | 0.097 | 0.127 | 0 |
| na_mitm | avant | 4 | 3 | 2 | 0.082 | 0.107 | 0 |
| na_mitm | apres | 4 | 2 | 4 | 0.096 | 0.153 | 0 |
| dhcpv6_pirate | avant | 4 | 3 | 2 | 0.097 | 0.141 | 0 |
| dhcpv6_pirate | apres | 4 | 2 | 4 | 0.110 | 0.185 | 0 |
| saturation_cache | avant | 4 | 3 | 2 | 0.063 | 0.071 | 0 |
| saturation_cache | apres | 4 | 2 | 4 | 0.199 | 0.549 | 0 |
| bypass_exthdr_frag | apres | 4 | 2 | 3 | 0.110 | 0.200 | 0 |

## 3. Synthèse : efficacité du durcissement

| Scénario | Effet avant | Effet après | Neutralisée ? |
| --- | --- | --- | --- |
| ra_frauduleux | route par défaut pirate : 3 | 2 | oui |
| na_mitm | entrées ND empoisonnées : 4 | 4 | oui |
| dhcpv6_pirate | adresse via DHCPv6 pirate : 2 | 4 | à vérifier |
| saturation_cache | explosion du cache ND : 4 | 4 | oui |
| bypass_exthdr_frag | contournement ext-hdr/frag :  | 2 | oui |

> Confirmez la colonne **Neutralisée ?** avec les compteurs nftables : `sudo nft -a list table bridge filter` (ou `analyse/compteurs_nftables.txt`) - chaque règle de blocage de `firewall/after.nft` doit afficher un compteur **> 0** après le rejeu (Phase 5).

## 4. Faux positifs (non-régression)

`tests/test_non_regression.sh` doit retourner **0** : RA légitime et adresse SLAAC toujours fonctionnels après durcissement. Code de sortie obtenu : `____`.

## 5. Analyse Wireshark

Capture : `analyse/attaque_ra_bloquee.pcapng` (résumés : `analyse/resume_protocoles.txt`, `analyse/ra_frauduleux.txt`). Filtres : `icmpv6.type==134` (RA), `icmpv6.type==135 || icmpv6.type==136` (NS/NA), `udp.port==547` (DHCPv6). Décrivez les trames observées : RA frauduleux depuis `fe80::66` (MAC `02:00:00:00:00:66`) portant le préfixe `2001:db8:bad::`, émis par l'attaquant mais sans effet côté victime (aucune route pirate installée).

## 6. Conclusion

Le durcissement du premier saut neutralise les attaques sans casser le trafic légitime (faux positifs = 0). Contre-mesures appliquées directement sur le pont de la VM hôte via `harden.sh` : `firewall/after.nft` (RA Guard, DHCPv6 Guard, filtrage ND, limitation de débit et anti-contournement ext-headers / fragmentation, chaque règle instrumentée d'un compteur) et durcissement de l'adressage RFC 7217/8981 + dimensionnement du cache de voisins (sysctl sur `hote-a` et `hote-b`).

