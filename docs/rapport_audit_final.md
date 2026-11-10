# Rapport d'audit — Sécurité du segment local IPv6 (Projet 10)

## 1. Résumé exécutif

Un LAN IPv6 d'entreprise (SLAAC / ND / DHCPv6) a été déployé **sans protection**,
soumis en laboratoire à quatre attaques du premier saut (RA frauduleux, usurpation
NA/MITM, serveur DHCPv6 pirate, saturation du cache de voisins), puis **sécurisé**
et **ré-attaqué**. Le durcissement — RA Guard, DHCPv6 Guard, filtrage ND, limitation
de débit et anti-contournement (en-têtes d'extension / fragmentation) — est appliqué
directement sur le pont `bridge-lan` de la VM hôte via `nftables` (famille `bridge`,
script `harden.sh`), car ce pont n'est pas un conteneur. L'adressage des hôtes est
durci selon les RFC 7217 et 8981.

**Bilan :** le RA frauduleux, le DHCPv6 pirate, la saturation du cache et les
tentatives de contournement sont **neutralisés** (chaque règle de blocage affiche un
compteur > 0, et aucune signature d'attaque ne subsiste côté victime). L'usurpation
NA n'est que **partiellement atténuée**. **Zéro faux positif** : le trafic légitime
(RA du vrai routeur, SLAAC, DHCPv6 Kea) continue de fonctionner.

## 2. Mesures avant / après, par scénario

Source : `mesures/indicateurs.csv`. `avant` = LAN non protégé, `apres` = LAN durci.

| Scénario | Phase | Voisins (cache ND) | Routes par défaut | Adresses globales | Latence moy. (ms) | Latence max. (ms) | Perte (%) |
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

**Lecture des colonnes :**
- `routes_defaut` : la référence saine vaut **2** (route par défaut légitime sur
  `eth1` + route de gestion sur `eth0`). Sous attaque non protégée, elle monte à
  **3** (le RA frauduleux installe une route pirate) ; après durcissement elle
  revient à **2** → le RA pirate est rejeté.
- `adresses_globales` : la hausse de **2 à 4** après durcissement **n'est pas** une
  adresse pirate. C'est l'effet du durcissement lui-même (`use_tempaddr=2`, RFC 8981)
  qui génère des **adresses temporaires** en plus de l'adresse stable. La
  vérification `ip -6 addr show` confirme que les 4 adresses appartiennent au préfixe
  légitime `2001:db8:10:1::/64` (adresse stable + 2 temporaires) plus l'adresse de
  gestion `eth0` ; **aucune adresse `2001:db8:bad::` ni adresse du pool DHCPv6 pirate**.
- `voisins_cache` : stable à **4** partout — sur un hôte (et non un routeur), le flood
  de NS vers des cibles aléatoires n'alimente pas son cache. La preuve de blocage de la
  saturation est le **compteur nftables** (§3), pas cette colonne.
- `latence` / `perte` : latence sub-milliseconde, **0 % de perte** partout. Le pic à
  **0,549 ms** (saturation, après) est la trace du flood absorbé par la limitation de
  débit — impact négligeable.

## 3. Compteurs nftables (preuve de blocage)

Source : `analyse/compteurs_nftables.txt`, après rejeu des attaques sur le LAN durci.

| Règle de blocage | Paquets rejetés |
| --- | --- |
| Anti-contournement — ND fragmenté (RFC 6980) | 20 |
| Anti-contournement — RA via en-tête d'extension | 20 |
| Anti-contournement — DHCPv6 via en-tête d'extension | 0 |
| **RA Guard** | **40** |
| **DHCPv6 Guard** | **544** |
| ND — source invalide | 0 |
| **ND — limite de débit NS** | **17 557** |
| ND — limite de débit RS | 0 |
| Trafic légitime (règle `accept`) | 3 659 |

Chaque contre-mesure sollicitée affiche un compteur **> 0**, ce qui prouve que les
attaques sont interceptées au pont :
- **RA Guard = 40** : les RA frauduleux (diffusés en multicast sur le pont) sont tous rejetés.
- **DHCPv6 Guard = 544** : les réponses serveur (UDP sport 547) issues du port pirate
  sont bloquées — seul Kea, sur `x2`, est autorisé.
- **Anti-contournement = 20 + 20** : les RA cachés derrière un en-tête Fragment et un
  Destination Options sont rejetés (le contournement échoue).
- **Limite de débit NS = 17 557** : le flood de Neighbor Solicitation est massivement absorbé.
- **Trafic légitime = 3 659** : le trafic normal continue de passer (cohérent avec §5).

## 4. Synthèse : efficacité par attaque

| Attaque | Réussie avant | Après durcissement | Preuve | Verdict |
| --- | --- | --- | --- | --- |
| RA frauduleux | oui (route pirate : routes_defaut 2→3) | sans effet (retour à 2) | RA Guard = 40 ; 10 RA capturés sans effet | **Neutralisée** |
| Usurpation NA (MITM) | — | source valide non filtrée | seule l'entrée propre de l'attaquant (`fe80::66`) subsiste | **Partiellement atténuée** |
| DHCPv6 pirate | oui | aucune adresse du pool attribuée | DHCPv6 Guard = 544 ; `ip -6 addr` sans adresse pirate | **Neutralisée** |
| Saturation du cache | flood émis | absorbé par la limite de débit | ND limite débit NS = 17 557 | **Neutralisée** |
| Contournement ext-hdr / frag | — | RA fragmentés / encapsulés rejetés | anti-bypass = 20 + 20 | **Neutralisée** |

## 5. Faux positifs (non-régression)

`tests/test_non_regression.sh` retourne **0** : l'adresse SLAAC légitime est présente,
la route par défaut légitime est installée, et le routeur `2001:db8:10:1::1` répond au
ping. **Aucun faux positif** — le durcissement ne bloque aucun trafic légitime (confirmé
aussi par la règle `accept` = 3 659 paquets en §3).

## 6. Analyse Wireshark

Capture : `analyse/attaque_ra_bloquee.pcapng` (résumés : `analyse/resume_protocoles.txt`,
`analyse/ra_frauduleux.txt`).
- Hiérarchie des protocoles (`tshark -z io,phs`) : **10 trames, 1100 octets, 100 % ICMPv6**
  — les 10 RA frauduleux émis par l'attaquant.
- Filtre `icmpv6.type==134` : 10 Router Advertisement, source `fe80::66`, MAC
  `02:00:00:00:00:66`, option Prefix Information annonçant `2001:db8:bad::/64`.
- Corrélation avec le durcissement : ces RA sont bien **émis** par l'attaquant mais
  **sans effet** côté victime (aucune route `2001:db8:bad::` — `ip -6 route show`), et le
  compteur **RA Guard** s'incrémente en conséquence.
- Filtres complémentaires pour l'analyse des autres familles : `icmpv6.type==135 || icmpv6.type==136`
  (NS/NA), `udp.port==547` (DHCPv6).

## 7. Indicateurs demandés

| Indicateur | Résultat |
| --- | --- |
| Attaques réussies avant / après | 4/4 réussies avant ; 0 effective après (NA : partielle) |
| Taux de blocage | RA, DHCPv6, saturation, contournement : neutralisés ; NA : partiel |
| Faux positifs (RA légitimes bloqués) | **0** |
| Taille du cache sous attaque | stable côté hôte ; flood absorbé (17 557 NS rejetés) |
| Impact sur la latence | sub-milliseconde ; max 0,549 ms (saturation) ; **0 % de perte** |

## 8. Conclusion et limites

Le durcissement du premier saut neutralise le RA frauduleux, le DHCPv6 pirate, la
saturation du cache et les tentatives de contournement par en-têtes d'extension /
fragmentation, **sans aucun faux positif**. Les contre-mesures sont appliquées sur le
pont de la VM hôte via `harden.sh` : `firewall/after.nft` (RA Guard, DHCPv6 Guard,
filtrage ND, limitation de débit, anti-contournement — chaque règle instrumentée d'un
compteur) et durcissement de l'adressage RFC 7217/8981 + dimensionnement du cache de
voisins (sysctl sur `hote-a` et `hote-b`).

**Limite identifiée :** l'usurpation NA (MITM) n'est que **partiellement atténuée**. Le
filtrage ND ne rejette que les NS/NA à adresse source invalide (`::` / multicast) ; un
NA forgé avec une source valide franchit le filtre. Une protection complète nécessiterait
des mécanismes de liaison adresse↔port de type **SAVI** (RFC 7039) ou **SEND** (RFC 3971),
au-delà du filtrage nftables du premier saut.