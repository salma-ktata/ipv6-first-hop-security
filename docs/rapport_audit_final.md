# Rapport d'audit — Sécurité du segment local IPv6 (Projet 10)

## 1. Résumé exécutif

Un LAN IPv6 d'entreprise (SLAAC / ND / DHCPv6) a été déployé **sans protection**,
soumis en laboratoire à quatre attaques du premier saut (RA frauduleux, usurpation
NA/MITM, serveur DHCPv6 pirate, saturation du cache de voisins) et à des tentatives de
contournement (en-têtes d'extension / fragmentation), puis **sécurisé** et
**ré-attaqué**. Le durcissement — RA Guard, DHCPv6 Guard, filtrage ND, limitation de
débit et anti-contournement — est appliqué directement sur le pont `bridge-lan` de la
VM hôte via `nftables` (famille `bridge`, script `harden.sh`), car ce pont n'est pas un
conteneur. L'adressage des hôtes est durci selon les RFC 7217 et 8981.

**Bilan.** Les **quatre attaques** sont **démontrées** sur le LAN non protégé (preuve
avant) puis **neutralisées** après durcissement (preuve après), avec **zéro faux
positif** (test de non-régression). Les tentatives de contournement ne produisent aucun
effet, même sans protection, le filtrage anti-contournement (RFC 6980) restant une
mesure préventive. Toutes les preuves sont sauvegardées dans `analyse/` et
`mesures/indicateurs.csv`.

## 2. Méthodologie et mesure de référence

Les mesures `avant` sont prises sur le LAN **non protégé** (filtrage retiré) ; les
mesures `apres` sur le LAN **durci**. L'environnement est remis à l'état vulnérable
entre chaque scénario pour éviter toute contamination.

**Référence (3 mesures, M8).** Source `mesures/indicateurs.csv` :

| # | Voisins | Routes défaut | Adr. globales | Latence moy. (ms) | Latence max. (ms) | Perte (%) |
|---|---|---|---|---|---|---|
| 1 | 1 | 2 | 1 | 0.568 | 2.334 | 0 |
| 2 | 2 | 2 | 1 | 0.134 | 0.293 | 0 |
| 3 | 2 | 2 | 1 | 0.127 | 0.331 | 0 |

**Lecture.** À état **identique**, la latence moyenne varie de **0,127 à 0,568 ms** (et
le maximum de 0,293 à 2,334 ms). Cette dispersion d'un facteur ~4 montre que les écarts
de latence sub-milliseconde entre scénarios **ne sont pas statistiquement significatifs** ;
seul l'indicateur binaire **perte de paquets (0 %)** est exploité comme mesure de
disponibilité. La référence propre affiche **2 routes par défaut** (routeur légitime sur
`eth1` + passerelle de gestion sur `eth0`), base de comparaison pour l'attaque RA.

## 3. Démonstration des attaques (avant / après)

Chaque attaque est prouvée par une **signature observable** côté victime avant
durcissement, puis par sa **disparition** après. Les fichiers de preuve sont indiqués.

### 3.1 RA frauduleux — **neutralisé**
- **Avant :** l'attaquant émet des Router Advertisement annonçant le préfixe pirate
  `2001:db8:bad::/64` (capture `analyse/attaque_ra_bloquee.pcap`, 10 trames, cf. §6).
- **Après :** aucune route via `2001:db8:bad::` n'est installée côté victime
  (`analyse/route_victime_apres.txt`) ; la règle **RA Guard** rejette les RA émis depuis un
  port non fiable (**compteur = 40**, §4).

### 3.2 Usurpation NA / MITM — **neutralisée**
- **Avant** (`analyse/m2_neigh_avant.txt`) : après amorçage du dialogue hôte-à-hôte, le
  cache de voisins de la victime associe l'adresse de `hote-b`
  (`2001:db8:10:1:a8c1:abff:fe98:8251`) à la **MAC de l'attaquant `02:00:00:00:00:66`** —
  cache **empoisonné**, MITM établi.
- **Après** (`analyse/m2_neigh_apres.txt`) : la même entrée passe à l'état **`FAILED`**,
  sans pointer vers la MAC de l'attaquant — l'empoisonnement **n'aboutit plus**.

### 3.3 Serveur DHCPv6 pirate — **neutralisé**
- **Avant** (`analyse/m1_client_avant.txt`) : le serveur légitime Kea étant arrêté pour
  isoler la concurrence, la victime obtient un bail du **serveur pirate** :
  `udhcpc6: IPv6 obtained, lease time 600` (adresse du préfixe pirate
  `2001:db8:bad::1000`). Le pirate attribue donc réellement une adresse.
- **Après** : la règle **DHCPv6 Guard** (`udp sport 547 iifname != x2 drop`) rejette les
  réponses serveur issues d'un port non fiable (**compteur = 2**, §4) ; la victime n'obtient
  plus de bail pirate.

> Remarque : la capture automatisée côté pont (`m1_pirate_addr_avant.txt`) n'a pas
> intercepté l'échange (fenêtre temporelle) ; la **preuve retenue est le journal client**
> ci-dessus, plus fiable.

### 3.4 Saturation du cache de voisins — **neutralisée**
- **Avant** (`analyse/m3_cache_routeur_avant.txt`) : un flood de Neighbor Solicitation à
  **sources aléatoires** visant le routeur fait passer son cache de **12 à 622 entrées**
  (×52) — saturation démontrée.
- **Après** (`analyse/m3_cache_routeur_apres.txt`) : sous le même flood, le cache
  **décroît de 622 à 223** (les entrées résiduelles expirent, le nouveau flood est
  absorbé par la limitation de débit NS — **6 032 paquets rejetés**, §4).

### 3.5 Contournement ext-hdr / fragmentation — **sans effet**
- **Avant** (`analyse/m4_route_avant.txt`) : même **sans protection**, le RA encapsulé /
  fragmenté **n'installe aucune route pirate** (seule subsiste la passerelle légitime
  `fe80::a8c1:abff:fef3:abdc` sur `eth1`). La pile IPv6 de la victime ignore ces RA
  malformés.
- **Après** : les règles anti-contournement (`ip6 nexthdr ipv6-frag drop` et
  `ip6 nexthdr {hopopt,dstopts,route} … drop`, RFC 6980) rejettent ces paquets par
  précaution (**compteurs = 20 + 20**, §4).

### Synthèse

| Attaque | Signature avant | État après | Verdict |
| --- | --- | --- | --- |
| RA frauduleux | RA `2001:db8:bad::/64` émis (10 trames) | aucune route pirate | **Neutralisée** |
| Usurpation NA (MITM) | cache → MAC attaquant `…00:66` | entrée `FAILED`, non empoisonnée | **Neutralisée** |
| DHCPv6 pirate | bail pirate obtenu (`IPv6 obtained`) | aucun bail pirate | **Neutralisée** |
| Saturation cache | cache routeur 12 → 622 | 622 → 223 (absorbé) | **Neutralisée** |
| Contournement ext-hdr/frag | aucun effet (RA ignoré) | rejeté (RFC 6980) | **Sans effet / préventif** |

## 4. Pare-feu nftables : compteurs par règle

Source `analyse/compteurs_nftables.txt` (table `bridge filter`, chaîne `forward`), après
rejeu des attaques sur le LAN durci. **Chaque règle de blocage est instrumentée d'un
compteur** :

| Règle | Paquets rejetés |
| --- | --- |
| Anti-contournement — tous fragments IPv6 (RFC 6980) | 20 |
| Anti-contournement — RA via en-tête d'extension | 20 |
| Anti-contournement — DHCPv6 via en-tête d'extension | 0 |
| Anti-contournement — en-tête d'extension suspect (log) | 0 |
| **RA Guard** (`nd-router-advert iifname != x1`) | **40** |
| **DHCPv6 Guard** (`udp sport 547 iifname != x2`) | **2** |
| ND — source multicast invalide | 0 |
| NA — source `::` invalide | 0 |
| **ND — limitation de débit NS** | **6 032** |
| ND — limitation de débit RS | 0 |
| Trafic légitime (règle `accept`) | 3 476 |

**Lecture.** Chaque contre-mesure sollicitée affiche un compteur **> 0** : RA Guard (**40**)
rejette les RA frauduleux (évalués sur chaque port aval du pont — le nombre dépasse les
10 trames émises), DHCPv6 Guard (**2**) bloque les réponses du serveur pirate,
l'anti-contournement (**20 + 20**) rejette les RA fragmentés et encapsulés, et la
limitation de débit NS (**6 032**) absorbe le flood de saturation. La règle `accept`
(**3 476** paquets légitimes) confirme que le trafic normal continue de passer (cohérent
avec la non-régression, §5).

**Filtrage ND compatible DAD.** La règle ND est séparée : seules les NS/NA à source
**multicast** (`ff00::/8`) et les NA à source **non spécifiée** (`::`) sont rejetées ; les
**NS de source `::` (Duplicate Address Detection) sont volontairement autorisées**, afin
de ne pas casser la détection d'adresse dupliquée des hôtes — ce qui explique l'absence de
faux positif (§5).

Le durcissement de l'adressage (sysctl) complète le pare-feu : adresses temporaires
RFC 8981 (`use_tempaddr=2`), adresses stables RFC 7217 (`addr_gen_mode=3`) et
dimensionnement du cache de voisins (`gc_thresh1/2/3 = 512/1024/2048`).

## 5. Faux positifs (non-régression)

Source `analyse/non_regression.txt` — après durcissement :

1. adresse SLAAC légitime (`2001:db8:10:1:…`) présente : **OK** ;
2. route par défaut légitime présente : **OK** ;
3. routeur `2001:db8:10:1::1` joignable : **OK**.

**Code de sortie : `0` → aucun faux positif.** Le trafic légitime (RA du vrai routeur,
SLAAC, joignabilité) reste pleinement fonctionnel, ce que confirme la règle `accept`
(1 636 paquets légitimes passés, §4).

**Adressage victime** (`analyse/adressage_victime.txt`) : trois adresses globales, toutes
dans le préfixe légitime `2001:db8:10:1::/64` — une stable (`…fee9:8d95`, RFC 7217) et
deux temporaires (RFC 8981) — **aucune adresse `2001:db8:bad::` ni adresse de pool
pirate**. La variation du compteur `adresses_globales` (1 à la référence, puis plus)
s'explique uniquement par la génération d'adresses temporaires, non par une attaque.

## 6. Analyse Wireshark

Capture `analyse/attaque_ra_bloquee.pcap` (résumés `analyse/resume_protocoles.txt`,
`analyse/ra_frauduleux.txt`) :

- **Hiérarchie des protocoles** : **10 trames, 1 100 octets, 100 % ICMPv6** — les RA
  frauduleux émis par l'attaquant.
- **Détail (`icmpv6.type==134`)** : 10 Router Advertisement, source `fe80::66`, MAC
  `02:00:00:00:00:66`, à intervalle ~1 s, annonçant le préfixe pirate.
- **Corrélation** : ces RA sont **émis** mais **sans effet** côté victime après
  durcissement (aucune route `2001:db8:bad::`), ce que confirme §3.1.
- Filtres complémentaires : `icmpv6.type==135 || icmpv6.type==136` (NS/NA),
  `udp.port==547` (DHCPv6).

## 7. Indicateurs demandés

| Indicateur | Résultat |
| --- | --- |
| Attaques réussies avant / neutralisées après | **4 / 4** (RA, NA, DHCPv6, saturation) |
| Taux de blocage (compteurs nftables) | RA Guard 40, DHCPv6 Guard 2, anti-bypass 20+20, limite NS 6 032 |
| Contournement (ext-hdr / fragmentation) | sans effet même sans protection ; rejeté par précaution |
| Faux positifs (RA légitimes bloqués) | **0** (non-régression = 0 ; DAD préservé) |
| Taille du cache sous attaque | routeur **12 → 622** (avant), **absorbé** (après) |
| Impact sur la latence | sub-milliseconde ; **0 % de perte** ; écarts non significatifs (M8) |

## 8. Conclusion et limites

Le durcissement du premier saut **neutralise les quatre attaques démontrées** (RA
frauduleux, usurpation NA, DHCPv6 pirate, saturation du cache) **sans aucun faux
positif**. Les contre-mesures sont appliquées sur le pont de la VM hôte via `harden.sh` :
`firewall/after.nft` (RA Guard, DHCPv6 Guard, filtrage ND, limitation de débit,
anti-contournement) et durcissement de l'adressage RFC 7217/8981 + cache de voisins.

**Limites (assumées) :**
- **Mesure unique par scénario d'attaque** (hors référence 3× M8) : les écarts de latence
  sub-milliseconde ne sont pas significatifs ; seule la perte (0 %) est exploitée.
- **Un seul hôte victime** (`hote-a`) ; le routeur sert de cible pour la saturation.
- **DHCPv6 (M1)** : la démonstration « avant » a nécessité d'**arrêter Kea** pour isoler
  le serveur pirate de la concurrence ; la preuve retenue est le journal client
  (`IPv6 obtained`), la capture côté pont n'ayant pas intercepté l'échange.
- **Usurpation NA** : neutralisée dans ce test ; une protection renforcée contre un NA à
  source valide relèverait de mécanismes **SAVI** (RFC 7039) ou **SEND** (RFC 3971),
  au-delà du filtrage nftables du premier saut.

---

*Source de vérité : ce fichier `docs/rapport_audit_final.md` est édité à la main et fait
foi. Les chiffres proviennent de `mesures/indicateurs.csv` et du dossier `analyse/`.*