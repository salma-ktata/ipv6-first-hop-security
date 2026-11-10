# Ansible — déploiement de la base vulnérable

Ces playbooks automatisent **uniquement** le déploiement du LAN IPv6 **vulnérable**
(radvd + FRR sur le routeur, Kea sur le serveur DHCPv6). Le **durcissement** (RA Guard,
DHCPv6 Guard, filtrage ND, sysctl) se fait avec **`harden.sh`** à la racine du dépôt,
pas via Ansible — `bridge-lan` n'étant pas un conteneur.

## Prérequis
- Pont `bridge-lan` + topologie déjà déployés (voir le README racine).
- Collections : `ansible-galaxy collection install -r requirements.yml`

## Utilisation
    sudo python3 deploy.py vulnerable     # deploie radvd / FRR / Kea (base vulnerable)
    sudo python3 deploy.py check          # dry-run (--check --diff), ne modifie rien

## Contenu
- `inventory/hosts.yml` — routeur, dhcp6, hôtes (connexion Docker).
- `site.yml` — plays Phase 1 (rôles `radvd`, `frr`, `kea`).
- `roles/radvd`, `roles/frr`, `roles/kea` — installation + configuration des services.

> Les rôles de durcissement (`firewall_after`, `firewall_before`, `hardening`) ont été
> retirés : cette partie est gérée par `harden.sh`.