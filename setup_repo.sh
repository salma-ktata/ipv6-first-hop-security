#!/usr/bin/env bash
set -euo pipefail
REPO_URL="${1:?Usage: ./setup_repo.sh <url-git-du-depot>}"
echo "== Dépendances système (Debian/Ubuntu) =="
sudo apt update
sudo apt install -y git nftables python3-pip python3-scapy tcpdump \
	tshark wireshark \
	frr radvd thc-ipv6 \
	kea-dhcp-ddns-server kea-dhcp6-server kea-common || true
pip3 install --user scapy
# tshark/wireshark packaging asks interactively whether non-root users can
# capture packets; pre-seed "yes" so the install above doesn't hang.

echo "wireshark-common wireshark-common/install-setuid boolean true" | sudo
debconf-set-selections 2>/dev/null || true
sudo dpkg-reconfigure -f noninteractive wireshark-common 2>/dev/null || true
sudo usermod -aG wireshark "$USER" 2>/dev/null || true
echo "== Vérification Kea =="
command -v kea-dhcp6 >/dev/null && echo "Kea DHCPv6 installé." || \
echo "ATTENTION : kea-dhcp6 introuvable — vérifiez le nom du paquet pour
votre distro."
echo "== Containerlab =="
if ! command -v containerlab >/dev/null; then
bash -c "$(curl -sL https://get.containerlab.dev)"
fi
echo "== Clonage du dépôt =="
git clone "$REPO_URL"
cd "$(basename "$REPO_URL" .git)"
echo "== Vérification des prérequis noyau =="
if [ ! -d /proc/sys/net/ipv6 ]; then
echo "ATTENTION : IPv6 semble désactivé sur ce noyau."
fi
lsmod | grep -q br_netfilter || echo "ATTENTION : modprobe br_netfilter
requis pour nftables famille bridge."
echo "Prêt. Démarrer la topologie avec : sudo containerlab deploy -t
topo/topo.clab.yml"
