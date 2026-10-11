#!/bin/sh
set -eu

PHASE="${1:?usage: collect_metrics.sh <avant|apres> <scenario>}"
SCENARIO="${2:?usage: collect_metrics.sh <avant|apres> <scenario>}"
IFACE="${IFACE:-eth1}"
CSV="$(dirname "$0")/indicateurs.csv"

if [ ! -f "$CSV" ]; then
    echo "horodatage,phase,scenario,taille_cache_voisins,entrees_incomplete,latence_ms,compteurs_nftables" > "$CSV"
fi

TS="$(date -Iseconds)"

CACHE_SIZE=$(ip -6 neigh show dev "$IFACE" 2>/dev/null | wc -l || echo 0)
INCOMPLETE=$(ip -6 neigh show dev "$IFACE" 2>/dev/null | grep -c INCOMPLETE || echo 0)

ROUTER_ADDR="${ROUTER_ADDR:-2001:db8:10:1::1}"
LATENCY=$(ping6 -c 5 -q "$ROUTER_ADDR" 2>/dev/null \
    | awk -F'/' '/min\/avg\/max/ {print $5}' || echo "NA")

COUNTERS=$(nft -a list table bridge filter 2>/dev/null \
    | grep -oE 'comment "[^"]+".*counter packets [0-9]+' \
    | awk -F'packets ' '{print $2}' | paste -sd ';' - || echo "NA")

echo "${TS},${PHASE},${SCENARIO},${CACHE_SIZE},${INCOMPLETE},${LATENCY},\"${COUNTERS}\"" >> "$CSV"

echo "Mesure enregistree: phase=${PHASE} scenario=${SCENARIO} cache=${CACHE_SIZE} incomplete=${INCOMPLETE} latence=${LATENCY}ms"
