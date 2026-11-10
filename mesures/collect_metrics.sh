#!/bin/sh
# mesures/collect_metrics.sh — collecteur d'indicateurs (CSV clair)
# Usage : sudo ./mesures/collect_metrics.sh <avant|apres> <scenario>
set -u

PHASE="${1:-avant}"
SCENARIO="${2:-reference}"
VICTIM="${VICTIM:-clab-projet10-ipv6-hote-a}"
ROUTER="${ROUTER:-2001:db8:10:1::1}"
IFACE="${IFACE:-eth1}"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
CSV="$SCRIPT_DIR/indicateurs.csv"

NEIGH=$(docker exec "$VICTIM" ip -6 neigh show dev "$IFACE" 2>/dev/null | grep -c . || echo 0)
ROUTES_DEF=$(docker exec "$VICTIM" ip -6 route show default 2>/dev/null | grep -c . || echo 0)
ADDR_GLOB=$(docker exec "$VICTIM" ip -6 addr show dev "$IFACE" scope global 2>/dev/null | grep -c 'inet6' || echo 0)

PING=$(docker exec "$VICTIM" ping6 -c 5 -i 0.2 -w 5 "$ROUTER" 2>/dev/null)
LOSS=$(printf '%s\n' "$PING" | sed -n 's/.*[^0-9]\([0-9]*\)% packet loss.*/\1/p' | head -n1)
STATS=$(printf '%s\n' "$PING" | grep -E 'rtt|round-trip' | sed 's#.*= ##; s# ms##')
LAT_AVG=$(printf '%s\n' "$STATS" | cut -d/ -f2)
LAT_MAX=$(printf '%s\n' "$STATS" | cut -d/ -f3)
[ -z "$LOSS" ] && LOSS=100
[ -z "$LAT_AVG" ] && LAT_AVG=NA
[ -z "$LAT_MAX" ] && LAT_MAX=NA

TS=$(date '+%Y-%m-%d %H:%M:%S')

if [ ! -f "$CSV" ]; then
  echo "horodatage,phase,scenario,voisins_cache,routes_defaut,adresses_globales,latence_moy_ms,latence_max_ms,perte_pct" > "$CSV"
fi
echo "$TS,$PHASE,$SCENARIO,$NEIGH,$ROUTES_DEF,$ADDR_GLOB,$LAT_AVG,$LAT_MAX,$LOSS" >> "$CSV"

echo "----------------------------------------------------------------"
echo " Mesure enregistree : phase=$PHASE  scenario=$SCENARIO"
echo "   voisins (cache ND) ....... $NEIGH"
echo "   routes par defaut ........ $ROUTES_DEF   (>1 => RA pirate accepte)"
echo "   adresses globales ........ $ADDR_GLOB    (>1 => prefixe pirate accepte)"
echo "   latence moy / max (ms) ... $LAT_AVG / $LAT_MAX"
echo "   perte paquets (%) ........ $LOSS"
echo "   -> $CSV"
echo "----------------------------------------------------------------"
