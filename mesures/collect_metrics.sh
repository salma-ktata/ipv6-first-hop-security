
#!/usr/bin/env bash

set -euo pipefail

PHASE="${1:?Usage: collect_metrics.sh <avant|apres> <scenario>}"
SCENARIO="${2:?Scenario required}"

IFACE="${IFACE:-eth1}"
PING_TARGET="${PING_TARGET:-2001:db8:10:1::1}"
NODE="${NODE:-$(hostname)}"

CSV="${CSV:-$(dirname "$0")/indicateurs.csv}"

mkdir -p "$(dirname "$CSV")"

if [ ! -s "$CSV" ]; then
    echo "timestamp,phase,scenario,node,interface,neighbor_entries,incomplete_entries,ping_avg_ms" > "$CSV"
fi

TIMESTAMP="$(date -Iseconds)"

# Neighbor-cache measurements
NEIGHBORS="$(ip -6 neigh show dev "$IFACE" 2>/dev/null || true)"

TOTAL="$(printf '%s\n' "$NEIGHBORS" |
    awk 'NF {n++} END {print n+0}')"

INCOMPLETE="$(printf '%s\n' "$NEIGHBORS" |
    awk '$NF == "INCOMPLETE" {n++} END {print n+0}')"

# Connectivity measurement
PING_OUTPUT="$(ping -6 -c 3 -W 1 "$PING_TARGET" 2>&1 || true)"

PING_AVG="$(printf '%s\n' "$PING_OUTPUT" |
    sed -nE 's/.* = [0-9.]+\/([0-9.]+)\/.*/\1/p' |
    tail -n 1)"

if [ -z "$PING_AVG" ]; then
    PING_AVG="NA"
fi

# CSV output
printf '"%s","%s","%s","%s","%s",%s,%s,%s\n' \
    "$TIMESTAMP" \
    "$PHASE" \
    "$SCENARIO" \
    "$NODE" \
    "$IFACE" \
    "$TOTAL" \
    "$INCOMPLETE" \
    "$PING_AVG" >> "$CSV"

echo "Measurement completed"
echo "Phase: $PHASE"
echo "Scenario: $SCENARIO"
echo "Node: $NODE"
echo "Neighbor entries: $TOTAL"
echo "Incomplete entries: $INCOMPLETE"
echo "Average latency: $PING_AVG ms"
