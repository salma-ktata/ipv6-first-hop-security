
#!/usr/bin/env bash

set -euo pipefail

PHASE="${1:?Usage: collect_firewall_counters.sh <avant|apres> <scenario>}"
SCENARIO="${2:?Scenario required}"

OUT="${OUT:-mesures/firewall_counters.csv}"

mkdir -p "$(dirname "$OUT")"

if [ ! -s "$OUT" ]; then
    echo "timestamp,phase,scenario,rule,packets,bytes" > "$OUT"
fi

nft -j list table bridge ipv6_fhs |
python3 -c '
import csv
import datetime
import json
import sys

data = json.load(sys.stdin)
timestamp = datetime.datetime.now().astimezone().isoformat()

phase = sys.argv[1]
scenario = sys.argv[2]

writer = csv.writer(sys.stdout)

for item in data.get("nftables", []):
    rule = item.get("rule")

    if not rule:
        continue

    comment = rule.get("comment", "unnamed")

    packets = 0
    byte_count = 0

    for expression in rule.get("expr", []):
        counter = expression.get("counter", {})

        packets += counter.get("packets", 0)
        byte_count += counter.get("bytes", 0)

    writer.writerow([
        timestamp,
        phase,
        scenario,
        comment,
        packets,
        byte_count
    ])
' "$PHASE" "$SCENARIO" >> "$OUT"

echo "Firewall counters collected in $OUT"
