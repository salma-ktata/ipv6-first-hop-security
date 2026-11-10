#!/usr/bin/env bash
set -euo pipefail

BRIDGE="${1:-bridge-lan}"

if ! ip link show dev "$BRIDGE" >/dev/null 2>&1; then
    ip link add name "$BRIDGE" type bridge
fi

ip link set dev "$BRIDGE" up

echo "Bridge successfully prepared:"
ip -d link show dev "$BRIDGE"
