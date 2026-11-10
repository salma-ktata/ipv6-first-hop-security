
"""Shared helpers for the isolated Containerlab experiments."""

import ipaddress
import re
import subprocess

from scapy.all import get_if_hwaddr

LAB_INTERFACE = "eth1"


def add_lab_guard(parser):
    parser.add_argument(
        "--iface",
        default=LAB_INTERFACE,
        help="Lab interface (restricted to eth1)",
    )

    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="Confirm execution inside the isolated Containerlab",
    )


def require_lab_interface(parser, iface, confirmed):
    if not confirmed:
        parser.error(
            "Pass --confirm-isolated-lab only inside the isolated lab"
        )

    if iface != LAB_INTERFACE:
        parser.error("This script is restricted to interface eth1")

    try:
        mac = get_if_hwaddr(iface)
        validate_mac(mac, "interface MAC")
    except Exception as exc:
        parser.error(f"Cannot read interface MAC: {exc}")

    return mac.lower()


def get_link_local_ipv6(iface):
    """Return the link-local IPv6 address assigned to an interface."""

    result = subprocess.run(
        ["ip", "-6", "-o", "addr", "show", "dev", iface, "scope", "link"],
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip())

    candidates = re.findall(
        r"\binet6\s+([0-9a-fA-F:]+)/\d+\b",
        result.stdout,
    )

    for candidate in candidates:
        address = ipaddress.IPv6Address(candidate)

        if address.is_link_local:
            return str(address)

    raise RuntimeError(
        f"No link-local IPv6 address configured on {iface}"
    )


def validate_mac(value, label="MAC address"):
    """Validate a unicast Ethernet MAC address."""

    if not re.fullmatch(
        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}",
        value,
    ):
        raise ValueError(f"Invalid {label}: {value!r}")

    first_octet = int(value.split(":")[0], 16)

    if first_octet & 1:
        raise ValueError(f"{label} must be unicast")

    return value.lower()
