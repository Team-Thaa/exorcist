"""Conservative TCP discovery for explicitly supplied private IPv4 subnets."""

import concurrent.futures
import ipaddress
import re
import socket
import subprocess

from .audit import audit_device

SCAN_PORTS = (22, 23, 53, 80, 443, 554, 8080, 8443)
_PRIVATE_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_MAC_PATTERN = re.compile(r"(?i)(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")


def _validated_network(value: str) -> ipaddress.IPv4Network:
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid network: {value}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("only private IPv4 networks are supported")
    if not any(network.subnet_of(private) for private in _PRIVATE_RANGES):
        raise ValueError("scan only an authorized RFC 1918 private IPv4 network")
    if network.prefixlen < 24:
        raise ValueError("network must be /24 or smaller to limit scan scope")
    return network


def _probe_host(ip: str, timeout: float) -> list[int]:
    open_ports = []
    for port in SCAN_PORTS:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.append(port)
        except (OSError, TimeoutError):
            continue
    return open_ports


def _mac_for(ip: str) -> str:
    """Read the neighbor cache populated by the local TCP connection probes."""
    for command in (("ip", "neigh", "show", ip), ("arp", "-n", ip)):
        try:
            result = subprocess.run(
                command, capture_output=True, text=True, check=False, timeout=1
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        match = _MAC_PATTERN.search(result.stdout)
        if match:
            return match.group(0).lower()
    return f"ip:{ip}"


def scan_network(network: str, timeout: float = 0.25) -> list[dict]:
    """Find hosts with a reachable common service and audit their exposure.

    The scan is limited to RFC 1918 /24-or-smaller ranges and only attempts
    TCP connections to the small, fixed list in ``SCAN_PORTS``.
    """
    subnet = _validated_network(network)
    if not 0.05 <= timeout <= 2:
        raise ValueError("timeout must be between 0.05 and 2 seconds")

    hosts = [str(address) for address in subnet.hosts()]
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as executor:
        results = executor.map(lambda ip: (ip, _probe_host(ip, timeout)), hosts)
        devices = [
            audit_device(ip, _mac_for(ip), ports)
            for ip, ports in results
            if ports
        ]
    return devices
