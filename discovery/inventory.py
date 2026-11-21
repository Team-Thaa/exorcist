"""Build a passive device inventory from Zeek connection metadata."""

from __future__ import annotations

import ipaddress
import json
import re
import warnings
from pathlib import Path
from typing import Callable, Iterable, Iterator

from .audit import audit_device

_MAC_PATTERN = re.compile(r"(?i)^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$")
_RESPONDED_STATES = {"SF", "S1", "S2", "S3", "SH"}
_UNANSWERED_STATES = {"S0", "REJ", "OTH"}


def read_conn_log(path: str | Path) -> Iterator[dict]:
    """Read Zeek JSON connection rows, ignoring Zeek's comment/header lines."""
    with open(path, encoding="utf-8") as log:
        for line_number, line in enumerate(log, start=1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
            if not isinstance(row, dict):
                raise ValueError(f"{path}:{line_number}: expected a JSON object")
            yield row


def read_arp_table(path: str | Path = "/proc/net/arp") -> dict[str, str]:
    """Read the Linux neighbor cache without sending packets to any device."""
    table = {}
    try:
        with open(path, encoding="utf-8") as arp:
            next(arp, None)
            for line in arp:
                parts = line.split()
                if len(parts) >= 4 and _valid_mac(parts[3]):
                    table[parts[0]] = parts[3].lower()
    except FileNotFoundError:
        warnings.warn(f"ARP table not available at {path}; using Zeek MACs or IP fallbacks")
    return table


def _valid_mac(value: object) -> bool:
    return (
        isinstance(value, str)
        and _MAC_PATTERN.fullmatch(value) is not None
        and value.lower() != "00:00:00:00:00:00"
    )


def _mac_for(ip: str, zeek_mac: object, arp_table: dict[str, str]) -> str:
    if _valid_mac(zeek_mac):
        return zeek_mac.lower()
    arp_mac = arp_table.get(ip)
    return arp_mac.lower() if _valid_mac(arp_mac) else f"ip:{ip}"


def _is_lan_ip(value: object, network: ipaddress.IPv4Network) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        return False
    return isinstance(address, ipaddress.IPv4Address) and address in network


def _responded(row: dict) -> bool:
    if row.get("conn_state") in _RESPONDED_STATES:
        return True
    try:
        return int(row.get("resp_bytes", 0)) > 0
    except (TypeError, ValueError):
        return False


def _answered(row: dict) -> bool:
    """True if the destination showed any sign of life, so it can be recorded as a device.
    Unanswered attempts (a scan of empty addresses) must not invent devices."""
    if row.get("conn_state") not in _UNANSWERED_STATES:
        return True
    try:
        return int(row.get("resp_bytes", 0)) > 0
    except (TypeError, ValueError):
        return False


def discover_devices(
    rows: Iterable[dict],
    lan_cidr: str = "192.168.50.0/24",
    arp_table: dict[str, str] | None = None,
    gateway_ip: str = "192.168.50.1",
    decoy_ip: str = "192.168.50.99",
    mac_lookup: Callable[[str, object, dict[str, str]], str] = _mac_for,
) -> list[dict]:
    """Inventory LAN devices and observed inbound services from Zeek conn rows.

    Only endpoints inside ``lan_cidr`` are considered. A destination port is
    recorded as a service for that endpoint only when the connection shows a
    response; this is passive evidence, not a complete port scan.
    """
    try:
        network = ipaddress.ip_network(lan_cidr, strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid LAN_CIDR: {lan_cidr}") from exc
    if not isinstance(network, ipaddress.IPv4Network):
        raise ValueError("LAN_CIDR must be an IPv4 network")

    excluded = {gateway_ip, decoy_ip}
    arp = arp_table or {}
    devices: dict[str, dict] = {}

    def observe(ip: str, zeek_mac: object, timestamp: float) -> dict | None:
        if ip in excluded or not _is_lan_ip(ip, network):
            return None
        mac = mac_lookup(ip, zeek_mac, arp)
        fallback_mac = f"ip:{ip}"
        if mac != fallback_mac and fallback_mac in devices:
            fallback = devices.pop(fallback_mac)
            existing = devices.get(mac)
            if existing is None:
                fallback["mac"] = mac
                devices[mac] = fallback
            else:
                existing["ports"].update(fallback["ports"])
                if fallback["last_seen"] > existing["last_seen"]:
                    existing["ip"] = fallback["ip"]
                    existing["last_seen"] = fallback["last_seen"]
        device = devices.get(mac)
        if device is None:
            device = {"mac": mac, "ip": ip, "ports": set(), "last_seen": timestamp}
            devices[mac] = device
        elif timestamp >= device["last_seen"]:
            device["ip"] = ip
            device["last_seen"] = timestamp
        return device

    for row in rows:
        if not isinstance(row, dict):
            raise ValueError("each Zeek connection row must be a JSON object")
        origin_ip, responder_ip = row.get("id.orig_h"), row.get("id.resp_h")
        if not isinstance(origin_ip, str) or not isinstance(responder_ip, str):
            raise ValueError("Zeek connection row is missing id.orig_h or id.resp_h")
        try:
            timestamp = float(row.get("ts", 0))
        except (TypeError, ValueError):
            timestamp = 0

        observe(origin_ip, row.get("orig_l2_addr"), timestamp)
        responder = observe(responder_ip, None, timestamp) if _answered(row) else None
        if responder is not None and _responded(row):
            port = row.get("id.resp_p")
            if isinstance(port, int) and 0 < port <= 65535:
                responder["ports"].add(port)

    result = []
    for device in devices.values():
        record = audit_device(device["ip"], device["mac"], sorted(device["ports"]))
        record["explanation"] = (
            f"Exposure score {record['exposure_score']}/100 from "
            f"{len(record['open_ports'])} LAN service(s) observed responding in Zeek logs. "
            "This is passive evidence, not a complete port scan; firmware and "
            "internet reachability were not tested. Infection status is determined "
            "separately by the detection engine."
        )
        result.append(record)
    return sorted(result, key=lambda device: (device["ip"], device["mac"]))
