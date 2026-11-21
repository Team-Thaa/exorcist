import pytest

from discovery.audit import audit_device
from discovery import scanner


def test_audit_scores_reachable_risky_services_and_infers_camera():
    device = audit_device("192.168.1.20", "aa:bb:cc:dd:ee:ff", [554, 23, 554])

    assert device["open_ports"] == [23, 554]
    assert device["type"] == "camera"
    assert device["exposure_score"] == 65
    assert device["status"] == "at_risk"
    assert len(device["findings"]) == 2
    assert device["mac"] == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize(
    "network",
    ["8.8.8.0/24", "192.168.0.0/16", "2001:db8::/64", "not-a-network"],
)
def test_scan_rejects_non_private_or_oversized_networks(network):
    with pytest.raises(ValueError):
        scanner.scan_network(network)


def test_scan_only_returns_hosts_with_open_ports(monkeypatch):
    monkeypatch.setattr(
        scanner,
        "_probe_host",
        lambda ip, timeout: [80] if ip == "192.168.1.2" else [],
    )
    monkeypatch.setattr(scanner, "_mac_for", lambda ip: "aa:bb:cc:dd:ee:ff")

    devices = scanner.scan_network("192.168.1.0/30")

    assert len(devices) == 1
    assert devices[0]["ip"] == "192.168.1.2"
    assert devices[0]["open_ports"] == [80]
    assert devices[0]["status"] == "safe"
