import json

import pytest

from discovery.audit import audit_device
from discovery.inventory import discover_devices, read_conn_log, read_arp_table


def test_audit_scores_observed_risky_services_and_infers_camera():
    device = audit_device("192.168.50.20", "aa:bb:cc:dd:ee:ff", [554, 23, 554])

    assert device["open_ports"] == [23, 554]
    assert device["type"] == "camera"
    assert device["exposure_score"] == 65
    assert "status" not in device
    assert len(device["findings"]) == 2
    assert device["mac"] == "aa:bb:cc:dd:ee:ff"


def conn(origin, responder, port, *, state="SF", resp_bytes=1, ts=1, mac=None):
    row = {
        "ts": ts,
        "id.orig_h": origin,
        "id.resp_h": responder,
        "id.resp_p": port,
        "conn_state": state,
        "resp_bytes": resp_bytes,
    }
    if mac:
        row["orig_l2_addr"] = mac
    return row


def test_inventory_uses_zeek_mac_and_only_records_observed_responder_services():
    rows = [
        conn("192.168.50.23", "192.168.50.24", 554, mac="AA:BB:CC:00:00:23"),
        conn("192.168.50.24", "8.8.8.8", 443, mac="aa:bb:cc:00:00:24"),
        conn("192.168.50.25", "192.168.50.24", 23, state="S0", resp_bytes=0),
    ]

    devices = discover_devices(rows, arp_table={"192.168.50.24": "aa:bb:cc:00:00:24"})

    by_mac = {device["mac"]: device for device in devices}
    assert by_mac["aa:bb:cc:00:00:23"]["ip"] == "192.168.50.23"
    assert by_mac["aa:bb:cc:00:00:23"]["open_ports"] == []
    assert by_mac["aa:bb:cc:00:00:24"]["open_ports"] == [554]
    assert by_mac["aa:bb:cc:00:00:24"]["type"] == "camera"


def test_inventory_filters_gateway_decoy_and_external_addresses():
    rows = [
        conn("192.168.50.1", "8.8.8.8", 443, mac="aa:bb:cc:00:00:01"),
        conn("192.168.50.99", "192.168.50.23", 23, mac="aa:bb:cc:00:00:99"),
        conn("8.8.8.8", "192.168.50.23", 80, mac="aa:bb:cc:00:00:88"),
        conn("192.168.50.23", "1.1.1.1", 443, mac="aa:bb:cc:00:00:23"),
    ]

    devices = discover_devices(rows)

    assert [device["mac"] for device in devices] == ["aa:bb:cc:00:00:23"]


def test_inventory_tracks_device_by_mac_when_ip_changes():
    rows = [
        conn("192.168.50.23", "8.8.8.8", 443, ts=1, mac="aa:bb:cc:00:00:23"),
        conn("192.168.50.42", "8.8.8.8", 443, ts=2, mac="aa:bb:cc:00:00:23"),
    ]

    devices = discover_devices(rows)

    assert len(devices) == 1
    assert devices[0]["mac"] == "aa:bb:cc:00:00:23"
    assert devices[0]["ip"] == "192.168.50.42"


def test_inventory_merges_ip_fallback_when_zeek_mac_is_seen_later():
    rows = [
        conn("192.168.50.23", "192.168.50.24", 554, ts=1, mac="aa:bb:cc:00:00:23"),
        conn("192.168.50.24", "8.8.8.8", 443, ts=2, mac="aa:bb:cc:00:00:24"),
    ]

    devices = discover_devices(rows)

    assert len(devices) == 2
    assert {device["mac"] for device in devices} == {
        "aa:bb:cc:00:00:23",
        "aa:bb:cc:00:00:24",
    }
    assert next(device for device in devices if device["mac"].endswith(":24"))["open_ports"] == [554]


def test_inventory_uses_ip_fallback_without_zeek_mac_or_arp():
    devices = discover_devices([conn("192.168.50.23", "8.8.8.8", 443)])

    assert devices[0]["mac"] == "ip:192.168.50.23"


def test_log_reader_skips_zeek_headers_and_errors_on_invalid_json(tmp_path):
    log_path = tmp_path / "conn.log"
    row = conn("192.168.50.23", "8.8.8.8", 443, mac="aa:bb:cc:00:00:23")
    log_path.write_text("#separator \\x09\n" + json.dumps(row) + "\n")

    assert list(read_conn_log(log_path)) == [row]

    log_path.write_text("{invalid}\n")
    with pytest.raises(ValueError, match="conn.log:1: invalid JSON"):
        list(read_conn_log(log_path))


def test_arp_reader_uses_only_valid_mac_rows(tmp_path):
    arp_path = tmp_path / "arp"
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.50.23 0x1 0x2 aa:bb:cc:00:00:23 * br-lan\n"
        "192.168.50.24 0x1 0x0 00:00:00:00:00:00 * br-lan\n"
    )

    assert read_arp_table(arp_path) == {"192.168.50.23": "aa:bb:cc:00:00:23"}


@pytest.mark.parametrize("network", ["not-a-network", "2001:db8::/64"])
def test_inventory_rejects_invalid_lan_cidr(network):
    with pytest.raises(ValueError):
        discover_devices([], lan_cidr=network)
