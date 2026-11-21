"""Tests with synthetic Zeek rows, so the engine can be checked without the lab.
Run: python -m pytest -q
"""
import asyncio
import os
import socket
import threading
import time

os.environ.setdefault("DECOY_IP", "127.0.0.2")
os.environ.setdefault("ALERT_FILE", "/tmp/test_alerts.jsonl")
os.environ.setdefault("API_URL", "http://127.0.0.1:9")   # nothing listening: alerts saved locally

import pytest
from engine import config, detectors
from engine.detectors import (Beaconing, FanOut, LanScan, RiskyProtocol, SuspiciousDNS,
                              ThreatIntel)
from engine.scoring import Scorer

CAM = "192.168.50.23"
T0 = 1_700_000_000.0


@pytest.fixture(autouse=True)
def reset_cooldown():
    detectors.cooldown.last.clear()


def conn(dst, port=80, ts=T0, src=CAM):
    return {"ts": ts, "id.orig_h": src, "id.resp_h": dst, "id.resp_p": port,
            "proto": "tcp", "conn_state": "S0", "orig_l2_addr": "aa:bb:cc:00:00:23"}


def run(det, rows):
    out = []
    for r in rows:
        out += det.on_conn(r)
    return out


def test_lan_scan_fires_on_telnet_sweep():
    rows = [conn(f"192.168.50.{100 + i}", 23, T0 + i) for i in range(12)]
    alerts = run(LanScan(), rows)
    assert len(alerts) == 1 and alerts[0]["type"] == "lan_scan"
    assert alerts[0]["mac"] == "aa:bb:cc:00:00:23"


def test_lan_scan_ignores_normal_web_traffic():
    rows = [conn(f"192.168.50.{100 + i}", 80, T0 + i) for i in range(30)]
    assert run(LanScan(), rows) == []


def test_beaconing_fires_on_steady_rhythm():
    rows = [conn("10.66.0.10", 443, T0 + 30 * i + (0.3 if i % 2 else -0.2)) for i in range(8)]
    alerts = run(Beaconing(), rows)
    assert alerts and alerts[0]["type"] == "beaconing" and "every 30s" in alerts[0]["evidence"]


def test_beaconing_ignores_irregular_traffic():
    gaps = [3, 45, 12, 90, 7, 33, 61, 5]
    t, rows = T0, []
    for g in gaps:
        t += g
        rows.append(conn("142.250.1.1", 443, t))
    assert run(Beaconing(), rows) == []


def test_fanout_fires_on_ddos_pattern():
    rows = [conn(f"8.{i // 250}.{i % 250}.1", 80, T0 + i * 0.1) for i in range(120)]
    alerts = run(FanOut(), rows)
    assert alerts and alerts[0]["type"] == "fanout"


def test_threat_intel_ip_and_domain():
    ti = ThreatIntel({"10.66.0.10"}, {"evil-c2.lab"})
    assert ti.on_conn(conn("10.66.0.10"))[0]["severity"] == "critical"
    dns = {"ts": T0, "id.orig_h": CAM, "id.resp_h": config.GATEWAY_IP, "query": "x.evil-c2.lab"}
    assert ti.on_dns(dns)[0]["type"] == "threat_intel"


def test_risky_protocol():
    assert RiskyProtocol().on_conn(conn("8.8.4.4", 6667))[0]["type"] == "risky_protocol"
    assert RiskyProtocol().on_conn(conn("8.8.4.4", 443)) == []


def test_dns_random_domain_and_nxdomain_burst():
    d = SuspiciousDNS()
    rand = {"ts": T0, "id.orig_h": CAM, "id.resp_h": config.GATEWAY_IP, "query": "xk3j9qpz7w2lmv8r.com"}
    assert d.on_dns(rand)[0]["type"] == "dns_suspicious"
    normal = {"ts": T0, "id.orig_h": CAM, "id.resp_h": config.GATEWAY_IP, "query": "api.hik-connect.com"}
    assert d.on_dns(normal) == []
    out = []
    for i in range(25):
        out += d.on_dns({"ts": T0 + i, "id.orig_h": "192.168.50.24", "id.resp_h": config.GATEWAY_IP,
                         "query": f"a{i}.example", "rcode_name": "NXDOMAIN"})
    assert any("failed DNS" in a["evidence"] for a in out)


def test_scoring_matches_worked_examples():
    s = Scorer()
    now = T0
    s.add({"mac": "decoy", "type": "decoy_login", "ts": now})
    assert s.score("decoy", now)["status"] == "infected"

    s.add({"mac": "weak", "type": "beaconing", "ts": now})
    assert s.score("weak", now)["status"] != "infected"

    s.add({"mac": "both", "type": "beaconing", "ts": now})
    s.add({"mac": "both", "type": "lan_scan", "ts": now})
    assert s.score("both", now)["status"] == "infected"


def test_scoring_no_double_count_and_decay():
    s = Scorer()
    s.add({"mac": "m", "type": "threat_intel", "ts": T0})
    one = s.score("m", T0)["infection_score"]
    s.add({"mac": "m", "type": "beaconing", "ts": T0})      # same family: must not add
    assert s.score("m", T0)["infection_score"] == one
    assert s.score("m", T0 + 3 * 3600)["status"] == "safe"  # fades after hours


def test_decoy_catches_telnet_login():
    config.DECOY_TELNET_PORTS, config.DECOY_HTTP_PORT = [12323], 18080
    from engine.decoy import Decoy
    got = []
    decoy = Decoy(got.extend)
    threading.Thread(target=decoy.run, daemon=True).start()
    time.sleep(0.5)
    s = socket.create_connection((config.DECOY_IP, 12323), source_address=("127.0.0.3", 0))
    s.recv(100); s.sendall(b"admin\r\n")
    s.recv(100); s.sendall(b"admin\r\n")
    time.sleep(0.3)
    s.close()
    assert any(a["type"] == "decoy_login" and "admin/admin" in a["evidence"] for a in got)
    assert all(a["severity"] == "critical" for a in got)
