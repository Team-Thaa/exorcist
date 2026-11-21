from fastapi.testclient import TestClient

from api.main import create_app


MAC = "aa:bb:cc:00:00:23"


def build_client(tmp_path, quarantine_action=None):
    app = create_app(
        tmp_path / "exorcist.sqlite3",
        quarantine_action=quarantine_action or (lambda action, mac: True),
    )
    return TestClient(app)


def device_payload():
    return {
        "mac": MAC.upper(),
        "ip": "192.168.50.23",
        "type": "camera",
        "open_ports": [23, 554],
        "exposure_score": 65,
        "findings": ["Telnet is reachable."],
    }


def alert_payload(**changes):
    return {
        "mac": MAC,
        "ip": "192.168.50.23",
        "source": "engine",
        "type": "lan_scan",
        "severity": "high",
        "evidence": "Tried Telnet/SSH on 10 local devices in 60s",
        "time": "2026-11-21T18:00:00Z",
        "ts": 1795284000.0,
        "infection_score": 92,
        "status": "infected",
        **changes,
    }


def test_device_upsert_and_alert_update_persisted_status(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with build_client(tmp_path) as client:
        response = client.post("/devices", json=device_payload())
        assert response.status_code == 201
        assert response.json()["mac"] == MAC
        assert response.json()["quarantined"] is False

        updated = client.post(
            "/devices",
            json={"mac": MAC, "ip": "192.168.50.24", "label": "Updated camera"},
        )
        assert updated.status_code == 201
        assert updated.json()["open_ports"] == [23, 554]

        alert = client.post("/alerts", json=alert_payload())
        assert alert.status_code == 201
        assert alert.json()["device"]["status"] == "infected"
        assert client.get("/devices").json()[0]["infection_score"] == 92
        assert client.get(f"/devices/{MAC.upper()}").json()["ip"] == "192.168.50.23"
        assert client.get("/alerts").json()[0]["type"] == "lan_scan"

    with build_client(tmp_path) as restarted_client:
        persisted = restarted_client.get(f"/devices/{MAC}")
        assert persisted.status_code == 200
        assert persisted.json()["status"] == "infected"
        assert restarted_client.get("/alerts").json()[0]["mac"] == MAC


def test_live_websocket_broadcasts_alert_and_device_status(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with build_client(tmp_path) as client:
        with client.websocket_connect("/live") as websocket:
            response = client.post("/alerts", json=alert_payload())

            assert response.status_code == 201
            alert_event = websocket.receive_json()
            device_event = websocket.receive_json()
            assert alert_event == {
                "event": "alert.created",
                "alert": response.json()["alert"],
            }
            assert device_event["event"] == "device.updated"
            assert device_event["device"]["infection_score"] == 92


def test_alert_validation_matches_shared_schema(tmp_path):
    with build_client(tmp_path) as client:
        missing_confidence = client.post(
            "/alerts",
            json=alert_payload(source="model", type="ml_botnet"),
        )
        assert missing_confidence.status_code == 422

        extra_field = client.post("/alerts", json=alert_payload(unexpected="no"))
        assert extra_field.status_code == 422

        invalid_score = client.post("/alerts", json=alert_payload(infection_score=101))
        assert invalid_score.status_code == 422

        naive_timestamp = client.post(
            "/alerts",
            json=alert_payload(time="2026-11-21T18:00:00"),
        )
        assert naive_timestamp.status_code == 422


def test_model_alert_accepts_confidence_and_limited_features(tmp_path, monkeypatch):
    monkeypatch.delenv("TELEGRAM_BOT_TOKEN", raising=False)
    monkeypatch.delenv("TELEGRAM_CHAT_ID", raising=False)
    with build_client(tmp_path) as client:
        response = client.post(
            "/alerts",
            json=alert_payload(
                source="model",
                type="ml_botnet",
                confidence=0.93,
                top_features=["beacon interval", "destination fanout"],
            ),
        )

        assert response.status_code == 201
        assert response.json()["alert"]["confidence"] == 0.93


def test_device_accepts_additional_schema_properties(tmp_path):
    with build_client(tmp_path) as client:
        response = client.post(
            "/devices",
            json={**device_payload(), "last_seen": "from-discovery"},
        )

        assert response.status_code == 201
        assert response.json()["last_seen"] == "from-discovery"


def test_dashboard_is_served_from_same_origin_as_api(tmp_path):
    with build_client(tmp_path) as client:
        page = client.get("/")
        script = client.get("/app.js")
        stylesheet = client.get("/app.css")

        assert page.status_code == 200
        assert 'href="/app.css"' in page.text
        assert script.status_code == 200
        assert "WebSocket" in script.text
        assert stylesheet.status_code == 200


def test_quarantine_and_release_are_mac_keyed_and_idempotent(tmp_path):
    calls = []

    def backend(action, mac):
        calls.append((action, mac))
        return True

    with build_client(tmp_path, backend) as client:
        client.post("/devices", json=device_payload())
        quarantined = client.post(f"/devices/{MAC}/quarantine")
        assert quarantined.status_code == 200
        assert quarantined.json()["quarantined"] is True
        assert calls == [("quarantine", MAC)]

        client.post(f"/devices/{MAC}/quarantine")
        released = client.post(f"/devices/{MAC}/release")
        assert released.status_code == 200
        assert released.json()["quarantined"] is False
        assert calls == [("quarantine", MAC), ("release", MAC)]


def test_quarantine_failure_does_not_change_device_state(tmp_path):
    with build_client(tmp_path, lambda action, mac: False) as client:
        client.post("/devices", json=device_payload())

        response = client.post(f"/devices/{MAC}/quarantine")

        assert response.status_code == 503
        assert client.get(f"/devices/{MAC}").json()["quarantined"] is False


def test_quarantine_rejects_ip_fallback_and_unknown_devices(tmp_path):
    with build_client(tmp_path) as client:
        fallback = client.post("/devices/ip:192.168.50.44/quarantine")
        unknown = client.post("/devices/aa:bb:cc:00:00:44/quarantine")

        assert fallback.status_code == 422
        assert unknown.status_code == 404
