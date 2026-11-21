"""SQLite persistence for devices and detection alerts."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


class Store:
    def __init__(self, path: str | Path):
        self.path = Path(path)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self.path), timeout=10)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _decode_device(row: sqlite3.Row | None) -> dict[str, Any] | None:
        return json.loads(row["payload"]) if row else None

    @staticmethod
    def _save_device(connection: sqlite3.Connection, payload: dict[str, Any]) -> None:
        now = datetime.now(timezone.utc).isoformat()
        connection.execute(
            """
            INSERT INTO devices (mac, ip, status, infection_score, quarantined, payload, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(mac) DO UPDATE SET
                ip = excluded.ip,
                status = excluded.status,
                infection_score = excluded.infection_score,
                quarantined = excluded.quarantined,
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (
                payload["mac"],
                payload["ip"],
                payload.get("status"),
                payload.get("infection_score"),
                int(payload.get("quarantined", False)),
                json.dumps(payload, separators=(",", ":")),
                now,
            ),
        )

    def initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    mac TEXT PRIMARY KEY,
                    ip TEXT NOT NULL,
                    status TEXT,
                    infection_score INTEGER,
                    quarantined INTEGER NOT NULL DEFAULT 0,
                    payload TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    mac TEXT NOT NULL,
                    ts REAL NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS alerts_by_time ON alerts(ts DESC, id DESC);
                """
            )

    def upsert_device(self, incoming: dict[str, Any]) -> tuple[dict[str, Any], bool]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM devices WHERE mac = ?", (incoming["mac"],)
            ).fetchone()
            existing = self._decode_device(row) or {}
            merged = {**existing, **incoming}
            merged.setdefault("quarantined", False)
            changed = merged != existing
            self._save_device(connection, merged)
        return merged, changed

    def get_device(self, mac: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
        return self._decode_device(row)

    def list_devices(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM devices ORDER BY ip, mac"
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]

    def add_alert(self, alert: dict[str, Any]) -> tuple[dict[str, Any], str | None, bool]:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM devices WHERE mac = ?", (alert["mac"],)
            ).fetchone()
            existing = self._decode_device(row) or {}
            previous_status = existing.get("status")
            previous_score = existing.get("infection_score")
            device = {
                **existing,
                "mac": alert["mac"],
                "ip": alert["ip"],
                "infection_score": alert["infection_score"],
                "status": alert["status"],
            }
            device.setdefault("quarantined", False)
            changed = (
                previous_status != device["status"]
                or previous_score != device["infection_score"]
                or existing.get("ip") != device["ip"]
            )
            connection.execute(
                "INSERT INTO alerts (mac, ts, payload) VALUES (?, ?, ?)",
                (alert["mac"], alert["ts"], json.dumps(alert, separators=(",", ":"))),
            )
            self._save_device(connection, device)
        return device, previous_status, changed

    def set_quarantined(self, mac: str, quarantined: bool) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT payload FROM devices WHERE mac = ?", (mac,)
            ).fetchone()
            device = self._decode_device(row)
            if device is None:
                return None
            device["quarantined"] = quarantined
            self._save_device(connection, device)
        return device

    def list_alerts(self, limit: int) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT payload FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [json.loads(row["payload"]) for row in rows]
