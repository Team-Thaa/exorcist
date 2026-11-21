"""FastAPI application for devices, alerts, live updates, and quarantine."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .notifiers.telegram.notifier import notify as telegram_notify
from .storage import Store

ROOT = Path(__file__).resolve().parents[1]
DB_PATH = Path(
    os.environ.get("EXORCIST_DB_PATH", str(Path(__file__).with_name("exorcist.sqlite3")))
)
MAC_PATTERN = re.compile(r"^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
logger = logging.getLogger("exorcist.api")

DETECTION_ENGINE_PATH = str(ROOT / "detection-engine")
if DETECTION_ENGINE_PATH not in sys.path:
    sys.path.insert(0, DETECTION_ENGINE_PATH)
from engine import quarantine as engine_quarantine  # noqa: E402


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)


class AlertIn(StrictModel):
    mac: str
    ip: str
    source: Literal["engine", "model"]
    type: Literal[
        "decoy_login",
        "lan_scan",
        "beaconing",
        "threat_intel",
        "dns_suspicious",
        "dns_hijack",
        "fanout",
        "risky_protocol",
        "ml_botnet",
        "ml_anomaly",
    ]
    severity: Literal["low", "medium", "high", "critical"]
    evidence: str
    time: datetime
    ts: float
    confidence: Optional[float] = Field(default=None, ge=0, le=1)
    top_features: Optional[list[str]] = Field(default=None, max_length=3)
    infection_score: int = Field(ge=0, le=100)
    status: Literal["safe", "at_risk", "infected"]

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        return value.lower()

    @field_validator("time")
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("time must include a timezone")
        return value

    @model_validator(mode="after")
    def require_model_confidence(self) -> "AlertIn":
        if self.source == "model" and self.confidence is None:
            raise ValueError("model alerts require confidence")
        return self


class DeviceIn(StrictModel):
    model_config = ConfigDict(extra="allow", allow_inf_nan=False)

    mac: str
    ip: str
    vendor: Optional[str] = None
    type: Optional[str] = None
    label: Optional[str] = None
    open_ports: Optional[list[int]] = None
    firmware: Optional[str] = None
    exposure_score: Optional[int] = Field(default=None, ge=0, le=100)
    findings: Optional[list[str]] = None
    infection_score: Optional[int] = Field(default=None, ge=0, le=100)
    status: Optional[Literal["safe", "at_risk", "infected"]] = None
    quarantined: Optional[bool] = None
    explanation: Optional[str] = None

    @field_validator("mac")
    @classmethod
    def normalize_mac(cls, value: str) -> str:
        return value.lower()


class ConnectionManager:
    def __init__(self) -> None:
        self.connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self.connections.discard(websocket)

    async def broadcast(self, message: dict[str, Any]) -> None:
        stale = []
        for websocket in tuple(self.connections):
            try:
                await websocket.send_json(message)
            except (RuntimeError, OSError) as exc:
                logger.warning("Removing disconnected /live client: %s", exc)
                stale.append(websocket)
        for websocket in stale:
            self.disconnect(websocket)


def _quarantine(action: str, mac: str) -> bool:
    function = engine_quarantine.quarantine if action == "quarantine" else engine_quarantine.release
    return bool(function(mac))


def create_app(
    db_path: str | Path = DB_PATH,
    quarantine_action: Callable[[str, str], bool] = _quarantine,
) -> FastAPI:
    store = Store(db_path)
    live = ConnectionManager()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        store.initialize()
        yield

    app = FastAPI(title="Exorcist API", version="0.1.0", lifespan=lifespan)
    app.state.store = store

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/devices", status_code=201)
    async def upsert_device(device: DeviceIn) -> dict[str, Any]:
        payload, changed = store.upsert_device(
            device.model_dump(mode="json", exclude_unset=True, exclude_none=True)
        )
        if changed:
            await live.broadcast({"event": "device.updated", "device": payload})
        return payload

    @app.get("/devices")
    def list_devices() -> list[dict[str, Any]]:
        return store.list_devices()

    @app.get("/devices/{mac}")
    def get_device(mac: str) -> dict[str, Any]:
        device = store.get_device(mac.lower())
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")
        return device

    @app.post("/alerts", status_code=201)
    async def create_alert(
        alert: AlertIn, background_tasks: BackgroundTasks
    ) -> dict[str, Any]:
        payload = alert.model_dump(mode="json", exclude_none=True)
        device, previous_status, status_changed = store.add_alert(payload)
        await live.broadcast({"event": "alert.created", "alert": payload})
        if status_changed:
            await live.broadcast({"event": "device.updated", "device": device})
        if device["status"] in {"at_risk", "infected"} and device["status"] != previous_status:
            background_tasks.add_task(telegram_notify, device, payload)
        return {"accepted": True, "alert": payload, "device": device}

    @app.get("/alerts")
    def list_alerts(limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
        return store.list_alerts(limit)

    async def set_quarantine(mac: str, action: str) -> dict[str, Any]:
        normalized_mac = mac.lower()
        if not MAC_PATTERN.fullmatch(normalized_mac):
            raise HTTPException(status_code=422, detail="Quarantine requires a valid device MAC address")
        device = store.get_device(normalized_mac)
        if device is None:
            raise HTTPException(status_code=404, detail="Device not found")

        quarantined = action == "quarantine"
        if bool(device.get("quarantined", False)) == quarantined:
            return device

        try:
            succeeded = await asyncio.to_thread(quarantine_action, action, normalized_mac)
        except OSError as exc:
            logger.exception("Could not %s device %s", action, normalized_mac)
            raise HTTPException(status_code=503, detail=f"Quarantine backend unavailable: {exc}") from exc
        if not succeeded:
            raise HTTPException(
                status_code=503,
                detail=f"Could not {action} device; check nftables and API permissions",
            )

        updated = store.set_quarantined(normalized_mac, quarantined)
        if updated is None:
            raise HTTPException(status_code=404, detail="Device not found")
        await live.broadcast({"event": "device.updated", "device": updated})
        return updated

    @app.post("/devices/{mac}/quarantine")
    async def quarantine_device(mac: str) -> dict[str, Any]:
        return await set_quarantine(mac, "quarantine")

    @app.post("/devices/{mac}/release")
    async def release_device(mac: str) -> dict[str, Any]:
        return await set_quarantine(mac, "release")

    @app.websocket("/live")
    async def live_updates(websocket: WebSocket) -> None:
        await live.connect(websocket)
        try:
            while True:
                await websocket.receive_text()
        except WebSocketDisconnect:
            live.disconnect(websocket)

    return app


app = create_app()
