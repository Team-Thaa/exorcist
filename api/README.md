# API

FastAPI + SQLite hub for discovery records and detection-engine alerts. The
API persists device state, broadcasts updates over `/live`, and calls the
detection engine's existing nftables quarantine functions.

## Run locally

From the repository root:

```bash
python3 -m pip install -r api/requirements.txt
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

The dashboard is served at `http://127.0.0.1:8000/` from the same origin as
the API, so its REST and WebSocket requests need no separate CORS setup.

The detection engine already posts alerts to `http://127.0.0.1:8000/alerts`.
The database defaults to `api/exorcist.sqlite3` (ignored by Git); set
`EXORCIST_DB_PATH` to choose another path.

## Endpoints

- `GET /health`: liveness check.
- `POST /devices`: add or update one discovery record. Identity is the
  lowercased MAC address; partial updates preserve fields already known.
- `GET /devices` and `GET /devices/{mac}`: list or retrieve devices.
- `POST /alerts`: validate and persist an alert matching
  `shared/alert.schema.json`, then update that device's infection score and
  status from the detection engine.
- `GET /alerts?limit=100`: most recent alerts (limit 1–500).
- `WebSocket /live`: JSON events `alert.created` and `device.updated`.
- `POST /devices/{mac}/quarantine` and `POST /devices/{mac}/release`: apply the
  engine's nftables action and persist the quarantine state. These actions
  require a known, real MAC address; `ip:<address>` fallback identities are
  not eligible.

The `POST /devices` body is one object matching `shared/device.schema.json`.
The alert body follows `shared/alert.schema.json`; model alerts must include
`confidence`. Alert fields not in the schema are rejected; device records
allow additional properties, consistent with `shared/device.schema.json`.

## Quarantine and Telegram

Quarantine invokes `detection-engine/engine/quarantine.py` in-process. Run the
API on the gateway with permissions to execute `nft`; if the action fails, the
API returns `503` and does not mark the device quarantined. `DRY_RUN=1` is
useful for testing, but reports successful actions without changing the
firewall.

Telegram is optional. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` to send a
message when a device changes to `at_risk` or `infected`. Without both values,
the API runs normally and sends no Telegram messages.

The API is unauthenticated in this initial lab version. Keep it on localhost
or a trusted isolated network; do not expose it directly to the internet.

## Tests

```bash
python3 -m pip install -r api/requirements-dev.txt
python3 -m pytest api/tests -q
```
