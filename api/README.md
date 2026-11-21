# api

FastAPI + SQLite. The hub between the detectors and the dashboard.

- `POST /alerts`: alerts from the detection engine and models (`shared/alert.schema.json`)
- device list and status, quarantine trigger
- `WebSocket /live`: pushes new alerts and status changes to the dashboard
- `notifiers/`: outbound alerts (Telegram)
