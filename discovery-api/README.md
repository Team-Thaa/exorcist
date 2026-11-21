# Discovery + API (owner: Aaryan)

Device discovery, exposure audit, FastAPI + SQLite API, Telegram alerts.

- `discovery/`: find devices on the LAN, fingerprint vendor/type, audit open ports and firmware
- `api/`: FastAPI app. Receives engine alerts on `POST /alerts`, serves device status, pushes to the dashboard over WebSocket `/live`
- `telegram/`: alert bot

Data contracts are in the root `CLAUDE.md`.
