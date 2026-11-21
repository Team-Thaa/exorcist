# Exorcist

Finds routers and CCTV cameras on a network, shows how easily each could be hacked, spots devices already in a botnet from their traffic alone, explains why in plain language, and quarantines them with one click. Team Tha, SatHack round 1.

## How data flows

```
discovery ──► devices ─┐
                       ├──► api ──► dashboard (/live), Telegram
detection-engine ──► alerts ─┘
   ▲ models (plug into the engine)
```

| Folder | What it does | Owner |
|---|---|---|
| `discovery/` | Find devices, exposure audit | Aaryan |
| `detection-engine/` | Rules, decoy, scoring, quarantine | Varun |
| `models/` | Random Forest, Isolation Forest, LLM explanations | Tejas |
| `api/` | FastAPI + SQLite, `/alerts`, `/live`, Telegram notifier | Aaryan |
| `dashboard/` | Radar view, device detail, live feed, quarantine button | Vedanti |
| `shared/` | Alert and device data formats (JSON schemas) | everyone |
| `lab/` | Pi 5 gateway, QEMU VMs, fake bot, fake C2 | Nitin |
| `docs/` | Architecture notes, pitch | Nitin |
