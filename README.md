# Exorcist

Finds routers and CCTV cameras on a network, shows how easily each could be hacked, spots devices already in a botnet from their traffic alone, explains why in plain language, and quarantines them with one click. Team Tha, SatHack round 1.

| Folder | What | Owner |
|---|---|---|
| `detection-engine/` | Rules, decoy, scoring, quarantine | Varun |
| `discovery-api/` | Device discovery, exposure audit, FastAPI + SQLite, Telegram | Aaryan |
| `ai-models/` | Model A (Random Forest), Model B (Isolation Forest), LLM explanations | Tejas |
| `dashboard/` | Radar view, device detail, live feed, quarantine button | Vedanti |
| `lab/` | Pi 5 gateway, QEMU VMs, fake bot, fake C2 | Nitin |
| `pitch/` | Slides and demo script | Nitin |

Full project context and data contracts: `CLAUDE.md`.
