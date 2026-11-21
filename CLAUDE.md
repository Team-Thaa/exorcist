# Project context for Claude Code

## What this is

Team Tha's entry for SatHack (round 1, AI & Cybersecurity track, open innovation). Project name not final (repo: Exorcist).

A tool that finds routers and CCTV cameras on a network, shows how easily each could be hacked, detects devices that are **already** part of a botnet from their traffic alone, explains why in plain language, and quarantines them with one click. Nothing is installed on the devices themselves: all traffic passes through a Raspberry Pi 5 gateway, where it is observed.

**USP:** we name the exact infected device (India's Cyber Swachhta Kendra only knows the infected IP, i.e. a whole home), a decoy tripwire gives proof instead of guesses, and an AI layer adds learned detection. Existing tools: Fing (scanning only), Firewalla ($109–$418 box, generic alarms), IoT Inspector (privacy research), Bitdefender BOX (discontinued).

## Team and ownership

| Person | Owns |
|---|---|
| Varun | Detection engine (`detection-engine/engine/`) |
| Aaryan | Device discovery, exposure audit, FastAPI + SQLite API, Telegram alerts |
| Tejas | AI: Model A (Random Forest on IoT-23), Model B (per-device Isolation Forest), LLM explanations |
| Vedanti | Dashboard (radar view, device detail, live feed, quarantine button) |
| Nitin | Test lab (Pi 5 gateway + QEMU VMs) and the pitch |

## Architecture

```
Lab devices (QEMU: OpenWrt router VM, fake camera VM running a fake bot; team phones)
      │  all traffic via the Pi
      ▼
Pi 5 gateway: bridge br-lan 192.168.50.0/24, Pi = .1, decoy IP = .99
   Zeek (JSON logs, mac-logging) ──► engine (rules + decoy + scoring + quarantine)
                                 ──► Tejas's models (via engine hook)
   Fake C2: 10.66.0.10:8080 on a dummy interface on the Pi (lab only)
      │ alerts (HTTP POST /alerts)
      ▼
Aaryan's API (FastAPI) ──► Vedanti's dashboard (WebSocket /live), Telegram
```

No physical router: the "vulnerable router" is an OpenWrt x86-64 VM in QEMU. VMs attach to a Linux bridge on Nitin's laptop, connected to the Pi by Ethernet (not Wi-Fi, which can't bridge several MACs). Backup plan: everything on one Linux laptop with `br0`.

## Repo layout

| Folder | Owner |
|---|---|
| `detection-engine/` | Varun |
| `discovery-api/` (`discovery/`, `api/`, `telegram/`) | Aaryan |
| `ai-models/` (`model_a/`, `model_b/`, `explain/`, `data/` git-ignored) | Tejas |
| `dashboard/` | Vedanti |
| `lab/` (`pi-setup/`, `vms/`, `fake-bot/`, `fake-c2/`, `captures/` git-ignored) | Nitin |
| `pitch/` | Nitin |

All engine code lives in `detection-engine/`. Run every engine command below from that directory.

### `detection-engine/engine/`

| File | Role |
|---|---|
| `config.py` | All settings and thresholds, overridable by env vars (`LAN_CIDR`, `GATEWAY_IP`, `DECOY_IP`, `ROUTER_IP`, `ZEEK_LOG_DIR`, `API_URL`, `ALERT_FILE`, `DRY_RUN`, ...) |
| `tailer.py` | `follow(path)`: tail -f for Zeek JSON logs, survives rotation |
| `devices.py` | `mac_for(ip, zeek_mac)`: Zeek's `orig_l2_addr` first, else `/proc/net/arp`, else `ip:<addr>` |
| `detectors.py` | Rule detectors with `on_conn(row)` / `on_dns(row)` returning alert lists: `LanScan`, `FanOut`, `Beaconing`, `ThreatIntel`, `RiskyProtocol`, `SuspiciousDNS`. Shared `make_alert()` with per (mac, type, key) cooldown |
| `decoy.py` | asyncio fake camera on `DECOY_IP`: Telnet 23/2323 (captures user/pass, strips IAC bytes) and HTTP 80 login page. Any contact = critical `decoy_login` |
| `dns_hijack.py` | Every 60 s asks `ROUTER_IP` and 1.1.1.1 for 5 domains; alerts if 3+ disagree by /16 prefix |
| `scoring.py` | `Scorer`: evidence-based score (see below) |
| `quarantine.py` | nftables table `inet botguard`, set of MACs; drops quarantined MACs in forward chain and, in input chain, to non-LAN destinations (needed because the fake C2 is hosted on the Pi) |
| `alerts.py` | `AlertSink.emit()`: adds to scorer, attaches score/status, appends to `alerts.jsonl`, POSTs to `API_URL/alerts`, prints |
| `main.py` | Live mode (threads: decoy, DNS hijack loop, dns.log, conn.log) and `--replay conn.log dns.log`. `extra_handlers` hook for Tejas's models |

Other files in `detection-engine/`: `rates.json` (detector counts), `threatlist.txt` (local bad IPs/domains, includes the fake C2), `tests/test_engine.py` (11 pytest tests with synthetic Zeek rows, all passing), `README.md` (Pi setup).

## Detectors (starting thresholds, untuned)

| Type | Fires when | Severity |
|---|---|---|
| `decoy_login` | Any LAN device contacts the decoy | critical |
| `lan_scan` | ≥10 distinct LAN targets on 22/23/2323 in 60 s | high |
| `beaconing` | ≥6 contacts to one external IP, gap 5–3600 s, std/mean ≤ 0.10 | high |
| `threat_intel` | Destination IP or queried domain on the list (local file + abuse.ch Feodo) | critical |
| `dns_suspicious` | First label ≥12 chars with entropy ≥3.5, ≥20 NXDOMAIN in 60 s, or DNS sent to a server other than the gateway | medium |
| `dns_hijack` | Router DNS answers mismatch trusted resolver | critical |
| `fanout` | ≥100 distinct external IPs in 60 s | high |
| `risky_protocol` | Outbound 25, 6667, 5555, 23, 2323 | medium |
| `ml_botnet`, `ml_anomaly` | From Tejas's models, with `confidence` 0–1 | — |

## Scoring (deterministic, evidence-based)

- Per detector, from `rates.json`: weight = ln(hit rate / false-alarm rate), with +1 smoothing: `(hits+1)/(runs+2)` and `(false+1)/(healthy+2)`. Model alerts are multiplied by their `confidence`.
- Detectors are grouped into families (`decoy`, `bad_servers`, `spreading`, `dns`, `attack`, `ai`); only the strongest clue per family counts.
- Clues fade with a 600 s half-life. Score uses the alert's own `ts` as "now", so replay works.
- logit = ln(prior/(1−prior)) + Σ weights, prior 0.01; P = sigmoid. Red ≥ 0.8, yellow ≥ 0.3.
- `"hard": true` (decoy_login, threat_intel): a hit younger than the half-life forces at least red, because no healthy device can trigger it by design.
- **`rates.json` currently holds placeholder numbers.** Replace them with lab counts: 20 fake-bot runs across variants (full, scan only, beacon only, slow scan) for hits; ~240 healthy device-minutes plus replayed IoT-23 benign captures for false alarms.

## Data contracts

Alert (engine → `POST /alerts`):
```json
{"mac": "aa:bb:cc:00:00:23", "ip": "192.168.50.23", "source": "engine", "type": "lan_scan",
 "severity": "high", "evidence": "Tried Telnet/SSH on 10 local devices in 60s",
 "time": "2026-11-21T18:30:00Z", "ts": 1700000100.0, "infection_score": 98, "status": "infected"}
```
`source` is `engine` or `model`. `status` is `safe`, `at_risk` or `infected`.

Device (Aaryan's audit): `mac, ip, vendor, type, label, open_ports, firmware, exposure_score, findings[]`.
Device status (API): `mac, exposure_score, infection_score, status, quarantined, explanation`.

Model hook:
```python
from engine.main import extra_handlers
extra_handlers["conn"].append(handler)   # handler(row) -> list of alerts or None
```
Model B plan: 10 s windows sliding every 5 s, ~60 windows (~5 min) to learn, threshold = 1st percentile of training scores, alert after 2 consecutive anomalous windows, report top 3 deviating features.

## How to run (from `detection-engine/`)

```bash
python -m pytest -q                                   # tests, no lab needed
python -m engine.main --replay conn.log dns.log       # replay Zeek JSON logs (zeek -r x.pcap LogAscii::use_json=T)

# On the Pi (see detection-engine/README.md for full setup):
sudo zeek -i br-lan -C LogAscii::use_json=T policy/protocols/conn/mac-logging   # in ~/zeeklogs
sudo ZEEK_LOG_DIR=$HOME/zeeklogs ROUTER_IP=<openwrt-vm-ip> python3 -m engine.main
sudo python3 -m engine.quarantine add|del <mac>
DRY_RUN=1 ...                                         # print nft commands instead of running them
```

## Status: what is NOT done or verified

- Never run live: Zeek on the Pi, decoy on the real IP (tested on localhost ports only), nftables (dry run only).
- Thresholds and `rates.json` are untuned placeholders.
- Aaryan's API, Tejas's models and Vedanti's dashboard are separate and not yet integrated.
- Zeek on Raspberry Pi OS may need building from source.

## Rules for working on this

- Lab only: the fake bot and fake C2 are our own harmless scripts; never real malware; never scan or attack anything outside the lab subnets.
- Metadata only: the engine reads connection and DNS metadata, never payload content.
- Keep verdicts explainable: every alert carries human-readable `evidence`; scoring stays deterministic.
- Keep it simple: hackathon code, standard library where possible (dnspython is the only extra dependency).
- Commit in small steps with clear messages during the event.
