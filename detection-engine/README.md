# Detection engine

Owner: Varun.

The engine watches the traffic of every device on the LAN and decides which devices are already
infected. It reads Zeek's connection and DNS logs (metadata only, never content), runs a set of
simple rules, and turns their alerts into one infection score per device. A decoy "camera" gives
hard proof: no honest device ever talks to it. Every alert says in plain English why it fired.
Alerts go to the API, and a device can be cut off from the internet with nftables.

## Files

| File | What it does |
|---|---|
| `engine/config.py` | All settings and thresholds in one place. Some can be changed with environment variables (see below). |
| `engine/tailer.py` | `follow(path)`: reads a Zeek JSON log like `tail -f` and keeps going when Zeek rotates the file. |
| `engine/devices.py` | `mac_for(ip, zeek_mac)`: turns an IP into a MAC. Uses Zeek's MAC first, then `/proc/net/arp`, then falls back to `ip:<address>`. |
| `engine/detectors.py` | The rule detectors (table below) and `make_alert()`, which builds every alert and stops repeats. |
| `engine/decoy.py` | The live decoy: a fake camera on `DECOY_IP` with Telnet on ports 23 and 2323 and a login page on port 80. It records any username and password tried. |
| `engine/dns_hijack.py` | Every 60 s, asks the router and 1.1.1.1 for the same 5 domains and alerts if the router's answers look wrong. |
| `engine/scoring.py` | `Scorer`: turns a device's alerts into an infection score from 0 to 100 and a status. |
| `engine/quarantine.py` | Blocks or releases a device by MAC address using nftables. |
| `engine/alerts.py` | `AlertSink`: scores each alert, saves it to `alerts.jsonl`, posts it to the API and prints it. |
| `engine/main.py` | Starts everything: live mode or replay mode. Also has the `extra_handlers` hook for the AI models. |
| `demo/simulate.py` | Writes fake Zeek logs in real time for a demo: a normal network, then an infected camera. |
| `demo/board.py` | A live scoreboard in the terminal, read from the alert file. |
| `rates.json` | How often each detector fires on infected and healthy devices. Used for scoring. **Placeholder numbers.** |
| `threatlist.txt` | Local list of bad IPs and domains. Includes the lab's fake C2 (`10.66.0.10`, `evil-c2.lab`). |
| `tests/test_engine.py` | 19 tests with fake Zeek rows. No lab needed. |

## Detectors

Starting thresholds, not tuned yet. All of them are in `engine/config.py`.

| Alert type | Fires when | Severity |
|---|---|---|
| `decoy_login` | A LAN device contacts the decoy (any port, any connection). See "The decoy" below. | critical |
| `lan_scan` | One LAN device tries ports 22, 23 or 2323 on at least 10 different LAN addresses within 60 s. Connections to the decoy don't count here. | high |
| `fanout` | One LAN device contacts at least 100 different internet addresses within 60 s. | high |
| `beaconing` | One LAN device contacts the same internet address at least 6 times, the average gap is 5 to 3600 s, and the gaps vary by 10% or less (standard deviation / mean ≤ 0.10). | high |
| `threat_intel` | A LAN device connects to an IP on the threat list, or looks up a domain on it (or a subdomain of it). The list is `threatlist.txt` plus the abuse.ch Feodo list, downloaded at startup. | critical |
| `risky_protocol` | A LAN device uses port 25 (SMTP), 6667 (IRC), 5555 (Android debug), 23 or 2323 (Telnet) towards the internet. | medium |
| `dns_suspicious` | A lookup whose first label is at least 12 characters with entropy ≥ 3.5 (random-looking), or at least 20 failed lookups (NXDOMAIN) within 60 s, or a LAN device sending DNS to a server other than the gateway. | medium |
| `dns_hijack` | At least 3 of the 5 check domains get router answers whose first two octets match none of 1.1.1.1's answers. Only runs when `ROUTER_IP` is set and `dnspython` is installed. | critical |
| `ml_botnet`, `ml_anomaly` | Sent by the AI models through `extra_handlers`, with a `confidence` from 0 to 1. No model is plugged in yet. | set by the model |

The same alert (same device, same type, same target) is not repeated within 120 s.

**Trusted scanners.** `LanScan`, `FanOut`, `DecoyContact` and the live decoy ignore any source in
`TRUSTED_SCANNERS`. The gateway is always in that set. Other detectors still apply to trusted machines.

### The decoy

There are two ways to catch decoy contact:

1. **The live decoy listener** (`engine/decoy.py`). It answers on `DECOY_IP` ports 23, 2323 and 80,
   so it can also record the username and password a bot tries. It needs root (ports below 1024)
   and `DECOY_IP` must be an address of this machine.
2. **`DecoyContact`** (in `engine/detectors.py`). It spots any connection to `DECOY_IP` in `conn.log`.
   This works in replay mode and when the listener is off.

In live mode, the engine starts the listener and waits 1 second. If the listener is still running,
it removes `DecoyContact`, so one decoy hit doesn't show up twice. If the listener failed to start
(for example, no root, or `DECOY_IP` is not on this machine), it keeps `DecoyContact` and prints
`[decoy] listener failed to start; spotting decoy contact in conn.log instead`.
With `--no-decoy`, and in replay mode, only `DecoyContact` is used.

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `LAN_CIDR` | `192.168.50.0/24` | The lab network. Only devices inside it are judged. |
| `GATEWAY_IP` | `192.168.50.1` | The Pi. Also the LAN's DNS server. Always a trusted scanner. |
| `ROUTER_IP` | empty | Router to check for DNS hijacking. Empty turns the check off. |
| `LAN_IFACE` | `br-lan` | Defined but not used by the code yet. |
| `DECOY_IP` | `192.168.50.99` | Address of the decoy. |
| `TRUSTED_SCANNERS` | empty | Extra trusted IPs, comma-separated, for example `192.168.50.10,192.168.50.11`. The gateway is always added. |
| `ZEEK_LOG_DIR` | `/opt/zeek/logs/current` | Folder with Zeek's `conn.log` and `dns.log` (live mode). |
| `API_URL` | `http://127.0.0.1:8000` | Alerts are posted to `API_URL/alerts`. If the API is down, alerts are still printed and saved. |
| `ALERT_FILE` | `alerts.jsonl` | Local copy of every alert, one JSON object per line. Relative to the folder you run from. |
| `THREAT_FILE` | `threatlist.txt` (next to `engine/`) | Local threat list. |
| `RATES_FILE` | `rates.json` (next to `engine/`) | Detector rates for scoring. |
| `DRY_RUN` | `0` | `1` prints the `nft` commands instead of running them. |

The thresholds (window, counts, ports, cooldown, prior, half-life) are not environment variables.
Change them in `engine/config.py`.

## Scoring

The score is a probability from 0 to 100, built from evidence:

1. **Weight per detector.** From `rates.json`:
   `weight = ln(hit rate / false-alarm rate)`, with hit rate = `(hits + 1) / (runs + 2)` and
   false-alarm rate = `(false + 1) / (healthy + 2)`. The `+1` keeps rates away from 0 and 100%.
   A model alert's weight is multiplied by its `confidence`.
2. **Families.** Each detector belongs to a family (`decoy`, `bad_servers`, `spreading`, `dns`,
   `attack`, `ai`). Only the strongest clue in each family counts, so related clues are not
   counted twice.
3. **Fading.** A clue loses half its weight every 600 s. The alert's own `ts` is used as "now",
   so replayed logs score the same way as live traffic.
4. **Log-odds.** Start from a prior of 1% (`ln(0.01 / 0.99)`), add the weights, and turn the sum
   back into a probability with the sigmoid function.
5. **Hard evidence.** Detectors marked `"hard": true` in `rates.json` (`decoy_login` and
   `threat_intel`) cannot be triggered by a healthy device by design. A hit younger than 600 s
   makes the score at least 80 on its own.
6. **Status.** 80 or more is `infected`, 30 or more is `at_risk`, below 30 is `safe`.

**`rates.json` still holds placeholder numbers.** To measure real ones: run each fake-bot variant
(full, scan only, beacon only, slow scan) about 5 times (20 runs) and count, per detector, the runs
where it fired (`hits` / `runs`). Then run healthy devices for about an hour plus replayed IoT-23
benign captures and count the device-minutes where it fired (`false` / `healthy`).

## How to run

Run every command from this folder (`detection-engine/`).

### Tests (any laptop)

```bash
pip install pytest dnspython
python -m pytest -q
```

### Replay Zeek logs

```bash
zeek -r capture.pcap LogAscii::use_json=T              # writes conn.log and dns.log
python -m engine.main --replay conn.log dns.log
```

A file is treated as a DNS log if its name contains `dns`. Rows are sorted by time before they are
processed. Replay never starts the decoy listener and never touches nftables.

### Live on the Pi

Assumes the LAN bridge is `br-lan` on `192.168.50.0/24` with the Pi at `.1`.

One-time setup:

```bash
sudo apt install nftables python3-pip
pip install dnspython --break-system-packages
# Zeek: try `sudo apt install zeek`; otherwise use the official Zeek packages or build from source.

sudo ip addr add 192.168.50.99/24 dev br-lan            # the decoy's address

# Lab only: fake C2 server on its own subnet, hosted on the Pi
sudo ip link add c2 type dummy
sudo ip addr add 10.66.0.10/24 dev c2
sudo ip link set c2 up
python3 -m http.server 8080 --bind 10.66.0.10 &
```

Terminal 1, Zeek with JSON logs and MAC addresses:

```bash
mkdir -p ~/zeeklogs && cd ~/zeeklogs
sudo zeek -i br-lan -C LogAscii::use_json=T policy/protocols/conn/mac-logging
```

Terminal 2, the engine:

```bash
sudo ZEEK_LOG_DIR=$HOME/zeeklogs API_URL=http://127.0.0.1:8000 python3 -m engine.main
```

Add `ROUTER_IP=<router IP>` to turn on the DNS hijack check, and `TRUSTED_SCANNERS=<ip>,<ip>` for
machines that are allowed to scan. Add `--no-decoy` to run without the decoy listener.
Live mode runs `quarantine.setup()` first, which creates the nftables table.

Quarantine by hand (the API calls the same functions, `quarantine(mac)` and `release(mac)`):

```bash
sudo python3 -m engine.quarantine                          # create the nftables table (setup)
sudo python3 -m engine.quarantine add aa:bb:cc:dd:ee:ff
sudo python3 -m engine.quarantine del aa:bb:cc:dd:ee:ff
DRY_RUN=1 python3 -m engine.quarantine add aa:bb:cc:dd:ee:ff   # print the nft command only
```

A quarantined MAC is dropped in the `forward` chain, and in the `input` chain for any destination
outside `LAN_CIDR` (needed because the lab's fake C2 is hosted on the Pi). LAN traffic keeps working.

### Terminal demo (no lab needed)

Three terminals, all in `detection-engine/`:

```bash
# 1. Engine, reading the demo folder (decoy off, nftables dry run, no API)
ZEEK_LOG_DIR=/tmp/demo ALERT_FILE=/tmp/demo/alerts.jsonl DRY_RUN=1 API_URL=http://127.0.0.1:9 \
  python -m engine.main --no-decoy

# 2. Scoreboard
python demo/board.py --file /tmp/demo/alerts.jsonl --since-now

# 3. Traffic
python demo/simulate.py --dir /tmp/demo
```

`API_URL=http://127.0.0.1:9` points at a port where nothing listens, so alerts are only printed
and saved. Point it at the real API to feed the web dashboard instead.

The simulator first shows a normal network for about 20 s (a phone browsing, a camera uploading to
its cloud, the phone watching the camera's stream). Then the camera gets infected: it beacons to
the fake C2 every 30 simulated seconds, looks up 3 random domains, and tries Telnet on 15 LAN
addresses including the decoy. Simulated time runs faster than real time. Expected result: no
alerts in phase 1; then `threat_intel`, `dns_suspicious`, `decoy_login`, `lan_scan` and
`beaconing` for the camera, which ends `infected`. The phone never alerts.

Options:

- `simulate.py`: `--dir` (default `/tmp/demo`), `--wait` seconds before traffic starts (default 3),
  `--pace` to scale the delays (`0.5` = twice as fast), `--seed`. It deletes and recreates
  `conn.log` and `dns.log` at startup.
- `board.py`: `--file` (default `alerts.jsonl`), `--since-now` to hide alerts already in the file,
  `--every` refresh seconds (default 1). Ctrl+C exits.

## For the AI models

```python
from engine.main import extra_handlers
extra_handlers["conn"].append(my_handler)   # called with every conn.log row; "dns" also exists
```

The handler returns a list of alerts or nothing. Alerts must match `shared/alert.schema.json`:
type `ml_botnet` or `ml_anomaly`, `source: "model"`, a `confidence` from 0 to 1, and optionally
`top_features` (up to 3 strings). The engine adds `infection_score` and `status` before posting.

## Alert format

Posted to `POST /alerts` and saved to `ALERT_FILE`:

```json
{"mac": "aa:bb:cc:00:00:23", "ip": "192.168.50.23", "source": "engine", "type": "lan_scan",
 "severity": "high", "evidence": "Tried Telnet/SSH on 10 local devices in 60s",
 "time": "2023-11-14T22:13:29Z", "ts": 1700000009.0, "infection_score": 36, "status": "at_risk"}
```

## Not verified yet

- Never run on the Pi with real Zeek. All tests and demos use synthetic Zeek rows.
- nftables quarantine has only run in dry-run mode, never on a real firewall.
- The live decoy listener has only been tested on local test ports, not on `192.168.50.99`.
- `dns_hijack` has not been run against a real router.
- `rates.json` holds placeholder numbers, so scores are not calibrated yet.
- No AI model is plugged into `extra_handlers` yet.
