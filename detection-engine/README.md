# Detection engine (Varun)

Watches every device's traffic on the Pi gateway and raises alerts with proof:
decoy tripwire, LAN scan, beaconing, threat intel, suspicious DNS, DNS hijack,
fan-out/DDoS and risky protocols. Scores each device from measured detector
rates, and can quarantine a device in one call.

```
engine/
  config.py      all settings (override with environment variables)
  tailer.py      follows Zeek JSON logs like tail -f
  devices.py     IP -> MAC lookup
  detectors.py   the rule-based detectors
  decoy.py       fake camera: Telnet 23/2323 + login page on 80
  dns_hijack.py  compares the router's DNS answers with 1.1.1.1
  scoring.py     evidence-based infection score
  quarantine.py  nftables block / release by MAC
  alerts.py      sends alerts to the API, keeps alerts.jsonl
  main.py        wires everything together
rates.json       detector hit / false-alarm counts (REPLACE with lab numbers)
threatlist.txt   local bad IPs and domains (includes the lab's fake C2)
tests/           tests with fake Zeek rows, no lab needed
```

## 1. Test it on any laptop (no lab needed)

```bash
pip install pytest dnspython
python -m pytest -q          # 11 tests: every detector, scoring, and the decoy
```

## 2. Set up the Pi 5 gateway

Assumes the LAN bridge is `br-lan` on 192.168.50.0/24 with the Pi at .1 (Nitin's setup).

```bash
# Packages
sudo apt install nftables python3-pip
pip install dnspython --break-system-packages
# Zeek: try `sudo apt install zeek`. If your OS has no package, use the official Zeek
# package repo or build from source (docs.zeek.org). Building on a Pi takes a while: do it tonight.

# Give the Pi an extra address for the decoy
sudo ip addr add 192.168.50.99/24 dev br-lan

# Fake C2 server on its own subnet, hosted on the Pi (lab only)
sudo ip link add c2 type dummy
sudo ip addr add 10.66.0.10/24 dev c2
sudo ip link set c2 up
python3 -m http.server 8080 --bind 10.66.0.10 &
```

## 3. Run it

Terminal 1, Zeek with JSON logs and MAC addresses:
```bash
mkdir -p ~/zeeklogs && cd ~/zeeklogs
sudo zeek -i br-lan -C LogAscii::use_json=T policy/protocols/conn/mac-logging
```

Terminal 2, the engine:
```bash
cd engine-folder
sudo ZEEK_LOG_DIR=$HOME/zeeklogs ROUTER_IP=<OpenWrt VM IP> API_URL=http://127.0.0.1:8000 \
     python3 -m engine.main
```

`ROUTER_IP` is optional; it turns on the DNS hijack check against that router.
If Aaryan's API is not running yet, alerts still print and are saved to `alerts.jsonl`.

Quarantine by hand:
```bash
sudo python3 -m engine.quarantine add aa:bb:cc:dd:ee:ff
sudo python3 -m engine.quarantine del aa:bb:cc:dd:ee:ff
```
Aaryan's API calls `quarantine.quarantine(mac)` and `quarantine.release(mac)`.

## 4. Replay a capture (for testing and measuring rates)

```bash
zeek -r capture.pcap LogAscii::use_json=T      # writes conn.log, dns.log
python3 -m engine.main --replay conn.log dns.log
```

## 5. Measure the real detector rates (replace the placeholders)

`rates.json` holds made-up starting numbers. Before the pitch:

1. **Hits:** run each fake-bot variant (full, scan only, beacon only, slow scan) about 5 times,
   20 runs in total. For each detector, count the runs where it fired: `hits` / `runs`.
2. **False alarms:** run the phones and clean VMs for 1 hour with the bot off, plus replayed
   IoT-23 benign captures. Count device-minutes where each detector fired: `false` / `healthy`.
3. Edit `rates.json` and rerun the tests.

`"hard": true` marks clues no healthy device can trigger by design (decoy contact, known-bad
server). A fresh hit on one of those turns the device red on its own.

## For Tejas: plug the models in

```python
from engine.main import extra_handlers
extra_handlers["conn"].append(my_handler)   # gets every parsed conn.log row
```
Return a list of alerts with type `ml_botnet` or `ml_anomaly` and a `confidence` between 0 and 1;
the scorer weights them by `rates.json` times confidence.

## Alert format (posted to `POST /alerts`)

```json
{"mac": "aa:bb:cc:00:00:23", "ip": "192.168.50.23", "source": "engine", "type": "lan_scan",
 "severity": "high", "evidence": "Tried Telnet/SSH on 10 local devices in 60s",
 "time": "2023-11-14T22:15:00Z", "ts": 1700000100.0, "infection_score": 98, "status": "infected"}
```

## Not tested yet

- The nftables rules were only checked in dry-run mode, not on a real firewall.
- Live capture on the Pi with real Zeek; the tests use synthetic Zeek rows.
- The decoy was tested on localhost ports, not on the real decoy IP.
