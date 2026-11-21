# discovery

Finds LAN hosts with reachable common TCP services and creates one record per
device matching `shared/device.schema.json`. The initial exposure audit is
limited to observed LAN ports: it reports reachable services, an explainable
0–100 exposure score, and basic type hints (for example, RTSP suggests a
camera). It does not exploit services, retrieve firmware, or test whether a
service is reachable from the internet.

## Run

From the repository root, scan an authorized private subnet no larger than a
`/24`:

```bash
python3 -m discovery --network 192.168.1.0/24
```

The output is a JSON array on stdout. Connection timeout is configurable from
0.05 to 2 seconds:

```bash
python3 -m discovery --network 192.168.1.0/24 --timeout 0.5
```

The scanner uses only Python's standard library. It checks TCP ports
22, 23, 53, 80, 443, 554, 8080, and 8443, sequentially per host with at most
32 hosts in flight. Hosts with no reachable checked port are omitted. MAC
addresses are read from the OS neighbor cache; if unavailable, the record
uses `ip:<address>` as a placeholder.

The API currently has no documented device-ingest route, so this first version
prints schema-shaped records rather than posting them. Firmware inventory and
vendor identification require a trusted inventory source and are intentionally
not guessed from open ports.

## Exposure score

Scores are additive and capped at 100. Telnet (23) contributes 40, RTSP (554)
25, unencrypted HTTP (80/8080) 15, SSH and DNS (22/53) 10 each, and HTTPS
(443/8443) 5 each. A score of 30 or more is marked `at_risk`; lower scores are
`safe`. These are triage heuristics, not vulnerability findings.

## Tests

```bash
python3 -m pytest discovery/tests -q
```
