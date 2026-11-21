# discovery

Builds a LAN device inventory from Zeek `conn.log` JSON, following the
technical guide's metadata-only design. It does not probe or otherwise touch
devices. Device identity is the MAC address: use Zeek's `orig_l2_addr` first,
then the Pi's `/proc/net/arp` table, and finally `ip:<address>` if neither
provides a MAC.

## Run

Run from the repository root after starting Zeek with JSON logs and
`policy/protocols/conn/mac-logging`, as described in the detection-engine
guide:

```bash
ZEEK_LOG_DIR=$HOME/zeeklogs python3 -m discovery
```

By default, discovery reads `$ZEEK_LOG_DIR/conn.log` (or
`/opt/zeek/logs/current/conn.log`) and uses the detection engine's `LAN_CIDR`,
`GATEWAY_IP`, and `DECOY_IP` defaults. Override them when needed:

```bash
LAN_CIDR=192.168.50.0/24 ZEEK_LOG_DIR=$HOME/zeeklogs \
  python3 -m discovery --conn-log $HOME/zeeklogs/conn.log
```

The output is a JSON array of records matching `shared/device.schema.json`.
Zeek header lines are ignored, and malformed JSON is reported with its file
and line number. The default LAN is `192.168.50.0/24`; the gateway and decoy
are excluded from the inventory. Only LAN endpoints observed in the log are
included.

## Exposure audit

No active port scan is performed. A destination port is included in
`open_ports` only when Zeek records a LAN device responding to a connection
(for example, `SF` or `SH` state, or positive responder bytes). This is
passive evidence, not a complete inventory of listening services; long-lived
connections may not appear in Zeek logs until they close. The exposure score
is a transparent triage heuristic based on these observed services, not an
infection verdict or proof of internet reachability. Discovery does not set
the device `status` or `infection_score`; those are owned by the detection
engine, which evaluates behavioral evidence.

Scores are additive and capped at 100. Telnet (23/2323) contributes 40, RTSP
(554) 25, unencrypted HTTP (80/8080) 15, SSH and DNS (22/53) 10 each, and
HTTPS (443/8443) 5 each. Firmware and vendor fields are not guessed.

## Tests

```bash
python3 -m pytest discovery/tests -q
```
