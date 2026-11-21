"""Run the detection engine.

Live:    sudo python -m engine.main
Replay:  python -m engine.main --replay conn.log [dns.log]   (Zeek JSON logs, e.g. from `zeek -r capture.pcap`)
"""
import argparse
import os
import threading
import urllib.request

from . import config, dns_hijack, quarantine
from .alerts import AlertSink
from .decoy import Decoy
from .detectors import DecoyContact, default_detectors
from .scoring import Scorer
from .tailer import follow

# Tejas: register functions here to receive every parsed conn/dns row, e.g.
#   from engine.main import extra_handlers; extra_handlers["conn"].append(my_window_builder)
# A handler may return a list of alerts (type ml_botnet / ml_anomaly) or nothing.
extra_handlers = {"conn": [], "dns": []}


def load_threats():
    ips, domains = set(), set()
    if os.path.exists(config.THREAT_FILE):
        for line in open(config.THREAT_FILE):
            line = line.split("#")[0].strip()
            if line:
                (ips if line.replace(".", "").isdigit() else domains).add(line.lower())
    try:
        text = urllib.request.urlopen(config.FEODO_URL, timeout=5).read().decode()
        ips |= {l.strip() for l in text.splitlines() if l.strip() and not l.startswith("#")}
    except Exception:
        print("[threat] could not download abuse.ch list, using local list only")
    print(f"[threat] {len(ips)} bad IPs, {len(domains)} bad domains loaded")
    return ips, domains


def process(kind, rows, detectors, sink):
    for r in rows:
        if "id.orig_h" not in r:
            continue
        r.setdefault("id.resp_p", 0)
        for d in detectors[kind]:
            handler = getattr(d, "on_" + kind, None)
            if handler:
                sink.emit(handler(r))
        for h in extra_handlers[kind]:
            out = h(r)
            if out:
                sink.emit(out)


def without_decoy_contact(detectors):
    """Copy of the detectors without DecoyContact. Used when the live decoy listener reports hits itself,
    so one decoy hit doesn't show up twice."""
    return {**detectors, "conn": [d for d in detectors["conn"] if not isinstance(d, DecoyContact)]}


def start_decoy(emit, wait=1.0):
    """Start the decoy listener in a background thread. Returns True if it is still running after
    `wait` seconds. If it can't bind its ports (decoy IP not on this machine, no root for port 23),
    the thread dies straight away and this returns False."""
    t = threading.Thread(target=Decoy(emit).run, daemon=True)
    t.start()
    t.join(wait)
    return t.is_alive()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay", nargs="+", help="process Zeek JSON log files and exit")
    ap.add_argument("--no-decoy", action="store_true")
    args = ap.parse_args()

    ips, domains = load_threats()
    detectors = default_detectors(ips, domains)
    sink = AlertSink(Scorer())

    if args.replay:
        for path in args.replay:
            kind = "dns" if "dns" in os.path.basename(path) else "conn"
            rows = sorted(follow_once(path), key=lambda r: r.get("ts", 0))
            print(f"[replay] {path}: {len(rows)} rows as {kind}")
            process(kind, rows, detectors, sink)
        return

    quarantine.setup()
    if not args.no_decoy:
        if start_decoy(sink.emit):
            detectors = without_decoy_contact(detectors)   # the listener reports decoy hits itself
        else:
            print("[decoy] listener failed to start; spotting decoy contact in conn.log instead")
    if config.ROUTER_IP:
        threading.Thread(target=dns_hijack.loop, args=(config.ROUTER_IP, sink.emit), daemon=True).start()
    dns_path = os.path.join(config.ZEEK_LOG_DIR, "dns.log")
    threading.Thread(target=process, args=("dns", follow(dns_path), detectors, sink), daemon=True).start()
    print(f"[engine] watching {config.ZEEK_LOG_DIR}")
    process("conn", follow(os.path.join(config.ZEEK_LOG_DIR, "conn.log")), detectors, sink)


def follow_once(path):
    import json
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    pass


if __name__ == "__main__":
    main()
