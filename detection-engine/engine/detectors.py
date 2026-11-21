"""Rule-based detectors. Each one reads Zeek rows and returns Alert dicts.

Zeek conn.log fields used: ts, id.orig_h, id.resp_h, id.resp_p, proto, conn_state,
orig_bytes, resp_bytes, orig_l2_addr (if mac-logging is loaded).
Zeek dns.log fields used: ts, id.orig_h, id.resp_h, query, rcode_name.
"""
import math
import statistics
from collections import defaultdict, deque
from datetime import datetime, timezone

from . import config
from .devices import mac_for


def iso(ts):
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace("+00:00", "Z")


class Cooldown:
    """Stops the same alert (device + type + target) from repeating every second."""
    def __init__(self, seconds=config.ALERT_COOLDOWN_SEC):
        self.seconds, self.last = seconds, {}

    def ready(self, key, ts):
        if ts - self.last.get(key, -1e18) < self.seconds:
            return False
        self.last[key] = ts
        return True


cooldown = Cooldown()


def make_alert(src_ip, atype, severity, evidence, ts, zeek_mac=None, key=""):
    mac = mac_for(src_ip, zeek_mac)
    if not cooldown.ready((mac, atype, key), ts):
        return []
    return [{"mac": mac, "ip": src_ip, "source": "engine", "type": atype,
             "severity": severity, "evidence": evidence, "time": iso(ts), "ts": ts}]


class SlidingSet:
    """Distinct items seen per device in the last WINDOW_SEC seconds."""
    def __init__(self, window=config.WINDOW_SEC):
        self.window = window
        self.events = defaultdict(deque)   # src -> deque[(ts, item)]

    def add(self, src, item, ts):
        q = self.events[src]
        q.append((ts, item))
        while q and ts - q[0][0] > self.window:
            q.popleft()
        return {i for _, i in q}


# ---------------------------------------------------------------- conn.log detectors

class DecoyContact:
    """Backup for decoy.py: spots decoy contact in conn.log, so replays and rate measurement see it too."""
    def on_conn(self, r):
        src, dst, port, ts = r["id.orig_h"], r["id.resp_h"], r["id.resp_p"], r["ts"]
        if dst == config.DECOY_IP and config.is_lan(src) and src not in config.TRUSTED_SCANNERS:
            return make_alert(src, "decoy_login", "critical",
                              f"Contacted decoy {config.DECOY_IP} on port {port} (seen in traffic)", ts,
                              r.get("orig_l2_addr"), key="zeek")
        return []


class LanScan:
    """One device trying Telnet/SSH on many local devices = a bot spreading."""
    def __init__(self):
        self.targets = SlidingSet()

    def on_conn(self, r):
        src, dst, port, ts = r["id.orig_h"], r["id.resp_h"], r["id.resp_p"], r["ts"]
        if not (config.is_lan(src) and config.is_lan(dst)) or port not in config.LAN_SCAN_PORTS:
            return []
        if src in config.TRUSTED_SCANNERS:
            return []  # e.g. the discovery scanner
        if dst == config.DECOY_IP:
            return []  # the decoy has its own detector
        seen = self.targets.add(src, dst, ts)
        if len(seen) >= config.LAN_SCAN_MIN_TARGETS:
            return make_alert(src, "lan_scan", "high",
                              f"Tried Telnet/SSH on {len(seen)} local devices in {config.WINDOW_SEC}s",
                              ts, r.get("orig_l2_addr"))
        return []


class FanOut:
    """Contacting a huge number of outside addresses = DDoS or internet scanning."""
    def __init__(self):
        self.dests = SlidingSet()

    def on_conn(self, r):
        src, dst, ts = r["id.orig_h"], r["id.resp_h"], r["ts"]
        if not config.is_lan(src) or config.is_lan(dst) or src in config.TRUSTED_SCANNERS:
            return []
        seen = self.dests.add(src, dst, ts)
        if len(seen) >= config.FANOUT_MIN_DESTS:
            return make_alert(src, "fanout", "high",
                              f"Contacted {len(seen)} different internet addresses in {config.WINDOW_SEC}s",
                              ts, r.get("orig_l2_addr"))
        return []


class Beaconing:
    """Calling the same outside server at a steady rhythm = bot checking in with its C2."""
    def __init__(self):
        self.times = defaultdict(lambda: deque(maxlen=20))   # (src, dst) -> timestamps

    def on_conn(self, r):
        src, dst, ts = r["id.orig_h"], r["id.resp_h"], r["ts"]
        if not config.is_lan(src) or config.is_lan(dst):
            return []
        q = self.times[(src, dst)]
        q.append(ts)
        if len(q) < config.BEACON_MIN_EVENTS:
            return []
        gaps = [b - a for a, b in zip(q, list(q)[1:]) if b - a > 0.5]   # ignore same-burst duplicates
        if len(gaps) < config.BEACON_MIN_EVENTS - 1:
            return []
        mean = statistics.mean(gaps)
        spread = statistics.pstdev(gaps) / mean
        if config.BEACON_MIN_GAP <= mean <= config.BEACON_MAX_GAP and spread <= config.BEACON_MAX_SPREAD:
            return make_alert(src, "beaconing", "high",
                              f"Contacts {dst} every {mean:.0f}s like clockwork ({len(gaps)} times, "
                              f"variation {spread:.0%})", ts, r.get("orig_l2_addr"), key=dst)
        return []


class ThreatIntel:
    """Talking to an IP or domain on a known-bad list."""
    def __init__(self, ips=None, domains=None):
        self.ips, self.domains = set(ips or []), set(domains or [])

    def on_conn(self, r):
        src, dst = r["id.orig_h"], r["id.resp_h"]
        if config.is_lan(src) and dst in self.ips:
            return make_alert(src, "threat_intel", "critical",
                              f"Connected to known malicious server {dst}", r["ts"],
                              r.get("orig_l2_addr"), key=dst)
        return []

    def on_dns(self, r):
        q = (r.get("query") or "").lower().rstrip(".")
        if q and any(q == d or q.endswith("." + d) for d in self.domains):
            return make_alert(r["id.orig_h"], "threat_intel", "critical",
                              f"Looked up known malicious domain {q}", r["ts"], key=q)
        return []


class RiskyProtocol:
    """IoT devices using email, IRC, ADB or Telnet towards the internet."""
    def on_conn(self, r):
        src, dst, port = r["id.orig_h"], r["id.resp_h"], r["id.resp_p"]
        if config.is_lan(src) and not config.is_lan(dst) and port in config.RISKY_PORTS:
            return make_alert(src, "risky_protocol", "medium",
                              f"Used {config.RISKY_PORTS[port]} (port {port}) to {dst}", r["ts"],
                              r.get("orig_l2_addr"), key=str(port))
        return []


# ---------------------------------------------------------------- dns.log detectors

def entropy(s):
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


class SuspiciousDNS:
    """Random-looking domains, bursts of failed lookups, or bypassing the LAN DNS server."""
    def __init__(self):
        self.failures = defaultdict(deque)

    def on_dns(self, r):
        src, ts = r["id.orig_h"], r["ts"]
        q = (r.get("query") or "").lower()
        out = []
        label = q.split(".")[0] if q else ""
        if len(label) >= config.DNS_LABEL_MIN_LEN and entropy(label) >= config.DNS_ENTROPY_MIN:
            out += make_alert(src, "dns_suspicious", "medium",
                              f"Looked up random-looking domain {q}", ts, key="entropy")
        if r.get("rcode_name") == "NXDOMAIN":
            f = self.failures[src]
            f.append(ts)
            while f and ts - f[0] > config.WINDOW_SEC:
                f.popleft()
            if len(f) >= config.DNS_NXDOMAIN_BURST:
                out += make_alert(src, "dns_suspicious", "medium",
                                  f"{len(f)} failed DNS lookups in {config.WINDOW_SEC}s", ts, key="nxdomain")
        resolver = r.get("id.resp_h")
        if resolver and resolver != config.GATEWAY_IP and config.is_lan(src):
            out += make_alert(src, "dns_suspicious", "medium",
                              f"Sends DNS to {resolver} instead of the local DNS server", ts, key="bypass")
        return out


def default_detectors(threat_ips=(), threat_domains=()):
    ti = ThreatIntel(threat_ips, threat_domains)
    return {
        "conn": [DecoyContact(), LanScan(), FanOut(), Beaconing(), ti, RiskyProtocol()],
        "dns": [SuspiciousDNS(), ti],
    }
