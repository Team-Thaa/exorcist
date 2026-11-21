"""Check whether the router's DNS is lying (a common sign of router malware).

Ask the router and a trusted resolver for the same well-known domains and compare.
CDNs return different IPs in different places, so we compare the owning network
(first two octets) and only alert when most domains disagree.
"""
import time

try:
    import dns.resolver
except ImportError:   # pip install dnspython
    dns = None

from . import config
from .detectors import make_alert

CHECK_DOMAINS = ["google.com", "facebook.com", "wikipedia.org", "sbi.co.in", "paytm.com"]
TRUSTED = "1.1.1.1"


def _ask(server, name):
    r = dns.resolver.Resolver(configure=False)
    r.nameservers, r.lifetime = [server], 3
    try:
        return {a.to_text() for a in r.resolve(name, "A")}
    except Exception:
        return set()


def _prefixes(ips):
    return {".".join(ip.split(".")[:2]) for ip in ips}


def check(router_ip, emit):
    if dns is None:
        print("[dns_hijack] dnspython not installed, skipping")
        return
    mismatched = []
    for name in CHECK_DOMAINS:
        local, trusted = _ask(router_ip, name), _ask(TRUSTED, name)
        if local and trusted and not (_prefixes(local) & _prefixes(trusted)):
            mismatched.append(f"{name} -> {sorted(local)[0]} (expected {sorted(trusted)[0]})")
    if len(mismatched) >= 3:
        emit(make_alert(router_ip, "dns_hijack", "critical",
                        "Router DNS gives wrong answers: " + "; ".join(mismatched[:3]),
                        time.time(), key="hijack"))


def loop(router_ip, emit, every=60):
    while True:
        check(router_ip, emit)
        time.sleep(every)
