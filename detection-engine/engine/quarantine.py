"""Cut a device off from the internet while keeping it on the local network.

Uses an nftables set of MAC addresses. The `inet` forward chain only sees routed
(internet-bound) traffic, so LAN-to-LAN traffic through the bridge keeps working.
"""
import subprocess

from . import config

T = config.NFT_TABLE


def _nft(*args):
    cmd = ["nft", *args]
    if config.DRY_RUN:
        print("[dry-run]", " ".join(cmd))
        return True
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("[quarantine] nft error:", r.stderr.strip())
    return r.returncode == 0


def setup():
    _nft("add", "table", "inet", T)
    _nft("add", "set", "inet", T, "quarantined", "{ type ether_addr; }")
    _nft("add", "chain", "inet", T, "forward", "{ type filter hook forward priority -10; policy accept; }")
    _nft("flush", "chain", "inet", T, "forward")
    _nft("add", "rule", "inet", T, "forward", "ether", "saddr", "@quarantined", "counter", "drop")
    # Traffic to addresses hosted on the gateway itself (like the lab's fake C2) goes through the
    # input chain, not forward. Block quarantined devices there too, except for LAN addresses.
    _nft("add", "chain", "inet", T, "input", "{ type filter hook input priority -10; policy accept; }")
    _nft("flush", "chain", "inet", T, "input")
    _nft("add", "rule", "inet", T, "input", "ether", "saddr", "@quarantined",
         "ip", "daddr", "!=", str(config.LAN_CIDR), "counter", "drop")


def quarantine(mac: str) -> bool:
    return _nft("add", "element", "inet", T, "quarantined", "{ %s }" % mac.lower())


def release(mac: str) -> bool:
    return _nft("delete", "element", "inet", T, "quarantined", "{ %s }" % mac.lower())


if __name__ == "__main__":
    import sys
    action, *rest = sys.argv[1:] or ["setup"]
    {"setup": lambda: setup(), "add": lambda: quarantine(rest[0]),
     "del": lambda: release(rest[0])}[action]()
