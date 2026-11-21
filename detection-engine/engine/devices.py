"""Map IP addresses to MAC addresses (the device identity everyone else uses)."""
import time

_cache = {}
_last_read = 0


def _read_arp():
    table = {}
    try:
        with open("/proc/net/arp") as f:
            next(f)
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[3] != "00:00:00:00:00:00":
                    table[parts[0]] = parts[3].lower()
    except (FileNotFoundError, StopIteration):
        pass
    return table


def mac_for(ip: str, zeek_mac: str = None) -> str:
    """Prefer the MAC Zeek logged (mac-logging policy); fall back to the ARP table."""
    global _last_read
    if zeek_mac:
        _cache[ip] = zeek_mac.lower()
        return _cache[ip]
    if ip not in _cache and time.time() - _last_read > 5:
        _cache.update(_read_arp())
        _last_read = time.time()
    return _cache.get(ip, f"ip:{ip}")
