"""All settings in one place. Override any of them with environment variables."""
import ipaddress
import os

def env(name, default):
    return os.environ.get(name, default)

# Network
LAN_CIDR = ipaddress.ip_network(env("LAN_CIDR", "192.168.50.0/24"))
GATEWAY_IP = env("GATEWAY_IP", "192.168.50.1")          # the Pi itself (also the LAN DNS server)
ROUTER_IP = env("ROUTER_IP", "")                          # router whose DNS we check (OpenWrt VM); empty = skip
LAN_IFACE = env("LAN_IFACE", "br-lan")
DECOY_IP = env("DECOY_IP", "192.168.50.99")             # extra IP added to the Pi for the decoy
DECOY_TELNET_PORTS = [23, 2323]
DECOY_HTTP_PORT = 80
# Machines allowed to scan the LAN (e.g. the discovery scanner). LanScan, FanOut and the decoy ignore them.
# Comma-separated, e.g. TRUSTED_SCANNERS=192.168.50.10,192.168.50.11. The gateway is always included.
TRUSTED_SCANNERS = {GATEWAY_IP} | {ip.strip() for ip in env("TRUSTED_SCANNERS", "").split(",") if ip.strip()}

# Zeek logs (run Zeek with JSON output, see README)
ZEEK_LOG_DIR = env("ZEEK_LOG_DIR", "/opt/zeek/logs/current")

# Where alerts go
API_URL = env("API_URL", "http://127.0.0.1:8000")
ALERT_FILE = env("ALERT_FILE", "alerts.jsonl")          # local copy of every alert

# Threat intel
THREAT_FILE = env("THREAT_FILE", os.path.join(os.path.dirname(__file__), "..", "threatlist.txt"))
FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

# Detector thresholds (starting values, tune in the lab)
WINDOW_SEC = 60
LAN_SCAN_PORTS = {22, 23, 2323}
LAN_SCAN_MIN_TARGETS = 10
FANOUT_MIN_DESTS = 100
BEACON_MIN_EVENTS = 6
BEACON_MAX_SPREAD = 0.10          # std / mean of gaps between connections
BEACON_MIN_GAP, BEACON_MAX_GAP = 5, 3600
DNS_ENTROPY_MIN = 3.5
DNS_LABEL_MIN_LEN = 12
DNS_NXDOMAIN_BURST = 20
RISKY_PORTS = {25: "SMTP", 6667: "IRC", 5555: "Android debug (ADB)", 23: "Telnet", 2323: "Telnet"}
ALERT_COOLDOWN_SEC = 120          # don't repeat the same alert for the same device + target

# Scoring
RATES_FILE = env("RATES_FILE", os.path.join(os.path.dirname(__file__), "..", "rates.json"))
PRIOR = 0.01
HALF_LIFE_SEC = 600
RED_AT, YELLOW_AT = 0.8, 0.3

# Quarantine
NFT_TABLE = "botguard"
DRY_RUN = env("DRY_RUN", "0") == "1"   # print nft commands instead of running them


def is_lan(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in LAN_CIDR
    except ValueError:
        return False
