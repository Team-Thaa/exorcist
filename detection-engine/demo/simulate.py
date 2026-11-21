"""Traffic simulator for the live demo. Writes Zeek-style JSON lines to <dir>/conn.log and <dir>/dns.log
while the engine runs in live mode on that folder. Lab demo only: nothing is sent on the network.

  Terminal 1:  ZEEK_LOG_DIR=/tmp/demo DRY_RUN=1 API_URL=http://127.0.0.1:9 python -m engine.main --no-decoy
  Terminal 2:  python demo/simulate.py --dir /tmp/demo

Simulated timestamps run faster than real time, so a 30 s beacon interval takes about 1 real second.
"""
import argparse
import json
import os
import random
import time
import uuid

GATEWAY = "192.168.50.1"
GATEWAY_DEV = (GATEWAY, "aa:bb:cc:00:00:01")
DECOY = "192.168.50.99"
C2 = ("10.66.0.10", 8080)
PHONE = ("192.168.50.30", "aa:bb:cc:00:00:30")
CAMERA = ("192.168.50.23", "aa:bb:cc:00:00:23")
CAMERA_CLOUD = ("52.66.10.4", 443)
PHONE_SITES = [("www.wikipedia.org", "185.15.59.224"), ("news.ycombinator.com", "209.216.230.207"),
               ("www.youtube.com", "142.250.183.14"), ("m.facebook.com", "157.240.16.35"),
               ("www.amazon.in", "52.95.120.38"), ("open.spotify.com", "35.186.224.25"),
               ("www.reddit.com", "151.101.1.140"), ("maps.google.com", "142.250.183.46")]
RANDOM_DOMAINS = ["xk3j9qpz7vmw2rtl.top", "q8zv1nf4kd7wy2hc.top", "m5tq9xr2bj6lp0ve.top"]


def conn(ts, dev, dst, port, state="SF", proto="tcp", sent=600, recv=4000):
    ip, mac = dev
    return ("conn", {"ts": ts, "uid": "C" + uuid.uuid4().hex[:17], "id.orig_h": ip,
                     "id.orig_p": random.randint(40000, 60000), "id.resp_h": dst, "id.resp_p": port,
                     "proto": proto, "duration": 0.0 if state == "S0" else round(random.uniform(0.1, 3), 3),
                     "orig_bytes": 0 if state == "S0" else sent, "resp_bytes": 0 if state == "S0" else recv,
                     "conn_state": state, "orig_l2_addr": mac})


def dns(ts, dev, query, rcode="NOERROR", answer=None):
    ip, mac = dev
    return ("dns", {"ts": ts, "uid": "D" + uuid.uuid4().hex[:17], "id.orig_h": ip,
                    "id.orig_p": random.randint(40000, 60000), "id.resp_h": GATEWAY, "id.resp_p": 53,
                    "proto": "udp", "query": query, "qtype_name": "A", "rcode_name": rcode,
                    "answers": [answer] if answer else [], "orig_l2_addr": mac})


def phase1(t0):
    """Normal network: phone browses at irregular times, camera uploads to its cloud at irregular times."""
    ev, t = [], t0
    for domain, ip in random.sample(PHONE_SITES, len(PHONE_SITES)):
        t += random.uniform(4, 35)
        ev.append((dns(t, PHONE, domain, answer=ip), f"phone looks up {domain}"))
        ev.append((conn(t + 0.05, PHONE, ip, 443), f"phone opens {domain}"))
    for gap in (0, 23, 61, 70, 112, 150, 198):   # irregular, so it never looks like beaconing
        ev.append((conn(t0 + 3 + gap, CAMERA, *CAMERA_CLOUD, sent=250000, recv=900),
                   "camera uploads video clip to its cloud"))
    # Connections TO the camera that it answers, so passive discovery sees RTSP (camera) and open Telnet.
    for at in (30, 125, 205):
        ev.append((conn(t0 + at, PHONE, CAMERA[0], 554, sent=900, recv=250000),
                   "phone watches the camera's live stream (RTSP 554)"))
    for at in (80, 170):
        ev.append((conn(t0 + at, GATEWAY_DEV, CAMERA[0], 23, sent=60, recv=120),
                   "gateway checks the camera's Telnet port (answers: open)"))
    return sorted(ev, key=lambda e: e[0][1]["ts"]), t0 + 260


def phase2(t0):
    """Infected camera: C2 beacons every 30 s, random-looking DNS, Telnet scan of 15 LAN IPs (incl. decoy)."""
    ev = []
    for i in range(9):
        ev.append((conn(t0 + 30 * i + random.uniform(-0.4, 0.4), CAMERA, *C2, sent=120, recv=80),
                   f"camera checks in with C2 {C2[0]}:{C2[1]} (beacon {i + 1})"))
    for k, d in enumerate(RANDOM_DOMAINS):
        ev.append((dns(t0 + 40 + 1.5 * k, CAMERA, d, rcode="NXDOMAIN"), f"camera looks up {d} (NXDOMAIN)"))
    targets = [f"192.168.50.{h}" for h in range(101, 115)]
    targets.insert(5, DECOY)
    for k, dst in enumerate(targets):
        ev.append((conn(t0 + 95 + 2 * k, CAMERA, dst, 23, state="S0"), f"camera tries Telnet on {dst}"))
    return sorted(ev, key=lambda e: e[0][1]["ts"])


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dir", default="/tmp/demo")
    ap.add_argument("--wait", type=float, default=3, help="seconds to wait before traffic starts")
    ap.add_argument("--pace", type=float, default=1.0, help="multiply real delays (0.5 = twice as fast)")
    ap.add_argument("--seed", type=int, default=7)
    args = ap.parse_args()
    random.seed(args.seed)

    os.makedirs(args.dir, exist_ok=True)
    paths = {k: os.path.join(args.dir, f"{k}.log") for k in ("conn", "dns")}
    for p in paths.values():      # fresh files (new inode) so a running engine re-reads from the start
        if os.path.exists(p):
            os.remove(p)
        open(p, "w").close()
    print(f"Logs: {paths['conn']}, {paths['dns']}. Starting in {args.wait:.0f}s...", flush=True)
    time.sleep(args.wait)

    def play(events):
        for (kind, row), note in events:
            with open(paths[kind], "a") as f:
                f.write(json.dumps(row) + "\n")
            print(f"  {note}", flush=True)
            time.sleep(random.uniform(0.5, 1.0) * args.pace)

    t0 = time.time()
    p1, t_end = phase1(t0)
    print("\n== 1. Normal network: phone browsing, camera uploading to its cloud ==", flush=True)
    play(p1)
    print("\n== 2. Camera gets infected ==", flush=True)
    time.sleep(1.5 * args.pace)
    play(phase2(t_end + 20))
    print("\nDone. Quarantine the camera now.", flush=True)


if __name__ == "__main__":
    main()
