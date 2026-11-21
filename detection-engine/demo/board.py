"""Live terminal scoreboard for the demo. Re-reads the engine's alert file every second and redraws.

  python demo/board.py --file alerts.jsonl [--since-now]

Standard library only. Ctrl+C exits and restores the cursor.
"""
import argparse
import json
import os
import shutil
import signal
import sys
import time

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
COLOURS = {"safe": "\033[32m", "at_risk": "\033[33m", "infected": "\033[31m"}
LABELS = {"safe": "SAFE", "at_risk": "AT RISK", "infected": "INFECTED"}


def read_alerts(path, skip_bytes=0):
    """All complete alert lines after the first `skip_bytes` bytes. A half-written last line is ignored."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return []
    if len(data) < skip_bytes:      # file was replaced or truncated: everything in it is new
        skip_bytes = 0
    alerts = []
    for line in data[skip_bytes:].split(b"\n")[:-1]:   # last piece has no newline yet: skip it
        try:
            a = json.loads(line)
        except ValueError:
            continue
        if isinstance(a, dict) and "mac" in a:
            alerts.append(a)
    return alerts


def devices(alerts):
    """One entry per MAC, from that device's latest alert (by ts), plus its alert count."""
    by_mac = {}
    for a in alerts:
        d = by_mac.setdefault(a["mac"], {"count": 0, "latest": a})
        d["count"] += 1
        if a.get("ts", 0) >= d["latest"].get("ts", 0):
            d["latest"] = a
    rows = [dict(d["latest"], count=d["count"]) for d in by_mac.values()]
    return sorted(rows, key=lambda r: r.get("infection_score", 0), reverse=True)


def render(rows, width):
    out = [f"{BOLD}EXORCIST · live device board{RESET}   {time.strftime('%H:%M:%S')}", ""]
    if not rows:
        out.append(f"{DIM}waiting for alerts...{RESET}")
        return "\n".join(out)
    out.append(f"{DIM}{'DEVICE':<17} {'IP':<15} {'SCORE':<24} {'STATUS':<8} {'ALERTS':>6}  LATEST EVIDENCE{RESET}")
    counts = {"safe": 0, "at_risk": 0, "infected": 0}
    for r in rows:
        score = max(0, min(100, int(r.get("infection_score", 0))))
        status = r.get("status", "safe")
        counts[status] = counts.get(status, 0) + 1
        colour = COLOURS.get(status, "")
        filled = round(score / 5)
        bar = colour + "█" * filled + RESET + DIM + "░" * (20 - filled) + RESET
        fixed = f"{r['mac']:<17} {r.get('ip', ''):<15} "
        tail = f" {score:>3} {colour}{LABELS.get(status, status):<8}{RESET} {r['count']:>6}  "
        used = 17 + 1 + 15 + 1 + 20 + 4 + 1 + 8 + 1 + 6 + 2
        room = max(10, width - used - 1)
        ev = str(r.get("evidence", ""))
        ev = ev if len(ev) <= room else ev[:room - 1] + "…"
        out.append(fixed + bar + tail + ev)
    out += ["", f"{COLOURS['safe']}{counts['safe']} safe{RESET}  ·  "
                f"{COLOURS['at_risk']}{counts['at_risk']} at risk{RESET}  ·  "
                f"{COLOURS['infected']}{counts['infected']} infected{RESET}"]
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="alerts.jsonl", help="the engine's ALERT_FILE")
    ap.add_argument("--since-now", action="store_true", help="ignore alerts already in the file at startup")
    ap.add_argument("--every", type=float, default=1.0, help="refresh interval in seconds")
    args = ap.parse_args()

    # --since-now: skip everything already in the file. This uses the file position rather than ts,
    # because the demo simulator's timestamps run ahead of the clock, so old runs can have "future" ts.
    skip = os.path.getsize(args.file) if args.since_now and os.path.exists(args.file) else 0

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))   # e.g. `timeout`: exit through the finally
    sys.stdout.write("\033[?25l")                            # hide cursor
    try:
        while True:
            rows = devices(read_alerts(args.file, skip))
            width = shutil.get_terminal_size((120, 30)).columns
            sys.stdout.write("\033[H\033[2J" + render(rows, width) + "\n")
            sys.stdout.flush()
            time.sleep(args.every)
    except KeyboardInterrupt:
        pass
    finally:
        sys.stdout.write(RESET + "\033[?25h\n")              # show cursor again
        sys.stdout.flush()


if __name__ == "__main__":
    main()
