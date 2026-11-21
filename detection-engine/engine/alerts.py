"""Send alerts to Aaryan's API, keep a local copy, and update the infection score."""
import json
import threading
import urllib.request

from . import config

_lock = threading.Lock()


def _post(path, payload):
    req = urllib.request.Request(config.API_URL + path, data=json.dumps(payload).encode(),
                                 headers={"Content-Type": "application/json"}, method="POST")
    try:
        urllib.request.urlopen(req, timeout=2).read()
        return True
    except Exception:
        return False


class AlertSink:
    def __init__(self, scorer):
        self.scorer = scorer

    def emit(self, alerts):
        for a in alerts:
            with _lock:
                self.scorer.add(a)
                status = self.scorer.score(a["mac"], now=a.get("ts"))   # traffic time, works for replay too
                a["infection_score"] = status["infection_score"]
                a["status"] = status["status"]
                with open(config.ALERT_FILE, "a") as f:
                    f.write(json.dumps(a) + "\n")
            sent = _post("/alerts", a)
            flag = "" if sent else "  (API offline, saved locally)"
            print(f"[{a['severity'].upper():8}] {a['mac']} {a['type']}: {a['evidence']} "
                  f"-> score {a['infection_score']} {a['status']}{flag}")
