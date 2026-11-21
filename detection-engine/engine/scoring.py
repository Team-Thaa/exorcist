"""Evidence-based infection score.

Each detector's weight = ln(hit rate / false-alarm rate), measured in the lab and stored in rates.json.
Only the strongest clue per family counts (no double counting), and clues fade over time.
"""
import json
import math
import time
from collections import defaultdict

from . import config


def load_rates(path=config.RATES_FILE):
    with open(path) as f:
        return {k: v for k, v in json.load(f).items() if not k.startswith("_")}


class Scorer:
    def __init__(self, rates=None):
        self.rates = rates or load_rates()
        self.history = defaultdict(list)   # mac -> [alert, ...]

    def weight(self, atype, confidence=None):
        r = self.rates[atype]
        hit = (r["hits"] + 1) / (r["runs"] + 2)            # +1 smoothing: never 0 or 100%
        false = (r["false"] + 1) / (r["healthy"] + 2)
        w = math.log(hit / false)
        if confidence is not None:                        # model alerts scale by their confidence
            w *= max(0.0, min(1.0, confidence))
        return w

    def add(self, alert):
        self.history[alert["mac"]].append(alert)

    def score(self, mac, now=None):
        now = now or time.time()
        best = {}
        for a in self.history.get(mac, []):
            if a["type"] not in self.rates:
                continue
            age = max(0.0, now - a.get("ts", now))
            w = self.weight(a["type"], a.get("confidence")) * 0.5 ** (age / config.HALF_LIFE_SEC)
            fam = self.rates[a["type"]]["family"]
            if w > best.get(fam, (0, None))[0]:
                best[fam] = (w, a["type"])
        logit = math.log(config.PRIOR / (1 - config.PRIOR)) + sum(w for w, _ in best.values())
        p = 1 / (1 + math.exp(-logit))
        # Hard evidence (decoy contact, known-bad server): no healthy device can trigger it by design,
        # so a fresh hit is enough on its own. It still fades like any other clue.
        for a in self.history.get(mac, []):
            r = self.rates.get(a["type"], {})
            if r.get("hard") and now - a.get("ts", now) < config.HALF_LIFE_SEC:
                p = max(p, config.RED_AT)
        status = "infected" if p >= config.RED_AT else "at_risk" if p >= config.YELLOW_AT else "safe"
        reasons = sorted(((round(w, 2), t) for w, t in best.values()), reverse=True)
        return {"mac": mac, "infection_score": round(p * 100), "status": status, "reasons": reasons}
