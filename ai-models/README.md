# AI models (owner: Tejas)

- `model_a/`: Random Forest trained on IoT-23 (`ml_botnet` alerts)
- `model_b/`: per-device Isolation Forest (`ml_anomaly` alerts)
- `explain/`: LLM plain-language explanations of alerts
- `data/`: datasets (git-ignored, keep downloads out of the repo)

Hook into the engine:
```python
from engine.main import extra_handlers
extra_handlers["conn"].append(handler)   # handler(row) -> list of alerts or None
```
Alerts need `source: "model"` and a `confidence` between 0 and 1.
