# models

- `model_a/`: Random Forest trained on IoT-23 (emits `ml_botnet`)
- `model_b/`: per-device Isolation Forest (emits `ml_anomaly`)
- `explain/`: LLM plain-language explanations of alerts
- `data/`: datasets (git-ignored)

Models plug into the detection engine:
```python
from engine.main import extra_handlers
extra_handlers["conn"].append(handler)   # handler(row) -> list of alerts or None
```
Alerts must match `shared/alert.schema.json`, with `source: "model"` and a `confidence` between 0 and 1.
