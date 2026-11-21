# dashboard

The terminal-style Exorcist UI is served by the FastAPI app at `/`:

```bash
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

Pages are available through the navigation and URL hash:

- `#/overview`: network summary and recent alerts.
- `#/radar`: clickable map of discovered devices.
- `#/devices`: searchable, status-filtered device list.
- `#/device/{mac}`: device details, observed services, findings, and
  quarantine/release controls.
- `#/alerts`: recent detection-engine events.
- `#/settings`: API health and endpoint summary.

The dashboard loads `GET /devices` and `GET /alerts?limit=100`, listens to
WebSocket `/live` for `alert.created` and `device.updated` events, and posts
quarantine actions to the API. Serve it through the API on the same origin;
opening `index.html` directly does not provide API access.
