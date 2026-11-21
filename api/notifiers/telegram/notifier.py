"""Optional Telegram notifications for device status transitions."""

import json
import logging
import os
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)


def notify(device: dict, alert: dict) -> None:
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token and not chat_id:
        return
    if not token or not chat_id:
        logger.error("Telegram notification skipped: set both TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID")
        return

    message = (
        f"Exorcist: {device['status'].upper()}\n"
        f"Device: {device.get('label', device['mac'])}\n"
        f"IP: {device['ip']}\n"
        f"Score: {device['infection_score']}/100\n"
        f"Evidence: {alert['evidence']}"
    )
    request = Request(
        f"https://api.telegram.org/bot{token}/sendMessage",
        data=urlencode({"chat_id": chat_id, "text": message}).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5) as response:
            result = json.loads(response.read())
    except HTTPError as exc:
        logger.error("Telegram notification failed with HTTP %s", exc.code)
        return
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        logger.error("Telegram notification failed: %s", getattr(exc, "reason", type(exc).__name__))
        return
    if not result.get("ok"):
        logger.error("Telegram notification was rejected by the Bot API")
