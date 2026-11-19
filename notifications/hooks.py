"""Opt-in notification hooks with no network activity by default."""
from __future__ import annotations

import json
import os
import smtplib
from email.message import EmailMessage
from urllib.request import Request, urlopen


def send_webhook(message: str, url: str | None = None) -> bool:
    target = url or os.getenv("AEGIS_WEBHOOK_URL")
    if not target:
        return False
    request = Request(target, data=json.dumps({"text": message}).encode(), headers={"Content-Type": "application/json"}, method="POST")
    with urlopen(request, timeout=5):
        return True


def send_telegram(message: str) -> bool:
    token, chat_id = os.getenv("AEGIS_TELEGRAM_BOT_TOKEN"), os.getenv("AEGIS_TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        return False
    return send_webhook(message, f"https://api.telegram.org/bot{token}/sendMessage?chat_id={chat_id}")


def send_email(message: str) -> bool:
    host, sender, recipient = os.getenv("AEGIS_SMTP_HOST"), os.getenv("AEGIS_SMTP_FROM"), os.getenv("AEGIS_SMTP_TO")
    if not host or not sender or not recipient:
        return False
    email = EmailMessage()
    email["Subject"], email["From"], email["To"] = "AegisAI response notification", sender, recipient
    email.set_content(message)
    with smtplib.SMTP(host, int(os.getenv("AEGIS_SMTP_PORT", "25")), timeout=5) as smtp:
        smtp.send_message(email)
    return True