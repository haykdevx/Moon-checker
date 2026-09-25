"""Posts a verdict embed to the admin's own Discord webhook (sent by the worker, never inline)."""
import json
import logging
import urllib.request

from django.conf import settings
from django.urls import reverse

from accounts.models import webhook_validator

log = logging.getLogger("moon.notify")

COLORS = {"CLEAN": 0x37D67A, "SUSPICIOUS": 0xF6B949, "CHEAT": 0xFF5A5A, "INCONCLUSIVE": 0xB6B6C6}
TRUST = {"ok": "✅ no warnings", "warn": "⚠️ warnings — review", "bad": "⛔ red flags — review"}


def embed_for(session):
    counts = session.counts or {}
    return {
        "username": "Moon Checker",
        "allowed_mentions": {"parse": []},
        "embeds": [{
            "title": f"Check complete — {session.player_name}"[:250],
            "url": settings.PUBLIC_URL + reverse("checks:detail", args=[session.pk]),
            "color": COLORS.get(session.verdict, 0x6F78EF),
            "fields": [
                {"name": "Verdict", "value": f"**{session.verdict}** ({session.score}/100)", "inline": True},
                {"name": "Trust", "value": TRUST.get(session.trust, "?"), "inline": True},
                {"name": "Findings", "value": " · ".join(
                    f"{k.upper()} {counts.get(k, 0)}" for k in ("critical", "high", "medium")), "inline": False},
                {"name": "Code", "value": session.code, "inline": True},
                {"name": "Verification", "value": session.verification_code or "-", "inline": True},
            ],
            "footer": {"text": f"admin {session.admin.username}"},
            "timestamp": session.completed_at.isoformat() if session.completed_at else None,
        }],
    }


def send(session, timeout=6):
    url = session.admin.discord_webhook
    webhook_validator(url)  # re-validate: only ever talk to discord.com
    body = json.dumps(embed_for(session)).encode()
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", "User-Agent": "MoonPanel/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - URL validated above
        return 200 <= resp.status < 300
