"""Posts a verdict embed to the admin's own Discord webhook (sent by the worker, never inline)."""
import json
import logging
import urllib.request

from django.conf import settings
from django.urls import reverse

from accounts.models import webhook_validator

log = logging.getLogger("moon.notify")

from .templatetags.moon import outcome_label

COLORS = {"VALIDATED_DETECTION": 0xFF5A5A, "REVIEW_REQUIRED": 0xF6B949, "INCOMPLETE_SCAN": 0x9AA0FF,
          "UNSUPPORTED_CONFIGURATION": 0xB6B6C6, "NO_EVIDENCE": 0x37D67A,
          "CLEAN": 0x37D67A, "SUSPICIOUS": 0xF6B949, "CHEAT": 0xFF5A5A, "INCONCLUSIVE": 0xB6B6C6}
# the panel's consistency checks only; whether the official checker really ran is never verified
TRUST = {"ok": "no contradictions found (checker run not verified)", "warn": "⚠️ warnings — review",
         "bad": "⛔ contradictions — review"}


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
                {"name": "Outcome", "value": f"**{outcome_label(session.verdict)}**"
                 + (f" ({session.score}/100, legacy)" if session.score is not None else ""), "inline": True},
                {"name": "Report checks", "value": TRUST.get(session.trust, "?"), "inline": True},
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
