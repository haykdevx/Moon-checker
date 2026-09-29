import logging

from .models import AuditEvent

log = logging.getLogger("moon.audit")


def client_ip(request):
    return request.META.get("REMOTE_ADDR") if request is not None else None


def record(request, action, target="", actor=None, **details):
    """Writes one audit event. Never raises: auditing must not break the action itself."""
    try:
        if actor is None and request is not None and getattr(request, "user", None) is not None \
                and request.user.is_authenticated:
            actor = request.user
        ua = request.META.get("HTTP_USER_AGENT", "")[:200] if request is not None else ""
        AuditEvent.objects.create(
            actor=actor,
            actor_label=(actor.username if actor is not None else "")[:64],
            action=action[:64],
            target=str(target)[:200],
            ip=client_ip(request),
            user_agent=ua,
            details=details,
        )
    except Exception:  # pragma: no cover - defensive
        log.exception("audit write failed: %s %s", action, target)


# details that identify a player or their PC; admin identities and actions are kept for accountability
PLAYER_KEYS = ("player", "host", "code", "hostname", "user", "steam", "discord", "contact")


def scrub_player_data(targets):
    """Removes what identifies a player from the audit events of these checks (their data is gone):
    player name, PC and code details, and the IP / browser of events the player's checker caused
    (no panel member as actor). The events themselves — what happened, when, by which admin — stay."""
    targets = [str(t) for t in targets]
    if not targets:
        return 0
    n = 0
    for ev in AuditEvent.objects.filter(target__in=targets):
        details = {k: v for k, v in (ev.details or {}).items() if k not in PLAYER_KEYS}
        changed = details != (ev.details or {})
        if ev.actor_id is None and (ev.ip or ev.user_agent):
            ev.ip, ev.user_agent = None, ""
            changed = True
        if changed:
            ev.details = details
            ev.save(update_fields=["details", "ip", "user_agent"])
            n += 1
    return n
