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
