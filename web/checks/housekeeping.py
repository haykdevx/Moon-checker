"""Periodic maintenance, run by the worker container (manage.py moon_worker)."""
import logging
from datetime import timedelta

from django.conf import settings

from django.db.models import Q
from django.utils import timezone

from accounts.models import Invite
from core.audit import record, scrub_player_data
from core.models import SiteSettings

from . import notify
from .models import CheckSession

log = logging.getLogger("moon.worker")


def expire_and_abandon(now=None):
    now = now or timezone.now()
    site = SiteSettings.load()
    expired = CheckSession.objects.filter(status=CheckSession.WAITING, expires_at__lte=now) \
        .update(status=CheckSession.EXPIRED)
    # a running scan heartbeats every few seconds; a player still reading the start
    # screen (connected, not started) gets as long as the code itself was valid
    scan_cutoff = now - timedelta(minutes=site.heartbeat_timeout_minutes)
    idle_cutoff = now - timedelta(minutes=site.code_ttl_minutes)
    abandoned = CheckSession.objects.filter(
        Q(status=CheckSession.SCANNING, last_seen_at__lt=scan_cutoff)
        | Q(status=CheckSession.CONNECTED, claimed_at__lt=idle_cutoff)
    ).update(status=CheckSession.ABANDONED)
    return expired, abandoned


def send_notifications(limit=20):
    sent = 0
    for s in CheckSession.objects.filter(notify_state="pending").select_related("admin")[:limit]:
        try:
            ok = notify.send(s)
        except Exception as e:  # network errors, bad webhook, validation
            log.warning("discord notify failed for %s: %s", s.pk, e)
            ok = False
        s.notify_state = "sent" if ok else "failed"
        s.save(update_fields=["notify_state"])
        sent += ok
    return sent


def purge_old(now=None):
    now = now or timezone.now()
    days = SiteSettings.load().retention_days
    deleted = 0
    if days:
        cutoff = now - timedelta(days=days)
        old = CheckSession.objects.filter(created_at__lt=cutoff).exclude(status__in=CheckSession.OPEN_STATUSES)
        deleted = old.count()
        if deleted:
            gone = [str(pk) for pk in old.values_list("pk", flat=True)]
            old.delete()
            scrub_player_data(gone)
            record(None, "retention.purged", f"{deleted} checks", days=days)
    # the audit log itself is kept for a limited time (accountability, not an archive)
    from core.models import AuditEvent
    AuditEvent.objects.filter(at__lt=now - timedelta(days=settings.MOON_AUDIT_RETENTION_DAYS)).delete()
    Invite.objects.filter(expires_at__lt=now - timedelta(days=30)).delete()
    return deleted
