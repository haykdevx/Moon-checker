from django.conf import settings
from django.core.cache import cache
from django.core.validators import MaxValueValidator, MinValueValidator, RegexValidator
from django.db import models


class SiteSettings(models.Model):
    """Singleton (pk=1) with the knobs an owner can change from the panel."""

    code_ttl_minutes = models.PositiveIntegerField(
        default=30, validators=[MinValueValidator(5), MaxValueValidator(24 * 60)],
        help_text="How long a check code stays valid before the player enters it.")
    heartbeat_timeout_minutes = models.PositiveIntegerField(
        default=4, validators=[MinValueValidator(2), MaxValueValidator(60)],
        help_text="A running check that stops reporting for this long is marked ABANDONED.")
    retention_days = models.PositiveIntegerField(
        default=180, validators=[MaxValueValidator(3650)],
        help_text="Completed checks older than this are deleted automatically (0 = keep forever).")
    require_2fa = models.BooleanField(
        default=True, help_text="Every team member must enable two-factor authentication.")
    min_checker_version = models.CharField(
        max_length=20, default="1.0.0", validators=[RegexValidator(r"^\d+(\.\d+){0,3}$")],
        help_text="Older checkers are refused when they try to connect.")
    block_untrusted_builds = models.BooleanField(
        default=False,
        help_text="Refuse to connect checkers whose file hash is not in the trusted build list.")
    accept_unbound_reports = models.BooleanField(
        default=False,
        help_text="Transition only: accept reports from checkers older than 1.3, which cannot bind their "
                  "report to the check. Such reports are marked and have weaker replay protection.")
    fast_scan_seconds = models.PositiveIntegerField(
        default=20, validators=[MaxValueValidator(3600)],
        help_text="A completed scan faster than this (measured by the server) is flagged.")

    class Meta:
        verbose_name = "site settings"

    CACHE_KEY = "moon:site-settings"

    def save(self, *args, **kwargs):
        self.pk = 1
        super().save(*args, **kwargs)
        cache.delete(self.CACHE_KEY)

    @classmethod
    def load(cls):
        obj = cache.get(cls.CACHE_KEY)
        if obj is None:
            obj, _ = cls.objects.get_or_create(pk=1)
            cache.set(cls.CACHE_KEY, obj, 60)
        return obj


class AuditEvent(models.Model):
    """Append-only record of every security-relevant action."""

    at = models.DateTimeField(auto_now_add=True, db_index=True)
    actor = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                              on_delete=models.SET_NULL, related_name="+")
    actor_label = models.CharField(max_length=64, blank=True)
    action = models.CharField(max_length=64, db_index=True)
    target = models.CharField(max_length=200, blank=True)
    ip = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.CharField(max_length=200, blank=True)
    details = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-at", "-id"]

    def __str__(self):
        return f"{self.at:%Y-%m-%d %H:%M} {self.actor_label} {self.action} {self.target}"
