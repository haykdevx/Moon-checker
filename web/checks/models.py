import uuid

from django.conf import settings
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone


class TrustedBuild(models.Model):
    """SHA-256 of an official MoonCheck.exe / moon-checker.jar. Anything else is flagged."""

    sha256 = models.CharField(max_length=64, unique=True,
                              validators=[RegexValidator(r"^[0-9a-f]{64}$", "64 lowercase hex characters")])
    label = models.CharField(max_length=80)
    added_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                 on_delete=models.SET_NULL, related_name="+")
    added_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-added_at"]

    def __str__(self):
        return f"{self.label} ({self.sha256[:12]})"


class CheckSession(models.Model):
    WAITING = "WAITING"
    CONNECTED = "CONNECTED"
    SCANNING = "SCANNING"
    COMPLETED = "COMPLETED"
    ABANDONED = "ABANDONED"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"
    STATUS_CHOICES = [(s, s.title()) for s in
                      (WAITING, CONNECTED, SCANNING, COMPLETED, ABANDONED, EXPIRED, CANCELLED)]
    LIVE_STATUSES = (CONNECTED, SCANNING)
    OPEN_STATUSES = (WAITING, CONNECTED, SCANNING)

    DECISION_NONE = ""
    DECISION_CHOICES = [
        ("", "Not decided"),
        ("CLEARED", "Cleared — no cheats"),
        ("BANNED", "Banned"),
        ("REVIEW", "Needs another review"),
        ("RECHECK", "Re-check required"),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    code = models.CharField(max_length=9, unique=True)
    admin = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.PROTECT, related_name="check_sessions")
    player_name = models.CharField(max_length=64)
    player_steam = models.CharField("Steam profile / ID", max_length=100, blank=True)
    player_discord = models.CharField(max_length=64, blank=True)
    note = models.CharField(max_length=500, blank=True)

    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default=WAITING, db_index=True)
    created_at = models.DateTimeField(default=timezone.now, db_index=True)
    expires_at = models.DateTimeField()

    # set when the checker enters the code
    claimed_at = models.DateTimeField(null=True, blank=True)
    claimed_ip = models.GenericIPAddressField(null=True, blank=True)
    client = models.JSONField(default=dict, blank=True)
    token_hash = models.CharField(max_length=64, blank=True)

    # live progress
    scan_started_at = models.DateTimeField(null=True, blank=True)
    last_seen_at = models.DateTimeField(null=True, blank=True)
    progress_done = models.PositiveIntegerField(default=0)
    progress_total = models.PositiveIntegerField(default=0)
    progress_module = models.CharField(max_length=64, blank=True)
    live_counts = models.JSONField(default=dict, blank=True)
    interruptions = models.PositiveIntegerField(default=0)

    # result
    completed_at = models.DateTimeField(null=True, blank=True)
    report_ip = models.GenericIPAddressField(null=True, blank=True)
    verdict = models.CharField(max_length=32, blank=True, db_index=True)  # v2 outcome or legacy v1 verdict
    score = models.PositiveSmallIntegerField(null=True, blank=True)
    counts = models.JSONField(default=dict, blank=True)
    verification_code = models.CharField(max_length=12, blank=True)
    client_check_id = models.CharField(max_length=40, blank=True, db_index=True)
    flags = models.JSONField(default=list, blank=True)
    trust = models.CharField(max_length=4, blank=True)  # ok / warn / bad

    decision = models.CharField(max_length=8, choices=DECISION_CHOICES, blank=True, db_index=True)
    decision_note = models.CharField(max_length=1000, blank=True)
    decision_by = models.ForeignKey(settings.AUTH_USER_MODEL, null=True, blank=True,
                                    on_delete=models.SET_NULL, related_name="+")
    decision_at = models.DateTimeField(null=True, blank=True)

    notify_state = models.CharField(max_length=8, blank=True)  # "", pending, sent, failed

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.code} {self.player_name}"

    @property
    def is_open(self):
        return self.status in self.OPEN_STATUSES

    @property
    def is_live(self):
        return self.status in self.LIVE_STATUSES

    @property
    def progress_percent(self):
        if self.status == self.COMPLETED:
            return 100
        if not self.progress_total:
            return 0
        return min(100, round(100 * self.progress_done / self.progress_total))

    @property
    def severity_counts(self):
        src = self.counts if self.status == self.COMPLETED else self.live_counts
        return [(s, int(src.get(s.lower(), 0))) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]


class Report(models.Model):
    """The evidence bundle exactly as the checker sent it (gzip) plus parsed metadata."""

    session = models.OneToOneField(CheckSession, primary_key=True, on_delete=models.CASCADE, related_name="report")
    raw_gzip = models.BinaryField()
    sha256 = models.CharField(max_length=64)
    size_bytes = models.PositiveIntegerField()
    received_at = models.DateTimeField(auto_now_add=True)
    environment = models.JSONField(default=dict)
    modules = models.JSONField(default=dict)
    meta = models.JSONField(default=dict)


class FindingRow(models.Model):
    SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    session = models.ForeignKey(CheckSession, on_delete=models.CASCADE, related_name="findings")
    idx = models.PositiveIntegerField()
    severity = models.CharField(max_length=8, db_index=True)
    kind = models.CharField(max_length=16, blank=True, db_index=True)  # DETECTION/INDICATOR/... (v2)
    rule_id = models.CharField(max_length=100, blank=True, db_index=True)
    category = models.CharField(max_length=24)
    module = models.CharField(max_length=40)
    title = models.CharField(max_length=300)
    detail = models.TextField(blank=True)
    evidence = models.TextField(blank=True)
    source = models.CharField(max_length=120, blank=True)
    when = models.CharField(max_length=40, blank=True)

    class Meta:
        ordering = ["idx"]
        indexes = [models.Index(fields=["session", "idx"])]
