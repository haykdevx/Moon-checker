import hashlib
import secrets
from datetime import timedelta

from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager
from django.core.validators import RegexValidator
from django.db import models
from django.utils import timezone

from .permissions import OWNER_RANK, OWNER_SLUG, PERMISSIONS

alias_validator = RegexValidator(
    r"^[a-z0-9][a-z0-9_.-]{2,31}$",
    "3-32 characters: lowercase letters, digits, dot, dash or underscore; must start with a letter or digit.")

webhook_validator = RegexValidator(
    r"^https://(?:(?:ptb|canary)\.)?discord(?:app)?\.com/api/webhooks/\d{5,25}/[A-Za-z0-9_-]{20,120}$",
    "Must be a Discord webhook URL (https://discord.com/api/webhooks/...).")


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


class Role(models.Model):
    slug = models.SlugField(max_length=40, unique=True)
    name = models.CharField(max_length=40, unique=True)
    rank = models.PositiveSmallIntegerField(help_text="Higher rank manages lower ranks. Owner is 100.")
    color = models.CharField(max_length=7, default="#6f78ef",
                             validators=[RegexValidator(r"^#[0-9a-fA-F]{6}$")])
    description = models.CharField(max_length=200, blank=True)
    permissions = models.JSONField(default=list)
    is_system = models.BooleanField(default=False)

    class Meta:
        ordering = ["-rank", "name"]

    def __str__(self):
        return str(self.label)

    @property
    def label(self):
        """A built-in role keeps its translated name until someone renames it."""
        from django.utils.translation import gettext
        from .permissions import DEFAULT_TEXT
        default = DEFAULT_TEXT.get(self.slug)
        return gettext(self.name) if default and default[0] == self.name else self.name

    @property
    def label_description(self):
        from django.utils.translation import gettext
        from .permissions import DEFAULT_TEXT
        default = DEFAULT_TEXT.get(self.slug)
        return gettext(self.description) if default and default[1] == self.description else self.description

    @property
    def is_owner_role(self):
        return self.slug == OWNER_SLUG

    def has(self, code):
        if code not in PERMISSIONS:
            raise KeyError(code)
        return self.is_owner_role or code in self.permissions


class UserManager(BaseUserManager):
    use_in_migrations = True

    def get_by_natural_key(self, username):
        return self.get(username=(username or "").strip().lower())

    def create_user(self, username, password=None, role=None, **extra):
        user = self.model(username=username.strip().lower(), role=role, **extra)
        user.set_password(password)
        user.full_clean(exclude=["password"])
        user.save(using=self._db)
        return user


class User(AbstractBaseUser):
    """A panel member. ``username`` is the public admin alias shown to players."""

    username = models.CharField("alias", max_length=32, unique=True, validators=[alias_validator])
    display_name = models.CharField(max_length=64, blank=True)
    role = models.ForeignKey(Role, on_delete=models.PROTECT, related_name="members")
    is_active = models.BooleanField(default=True)
    discord = models.CharField(max_length=64, blank=True, help_text="Discord name, shown to teammates.")
    discord_webhook = models.CharField(
        max_length=300, blank=True, validators=[webhook_validator],
        help_text="Optional: completed checks are posted to this Discord channel webhook.")
    totp_secret = models.CharField(max_length=64, blank=True)
    totp_enabled = models.BooleanField(default=False)
    totp_last_step = models.BigIntegerField(default=0)
    must_change_password = models.BooleanField(default=False)
    session_epoch = models.PositiveIntegerField(default=0)
    date_joined = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey("self", null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = []

    class Meta:
        ordering = ["username"]

    def __str__(self):
        return self.username

    def save(self, *args, **kwargs):
        self.username = (self.username or "").strip().lower()
        super().save(*args, **kwargs)

    @property
    def label(self):
        return self.display_name or self.username

    @property
    def rank(self):
        return self.role.rank

    @property
    def is_owner(self):
        return self.role.is_owner_role

    def can(self, code):
        return self.is_active and self.role.has(code)

    def get_session_auth_hash(self):
        # Bumping session_epoch (sign out everywhere, disable, role change) invalidates
        # every existing session, exactly like a password change does.
        base = super().get_session_auth_hash()
        return hashlib.sha256(f"{base}:{self.session_epoch}".encode()).hexdigest()

    def bump_sessions(self):
        self.session_epoch = models.F("session_epoch") + 1
        self.save(update_fields=["session_epoch"])
        self.refresh_from_db(fields=["session_epoch"])


class RecoveryCode(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="recovery_codes")
    code_hash = models.CharField(max_length=64)
    used_at = models.DateTimeField(null=True, blank=True)


class Invite(models.Model):
    """One-time link: either a new member invite or a password reset for an existing member."""

    KIND_INVITE = "invite"
    KIND_RESET = "reset"

    kind = models.CharField(max_length=10, choices=[(KIND_INVITE, "Invite"), (KIND_RESET, "Password reset")])
    token_hash = models.CharField(max_length=64, unique=True)
    role = models.ForeignKey(Role, null=True, blank=True, on_delete=models.CASCADE)
    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.CASCADE, related_name="+")
    note = models.CharField(max_length=100, blank=True)
    created_by = models.ForeignKey(User, null=True, on_delete=models.SET_NULL, related_name="+")
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    used_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="+")

    class Meta:
        ordering = ["-created_at"]

    @classmethod
    def issue(cls, kind, created_by, hours=48, **fields):
        token = secrets.token_urlsafe(32)
        invite = cls.objects.create(kind=kind, token_hash=hash_token(token), created_by=created_by,
                                    expires_at=timezone.now() + timedelta(hours=hours), **fields)
        return invite, token

    @classmethod
    def find_valid(cls, token):
        if not token or len(token) > 100:
            return None
        inv = cls.objects.filter(token_hash=hash_token(token), used_at__isnull=True,
                                 expires_at__gt=timezone.now()).select_related("role", "user").first()
        if inv and inv.kind == cls.KIND_RESET and (inv.user is None or not inv.user.is_active):
            return None
        return inv

    @property
    def is_open(self):
        return self.used_at is None and self.expires_at > timezone.now()


__all__ = ["Role", "User", "RecoveryCode", "Invite", "hash_token", "OWNER_RANK", "OWNER_SLUG"]
