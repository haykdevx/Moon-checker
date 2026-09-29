"""RFC 6238 TOTP (SHA-1, 6 digits, 30 s) with replay protection, plus recovery codes."""
import base64
import hashlib
import hmac
import secrets
import struct
import time
from urllib.parse import quote

import segno
from django.utils import timezone

from .models import RecoveryCode, User, hash_token

ISSUER = "Moon Panel"
STEP = 30
DIGITS = 6


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _code_at(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def match_step(secret, code, last_step=0, now=None, window=1):
    """Returns the matching time step (> last_step, so a code works once) or None."""
    code = "".join(ch for ch in (code or "") if ch.isdigit())
    if len(code) != DIGITS or not secret:
        return None
    current = int((now if now is not None else time.time()) // STEP)
    for step in range(current - window, current + window + 1):
        if step > last_step and hmac.compare_digest(_code_at(secret, step), code):
            return step
    return None


def verify_user(user, code, now=None):
    """Checks a TOTP code for an enrolled user and consumes its time step.

    The step is consumed by one conditional UPDATE against the stored row, not the in-memory
    user: of two requests with the same code (or two stale copies of the user) exactly one
    wins, on SQLite and PostgreSQL alike. The UPDATE also requires the same secret and 2FA
    still enabled, so a code checked against an enrolment that was reset or replaced in the
    meantime does not sign anyone in.
    """
    secret = user.totp_secret
    if not user.totp_enabled or not secret:
        return False
    step = match_step(secret, code, 0, now)  # the stored last step decides below
    if step is None:
        return False
    won = User.objects.filter(pk=user.pk, totp_enabled=True, totp_secret=secret,
                              totp_last_step__lt=step).update(totp_last_step=step)
    if won:
        user.totp_last_step = step
    return won == 1


def provisioning_uri(user, secret):
    label = quote(f"{ISSUER}:{user.username}")
    return f"otpauth://totp/{label}?secret={secret}&issuer={quote(ISSUER)}&algorithm=SHA1&digits=6&period=30"


def qr_svg(uri):
    return segno.make(uri, error="m").svg_inline(scale=5, dark="#12141f", light="#ffffff", border=2)


def issue_recovery_codes(user, count=10):
    user.recovery_codes.all().delete()
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(5).upper()
        code = f"{raw[:5]}-{raw[5:]}"
        codes.append(code)
        RecoveryCode.objects.create(user=user, code_hash=hash_token(code))
    return codes


def use_recovery_code(user, code):
    """Consumes a recovery code once (conditional UPDATE on the code's own row: exactly one of
    two concurrent uses succeeds). Codes belong to the current enrolment: disabling or resetting
    2FA deletes them, and a user whose stored 2FA is off cannot use one."""
    code = (code or "").strip().upper()
    if len(code) == 10 and "-" not in code:
        code = f"{code[:5]}-{code[5:]}"
    if not User.objects.filter(pk=user.pk, totp_enabled=True).exists():
        return False
    return RecoveryCode.objects.filter(user_id=user.pk, code_hash=hash_token(code), used_at__isnull=True) \
        .update(used_at=timezone.now()) == 1
