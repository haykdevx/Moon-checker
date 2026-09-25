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

from .models import RecoveryCode, hash_token

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


def verify_user(user, code):
    """Checks a TOTP code for an enrolled user and consumes its time step."""
    step = match_step(user.totp_secret, code, user.totp_last_step)
    if step is None:
        return False
    user.totp_last_step = step
    user.save(update_fields=["totp_last_step"])
    return True


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
    code = (code or "").strip().upper()
    if len(code) == 10 and "-" not in code:
        code = f"{code[:5]}-{code[5:]}"
    rc = user.recovery_codes.filter(code_hash=hash_token(code), used_at__isnull=True).first()
    if rc is None:
        return False
    rc.used_at = timezone.now()
    rc.save(update_fields=["used_at"])
    return True
