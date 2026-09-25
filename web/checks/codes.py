"""Player-typeable one-time check codes: 8 symbols from an unambiguous alphabet, shown as XXXX-XXXX."""
import secrets

ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I
LENGTH = 8


def generate():
    raw = "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
    return f"{raw[:4]}-{raw[4:]}"


def normalize(value):
    """Accepts any casing / spacing / dashes; returns XXXX-XXXX or None."""
    if not isinstance(value, str) or len(value) > 32:
        return None
    raw = "".join(ch for ch in value.upper() if ch.isalnum())
    if len(raw) != LENGTH or any(ch not in ALPHABET for ch in raw):
        return None
    return f"{raw[:4]}-{raw[4:]}"
