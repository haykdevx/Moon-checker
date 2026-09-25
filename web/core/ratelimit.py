"""Fixed-window counters in the shared cache (Redis in production)."""
from django.core.cache import cache


def _key(bucket, ident):
    return f"rl:{bucket}:{ident}"


def hit(bucket, ident, window_seconds):
    """Increments and returns the counter for this window."""
    key = _key(bucket, ident)
    if cache.add(key, 1, timeout=window_seconds):
        return 1
    try:
        return cache.incr(key)
    except ValueError:  # expired between add and incr
        cache.add(key, 1, timeout=window_seconds)
        return 1


def count(bucket, ident):
    return cache.get(_key(bucket, ident), 0)


def exceeded(bucket, ident, limit):
    return count(bucket, ident) >= limit


def reset(bucket, ident):
    cache.delete(_key(bucket, ident))
