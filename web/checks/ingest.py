"""
Boundary validation for everything the checker sends. The checker runs on the
player's PC, so every byte here is untrusted: sizes are capped before and after
decompression, the JSON shape is checked field by field and all strings are
truncated to the column sizes.
"""
import gzip
import hashlib
import hmac
import json
import re
import zlib

from django.conf import settings

SCHEMA = "moon-check/1"
VERDICTS = {"CLEAN", "SUSPICIOUS", "CHEAT", "INCONCLUSIVE"}
SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}
MODULE_STATES = {"PENDING", "RUNNING", "OK", "SKIPPED", "ERROR", "TIMEOUT"}
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^\d+(\.\d+){0,3}$")


class IngestError(Exception):
    def __init__(self, status, code, message):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


def clip(value, limit):
    if value is None:
        return ""
    if not isinstance(value, str):
        value = str(value)
    value = value.replace("\x00", "")
    return value[:limit]


def version_tuple(value):
    if not isinstance(value, str) or not _VERSION.match(value.strip()):
        return (0,)
    return tuple(int(p) for p in value.strip().split("."))


def read_body(request, limit):
    body = request.read(limit + 1)
    if len(body) > limit:
        raise IngestError(413, "too_large", "Upload is too large.")
    return body


def gunzip_limited(data, limit):
    try:
        d = zlib.decompressobj(16 + zlib.MAX_WBITS)
        out = d.decompress(data, limit + 1)
        if len(out) > limit or d.unconsumed_tail:
            raise IngestError(413, "too_large", "Report is too large after decompression.")
        if not d.eof:
            raise IngestError(400, "bad_encoding", "Truncated gzip stream.")
        return out
    except zlib.error:
        raise IngestError(400, "bad_encoding", "Body is not valid gzip.") from None


def decode_report_body(request):
    body = read_body(request, settings.MOON_MAX_UPLOAD_BYTES)
    encoding = request.headers.get("Content-Encoding", "").strip().lower()
    if encoding == "gzip":
        body = gunzip_limited(body, settings.MOON_MAX_REPORT_BYTES)
    elif encoding not in ("", "identity"):
        raise IngestError(415, "bad_encoding", "Only gzip or identity encoding is accepted.")
    if len(body) > settings.MOON_MAX_REPORT_BYTES:
        raise IngestError(413, "too_large", "Report is too large.")
    return body


def parse_json_object(raw):
    try:
        obj = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise IngestError(400, "bad_json", "Body is not valid JSON.") from None
    if not isinstance(obj, dict):
        raise IngestError(400, "bad_json", "Expected a JSON object.")
    return obj


def verification_code(canonical_bytes):
    """Same derivation as core/Integrity.shortCode in the checker, so both screens show one code."""
    mac = hmac.new(settings.MOON_VERIFICATION_KEY.encode(), canonical_bytes, hashlib.sha256).hexdigest().upper()
    return f"{mac[0:4]}-{mac[4:8]}-{mac[8:10]}"


def sanitize_client(value):
    """What the checker reports about itself when it claims a code."""
    c = value if isinstance(value, dict) else {}
    full = clip(c.get("selfHashFull"), 64).lower()
    return {
        "hostname": clip(c.get("hostname"), 100),
        "user": clip(c.get("user"), 100),
        "os": clip(c.get("os"), 100),
        "appVersion": clip(c.get("appVersion"), 20),
        "selfHash": clip(c.get("selfHash"), 16),
        "selfHashFull": full if _HEX64.match(full) else "",
        "jvm": clip(c.get("jvm"), 100),
        "elevated": c.get("elevated") is True,
        "offsetMinutes": c.get("utcOffsetMinutes") if isinstance(c.get("utcOffsetMinutes"), int)
        and -900 <= c.get("utcOffsetMinutes") <= 900 else None,
    }


def _int(value, lo, hi, default=0):
    if isinstance(value, bool) or not isinstance(value, int):
        return default
    return max(lo, min(hi, value))


def sanitize_progress(obj):
    counts = obj.get("counts") if isinstance(obj.get("counts"), dict) else {}
    return {
        "done": _int(obj.get("done"), 0, 1000),
        "total": _int(obj.get("total"), 0, 1000),
        "module": clip(obj.get("module"), 64),
        "counts": {s.lower(): _int(counts.get(s.lower()), 0, 10 ** 6) for s in SEVERITIES},
    }


def validate_report(obj):
    """Returns a normalised dict; raises IngestError(422) on anything unexpected."""
    def bad(msg):
        raise IngestError(422, "invalid_report", msg)

    if obj.get("schema") != SCHEMA:
        bad("Unsupported report schema.")
    if obj.get("verdict") not in VERDICTS:
        bad("Unknown verdict.")
    score = obj.get("score")
    if isinstance(score, bool) or not isinstance(score, int) or not 0 <= score <= 100:
        bad("Score must be 0-100.")
    check_id = obj.get("checkId")
    if not isinstance(check_id, str) or not re.match(r"^MOON-\d{6}-[A-Z0-9]{4,8}$", check_id):
        bad("Bad checkId.")
    env = obj.get("environment")
    if not isinstance(env, dict):
        bad("Missing environment.")
    modules = obj.get("modules")
    if not isinstance(modules, dict) or len(modules) > 200:
        bad("Bad modules map.")
    findings = obj.get("findings")
    if not isinstance(findings, list):
        bad("Missing findings.")
    if len(findings) > settings.MOON_MAX_FINDINGS:
        bad("Too many findings.")

    clean_findings = []
    for i, f in enumerate(findings):
        if not isinstance(f, dict) or f.get("severity") not in SEVERITIES or not isinstance(f.get("title"), str):
            bad(f"Finding #{i} is malformed.")
        clean_findings.append({
            "idx": i,
            "severity": f["severity"],
            "category": clip(f.get("category"), 24),
            "module": clip(f.get("module"), 40),
            "title": clip(f.get("title"), 300),
            "detail": clip(f.get("detail"), 4000),
            "evidence": clip(f.get("evidence"), 4000),
            "source": clip(f.get("source"), 120),
            "weight": _int(f.get("weight"), -1000, 1000),
            "when": clip(f.get("when"), 40),
        })

    duration = obj.get("durationSeconds")
    return {
        "checkId": check_id,
        "verdict": obj["verdict"],
        "score": score,
        "startedAt": clip(obj.get("startedAt"), 40),
        "finishedAt": clip(obj.get("finishedAt"), 40),
        "durationSeconds": duration if isinstance(duration, int) and not isinstance(duration, bool) else None,
        "signatureVersion": clip(obj.get("signatureVersion"), 40),
        "signatureOrigin": clip(obj.get("signatureOrigin"), 80),
        "environment": {
            "hostname": clip(env.get("hostname"), 100),
            "os": clip(env.get("os"), 100),
            "user": clip(env.get("user"), 100),
            "elevated": env.get("elevated") is True,
            "appVersion": clip(env.get("appVersion"), 20),
            "selfHash": clip(env.get("selfHash"), 16),
            "jvm": clip(env.get("jvm"), 100),
        },
        "modules": {clip(k, 40): (v if v in MODULE_STATES else "ERROR") for k, v in modules.items()},
        "findings": clean_findings,
    }


def gzip_bytes(raw):
    return gzip.compress(raw, compresslevel=6)
