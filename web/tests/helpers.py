import gzip
import json
from datetime import timedelta

from django.utils import timezone

from accounts.models import Role, User
from checks import codes
from checks.models import CheckSession

HASH = "ab" * 32


def make_user(alias, role_slug="admin", password="correct horse battery", **extra):
    return User.objects.create_user(alias, password, role=Role.objects.get(slug=role_slug), **extra)


def make_session(admin, **extra):
    fields = {"player_name": "PlayerOne", "code": codes.generate(),
              "expires_at": timezone.now() + timedelta(minutes=30)}
    fields.update(extra)
    return CheckSession.objects.create(admin=admin, **fields)


def client_info(**over):
    info = {"hostname": "DESKTOP-1", "user": "player", "os": "Windows 11", "appVersion": "1.1.0",
            "selfHash": HASH[:12], "selfHashFull": HASH, "jvm": "Temurin 21", "elevated": True}
    info.update(over)
    return info


def report_payload(check_id="MOON-260925-ABCD", verdict="CHEAT", score=100, findings=None, **env_over):
    env = {"hostname": "DESKTOP-1", "os": "Windows 11", "user": "player", "elevated": True,
           "appVersion": "1.1.0", "selfHash": HASH[:12], "jvm": "Temurin 21"}
    env.update(env_over)
    if findings is None:
        findings = [{"severity": "CRITICAL", "category": "FILES", "module": "files", "title": "Cheat loader",
                     "detail": "hash match", "evidence": "C:\\x\\loader.exe", "source": "MFT", "weight": 100,
                     "when": None}]
    return {"schema": "moon-check/1", "checkId": check_id, "startedAt": "2026-09-25T10:00:00",
            "finishedAt": timezone.now().isoformat().replace("+00:00", "Z"), "durationSeconds": 0,
            "verdict": verdict, "score": score, "signatureVersion": "7", "signatureOrigin": "bundled",
            "environment": env, "modules": {"files": "OK", "execution": "OK"}, "findings": findings}


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def gz(data):
    return gzip.compress(data)
